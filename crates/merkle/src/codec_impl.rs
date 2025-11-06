//! strata-codec serialization support for Merkle types.
//! Enable via `--features codec`.

use crate::CompactMmr64;
use crate::hasher::MerkleHash;
use crate::proof::{MerkleProof, RawMerkleProof};

use strata_codec::{Codec, CodecError, Decoder, Encoder, VarVec};

impl<H> Codec for CompactMmr64<H>
where
    H: MerkleHash + Codec + ssz::Encode + ssz::Decode,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let entries = u64::decode(dec)?;
        let cap_log2 = u8::decode(dec)?;
        // Reconstruct full peaks array including zeros to preserve capacity
        let mut roots = vec![H::zero(); cap_log2 as usize];
        // Read actual peaks and place them at the correct positions
        for (i, root) in roots.iter_mut().enumerate() {
            if (entries >> i) & 1 != 0 {
                *root = H::decode(dec)?;
            }
        }
        CompactMmr64::from_parts(entries, roots)
            .map_err(|_| CodecError::MalformedField("CompactMmr64.roots"))
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.entries.encode(enc)?;
        self.cap_log2().encode(enc)?;
        // Write only non-zero peaks (actual peaks)
        for (i, h) in self.roots().iter().enumerate() {
            if (self.entries >> i) & 1 != 0 {
                h.encode(enc)?;
            }
        }
        Ok(())
    }
}

// RawMerkleProof

impl<H> Codec for RawMerkleProof<H>
where
    H: MerkleHash + Codec + ssz::Encode + ssz::Decode,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let cohashes_vec: VarVec<H> = VarVec::decode(dec)?;
        RawMerkleProof::new_from_vec(cohashes_vec.into_inner())
            .map_err(|_| CodecError::MalformedField("RawMerkleProof.cohashes"))
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        let vec: VarVec<H> =
            VarVec::<H>::from_vec(self.cohashes().to_vec()).ok_or(CodecError::OverflowContainer)?;
        vec.encode(enc)
    }
}

// MerkleProof

impl<H> Codec for MerkleProof<H>
where
    H: MerkleHash + Codec + ssz::Encode + ssz::Decode,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let inner = RawMerkleProof::<H>::decode(dec)?;
        let index = u64::decode(dec)?;
        Ok(Self { inner, index })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.inner.encode(enc)?;
        self.index.encode(enc)
    }
}

#[cfg(test)]
mod tests {
    use crate::MerkleMr64;

    use super::*;
    use proptest::prelude::*;
    use sha2::Sha256;
    use strata_codec::{decode_buf_exact, encode_to_vec};

    type H = [u8; 32];
    type Hasher = crate::Sha256Hasher;

    fn make_hashes(n: usize) -> Vec<H> {
        use sha2::Digest;
        (0..n)
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect()
    }

    fn arb_hash() -> impl Strategy<Value = H> {
        any::<[u8; 32]>()
    }

    fn arb_cohashes() -> impl Strategy<Value = Vec<H>> {
        prop::collection::vec(arb_hash(), 0..20)
    }

    proptest! {
        #[test]
        fn roundtrip_raw_proof(cohashes in arb_cohashes()) {
            let raw = RawMerkleProof::<H>::new_from_vec(cohashes).expect("create raw proof");
            let bytes = encode_to_vec(&raw).expect("serialize raw");
            let de: RawMerkleProof<H> = decode_buf_exact(&bytes).expect("deserialize raw");
            prop_assert_eq!(raw, de);
        }

        #[test]
        fn roundtrip_merkle_proof(cohashes in arb_cohashes(), index in any::<u64>()) {
            let proof = MerkleProof::<H>::from_cohashes_vec(cohashes, index).expect("create proof");
            let bytes = encode_to_vec(&proof).expect("serialize proof");
            let de: MerkleProof<H> = decode_buf_exact(&bytes).expect("deserialize proof");
            prop_assert_eq!(proof, de);
        }

        #[test]
        fn roundtrip_compact_mmr(num_leaves in 1usize..=64) {
            let mut mmr: MerkleMr64<Hasher> = MerkleMr64::new(8);
            let leaves = make_hashes(num_leaves);
            for h in leaves.iter() {
                mmr.add_leaf(*h).expect("add leaf");
            }
            let compact: CompactMmr64<[u8; 32]> = mmr.into();

            let bytes = encode_to_vec(&compact).expect("serialize compact");
            let de: CompactMmr64<H> = decode_buf_exact(&bytes).expect("deserialize compact");
            prop_assert_eq!(compact, de);
        }
    }
}
