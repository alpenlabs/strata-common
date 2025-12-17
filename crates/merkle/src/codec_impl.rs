//! strata-codec serialization support for Merkle types.
//! Enable via `--features codec`.

use crate::hasher::MerkleHash;
use crate::mmr::CompactMmr64;
use crate::proof::{MerkleProof, RawMerkleProof};

use strata_codec::{Codec, CodecError, Decoder, Encoder, VarVec};

// CompactMmr64

impl<H> Codec for CompactMmr64<H>
where
    H: MerkleHash + Codec,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let entries = u64::decode(dec)?;
        let cap_log2 = u8::decode(dec)?;
        // Number of roots equals popcount of entries (one per peak)
        let roots_len = entries.count_ones() as usize;
        let mut roots = Vec::with_capacity(roots_len);
        for _ in 0..roots_len {
            roots.push(H::decode(dec)?);
        }
        Ok(Self {
            entries,
            cap_log2,
            roots,
        })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.entries.encode(enc)?;
        self.cap_log2.encode(enc)?;
        // Validate roots length matches expected popcount to avoid misalignment
        let expected = self.entries.count_ones() as usize;
        if self.roots.len() != expected {
            return Err(CodecError::MalformedField("CompactMmr64.roots"));
        }
        for h in &self.roots {
            h.encode(enc)?;
        }
        Ok(())
    }
}

// RawMerkleProof

impl<H> Codec for RawMerkleProof<H>
where
    H: MerkleHash + Codec,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let cohashes_vec: VarVec<H> = VarVec::decode(dec)?;
        Ok(Self {
            cohashes: cohashes_vec.into_inner(),
        })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        let vec: VarVec<H> =
            VarVec::<H>::from_vec(self.cohashes.clone()).ok_or(CodecError::OverflowContainer)?;
        vec.encode(enc)
    }
}

// MerkleProof

impl<H> Codec for MerkleProof<H>
where
    H: MerkleHash + Codec,
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
    use super::*;
    use crate::Mmr;
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
            let raw = RawMerkleProof::<H>::new(cohashes);
            let bytes = encode_to_vec(&raw).expect("serialize raw");
            let de: RawMerkleProof<H> = decode_buf_exact(&bytes).expect("deserialize raw");
            prop_assert_eq!(raw, de);
        }

        #[test]
        fn roundtrip_merkle_proof(cohashes in arb_cohashes(), index in any::<u64>()) {
            let proof = MerkleProof::<H>::from_cohashes(cohashes, index);
            let bytes = encode_to_vec(&proof).expect("serialize proof");
            let de: MerkleProof<H> = decode_buf_exact(&bytes).expect("deserialize proof");
            prop_assert_eq!(proof, de);
        }

        #[test]
        fn roundtrip_compact_mmr(num_leaves in 1usize..=64) {
            let mut mmr = CompactMmr64::<H>::new(8);
            let leaves = make_hashes(num_leaves);
            for h in leaves.iter() {
                Mmr::<Hasher>::add_leaf(&mut mmr, *h).expect("add leaf");
            }

            let bytes = encode_to_vec(&mmr).expect("serialize compact");
            let de: CompactMmr64<H> = decode_buf_exact(&bytes).expect("deserialize compact");
            prop_assert_eq!(mmr, de);
        }
    }
}
