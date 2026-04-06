//! strata-codec serialization support for Merkle types.
//! Enable via `--features codec`.

use strata_codec::{Codec, CodecError, Decoder, Encoder, VarVec};

use crate::hasher::MerkleHash;
use crate::proof::{MerkleProof, RawMerkleProof};

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
        self.index.encode(enc)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_codec::{decode_buf_exact, encode_to_vec};

    use super::*;

    type H = [u8; 32];

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
    }
}
