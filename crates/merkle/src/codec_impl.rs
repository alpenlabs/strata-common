//! strata-codec serialization support for Merkle types.
//! Enable via `--features codec`.

use strata_codec::{Codec, CodecError, Decoder, Encoder, VarVec, Varint};

use crate::hasher::MerkleHash;
use crate::proof::{MerkleProof, RawMerkleProof};

/// Maximum number of cohashes accepted by Codec proof serialization.
// Matches `MAX_PROOF_DEPTH` in `ssz/proof.ssz`. Defined separately so Codec does not
// require the `ssz` feature.
const MAX_CODEC_PROOF_DEPTH: u32 = 64;

// RawMerkleProof

impl<H> Codec for RawMerkleProof<H>
where
    H: MerkleHash + Codec,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let cohashes_vec: VarVec<H, MAX_CODEC_PROOF_DEPTH> = VarVec::decode(dec)?;
        Ok(Self {
            cohashes: cohashes_vec.into_inner(),
        })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        if self.cohashes.len() > MAX_CODEC_PROOF_DEPTH as usize {
            return Err(CodecError::OverflowContainer);
        }

        Varint::new_usize(self.cohashes.len())
            .ok_or(CodecError::OverflowContainer)?
            .encode(enc)?;
        for cohash in &self.cohashes {
            cohash.encode(enc)?;
        }
        Ok(())
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
    #[cfg(feature = "ssz")]
    use crate::MAX_PROOF_DEPTH;

    type H = [u8; 32];

    fn arb_hash() -> impl Strategy<Value = H> {
        any::<[u8; 32]>()
    }

    fn arb_cohashes() -> impl Strategy<Value = Vec<H>> {
        prop::collection::vec(arb_hash(), 0..=MAX_CODEC_PROOF_DEPTH as usize)
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn test_codec_depth_limit_matches_ssz() {
        assert_eq!(u64::from(MAX_CODEC_PROOF_DEPTH), MAX_PROOF_DEPTH);
    }

    #[test]
    fn test_codec_round_trips_proofs_at_min_and_max_depth() {
        for depth in [0, MAX_CODEC_PROOF_DEPTH as usize] {
            let raw = RawMerkleProof::<H>::new(vec![[0x11; 32]; depth]);
            let bytes = encode_to_vec(&raw).unwrap();
            assert_eq!(decode_buf_exact::<RawMerkleProof<H>>(&bytes).unwrap(), raw);

            let indexed = raw.into_indexed(0);
            let bytes = encode_to_vec(&indexed).unwrap();
            assert_eq!(decode_buf_exact::<MerkleProof<H>>(&bytes).unwrap(), indexed);
        }
    }

    #[test]
    fn test_codec_encode_rejects_oversized_proof_without_writing() {
        let raw = RawMerkleProof::<H>::new(vec![[0x11; 32]; (MAX_CODEC_PROOF_DEPTH + 1) as usize]);
        // A pre-existing byte that must be the only content after a rejected encode.
        let mut bytes = vec![0xa5];
        let result = raw.encode(&mut bytes);
        assert!(
            matches!(result, Err(CodecError::OverflowContainer)),
            "{result:?}"
        );
        assert_eq!(bytes, [0xa5]);

        let indexed = raw.into_indexed(0);
        let result = indexed.encode(&mut bytes);
        assert!(
            matches!(result, Err(CodecError::OverflowContainer)),
            "{result:?}"
        );
        assert_eq!(bytes, [0xa5]);
    }

    #[test]
    fn test_codec_rejects_oversized_proof_without_body() {
        // Test just over the limit, Zellic's proposed cap (256), and the reproduced depth (257).
        for count in [MAX_CODEC_PROOF_DEPTH + 1, 256, 257] {
            let prefix = encode_to_vec(&Varint::new(count).unwrap()).unwrap();
            // No hashes follow the prefix. OverflowContainer rather than OverrunInput
            // shows the count is rejected before any hash is read.
            let result = decode_buf_exact::<RawMerkleProof<H>>(&prefix);
            assert!(
                matches!(result, Err(CodecError::OverflowContainer)),
                "count = {count}, result = {result:?}"
            );
            let result = decode_buf_exact::<MerkleProof<H>>(&prefix);
            assert!(
                matches!(result, Err(CodecError::OverflowContainer)),
                "count = {count}, result = {result:?}"
            );
        }
    }

    #[test]
    fn test_codec_rejects_truncated_proofs() {
        let raw = RawMerkleProof::<H>::new(vec![[0x11; 32]; MAX_CODEC_PROOF_DEPTH as usize]);
        let bytes = encode_to_vec(&raw).unwrap();
        let prefix_len = Varint::new(MAX_CODEC_PROOF_DEPTH).unwrap().byte_len();
        // The first slice contains only the length prefix; the second cuts the last hash short.
        for truncated in [&bytes[..prefix_len], &bytes[..bytes.len() - 1]] {
            let result = decode_buf_exact::<RawMerkleProof<H>>(truncated);
            assert!(
                matches!(result, Err(CodecError::OverrunInput)),
                "input length = {}, result = {result:?}",
                truncated.len()
            );
            let result = decode_buf_exact::<MerkleProof<H>>(truncated);
            assert!(
                matches!(result, Err(CodecError::OverrunInput)),
                "input length = {}, result = {result:?}",
                truncated.len()
            );
        }

        let indexed = raw.into_indexed(1);
        let bytes = encode_to_vec(&indexed).unwrap();
        // Cut the final byte from the index, leaving all hashes intact.
        let result = decode_buf_exact::<MerkleProof<H>>(&bytes[..bytes.len() - 1]);
        assert!(
            matches!(result, Err(CodecError::OverrunInput)),
            "{result:?}"
        );
    }

    #[test]
    fn test_codec_proof_wire_vectors() {
        let raw = RawMerkleProof::<H>::new(vec![[0x11; 32], [0x22; 32]]);
        let mut expected = vec![2];
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 32]);
        assert_eq!(encode_to_vec(&raw).unwrap(), expected);
        assert_eq!(
            decode_buf_exact::<RawMerkleProof<H>>(&expected).unwrap(),
            raw
        );

        let indexed = raw.into_indexed(1);
        // The indexed proof appends its index as a big-endian u64.
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(encode_to_vec(&indexed).unwrap(), expected);
        assert_eq!(
            decode_buf_exact::<MerkleProof<H>>(&expected).unwrap(),
            indexed
        );
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
