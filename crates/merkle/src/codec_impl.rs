//! strata-codec serialization support for Merkle types.
//! Enable via `--features code`.

use crate::hasher::{MerkleHash, MerkleHasher};
use crate::mmr::{CompactMmr64, MerkleMr64};
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
        let roots_vec: VarVec<H> = VarVec::decode(dec)?;
        Ok(Self {
            entries,
            cap_log2,
            roots: roots_vec.into_inner(),
        })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.entries.encode(enc)?;
        self.cap_log2.encode(enc)?;
        let roots_vec: VarVec<H> =
            VarVec::<H>::from_vec(self.roots.clone()).ok_or(CodecError::OverflowContainer)?;
        roots_vec.encode(enc)
    }
}

// MerkleMr64

impl<MH> Codec for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
    MH::Hash: Codec,
{
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let num = u64::decode(dec)?;
        let peaks_vec: VarVec<MH::Hash> = VarVec::decode(dec)?;
        Ok(MerkleMr64::from_parts(num, peaks_vec.into_inner()))
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.num.encode(enc)?;
        let peaks = self.peaks.to_vec();
        let peaks_vec: VarVec<MH::Hash> =
            VarVec::<MH::Hash>::from_vec(peaks).ok_or(CodecError::OverflowContainer)?;
        peaks_vec.encode(enc)
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

    #[test]
    fn roundtrip_raw_proof() {
        let raw = RawMerkleProof::<H>::new(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        let bytes = encode_to_vec(&raw).expect("serialize raw");
        let de: RawMerkleProof<H> = decode_buf_exact(&bytes).expect("deserialize raw");
        assert_eq!(raw, de);
    }

    #[test]
    fn roundtrip_merkle_proof() {
        let proof = MerkleProof::<H>::from_cohashes(vec![[9u8; 32], [8u8; 32]], 5);
        let bytes = encode_to_vec(&proof).expect("serialize proof");
        let de: MerkleProof<H> = decode_buf_exact(&bytes).expect("deserialize proof");
        assert_eq!(proof, de);
    }

    #[test]
    fn roundtrip_mmr() {
        let mut mmr: MerkleMr64<Hasher> = MerkleMr64::new(8);
        let leaves = make_hashes(7);
        for h in leaves.iter() {
            mmr.add_leaf(*h).expect("add leaf");
        }

        let bytes = encode_to_vec(&mmr).expect("serialize mmr");
        let de: MerkleMr64<Hasher> = decode_buf_exact(&bytes).expect("deserialize mmr");

        assert_eq!(mmr.num, de.num);
        assert_eq!(mmr.peaks_slice(), de.peaks_slice());
    }

    #[test]
    fn roundtrip_compact_mmr() {
        let mut mmr: MerkleMr64<Hasher> = MerkleMr64::new(8);
        let leaves = make_hashes(10);
        for h in leaves.iter() {
            mmr.add_leaf(*h).expect("add leaf");
        }
        let compact = mmr.to_compact();

        let bytes = encode_to_vec(&compact).expect("serialize compact");
        let de: CompactMmr64<H> = decode_buf_exact(&bytes).expect("deserialize compact");
        assert_eq!(compact, de);

        let rebuilt = MerkleMr64::<Hasher>::from_compact(&de);
        assert_eq!(mmr.num, rebuilt.num);
        assert_eq!(mmr.peaks_slice(), rebuilt.peaks_slice());
    }
}
