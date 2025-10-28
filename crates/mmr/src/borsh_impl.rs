//! Borsh serialization support for Merkle types.
//! Enable via `--features borsh`.

use borsh::{BorshDeserialize, BorshSerialize, io};

use crate::hasher::{MerkleHash, MerkleHasher};
use crate::mmr::{CompactMmr, MerkleMr64};
use crate::proof::{MerkleProof, RawMerkleProof};

// CompactMmr

impl<H> BorshSerialize for CompactMmr<H>
where
    H: MerkleHash + BorshSerialize,
{
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.entries.serialize(writer)?;
        self.cap_log2.serialize(writer)?;
        self.roots.serialize(writer)
    }
}

impl<H> BorshDeserialize for CompactMmr<H>
where
    H: MerkleHash + BorshDeserialize,
{
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let entries = u64::deserialize_reader(reader)?;
        let cap_log2 = u8::deserialize_reader(reader)?;
        let roots = <Vec<H>>::deserialize_reader(reader)?;
        Ok(Self {
            entries,
            cap_log2,
            roots,
        })
    }
}

// MerkleMr64

impl<MH> BorshSerialize for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
    MH::Hash: BorshSerialize,
{
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.num.serialize(writer)?;
        // Serialize peaks as a Vec for stability
        let peaks: Vec<MH::Hash> = self.peaks.to_vec();
        peaks.serialize(writer)
    }
}

impl<MH> BorshDeserialize for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
    MH::Hash: BorshDeserialize,
{
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let num = u64::deserialize_reader(reader)?;
        let peaks: Vec<MH::Hash> = Vec::deserialize_reader(reader)?;
        Ok(MerkleMr64::from_parts(num, peaks))
    }
}

// RawMerkleProof

impl<H> BorshSerialize for RawMerkleProof<H>
where
    H: MerkleHash + BorshSerialize,
{
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.cohashes.serialize(writer)
    }
}

impl<H> BorshDeserialize for RawMerkleProof<H>
where
    H: MerkleHash + BorshDeserialize,
{
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let cohashes = <Vec<H>>::deserialize_reader(reader)?;
        Ok(Self { cohashes })
    }
}

// MerkleProof

impl<H> BorshSerialize for MerkleProof<H>
where
    H: MerkleHash + BorshSerialize,
{
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.inner.serialize(writer)?;
        self.index.serialize(writer)
    }
}

impl<H> BorshDeserialize for MerkleProof<H>
where
    H: MerkleHash + BorshDeserialize,
{
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let inner = RawMerkleProof::<H>::deserialize_reader(reader)?;
        let index = u64::deserialize_reader(reader)?;
        Ok(Self { inner, index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{from_slice, to_vec};
    use sha2::Sha256;

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
        let bytes = to_vec(&raw).expect("serialize raw");
        let de: RawMerkleProof<H> = from_slice(&bytes).expect("deserialize raw");
        assert_eq!(raw, de);
    }

    #[test]
    fn roundtrip_merkle_proof() {
        let proof = MerkleProof::<H>::from_cohashes(vec![[9u8; 32], [8u8; 32]], 5);
        let bytes = to_vec(&proof).expect("serialize proof");
        let de: MerkleProof<H> = from_slice(&bytes).expect("deserialize proof");
        assert_eq!(proof, de);
    }

    #[test]
    fn roundtrip_mmr() {
        let mut mmr: MerkleMr64<Hasher> = MerkleMr64::new(8);
        let leaves = make_hashes(7);
        for h in leaves.iter() {
            mmr.add_leaf(*h).expect("add leaf");
        }

        let bytes = to_vec(&mmr).expect("serialize mmr");
        let de: MerkleMr64<Hasher> = from_slice(&bytes).expect("deserialize mmr");

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

        let bytes = to_vec(&compact).expect("serialize compact");
        let de: CompactMmr<H> = from_slice(&bytes).expect("deserialize compact");
        assert_eq!(compact, de);

        let rebuilt = MerkleMr64::<Hasher>::from_compact(&de);
        assert_eq!(mmr.num, rebuilt.num);
        assert_eq!(mmr.peaks_slice(), rebuilt.peaks_slice());
    }
}
