//! Serde serialization support for Merkle types.
//! Enable via `--features serde`.

use crate::hasher::MerkleHash;
use crate::hasher::MerkleHasher;
use crate::mmr::{CompactMmr64, MerkleMr64};
use crate::proof::{MerkleProof, RawMerkleProof};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// CompactMmr64

impl<H> Serialize for CompactMmr64<H>
where
    H: MerkleHash + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (&self.entries, &self.cap_log2, &self.roots).serialize(serializer)
    }
}

impl<'de, H> Deserialize<'de> for CompactMmr64<H>
where
    H: MerkleHash + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (entries, cap_log2, roots) = <(u64, u8, Vec<H>)>::deserialize(deserializer)?;
        Ok(Self {
            entries,
            cap_log2,
            roots,
        })
    }
}

// MerkleMr64

impl<MH> Serialize for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
    MH::Hash: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (&self.num, &self.peaks.to_vec()).serialize(serializer)
    }
}

impl<'de, MH> Deserialize<'de> for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
    MH::Hash: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (num, peaks): (u64, Vec<MH::Hash>) = <(u64, Vec<MH::Hash>)>::deserialize(deserializer)?;
        Ok(MerkleMr64::from_parts(num, peaks))
    }
}

// RawMerkleProof

impl<H> Serialize for RawMerkleProof<H>
where
    H: MerkleHash + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.cohashes.serialize(serializer)
    }
}

impl<'de, H> Deserialize<'de> for RawMerkleProof<H>
where
    H: MerkleHash + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cohashes = <Vec<H>>::deserialize(deserializer)?;
        Ok(Self { cohashes })
    }
}

// MerkleProof

impl<H> Serialize for MerkleProof<H>
where
    H: MerkleHash + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (&self.inner, &self.index).serialize(serializer)
    }
}

impl<'de, H> Deserialize<'de> for MerkleProof<H>
where
    H: MerkleHash + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (inner, index): (RawMerkleProof<H>, u64) =
            <(RawMerkleProof<H>, u64)>::deserialize(deserializer)?;
        Ok(Self { inner, index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    // Use serde_json for roundtrip tests
    use serde_json::{from_str, to_string};

    type H = [u8; 32];
    type Hasher = crate::Sha256Hasher;

    fn make_hashes(n: usize) -> Vec<H> {
        use sha2::Digest;
        (0..n)
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect()
    }

    #[test]
    fn roundtrip_raw_proof_json() {
        let raw = RawMerkleProof::<H>::new(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        let s = to_string(&raw).expect("serialize raw");
        let de: RawMerkleProof<H> = from_str(&s).expect("deserialize raw");
        assert_eq!(raw, de);
    }

    #[test]
    fn roundtrip_merkle_proof_json() {
        let proof = MerkleProof::<H>::from_cohashes(vec![[9u8; 32], [8u8; 32]], 5);
        let s = to_string(&proof).expect("serialize proof");
        let de: MerkleProof<H> = from_str(&s).expect("deserialize proof");
        assert_eq!(proof, de);
    }

    #[test]
    fn roundtrip_mmr_json() {
        let mut mmr: MerkleMr64<Hasher> = MerkleMr64::new(8);
        let leaves = make_hashes(7);
        for h in leaves.iter() {
            mmr.add_leaf(*h).expect("add leaf");
        }

        let s = to_string(&mmr).expect("serialize mmr");
        let de: MerkleMr64<Hasher> = from_str(&s).expect("deserialize mmr");

        assert_eq!(mmr.num, de.num);
        assert_eq!(mmr.peaks_slice(), de.peaks_slice());
    }

    #[test]
    fn roundtrip_compact_mmr_json() {
        let mut mmr: MerkleMr64<Hasher> = MerkleMr64::new(8);
        let leaves = make_hashes(10);
        for h in leaves.iter() {
            mmr.add_leaf(*h).expect("add leaf");
        }
        let compact = mmr.to_compact();

        let s = to_string(&compact).expect("serialize compact");
        let de: CompactMmr64<H> = from_str(&s).expect("deserialize compact");
        assert_eq!(compact, de);

        let rebuilt = MerkleMr64::<Hasher>::from_compact(&de);
        assert_eq!(mmr.num, rebuilt.num);
        assert_eq!(mmr.peaks_slice(), rebuilt.peaks_slice());
    }
}
