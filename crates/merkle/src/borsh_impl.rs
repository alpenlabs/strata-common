//! Borsh serialization implementations for SSZ-generated types.

use crate::{CompactMmr64, MerkleProof, RawMerkleProof};
use borsh::{BorshDeserialize, BorshSerialize};

impl<H> BorshSerialize for CompactMmr64<H>
where
    H: BorshSerialize + ssz::Encode + ssz::Decode,
{
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.entries.serialize(writer)?;
        // Serialize as length-prefixed vector
        let len = self.roots.len() as u32;
        len.serialize(writer)?;
        for item in self.roots.iter() {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

impl<H> BorshDeserialize for CompactMmr64<H>
where
    H: BorshDeserialize + ssz::Encode + ssz::Decode,
{
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let entries = u64::deserialize_reader(reader)?;
        let len = u32::deserialize_reader(reader)?;
        let mut roots_vec = Vec::with_capacity(len as usize);
        for _ in 0..len {
            roots_vec.push(H::deserialize_reader(reader)?);
        }
        let roots = ssz_types::VariableList::new(roots_vec).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid roots length: {e:?}"),
            )
        })?;
        Ok(CompactMmr64 { entries, roots })
    }
}

impl<H> BorshSerialize for RawMerkleProof<H>
where
    H: BorshSerialize + ssz::Encode + ssz::Decode,
{
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let len = self.cohashes.len() as u32;
        len.serialize(writer)?;
        for item in self.cohashes.iter() {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

impl<H> BorshDeserialize for RawMerkleProof<H>
where
    H: BorshDeserialize + ssz::Encode + ssz::Decode,
{
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)?;
        let mut cohashes_vec = Vec::with_capacity(len as usize);
        for _ in 0..len {
            cohashes_vec.push(H::deserialize_reader(reader)?);
        }
        let cohashes = ssz_types::VariableList::new(cohashes_vec).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid cohashes length: {e:?}"),
            )
        })?;
        Ok(RawMerkleProof { cohashes })
    }
}

impl<H> BorshSerialize for MerkleProof<H>
where
    H: BorshSerialize + ssz::Encode + ssz::Decode,
{
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.inner.serialize(writer)?;
        self.index.serialize(writer)?;
        Ok(())
    }
}

impl<H> BorshDeserialize for MerkleProof<H>
where
    H: BorshDeserialize + ssz::Encode + ssz::Decode,
{
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let inner = RawMerkleProof::deserialize_reader(reader)?;
        let index = u64::deserialize_reader(reader)?;
        Ok(MerkleProof { inner, index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::VariableList;

    type TestHash = [u8; 32];

    #[test]
    fn test_compact_mmr_borsh_roundtrip() {
        let roots = VariableList::new(vec![[1u8; 32], [2u8; 32], [3u8; 32]]).unwrap();

        let mmr = CompactMmr64 { entries: 7, roots };

        let bytes = borsh::to_vec(&mmr).unwrap();
        let decoded: CompactMmr64<TestHash> = borsh::from_slice(&bytes).unwrap();

        assert_eq!(mmr.entries, decoded.entries);
        assert_eq!(mmr.roots.len(), decoded.roots.len());
        for (a, b) in mmr.roots.iter().zip(decoded.roots.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_raw_merkle_proof_borsh_roundtrip() {
        let cohashes = VariableList::new(vec![[1u8; 32], [2u8; 32]]).unwrap();

        let proof = RawMerkleProof { cohashes };

        let bytes = borsh::to_vec(&proof).unwrap();
        let decoded: RawMerkleProof<TestHash> = borsh::from_slice(&bytes).unwrap();

        assert_eq!(proof.cohashes.len(), decoded.cohashes.len());
        for (a, b) in proof.cohashes.iter().zip(decoded.cohashes.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_merkle_proof_borsh_roundtrip() {
        let cohashes = VariableList::new(vec![[1u8; 32], [2u8; 32]]).unwrap();
        let inner = RawMerkleProof { cohashes };

        let proof = MerkleProof { inner, index: 42 };

        let bytes = borsh::to_vec(&proof).unwrap();
        let decoded: MerkleProof<TestHash> = borsh::from_slice(&bytes).unwrap();

        assert_eq!(proof.index, decoded.index);
        assert_eq!(proof.inner.cohashes.len(), decoded.inner.cohashes.len());
        for (a, b) in proof
            .inner
            .cohashes
            .iter()
            .zip(decoded.inner.cohashes.iter())
        {
            assert_eq!(a, b);
        }
    }
}
