//! Proof types shared by MMR and the binary Merkle tree.

use crate::hasher::{MerkleHash, MerkleHasher};
use ssz_types::VariableList;

// Re-export SSZ-generated types
pub use crate::ssz_generated::ssz::proof::{MAX_PROOF_DEPTH, MerkleProof, RawMerkleProof};

// Extension methods for MerkleProof
impl<H> MerkleProof<H>
where
    H: MerkleHash + ssz::Encode + ssz::Decode,
{
    /// Constructs a new empty proof for the 0 index.
    pub fn new_zero() -> Self {
        Self::new_empty(0)
    }

    /// Constructs a new empty proof for some index.  This probably will not
    /// validate properly.
    pub(crate) fn new_empty(index: u64) -> Self {
        Self {
            inner: RawMerkleProof::new_zero(),
            index,
        }
    }

    /// Constructs a new instance from a Vec of cohashes.
    pub fn from_cohashes_vec(cohashes: Vec<H>, index: u64) -> Result<Self, ssz_types::Error> {
        Ok(Self {
            inner: RawMerkleProof::new_from_vec(cohashes)?,
            index,
        })
    }

    /// Constructs a new instance from a Vec of cohashes (panics on error).
    /// This is a convenience wrapper around `from_cohashes_vec` for contexts where
    /// the cohashes are known to be valid (e.g., internal tree operations).
    pub fn from_cohashes(cohashes: Vec<H>, index: u64) -> Self {
        Self::from_cohashes_vec(cohashes, index).expect("cohashes within MAX_PROOF_DEPTH")
    }

    /// Exposes the raw inner proof.
    pub fn inner_raw(&self) -> &RawMerkleProof<H> {
        &self.inner
    }

    pub(crate) fn inner_mut(&mut self) -> &mut RawMerkleProof<H> {
        &mut self.inner
    }

    /// Returns the cohash path for this proof.
    pub fn cohashes(&self) -> &[H] {
        &self.inner.cohashes
    }

    /// Returns the index this proof is for.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Discards the index and returns the raw merkle proof.
    pub fn into_raw(self) -> RawMerkleProof<H> {
        self.inner
    }

    /// Computes the root obtained by applying this proof to `leaf`.
    ///
    /// The caller specifies the merkle hasher implementation via `MH`.
    pub fn compute_root<MH>(&self, leaf: &H) -> H
    where
        MH: MerkleHasher<Hash = H>,
    {
        if self.cohashes().is_empty() {
            return *leaf;
        }

        let mut cur = *leaf;
        let mut flags = self.index;
        for co in self.cohashes().iter() {
            cur = if flags & 1 == 1 {
                MH::hash_node(*co, cur)
            } else {
                MH::hash_node(cur, *co)
            };
            flags >>= 1;
        }

        cur
    }

    /// Verifies this proof for `leaf` against the expected `root`.
    pub fn verify_with_root<MH>(&self, root: &H, leaf: &H) -> bool
    where
        MH: MerkleHasher<Hash = H>,
    {
        let computed = self.compute_root::<MH>(leaf);
        <H as MerkleHash>::eq_ct(&computed, root)
    }
}

// Extension methods for RawMerkleProof
impl<H> RawMerkleProof<H>
where
    H: MerkleHash + ssz::Encode + ssz::Decode,
{
    /// Creates a new raw proof from a Vec (fallible).
    pub fn new_from_vec(cohashes: Vec<H>) -> Result<Self, ssz_types::Error> {
        Ok(Self {
            cohashes: VariableList::new(cohashes)?,
        })
    }

    /// Creates an empty raw proof (zero cohash path).
    pub fn new_zero() -> Self {
        Self {
            cohashes: VariableList::empty(),
        }
    }

    /// Returns the cohash path in this proof.
    pub fn cohashes(&self) -> &[H] {
        &self.cohashes
    }

    pub(crate) fn cohashes_list_mut(
        &mut self,
    ) -> &mut VariableList<H, { MAX_PROOF_DEPTH as usize }> {
        &mut self.cohashes
    }

    /// Takes an index that this merkle proof is allegedly for and constructs a
    /// full proof using the cohash path we have.
    pub fn into_indexed(self, idx: u64) -> MerkleProof<H> {
        MerkleProof {
            inner: self,
            index: idx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    type TestHash = [u8; 32];

    #[test]
    fn test_raw_merkle_proof_ssz_roundtrip() {
        let cohashes = VariableList::new(vec![[1u8; 32], [2u8; 32]]).unwrap();
        let proof = RawMerkleProof { cohashes };

        let encoded = proof.as_ssz_bytes();
        let decoded = RawMerkleProof::<TestHash>::from_ssz_bytes(&encoded).unwrap();

        assert_eq!(proof.cohashes.len(), decoded.cohashes.len());
        for (a, b) in proof.cohashes.iter().zip(decoded.cohashes.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_raw_merkle_proof_ssz_empty() {
        let cohashes: VariableList<TestHash, 64> = VariableList::new(vec![]).unwrap();
        let proof = RawMerkleProof { cohashes };

        let encoded = proof.as_ssz_bytes();
        let decoded = RawMerkleProof::<TestHash>::from_ssz_bytes(&encoded).unwrap();

        assert_eq!(proof.cohashes.len(), 0);
        assert_eq!(decoded.cohashes.len(), 0);
    }

    #[test]
    fn test_merkle_proof_ssz_roundtrip() {
        let cohashes = VariableList::new(vec![[1u8; 32], [2u8; 32]]).unwrap();
        let inner = RawMerkleProof { cohashes };
        let proof = MerkleProof { inner, index: 42 };

        let encoded = proof.as_ssz_bytes();
        let decoded = MerkleProof::<TestHash>::from_ssz_bytes(&encoded).unwrap();

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

    #[test]
    fn test_merkle_proof_ssz_max_depth() {
        // Test with maximum proof depth (64 elements)
        let cohashes = VariableList::new(vec![[0u8; 32]; 64]).unwrap();
        let inner = RawMerkleProof { cohashes };
        let proof = MerkleProof {
            inner,
            index: u64::MAX,
        };

        let encoded = proof.as_ssz_bytes();
        let decoded = MerkleProof::<TestHash>::from_ssz_bytes(&encoded).unwrap();

        assert_eq!(proof.index, decoded.index);
        assert_eq!(proof.inner.cohashes.len(), 64);
        assert_eq!(decoded.inner.cohashes.len(), 64);
    }
}
