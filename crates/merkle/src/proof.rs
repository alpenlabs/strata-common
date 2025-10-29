//! Proof types shared by MMR and the binary Merkle tree.

use crate::hasher::MerkleHash;

/// Proof for an entry in an MMR/tree.
///
/// If the MMR or tree that produced this proof is updated, then this proof has
/// to be updated as well.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct MerkleProof<H>
where
    H: MerkleHash,
{
    /// Sibling hashes required for proof.
    pub(crate) inner: RawMerkleProof<H>,

    /// Index of the element for which this proof is for.
    pub(crate) index: u64,
}

impl<H: MerkleHash> MerkleProof<H> {
    fn new(inner: RawMerkleProof<H>, index: u64) -> Self {
        Self { inner, index }
    }

    /// Constructs a new empty proof for the 0 index.
    pub fn new_zero() -> Self {
        Self::new_empty(0)
    }

    /// Constructs a new empty proof for some index.  This probably will not
    /// validate properly.
    pub(crate) fn new_empty(index: u64) -> Self {
        Self::new(RawMerkleProof::new_zero(), index)
    }

    /// Constructs a new instance from the path.
    pub fn from_cohashes(cohashes: Vec<H>, index: u64) -> Self {
        Self::new(RawMerkleProof::new(cohashes), index)
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
        self.inner.cohashes()
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
        MH: crate::hasher::MerkleHasher<Hash = H>,
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
        MH: crate::hasher::MerkleHasher<Hash = H>,
    {
        let computed = self.compute_root::<MH>(leaf);
        <H as MerkleHash>::eq_ct(&computed, root)
    }
}

/// Raw proof for some entry in a MMR/tree.
///
/// This doesn't include the index of the entry being proven, which makes this
/// useful in contexts where we establish that value separately.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct RawMerkleProof<H>
where
    H: MerkleHash,
{
    pub(crate) cohashes: Vec<H>,
}

impl<H: MerkleHash> RawMerkleProof<H> {
    /// Creates a new raw proof from a cohash path.
    pub fn new(cohashes: Vec<H>) -> Self {
        Self { cohashes }
    }

    /// Creates an empty raw proof (zero cohash path).
    pub fn new_zero() -> Self {
        Self::new(Vec::new())
    }

    /// Returns the cohash path in this proof.
    pub fn cohashes(&self) -> &[H] {
        &self.cohashes
    }

    pub(crate) fn cohashes_vec_mut(&mut self) -> &mut Vec<H> {
        &mut self.cohashes
    }

    /// Takes an index that this merkle proof is allegedly for and constructs a
    /// full proof using the cohash path we have.
    pub fn into_indexed(self, idx: u64) -> MerkleProof<H> {
        MerkleProof::from_cohashes(self.cohashes, idx)
    }
}
