//! Proof types shared by MMR and the binary Merkle tree.

use crate::hasher::{MerkleHash, MerkleHasher};

/// Trait for raw proof data (cohashes only, no index).
///
/// This trait is implemented by both `RawMerkleProof<H>` and `RawMerkleProofB32`,
/// allowing generic algorithms to work with either representation.
pub trait RawProofData {
    /// The hash type used in this proof.
    type Hash: MerkleHash;

    /// Returns an iterator over the cohashes in this proof.
    fn cohashes_iter(&self) -> impl Iterator<Item = &Self::Hash>;

    /// Returns the number of cohashes in this proof.
    fn cohashes_len(&self) -> usize;
}

/// Trait for indexed proof data (cohashes + index).
///
/// This trait extends `RawProofData` with an index, representing a complete
/// merkle proof that can be verified against a root.
pub trait ProofData {
    /// The hash type used in this proof.
    type Hash: MerkleHash;

    /// Returns the index this proof is for.
    fn index(&self) -> u64;

    /// Returns an iterator over the cohashes in this proof.
    fn cohashes_iter(&self) -> impl Iterator<Item = &Self::Hash>;

    /// Returns the number of cohashes in this proof.
    fn cohashes_len(&self) -> usize;
}

/// Computes the root obtained by applying a proof to a leaf.
///
/// This generic function works with any type implementing `ProofData`.
pub fn compute_root<P, MH>(proof: &P, leaf: &P::Hash) -> P::Hash
where
    P: ProofData,
    MH: MerkleHasher<Hash = P::Hash>,
{
    compute_root_generic::<P::Hash, MH, _>(
        proof.cohashes_iter(),
        proof.cohashes_len(),
        proof.index(),
        leaf,
    )
}

/// Verifies a proof for a leaf against an expected root.
///
/// This generic function works with any type implementing `ProofData`.
pub fn verify_with_root<P, MH>(proof: &P, root: &P::Hash, leaf: &P::Hash) -> bool
where
    P: ProofData,
    MH: MerkleHasher<Hash = P::Hash>,
{
    let computed = compute_root::<P, MH>(proof, leaf);
    <P::Hash as MerkleHash>::eq_ct(&computed, root)
}

/// Core merkle proof computation algorithm.
///
/// This function implements the shared logic for computing a merkle root from a leaf
/// and cohash path, parameterized over any iterator of hash references.
#[inline]
pub(crate) fn compute_root_generic<'a, H, MH, I>(
    cohashes: I,
    cohash_count: usize,
    index: u64,
    leaf: &H,
) -> H
where
    H: MerkleHash + 'a,
    MH: MerkleHasher<Hash = H>,
    I: Iterator<Item = &'a H>,
{
    if cohash_count == 0 {
        return *leaf;
    }

    let mut cur = *leaf;
    let mut flags = index;
    for co in cohashes {
        cur = if flags & 1 == 1 {
            MH::hash_node(*co, cur)
        } else {
            MH::hash_node(cur, *co)
        };
        flags >>= 1;
    }

    cur
}

/// Proof for an entry in an MMR/tree.
///
/// If the MMR or tree that produced this proof is updated, then this proof has
/// to be updated as well.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
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
        MH: MerkleHasher<Hash = H>,
    {
        compute_root::<Self, MH>(self, leaf)
    }

    /// Verifies this proof for `leaf` against the expected `root`.
    pub fn verify_with_root<MH>(&self, root: &H, leaf: &H) -> bool
    where
        MH: MerkleHasher<Hash = H>,
    {
        verify_with_root::<Self, MH>(self, root, leaf)
    }
}

impl<H: MerkleHash> ProofData for MerkleProof<H> {
    type Hash = H;

    fn index(&self) -> u64 {
        self.index
    }

    fn cohashes_iter(&self) -> impl Iterator<Item = &Self::Hash> {
        self.inner.cohashes.iter()
    }

    fn cohashes_len(&self) -> usize {
        self.inner.cohashes.len()
    }
}

/// Raw proof for some entry in a MMR/tree.
///
/// This doesn't include the index of the entry being proven, which makes this
/// useful in contexts where we establish that value separately.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
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

impl<H: MerkleHash> RawProofData for RawMerkleProof<H> {
    type Hash = H;

    fn cohashes_iter(&self) -> impl Iterator<Item = &Self::Hash> {
        self.cohashes.iter()
    }

    fn cohashes_len(&self) -> usize {
        self.cohashes.len()
    }
}

#[cfg(feature = "ssz")]
mod proofb32 {
    use super::*;
    use crate::{
        Sha256Hasher,
        hasher::MerkleHasher,
        ssz_generated::ssz::proof::{MerkleProofB32, RawMerkleProofB32},
    };
    use ssz_types::FixedBytes;

    type Hash32 = <Sha256Hasher as MerkleHasher>::Hash;

    impl RawMerkleProofB32 {
        /// Creates a concrete proof from a generic RawMerkleProof
        pub fn from_generic(proof: &RawMerkleProof<Hash32>) -> Self {
            let cohashes: Vec<_> = proof
                .cohashes()
                .iter()
                .map(|h| FixedBytes::<32>::from(*h))
                .collect();
            Self {
                cohashes: cohashes.into(),
            }
        }

        /// Creates a new raw proof from a cohash path.
        ///
        /// This is similar to `RawMerkleProof::new`.
        pub fn new(cohashes: Vec<[u8; 32]>) -> Self {
            let cohashes_vec: Vec<_> = cohashes.into_iter().map(FixedBytes::<32>::from).collect();
            Self {
                cohashes: cohashes_vec.into(),
            }
        }

        /// Creates an empty raw proof (zero cohash path).
        ///
        /// This is similar to `RawMerkleProof::new_zero`.
        pub fn new_zero() -> Self {
            Self {
                cohashes: vec![].into(),
            }
        }

        /// Returns the cohash path in this proof.
        ///
        /// This is similar to `RawMerkleProof::cohashes`.
        pub fn cohashes(&self) -> Vec<[u8; 32]> {
            self.cohashes.iter().map(|h| h.0).collect()
        }

        /// Provides mutable access to the cohashes VariableList.
        ///
        /// This is similar to `RawMerkleProof::cohashes_vec_mut`, but returns
        /// a mutable reference to the VariableList instead of Vec.
        pub fn cohashes_list_mut(&mut self) -> &mut ssz_types::VariableList<FixedBytes<32>, 64> {
            &mut self.cohashes
        }

        /// Takes an index that this merkle proof is allegedly for and constructs a
        /// full proof using the cohash path we have.
        ///
        /// This is similar to `RawMerkleProof::into_indexed`.
        pub fn into_indexed(self, idx: u64) -> MerkleProofB32 {
            MerkleProofB32 {
                inner: self,
                index: idx,
            }
        }
    }

    impl RawProofData for RawMerkleProofB32 {
        type Hash = [u8; 32];

        fn cohashes_iter(&self) -> impl Iterator<Item = &Self::Hash> {
            self.cohashes.iter().map(|fb| &fb.0)
        }

        fn cohashes_len(&self) -> usize {
            self.cohashes.len()
        }
    }

    impl MerkleProofB32 {
        /// Creates a concrete proof from a generic MerkleProof
        pub fn from_generic(proof: &MerkleProof<Hash32>) -> Self {
            Self {
                inner: RawMerkleProofB32::from_generic(proof.inner_raw()),
                index: proof.index(),
            }
        }

        /// Constructs a new proof from cohashes and index.
        ///
        /// This is similar to `MerkleProof::from_cohashes`.
        pub fn from_cohashes(cohashes: Vec<[u8; 32]>, index: u64) -> Self {
            let cohashes_vec: Vec<_> = cohashes.into_iter().map(FixedBytes::<32>::from).collect();
            Self {
                inner: RawMerkleProofB32 {
                    cohashes: cohashes_vec.into(),
                },
                index,
            }
        }

        /// Constructs a new empty proof for the 0 index.
        ///
        /// This is similar to `MerkleProof::new_zero`.
        pub fn new_zero() -> Self {
            Self {
                inner: RawMerkleProofB32 {
                    cohashes: vec![].into(),
                },
                index: 0,
            }
        }

        /// Returns the cohash path for this proof.
        ///
        /// This is similar to `MerkleProof::cohashes`.
        pub fn cohashes(&self) -> Vec<[u8; 32]> {
            self.inner.cohashes.iter().map(|h| h.0).collect()
        }

        /// Returns the index this proof is for.
        ///
        /// This is similar to `MerkleProof::index`.
        pub fn index(&self) -> u64 {
            self.index
        }

        /// Exposes the raw inner proof.
        ///
        /// This is similar to `MerkleProof::inner_raw`.
        pub fn inner_raw(&self) -> &RawMerkleProofB32 {
            &self.inner
        }

        /// Provides mutable access to the inner raw proof.
        ///
        /// This is similar to `MerkleProof::inner_mut`.
        pub fn inner_mut(&mut self) -> &mut RawMerkleProofB32 {
            &mut self.inner
        }

        /// Discards the index and returns the raw merkle proof.
        ///
        /// This is similar to `MerkleProof::into_raw`.
        pub fn into_raw(self) -> RawMerkleProofB32 {
            self.inner
        }

        /// Computes the root obtained by applying this proof to `leaf`.
        ///
        /// This method uses Sha256Hasher as the merkle hasher implementation.
        pub fn compute_root(&self, leaf: &[u8; 32]) -> [u8; 32] {
            compute_root::<Self, Sha256Hasher>(self, leaf)
        }

        /// Verifies this proof for `leaf` against the expected `root`.
        ///
        /// This method uses Sha256Hasher as the merkle hasher implementation.
        pub fn verify_with_root(&self, root: &[u8; 32], leaf: &[u8; 32]) -> bool {
            verify_with_root::<Self, Sha256Hasher>(self, root, leaf)
        }
    }

    impl ProofData for MerkleProofB32 {
        type Hash = [u8; 32];

        fn index(&self) -> u64 {
            self.index
        }

        fn cohashes_iter(&self) -> impl Iterator<Item = &Self::Hash> {
            self.inner.cohashes.iter().map(|fb| &fb.0)
        }

        fn cohashes_len(&self) -> usize {
            self.inner.cohashes.len()
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ssz")]
    use {
        crate::{MerkleMr64, MerkleProof, MerkleProofB32, RawMerkleProofB32, Sha256Hasher},
        sha2::{Digest, Sha256},
        ssz::{Decode, Encode},
        ssz_types::FixedBytes,
    };

    #[cfg(feature = "ssz")]
    type Hash32 = <Sha256Hasher as crate::MerkleHasher>::Hash;

    // B32 type conversion tests
    #[test]
    #[cfg(feature = "ssz")]
    fn test_proof_conversion_from_generic() {
        // Create a generic proof
        let hash1: Hash32 = Sha256::digest(b"cohash1").into();
        let hash2: Hash32 = Sha256::digest(b"cohash2").into();
        let cohashes = vec![hash1, hash2];
        let index = 5;

        let generic_proof = MerkleProof::from_cohashes(cohashes.clone(), index);

        // Convert to concrete
        let concrete_proof = MerkleProofB32::from_generic(&generic_proof);

        // Verify fields match
        assert_eq!(concrete_proof.index, generic_proof.index());
        assert_eq!(concrete_proof.cohashes(), cohashes);
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_proof_compute_root() {
        // Create a simple proof
        let leaf: Hash32 = Sha256::digest(b"leaf").into();
        let cohash1: Hash32 = Sha256::digest(b"cohash1").into();
        let cohash2: Hash32 = Sha256::digest(b"cohash2").into();

        let generic_proof = MerkleProof::from_cohashes(vec![cohash1, cohash2], 1);
        let concrete_proof = MerkleProofB32::from_generic(&generic_proof);

        // Compute root using both methods
        let generic_root = generic_proof.compute_root::<Sha256Hasher>(&leaf);
        let concrete_root = concrete_proof.compute_root(&leaf);

        // Should produce same result
        assert_eq!(generic_root, concrete_root);
    }

    // SSZ serialization tests
    #[cfg(feature = "ssz")]
    fn generate_proof_for_test() -> (MerkleProof<Hash32>, Hash32) {
        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        let hash1: [u8; 32] = Sha256::digest(b"test1").into();
        let hash2: [u8; 32] = Sha256::digest(b"test2").into();
        let hash3: [u8; 32] = Sha256::digest(b"test3").into();

        // Add first leaf
        let mut proof_list = Vec::new();
        mmr.add_leaf_updating_proof_list(hash1, &mut proof_list)
            .unwrap();
        // Add second leaf
        let proof2 = mmr
            .add_leaf_updating_proof_list(hash2, &mut proof_list)
            .unwrap();
        mmr.add_leaf_updating_proof_list(hash3, &mut proof_list)
            .unwrap();

        (proof2, hash2)
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_raw_merkle_proof_ssz_roundtrip() {
        let (proof, _) = generate_proof_for_test();
        let raw_proof = proof.into_raw();

        // Convert to SSZ type
        let cohashes_vec: Vec<_> = raw_proof
            .cohashes()
            .iter()
            .map(|h| FixedBytes::<32>::from(*h))
            .collect();
        let ssz_proof = RawMerkleProofB32 {
            cohashes: cohashes_vec.into(),
        };

        let encoded = ssz_proof.as_ssz_bytes();
        let decoded = RawMerkleProofB32::from_ssz_bytes(&encoded).expect("Failed to decode");

        assert_eq!(ssz_proof.cohashes.len(), decoded.cohashes.len());
        for (orig, dec) in ssz_proof.cohashes.iter().zip(decoded.cohashes.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_merkle_proof_ssz_roundtrip() {
        let (proof, _) = generate_proof_for_test();

        // Convert to SSZ type
        let cohashes_vec: Vec<_> = proof
            .cohashes()
            .iter()
            .map(|h| FixedBytes::<32>::from(*h))
            .collect();
        let ssz_proof = MerkleProofB32 {
            inner: RawMerkleProofB32 {
                cohashes: cohashes_vec.into(),
            },
            index: proof.index(),
        };

        let encoded = ssz_proof.as_ssz_bytes();
        let decoded = MerkleProofB32::from_ssz_bytes(&encoded).expect("Failed to decode");

        assert_eq!(ssz_proof.index, decoded.index);
        assert_eq!(ssz_proof.inner.cohashes.len(), decoded.inner.cohashes.len());
        for (orig, dec) in ssz_proof
            .inner
            .cohashes
            .iter()
            .zip(decoded.inner.cohashes.iter())
        {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_empty_proof_ssz() {
        let ssz_proof = MerkleProofB32 {
            inner: RawMerkleProofB32 {
                cohashes: vec![].into(),
            },
            index: 0,
        };

        let encoded = ssz_proof.as_ssz_bytes();
        let decoded = MerkleProofB32::from_ssz_bytes(&encoded).expect("Failed to decode");

        assert_eq!(ssz_proof.index, decoded.index);
        assert_eq!(ssz_proof.inner.cohashes.len(), 0);
        assert_eq!(decoded.inner.cohashes.len(), 0);
    }
}
