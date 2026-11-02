//! Object-safe MMR handle with the hasher fixed at construction.

use std::fmt;
use std::marker::PhantomData;

use strata_merkle::{MerkleHash, MerkleHasher, MerkleProof};

use super::error::MmrError;
use super::index::LeafPos;
use super::store::{MmrMetaPack, MmrNodeStore, StoredMmr, StoredMmrExt};

/// The full MMR API as a trait object.
///
/// [`StoredMmrExt`] names the hasher on every leaf write, and on a type-erased
/// store each node read inside the write is a dynamic call. This trait fixes
/// the hasher in the implementation instead, so every method is non-generic and
/// a `Box<dyn MmrHandle<H, Error = E>>` can read, write, prove, and prune
/// without naming the backend or the hasher.
///
/// [`HashedMmr`] implements it over any [`MmrNodeStore`]. Each call costs one
/// dynamic dispatch. The node reads and writes inside it are static, since
/// `HashedMmr` knows the concrete store.
///
/// Method semantics and errors match the [`StoredMmr`] or [`StoredMmrExt`]
/// method of the same name.
/// [`seed_from_peaks`](StoredMmrExt::seed_from_peaks) is left out because
/// [`MmrState`](strata_merkle::MmrState) is not object-safe. Seed the store
/// through [`HashedMmr::inner`] before erasing its type.
pub trait MmrHandle<H: MerkleHash> {
    /// The backend's storage error type.
    type Error;

    /// See [`StoredMmr::leaf_count`].
    fn leaf_count(&self) -> Result<u64, MmrError<Self::Error>>;

    /// See [`StoredMmr::pruned_before`].
    fn pruned_before(&self) -> Result<u64, MmrError<Self::Error>>;

    /// See [`StoredMmr::get_leaf`].
    fn get_leaf(&self, leaf_index: u64) -> Result<Option<H>, MmrError<Self::Error>>;

    /// See [`StoredMmrExt::append_leaf`].
    fn append_leaf(&self, value: H) -> Result<u64, MmrError<Self::Error>>;

    /// See [`StoredMmrExt::put_leaf`].
    fn put_leaf(&self, leaf_index: u64, value: H) -> Result<(), MmrError<Self::Error>>;

    /// See [`StoredMmrExt::prefill`].
    fn prefill(&self, target_count: u64, sentinel: H) -> Result<(), MmrError<Self::Error>>;

    /// See [`StoredMmr::generate_proof_at_idx`].
    fn generate_proof_at_idx(
        &self,
        leaf_index: u64,
    ) -> Result<MerkleProof<H>, MmrError<Self::Error>>;

    /// See [`StoredMmr::generate_proof_at_size`].
    fn generate_proof_at_size(
        &self,
        leaf_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProof<H>, MmrError<Self::Error>>;

    /// See [`StoredMmr::prune_before`].
    fn prune_before(&self, before: LeafPos) -> Result<(), MmrError<Self::Error>>;

    /// See [`StoredMmr::prune_after`].
    fn prune_after(&self, after: LeafPos) -> Result<(), MmrError<Self::Error>>;

    /// See [`StoredMmr::pop_leaf`].
    fn pop_leaf(&self) -> Result<Option<H>, MmrError<Self::Error>>;
}

/// An [`MmrNodeStore`] paired with the [`MerkleHasher`] that combines its
/// nodes, exposed as an [`MmrHandle`].
pub struct HashedMmr<S, MH> {
    store: S,
    // `fn() -> MH` keeps `Send`/`Sync` independent of the hasher type.
    _hasher: PhantomData<fn() -> MH>,
}

impl<S, MH> HashedMmr<S, MH> {
    /// Wraps `store`, combining nodes with `MH` on every leaf write.
    pub fn new(store: S) -> Self {
        Self {
            store,
            _hasher: PhantomData,
        }
    }

    /// Returns the wrapped store.
    pub fn inner(&self) -> &S {
        &self.store
    }

    /// Unwraps the store.
    pub fn into_inner(self) -> S {
        self.store
    }
}

impl<S: fmt::Debug, MH> fmt::Debug for HashedMmr<S, MH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashedMmr")
            .field("store", &self.store)
            .finish()
    }
}

impl<S, MH> MmrHandle<S::Hash> for HashedMmr<S, MH>
where
    S: MmrNodeStore,
    S::Hash: MmrMetaPack,
    MH: MerkleHasher<Hash = S::Hash>,
{
    type Error = S::Error;

    fn leaf_count(&self) -> Result<u64, MmrError<S::Error>> {
        self.store.leaf_count()
    }

    fn pruned_before(&self) -> Result<u64, MmrError<S::Error>> {
        self.store.pruned_before()
    }

    fn get_leaf(&self, leaf_index: u64) -> Result<Option<S::Hash>, MmrError<S::Error>> {
        self.store.get_leaf(leaf_index)
    }

    fn append_leaf(&self, value: S::Hash) -> Result<u64, MmrError<S::Error>> {
        self.store.append_leaf::<MH>(value)
    }

    fn put_leaf(&self, leaf_index: u64, value: S::Hash) -> Result<(), MmrError<S::Error>> {
        self.store.put_leaf::<MH>(leaf_index, value)
    }

    fn prefill(&self, target_count: u64, sentinel: S::Hash) -> Result<(), MmrError<S::Error>> {
        self.store.prefill::<MH>(target_count, sentinel)
    }

    fn generate_proof_at_idx(
        &self,
        leaf_index: u64,
    ) -> Result<MerkleProof<S::Hash>, MmrError<S::Error>> {
        self.store.generate_proof_at_idx(leaf_index)
    }

    fn generate_proof_at_size(
        &self,
        leaf_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProof<S::Hash>, MmrError<S::Error>> {
        self.store.generate_proof_at_size(leaf_index, at_leaf_count)
    }

    fn prune_before(&self, before: LeafPos) -> Result<(), MmrError<S::Error>> {
        self.store.prune_before(before)
    }

    fn prune_after(&self, after: LeafPos) -> Result<(), MmrError<S::Error>> {
        self.store.prune_after(after)
    }

    fn pop_leaf(&self) -> Result<Option<S::Hash>, MmrError<S::Error>> {
        self.store.pop_leaf()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use strata_merkle::{CompactMmr64, Mmr, Sha256Hasher};

    use super::*;
    use crate::memory::MemMmr;

    type Hash32 = [u8; 32];

    fn leaf(i: u64) -> Hash32 {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_be_bytes());
        h[31] = 0xab;
        h
    }

    fn erased() -> Box<dyn MmrHandle<Hash32, Error = Infallible>> {
        Box::new(HashedMmr::<_, Sha256Hasher>::new(
            MemMmr::<Hash32>::default(),
        ))
    }

    #[test]
    fn writes_and_proves_through_trait_object() {
        let mmr = erased();
        let mut reference = CompactMmr64::<Hash32>::new(64);
        for i in 0..7 {
            assert_eq!(mmr.append_leaf(leaf(i)).unwrap(), i);
            Mmr::<Sha256Hasher>::add_leaf(&mut reference, leaf(i)).unwrap();
        }
        assert_eq!(mmr.leaf_count().unwrap(), 7);
        assert_eq!(mmr.get_leaf(3).unwrap(), Some(leaf(3)));
        for i in 0..7 {
            let proof = mmr.generate_proof_at_idx(i).unwrap();
            assert!(reference.verify::<Sha256Hasher>(&proof, &leaf(i)));
        }

        mmr.put_leaf(2, leaf(100)).unwrap();
        assert_eq!(mmr.get_leaf(2).unwrap(), Some(leaf(100)));
    }

    #[test]
    fn prefill_prune_and_pop_through_trait_object() {
        let mmr = erased();
        mmr.prefill(4, leaf(0xff)).unwrap();
        mmr.append_leaf(leaf(4)).unwrap();

        mmr.prune_before(LeafPos::new(2)).unwrap();
        assert_eq!(mmr.pruned_before().unwrap(), 2);
        assert!(matches!(
            mmr.generate_proof_at_idx(0),
            Err(MmrError::Pruned { index: 0, .. })
        ));

        assert_eq!(mmr.pop_leaf().unwrap(), Some(leaf(4)));
        mmr.prune_after(LeafPos::new(3)).unwrap();
        assert_eq!(mmr.leaf_count().unwrap(), 3);
    }

    #[test]
    fn matches_stored_mmr() {
        let handle = HashedMmr::<_, Sha256Hasher>::new(MemMmr::<Hash32>::default());
        let direct = MemMmr::<Hash32>::default();
        for i in 0..5 {
            MmrHandle::append_leaf(&handle, leaf(i)).unwrap();
            direct.append_leaf::<Sha256Hasher>(leaf(i)).unwrap();
        }
        assert_eq!(handle.inner(), &direct);
    }
}
