//! The storage backend trait and the derived MMR API.

use super::algorithm::{assemble_proof, proof_positions, write_plan};
use super::error::MmrError;
use super::index::NodePos;
use crate::hasher::{MerkleHash, MerkleHasher};
use crate::proof::MerkleProof;

/// Reserved metadata tag holding the leaf count (== next leaf index).
const NEXT_INDEX_TAG: u64 = 0;

/// Reversible packing of a `u64` into a hash-sized metadata value.
///
/// The node store keeps its leaf count in a reserved metadata slot that holds a
/// `Hash`-typed value like any node, so the backend stays a two-method
/// key→hash map. This trait packs the count into (and out of) that value.
///
/// Blanket-implemented for every `[u8; N]` with `N >= 8`, which covers every
/// [`MerkleHash`] in this crate.
pub trait MmrMetaPack: MerkleHash {
    /// Packs `value` into a hash-sized metadata value.
    fn pack_u64(value: u64) -> Self;

    /// Recovers the `u64` previously stored by [`pack_u64`](Self::pack_u64).
    fn unpack_u64(&self) -> u64;
}

impl<const N: usize> MmrMetaPack for [u8; N] {
    fn pack_u64(value: u64) -> Self {
        // Every real hash is at least 8 bytes; the count rides in the leading 8.
        let mut bytes = [0u8; N];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn unpack_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self[..8]);
        u64::from_le_bytes(bytes)
    }
}

/// Storage backend for MMR nodes.
///
/// An implementor writes only [`get_node`](Self::get_node) and
/// [`put_node`](Self::put_node); [`get_nodes`](Self::get_nodes) and
/// [`commit`](Self::commit) have correct defaults that a backend may override
/// for batching/atomicity. One backend instance corresponds to one MMR — any
/// namespacing is the implementor's concern and invisible here.
///
/// The derived leaf/proof API lives in [`StoredMmr`], which is
/// blanket-implemented for every `MmrNodeStore`; callers use that and never
/// call `put_node`.
pub trait MmrNodeStore {
    /// The hash type stored at each node.
    type Hash: MerkleHash;

    /// The backend's storage error type.
    type Error;

    /// Returns the node stored at `pos`, if present.
    fn get_node(&self, pos: NodePos) -> Result<Option<Self::Hash>, Self::Error>;

    /// Stores `value` at `pos`.
    fn put_node(&self, pos: NodePos, value: Self::Hash) -> Result<(), Self::Error>;

    /// Reads several nodes in one call.
    ///
    /// The default loops [`get_node`](Self::get_node); backends with a native
    /// multi-get should override it for a single round-trip.
    fn get_nodes(&self, positions: &[NodePos]) -> Result<Vec<Option<Self::Hash>>, Self::Error> {
        positions.iter().map(|pos| self.get_node(*pos)).collect()
    }

    /// Writes all `writes` together.
    ///
    /// The default loops [`put_node`](Self::put_node); transactional backends
    /// should override it so a leaf write (leaf + ancestors + leaf-count) is
    /// atomic.
    fn commit(&self, writes: &[(NodePos, Self::Hash)]) -> Result<(), Self::Error> {
        for (pos, value) in writes {
            self.put_node(*pos, *value)?;
        }
        Ok(())
    }
}

/// The derived MMR API over any [`MmrNodeStore`], parameterized by the
/// [`MerkleHasher`] used to combine nodes.
///
/// Blanket-implemented for every backend whose stored hash matches the hasher's
/// hash type; callers use these methods and never touch
/// [`MmrNodeStore::put_node`] directly. Because the trait is generic over the
/// hasher, call sites disambiguate with a turbofish, e.g.
/// `StoredMmr::<Sha256Hasher>::append_leaf(&store, value)`.
pub trait StoredMmr<MH: MerkleHasher>: MmrNodeStore<Hash = MH::Hash>
where
    MH::Hash: MmrMetaPack,
{
    /// Returns the number of leaves (== the next leaf index).
    ///
    /// `O(1)`: reads the reserved leaf-count metadata slot.
    fn leaf_count(&self) -> Result<u64, MmrError<Self::Error>> {
        Ok(self
            .get_node(NodePos::meta(NEXT_INDEX_TAG))
            .map_err(MmrError::Backend)?
            .map(|h| h.unpack_u64())
            .unwrap_or(0))
    }

    /// Reads the leaf hash at `leaf_index`, if present.
    fn get_leaf(&self, leaf_index: u64) -> Result<Option<MH::Hash>, MmrError<Self::Error>> {
        self.get_node(NodePos::new(0, leaf_index))
            .map_err(MmrError::Backend)
    }

    /// Appends `value` as a new leaf at the end and returns its index.
    ///
    /// Convenience over [`put_leaf`](Self::put_leaf) at the current end.
    fn append_leaf(&self, value: MH::Hash) -> Result<u64, MmrError<Self::Error>> {
        let index = <Self as StoredMmr<MH>>::leaf_count(self)?;
        <Self as StoredMmr<MH>>::put_leaf(self, index, value)?;
        Ok(index)
    }

    /// Writes `value` as the leaf at `leaf_index`, recomputing its ancestors.
    ///
    /// `leaf_index` may be the current end (an append, which extends the leaf
    /// count) or an existing index (an overwrite). The leaf, its recomputed
    /// ancestors, and any leaf-count bump are written in a single
    /// [`commit`](MmrNodeStore::commit).
    ///
    /// Errors with [`MmrError::LeafGap`] if `leaf_index` is past the append
    /// point (`> leaf_count`), which would skip the leaves in between, and with
    /// [`MmrError::MaxCapacity`] if the store is already at the `u64::MAX` leaf
    /// ceiling. A [`MmrError::NodeMissing`] instead signals a corrupt store: a
    /// sibling required by an in-range write is absent.
    fn put_leaf(&self, leaf_index: u64, value: MH::Hash) -> Result<(), MmrError<Self::Error>> {
        let old_count = <Self as StoredMmr<MH>>::leaf_count(self)?;
        // Only an overwrite (`< old_count`) or an append (`== old_count`) is
        // valid. Writing further out would leave a hole that the sibling reads
        // in `write_plan` don't always catch: an isolated height-0 peak (e.g.
        // leaf 4 in a 5-leaf MMR) recomputes no ancestors, so the gap would
        // commit silently. Reject the whole range explicitly.
        if leaf_index > old_count {
            return Err(MmrError::LeafGap {
                index: leaf_index,
                leaf_count: old_count,
            });
        }
        // The writable range is `0..=old_count`, so the largest valid index is
        // `u64::MAX - 1` (a leaf at `u64::MAX` would imply a `u64::MAX + 1`
        // count). Reject a full store before the `+ 1` below overflows.
        let next_count = leaf_index.checked_add(1).ok_or(MmrError::MaxCapacity)?;
        let new_count = old_count.max(next_count);

        let mut writes =
            write_plan::<MH, _>(leaf_index, value, new_count, |pos| self.get_node(pos))?;
        if new_count != old_count {
            writes.push((NodePos::meta(NEXT_INDEX_TAG), MH::Hash::pack_u64(new_count)));
        }
        self.commit(&writes).map_err(MmrError::Backend)
    }

    /// Generates an inclusion proof for `leaf_index` against the current MMR
    /// size.
    fn generate_proof_at_idx(
        &self,
        leaf_index: u64,
    ) -> Result<MerkleProof<MH::Hash>, MmrError<Self::Error>> {
        let count = <Self as StoredMmr<MH>>::leaf_count(self)?;
        <Self as StoredMmr<MH>>::generate_proof_at_size(self, leaf_index, count)
    }

    /// Generates an inclusion proof for `leaf_index` against an MMR of exactly
    /// `at_leaf_count` leaves.
    ///
    /// Exact for any historical size: stored nodes are immutable under
    /// append-only use, so the proof path for `leaf_index` in a
    /// size-`at_leaf_count` MMR walks the same nodes regardless of later
    /// appends.
    fn generate_proof_at_size(
        &self,
        leaf_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProof<MH::Hash>, MmrError<Self::Error>> {
        if leaf_index >= at_leaf_count {
            return Err(MmrError::LeafOutOfRange {
                index: leaf_index,
                leaf_count: at_leaf_count,
            });
        }

        let positions = proof_positions(leaf_index, at_leaf_count);
        let fetched = self.get_nodes(&positions).map_err(MmrError::Backend)?;

        let mut cohashes = Vec::with_capacity(positions.len());
        for (pos, value) in positions.iter().zip(fetched) {
            cohashes.push(value.ok_or(MmrError::NodeMissing(*pos))?);
        }

        Ok(assemble_proof(leaf_index, cohashes))
    }

    /// Appends `sentinel` leaves until the MMR holds at least `target_count`.
    ///
    /// Idempotent. Used to align leaf indices with an external numbering (e.g.
    /// genesis prefill so leaf index equals L1 block height).
    fn prefill(&self, target_count: u64, sentinel: MH::Hash) -> Result<(), MmrError<Self::Error>> {
        let mut count = <Self as StoredMmr<MH>>::leaf_count(self)?;
        while count < target_count {
            <Self as StoredMmr<MH>>::append_leaf(self, sentinel)?;
            count += 1;
        }
        Ok(())
    }
}

impl<MH, T> StoredMmr<MH> for T
where
    MH: MerkleHasher,
    MH::Hash: MmrMetaPack,
    T: MmrNodeStore<Hash = MH::Hash> + ?Sized,
{
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use proptest::prelude::*;

    use super::*;
    use crate::legacy_compact_mmr::CompactMmr64;
    use crate::node_store::memory::MemMmr;
    use crate::proof::MerkleProof;
    use crate::{Mmr, Sha256Hasher};

    type Hash32 = [u8; 32];

    // The store is generic over the hasher; these helpers pin Sha256Hasher and
    // the in-memory backend so the tests read like the original concrete API.
    fn append(store: &MemMmr<Hash32>, value: Hash32) -> u64 {
        StoredMmr::<Sha256Hasher>::append_leaf(store, value).unwrap()
    }

    fn put(
        store: &MemMmr<Hash32>,
        index: u64,
        value: Hash32,
    ) -> Result<(), MmrError<std::convert::Infallible>> {
        StoredMmr::<Sha256Hasher>::put_leaf(store, index, value)
    }

    fn count(store: &MemMmr<Hash32>) -> u64 {
        StoredMmr::<Sha256Hasher>::leaf_count(store).unwrap()
    }

    fn read_leaf(store: &MemMmr<Hash32>, index: u64) -> Option<Hash32> {
        StoredMmr::<Sha256Hasher>::get_leaf(store, index).unwrap()
    }

    fn proof_at_size(store: &MemMmr<Hash32>, index: u64, size: u64) -> MerkleProof<Hash32> {
        StoredMmr::<Sha256Hasher>::generate_proof_at_size(store, index, size).unwrap()
    }

    /// Deterministic distinct leaf for the concrete (non-property) tests.
    fn leaf(i: u64) -> Hash32 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        bytes[31] = 0xAB;
        bytes
    }

    /// Strategy for a random 32-byte leaf value.
    fn leaf_bytes() -> impl Strategy<Value = Hash32> {
        prop::array::uniform32(any::<u8>())
    }

    /// Strategy for `(leaves, size, leaf_index)` with `len` in `len_range`,
    /// `1 <= size <= len`, and `leaf_index < size`.
    fn leaves_and_query(len_range: Range<usize>) -> impl Strategy<Value = (Vec<Hash32>, u64, u64)> {
        len_range
            .prop_flat_map(|len| (prop::collection::vec(leaf_bytes(), len..=len), 1usize..=len))
            .prop_flat_map(|(leaves, size)| (Just(leaves), Just(size), 0usize..size))
            .prop_map(|(leaves, size, index)| (leaves, size as u64, index as u64))
    }

    /// Reference compact-peaks MMR built by replaying `leaves`.
    fn reference_mmr(leaves: &[Hash32]) -> CompactMmr64<Hash32> {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        for value in leaves {
            Mmr::<Sha256Hasher>::add_leaf(&mut mmr, *value).unwrap();
        }
        mmr
    }

    // ---- concrete edge cases ----

    #[test]
    fn empty_mmr_has_no_leaves() {
        let mmr = MemMmr::<Hash32>::default();
        assert_eq!(count(&mmr), 0);
        assert_eq!(read_leaf(&mmr, 0), None);
    }

    #[test]
    fn append_returns_sequential_indices() {
        let mmr = MemMmr::<Hash32>::default();
        for i in 0..10 {
            assert_eq!(append(&mmr, leaf(i)), i);
        }
        assert_eq!(count(&mmr), 10);
    }

    #[test]
    fn out_of_range_proof_errors() {
        let mmr = MemMmr::<Hash32>::default();
        append(&mmr, leaf(0));
        assert!(matches!(
            StoredMmr::<Sha256Hasher>::generate_proof_at_size(&mmr, 1, 1),
            Err(MmrError::LeafOutOfRange {
                index: 1,
                leaf_count: 1
            })
        ));
    }

    #[test]
    fn put_leaf_past_end_is_rejected() {
        let mmr = MemMmr::<Hash32>::default();
        append(&mmr, leaf(0));
        // Index 5 is well past the append point (1).
        assert!(matches!(
            put(&mmr, 5, leaf(5)),
            Err(MmrError::LeafGap {
                index: 5,
                leaf_count: 1
            })
        ));

        // Regression: with 3 leaves, index 4 is the isolated height-0 peak of a
        // 5-leaf MMR, so `write_plan` reads no sibling and would otherwise
        // commit a gap (leaf 3 absent). The explicit range check must reject it
        // and leave the store untouched.
        let mmr = MemMmr::<Hash32>::default();
        for i in 0..3 {
            append(&mmr, leaf(i));
        }
        assert!(matches!(
            put(&mmr, 4, leaf(4)),
            Err(MmrError::LeafGap {
                index: 4,
                leaf_count: 3
            })
        ));
        assert_eq!(count(&mmr), 3);
        assert_eq!(read_leaf(&mmr, 4), None);

        // The append point itself (== count) is still allowed.
        put(&mmr, 3, leaf(3)).unwrap();
        assert_eq!(count(&mmr), 4);
    }

    #[test]
    fn append_at_capacity_is_rejected() {
        let mmr = MemMmr::<Hash32>::default();
        // Drive the leaf count to the u64 ceiling without materializing leaves;
        // append would then need index u64::MAX, whose `+ 1` overflows.
        mmr.put_node(
            NodePos::meta(NEXT_INDEX_TAG),
            <Hash32 as MmrMetaPack>::pack_u64(u64::MAX),
        )
        .unwrap();
        assert_eq!(count(&mmr), u64::MAX);
        assert!(matches!(
            StoredMmr::<Sha256Hasher>::append_leaf(&mmr, leaf(0)),
            Err(MmrError::MaxCapacity)
        ));
        // A direct put at the unwritable max index is rejected the same way.
        assert!(matches!(
            put(&mmr, u64::MAX, leaf(0)),
            Err(MmrError::MaxCapacity)
        ));
    }

    #[test]
    fn prefill_is_idempotent_and_counts() {
        let mmr = MemMmr::<Hash32>::default();
        StoredMmr::<Sha256Hasher>::prefill(&mmr, 5, leaf(0xff)).unwrap();
        assert_eq!(count(&mmr), 5);
        StoredMmr::<Sha256Hasher>::prefill(&mmr, 5, leaf(0xff)).unwrap();
        assert_eq!(count(&mmr), 5);
        StoredMmr::<Sha256Hasher>::prefill(&mmr, 8, leaf(0xff)).unwrap();
        assert_eq!(count(&mmr), 8);
    }

    /// Exhaustive, deterministic parity for small sizes: our proof's cohashes
    /// and index are identical to `strata-merkle`'s replay-based proof, and it
    /// verifies (while a tampered leaf does not). This is the load-bearing
    /// compatibility check.
    #[test]
    fn small_proofs_match_replay_reference() {
        for n in 1..=32u64 {
            let leaves: Vec<Hash32> = (0..n).map(leaf).collect();
            let mmr = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&mmr, *value);
            }

            let mut reference = CompactMmr64::<Hash32>::new(64);
            let mut proof_list = Vec::new();
            for value in &leaves {
                let proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                    &mut reference,
                    *value,
                    &mut proof_list,
                )
                .unwrap();
                proof_list.push(proof);
            }

            for idx in 0..n {
                let proof = proof_at_size(&mmr, idx, n);
                let ref_proof = &proof_list[idx as usize];
                assert_eq!(proof.cohashes(), ref_proof.cohashes(), "n={n} idx={idx}");
                assert_eq!(proof.index(), ref_proof.index(), "n={n} idx={idx}");
                assert!(reference.verify::<Sha256Hasher>(&proof, &leaves[idx as usize]));
                assert!(!reference.verify::<Sha256Hasher>(&proof, &leaf(idx + 1000)));
            }
        }
    }

    // ---- property tests ----

    proptest! {
        /// For any leaf set and any historical `(size, index)`, our proof
        /// verifies against the reference compact-peaks MMR at that size.
        #[test]
        fn proof_verifies_against_reference((leaves, size, index) in leaves_and_query(1..64)) {
            let mmr = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&mmr, *value);
            }
            let reference = reference_mmr(&leaves[..size as usize]);
            let proof = proof_at_size(&mmr, index, size);
            prop_assert!(reference.verify::<Sha256Hasher>(&proof, &leaves[index as usize]));
        }

        /// `append_leaf` is exactly `put_leaf` at the current end.
        #[test]
        fn append_equals_put_at_end(values in prop::collection::vec(leaf_bytes(), 0..64)) {
            let appended = MemMmr::<Hash32>::default();
            let put_store = MemMmr::<Hash32>::default();
            for (i, value) in values.iter().enumerate() {
                append(&appended, *value);
                put(&put_store, i as u64, *value).unwrap();
            }
            let n = values.len() as u64;
            prop_assert_eq!(count(&appended), count(&put_store));
            for idx in 0..n {
                let appended_proof = proof_at_size(&appended, idx, n);
                let put_proof = proof_at_size(&put_store, idx, n);
                prop_assert_eq!(appended_proof.cohashes(), put_proof.cohashes());
            }
        }

        /// Overwriting a leaf yields the same tree as rebuilding from scratch
        /// with that leaf changed.
        #[test]
        fn overwrite_equals_rebuild(
            (leaves, _size, index) in leaves_and_query(1..64),
            new_value in leaf_bytes(),
        ) {
            let n = leaves.len() as u64;
            let mmr = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&mmr, *value);
            }
            put(&mmr, index, new_value).unwrap();
            prop_assert_eq!(count(&mmr), n);
            prop_assert_eq!(read_leaf(&mmr, index).unwrap(), new_value);

            let rebuilt = MemMmr::<Hash32>::default();
            for (i, value) in leaves.iter().enumerate() {
                let v = if i as u64 == index { new_value } else { *value };
                append(&rebuilt, v);
            }
            for idx in 0..n {
                let mmr_proof = proof_at_size(&mmr, idx, n);
                let rebuilt_proof = proof_at_size(&rebuilt, idx, n);
                prop_assert_eq!(mmr_proof.cohashes(), rebuilt_proof.cohashes());
            }
        }

        /// A proof taken at `size` is unchanged by appends after `size`.
        #[test]
        fn historical_proof_unaffected_by_later_appends(
            (leaves, size, index) in leaves_and_query(1..64),
            extra in prop::collection::vec(leaf_bytes(), 0..32),
        ) {
            let mmr = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&mmr, *value);
            }
            let before = proof_at_size(&mmr, index, size);
            for value in &extra {
                append(&mmr, *value);
            }
            let after = proof_at_size(&mmr, index, size);
            prop_assert_eq!(before.cohashes(), after.cohashes());
        }
    }
}
