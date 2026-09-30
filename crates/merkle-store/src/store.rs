//! The storage backend trait and the derived MMR API.

use strata_merkle::{MerkleHash, MerkleHasher, MerkleProof};

use super::algorithm::{
    assemble_proof, iter_prune_after_positions, iter_prune_before_positions, proof_positions,
    write_plan,
};
use super::error::MmrError;
use super::index::{LeafPos, NodePos, peak_positions};

/// Reserved metadata tag holding the leaf count (== next leaf index).
const NEXT_INDEX_TAG: u64 = 0;

/// Reserved metadata tag holding the prune watermark: every leaf below this
/// index has been discarded by [`prune_before`](StoredMmr::prune_before) and can
/// no longer be proven. Absent (the default) means `0` — nothing pruned.
const PRUNED_BEFORE_TAG: u64 = 1;

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
        // Big-endian keeps every multi-byte integer in this module encoded the
        // same way as `NodePos::to_key`.
        let mut bytes = [0u8; N];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn unpack_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self[..8]);
        u64::from_be_bytes(bytes)
    }
}

/// Storage backend for MMR nodes.
///
/// An implementor writes [`get_node`](Self::get_node),
/// [`put_node`](Self::put_node), and [`delete_node`](Self::delete_node);
/// [`get_nodes`](Self::get_nodes) and [`commit`](Self::commit) have correct
/// defaults that a backend may override for batching/atomicity. One backend
/// instance corresponds to one MMR — any namespacing is the implementor's
/// concern and invisible here.
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
    ///
    /// Overwriting a node that is already present is not an error.
    fn put_node(&self, pos: NodePos, value: Self::Hash) -> Result<(), Self::Error>;

    /// Removes the node at `pos`.
    ///
    /// Idempotent: removing a node that is absent is not an error.
    fn delete_node(&self, pos: NodePos) -> Result<(), Self::Error>;

    /// Reads several nodes in one call.
    ///
    /// The default loops [`get_node`](Self::get_node); backends with a native
    /// multi-get should override it for a single round-trip.
    fn get_nodes(&self, positions: &[NodePos]) -> Result<Vec<Option<Self::Hash>>, Self::Error> {
        positions.iter().map(|pos| self.get_node(*pos)).collect()
    }

    /// Applies `writes` and `deletes` as one batch: every position in `writes`
    /// is stored and every position in `deletes` is removed.
    ///
    /// The derived MMR ops use this as their sole mutation path — a leaf write
    /// (leaf + ancestors + leaf-count) or a prune (node deletes + watermark/count
    /// update) is handed to a single `commit` call. Transactional backends should
    /// override it so the whole batch lands atomically; the default loops
    /// [`delete_node`](Self::delete_node) then [`put_node`](Self::put_node).
    ///
    /// Durability and atomicity are the backend's concern: a persistent backend
    /// is expected to override this so the whole batch lands as one unit. The
    /// in-memory default loops [`delete_node`](Self::delete_node) then
    /// [`put_node`](Self::put_node) — applying deletes before writes — which
    /// pins down one thing callers rely on: if a position appears in both
    /// `deletes` and `writes`, the write wins (the node ends up stored, not
    /// removed). The derived ops never pass overlapping sets, but defining the
    /// resolution rather than leaving it to the backend keeps an overriding
    /// backend consistent with the default.
    fn commit(
        &self,
        writes: &[(NodePos, Self::Hash)],
        deletes: &[NodePos],
    ) -> Result<(), Self::Error> {
        for pos in deletes {
            self.delete_node(*pos)?;
        }
        for (pos, value) in writes {
            self.put_node(*pos, *value)?;
        }
        Ok(())
    }
}

/// The derived MMR API over any [`MmrNodeStore`].
///
/// Blanket-implemented for every backend whose stored hash is
/// [`MmrMetaPack`]; callers use these methods and never touch
/// [`MmrNodeStore::put_node`] directly. Only the leaf-writing methods
/// ([`put_leaf`](Self::put_leaf), [`append_leaf`](Self::append_leaf), and
/// [`prefill`](Self::prefill)) recompute ancestors, so only they are generic
/// over the [`MerkleHasher`] used to combine nodes — and only they need a
/// turbofish, e.g. `store.put_leaf::<Sha256Hasher>(index, value)`. Every other
/// method works on the stored [`Hash`](MmrNodeStore::Hash) alone.
pub trait StoredMmr: MmrNodeStore
where
    Self::Hash: MmrMetaPack,
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

    /// Returns the prune watermark: every leaf with index `< pruned_before` has
    /// been discarded by [`prune_before`](Self::prune_before) and can no longer
    /// be proven. `0` (the default) means nothing has been pruned.
    ///
    /// `O(1)`: reads the reserved watermark metadata slot.
    fn pruned_before(&self) -> Result<u64, MmrError<Self::Error>> {
        Ok(self
            .get_node(NodePos::meta(PRUNED_BEFORE_TAG))
            .map_err(MmrError::Backend)?
            .map(|h| h.unpack_u64())
            .unwrap_or(0))
    }

    /// Reads the leaf hash at `leaf_index`, if present.
    fn get_leaf(&self, leaf_index: u64) -> Result<Option<Self::Hash>, MmrError<Self::Error>> {
        self.get_node(NodePos::new(0, leaf_index))
            .map_err(MmrError::Backend)
    }

    /// Appends `value` as a new leaf at the end and returns its index.
    ///
    /// Convenience over [`put_leaf`](Self::put_leaf) at the current end.
    fn append_leaf<MH>(&self, value: Self::Hash) -> Result<u64, MmrError<Self::Error>>
    where
        Self: Sized,
        MH: MerkleHasher<Hash = Self::Hash>,
    {
        let index = self.leaf_count()?;
        self.put_leaf::<MH>(index, value)?;
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
    /// point (`> leaf_count`), which would skip the leaves in between, with
    /// [`MmrError::Pruned`] if it is an overwrite below the prune watermark (see
    /// below), and with [`MmrError::MaxCapacity`] if the store is already at the
    /// `u64::MAX` leaf ceiling. A [`MmrError::NodeMissing`] instead signals a
    /// corrupt store: a sibling required by an in-range write is absent.
    fn put_leaf<MH>(&self, leaf_index: u64, value: Self::Hash) -> Result<(), MmrError<Self::Error>>
    where
        Self: Sized,
        MH: MerkleHasher<Hash = Self::Hash>,
    {
        let old_count = self.leaf_count()?;
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
        // Reject an overwrite below the prune watermark. A pruned leaf's node
        // can physically survive when a later leaf needs it as a sibling cohash:
        // with 6 leaves, leaf 4 and leaf 5 share peak (1,2), so `prune_before(5)`
        // keeps leaf 4 even though it marks it pruned. Overwriting leaf 4 would
        // walk up and recompute (1,2) from the surviving leaf 5, silently
        // changing the root and leaf 5's proof — yet leaf 5 was never pruned.
        // An append (`leaf_index == old_count`) is always at or above the
        // watermark (which never exceeds the leaf count), so this only ever
        // fires on an overwrite.
        let pruned_before = self.pruned_before()?;
        if leaf_index < pruned_before {
            return Err(MmrError::Pruned {
                index: leaf_index,
                pruned_before,
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
        self.commit(&writes, &[]).map_err(MmrError::Backend)
    }

    /// Generates an inclusion proof for `leaf_index` against the current MMR
    /// size.
    fn generate_proof_at_idx(
        &self,
        leaf_index: u64,
    ) -> Result<MerkleProof<Self::Hash>, MmrError<Self::Error>> {
        let count = self.leaf_count()?;
        self.generate_proof_at_size(leaf_index, count)
    }

    /// Generates an inclusion proof for `leaf_index` against an MMR of exactly
    /// `at_leaf_count` leaves.
    ///
    /// Exact for any retained historical size: a stored node's hash covers a
    /// fixed leaf range and never changes under appends, so the proof path for
    /// `leaf_index` in a size-`at_leaf_count` MMR walks the same nodes
    /// regardless of later appends.
    ///
    /// Errors with [`MmrError::LeafOutOfRange`] if `at_leaf_count` exceeds the
    /// store's current [`leaf_count`](Self::leaf_count): the immutability above
    /// only holds for sizes the store still retains, and
    /// [`prune_after`](Self::prune_after) can truncate leaves off the top.
    /// The hazard this prevents is not a malformed proof but a *valid* one: a
    /// truncated-away leaf that is a lone peak at `at_leaf_count` has an empty
    /// proof path, so it slips past the missing-node check below and assembles
    /// into a proof that still verifies against the (now-abandoned) size-
    /// `at_leaf_count` root. The store would thus vouch for a leaf it
    /// deliberately rolled back, with nothing to signal the state is gone. The
    /// guard makes the store vend proofs only against sizes it still holds.
    ///
    /// Errors with [`MmrError::Pruned`] if `leaf_index` is below the store's
    /// prune watermark (see [`prune_before`](Self::prune_before)): the nodes
    /// were deliberately discarded, so this is reported distinctly from a
    /// [`MmrError::NodeMissing`] corruption.
    fn generate_proof_at_size(
        &self,
        leaf_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProof<Self::Hash>, MmrError<Self::Error>> {
        if leaf_index >= at_leaf_count {
            return Err(MmrError::LeafOutOfRange {
                index: leaf_index,
                leaf_count: at_leaf_count,
            });
        }

        let leaf_count = self.leaf_count()?;
        if at_leaf_count > leaf_count {
            return Err(MmrError::LeafOutOfRange {
                index: at_leaf_count - 1,
                leaf_count,
            });
        }

        // A leaf below the watermark had its path discarded by `prune_before`;
        // report that intent rather than letting the missing-node read below
        // surface as `NodeMissing`, which a caller reads as corruption.
        let pruned_before = self.pruned_before()?;
        if leaf_index < pruned_before {
            return Err(MmrError::Pruned {
                index: leaf_index,
                pruned_before,
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
    fn prefill<MH>(
        &self,
        target_count: u64,
        sentinel: Self::Hash,
    ) -> Result<(), MmrError<Self::Error>>
    where
        Self: Sized,
        MH: MerkleHasher<Hash = Self::Hash>,
    {
        let mut count = self.leaf_count()?;
        while count < target_count {
            self.append_leaf::<MH>(sentinel)?;
            count += 1;
        }
        Ok(())
    }

    /// Prunes every node strictly before `before`, retaining only the peaks of
    /// the first `before.index()` leaves, and raises the prune watermark.
    ///
    /// Those peaks are the minimal set still required to prove leaves at or
    /// after `before` and to keep appending, so both continue to work; proofs
    /// for the *pruned* leaves afterward fail with [`MmrError::Pruned`]. The
    /// leaf count is unchanged. A `before` of `0` prunes nothing; one equal to
    /// the leaf count compacts the whole MMR down to its current peaks. The
    /// watermark is monotonic: a `before` at or below the current watermark only
    /// re-deletes already-pruned nodes and leaves the watermark untouched.
    ///
    /// Errors with [`MmrError::LeafOutOfRange`] if `before` is past the append
    /// point (`> leaf_count`).
    ///
    /// Note: the set of node positions to delete is materialized in full (into a
    /// `Vec`) before it is handed to [`commit`](MmrNodeStore::commit), so a single
    /// prune over a long-lived MMR allocates memory proportional to the number of
    /// removed nodes. The watermark is monotonic and the delete set idempotent, so
    /// a consumer that needs to bound peak memory can prune in steps — repeated
    /// calls advancing `before` — and converge to the same state. Bounding it that
    /// way is left to the consumer.
    ///
    /// The node deletes and the watermark write are handed to a single
    /// [`commit`](MmrNodeStore::commit), so a transactional backend applies them
    /// atomically. The operation is also idempotent on its own: the watermark is
    /// monotonic and the delete set recomputes identically, so re-running the
    /// same call converges to the same state.
    fn prune_before(&self, before: LeafPos) -> Result<(), MmrError<Self::Error>> {
        let leaf_count = self.leaf_count()?;
        let before_index = before.index();
        if before_index > leaf_count {
            return Err(MmrError::LeafOutOfRange {
                index: before_index,
                leaf_count,
            });
        }
        let positions: Vec<NodePos> = iter_prune_before_positions(before_index).collect();
        // Raise the watermark (monotonically) in the same commit as the deletes.
        let watermark = self.pruned_before()?;
        let writes: &[(NodePos, Self::Hash)] = &[(
            NodePos::meta(PRUNED_BEFORE_TAG),
            Self::Hash::pack_u64(before_index),
        )];
        let writes = if before_index > watermark {
            writes
        } else {
            &[]
        };
        self.commit(writes, &positions).map_err(MmrError::Backend)
    }

    /// Truncates the MMR to its first `after.index()` leaves, removing that leaf
    /// and every leaf after it together with their now-unreachable ancestors,
    /// and updates the stored leaf count.
    ///
    /// The retained nodes are exactly those of a freshly built MMR of
    /// `after.index()` leaves (a surviving node covers the same leaves, so its
    /// stored hash is unchanged), so the truncated store behaves identically to
    /// one that was only ever that size. An `after` equal to the leaf count is a
    /// no-op (nothing past the end); one of `0` empties the store. If a prior
    /// [`prune_before`](Self::prune_before) left the watermark above the new
    /// count, it is clamped down to it.
    ///
    /// Errors with [`MmrError::LeafOutOfRange`] if `after` is past the append
    /// point (`> leaf_count`), and with [`MmrError::Pruned`] if `keep` falls
    /// inside a prefix an earlier `prune_before` already discarded: the new MMR
    /// would need the peaks of its first `keep` leaves to stay appendable, and
    /// `prune_before` keeps only the peaks of *its own* cut, so a deeper cut can
    /// have removed them. Truncating onto a missing prefix would leave a store
    /// that reports the right leaf count yet cannot append, so it is rejected;
    /// `keep` at or above the watermark always has its prefix peaks intact.
    ///
    /// Note: like [`prune_before`](Self::prune_before), the delete set is
    /// materialized in full before the [`commit`](MmrNodeStore::commit). A single
    /// truncation that drops a huge suffix therefore allocates proportionally; a
    /// consumer bounding peak memory should truncate in steps.
    ///
    /// The node deletes and the leaf-count write are handed to a single
    /// [`commit`](MmrNodeStore::commit), so a transactional backend applies them
    /// atomically. The operation is also idempotent on its own: the delete set
    /// recomputes identically and the count and watermark settle to the same
    /// values, so re-running the same call converges to the same state.
    fn prune_after(&self, after: LeafPos) -> Result<(), MmrError<Self::Error>> {
        let leaf_count = self.leaf_count()?;
        let keep = after.index();
        if keep > leaf_count {
            return Err(MmrError::LeafOutOfRange {
                index: keep,
                leaf_count,
            });
        }
        if keep == leaf_count {
            return Ok(());
        }
        // The truncated store must still be appendable, which needs the peaks of
        // a `keep`-leaf MMR. A `prune_before` past `keep` can have discarded some
        // of them, so a `keep` below the watermark may have no intact prefix to
        // truncate onto; probe those peaks and reject the truncation if any is
        // gone, rather than commit an unappendable store. At or above the
        // watermark the peaks are always retained, so skip the probe.
        let watermark = self.pruned_before()?;
        if keep < watermark {
            let peaks: Vec<NodePos> = peak_positions(keep).collect();
            let present = self.get_nodes(&peaks).map_err(MmrError::Backend)?;
            if present.iter().any(Option::is_none) {
                return Err(MmrError::Pruned {
                    index: keep,
                    pruned_before: watermark,
                });
            }
        }
        let positions: Vec<NodePos> = iter_prune_after_positions(keep, leaf_count).collect();
        // Clamp the watermark to the new count, since no leaf at or above `keep`
        // survives to be reported `Pruned`. Order the writes so the leaf count is
        // the last write: it is the marker that "commits" the truncation, so an
        // interrupted prune that has not yet lowered it re-runs identically.
        let mut writes = Vec::with_capacity(2);
        if watermark > keep {
            writes.push((NodePos::meta(PRUNED_BEFORE_TAG), Self::Hash::pack_u64(keep)));
        }
        writes.push((NodePos::meta(NEXT_INDEX_TAG), Self::Hash::pack_u64(keep)));
        self.commit(&writes, &positions).map_err(MmrError::Backend)
    }

    /// Removes the last leaf and returns its value, or `None` if the MMR is
    /// already empty.
    ///
    /// The inverse of [`append_leaf`](Self::append_leaf), and a convenience over
    /// [`prune_after`](Self::prune_after) at `leaf_count - 1`: it drops the final
    /// leaf together with its now-unreachable ancestors and lowers the leaf count
    /// by one.
    ///
    /// The returned value is the leaf hash read just before removal. It is `None`
    /// when the store is empty, but also — distinct only by the count it leaves
    /// behind — when a prior [`prune_before`](Self::prune_before) had already
    /// discarded that leaf's hash (folded into a surviving peak) even though the
    /// count is non-zero; the pop still happens in that case.
    ///
    /// Errors with [`MmrError::Pruned`] (from [`prune_after`](Self::prune_after))
    /// when removing the last leaf would truncate onto a prefix whose peaks an
    /// earlier `prune_before` discarded: the shorter MMR could not be appended to,
    /// so the pop is refused rather than left to corrupt the store. Whether it
    /// errors depends on the cut's shape, not merely on a leaf hash being gone —
    /// a pop can still succeed (returning `None`) when the shorter prefix's peaks
    /// happen to survive.
    fn pop_leaf(&self) -> Result<Option<Self::Hash>, MmrError<Self::Error>> {
        let leaf_count = self.leaf_count()?;
        let Some(last_index) = leaf_count.checked_sub(1) else {
            return Ok(None);
        };
        let value = self.get_leaf(last_index)?;
        self.prune_after(LeafPos::new(last_index))?;
        Ok(value)
    }
}

impl<T> StoredMmr for T
where
    T: MmrNodeStore + ?Sized,
    T::Hash: MmrMetaPack,
{
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use proptest::prelude::*;
    use strata_merkle::{CompactMmr64, MerkleProof, Mmr, Sha256Hasher};

    use super::*;
    use crate::memory::MemMmr;

    type Hash32 = [u8; 32];

    // Only the leaf-writing helpers pin Sha256Hasher (via a method turbofish);
    // the rest call the hasher-free API directly on the in-memory backend.
    fn append(store: &MemMmr<Hash32>, value: Hash32) -> u64 {
        store.append_leaf::<Sha256Hasher>(value).unwrap()
    }

    fn put(
        store: &MemMmr<Hash32>,
        index: u64,
        value: Hash32,
    ) -> Result<(), MmrError<std::convert::Infallible>> {
        store.put_leaf::<Sha256Hasher>(index, value)
    }

    fn count(store: &MemMmr<Hash32>) -> u64 {
        store.leaf_count().unwrap()
    }

    fn read_leaf(store: &MemMmr<Hash32>, index: u64) -> Option<Hash32> {
        store.get_leaf(index).unwrap()
    }

    fn proof_at_size(store: &MemMmr<Hash32>, index: u64, size: u64) -> MerkleProof<Hash32> {
        store.generate_proof_at_size(index, size).unwrap()
    }

    fn prune_before(store: &MemMmr<Hash32>, before: u64) {
        store.prune_before(LeafPos::new(before)).unwrap();
    }

    fn prune_after(store: &MemMmr<Hash32>, after: u64) {
        store.prune_after(LeafPos::new(after)).unwrap();
    }

    fn pop(store: &MemMmr<Hash32>) -> Option<Hash32> {
        store.pop_leaf().unwrap()
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

    /// The hasher-free read/proof/prune API must stay dyn-compatible
    #[test]
    fn read_api_is_dyn_compatible() {
        let mmr = MemMmr::<Hash32>::default();
        append(&mmr, leaf(0));
        let store: &dyn StoredMmr<Hash = Hash32, Error = std::convert::Infallible> = &mmr;
        assert_eq!(store.leaf_count().unwrap(), 1);
        assert_eq!(store.get_leaf(0).unwrap(), Some(leaf(0)));
        store.generate_proof_at_idx(0).unwrap();
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
            mmr.generate_proof_at_size(1, 1),
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
            mmr.append_leaf::<Sha256Hasher>(leaf(0)),
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
        mmr.prefill::<Sha256Hasher>(5, leaf(0xff)).unwrap();
        assert_eq!(count(&mmr), 5);
        mmr.prefill::<Sha256Hasher>(5, leaf(0xff)).unwrap();
        assert_eq!(count(&mmr), 5);
        mmr.prefill::<Sha256Hasher>(8, leaf(0xff)).unwrap();
        assert_eq!(count(&mmr), 8);
    }

    // ---- pruning ----

    /// `prune_after(k)` deletes exactly the out-of-range nodes, leaving a store
    /// whose surviving nodes and leaf count match a fresh `k`-leaf build, for
    /// every `(n, k)` in a small exhaustive grid.
    #[test]
    fn prune_after_matches_fresh_build() {
        for n in 1..=16u64 {
            for k in 0..=n {
                let leaves: Vec<Hash32> = (0..n).map(leaf).collect();

                let pruned = MemMmr::<Hash32>::default();
                for value in &leaves {
                    append(&pruned, *value);
                }
                prune_after(&pruned, k);

                let fresh = MemMmr::<Hash32>::default();
                for value in &leaves[..k as usize] {
                    append(&fresh, *value);
                }

                assert_eq!(count(&pruned), k, "leaf_count n={n} k={k}");
                if k < n {
                    assert_eq!(read_leaf(&pruned, k), None, "dropped leaf n={n} k={k}");
                }
                for idx in 0..k {
                    assert_eq!(
                        proof_at_size(&pruned, idx, k).cohashes(),
                        proof_at_size(&fresh, idx, k).cohashes(),
                        "n={n} k={k} idx={idx}"
                    );
                }
            }
        }
    }

    /// Appending after a `prune_after` rolls forward exactly as if the truncated
    /// leaves had never existed.
    #[test]
    fn prune_after_then_append_matches_continuous_build() {
        let leaves: Vec<Hash32> = (0..10).map(leaf).collect();
        let store = MemMmr::<Hash32>::default();
        for value in &leaves {
            append(&store, *value);
        }
        prune_after(&store, 6);

        let extra: Vec<Hash32> = (100..105).map(leaf).collect();
        for value in &extra {
            append(&store, *value);
        }

        let reference = MemMmr::<Hash32>::default();
        for value in leaves[..6].iter().chain(extra.iter()) {
            append(&reference, *value);
        }

        let total = 6 + extra.len() as u64;
        assert_eq!(count(&store), total);
        for idx in 0..total {
            assert_eq!(
                proof_at_size(&store, idx, total).cohashes(),
                proof_at_size(&reference, idx, total).cohashes(),
                "idx={idx}"
            );
        }
    }

    /// `prune_before(k)` removes exactly the descendants of the prefix peaks and
    /// leaves the rest intact: leaf count is unchanged and every leaf in
    /// `[k, n)` still verifies against the reference.
    #[test]
    fn prune_before_deletes_exactly_the_descendants() {
        for n in 1..=16u64 {
            for k in 0..=n {
                let leaves: Vec<Hash32> = (0..n).map(leaf).collect();
                let store = MemMmr::<Hash32>::default();
                for value in &leaves {
                    append(&store, *value);
                }

                let deletes: Vec<NodePos> = iter_prune_before_positions(k).collect();
                for pos in &deletes {
                    assert!(
                        store.get_node(*pos).unwrap().is_some(),
                        "pre n={n} k={k} {pos:?}"
                    );
                }

                prune_before(&store, k);
                assert_eq!(count(&store), n, "leaf_count unchanged n={n} k={k}");

                for pos in &deletes {
                    assert!(
                        store.get_node(*pos).unwrap().is_none(),
                        "post n={n} k={k} {pos:?}"
                    );
                }

                let reference = reference_mmr(&leaves);
                for idx in k..n {
                    let proof = proof_at_size(&store, idx, n);
                    assert!(
                        reference.verify::<Sha256Hasher>(&proof, &leaves[idx as usize]),
                        "verify n={n} k={k} idx={idx}"
                    );
                }
            }
        }
    }

    /// A leaf below the watermark left by `prune_before` reports `Pruned`, while
    /// a leaf at/after the cut still proves.
    #[test]
    fn prune_before_makes_pruned_leaf_unprovable() {
        let leaves: Vec<Hash32> = (0..4).map(leaf).collect();
        let store = MemMmr::<Hash32>::default();
        for value in &leaves {
            append(&store, *value);
        }
        // Peaks of the first 2 leaves are [(1,0)]; this drops leaves 0 and 1.
        prune_before(&store, 2);
        assert_eq!(store.pruned_before().unwrap(), 2);

        for idx in 0..2 {
            assert!(matches!(
                store.generate_proof_at_size(idx, 4),
                Err(MmrError::Pruned {
                    index,
                    pruned_before: 2,
                }) if index == idx
            ));
        }

        let reference = reference_mmr(&leaves);
        let proof = proof_at_size(&store, 2, 4);
        assert!(reference.verify::<Sha256Hasher>(&proof, &leaf(2)));
    }

    /// Overwriting a leaf below the watermark is rejected: `prune_before` keeps
    /// the pruned leaf's covering peak, so the overwrite would recompute that
    /// peak from a surviving sibling and corrupt the root/proof of an unpruned
    /// leaf that shares it (e.g. with 6 leaves, `prune_before(5)` retains leaf 4
    /// as the sibling that proves leaf 5).
    #[test]
    fn put_leaf_below_watermark_is_rejected() {
        let leaves: Vec<Hash32> = (0..6).map(leaf).collect();
        let store = MemMmr::<Hash32>::default();
        for value in &leaves {
            append(&store, *value);
        }
        prune_before(&store, 5);
        assert_eq!(store.pruned_before().unwrap(), 5);

        // Leaf 4 is below the watermark but its peak survives to prove leaf 5.
        assert!(matches!(
            put(&store, 4, leaf(0xaa)),
            Err(MmrError::Pruned {
                index: 4,
                pruned_before: 5,
            })
        ));
        // Leaf 5 (at/above the watermark) still verifies, unchanged.
        let reference = reference_mmr(&leaves);
        assert!(reference.verify::<Sha256Hasher>(&proof_at_size(&store, 5, 6), &leaf(5)));

        // Appending at the end is unaffected by the watermark.
        append(&store, leaf(6));
        assert_eq!(count(&store), 7);
    }

    /// The watermark only ever rises under `prune_before`, and `prune_after`
    /// clamps it down to a new, smaller leaf count.
    #[test]
    fn prune_watermark_is_monotonic_and_clamped() {
        let store = MemMmr::<Hash32>::default();
        for i in 0..8 {
            append(&store, leaf(i));
        }
        let watermark = || store.pruned_before().unwrap();

        prune_before(&store, 3);
        assert_eq!(watermark(), 3);
        // A smaller cut re-deletes already-pruned nodes but never lowers it.
        prune_before(&store, 1);
        assert_eq!(watermark(), 3);
        // A larger cut raises it.
        prune_before(&store, 5);
        assert_eq!(watermark(), 5);
        // Truncating below the watermark clamps it to the surviving leaf count.
        prune_after(&store, 4);
        assert_eq!(count(&store), 4);
        assert_eq!(watermark(), 4);
        // Emptying resets it.
        prune_after(&store, 0);
        assert_eq!(watermark(), 0);
    }

    /// Truncating onto a prefix that `prune_before` already discarded is
    /// rejected: with 4 leaves, `prune_before(4)` keeps only peak `(2,0)`, so
    /// `prune_after(3)` — which would need the peaks of a 3-leaf MMR (`(1,0)` and
    /// `(0,2)`, both gone) to stay appendable — fails with `Pruned` and leaves
    /// the store untouched. A truncation whose prefix peaks survive (here
    /// `prune_after(4)` after `prune_before(5)`, peak `(2,0)` intact) still works.
    #[test]
    fn prune_after_into_pruned_prefix_is_rejected() {
        let store = MemMmr::<Hash32>::default();
        for i in 0..4 {
            append(&store, leaf(i));
        }
        prune_before(&store, 4);
        assert!(matches!(
            store.prune_after(LeafPos::new(3)),
            Err(MmrError::Pruned {
                index: 3,
                pruned_before: 4
            })
        ));
        // Rejected before any mutation: count and watermark are unchanged.
        assert_eq!(count(&store), 4);
        assert_eq!(store.pruned_before().unwrap(), 4);

        // A cut whose prefix peaks survived the earlier `prune_before` is allowed.
        let store = MemMmr::<Hash32>::default();
        for i in 0..8 {
            append(&store, leaf(i));
        }
        prune_before(&store, 5); // keeps peaks of 5 leaves: (2,0) and (0,4)
        prune_after(&store, 4); // needs (2,0), which is intact
        assert_eq!(count(&store), 4);
    }

    /// A historical proof against a size the store has truncated away is
    /// rejected. With 5 leaves, `prune_after(4)` drops leaf 4 (a lone height-0
    /// peak at size 5), so its proof path is empty; without the size guard
    /// `generate_proof_at_size(4, 5)` would return a proof for the rolled-back
    /// leaf instead of erroring.
    #[test]
    fn proof_past_truncated_size_is_rejected() {
        let store = MemMmr::<Hash32>::default();
        for i in 0..5 {
            append(&store, leaf(i));
        }
        prune_after(&store, 4);
        assert_eq!(count(&store), 4);

        // Leaf 4 was a lone peak at size 5 (empty proof path), so it slips past
        // the missing-node check; the size guard must reject it.
        assert!(matches!(
            store.generate_proof_at_size(4, 5),
            Err(MmrError::LeafOutOfRange {
                index: 4,
                leaf_count: 4
            })
        ));
        // A still-retained leaf is rejected too when the requested size is gone.
        assert!(matches!(
            store.generate_proof_at_size(2, 5),
            Err(MmrError::LeafOutOfRange {
                index: 4,
                leaf_count: 4
            })
        ));
        // Proofs against the retained size still work.
        let reference = reference_mmr(&(0..4).map(leaf).collect::<Vec<_>>());
        assert!(reference.verify::<Sha256Hasher>(&proof_at_size(&store, 2, 4), &leaf(2)));
    }

    /// `prune_before(leaf_count)` compacts the whole MMR to its current peaks,
    /// and appends afterward still roll forward correctly.
    #[test]
    fn prune_before_full_compaction_keeps_only_peaks() {
        let n = 6u64; // peaks: (2,0), (1,2)
        let leaves: Vec<Hash32> = (0..n).map(leaf).collect();
        let store = MemMmr::<Hash32>::default();
        for value in &leaves {
            append(&store, *value);
        }
        prune_before(&store, n);
        assert_eq!(count(&store), n);

        for pos in crate::peak_positions(n) {
            assert!(store.get_node(pos).unwrap().is_some(), "peak {pos:?} kept");
        }
        for pos in iter_prune_before_positions(n) {
            assert!(
                store.get_node(pos).unwrap().is_none(),
                "non-peak {pos:?} gone"
            );
        }

        let extra = [leaf(100), leaf(101)];
        for value in &extra {
            append(&store, *value);
        }
        let reference = MemMmr::<Hash32>::default();
        for value in leaves.iter().chain(extra.iter()) {
            append(&reference, *value);
        }
        let total = n + extra.len() as u64;
        // Only the newly appended leaves remain provable after full compaction.
        for idx in n..total {
            assert_eq!(
                proof_at_size(&store, idx, total).cohashes(),
                proof_at_size(&reference, idx, total).cohashes(),
                "idx={idx}"
            );
        }
    }

    /// Boundary inputs: no-op prunes, emptying, and out-of-range rejection.
    #[test]
    fn prune_boundaries() {
        let leaves: Vec<Hash32> = (0..5).map(leaf).collect();
        let store = MemMmr::<Hash32>::default();
        for value in &leaves {
            append(&store, *value);
        }

        // prune_before(0) and prune_after(leaf_count) change nothing.
        prune_before(&store, 0);
        prune_after(&store, 5);
        assert_eq!(count(&store), 5);
        let reference = reference_mmr(&leaves);
        for idx in 0..5 {
            assert!(reference.verify::<Sha256Hasher>(&proof_at_size(&store, idx, 5), &leaf(idx)));
        }

        // prune_after(0) empties the store.
        prune_after(&store, 0);
        assert_eq!(count(&store), 0);
        assert_eq!(read_leaf(&store, 0), None);

        // A cut past the append point is rejected, leaving the store untouched.
        let store = MemMmr::<Hash32>::default();
        for value in leaves.iter().take(3) {
            append(&store, *value);
        }
        assert!(matches!(
            store.prune_before(LeafPos::new(4)),
            Err(MmrError::LeafOutOfRange {
                index: 4,
                leaf_count: 3
            })
        ));
        assert!(matches!(
            store.prune_after(LeafPos::new(4)),
            Err(MmrError::LeafOutOfRange {
                index: 4,
                leaf_count: 3
            })
        ));
        assert_eq!(count(&store), 3);
    }

    /// `pop_leaf` is the inverse of `append_leaf`: it returns the last value,
    /// shrinks the count by one, and an empty store pops `None`. Repeated pops
    /// unwind the MMR leaf-by-leaf, each leaving a store identical to one built
    /// only up to that point.
    #[test]
    fn pop_leaf_unwinds_appends() {
        let store = MemMmr::<Hash32>::default();
        assert_eq!(pop(&store), None);

        let n = 7u64;
        for i in 0..n {
            append(&store, leaf(i));
        }

        for k in (0..n).rev() {
            assert_eq!(pop(&store), Some(leaf(k)), "popped value k={k}");
            assert_eq!(count(&store), k, "count after pop k={k}");

            let fresh = MemMmr::<Hash32>::default();
            for i in 0..k {
                append(&fresh, leaf(i));
            }
            for idx in 0..k {
                assert_eq!(
                    proof_at_size(&store, idx, k).cohashes(),
                    proof_at_size(&fresh, idx, k).cohashes(),
                    "k={k} idx={idx}"
                );
            }
        }

        // Fully drained, and popping past empty stays empty.
        assert_eq!(count(&store), 0);
        assert_eq!(pop(&store), None);
    }

    /// After a full `prune_before` compaction, popping the last leaf would
    /// truncate onto a prefix whose peaks are gone, leaving an unappendable
    /// store, so `pop_leaf` refuses with `Pruned` instead of dropping the count.
    /// But a pop whose shorter prefix peaks survive still succeeds: compacting 3
    /// leaves keeps peak `(1,0)`, which is exactly what a 2-leaf MMR needs, so the
    /// pop goes through (returning leaf 2's retained hash).
    #[test]
    fn pop_leaf_into_pruned_prefix_is_rejected() {
        let store = MemMmr::<Hash32>::default();
        for i in 0..4 {
            append(&store, leaf(i));
        }
        // Compaction keeps only peak (2,0); a 3-leaf MMR needs (1,0) and (0,2),
        // both discarded, so the pop down to 3 leaves cannot leave an appendable
        // store.
        prune_before(&store, 4);
        assert_eq!(read_leaf(&store, 3), None);
        assert!(matches!(
            store.pop_leaf(),
            Err(MmrError::Pruned {
                index: 3,
                pruned_before: 4
            })
        ));
        assert_eq!(count(&store), 4);

        // A pop whose shorter prefix survives compaction is still allowed.
        let store = MemMmr::<Hash32>::default();
        for i in 0..3 {
            append(&store, leaf(i));
        }
        prune_before(&store, 3); // keeps peaks of 3 leaves: (1,0) and (0,2)
        assert_eq!(pop(&store), Some(leaf(2))); // 2-leaf MMR needs (1,0), intact
        assert_eq!(count(&store), 2);
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

        /// `prune_after(k)` leaves a store indistinguishable from a fresh
        /// `k`-leaf build: same leaf count and same proof for every kept leaf.
        #[test]
        fn prune_after_equals_fresh_build((leaves, size, _index) in leaves_and_query(1..64)) {
            let k = size;
            let pruned = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&pruned, *value);
            }
            prune_after(&pruned, k);

            let fresh = MemMmr::<Hash32>::default();
            for value in &leaves[..k as usize] {
                append(&fresh, *value);
            }

            prop_assert_eq!(count(&pruned), k);
            for idx in 0..k {
                let pruned_proof = proof_at_size(&pruned, idx, k);
                let fresh_proof = proof_at_size(&fresh, idx, k);
                prop_assert_eq!(pruned_proof.cohashes(), fresh_proof.cohashes());
            }
        }

        /// `pop_leaf` unwinds an MMR leaf-by-leaf: each pop returns the last
        /// appended value, drops the count by one, and leaves a store whose proofs
        /// match a fresh build of the surviving prefix — down to empty, after
        /// which it keeps returning `None`.
        #[test]
        fn pop_leaf_unwinds_to_fresh_builds((leaves, _size, _index) in leaves_and_query(1..32)) {
            let n = leaves.len() as u64;
            let store = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&store, *value);
            }
            for k in (0..n).rev() {
                prop_assert_eq!(pop(&store), Some(leaves[k as usize]));
                prop_assert_eq!(count(&store), k);

                let fresh = MemMmr::<Hash32>::default();
                for value in &leaves[..k as usize] {
                    append(&fresh, *value);
                }
                for idx in 0..k {
                    let popped_proof = proof_at_size(&store, idx, k);
                    let fresh_proof = proof_at_size(&fresh, idx, k);
                    prop_assert_eq!(popped_proof.cohashes(), fresh_proof.cohashes());
                }
            }
            prop_assert_eq!(pop(&store), None);
            prop_assert_eq!(pop(&store), None);
        }

        /// After `prune_before(k)` every leaf in `[k, n)` still verifies against
        /// the reference and the leaf count is unchanged.
        #[test]
        fn prune_before_preserves_suffix_proofs((leaves, size, _index) in leaves_and_query(1..64)) {
            let n = leaves.len() as u64;
            let k = size;
            let store = MemMmr::<Hash32>::default();
            for value in &leaves {
                append(&store, *value);
            }
            prune_before(&store, k);

            prop_assert_eq!(count(&store), n);
            let reference = reference_mmr(&leaves);
            for idx in k..n {
                let proof = proof_at_size(&store, idx, n);
                prop_assert!(reference.verify::<Sha256Hasher>(&proof, &leaves[idx as usize]));
            }
        }
    }
}
