//! Pure MMR walks: write planning and proof-path computation.
//!
//! These functions are storage-agnostic. Writing a leaf reads the existing
//! sibling at each level via a fetch closure; proof generation is split into
//! position computation (no I/O) and assembly so the store can batch the fetch.
//!
//! Node hashing is supplied by the caller's [`MerkleHasher`], so a node store
//! produces proofs that verify against the same compact-peaks accumulators the
//! rest of the crate builds with that hasher.

use super::error::MmrError;
use super::index::{LeafPos, NodePos, peak_for_leaf};
use crate::hasher::{MerkleHash, MerkleHasher};
use crate::proof::MerkleProof;

/// Computes the nodes to write when setting `leaf` at `leaf_index` in an MMR
/// that has (or will have) `leaf_count` leaves.
///
/// Returns the leaf followed by every recomputed ancestor up to the leaf's
/// peak (bottom-up). This covers both an append (`leaf_index == old_count`,
/// where the cascade stops at the new isolated peak) and an overwrite
/// (`leaf_index < old_count`, where the full path to the existing peak is
/// recomputed). Each required sibling is read via `get` and must already be
/// present, else [`MmrError::NodeMissing`] — e.g. writing past the current end
/// would leave a gap.
///
/// Callers must pass the *effective* `leaf_count` (after the write) and ensure
/// `leaf_index < leaf_count`.
pub fn write_plan<MH, E>(
    leaf_index: u64,
    leaf: MH::Hash,
    leaf_count: u64,
    mut get: impl FnMut(NodePos) -> Result<Option<MH::Hash>, E>,
) -> Result<Vec<(NodePos, MH::Hash)>, MmrError<E>>
where
    MH: MerkleHasher,
{
    let peak_pos = peak_for_leaf(leaf_index, leaf_count);
    let mut current_pos = LeafPos::new(leaf_index).to_node_pos();
    let mut current_hash = leaf;
    let mut writes = vec![(current_pos, current_hash)];

    while current_pos != peak_pos {
        let sibling_pos = current_pos.sibling();
        let sibling_hash = get(sibling_pos)
            .map_err(MmrError::Backend)?
            .ok_or(MmrError::NodeMissing(sibling_pos))?;
        let (left, right) = if current_pos.is_left_child() {
            (current_hash, sibling_hash)
        } else {
            (sibling_hash, current_hash)
        };
        let parent_hash = MH::hash_node(left, right);
        let parent_pos = current_pos.parent();

        writes.push((parent_pos, parent_hash));
        current_pos = parent_pos;
        current_hash = parent_hash;
    }

    Ok(writes)
}

/// Computes the sibling positions on the proof path for `leaf_index` in an MMR
/// of `leaf_count` leaves (bottom-up).
///
/// The caller must ensure `leaf_index < leaf_count`.
pub fn proof_positions(leaf_index: u64, leaf_count: u64) -> Vec<NodePos> {
    let peak_pos = peak_for_leaf(leaf_index, leaf_count);
    let mut positions = Vec::new();
    let mut current_pos = LeafPos::new(leaf_index).to_node_pos();

    while current_pos != peak_pos {
        positions.push(current_pos.sibling());
        current_pos = current_pos.parent();
    }

    positions
}

/// Assembles an inclusion proof from cohashes already fetched in proof-path
/// order (the order returned by [`proof_positions`]).
pub fn assemble_proof<H: MerkleHash>(leaf_index: u64, cohashes: Vec<H>) -> MerkleProof<H> {
    MerkleProof::from_cohashes(cohashes, leaf_index)
}
