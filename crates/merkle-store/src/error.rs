//! Error type for derived MMR node-store operations.

use super::index::NodePos;

/// Error returned by the derived [`StoredMmr`](super::store::StoredMmr)
/// operations.
///
/// Generic over the backend's error `E` so the node store imposes no error type
/// on implementors.
#[derive(Debug, thiserror::Error)]
pub enum MmrError<E> {
    /// The underlying storage backend failed.
    #[error("mmr backend error: {0}")]
    Backend(E),

    /// A node required to complete the operation is absent from storage.
    ///
    /// For a consistent, append-only store this indicates corruption.
    #[error("missing mmr node at {0:?}")]
    NodeMissing(NodePos),

    /// The requested leaf index is beyond the MMR size being queried.
    #[error("leaf index {index} out of range (leaf_count={leaf_count})")]
    LeafOutOfRange {
        /// The out-of-range leaf index.
        index: u64,
        /// The MMR size against which the request was made.
        leaf_count: u64,
    },

    /// A leaf write was requested past the append point, which would skip the
    /// leaves in between and leave a gap. The only writable indices are
    /// `0..=leaf_count`: an existing index (overwrite) or exactly `leaf_count`
    /// (append).
    #[error("leaf write at {index} would leave a gap (leaf_count={leaf_count})")]
    LeafGap {
        /// The requested write index, past the append point.
        index: u64,
        /// The current leaf count — the highest writable index.
        leaf_count: u64,
    },

    /// The MMR already holds the maximum `u64::MAX` leaves, so no further leaf
    /// can be appended — the next index would overflow `u64`.
    #[error("MMR has reached max capacity")]
    MaxCapacity,

    /// The requested leaf lies in the pruned prefix: it is below the store's
    /// prune watermark, so the nodes needed to prove it have been discarded by
    /// [`prune_before`](super::store::StoredMmr::prune_before). Unlike
    /// [`NodeMissing`](Self::NodeMissing), this is an expected outcome of
    /// pruning, not corruption.
    #[error("leaf index {index} was pruned (pruned_before={pruned_before})")]
    Pruned {
        /// The requested leaf index, below the watermark.
        index: u64,
        /// The watermark: every leaf below this index has been pruned.
        pruned_before: u64,
    },
}
