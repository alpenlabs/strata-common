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
}
