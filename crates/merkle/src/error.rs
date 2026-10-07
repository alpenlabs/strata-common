//! Error types for the Merkle Mountain Range (MMR) crate.
use thiserror::Error;

/// Errors that can occur when operating on the MMR.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum MerkleError {
    /// The MMR has no elements.
    #[error("no element present in merkle tree")]
    NoElements,

    /// The number of elements is not a power of two when required.
    #[error("not power-of-2 size")]
    NotPowerOfTwo,

    /// The provided index does not exist within the MMR.
    #[error("index provided out of bounds")]
    IndexOutOfBounds,

    /// The supplied chunk size exceeds the allowable limit.
    #[error("provided chunk size too big")]
    ChunkSizeTooBig,

    /// The MMR has reached its maximum capacity and cannot accept more leaves.
    #[error("MMR has reached max capacity")]
    MaxCapacity,

    /// The MMR's entry count says there is a peak at `height`, but the MMR does
    /// not hold one.
    #[error("MMR has no peak at height {height}")]
    MissingPeak {
        /// The height of the missing peak.
        height: u8,
    },

    /// The MMR stores a different number of peaks than its entry count implies.
    #[error("MMR stores {actual} peaks but its entry count implies {expected}")]
    PeakCountMismatch {
        /// The number of peaks the entry count implies.
        expected: usize,
        /// The number of peaks stored.
        actual: usize,
    },

    /// An unknown or unexpected error occurred.
    #[error("unknown error")]
    Unknown,
}
