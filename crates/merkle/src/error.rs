//! Error types for the Merkle Mountain Range (MMR) crate.
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
/// Errors that can occur when operating on the MMR.
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

    /// An unknown or unexpected error occurred.
    #[error("unknown error")]
    Unknown,
}
