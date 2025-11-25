//! Merkle primitives and data structures.
//!
//! Modules:
//! - `hasher`: common hash and hasher traits/impls
//! - `mmr`: Merkle Mountain Range accumulator and proofs
//! - `tree`: generic binary Merkle tree with proofs
#![expect(
    clippy::declare_interior_mutable_const,
    reason = "Constants with interior mutability are needed for MMR implementation"
)]
#![expect(
    clippy::borrow_interior_mutable_const,
    reason = "Borrowing interior mutable constants is required for MMR operations"
)]

// stupid linter issue
#[cfg(test)]
use criterion as _;

#[cfg(feature = "codec")]
mod codec_impl;
pub mod error;
pub mod hasher;
pub mod mmr; // old
pub mod proof; // old
pub mod tree;

pub mod new_mmr;
pub mod new_state;
pub mod traits;

pub use new_state::NewMmrState;
pub use traits::MmrState;

// Include SSZ-generated types
#[cfg(feature = "ssz")]
#[allow(
    clippy::all,
    unreachable_pub,
    clippy::allow_attributes,
    missing_docs,
    reason = "generated code"
)]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

use hasher::{DigestMerkleHasher, DigestMerkleHasherNoPrefix};
use sha2::Sha256;

/// Merkle hash impl for SHA-256 `Digest` impl.
pub type Sha256Hasher = DigestMerkleHasher<Sha256, 32>;

/// Merkle hash impl for SHA-256 without prefixes.
pub type Sha256NoPrefixHasher = DigestMerkleHasherNoPrefix<Sha256, 32>;

/// Compatibility alias for the primary hasher trait used across Merkle data structures.
pub use hasher::MerkleHasher as StrataMerkle;

// Common re-exports for ergonomic access at the crate root.
pub use hasher::{MerkleHash, MerkleHasher};
pub use mmr::{CompactMmr64, MerkleMr64};
pub use proof::{MerkleProof, RawMerkleProof};
pub use tree::BinaryMerkleTree;

// Re-export SSZ-generated concrete types (32-byte hash versions)
#[cfg(feature = "ssz")]
pub use ssz_generated::ssz::mmr::*;
#[cfg(feature = "ssz")]
pub use ssz_generated::ssz::proof::*;
