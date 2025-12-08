//! Merkle primitives and data structures.
//!
//! # MMR (Merkle Mountain Range)
//!
//! The primary MMR implementation is [`MmrStateVec`] with the [`ext::Mmr`] extension trait.
//!
//! ```rust,ignore
//! use strata_merkle::{MmrStateVec, Sha256Hasher, ext::Mmr};
//!
//! let mut mmr = MmrStateVec::<[u8; 32]>::new_empty();
//! Mmr::<Sha256Hasher>::add_leaf(&mut mmr, leaf)?;
//! Mmr::<Sha256Hasher>::verify(&mmr, &proof, &leaf);
//! ```
//!
//! For SSZ-compatible types, use `CompactMmr64B32` which implements
//! the [`MmrState`] trait and works with the same `Mmr` extension methods.
//!
//! # Modules
//!
//! - `hasher`: common hash and hasher traits/impls
//! - `mmr`: [`CompactMmr64`] - compact MMR representation
//! - `ext`: [`Mmr`](ext::Mmr) extension trait with MMR algorithms
//! - `state`: [`MmrStateVec`] - the primary MMR state implementation
//! - `traits`: [`MmrState`] trait for MMR state backends
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
pub mod mmr;
pub mod proof;
pub mod tree;

pub mod ext;
pub mod state;
pub mod traits;

pub use state::MmrStateVec;
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
pub use mmr::CompactMmr64;
pub use proof::{MerkleProof, RawMerkleProof};
pub use tree::BinaryMerkleTree;

// Re-export SSZ-generated concrete types (32-byte hash versions)
#[cfg(feature = "ssz")]
pub use ssz_generated::ssz::mmr::*;
#[cfg(feature = "ssz")]
pub use ssz_generated::ssz::proof::*;
