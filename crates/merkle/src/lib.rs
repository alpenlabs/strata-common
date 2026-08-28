//! Merkle tree and merkle mountain range primitives, traits, etc.
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
// Used by tests gated by the `codec` feature.
#[cfg(test)]
use proptest as _;

#[cfg(feature = "codec")]
mod codec_impl;

#[cfg(any(test, feature = "legacy_compact"))]
mod legacy_compact_mmr;

mod error;
mod ext;
mod hasher;
mod mmr;
mod proof;
mod traits;
mod tree;

pub use error::*;
pub use ext::*;
pub use hasher::*;
#[cfg(any(test, feature = "legacy_compact"))]
pub use legacy_compact_mmr::*;
pub use proof::*;
pub use traits::*;
pub use tree::*;

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

use sha2::Sha256;

/// Merkle hash impl for SHA-256 `Digest` impl.
pub type Sha256Hasher = DigestMerkleHasher<Sha256, 32>;

/// Merkle hash impl for SHA-256 without prefixes.
pub type Sha256NoPrefixHasher = DigestMerkleHasherNoPrefix<Sha256, 32>;

/// Compatibility alias for the primary hasher trait used across Merkle data structures.
pub use hasher::MerkleHasher as StrataMerkle;
// Re-export SSZ-generated concrete types (32-byte hash versions)
#[cfg(feature = "ssz")]
pub use ssz_generated::ssz::mmr::*;
#[cfg(feature = "ssz")]
pub use ssz_generated::ssz::proof::*;
