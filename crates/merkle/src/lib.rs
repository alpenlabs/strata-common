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

#[cfg(feature = "borsh")]
mod borsh_impl;
#[cfg(feature = "codec")]
mod codec_impl;
#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(feature = "serde")]
use serde_json as _;

pub mod error;
pub mod hasher;
pub mod mmr;
pub mod proof;
#[allow(
    missing_docs,
    unreachable_pub,
    rustdoc::private_intra_doc_links,
    reason = "generated code from SSZ schemas"
)]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

pub mod tree;

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
pub use mmr::MerkleMr64;
pub use tree::BinaryMerkleTree;

// Re-export SSZ-generated types
// These types have Encode, Decode, and TreeHash implementations for SSZ serialization
pub use ssz_generated::ssz::mmr::{CompactMmr64, CompactMmr64Ref, MAX_MMR_PEAKS};
pub use ssz_generated::ssz::proof::{
    MerkleProof, MerkleProofRef, RawMerkleProof, RawMerkleProofRef,
};
