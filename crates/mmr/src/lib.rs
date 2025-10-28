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
pub mod error;
pub mod hasher;
pub mod mmr;
pub mod proof;
#[cfg(feature = "serde")]
mod serde_impl;
pub mod tree;

// Test-only dependency used in serde roundtrip tests when the `serde` feature
// is disabled, to satisfy unused dependency lint for dev-deps.
#[cfg(all(test, not(feature = "serde")))]
use serde_json as _;

// Mark digest as used to satisfy unused dependency lint in workspace.
use digest as _;

use hasher::DigestMerkleHasher;
use sha2::Sha256;

/// Merkle hash impl for SHA-256 `Digest` impl.
pub type Sha256Hasher = DigestMerkleHasher<Sha256, 32>;

/// Compatibility alias for the primary hasher trait used across Merkle data structures.
pub use hasher::MerkleHasher as StrataMerkle;

// Common re-exports for ergonomic access at the crate root.
pub use hasher::{MerkleHash, MerkleHasher};
pub use mmr::{CompactMmr64, MerkleMr64};
pub use proof::{MerkleProof, RawMerkleProof};
pub use tree::BinaryMerkleTree;

/// A convenient prelude bringing common types into scope.
pub mod prelude {
    pub use crate::Sha256Hasher;
    pub use crate::hasher::{DigestMerkleHasher, MerkleHash, MerkleHasher};
    pub use crate::mmr::{CompactMmr64, MerkleMr64};
    pub use crate::proof::{MerkleProof, RawMerkleProof};
    pub use crate::tree::BinaryMerkleTree;
}
