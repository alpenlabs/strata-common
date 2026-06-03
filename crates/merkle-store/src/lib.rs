//! Reusable Merkle Mountain Range (MMR) node store.
//!
//! Stores *every* MMR node — leaves and internal nodes — so inclusion proofs
//! are generated in `O(log n)` by walking the stored sibling path, with no
//! leaf replay. The surface a backend must implement is just two methods
//! ([`MmrNodeStore::get_node`] / [`MmrNodeStore::put_node`]); the leaf- and
//! proof-level API ([`StoredMmr`]) is derived on top.
//!
//! The store is storage- and namespace-agnostic (one backend instance == one
//! MMR) and generic over the [`MerkleHasher`](strata_merkle::MerkleHasher) used
//! to combine nodes: proofs are assembled as
//! [`MerkleProof`](strata_merkle::MerkleProof) and verify against the same
//! compact-peaks accumulators ([`Mmr`](strata_merkle::Mmr)) that `strata-merkle`
//! builds with that hasher.
//!
//! Leaf counts and indices are `u64`, matching the MMR entry ceiling documented
//! on [`MmrState`](strata_merkle::MmrState).

mod algorithm;
mod error;
mod index;
mod memory;
mod store;

pub use algorithm::{assemble_proof, proof_positions, write_plan};
pub use error::MmrError;
pub use index::{LeafPos, NodePos, peak_for_leaf, peak_positions};
pub use memory::MemMmr;
pub use store::{MmrMetaPack, MmrNodeStore, StoredMmr};
