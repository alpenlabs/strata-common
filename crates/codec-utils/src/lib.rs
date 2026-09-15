//! Utils around the strata-codec system that don't belong in the upstream crates.
//!
//! Enable the non-default `borsh` feature for the Borsh codec adapter.

#[cfg(feature = "borsh")]
mod borsh_shim;
mod chunk_iter_decoder;
mod ssz_shim;

#[cfg(feature = "borsh")]
pub use borsh_shim::*;
pub use chunk_iter_decoder::ChunkIterDecoder;
pub use ssz_shim::*;
