//! Utils around the strata-codec system that don't belong in the upstream crates.

mod chunk_iter_decoder;
mod ssz_shim;

pub use chunk_iter_decoder::ChunkIterDecoder;
pub use ssz_shim::*;
