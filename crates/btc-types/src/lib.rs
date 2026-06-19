//! Types relating to things we find or generate from Bitcoin blocks/txs/etc.

// `ssz_primitives` (FixedBytes) and `ssz_types` (VariableList) are referenced by
// the generated SSZ delegate types in `ssz_generated`.
use ssz_primitives as _;
use ssz_types as _;

/// SSZ delegate types generated from `ssz/btc.ssz`.
#[allow(unreachable_pub, missing_docs, reason = "generated code")]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

mod btc;
mod convert;
mod errors;
mod genesis;
mod params;

pub use btc::*;
pub use convert::*;
pub use errors::*;
pub use genesis::*;
pub use params::*;

#[cfg(test)]
mod test_helpers;
