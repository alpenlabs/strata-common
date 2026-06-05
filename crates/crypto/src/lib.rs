//! Cryptographic primitives.

// `ssz_primitives` (FixedBytes), `tree_hash`, and `tree_hash_derive` are
// referenced by the generated SSZ delegate types in `ssz_generated`.
#[cfg(test)]
use strata_ssz_tests as _;
use {ssz_primitives as _, tree_hash as _, tree_hash_derive as _};

/// SSZ delegate types generated from `ssz/threshold.ssz`.
#[allow(unreachable_pub, missing_docs, reason = "generated code")]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

/// Hashing functions.
pub mod hash;
/// Key types, derivation paths, and constants.
pub mod keys;

pub mod musig2;
pub mod schnorr;
/// Test utilities for cryptographic operations.
#[cfg(feature = "test-utils")]
pub mod test_utils;
/// Threshold signature schemes.
pub mod threshold_signature;

// Re-export even parity key types
pub use keys::even::{EvenPublicKey, EvenSecretKey, even_kp};
// Re-export MuSig2 key aggregation
pub use musig2::{Musig2Error, aggregate_schnorr_keys};
pub use schnorr::*;

#[cfg(test)]
mod test_helpers;
