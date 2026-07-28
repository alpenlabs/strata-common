//! ECDSA signature set for threshold signatures (M-of-N).
//!
//! This module provides types and functions for verifying a set of
//! ECDSA signatures against a threshold configuration. Used by the admin
//! subprotocol for hardware wallet compatibility.

mod config;
mod errors;
mod signature;
mod verification;

pub use config::{
    MAX_SIGNERS, ThresholdConfig, ThresholdConfigRef, ThresholdConfigUpdate,
    ThresholdConfigUpdateRef,
};
pub use errors::ThresholdSignatureError;
pub use signature::{IndexedSignature, IndexedSignatureRef, SignatureSet, SignatureSetRef};
pub use verification::verify_threshold_signatures;
