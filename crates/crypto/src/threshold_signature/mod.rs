//! ECDSA threshold signatures with indexed signers.

pub mod indexed;

// Re-export commonly used types from indexed
pub use indexed::{
    IndexedSignature, IndexedSignatureRef, SignatureSet, SignatureSetRef, ThresholdConfig,
    ThresholdConfigRef, ThresholdConfigUpdate, ThresholdConfigUpdateRef, ThresholdSignatureError,
    verify_threshold_signatures,
};
