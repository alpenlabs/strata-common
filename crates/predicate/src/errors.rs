//! Error types for the predicate format library.

use thiserror::Error;

/// Errors that can occur when working with predicates, claims, and witnesses.
#[derive(Clone, Debug, Error)]
pub enum PredicateError {
    // === Configuration and Type Errors ===
    /// Invalid or unsupported predicate type identifier.
    #[error("invalid predicate type {0}")]
    InvalidPredicateType(u8),

    // === Parsing Errors ===
    /// Predicate condition parsing failed.
    #[error("predicate parsing failed for type {predicate_type}: {reason}")]
    PredicateParsingFailed {
        /// The predicate type that failed to parse.
        predicate_type: u8,
        /// The reason for parsing failure.
        reason: String,
    },

    /// Witness parsing failed.
    #[error("witness parsing failed for type {predicate_type}: {reason}")]
    WitnessParsingFailed {
        /// The predicate type that failed witness parsing.
        predicate_type: u8,
        /// The reason for witness parsing failure.
        reason: String,
    },

    // === Verification Errors ===
    /// Predicate validation failed during verification setup.
    #[error("predicate validation failed: {reason}")]
    ValidationFailed {
        /// The reason for validation failure.
        reason: String,
    },

    /// Witness verification failed - witness does not satisfy the predicate.
    #[error("witness verification failed")]
    VerificationFailed,

    // === Serialization Errors ===
    /// Serialization or deserialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),
}

/// Result type alias for predicate operations.
pub(crate) type Result<T> = std::result::Result<T, PredicateError>;

// Implement From conversions for common error types
impl From<borsh::io::Error> for PredicateError {
    fn from(err: borsh::io::Error) -> Self {
        PredicateError::SerializationError(err.to_string())
    }
}
