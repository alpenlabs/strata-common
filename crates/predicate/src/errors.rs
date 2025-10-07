//! Error types for the predicate format library.
//!
//! This module defines all error types that can occur during predicate operations,
//! including parsing errors for predicates and witnesses, verification failures,
//! and configuration errors. All errors are structured with specific context
//! about which predicate type caused the error and detailed reasons for debugging.
use thiserror::Error;

use crate::type_ids::PredicateTypeId;

/// Errors that can occur when working with predicates, claims, and witnesses.
#[derive(Clone, Debug, Error)]
pub enum PredicateError {
    // === Configuration and Type Errors ===
    /// Invalid or unsupported predicate type identifier.
    #[error("invalid predicate type {0}")]
    InvalidPredicateType(u8),

    /// Missing predicate type identifier.
    #[error("missing predicate type")]
    MissingPredicateType,

    // === Parsing Errors ===
    /// Predicate condition parsing failed.
    #[error("predicate parsing failed for type {id}: {reason}")]
    PredicateParsingFailed {
        /// The predicate type that failed to parse.
        id: PredicateTypeId,
        /// The reason for parsing failure.
        reason: String,
    },

    /// Witness parsing failed.
    #[error("witness parsing failed for type {id}: {reason}")]
    WitnessParsingFailed {
        /// The predicate type that failed witness parsing.
        id: PredicateTypeId,
        /// The reason for witness parsing failure.
        reason: String,
    },

    // === Verification Errors ===
    /// Witness does not satisfy the predicate with claim.
    #[error("witness verification failed for claim in {id}: {reason}")]
    VerificationFailed {
        /// The predicate type that failed verification.
        id: PredicateTypeId,
        /// The reason for verification failure.
        reason: String,
    },
}

/// Result type alias for predicate operations.
pub(crate) type PredicateResult<T> = std::result::Result<T, PredicateError>;
