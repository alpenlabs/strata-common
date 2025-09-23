//! Test utilities for predicate verification testing.
//!
//! This module provides common test helper functions that are shared across
//! different predicate verifier implementations to ensure consistent error
//! checking and reduce code duplication in tests.

#[cfg(test)]
use crate::{errors::PredicateError, type_ids::PredicateTypeId};

#[cfg(test)]
/// Asserts that a result contains a `PredicateParsingFailed` error for the given predicate type.
pub(crate) fn assert_predicate_parsing_failed(
    result: Result<(), PredicateError>,
    expected_type: PredicateTypeId,
) {
    let err = result.unwrap_err();
    match err {
        PredicateError::PredicateParsingFailed { id, .. } => {
            assert_eq!(id, expected_type);
        }
        _ => panic!("Expected PredicateParsingFailed, got: {err:?}"),
    }
}

#[cfg(test)]
/// Asserts that a result contains a `WitnessParsingFailed` error for the given predicate type.
pub(crate) fn assert_witness_parsing_failed(
    result: Result<(), PredicateError>,
    expected_type: PredicateTypeId,
) {
    let err = result.unwrap_err();
    match err {
        PredicateError::WitnessParsingFailed { id, .. } => {
            assert_eq!(id, expected_type);
        }
        _ => panic!("Expected WitnessParsingFailed, got: {err:?}"),
    }
}

#[cfg(test)]
/// Asserts that a result contains a `VerificationFailed` error for the given predicate type.
pub(crate) fn assert_verification_failed(
    result: Result<(), PredicateError>,
    expected_type: PredicateTypeId,
) {
    let err = result.unwrap_err();
    match err {
        PredicateError::VerificationFailed { id, .. } => {
            assert_eq!(id, expected_type);
        }
        _ => panic!("Expected VerificationFailed, got: {err:?}"),
    }
}
