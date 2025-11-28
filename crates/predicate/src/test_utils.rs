//! Test utilities for predicate verification testing.
//!
//! This module provides common test helper functions that are shared across
//! different predicate verifier implementations to ensure consistent error
//! checking and reduce code duplication in tests.

use crate::{MAX_CONDITION_LEN, PredicateKey, errors::PredicateError, type_ids::PredicateTypeId};

use proptest::prelude::*;

/// Asserts that a result contains a `PredicateParsingFailed` error for the given predicate type.
pub(crate) fn assert_predicate_parsing_failed(
    result: Result<(), PredicateError>,
    expected_type: PredicateTypeId,
) {
    let err = result.unwrap_err();
    match err {
        PredicateError::ConditionParsingFailed { id, .. } => {
            assert_eq!(id, expected_type);
        }
        _ => panic!("Expected PredicateParsingFailed, got: {err:?}"),
    }
}

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

pub(crate) fn predicate_type_id_strategy() -> impl Strategy<Value = PredicateTypeId> {
    prop_oneof![
        Just(PredicateTypeId::NeverAccept),
        Just(PredicateTypeId::AlwaysAccept),
        Just(PredicateTypeId::Bip340Schnorr),
        Just(PredicateTypeId::Sp1Groth16),
    ]
}

pub(crate) fn condition_strategy() -> impl Strategy<Value = Vec<u8>> {
    bounded_condition_strategy(MAX_CONDITION_LEN as usize)
}

pub(crate) fn bounded_condition_strategy(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

pub(crate) fn predicate_key_strategy() -> impl Strategy<Value = PredicateKey> {
    (predicate_type_id_strategy(), condition_strategy())
        .prop_map(|(id, condition)| PredicateKey::new(id, condition))
}
