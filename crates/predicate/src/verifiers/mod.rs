//! Predicate type implementations.
//!
//! This module contains the individual implementations for each predicate type,
//! organized in separate files for better maintainability.

pub(crate) mod schnorr;
pub(crate) mod sp1_groth16;
pub(crate) mod verifier_type;

pub(crate) use schnorr::SchnorrVerifier;
pub(crate) use sp1_groth16::Sp1Groth16Verifier;
pub(crate) use verifier_type::VerifierType;
