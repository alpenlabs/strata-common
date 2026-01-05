//! Predicate type implementations.
//!
//! This module contains the individual implementations for each predicate type,
//! organized in separate files for better maintainability.

#[cfg(feature = "verify-schnorr")]
pub(crate) mod schnorr;
#[cfg(feature = "verify-sp1-groth16")]
pub(crate) mod sp1_groth16;
pub(crate) mod verifier_type;

#[cfg(feature = "verify-schnorr")]
pub(crate) use schnorr::SchnorrVerifier;
#[cfg(feature = "verify-sp1-groth16")]
pub(crate) use sp1_groth16::Sp1Groth16Verifier;
pub(crate) use verifier_type::VerifierType;
