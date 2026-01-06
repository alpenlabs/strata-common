//! Predicate type implementations.
//!
//! This module contains the individual implementations for each predicate type,
//! organized in separate files for better maintainability.

#[cfg(feature = "schnorr")]
pub(crate) mod schnorr;
#[cfg(feature = "sp1-groth16")]
pub(crate) mod sp1_groth16;
pub(crate) mod verifier_type;

#[cfg(feature = "schnorr")]
pub(crate) use schnorr::SchnorrVerifier;
#[cfg(feature = "sp1-groth16")]
pub(crate) use sp1_groth16::Sp1Groth16Verifier;
pub(crate) use verifier_type::VerifierType;
