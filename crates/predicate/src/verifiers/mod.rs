//! Predicate type implementations.
//!
//! This module contains the individual implementations for each predicate type,
//! organized in separate files for better maintainability.

pub(crate) mod schnorr;
pub(crate) mod sp1_groth16;

pub(crate) use schnorr::SchnorrVerifier;
pub(crate) use sp1_groth16::Sp1Groth16VerifierImpl;

use crate::constants::PredicateTypeId;
use crate::errors::PredicateError;
use crate::verifier::PredicateVerifier;

/// Enum representing all supported predicate types and their implementations.
///
/// This enum serves as a dispatch mechanism to route verification calls to the
/// appropriate predicate-specific implementation based on the predicate type.
/// Each variant contains the implementation for a specific predicate backend.
#[derive(Debug)]
pub(crate) enum PredicateImpl {
    /// Never accept predicate implementation (always fails verification).
    NeverAccept,
    /// Always accept predicate implementation (for testing and placeholders).
    AlwaysAccept,
    /// Schnorr BIP-340 signature predicate implementation.
    Schnorr(SchnorrVerifier),
    /// SP1 Groth16 zero-knowledge proof verifier implementation.
    Sp1Groth16Verifier(Sp1Groth16VerifierImpl),
}

impl PredicateImpl {
    /// Creates a predicate implementation instance from a predicate type ID.
    ///
    /// # Arguments
    /// * `predicate_type_id` - The predicate type identifier
    ///
    /// # Returns
    /// * The corresponding predicate implementation
    pub(crate) fn from(predicate_type_id: PredicateTypeId) -> Self {
        match predicate_type_id {
            PredicateTypeId::NeverAccept => PredicateImpl::NeverAccept,
            PredicateTypeId::AlwaysAccept => PredicateImpl::AlwaysAccept,
            PredicateTypeId::Bip340Schnorr => PredicateImpl::Schnorr(SchnorrVerifier),
            PredicateTypeId::Sp1Groth16 => PredicateImpl::Sp1Groth16Verifier(Sp1Groth16VerifierImpl),
        }
    }

    /// Verifies that a witness satisfies the predicate for a given claim.
    ///
    /// This method dispatches to the appropriate predicate-specific verification logic.
    ///
    /// # Arguments
    /// * `condition` - The predicate condition data
    /// * `claim` - The claim bytes to verify
    /// * `witness` - The witness bytes to verify
    ///
    /// # Returns
    /// * `Ok(())` if verification succeeds
    /// * `Err(PredicateError)` if verification fails or an error occurs
    pub(crate) fn verify_claim_witness(
        &self,
        condition: &[u8],
        claim: &[u8],
        witness: &[u8],
    ) -> Result<(), PredicateError> {
        match self {
            PredicateImpl::NeverAccept => Err(PredicateError::VerificationFailed {
                id: PredicateTypeId::NeverAccept,
                reason: "never accept".to_string(),
            }),
            PredicateImpl::AlwaysAccept => Ok(()),
            PredicateImpl::Schnorr(schnorr) => schnorr.verify(condition, claim, witness),
            PredicateImpl::Sp1Groth16Verifier(sp1) => sp1.verify(condition, claim, witness),
        }
    }
}
