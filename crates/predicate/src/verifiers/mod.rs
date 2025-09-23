//! Predicate type implementations.
//!
//! This module contains the individual implementations for each predicate type,
//! organized in separate files for better maintainability.

pub(crate) mod schnorr;
pub(crate) mod sp1_groth16;

pub(crate) use schnorr::SchnorrVerifier;
pub(crate) use sp1_groth16::Sp1Groth16Verifier;

use crate::errors::PredicateError;
use crate::type_ids::PredicateTypeId;
use crate::verifier::PredicateVerifier;

/// Enum representing all supported verifier types and their implementations.
///
/// This enum serves as a dispatch mechanism to route verification calls to the
/// appropriate predicate-specific implementation based on the predicate type.
/// Each variant contains the implementation for a specific verifier backend.
#[derive(Debug)]
pub(crate) enum VerifierType {
    /// Never accept verifier (always fails verification).
    NeverAccept,
    /// Always accept verifier (for testing and placeholders).
    AlwaysAccept,
    /// Schnorr BIP-340 signature verifier.
    Schnorr(SchnorrVerifier),
    /// SP1 Groth16 zero-knowledge proof verifier.
    Sp1Groth16(Sp1Groth16Verifier),
}

impl From<PredicateTypeId> for VerifierType {
    fn from(predicate_type_id: PredicateTypeId) -> Self {
        match predicate_type_id {
            PredicateTypeId::NeverAccept => VerifierType::NeverAccept,
            PredicateTypeId::AlwaysAccept => VerifierType::AlwaysAccept,
            PredicateTypeId::Bip340Schnorr => VerifierType::Schnorr(SchnorrVerifier),
            PredicateTypeId::Sp1Groth16 => VerifierType::Sp1Groth16(Sp1Groth16Verifier),
        }
    }
}

impl VerifierType {
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
            VerifierType::NeverAccept => Err(PredicateError::VerificationFailed {
                id: PredicateTypeId::NeverAccept,
                reason: "never accept".to_string(),
            }),
            VerifierType::AlwaysAccept => Ok(()),
            VerifierType::Schnorr(schnorr) => schnorr.verify(condition, claim, witness),
            VerifierType::Sp1Groth16(sp1) => sp1.verify(condition, claim, witness),
        }
    }
}
