use crate::errors::PredicateError;
use crate::type_ids::PredicateTypeId;
#[cfg(any(feature = "verify-schnorr", feature = "verify-sp1-groth16"))]
use crate::verifier::PredicateVerifier;

#[cfg(feature = "verify-schnorr")]
use super::SchnorrVerifier;
#[cfg(feature = "verify-sp1-groth16")]
use super::Sp1Groth16Verifier;

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
    #[cfg(feature = "verify-schnorr")]
    Schnorr(SchnorrVerifier),
    /// SP1 Groth16 zero-knowledge proof verifier.
    #[cfg(feature = "verify-sp1-groth16")]
    Sp1Groth16(Sp1Groth16Verifier),
}

impl TryFrom<PredicateTypeId> for VerifierType {
    type Error = PredicateError;

    fn try_from(predicate_type_id: PredicateTypeId) -> Result<Self, Self::Error> {
        match predicate_type_id {
            PredicateTypeId::NeverAccept => Ok(VerifierType::NeverAccept),
            PredicateTypeId::AlwaysAccept => Ok(VerifierType::AlwaysAccept),
            #[cfg(feature = "verify-schnorr")]
            PredicateTypeId::Bip340Schnorr => Ok(VerifierType::Schnorr(SchnorrVerifier)),
            #[cfg(not(feature = "verify-schnorr"))]
            PredicateTypeId::Bip340Schnorr => Err(PredicateError::UnsupportedPredicateType {
                id: PredicateTypeId::Bip340Schnorr,
                reason: "enable the 'verify-schnorr' feature to verify Schnorr signatures"
                    .to_string(),
            }),
            #[cfg(feature = "verify-sp1-groth16")]
            PredicateTypeId::Sp1Groth16 => Ok(VerifierType::Sp1Groth16(Sp1Groth16Verifier)),
            #[cfg(not(feature = "verify-sp1-groth16"))]
            PredicateTypeId::Sp1Groth16 => Err(PredicateError::UnsupportedPredicateType {
                id: PredicateTypeId::Sp1Groth16,
                reason: "enable the 'verify-sp1-groth16' feature to verify SP1 Groth16 proofs"
                    .to_string(),
            }),
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
            VerifierType::NeverAccept => {
                let _ = (condition, claim, witness);
                Err(PredicateError::VerificationFailed {
                    id: PredicateTypeId::NeverAccept,
                    reason: "never accept".to_string(),
                })
            }
            VerifierType::AlwaysAccept => {
                let _ = (condition, claim, witness);
                Ok(())
            }
            #[cfg(feature = "verify-schnorr")]
            VerifierType::Schnorr(schnorr) => schnorr.verify(condition, claim, witness),
            #[cfg(feature = "verify-sp1-groth16")]
            VerifierType::Sp1Groth16(sp1) => sp1.verify(condition, claim, witness),
        }
    }
}
