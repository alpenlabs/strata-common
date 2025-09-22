//! Implementation for Schnorr BIP-340 signature verification.

use k256::schnorr::{Signature, VerifyingKey};
use signature::Verifier;

use crate::constants::BIP340_SCHNORR_PREDICATE_TYPE;
use crate::errors::{PredicateError, Result};
use crate::verifier::PredicateVerifier;

/// Implementation for Schnorr BIP-340 signatures.
///
/// This implementation provides:
/// - condition: 32-byte x-only public key
/// - claim: message to be signed (serialized as claim bundle)
/// - witness: 64-byte Schnorr signature
#[derive(Debug, Default)]
pub(crate) struct SchnorrVerifier;

impl PredicateVerifier for SchnorrVerifier {
    type Predicate = VerifyingKey;
    type Witness = Signature;

    fn parse_condition(&self, condition: &[u8]) -> Result<Self::Predicate> {
        // BIP-340 requires exactly 32 bytes for x-only public keys
        if condition.len() != 32 {
            return Err(PredicateError::PredicateParsingFailed {
                predicate_type: BIP340_SCHNORR_PREDICATE_TYPE,
                reason: format!("expected 32 bytes, got {}", condition.len()),
            });
        }

        VerifyingKey::from_bytes(condition).map_err(|e| PredicateError::PredicateParsingFailed {
            predicate_type: BIP340_SCHNORR_PREDICATE_TYPE,
            reason: e.to_string(),
        })
    }

    fn parse_witness(&self, witness: &[u8]) -> Result<Self::Witness> {
        // BIP-340 Schnorr signatures are exactly 64 bytes
        if witness.len() != 64 {
            return Err(PredicateError::WitnessParsingFailed {
                predicate_type: BIP340_SCHNORR_PREDICATE_TYPE,
                reason: format!("expected 64 bytes, got {}", witness.len()),
            });
        }

        Signature::try_from(witness).map_err(|e| PredicateError::WitnessParsingFailed {
            predicate_type: BIP340_SCHNORR_PREDICATE_TYPE,
            reason: e.to_string(),
        })
    }

    fn verify_inner(
        &self,
        pubkey: &Self::Predicate,
        claim: &[u8],
        signature: &Self::Witness,
    ) -> Result<()> {
        // For BIP-340 Schnorr signatures, the message should be properly hashed
        // The verify method expects a properly formatted message
        pubkey
            .verify(claim, signature)
            .map_err(|e| PredicateError::VerificationFailed {
                predicate_type: BIP340_SCHNORR_PREDICATE_TYPE,
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;
    use rand::{RngCore, rngs::OsRng};
    use signature::Signer;

    use super::SchnorrVerifier;
    use crate::constants::BIP340_SCHNORR_PREDICATE_TYPE;
    use crate::errors::{PredicateError, Result};
    use crate::verifier::PredicateVerifier;

    fn assert_predicate_parsing_failed(result: Result<()>) {
        let err = result.unwrap_err();
        match err {
            PredicateError::PredicateParsingFailed { predicate_type, .. } => {
                assert_eq!(predicate_type, BIP340_SCHNORR_PREDICATE_TYPE);
            }
            _ => panic!("Expected PredicateParsingFailed, got: {err:?}"),
        }
    }

    fn assert_witness_parsing_failed(result: Result<()>) {
        let err = result.unwrap_err();
        match err {
            PredicateError::WitnessParsingFailed { predicate_type, .. } => {
                assert_eq!(predicate_type, BIP340_SCHNORR_PREDICATE_TYPE);
            }
            _ => panic!("Expected WitnessParsingFailed, got: {err:?}"),
        }
    }

    fn assert_verification_failed(result: Result<()>) {
        let err = result.unwrap_err();
        match err {
            PredicateError::VerificationFailed { predicate_type, .. } => {
                assert_eq!(predicate_type, BIP340_SCHNORR_PREDICATE_TYPE);
            }
            _ => panic!("Expected VerificationFailed, got: {err:?}"),
        }
    }

    fn load_predicate_claim_witness() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Generate random message
        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);

        // Generate key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let predicate = verifying_key.to_bytes().to_vec();

        // Create signature
        let sig = signing_key.sign(&msg).to_bytes().to_vec();

        (predicate, msg.to_vec(), sig)
    }

    #[test]
    fn test_schnorr_signature_verification_pass() {
        let verifier = SchnorrVerifier;

        // Generate random message
        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);

        // Create a modified message to test failure cases
        let mut mod_msg = msg;
        mod_msg.swap(1, 2);

        // Generate key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let predicate = verifying_key.to_bytes();

        // Create signatures
        let sig = signing_key.sign(&msg).to_bytes();
        let mod_sig = signing_key.sign(&mod_msg).to_bytes();

        // Test successful verification
        assert!(verifier.verify(&predicate, &msg, &sig).is_ok());

        // Test verification with wrong message should fail
        assert!(verifier.verify(&predicate, &mod_msg, &sig).is_err());

        // Test verification with modified signature for modified message should pass
        assert!(verifier.verify(&predicate, &mod_msg, &mod_sig).is_ok());

        // Test verification with wrong signature should fail
        assert!(verifier.verify(&predicate, &msg, &mod_sig).is_err());
    }

    #[test]
    fn test_schnorr_invalid_predicate() {
        let (predicate, claim, witness) = load_predicate_claim_witness();
        let verifier = SchnorrVerifier;

        // Test with larger predicates
        let mut larger_predicate = predicate.clone();
        larger_predicate.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&larger_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res);

        let mut larger_predicate = predicate.clone();
        larger_predicate.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&larger_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res);

        // Test with shorter predicate
        let shorter_predicate = &predicate[..predicate.len() - 5];
        let res = verifier.verify(shorter_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res);

        let shorter_predicate = &predicate[1..];
        let res = verifier.verify(shorter_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res);
    }

    #[test]
    fn test_schnorr_invalid_witness() {
        let (predicate, claim, mut witness) = load_predicate_claim_witness();
        let verifier = SchnorrVerifier;

        // Test with larger witness
        let mut larger_witness = witness.clone();
        larger_witness.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&predicate, &claim, &larger_witness);
        assert_witness_parsing_failed(res);

        // Test with shorter witness
        let shorter_witness = &witness[..witness.len() - 5];
        let res = verifier.verify(&predicate, &claim, shorter_witness);
        assert_witness_parsing_failed(res);

        // Test with modified bytes inside witness
        witness[0] = witness[0].wrapping_add(1);
        let res = verifier.verify(&predicate, &claim, &witness);
        assert_verification_failed(res);
    }

    #[test]
    fn test_schnorr_invalid_claim() {
        let (predicate, mut claim, witness) = load_predicate_claim_witness();
        let verifier = SchnorrVerifier;

        // Test with larger claim
        let mut larger_claim = claim.clone();
        larger_claim.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&predicate, &larger_claim, &witness);
        assert_verification_failed(res);

        // Test with shorter claim
        let shorter_claim = &claim[..claim.len() - 2];
        let res = verifier.verify(&predicate, shorter_claim, &witness);
        assert_verification_failed(res);

        // Test with modified bytes inside claim
        claim[0] = claim[0].wrapping_add(1);
        let res = verifier.verify(&predicate, &claim, &witness);
        assert_verification_failed(res);
    }
}
