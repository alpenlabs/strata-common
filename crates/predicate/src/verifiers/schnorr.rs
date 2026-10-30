//! Implementation for Schnorr BIP-340 signature verification.

use k256::schnorr::{Signature, VerifyingKey};

/// BIP-340 x-only public key size in bytes.
const BIP340_PUBKEY_SIZE: usize = 32;
/// BIP-340 Schnorr signature size in bytes.
const BIP340_SIGNATURE_SIZE: usize = 64;
use signature::Verifier;

use crate::errors::{PredicateError, PredicateResult};
use crate::type_ids::PredicateTypeId;
use crate::verifier::PredicateVerifier;

/// Schnorr BIP-340 signature verifier.
///
/// This verifier provides:
/// - condition: 32-byte x-only public key
/// - claim: message to be signed (serialized as claim bundle)
/// - witness: 64-byte Schnorr signature
#[derive(Debug, Default)]
pub(crate) struct SchnorrVerifier;

impl PredicateVerifier for SchnorrVerifier {
    type Condition = VerifyingKey;
    type Witness = Signature;

    fn parse_condition(&self, condition: &[u8]) -> PredicateResult<Self::Condition> {
        // BIP-340 requires exactly 32 bytes for x-only public keys
        if condition.len() != BIP340_PUBKEY_SIZE {
            return Err(PredicateError::ConditionParsingFailed {
                id: PredicateTypeId::Bip340Schnorr,
                reason: format!(
                    "expected {}-byte x-only public key, got {} bytes",
                    BIP340_PUBKEY_SIZE,
                    condition.len()
                ),
            });
        }

        VerifyingKey::from_slice(condition).map_err(|e| PredicateError::ConditionParsingFailed {
            id: PredicateTypeId::Bip340Schnorr,
            reason: format!("invalid x-only public key: {e}"),
        })
    }

    fn parse_witness(&self, witness: &[u8]) -> PredicateResult<Self::Witness> {
        // BIP-340 Schnorr signatures are exactly 64 bytes
        if witness.len() != BIP340_SIGNATURE_SIZE {
            return Err(PredicateError::WitnessParsingFailed {
                id: PredicateTypeId::Bip340Schnorr,
                reason: format!(
                    "expected {}-byte BIP-340 Schnorr signature, got {} bytes",
                    BIP340_SIGNATURE_SIZE,
                    witness.len()
                ),
            });
        }

        Signature::try_from(witness).map_err(|e| PredicateError::WitnessParsingFailed {
            id: PredicateTypeId::Bip340Schnorr,
            reason: format!("invalid BIP-340 Schnorr signature: {e}"),
        })
    }

    fn verify_inner(
        &self,
        pubkey: &Self::Condition,
        claim: &[u8],
        signature: &Self::Witness,
    ) -> PredicateResult<()> {
        // k256 runs BIP-340 over SHA-256(claim), not over the raw claim.
        pubkey
            .verify(claim, signature)
            .map_err(|e| PredicateError::VerificationFailed {
                id: PredicateTypeId::Bip340Schnorr,
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::Generate;
    use k256::schnorr::SigningKey;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use signature::Signer;

    use super::SchnorrVerifier;
    use crate::test_utils::{
        assert_predicate_parsing_failed, assert_verification_failed, assert_witness_parsing_failed,
    };
    use crate::type_ids::PredicateTypeId;
    use crate::verifier::PredicateVerifier;
    use crate::verifiers::schnorr::{BIP340_PUBKEY_SIZE, BIP340_SIGNATURE_SIZE};

    fn load_predicate_claim_witness() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Generate random message
        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);

        // Generate key pair
        let signing_key = SigningKey::generate();
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
        mod_msg[0] = !mod_msg[0];

        // Generate key pair
        let signing_key = SigningKey::generate();
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

    /// Pins the signed message to SHA-256(claim), so a k256 bump can't change it unnoticed.
    /// The signature was made with k256 0.13.4 over the SHA-256 digest of the claim.
    #[test]
    fn test_schnorr_known_answer() {
        let verifier = SchnorrVerifier;
        let predicate =
            hex::decode("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
                .unwrap();
        let claim = b"strata-predicate bip340 known answer";
        let witness = hex::decode(
            "05fda0574c7d0a90a2826521e2b8de5ccfe18178e7ad1377a67b1d0e863b714e\
             c6f5f3bcff4d5d0e80f1e4682980da3e2dbb487b7107d76af8b9b80dde1b3e52",
        )
        .unwrap();

        assert!(verifier.verify(&predicate, claim, &witness).is_ok());
    }

    #[test]
    fn test_schnorr_invalid_predicate() {
        let (predicate, claim, witness) = load_predicate_claim_witness();
        let verifier = SchnorrVerifier;

        // Test with larger predicates
        let mut larger_predicate = predicate.clone();
        larger_predicate.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&larger_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        let mut larger_predicate = predicate.clone();
        larger_predicate.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&larger_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        // Test with shorter predicate
        let shorter_predicate = &predicate[..predicate.len() - 5];
        let res = verifier.verify(shorter_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        let shorter_predicate = &predicate[1..];
        let res = verifier.verify(shorter_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Bip340Schnorr);
    }

    #[test]
    fn test_schnorr_invalid_witness() {
        let (predicate, claim, mut witness) = load_predicate_claim_witness();
        let verifier = SchnorrVerifier;

        // Test with larger witnesses
        let mut larger_witness = witness.clone();
        larger_witness.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&predicate, &claim, &larger_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        let mut larger_witness = witness.clone();
        larger_witness.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&predicate, &claim, &larger_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        // Test with shorter witnesses
        let shorter_witness = &witness[..witness.len() - 5];
        let res = verifier.verify(&predicate, &claim, shorter_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        let shorter_witness = &witness[1..];
        let res = verifier.verify(&predicate, &claim, shorter_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Bip340Schnorr);

        // Test with modified bytes inside witness
        witness[0] = witness[0].wrapping_add(1);
        let res = verifier.verify(&predicate, &claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Bip340Schnorr);
    }

    #[test]
    fn test_schnorr_invalid_claim() {
        let (predicate, mut claim, witness) = load_predicate_claim_witness();
        let verifier = SchnorrVerifier;

        // Test with larger claims
        let mut larger_claim = claim.clone();
        larger_claim.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&predicate, &larger_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Bip340Schnorr);

        let mut larger_claim = claim.clone();
        larger_claim.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&predicate, &larger_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Bip340Schnorr);

        // Test with shorter claims
        let shorter_claim = &claim[..claim.len() - 2];
        let res = verifier.verify(&predicate, shorter_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Bip340Schnorr);

        let shorter_claim = &claim[1..];
        let res = verifier.verify(&predicate, shorter_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Bip340Schnorr);

        // Test with modified bytes inside claim
        claim[0] = claim[0].wrapping_add(1);
        let res = verifier.verify(&predicate, &claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Bip340Schnorr);
    }

    #[test]
    fn test_sizes() {
        // Directly check that the key size magic number is correct
        let signing_key = SigningKey::generate();
        assert_eq!(
            signing_key.verifying_key().to_bytes().len(),
            BIP340_PUBKEY_SIZE
        );

        // Directly check that the signature size magic number is correct
        assert_eq!(
            signing_key.sign(&[0u8; 32]).to_bytes().len(),
            BIP340_SIGNATURE_SIZE
        );
    }
}
