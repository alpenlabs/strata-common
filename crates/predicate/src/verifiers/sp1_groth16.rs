//! SP1 Groth16 proof verification implementation.
//!
//! This module provides predicate verification for SP1-generated Groth16 proofs
//! using types and verification functions from the `zkaleido-sp1-groth16-verifier` crate.

use zkaleido_sp1_groth16_verifier::{SP1Groth16Verifier as Sp1Verifier, Sp1Groth16Proof};

use crate::errors::{PredicateError, PredicateResult};
use crate::type_ids::PredicateTypeId;
use crate::verifier::PredicateVerifier;

/// SP1 Groth16 proof verifier.
///
/// Thin wrapper around `zkaleido-sp1-groth16-verifier`, which performs the actual
/// parsing and proof verification.
///
/// ## Predicate Format
/// - **Condition**: Canonically-encoded `SP1Groth16Verifier` (verifying key + program ID), as
///   produced by `to_uncompressed_bytes` and parsed by `SP1Groth16Verifier::parse`
/// - **Witness**: Groth16 proof bytes; multiple encodings accepted by `Sp1Groth16Proof::parse`
/// - **Claim**: SP1 public values bytes
#[derive(Debug, Default)]
pub(crate) struct Sp1Groth16Verifier;

impl PredicateVerifier for Sp1Groth16Verifier {
    type Condition = Sp1Verifier;
    type Witness = Sp1Groth16Proof;

    fn parse_condition(&self, condition: &[u8]) -> PredicateResult<Self::Condition> {
        Sp1Verifier::parse(condition).map_err(|e| PredicateError::ConditionParsingFailed {
            id: PredicateTypeId::Sp1Groth16,
            reason: e.to_string(),
        })
    }

    fn parse_witness(&self, witness: &[u8]) -> PredicateResult<Self::Witness> {
        Sp1Groth16Proof::parse(witness).map_err(|e| PredicateError::WitnessParsingFailed {
            id: PredicateTypeId::Sp1Groth16,
            reason: e.to_string(),
        })
    }

    fn verify_inner(
        &self,
        program: &Self::Condition,
        claim: &[u8],
        proof: &Self::Witness,
    ) -> PredicateResult<()> {
        program
            .verify_parsed(proof, claim)
            .map_err(|e| PredicateError::VerificationFailed {
                id: PredicateTypeId::Sp1Groth16,
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
    use zkaleido::ProofReceiptWithMetadata;

    use super::*;
    use crate::test_utils::{
        assert_predicate_parsing_failed, assert_verification_failed, assert_witness_parsing_failed,
    };

    fn load_condition_claim_witness() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let proof_data =
            ProofReceiptWithMetadata::load("data/proofs/fibonacci_SP1_v6.1.0.proof.bin").unwrap();

        let verifier = Sp1Verifier::load(
            &GROTH16_VK_BYTES,
            proof_data.metadata().program_id().0,
            *VK_ROOT_BYTES,
            true,
        )
        .unwrap();

        let condition = verifier.to_uncompressed_bytes();
        let claim = proof_data.receipt().public_values().as_bytes().to_vec();
        let witness = proof_data.receipt().proof().as_bytes().to_vec();

        (condition, claim, witness)
    }

    #[test]
    fn test_sp1_groth16_predicate_verification() {
        let (predicate, claim, witness) = load_condition_claim_witness();
        let verifier = Sp1Groth16Verifier;
        let res = verifier.verify(&predicate, &claim, &witness);
        assert!(res.is_ok());
    }

    #[test]
    fn test_sp1_groth16_invalid_condition() {
        let (condition, claim, witness) = load_condition_claim_witness();
        let verifier = Sp1Groth16Verifier;

        // Test with larger predicates
        let mut larger_condition = condition.clone();
        larger_condition.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&larger_condition, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        let mut larger_condition = condition.clone();
        larger_condition.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&larger_condition, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        // Test with shorter predicates
        let shorter_predicate = &condition[..condition.len() - 5];
        let res = verifier.verify(shorter_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        let shorter_predicate = &condition[1..];
        let res = verifier.verify(shorter_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        let mut larger_predicate = condition.clone();
        larger_predicate.extend_from_slice(&[0u8; 10]);
        let same_size_predicate = &larger_predicate[10..];
        assert_eq!(same_size_predicate.len(), condition.len());
        let res = verifier.verify(same_size_predicate, &claim, &witness);
        assert_predicate_parsing_failed(res, PredicateTypeId::Sp1Groth16);
    }

    #[test]
    fn test_sp1_groth16_invalid_witness() {
        let (condition, claim, mut witness) = load_condition_claim_witness();
        let verifier = Sp1Groth16Verifier;

        // Test with larger witnesses
        let mut larger_witness = witness.clone();
        larger_witness.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&condition, &claim, &larger_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        let mut larger_witness = witness.clone();
        larger_witness.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&condition, &claim, &larger_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        // Test with shorter witnesses
        let shorter_witness = &witness[..witness.len() - 5];
        let res = verifier.verify(&condition, &claim, shorter_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        let shorter_witness = &witness[1..];
        let res = verifier.verify(&condition, &claim, shorter_witness);
        assert_witness_parsing_failed(res, PredicateTypeId::Sp1Groth16);

        // Test with modified bytes inside witness
        witness[0] = witness[0].wrapping_add(1);
        let res = verifier.verify(&condition, &claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Sp1Groth16);
    }

    #[test]
    fn test_sp1_groth16_invalid_claim() {
        let (condition, mut claim, witness) = load_condition_claim_witness();
        let verifier = Sp1Groth16Verifier;

        // Test with larger claims
        let mut larger_claim = claim.clone();
        larger_claim.extend_from_slice(&[0u8; 10]);
        let res = verifier.verify(&condition, &larger_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Sp1Groth16);

        let mut larger_claim = claim.clone();
        larger_claim.extend_from_slice(&[0u8; 1]);
        let res = verifier.verify(&condition, &larger_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Sp1Groth16);

        // Test with shorter claims
        let shorter_claim = &claim[..claim.len() - 2];
        let res = verifier.verify(&condition, shorter_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Sp1Groth16);

        let shorter_claim = &claim[1..];
        let res = verifier.verify(&condition, shorter_claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Sp1Groth16);

        // Test with modified bytes inside claim
        claim[0] = claim[0].wrapping_add(1);
        let res = verifier.verify(&condition, &claim, &witness);
        assert_verification_failed(res, PredicateTypeId::Sp1Groth16);
    }
}
