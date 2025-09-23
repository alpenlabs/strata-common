//! Predicate verification trait definition.
//!
//! This module provides the [`PredicateVerifier`] trait that defines how different predicate
//! types parse their conditions and witnesses, and verify claims, as specified in
//! SPS-predicate-fmt.
//!
//! The main verification entry point [`verify_claim_witness`] is located in the crate root.

use crate::errors::Result;

/// Base trait for implementing predicate type-specific verification logic.
///
/// This trait defines the interface for predicate implementations as specified in
/// SPS-predicate-fmt. Each predicate type (Always Accept, BIP-340 Schnorr, SP1 Groth16, etc.)
/// implements this trait to provide parsing and verification capabilities.
pub(crate) trait PredicateVerifier {
    /// The predicate condition type for this implementation.
    /// This can be a structured type that parses the raw condition bytes.
    type Condition;

    /// The witness type for this implementation.
    /// This can be a structured type that parses the raw witness bytes.
    type Witness;

    /// Parses raw condition bytes into the structured predicate type.
    fn parse_condition(&self, condition: &[u8]) -> Result<Self::Condition>;

    /// Parses raw witness bytes into the structured witness type.
    fn parse_witness(&self, witness: &[u8]) -> Result<Self::Witness>;

    /// Internal verification method that takes parsed predicate and witness types.
    fn verify_inner(
        &self,
        predicate: &Self::Condition,
        claim: &[u8],
        witness: &Self::Witness,
    ) -> Result<()>;

    /// Verifies that a witness satisfies the predicate for a given claim.
    ///
    /// This method handles parsing and verification in one step.
    fn verify(&self, condition: &[u8], claim: &[u8], witness: &[u8]) -> Result<()> {
        let predicate = self.parse_condition(condition)?;
        let parsed_witness = self.parse_witness(witness)?;
        self.verify_inner(&predicate, claim, &parsed_witness)
    }
}
