//! # Strata Predicate Format
//!
//! This crate implements the SPS-predicate-fmt specification for generic versioned
//! predicates, claims, and witnesses. It provides a unified interface for different
//! cryptographic verification systems including digital signatures and zero-knowledge proofs.
//!
//! The library is designed to be extensible, allowing new predicate types to be added
//! while maintaining backward compatibility and a consistent API.
//!
//! ## Core Concepts
//!
//! The predicate format defines three fundamental concepts:
//!
//! - **Predicate Keys**: An encoding of a formal boolean statement with a type identifier
//!   and condition data. Represented by the [`PredicateKey`] struct.
//! - **Claims**: A flat byte array representing a message that allegedly satisfies the predicate
//! - **Witnesses**: An encoded attestation proving that a claim satisfies the predicate
//!
//! These concepts generalize various cryptographic verification systems:
//!
//! ### Digital Signature Verification
//! - **Predicate Key**: Contains the verification public key
//! - **Claim**: The message that was signed
//! - **Witness**: The cryptographic signature
//!
//! ### Zero-Knowledge Proof Verification
//! - **Predicate Key**: Contains the verification key and program identifier
//! - **Claim**: Public inputs to the proof
//! - **Witness**: The zero-knowledge proof
//!
//! ### Testing and Placeholders
//! - **Predicate Key**: "Always Accept" type for testing scenarios
//! - **Claim**: Any data (ignored)
//! - **Witness**: Any data (ignored, always validates)
//!
//! ## Usage Examples
//!
//! ### Basic Verification
//!
//! ```rust
//! use strata_predicate::{PredicateKey, verify_claim_witness, ALWAYS_ACCEPT_PREDICATE_TYPE};
//!
//! // Create a predicate key (always accept type for testing)
//! let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"test_condition".to_vec());
//!
//! // Define claim and witness data
//! let claim = b"hello world";
//! let witness = b"test_signature";
//!
//! // Verify using the global function
//! verify_claim_witness(&predkey, claim, witness).unwrap();
//!
//! // Or verify using the predicate key method
//! predkey.verify_claim_witness(claim, witness).unwrap();
//! ```
//!
//! ### Serialization and Deserialization
//!
//! ```rust
//! use strata_predicate::{PredicateKey, ALWAYS_ACCEPT_PREDICATE_TYPE};
//!
//! // Create a predicate key
//! let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"condition_data".to_vec());
//!
//! // Serialize to bytes
//! let bytes = predkey.clone().into_bytes();
//!
//! // Deserialize from bytes
//! let restored = PredicateKey::from_bytes(&bytes);
//! assert_eq!(predkey, restored);
//! ```
//!
//! ## Supported Predicate Types
//!
//! Each predicate type is identified by a unique constant:
//!
//! - **Never Accept** ([`NEVER_ACCEPT_PREDICATE_TYPE`] = 0):
//!   Never accepts any witness for any claim. Represents an empty/invalid predicate.
//!
//! - **Always Accept** ([`ALWAYS_ACCEPT_PREDICATE_TYPE`] = 1):
//!   Accepts any witness for any claim. Used for testing and placeholder scenarios.
//!
//! - **Schnorr BIP-340** ([`BIP340_SCHNORR_PREDICATE_TYPE`] = 10):
//!   Schnorr signature verification using BIP-340 standard. Expects 32-byte x-only public keys.
//!
//! - **SP1 Groth16 Verifier** ([`SP1_GROTH16_PREDICATE_TYPE`] = 20):
//!   Zero-knowledge proof verification for SP1-generated Groth16 proofs.
//!
//! ## Public API
//!
//! The crate exposes:
//! - [`PredicateKey`]: Core predicate key type with serialization support
//! - [`verify_claim_witness`]: Main verification function
//! - Predicate type constants: [`NEVER_ACCEPT_PREDICATE_TYPE`], [`ALWAYS_ACCEPT_PREDICATE_TYPE`],
//!   [`BIP340_SCHNORR_PREDICATE_TYPE`], [`SP1_GROTH16_PREDICATE_TYPE`]
//!

pub mod constants;
mod errors;
pub mod key;
mod verifier;
mod verifiers;

// Re-export main API
pub use key::PredicateKey;

// Re-export predicate type constants for convenience
pub use constants::{
    ALWAYS_ACCEPT_PREDICATE_TYPE, BIP340_SCHNORR_PREDICATE_TYPE, NEVER_ACCEPT_PREDICATE_TYPE,
    SP1_GROTH16_PREDICATE_TYPE,
};

// Internal imports for the verify_claim_witness function
use errors::Result;
use verifiers::PredicateImpl;

/// Verifies that a witness satisfies a predicate key for a given claim.
///
/// This is the main verification function as specified in SPS-predicate-fmt.
///
/// # Arguments
/// * `predicate` - The predicate key containing the type and condition data
/// * `claim` - The claim bytes to verify against
/// * `witness` - The witness bytes to verify
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * `Err(PredicateError)` if verification fails or an error occurs
pub fn verify_claim_witness(predicate: &PredicateKey, claim: &[u8], witness: &[u8]) -> Result<()> {
    let predicate_impl = PredicateImpl::try_from(predicate.predicate_type())?;
    predicate_impl.verify_claim_witness(predicate.condition(), claim, witness)
}
