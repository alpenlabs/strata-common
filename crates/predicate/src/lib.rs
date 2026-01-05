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
//! use strata_predicate::{PredicateKey, PredicateTypeId};
//!
//! // Create a predicate key (always accept type for testing)
//! let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_condition".to_vec());
//!
//! // Define claim and witness data
//! let claim = b"hello world";
//! let witness = b"test_signature";
//!
//! // Verify using the global function
//! let predicate_bytes = predkey.as_buf_ref().to_bytes();
//! strata_predicate::verify_claim_witness(&predicate_bytes, claim, witness).unwrap();
//!
//! // Or verify using the predicate key method
//! predkey.verify_claim_witness(claim, witness).unwrap();
//! ```
//!
//!
//! ## Supported Predicate Types
//!
//! Each predicate type is identified by a unique constant:
//!
//! - **Never Accept** ([`PredicateTypeId::NeverAccept`] = 0):
//!   Never accepts any witness for any claim. Represents an empty/invalid predicate.
//!
//! - **Always Accept** ([`PredicateTypeId::AlwaysAccept`] = 1):
//!   Accepts any witness for any claim. Used for testing and placeholder scenarios.
//!
//! - **Schnorr BIP-340** ([`PredicateTypeId::Bip340Schnorr`] = 10):
//!   Schnorr signature verification using BIP-340 standard. Expects 32-byte x-only public keys.
//!   *Requires the `verify-schnorr` feature.*
//!
//! - **SP1 Groth16 Verifier** ([`PredicateTypeId::Sp1Groth16`] = 20):
//!   Zero-knowledge proof verification for SP1-generated Groth16 proofs.
//!   *Requires the `verify-sp1-groth16` feature.*
//!
//! ## Feature Flags
//!
//! ### Serialization
//! - `serde`: Enables Serialize/Deserialize implementations (default)
//! - `borsh`: Enables Borsh serialization support (default)
//!
//! ### Verification
//! - `verify-schnorr`: Enables Schnorr BIP-340 signature verification
//! - `verify-sp1-groth16`: Enables SP1 Groth16 zero-knowledge proof verification
//! - `verify-all`: Enables all verification backends (convenience feature)
//!
//! **Note**: The base [`verify_claim_witness`] function is always available and works with
//! `AlwaysAccept` and `NeverAccept` predicates without any features. Specific verifier features
//! are only needed for cryptographic verification.
//!
//! ## Public API
//!
//! The crate exposes:
//! - [`PredicateKey`]: Core predicate key type with serialization support
//! - [`PredicateKeyBuf`]: Zero-copy borrowed variant of predicate key
//! - [`verify_claim_witness`]: Main verification function
//! - [`PredicateTypeId`]: Enum representing all supported predicate types
//!

mod errors;
pub mod key;
#[cfg(test)]
mod test_utils;
pub mod type_ids;
mod verifier;
mod verifiers;

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "borsh")]
mod borsh;

#[cfg(feature = "arbitrary")]
mod arbitrary;

// Suppress unused dev-dependency warnings when verify features are disabled
#[cfg(all(test, not(feature = "verify-schnorr")))]
use rand as _;
#[cfg(all(test, not(feature = "verify-sp1-groth16")))]
use sp1_verifier as _;
#[cfg(all(test, not(feature = "verify-sp1-groth16")))]
use zkaleido as _;

#[allow(unreachable_pub, missing_docs, reason = "generated code")]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

// Publicly re-export only the SSZ items this crate's API intends to expose
pub use ssz_generated::ssz::key::{MAX_CONDITION_LEN, PredicateKey, PredicateKeyRef};

// Re-export main API
pub use key::PredicateKeyBuf;

// Re-export predicate type constants and enum for convenience
pub use type_ids::PredicateTypeId;

// Internal imports for the verify_claim_witness function
pub use errors::{PredicateError, PredicateResult};

/// Verifies that a witness satisfies a predicate key for a given claim.
///
/// This is the main verification function as specified in SPS-predicate-fmt.
///
/// # Arguments
/// * `predicate_bytes` - The raw predicate key bytes in format [type: u8][condition: bytes...]
/// * `claim` - The claim bytes to verify against
/// * `witness` - The witness bytes to verify
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * `Err(PredicateError)` if verification fails or an error occurs
pub fn verify_claim_witness(
    predicate_bytes: &[u8],
    claim: &[u8],
    witness: &[u8],
) -> PredicateResult<()> {
    let predicate = PredicateKeyBuf::try_from(predicate_bytes)?;
    predicate.verify_claim_witness(claim, witness)
}
