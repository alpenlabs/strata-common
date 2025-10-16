//! Constants and enumerations for predicate type identifiers.
//!
//! This module defines the [`PredicateTypeId`] enum that represents all supported
//! predicate types in the SPS-predicate-fmt specification. Each type has a unique
//! numeric identifier and corresponds to a specific verification backend.
//!
//! The type IDs are designed to be stable and extensible - new predicate types
//! can be added without breaking existing serialized predicate keys.

use core::fmt;
use std::str::FromStr;

use crate::errors::PredicateError;

/// Predicate type identifiers.
///
/// Each variant corresponds to a specific verification backend and has a stable
/// numeric value that's used in the serialized predicate format. The values are
/// chosen to allow for future expansion while maintaining backward compatibility.
///
/// ## Type Categories:
/// - **0-9**: Control flow predicates (never/always accept)
/// - **10-19**: Digital signature predicates
/// - **20-29**: Zero-knowledge proof predicates
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateTypeId {
    /// Never accepts any witness for any claim.
    ///
    /// Represents an invalid/empty predicate that will always fail verification.
    /// Useful for placeholder scenarios where you need a guaranteed-fail predicate.
    NeverAccept = 0,

    /// Always accepts any witness for any claim.
    ///
    /// Used for testing scenarios and placeholder predicates where verification
    /// should always succeed regardless of the witness or claim content.
    AlwaysAccept = 1,

    /// Schnorr signature verification using BIP-340 standard.
    ///
    /// Expects 32-byte x-only public keys and 64-byte signatures.
    /// Used for Bitcoin-compatible Schnorr signature verification.
    Bip340Schnorr = 10,

    /// SP1 Groth16 zero-knowledge proof verification.
    ///
    /// Verifies SP1-generated Groth16 proofs with program ID and public values.
    /// Supports both SHA-256 and Blake3 hashing for claim data.
    Sp1Groth16 = 20,
}

impl PredicateTypeId {
    /// Converts the enum to its underlying u8 value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<PredicateTypeId> for u8 {
    fn from(predicate_type: PredicateTypeId) -> Self {
        predicate_type as u8
    }
}

impl TryFrom<u8> for PredicateTypeId {
    type Error = crate::errors::PredicateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PredicateTypeId::NeverAccept),
            1 => Ok(PredicateTypeId::AlwaysAccept),
            10 => Ok(PredicateTypeId::Bip340Schnorr),
            20 => Ok(PredicateTypeId::Sp1Groth16),
            invalid => Err(PredicateError::InvalidPredicateType(invalid)),
        }
    }
}

impl fmt::Display for PredicateTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredicateTypeId::NeverAccept => write!(f, "NeverAccept"),
            PredicateTypeId::AlwaysAccept => write!(f, "AlwaysAccept"),
            PredicateTypeId::Bip340Schnorr => write!(f, "Bip340Schnorr"),
            PredicateTypeId::Sp1Groth16 => write!(f, "Sp1Groth16"),
        }
    }
}

impl FromStr for PredicateTypeId {
    type Err = PredicateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NeverAccept" => Ok(PredicateTypeId::NeverAccept),
            "AlwaysAccept" => Ok(PredicateTypeId::AlwaysAccept),
            "Bip340Schnorr" => Ok(PredicateTypeId::Bip340Schnorr),
            "Sp1Groth16" => Ok(PredicateTypeId::Sp1Groth16),
            unknown => Err(PredicateError::UnknownPredicateTypeName(
                unknown.to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::PredicateTypeId;

    #[test]
    fn test_roundtrip() {
        // Check that all expected type IDs are canonical
        let valid_bytes = [0, 1, 10, 20];
        for byte in valid_bytes {
            let parsed = PredicateTypeId::try_from(byte).unwrap();
            assert_eq!(parsed.as_u8(), byte);
        }

        // Check an arbitrary invalid type ID
        let invalid_byte = 30;
        assert!(PredicateTypeId::try_from(invalid_byte).is_err());
    }
}
