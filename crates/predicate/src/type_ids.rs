//! Constants for predicate types and values.

use core::fmt;

use crate::errors::PredicateError;

/// Predicate type identifiers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateTypeId {
    /// Never accepts any witness for any claim predicate type.
    NeverAccept = 0,
    /// Always accepts any witness for any claim predicate type.
    AlwaysAccept = 1,
    /// Schnorr signature verification using BIP-340 predicate type.
    Bip340Schnorr = 10,
    /// SP1 Groth16 verifier program verification predicate type.
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
