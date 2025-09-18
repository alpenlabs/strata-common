//! Predicate key implementation and type registry.

use crate::constants::{NEVER_ACCEPT_PREDICATE_TYPE, PredicateType};
use crate::errors::Result;

/// A predicate key encodes a formal boolean statement with a type identifier.
///
/// As defined in the SPS-predicate-fmt specification, a predicate key consists of:
/// - `type`: u8 - Indicates which predicate backend to use
/// - `condition`: bytes - Backend-specific predicate condition data
///
/// Each predicate type has its own interpretation of the condition data:
///
/// An empty predicate key represents the "never accept" predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicateKey {
    /// Raw bytes containing the type (first byte) and condition data (remaining bytes).
    /// If empty, represents the "never accept" predicate type.
    data: Vec<u8>,
}

impl PredicateKey {
    /// Creates a new predicate key from a type identifier and condition data.
    ///
    /// # Arguments
    /// * `predicate_type` - The type of predicate backend to use
    /// * `condition` - The condition data for this predicate type
    ///
    /// # Examples
    /// ```
    /// use strata_predicate::{PredicateKey, ALWAYS_ACCEPT_PREDICATE_TYPE};
    ///
    /// let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"test".to_vec());
    /// ```
    pub fn new(predicate_type: PredicateType, condition: Vec<u8>) -> Self {
        let mut data = Vec::with_capacity(1 + condition.len());
        data.push(predicate_type);
        data.extend_from_slice(&condition);
        Self { data }
    }

    /// Creates a predicate key from serialized bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    /// An empty byte array represents the "never accept" predicate.
    ///
    /// # Arguments
    /// * `bytes` - Serialized predicate key data
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            data: bytes.to_vec(),
        }
    }

    /// Returns a reference to the serialized predicate key bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the predicate key and returns the serialized bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Returns the predicate type identifier.
    ///
    /// If the data is empty, returns [`NEVER_ACCEPT_PREDICATE_TYPE`].
    /// Otherwise, returns the first byte as the predicate type.
    pub fn predicate_type(&self) -> PredicateType {
        if self.data.is_empty() {
            NEVER_ACCEPT_PREDICATE_TYPE
        } else {
            self.data[0]
        }
    }

    /// Returns the condition data for this predicate key.
    ///
    /// If the data is empty, returns an empty slice.
    /// Otherwise, returns all bytes except the first (type) byte.
    pub fn condition(&self) -> &[u8] {
        if self.data.is_empty() {
            &[]
        } else {
            &self.data[1..]
        }
    }

    /// Verifies that a witness satisfies this predicate key for a given claim.
    ///
    /// This is a convenience method that delegates to the global [`verify_claim_witness`] function.
    ///
    /// # Arguments
    /// * `claim` - The claim bytes to verify against
    /// * `witness` - The witness bytes to verify
    ///
    /// # Returns
    /// * `Ok(())` if verification succeeds
    /// * `Err(PredicateError)` if verification fails or an error occurs
    ///
    /// [`verify_claim_witness`]: crate::verify_claim_witness
    pub fn verify_claim_witness(&self, claim: &[u8], witness: &[u8]) -> Result<()> {
        crate::verify_claim_witness(self, claim, witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ALWAYS_ACCEPT_PREDICATE_TYPE;

    #[test]
    fn test_empty_predicate_key() {
        let empty_predkey = PredicateKey::from_bytes(&[]);

        // Empty predicate key should return NEVER_ACCEPT_PREDICATE_TYPE
        assert_eq!(empty_predkey.predicate_type(), NEVER_ACCEPT_PREDICATE_TYPE);

        // Condition should be empty
        assert_eq!(empty_predkey.condition(), &[]);

        // Serialization should work
        assert_eq!(empty_predkey.as_bytes(), vec![]);
    }

    #[test]
    fn test_non_empty_predicate_key() {
        let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"test_condition".to_vec());

        // Should return the correct predicate type
        assert_eq!(predkey.predicate_type(), ALWAYS_ACCEPT_PREDICATE_TYPE);

        // Should return the correct condition
        assert_eq!(predkey.condition(), b"test_condition");

        // Serialization should work correctly
        let serialized = predkey.as_bytes();
        assert_eq!(serialized[0], ALWAYS_ACCEPT_PREDICATE_TYPE);
        assert_eq!(&serialized[1..], b"test_condition");

        // Round-trip should work
        let restored = PredicateKey::from_bytes(serialized);
        assert_eq!(predkey, restored);
    }
}
