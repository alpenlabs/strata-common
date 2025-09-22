//! Predicate key implementation and type registry.

use crate::constants::{NEVER_ACCEPT_PREDICATE_TYPE, PredicateType};
use crate::errors::Result;

/// A trait for accessing predicate key data regardless of whether it's owned or borrowed.
///
/// This trait provides a common interface for both owned and borrowed predicate keys,
/// allowing code to work with predicate keys generically without caring about ownership.
pub trait AsPredicateKey {
    /// Returns the raw predicate key bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    fn as_bytes(&self) -> &[u8];

    /// Returns the predicate type identifier.
    ///
    /// If the data is empty, returns [`NEVER_ACCEPT_PREDICATE_TYPE`].
    /// Otherwise, returns the first byte as the predicate type.
    fn predicate_type(&self) -> PredicateType {
        let bytes = self.as_bytes();
        if bytes.is_empty() {
            NEVER_ACCEPT_PREDICATE_TYPE
        } else {
            bytes[0]
        }
    }

    /// Returns the condition data for this predicate key.
    ///
    /// If the data is empty, returns an empty slice.
    /// Otherwise, returns all bytes except the first (type) byte.
    fn condition(&self) -> &[u8] {
        let bytes = self.as_bytes();
        if bytes.is_empty() { &[] } else { &bytes[1..] }
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
    fn verify_claim_witness(&self, claim: &[u8], witness: &[u8]) -> Result<()> {
        crate::verify_claim_witness(self, claim, witness)
    }
}

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

/// A zero-copy predicate key that borrows from a buffer.
///
/// This is useful for parsing predicate keys without allocating when you already have
/// the data in a buffer and want to avoid copying it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PredicateKeyBuf<'b> {
    /// Raw bytes containing the type (first byte) and condition data (remaining bytes).
    /// If empty, represents the "never accept" predicate type.
    buf: &'b [u8],
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

    /// Consumes the predicate key and returns the serialized bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl AsPredicateKey for PredicateKey {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl<'b> PredicateKeyBuf<'b> {
    /// Creates a new predicate key buffer from borrowed bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    /// An empty byte array represents the "never accept" predicate.
    ///
    /// # Arguments
    /// * `buf` - Borrowed predicate key data
    pub fn new(buf: &'b [u8]) -> Self {
        Self { buf }
    }

    /// Converts this borrowed predicate key into an owned [`PredicateKey`].
    ///
    /// This allocates and copies the buffer data.
    pub fn to_owned(&self) -> PredicateKey {
        PredicateKey::from_bytes(self.buf)
    }
}

impl<'b> AsPredicateKey for PredicateKeyBuf<'b> {
    fn as_bytes(&self) -> &[u8] {
        self.buf
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

    #[test]
    fn test_empty_predicate_key_buf() {
        let empty_buf = PredicateKeyBuf::new(&[]);

        // Empty predicate key buffer should return NEVER_ACCEPT_PREDICATE_TYPE
        assert_eq!(empty_buf.predicate_type(), NEVER_ACCEPT_PREDICATE_TYPE);

        // Condition should be empty
        assert_eq!(empty_buf.condition(), &[]);

        // Should be able to convert to owned
        let owned = empty_buf.to_owned();
        assert_eq!(owned.as_bytes(), &[]);
    }

    #[test]
    fn test_non_empty_predicate_key_buf() {
        let data = [ALWAYS_ACCEPT_PREDICATE_TYPE]
            .iter()
            .chain(b"test_condition")
            .copied()
            .collect::<Vec<u8>>();
        let key_buf = PredicateKeyBuf::new(&data);

        // Should return the correct predicate type
        assert_eq!(key_buf.predicate_type(), ALWAYS_ACCEPT_PREDICATE_TYPE);

        // Should return the correct condition
        assert_eq!(key_buf.condition(), b"test_condition");

        // Should return the correct bytes
        assert_eq!(key_buf.as_bytes(), &data);

        // Should be able to convert to owned
        let owned = key_buf.to_owned();
        assert_eq!(owned.predicate_type(), ALWAYS_ACCEPT_PREDICATE_TYPE);
        assert_eq!(owned.condition(), b"test_condition");
    }

    #[test]
    fn test_predicate_key_buf_lifetime() {
        let data = vec![ALWAYS_ACCEPT_PREDICATE_TYPE, 42, 43, 44];

        // This should work - the buffer outlives the PredicateKeyBuf
        let key_buf = PredicateKeyBuf::new(&data);
        assert_eq!(key_buf.predicate_type(), ALWAYS_ACCEPT_PREDICATE_TYPE);
        assert_eq!(key_buf.condition(), &[42, 43, 44]);
    }
}
