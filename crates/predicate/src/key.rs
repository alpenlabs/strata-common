//! Predicate key implementation and type registry.

use crate::constants::PredicateTypeId;
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

    /// Decodes the predicate key into its type ID and condition data.
    ///
    /// This method decodes the raw predicate key bytes into their structured components:
    /// the predicate type as a strongly-typed enum and the condition data as a byte slice.
    /// This is the primary way to access predicate key components in a type-safe manner.
    ///
    /// For empty predicate keys, returns `PredicateTypeId::NeverAccept` with empty condition data.
    ///
    /// # Returns
    /// * `Ok((PredicateTypeId, &[u8]))` - The predicate type ID and condition data
    /// * `Err(u8)` - The invalid predicate type byte if decoding fails
    ///
    /// # Examples
    /// ```
    /// use strata_predicate::{AsPredicateKey, PredicateKey, PredicateTypeId, ALWAYS_ACCEPT_PREDICATE_TYPE};
    ///
    /// let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"test".to_vec());
    /// let (type_id, condition) = predkey.decode().unwrap();
    /// assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
    /// assert_eq!(condition, b"test");
    ///
    /// // Empty predicate keys return NeverAccept
    /// let empty = PredicateKey::from_bytes(&[]);
    /// let (type_id, condition) = empty.decode().unwrap();
    /// assert_eq!(type_id, PredicateTypeId::NeverAccept);
    /// assert_eq!(condition, &[]);
    /// ```
    fn decode(&self) -> Result<(PredicateTypeId, &[u8])> {
        let bytes = self.as_bytes();
        if bytes.is_empty() {
            Ok((PredicateTypeId::NeverAccept, &[]))
        } else {
            let type_id = PredicateTypeId::try_from(bytes[0])?;
            Ok((type_id, &bytes[1..]))
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
    pub fn new(predicate_type: u8, condition: Vec<u8>) -> Self {
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
    use crate::constants::{
        ALWAYS_ACCEPT_PREDICATE_TYPE, BIP340_SCHNORR_PREDICATE_TYPE, NEVER_ACCEPT_PREDICATE_TYPE,
        SP1_GROTH16_PREDICATE_TYPE,
    };

    #[test]
    fn test_empty_predicate_key() {
        let empty_predkey = PredicateKey::from_bytes(&[]);

        // Empty predicate key should decode to NeverAccept with empty condition
        let (type_id, condition) = empty_predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::NeverAccept);
        assert_eq!(condition, &[]);

        // Serialization should work
        assert_eq!(empty_predkey.as_bytes(), vec![]);
    }

    #[test]
    fn test_non_empty_predicate_key() {
        let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"test_condition".to_vec());

        // Should decode to correct type and condition
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, b"test_condition");

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

        // Empty predicate key buffer should decode to NeverAccept with empty condition
        let (type_id, condition) = empty_buf.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::NeverAccept);
        assert_eq!(condition, &[]);

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

        // Should decode to correct type and condition
        let (type_id, condition) = key_buf.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, b"test_condition");

        // Should return the correct bytes
        assert_eq!(key_buf.as_bytes(), &data);

        // Should be able to convert to owned
        let owned = key_buf.to_owned();
        let (owned_type_id, owned_condition) = owned.decode().unwrap();
        assert_eq!(owned_type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(owned_condition, b"test_condition");
    }

    #[test]
    fn test_decode_valid_predicate_types() {
        // Test NeverAccept (0)
        let predkey = PredicateKey::new(NEVER_ACCEPT_PREDICATE_TYPE, b"test".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::NeverAccept);
        assert_eq!(condition, b"test");

        // Test AlwaysAccept (1)
        let predkey = PredicateKey::new(ALWAYS_ACCEPT_PREDICATE_TYPE, b"condition".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, b"condition");

        // Test Bip340Schnorr (10)
        let predkey = PredicateKey::new(BIP340_SCHNORR_PREDICATE_TYPE, b"pubkey32".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::Bip340Schnorr);
        assert_eq!(condition, b"pubkey32");

        // Test Sp1Groth16 (20)
        let predkey = PredicateKey::new(SP1_GROTH16_PREDICATE_TYPE, b"vk_data".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::Sp1Groth16);
        assert_eq!(condition, b"vk_data");
    }

    #[test]
    fn test_decode_invalid_predicate_type() {
        // Test invalid predicate type (99 is not supported)
        let invalid_predkey = PredicateKey::new(99, b"test".to_vec());
        let result = invalid_predkey.decode();

        assert!(result.is_err());
        match result.unwrap_err() {
            crate::errors::PredicateError::InvalidPredicateType(invalid_type) => {
                assert_eq!(invalid_type, 99);
            }
            _ => panic!("Expected InvalidPredicateType error"),
        }
    }

    #[test]
    fn test_decode_single_byte_predicate() {
        // Test predicate key with only the type byte, no condition
        let predkey = PredicateKey::from_bytes(&[ALWAYS_ACCEPT_PREDICATE_TYPE]);
        let (type_id, condition) = predkey.decode().unwrap();

        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, &[]);
    }
}
