//! Predicate key implementation and type registry.

use crate::errors::PredicateResult;
use crate::type_ids::PredicateTypeId;

/// Decodes predicate key bytes into type ID and condition data.
///
/// This function decodes the raw predicate key bytes into their structured components:
/// the predicate type as a strongly-typed enum and the condition data as a byte slice.
/// This is the primary way to access predicate key components in a type-safe manner.
///
/// For empty predicate keys, returns `PredicateTypeId::NeverAccept` with empty condition data.
///
/// # Arguments
/// * `predicate_bytes` - The raw predicate key bytes in format [type: u8][condition: bytes...]
///
/// # Returns
/// * `Ok((PredicateTypeId, &[u8]))` - The predicate type ID and condition data
/// * `Err(PredicateError)` - Error if the predicate type is invalid
pub(crate) fn decode_predicate_key(
    predicate_bytes: &[u8],
) -> PredicateResult<(PredicateTypeId, &[u8])> {
    if predicate_bytes.is_empty() {
        Ok((PredicateTypeId::NeverAccept, &[]))
    } else {
        let type_id = PredicateTypeId::try_from(predicate_bytes[0])?;
        Ok((type_id, &predicate_bytes[1..]))
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
    data: &'b [u8],
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
    /// use strata_predicate::{PredicateKey, PredicateTypeId};
    ///
    /// let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test".to_vec());
    /// ```
    pub fn new(predicate_type: PredicateTypeId, condition: Vec<u8>) -> Self {
        let mut data = Vec::with_capacity(1 + condition.len());
        data.push(predicate_type.as_u8());
        data.extend_from_slice(&condition);
        Self { data }
    }

    /// Creates a predicate key that always accepts any witness for any claim.
    ///
    /// This is useful for testing scenarios where you need a predicate that
    /// unconditionally validates any input.
    pub fn always_accept() -> Self {
        Self::new(PredicateTypeId::AlwaysAccept, Vec::new())
    }

    /// Creates a predicate key that never accepts any witness for any claim.
    ///
    /// This represents an empty/invalid predicate that will reject all verification attempts.
    /// This is equivalent to creating a predicate key from empty bytes.
    pub fn never_accept() -> Self {
        PredicateKey { data: Vec::new() }
    }

    /// Returns the raw predicate key bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Decodes the predicate key into its type ID and condition data.
    ///
    /// # Returns
    /// * `Ok((PredicateTypeId, &[u8]))` - The predicate type ID and condition data
    /// * `Err(PredicateError)` - Error if the predicate type is invalid
    pub fn decode(&self) -> PredicateResult<(PredicateTypeId, &[u8])> {
        decode_predicate_key(&self.data)
    }

    /// Verifies that a witness satisfies this predicate key for a given claim.
    ///
    /// # Arguments
    /// * `claim` - The claim bytes to verify against
    /// * `witness` - The witness bytes to verify
    ///
    /// # Returns
    /// * `Ok(())` if verification succeeds
    /// * `Err(PredicateError)` if verification fails or an error occurs
    pub fn verify_claim_witness(&self, claim: &[u8], witness: &[u8]) -> PredicateResult<()> {
        crate::verify_claim_witness(&self.data, claim, witness)
    }

    /// Consumes the predicate key and returns the serialized bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl<'b> PredicateKeyBuf<'b> {
    /// Creates a new predicate key buffer from borrowed bytes with validation.
    ///
    /// The format is: [type: u8][condition: bytes...]
    /// An empty byte array represents the "never accept" predicate.
    ///
    /// This method validates that the first byte (if present) represents a valid
    /// predicate type identifier.
    ///
    /// # Arguments
    /// * `data` - Borrowed predicate key data
    ///
    /// # Returns
    /// * `Ok(PredicateKeyBuf)` if the bytes are valid
    /// * `Err(PredicateError)` if the predicate type is invalid
    pub fn try_new(data: &'b [u8]) -> PredicateResult<Self> {
        // Validate the bytes by attempting to decode them
        if data.is_empty() {
            // Empty is valid (represents NeverAccept)
            Ok(Self { data })
        } else {
            // Validate the first byte is a valid predicate type
            PredicateTypeId::try_from(data[0])?;
            Ok(Self { data })
        }
    }

    /// Returns the raw predicate key bytes.
    ///
    /// The format is: [type: u8][condition: bytes...]
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// Decodes the predicate key into its type ID and condition data.
    ///
    /// # Returns
    /// * `Ok((PredicateTypeId, &[u8]))` - The predicate type ID and condition data
    /// * `Err(PredicateError)` - Error if the predicate type is invalid
    pub fn decode(&self) -> PredicateResult<(PredicateTypeId, &[u8])> {
        decode_predicate_key(self.data)
    }

    /// Verifies that a witness satisfies this predicate key for a given claim.
    ///
    /// # Arguments
    /// * `claim` - The claim bytes to verify against
    /// * `witness` - The witness bytes to verify
    ///
    /// # Returns
    /// * `Ok(())` if verification succeeds
    /// * `Err(PredicateError)` if verification fails or an error occurs
    pub fn verify_claim_witness(&self, claim: &[u8], witness: &[u8]) -> PredicateResult<()> {
        crate::verify_claim_witness(self.data, claim, witness)
    }

    /// Converts this borrowed predicate key into an owned [`PredicateKey`].
    ///
    /// This allocates and copies the buffer data without validation.
    /// Use [`try_to_owned`] if you need validation.
    ///
    /// [`try_to_owned`]: Self::try_to_owned
    pub fn to_owned(&self) -> PredicateKey {
        PredicateKey {
            data: self.data.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_ids::PredicateTypeId;

    #[test]
    fn test_empty_predicate_key_buf() {
        let empty_buf = PredicateKeyBuf::try_new(&[]).unwrap();

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
        let data = [PredicateTypeId::AlwaysAccept.as_u8()]
            .iter()
            .chain(b"test_condition")
            .copied()
            .collect::<Vec<u8>>();
        let key_buf = PredicateKeyBuf::try_new(&data).unwrap();

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
    fn test_non_empty_predicate_key() {
        let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_condition".to_vec());

        // Should decode to correct type and condition
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, b"test_condition");

        // Serialization should work correctly
        let serialized = predkey.as_bytes();
        assert_eq!(serialized[0], PredicateTypeId::AlwaysAccept.as_u8());
        assert_eq!(&serialized[1..], b"test_condition");

        // Round-trip should work through PredicateKeyBuf
        let restored_buf = PredicateKeyBuf::try_new(serialized).unwrap();
        let restored = restored_buf.to_owned();
        assert_eq!(predkey, restored);
    }

    #[test]
    fn test_decode_valid_predicate_types() {
        // Test NeverAccept (0)
        let predkey = PredicateKey::new(PredicateTypeId::NeverAccept, b"test".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::NeverAccept);
        assert_eq!(condition, b"test");

        // Test AlwaysAccept (1)
        let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"condition".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, b"condition");

        // Test Bip340Schnorr (10)
        let predkey = PredicateKey::new(PredicateTypeId::Bip340Schnorr, b"pubkey32".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::Bip340Schnorr);
        assert_eq!(condition, b"pubkey32");

        // Test Sp1Groth16 (20)
        let predkey = PredicateKey::new(PredicateTypeId::Sp1Groth16, b"vk_data".to_vec());
        let (type_id, condition) = predkey.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::Sp1Groth16);
        assert_eq!(condition, b"vk_data");
    }

    #[test]
    fn test_decode_invalid_predicate_type() {
        // Test invalid predicate type (99 is not supported)
        let invalid_predkey = PredicateKey {
            data: vec![99, b't', b'e', b's', b't'],
        };
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
        let predkey = PredicateKey::always_accept();
        let (type_id, condition) = predkey.decode().unwrap();

        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);
        assert_eq!(condition, &[]);
    }

    #[test]
    fn test_validation_through_predicate_key_buf() {
        // Valid predicate types should succeed
        assert!(PredicateKeyBuf::try_new(&[PredicateTypeId::AlwaysAccept.as_u8()]).is_ok());
        assert!(PredicateKeyBuf::try_new(&[PredicateTypeId::Bip340Schnorr.as_u8(), 0x01]).is_ok());

        // Empty bytes should succeed (NeverAccept)
        assert!(PredicateKeyBuf::try_new(&[]).is_ok());

        // Invalid predicate type should fail
        assert!(PredicateKeyBuf::try_new(&[99]).is_err());
        assert!(PredicateKeyBuf::try_new(&[255, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_predicate_key_buf_validation_flow() {
        // Valid data should work through try_new
        let valid_data = [PredicateTypeId::AlwaysAccept.as_u8(), 0x01, 0x02];
        let key_buf = PredicateKeyBuf::try_new(&valid_data).unwrap();
        let owned = key_buf.to_owned();
        let (type_id, _) = owned.decode().unwrap();
        assert_eq!(type_id, PredicateTypeId::AlwaysAccept);

        // Invalid data should fail at try_new step
        let invalid_data = [99u8, 0x01, 0x02];
        assert!(PredicateKeyBuf::try_new(&invalid_data).is_err());
    }
}
