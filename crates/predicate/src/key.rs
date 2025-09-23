//! Predicate key implementation and type registry.

use crate::errors::PredicateResult;
use crate::type_ids::PredicateTypeId;
use crate::verifiers::VerifierType;

/// A predicate key encodes a formal boolean statement with a type identifier.
///
/// As defined in the SPS-predicate-fmt specification, a predicate key consists of:
/// - `id`: PredicateTypeId - Indicates which predicate backend to use
/// - `data`: Vec<u8> - Backend-specific predicate data
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicateKey {
    /// The predicate type identifier.
    id: PredicateTypeId,
    /// Backend-specific predicate data.
    data: Vec<u8>,
}

/// A zero-copy predicate key that borrows from a buffer.
///
/// This provides efficient parsing of predicate keys without allocation when you already have
/// the serialized data in memory. It references the same structure as PredicateKey but with
/// borrowed data instead of owned data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PredicateKeyBuf<'b> {
    /// The predicate type identifier.
    id: PredicateTypeId,
    /// Backend-specific predicate data.
    data: &'b [u8],
}

impl PredicateKey {
    /// Creates a new predicate key from a type identifier and data.
    ///
    /// # Arguments
    /// * `id` - The predicate type identifier indicating which backend to use
    /// * `data` - The backend-specific predicate data
    ///
    /// # Examples
    /// ```
    /// use strata_predicate::{PredicateKey, PredicateTypeId};
    ///
    /// let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test".to_vec());
    /// ```
    pub fn new(id: PredicateTypeId, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// Returns the predicate type identifier.
    pub fn id(&self) -> PredicateTypeId {
        self.id
    }

    /// Returns a reference to the predicate-specific data.
    pub fn data(&self) -> &[u8] {
        &self.data
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
        PredicateKey {
            id: PredicateTypeId::NeverAccept,
            data: Vec::new(),
        }
    }

    /// Returns a borrowed view of this predicate key as a `PredicateKeyBuf`.
    ///
    /// This provides zero-copy access to the predicate key data.
    pub fn as_buf_ref(&self) -> PredicateKeyBuf<'_> {
        PredicateKeyBuf {
            id: self.id,
            data: &self.data,
        }
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
        self.as_buf_ref().verify_claim_witness(claim, witness)
    }
}

impl<'b> PredicateKeyBuf<'b> {
    /// Creates a new predicate key buffer from borrowed bytes with validation.
    ///
    /// The format is: [id: u8][data: bytes...]
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
            Ok(Self {
                id: PredicateTypeId::NeverAccept,
                data: &[],
            })
        } else {
            // Validate the first byte is a valid predicate type
            let id = PredicateTypeId::try_from(data[0])?;
            Ok(Self {
                id,
                data: &data[1..],
            })
        }
    }

    /// Returns the predicate type identifier.
    pub fn id(&self) -> PredicateTypeId {
        self.id
    }

    /// Returns the predicate-specific data.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Returns the raw predicate key bytes.
    ///
    /// The format is: [id: u8][data: bytes...]
    /// An empty byte array represents the "never accept" predicate.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Handle the special case of NeverAccept with empty data
        if self.id == PredicateTypeId::NeverAccept && self.data.is_empty() {
            return Vec::new();
        }

        let mut bytes = Vec::with_capacity(1 + self.data.len());
        bytes.push(self.id.as_u8());
        bytes.extend_from_slice(self.data);
        bytes
    }

    /// Converts this borrowed predicate key into an owned [`PredicateKey`].
    ///
    /// This allocates and copies the buffer data.
    pub fn to_owned(&self) -> PredicateKey {
        PredicateKey {
            id: self.id,
            data: self.data.to_vec(),
        }
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
        let verifier = VerifierType::from(self.id);
        verifier.verify_claim_witness(self.data(), claim, witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_ids::PredicateTypeId;

    #[test]
    fn test_empty_predicate_key_buf() {
        let empty_buf = PredicateKeyBuf::try_new(&[]).unwrap();

        // Empty predicate key buffer should decode to NeverAccept with empty data
        assert_eq!(empty_buf.id(), PredicateTypeId::NeverAccept);
        assert_eq!(empty_buf.data(), &[]);

        // Should be able to convert to owned
        let owned = empty_buf.to_owned();
        assert_eq!(owned.as_buf_ref().to_bytes(), vec![]); // Fixed: empty bytes for NeverAccept
    }

    #[test]
    fn test_non_empty_predicate_key_buf() {
        let original_data = [PredicateTypeId::AlwaysAccept.as_u8()]
            .iter()
            .chain(b"test_condition")
            .copied()
            .collect::<Vec<u8>>();
        let key_buf = PredicateKeyBuf::try_new(&original_data).unwrap();

        // Should decode to correct type and data
        assert_eq!(key_buf.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(key_buf.data(), b"test_condition");

        // Should return the correct bytes
        assert_eq!(key_buf.to_bytes(), original_data);

        // Should be able to convert to owned
        let owned = key_buf.to_owned();
        assert_eq!(owned.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(owned.data(), b"test_condition");
    }

    #[test]
    fn test_non_empty_predicate_key() {
        let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_condition".to_vec());

        // Should have correct type and data
        assert_eq!(predkey.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(predkey.data(), b"test_condition");

        // Serialization should work correctly through buf_ref
        let serialized = predkey.as_buf_ref().to_bytes();
        assert_eq!(serialized[0], PredicateTypeId::AlwaysAccept.as_u8());
        assert_eq!(&serialized[1..], b"test_condition");

        // Round-trip should work through PredicateKeyBuf
        let restored_buf = PredicateKeyBuf::try_new(&serialized).unwrap();
        let restored = restored_buf.to_owned();
        assert_eq!(predkey, restored);
    }

    #[test]
    fn test_predicate_type_validation() {
        // Test invalid predicate type (99 is not supported) through PredicateKeyBuf
        let invalid_bytes = vec![99u8, b't', b'e', b's', b't'];
        let result = PredicateKeyBuf::try_new(&invalid_bytes);

        assert!(result.is_err());
        match result.unwrap_err() {
            crate::errors::PredicateError::InvalidPredicateType(invalid_type) => {
                assert_eq!(invalid_type, 99);
            }
            _ => panic!("Expected InvalidPredicateType error"),
        }

        // Test that always_accept() creates correct predicate
        let predkey = PredicateKey::always_accept();
        assert_eq!(predkey.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(predkey.data(), &[]);
    }

    #[test]
    fn test_predicate_key_buf_validation() {
        // Valid predicate types should succeed
        assert!(PredicateKeyBuf::try_new(&[PredicateTypeId::AlwaysAccept.as_u8()]).is_ok());
        assert!(PredicateKeyBuf::try_new(&[PredicateTypeId::Bip340Schnorr.as_u8(), 0x01]).is_ok());

        // Empty bytes should succeed (NeverAccept)
        assert!(PredicateKeyBuf::try_new(&[]).is_ok());

        // Invalid predicate types should fail
        assert!(PredicateKeyBuf::try_new(&[99]).is_err());
        assert!(PredicateKeyBuf::try_new(&[255, 0x01, 0x02]).is_err());

        // Valid data should work through try_new and convert properly
        let valid_data = [PredicateTypeId::AlwaysAccept.as_u8(), 0x01, 0x02];
        let key_buf = PredicateKeyBuf::try_new(&valid_data).unwrap();
        let owned = key_buf.to_owned();
        assert_eq!(owned.id(), PredicateTypeId::AlwaysAccept);
    }

    #[test]
    fn test_conversions_and_round_trips() {
        // Test conversion with data
        let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_data".to_vec());
        let key_buf = predkey.as_buf_ref();

        // Should have same type and data
        assert_eq!(key_buf.id(), predkey.id());
        assert_eq!(key_buf.data(), predkey.data());

        // Test round-trip conversion
        let back_to_owned = key_buf.to_owned();
        assert_eq!(predkey, back_to_owned);

        // Test never_accept special case
        let never_accept = PredicateKey::never_accept();
        assert_eq!(never_accept.id(), PredicateTypeId::NeverAccept);
        assert_eq!(never_accept.data(), &[]);
        assert_eq!(never_accept.as_buf_ref().to_bytes(), vec![]);
    }
}
