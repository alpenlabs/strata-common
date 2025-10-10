//! Predicate key implementation and type registry.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::errors::{PredicateError, PredicateResult};
use crate::type_ids::PredicateTypeId;
use crate::verifiers::VerifierType;

/// A predicate key encodes a formal boolean statement with a type identifier.
///
/// As defined in the SPS-predicate-fmt specification, a predicate key consists of:
/// - `id`: PredicateTypeId - Indicates which predicate backend to use
/// - `condition`: `Vec<u8>` - Backend-specific predicate condition bytes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicateKey {
    /// The predicate type identifier.
    id: PredicateTypeId,
    /// Backend-specific predicate condition bytes.
    condition: Vec<u8>,
}

/// A zero-copy predicate key that borrows from a buffer.
///
/// This provides efficient parsing of predicate keys without allocation when you already have
/// the serialized bytes in memory. It references the same structure as [`PredicateKey`] but with
/// borrowed condition bytes instead of owned condition storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PredicateKeyBuf<'b> {
    /// The predicate type identifier.
    id: PredicateTypeId,
    /// Backend-specific predicate condition bytes.
    condition: &'b [u8],
}

impl PredicateKey {
    /// Creates a new predicate key from a type identifier and condition bytes.
    ///
    /// # Arguments
    /// * `id` - The predicate type identifier indicating which backend to use
    /// * `condition` - The backend-specific predicate condition bytes
    ///
    /// # Examples
    /// ```
    /// use strata_predicate::{PredicateKey, PredicateTypeId};
    ///
    /// let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test".to_vec());
    /// ```
    pub fn new(id: PredicateTypeId, condition: Vec<u8>) -> Self {
        Self { id, condition }
    }

    /// Returns the predicate type identifier.
    pub fn id(&self) -> PredicateTypeId {
        self.id
    }

    /// Returns a reference to the predicate-specific condition bytes.
    pub fn condition(&self) -> &[u8] {
        &self.condition
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
    pub fn never_accept() -> Self {
        Self::new(PredicateTypeId::NeverAccept, Vec::new())
    }

    /// Returns a borrowed view of this predicate key as a `PredicateKeyBuf`.
    ///
    /// This provides zero-copy access to the predicate key condition bytes.
    pub fn as_buf_ref(&self) -> PredicateKeyBuf<'_> {
        PredicateKeyBuf {
            id: self.id,
            condition: &self.condition,
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

impl<'b> TryFrom<&'b [u8]> for PredicateKeyBuf<'b> {
    type Error = PredicateError;

    /// Creates a predicate key buffer from borrowed bytes with validation.
    ///
    /// The format is: `[id: u8][condition: bytes…]`. The first byte is validated against
    /// the [`PredicateTypeId`] registry and the remaining bytes are exposed as the predicate
    /// condition payload.
    fn try_from(bytes: &'b [u8]) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(PredicateError::MissingPredicateType);
        }

        let id = PredicateTypeId::try_from(bytes[0])?;
        Ok(Self {
            id,
            condition: &bytes[1..],
        })
    }
}

impl<'b> PredicateKeyBuf<'b> {
    /// Returns the predicate type identifier.
    pub fn id(&self) -> PredicateTypeId {
        self.id
    }

    /// Returns the predicate-specific condition bytes.
    pub fn condition(&self) -> &[u8] {
        self.condition
    }

    /// Returns the raw predicate key bytes.
    ///
    /// The format is: [id: u8][condition: bytes...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.condition.len());
        bytes.push(self.id.as_u8());
        bytes.extend_from_slice(self.condition);
        bytes
    }

    /// Converts this borrowed predicate key into an owned [`PredicateKey`].
    ///
    /// This allocates and copies the buffer condition bytes.
    pub fn to_owned(&self) -> PredicateKey {
        PredicateKey {
            id: self.id,
            condition: self.condition.to_vec(),
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
        verifier.verify_claim_witness(self.condition(), claim, witness)
    }
}

impl BorshSerialize for PredicateKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.as_buf_ref().to_bytes().serialize(writer)
    }
}

impl BorshDeserialize for PredicateKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        PredicateKeyBuf::try_from(bytes.as_slice())
            .map(|buf| buf.to_owned())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_ids::PredicateTypeId;

    #[test]
    fn test_non_empty_predicate_key_buf() {
        let original_data = [PredicateTypeId::AlwaysAccept.as_u8()]
            .iter()
            .chain(b"test_condition")
            .copied()
            .collect::<Vec<u8>>();
        let key_buf = PredicateKeyBuf::try_from(original_data.as_slice()).unwrap();

        // Should decode to correct type and condition bytes
        assert_eq!(key_buf.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(key_buf.condition(), b"test_condition");

        // Should return the correct bytes
        assert_eq!(key_buf.to_bytes(), original_data);

        // Should be able to convert to owned
        let owned = key_buf.to_owned();
        assert_eq!(owned.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(owned.condition(), b"test_condition");
    }

    #[test]
    fn test_non_empty_predicate_key() {
        let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_condition".to_vec());

        // Should have correct type and condition bytes
        assert_eq!(predkey.id(), PredicateTypeId::AlwaysAccept);
        assert_eq!(predkey.condition(), b"test_condition");

        // Serialization should work correctly through buf_ref
        let serialized = predkey.as_buf_ref().to_bytes();
        assert_eq!(serialized[0], PredicateTypeId::AlwaysAccept.as_u8());
        assert_eq!(&serialized[1..], b"test_condition");

        // Round-trip should work through PredicateKeyBuf
        let restored_buf = PredicateKeyBuf::try_from(serialized.as_slice()).unwrap();
        let restored = restored_buf.to_owned();
        assert_eq!(predkey, restored);
    }

    #[test]
    fn test_predicate_type_validation() {
        // Test invalid predicate type (99 is not supported) through PredicateKeyBuf
        let invalid_bytes = vec![99u8, b't', b'e', b's', b't'];
        let result = PredicateKeyBuf::try_from(invalid_bytes.as_slice());

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
        assert!(predkey.condition().is_empty());
    }

    #[test]
    fn test_predicate_key_buf_validation() {
        // Valid predicate types should succeed
        assert!(PredicateKeyBuf::try_from(&[PredicateTypeId::AlwaysAccept.as_u8()][..]).is_ok());
        assert!(
            PredicateKeyBuf::try_from(&[PredicateTypeId::Bip340Schnorr.as_u8(), 0x01][..]).is_ok()
        );

        // Empty bytes should fail
        assert!(PredicateKeyBuf::try_from(&[][..]).is_err());

        // Invalid predicate types should fail
        assert!(PredicateKeyBuf::try_from(&[99][..]).is_err());
        assert!(PredicateKeyBuf::try_from(&[255, 0x01, 0x02][..]).is_err());

        // Valid condition bytes should work through TryFrom and convert properly
        let valid_data = [PredicateTypeId::AlwaysAccept.as_u8(), 0x01, 0x02];
        let key_buf = PredicateKeyBuf::try_from(valid_data.as_slice()).unwrap();
        let owned = key_buf.to_owned();
        assert_eq!(owned.id(), PredicateTypeId::AlwaysAccept);
    }

    #[test]
    fn test_conversions_and_round_trips() {
        // Test conversion with condition bytes
        let predkey = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_data".to_vec());
        let key_buf = predkey.as_buf_ref();

        // Should have same type and condition bytes
        assert_eq!(key_buf.id(), predkey.id());
        assert_eq!(key_buf.condition(), predkey.condition());

        // Test round-trip conversion
        let back_to_owned = key_buf.to_owned();
        assert_eq!(predkey, back_to_owned);
    }

    #[test]
    fn test_borsh_serialization_roundtrip() {
        // Test with empty condition
        let predkey1 = PredicateKey::always_accept();
        let serialized1 = borsh::to_vec(&predkey1).unwrap();
        let deserialized1 = borsh::from_slice::<PredicateKey>(&serialized1).unwrap();
        assert_eq!(predkey1, deserialized1);

        // Test with non-empty condition
        let predkey2 =
            PredicateKey::new(PredicateTypeId::Bip340Schnorr, b"test_condition".to_vec());
        let serialized2 = borsh::to_vec(&predkey2).unwrap();
        let deserialized2 = borsh::from_slice::<PredicateKey>(&serialized2).unwrap();
        assert_eq!(predkey2, deserialized2);

        // Test that invalid data fails deserialization
        let invalid_bytes = vec![99u8, 0x01, 0x02];
        assert!(borsh::from_slice::<PredicateKey>(&invalid_bytes).is_err());
    }
}
