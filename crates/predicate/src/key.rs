//! Predicate key implementation and type registry.

use crate::errors::{PredicateError, PredicateResult};
use crate::type_ids::PredicateTypeId;
use crate::verifiers::VerifierType;
use crate::{MAX_CONDITION_LEN, PredicateKey};

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
    /// # Errors
    /// Returns [`PredicateError::ConditionTooLong`] if `condition` is longer than
    /// [`MAX_CONDITION_LEN`].
    pub fn try_new(id: PredicateTypeId, condition: Vec<u8>) -> PredicateResult<Self> {
        let len = condition.len();
        let condition = condition
            .try_into()
            .map_err(|_| PredicateError::ConditionTooLong { len })?;
        Ok(Self {
            id: id.as_u8(),
            condition,
        })
    }

    /// Returns the raw predicate type identifier.
    pub fn id(&self) -> u8 {
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
        Self::try_new(PredicateTypeId::AlwaysAccept, Vec::new())
            .expect("empty condition is always within the length limit")
    }

    /// Creates a predicate key that never accepts any witness for any claim.
    ///
    /// This represents an empty/invalid predicate that will reject all verification attempts.
    pub fn never_accept() -> Self {
        Self::try_new(PredicateTypeId::NeverAccept, Vec::new())
            .expect("empty condition is always within the length limit")
    }

    /// Attempts to borrow this predicate key as a `PredicateKeyBuf`.
    ///
    /// # Errors
    /// Returns an error if the raw type identifier doesn't map to a known [`PredicateTypeId`].
    /// This can't happen for a key built through [`PredicateKey::try_new`], but the SSZ-decoded
    /// `id` field is an unvalidated raw byte, so a key decoded from untrusted bytes (e.g.
    /// `from_ssz_bytes`) can carry an unregistered type.
    pub fn try_as_buf_ref(&self) -> PredicateResult<PredicateKeyBuf<'_>> {
        Ok(PredicateKeyBuf {
            id: self.id.try_into()?,
            condition: &self.condition,
        })
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
        self.try_as_buf_ref()?.verify_claim_witness(claim, witness)
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
        let condition = &bytes[1..];
        if condition.len() > MAX_CONDITION_LEN as usize {
            return Err(PredicateError::ConditionTooLong {
                len: condition.len(),
            });
        }

        Ok(Self { id, condition })
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
            id: self.id.as_u8(),
            // Every `PredicateKeyBuf` is built either from `TryFrom<&[u8]>` (which enforces the
            // length bound) or from `PredicateKey::try_as_buf_ref` (whose condition is already a
            // bounded `VariableList`), so this can never exceed `MAX_CONDITION_LEN`.
            condition: self
                .condition
                .to_vec()
                .try_into()
                .expect("condition length bounded by construction"),
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
        let verifier = VerifierType::try_from(self.id)?;
        verifier.verify_claim_witness(self.condition(), claim, witness)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ssz::view::DecodeView;
    use ssz::{Decode, Encode};

    use super::*;
    use crate::PredicateKeyRef;
    use crate::test_utils::{bounded_condition_strategy, predicate_key_strategy};

    #[test]
    fn proptest_predicate_key_roundtrip() {
        proptest!(|(predkey in predicate_key_strategy())| {
            let condition = predkey.condition().to_vec();
            let id: PredicateTypeId = predkey.id().try_into().unwrap();
            let predkey = PredicateKey::try_new(id, condition.clone()).unwrap();
            let buf = predkey.try_as_buf_ref().unwrap();

            prop_assert_eq!(buf.id(), id);
            prop_assert_eq!(buf.condition(), condition.as_slice());

            let serialized = buf.to_bytes();
            prop_assert_eq!(serialized.first(), Some(&id.as_u8()));
            prop_assert_eq!(&serialized[1..], condition.as_slice());

            let reparsed = PredicateKeyBuf::try_from(serialized.as_slice()).unwrap();
            prop_assert_eq!(reparsed.id(), id);
            prop_assert_eq!(reparsed.condition(), condition.as_slice());

            let owned = reparsed.to_owned();
            prop_assert_eq!(owned.id(), predkey.id());
            prop_assert_eq!(owned.condition(), predkey.condition());
        });
    }

    #[test]
    fn proptest_rejects_invalid_type_id() {
        proptest!(|(
            invalid_type in any::<u8>().prop_filter(
                "invalid predicate type",
                |&id| PredicateTypeId::try_from(id).is_err(),
            ),
            condition in bounded_condition_strategy(64)
        )| {
            let mut bytes = Vec::with_capacity(1 + condition.len());
            bytes.push(invalid_type);
            bytes.extend(condition);

            let result = PredicateKeyBuf::try_from(bytes.as_slice());
            prop_assert!(matches!(result, Err(PredicateError::InvalidPredicateType(id)) if id == invalid_type));
        });
    }

    #[test]
    fn proptest_ssz_roundtrip() {
        proptest!(|(predkey in predicate_key_strategy())| {
            let ssz_bytes = predkey.as_ssz_bytes();

            // Decode via owned SSZ type
            let decoded = PredicateKey::from_ssz_bytes(&ssz_bytes).unwrap();
            prop_assert_eq!(&predkey, &decoded);

            // Decode via zero-copy view
            let view = PredicateKeyRef::from_ssz_bytes(&ssz_bytes).unwrap();
            let owned_from_view = view.to_owned();
            prop_assert_eq!(&predkey, &owned_from_view);
        });
    }

    #[test]
    fn test_missing_type_prefix() {
        let result = PredicateKeyBuf::try_from(&[][..]);
        assert!(matches!(result, Err(PredicateError::MissingPredicateType)));
    }

    #[test]
    fn test_try_new_rejects_oversized_condition() {
        let oversized = vec![0u8; MAX_CONDITION_LEN as usize + 1];
        let result = PredicateKey::try_new(PredicateTypeId::AlwaysAccept, oversized);
        assert!(matches!(
            result,
            Err(PredicateError::ConditionTooLong { len })
            if len == MAX_CONDITION_LEN as usize + 1
        ));
    }

    #[test]
    fn test_try_from_rejects_oversized_condition() {
        let mut bytes = vec![PredicateTypeId::AlwaysAccept.as_u8()];
        bytes.extend(vec![0u8; MAX_CONDITION_LEN as usize + 1]);

        let result = PredicateKeyBuf::try_from(bytes.as_slice());
        assert!(matches!(
            result,
            Err(PredicateError::ConditionTooLong { len })
            if len == MAX_CONDITION_LEN as usize + 1
        ));
    }

    #[test]
    #[cfg(not(feature = "schnorr"))]
    fn test_unsupported_schnorr_gives_helpful_error() {
        let predkey = PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![0u8; 32]).unwrap();
        let claim = b"test claim";
        let witness = b"test witness";

        let result = predkey.verify_claim_witness(claim, witness);

        match result {
            Err(PredicateError::UnsupportedPredicateType { id, reason }) => {
                assert_eq!(id, PredicateTypeId::Bip340Schnorr);
                assert!(reason.contains("schnorr"));
            }
            _ => panic!("Expected UnsupportedPredicateType error, got: {result:?}"),
        }
    }

    #[test]
    #[cfg(not(feature = "sp1-groth16"))]
    fn test_unsupported_sp1_gives_helpful_error() {
        let predkey = PredicateKey::try_new(PredicateTypeId::Sp1Groth16, vec![0u8; 32]).unwrap();
        let claim = b"test claim";
        let witness = b"test witness";

        let result = predkey.verify_claim_witness(claim, witness);

        match result {
            Err(PredicateError::UnsupportedPredicateType { id, reason }) => {
                assert_eq!(id, PredicateTypeId::Sp1Groth16);
                assert!(reason.contains("sp1-groth16"));
            }
            _ => panic!("Expected UnsupportedPredicateType error, got: {result:?}"),
        }
    }
}
