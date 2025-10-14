use borsh::{BorshDeserialize, BorshSerialize};

use crate::{PredicateKey, PredicateKeyBuf};

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

    use crate::PredicateTypeId;

    use proptest::prelude::*;
    use zkaleido_sp1_groth16_verifier::SP1_GROTH16_VK_UNCOMPRESSED_SIZE;

    #[test]
    fn test_borsh_serialization_roundtrip() {
        // Test with empty condition
        let predkey1 = PredicateKey::always_accept();
        let serialized1 = borsh::to_vec(&predkey1).unwrap();
        let deserialized1 = borsh::from_slice::<PredicateKey>(&serialized1).unwrap();
        assert_eq!(predkey1, deserialized1);

        // Test with non-empty condition
        let predkey2 = PredicateKey::new(PredicateTypeId::AlwaysAccept, b"test_condition".to_vec());
        let serialized2 = borsh::to_vec(&predkey2).unwrap();
        let deserialized2 = borsh::from_slice::<PredicateKey>(&serialized2).unwrap();
        assert_eq!(predkey2, deserialized2);

        // Test that invalid data fails deserialization
        let invalid_bytes = vec![99u8, 0x01, 0x02];
        assert!(borsh::from_slice::<PredicateKey>(&invalid_bytes).is_err());
    }

    // Strategy to generate arbitrary PredicateTypeId
    fn predicate_type_id_strategy() -> impl Strategy<Value = PredicateTypeId> {
        prop_oneof![
            Just(PredicateTypeId::NeverAccept),
            Just(PredicateTypeId::AlwaysAccept),
            Just(PredicateTypeId::Bip340Schnorr),
            Just(PredicateTypeId::Sp1Groth16),
        ]
    }

    // Strategy to generate arbitrary PredicateKey
    fn predicate_key_strategy() -> impl Strategy<Value = PredicateKey> {
        (
            predicate_type_id_strategy(),
            prop::collection::vec(any::<u8>(), 0..SP1_GROTH16_VK_UNCOMPRESSED_SIZE),
        )
            .prop_map(|(id, condition)| PredicateKey::new(id, condition))
    }

    proptest! {
            #[test]
            fn proptest_borsh_roundtrip(predkey in predicate_key_strategy()) {
                // Serialize the predicate key
                let serialized = borsh::to_vec(&predkey).unwrap();

                // Deserialize it back
                let deserialized = borsh::from_slice::<PredicateKey>(&serialized).unwrap();

                // They should be equal
                prop_assert_eq!(predkey, deserialized);
            }

    }
}
