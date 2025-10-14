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
    use zkaleido_sp1_groth16_verifier::SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED;

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
            prop::collection::vec(any::<u8>(), 0..SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED),
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

            #[test]
            fn proptest_borsh_format_consistency(
                id in predicate_type_id_strategy(),
                condition in prop::collection::vec(any::<u8>(), 0..256)
            ) {
                let predkey = PredicateKey::new(id, condition.clone());
                let serialized = borsh::to_vec(&predkey).unwrap();

                // The borsh format serializes to_bytes() output as Vec<u8>
                // Vec<u8> is serialized as: 4 bytes length (LE) + bytes
                // to_bytes() returns: 1 byte (type_id) + condition bytes
                let expected_len = 4 + 1 + condition.len();
                prop_assert_eq!(serialized.len(), expected_len);

                // Verify we can deserialize it
                let deserialized = borsh::from_slice::<PredicateKey>(&serialized).unwrap();
                prop_assert_eq!(predkey.id(), deserialized.id());
                prop_assert_eq!(predkey.condition(), deserialized.condition());
            }

            #[test]
            fn proptest_borsh_invalid_type_id(
                invalid_type_id in any::<u8>().prop_filter("invalid type id", |&id| {
                    PredicateTypeId::try_from(id).is_err()
                }),
                condition_len in 0..256usize
            ) {
                // Create borsh-serialized data with invalid type ID
                // Format: [vec_len (4 bytes LE)][type_id (1 byte)][condition bytes]
                let mut serialized = Vec::new();

                // Total length is 1 (type_id) + condition_len
                let total_len = 1 + condition_len;
                serialized.extend_from_slice(&(total_len as u32).to_le_bytes());

                // Add the invalid type_id
                serialized.push(invalid_type_id);

                // Add condition bytes
                serialized.extend(vec![0u8; condition_len]);

                // Deserialization should fail
                let result = borsh::from_slice::<PredicateKey>(&serialized);
                prop_assert!(result.is_err());
            }
    }
}
