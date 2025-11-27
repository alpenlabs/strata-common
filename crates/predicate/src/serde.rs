//! Serde serialization and deserialization for predicate keys.
//!
//! This module implements `Serialize` and `Deserialize` for [`PredicateKey`] using different
//! strategies based on whether the format is human-readable.
//!
//! ## Human-Readable Format (JSON, TOML, etc.)
//!
//! Predicate keys are serialized as strings with the format:
//!
//! ```text
//! {PredicateTypeId}:{hex_condition}
//! ```
//!
//! Where:
//! - `{PredicateTypeId}` is the string representation of the predicate type enum variant
//!   (e.g., "AlwaysAccept", "Bip340Schnorr", "Sp1Groth16")
//! - `{hex_condition}` is the condition bytes encoded as lowercase hexadecimal
//!   (empty string if condition is empty)
//!
//! ## Examples
//!
//! ```text
//! "AlwaysAccept"                     // Empty condition (no colon)
//! "Bip340Schnorr:0102030405"         // 5-byte condition
//! "Sp1Groth16:deadbeef"              // 4-byte condition
//! ```
//!
//! ## Binary Format (bincode, etc.)
//!
//! For non-human-readable formats, the data is serialized as raw bytes in a tuple format:
//! `(predicate_type_id_u8, condition_bytes)`

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::{PredicateKey, PredicateTypeId};

impl Serialize for PredicateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let id: PredicateTypeId = self.id.try_into().map_err(serde::ser::Error::custom)?;
        if serializer.is_human_readable() {
            // Human-readable format: use string representation
            let formatted = if self.condition().is_empty() {
                format!("{id}")
            } else {
                let hex_condition = hex::encode(self.condition());
                format!("{id}:{hex_condition}")
            };
            serializer.serialize_str(&formatted)
        } else {
            // Binary format: serialize as tuple of (id_u8, condition_bytes)
            use serde::ser::SerializeTuple;
            let mut tuple = serializer.serialize_tuple(2)?;
            tuple.serialize_element(&id.as_u8())?;
            tuple.serialize_element(self.condition())?;
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for PredicateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // Human-readable format: expect string representation
            let s = String::deserialize(deserializer)?;
            let parts: Vec<&str> = s.splitn(2, ':').collect();

            let id = parts[0]
                .parse::<PredicateTypeId>()
                .map_err(serde::de::Error::custom)?;

            let condition = if parts.len() == 1 {
                // No colon, empty condition
                Vec::new()
            } else {
                hex::decode(parts[1])
                    .map_err(|e| serde::de::Error::custom(format!("Invalid hex encoding: {e}")))?
            };

            Ok(PredicateKey::new(id, condition))
        } else {
            struct PredicateKeyVisitor;

            impl<'de> Visitor<'de> for PredicateKeyVisitor {
                type Value = PredicateKey;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a tuple of (u8, Vec<u8>)")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let id_u8: u8 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                    let condition: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                    let id = PredicateTypeId::try_from(id_u8).map_err(|e| {
                        serde::de::Error::custom(format!("Invalid predicate type ID: {e}"))
                    })?;

                    Ok(PredicateKey::new(id, condition))
                }
            }

            deserializer.deserialize_tuple(2, PredicateKeyVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use zkaleido_sp1_groth16_verifier::SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED;

    #[test]
    fn test_serde_json_serialization() {
        // Test with empty condition (no colon)
        let predkey1 = PredicateKey::always_accept();
        let json1 = serde_json::to_string(&predkey1).unwrap();
        assert_eq!(json1, r#""AlwaysAccept""#);

        // Test round-trip with empty condition
        let deserialized1: PredicateKey = serde_json::from_str(&json1).unwrap();
        assert_eq!(predkey1, deserialized1);

        // Test with non-empty condition
        let predkey2 = PredicateKey::new(
            PredicateTypeId::Bip340Schnorr,
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
        );
        let json2 = serde_json::to_string(&predkey2).unwrap();
        assert_eq!(json2, r#""Bip340Schnorr:0102030405""#);

        // Test round-trip with non-empty condition
        let deserialized2: PredicateKey = serde_json::from_str(&json2).unwrap();
        assert_eq!(predkey2, deserialized2);

        // Test with another predicate type
        let predkey3 = PredicateKey::new(PredicateTypeId::Sp1Groth16, vec![0xde, 0xad, 0xbe, 0xef]);
        let json3 = serde_json::to_string(&predkey3).unwrap();
        assert_eq!(json3, r#""Sp1Groth16:deadbeef""#);

        let deserialized3: PredicateKey = serde_json::from_str(&json3).unwrap();
        assert_eq!(predkey3, deserialized3);
    }

    #[test]
    fn test_bincode_serialization() {
        // Test with empty condition
        let predkey1 = PredicateKey::always_accept();
        let encoded1 = bincode::serialize(&predkey1).unwrap();
        let decoded1: PredicateKey = bincode::deserialize(&encoded1).unwrap();
        assert_eq!(predkey1, decoded1);

        // Test with non-empty condition
        let predkey2 = PredicateKey::new(
            PredicateTypeId::Bip340Schnorr,
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
        );
        let encoded2 = bincode::serialize(&predkey2).unwrap();
        let decoded2: PredicateKey = bincode::deserialize(&encoded2).unwrap();
        assert_eq!(predkey2, decoded2);

        // Test with another predicate type
        let predkey3 = PredicateKey::new(PredicateTypeId::Sp1Groth16, vec![0xde, 0xad, 0xbe, 0xef]);
        let encoded3 = bincode::serialize(&predkey3).unwrap();
        let decoded3: PredicateKey = bincode::deserialize(&encoded3).unwrap();
        assert_eq!(predkey3, decoded3);
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
            prop::collection::vec(any::<u8>(), 0..SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED),
        )
            .prop_map(|(id, condition)| PredicateKey::new(id, condition))
    }

    proptest! {
            #[test]
            fn proptest_serde_roundtrip(predkey in predicate_key_strategy()) {
                // Serialize the predicate key
                let serialized_json = serde_json::to_vec(&predkey).unwrap();
                let serialized_bincode = bincode::serialize(&predkey).unwrap();

                // Deserialize it back
                let deserialized_json: PredicateKey = serde_json::from_slice(&serialized_json).unwrap();
                let deserialized_bincode: PredicateKey = bincode::deserialize(&serialized_bincode).unwrap();

                // They should be equal
                prop_assert_eq!(&predkey, &deserialized_json);
                prop_assert_eq!(&predkey, &deserialized_bincode);
            }

    }
}
