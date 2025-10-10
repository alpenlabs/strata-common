//! Serde serialization and deserialization for predicate keys.
//!
//! This module implements `Serialize` and `Deserialize` for [`PredicateKey`] using a
//! human-readable string format.
//!
//! ## Format
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
//! This format is particularly useful for JSON serialization and human-readable
//! configuration files.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{PredicateKey, PredicateTypeId};

impl Serialize for PredicateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = if self.condition().is_empty() {
            format!("{}", self.id())
        } else {
            let hex_condition = hex::encode(self.condition());
            format!("{}:{}", self.id(), hex_condition)
        };
        serializer.serialize_str(&formatted)
    }
}

impl<'de> Deserialize<'de> for PredicateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
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
                .map_err(|e| serde::de::Error::custom(format!("Invalid hex encoding: {}", e)))?
        };

        Ok(PredicateKey::new(id, condition))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

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
}
