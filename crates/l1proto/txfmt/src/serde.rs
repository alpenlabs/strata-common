use std::str::FromStr;

use serde::de;
use serde::{Deserialize, Serialize};

use crate::MagicBytes;
use crate::magic::MAGIC_BYTES_LEN;

impl Serialize for MagicBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for MagicBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct StrVisitor;

            impl de::Visitor<'_> for StrVisitor {
                type Value = MagicBytes;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "a {MAGIC_BYTES_LEN}-byte string")
                }

                fn visit_str<E: de::Error>(self, v: &str) -> Result<MagicBytes, E> {
                    MagicBytes::from_str(v).map_err(E::custom)
                }
            }

            d.deserialize_str(StrVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> de::Visitor<'de> for BytesVisitor {
                type Value = MagicBytes;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{MAGIC_BYTES_LEN} bytes")
                }

                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<MagicBytes, E> {
                    let bytes: [u8; MAGIC_BYTES_LEN] = v
                        .try_into()
                        .map_err(|_| E::invalid_length(v.len(), &self))?;
                    Ok(MagicBytes::new(bytes))
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_readable_roundtrip() {
        let magic = MagicBytes::new(*b"STRA");
        let json = serde_json::to_string(&magic).unwrap();
        assert_eq!(json, "\"STRA\"");
        let back: MagicBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(magic, back);
    }

    #[test]
    fn test_binary_roundtrip() {
        let magic = MagicBytes::new(*b"STRA");
        let encoded = bincode::serialize(&magic).unwrap();
        let back: MagicBytes = bincode::deserialize(&encoded).unwrap();
        assert_eq!(magic, back);
    }

    #[test]
    fn test_binary_roundtrip_non_utf8() {
        let magic = MagicBytes::new([0xFF, 0xFE, 0x00, 0x01]);
        let encoded = bincode::serialize(&magic).unwrap();
        let back: MagicBytes = bincode::deserialize(&encoded).unwrap();
        assert_eq!(magic, back);
    }

    #[test]
    fn test_human_readable_invalid_length() {
        let result: Result<MagicBytes, _> = serde_json::from_str("\"AB\"");
        assert!(result.is_err());
    }
}
