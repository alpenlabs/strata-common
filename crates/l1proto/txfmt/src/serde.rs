use std::str::FromStr;

use serde::{Deserialize, Serialize, de};

use crate::magic::MAGIC_BYTES_LEN;
use crate::types::{SubprotocolId, TxType};
use crate::{MagicBytes, TagData};

impl Serialize for MagicBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            // Prefer the readable string form, but fall back to the raw byte
            // array when the magic is not valid UTF-8. Serializing the `Display`
            // output for non-UTF-8 bytes yields the debug array (e.g.
            // `"[255, 254, 0, 1]"`), which deserialization then rejects; the
            // array form round-trips losslessly.
            match self.as_str() {
                Some(readable) => s.serialize_str(readable),
                None => s.serialize_bytes(self.as_bytes()),
            }
        } else {
            s.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for MagicBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HumanReadableVisitor;

            impl<'de> de::Visitor<'de> for HumanReadableVisitor {
                type Value = MagicBytes;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(
                        f,
                        "a {MAGIC_BYTES_LEN}-byte string or a {MAGIC_BYTES_LEN}-element byte array"
                    )
                }

                fn visit_str<E: de::Error>(self, v: &str) -> Result<MagicBytes, E> {
                    MagicBytes::from_str(v).map_err(E::custom)
                }

                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<MagicBytes, E> {
                    let bytes: [u8; MAGIC_BYTES_LEN] = v
                        .try_into()
                        .map_err(|_| E::invalid_length(v.len(), &self))?;
                    Ok(MagicBytes::new(bytes))
                }

                fn visit_seq<A: de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<MagicBytes, A::Error> {
                    let mut bytes = [0u8; MAGIC_BYTES_LEN];
                    for (i, slot) in bytes.iter_mut().enumerate() {
                        *slot = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                    }
                    if seq.next_element::<u8>()?.is_some() {
                        return Err(de::Error::invalid_length(MAGIC_BYTES_LEN + 1, &self));
                    }
                    Ok(MagicBytes::new(bytes))
                }
            }

            // Accepts both the string form (valid UTF-8) and the byte-array
            // fallback (non-UTF-8) emitted by `Serialize` above.
            d.deserialize_any(HumanReadableVisitor)
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

impl Serialize for TagData {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut st = s.serialize_struct("TagData", 3)?;
        st.serialize_field("subproto_id", &self.subproto_id())?;
        st.serialize_field("tx_type", &self.tx_type())?;
        st.serialize_field("aux_data", self.aux_data())?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for TagData {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Route reconstruction through `TagData::new` so deserialized values are
        // validated (e.g. the auxiliary-data length bound) instead of trusting
        // the input verbatim.
        #[derive(Deserialize)]
        struct Helper {
            subproto_id: SubprotocolId,
            tx_type: TxType,
            aux_data: Vec<u8>,
        }

        let helper = Helper::deserialize(d)?;
        TagData::new(helper.subproto_id, helper.tx_type, helper.aux_data).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_data_json_roundtrip() {
        let tag = TagData::new(3, 7, vec![1, 2, 3, 4]).unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(
            json,
            r#"{"subproto_id":3,"tx_type":7,"aux_data":[1,2,3,4]}"#
        );
        let back: TagData = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, back);
    }

    #[test]
    fn test_tag_data_deserialize_rejects_oversized_aux() {
        // 75 bytes exceeds MAX_AUX_LEN (74), so deserialization must fail.
        let aux: Vec<u8> = vec![0; 75];
        let json = format!(
            r#"{{"subproto_id":0,"tx_type":0,"aux_data":{}}}"#,
            serde_json::to_string(&aux).unwrap()
        );
        assert!(serde_json::from_str::<TagData>(&json).is_err());
    }

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

    #[test]
    fn test_human_readable_roundtrip_non_utf8() {
        // Non-UTF-8 magic must survive a JSON round trip: it serializes to the
        // byte-array fallback rather than the lossy `Display` string.
        let magic = MagicBytes::new([0xFF, 0xFE, 0x00, 0x01]);
        let json = serde_json::to_string(&magic).unwrap();
        assert_eq!(json, "[255,254,0,1]");
        let back: MagicBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(magic, back);
    }

    #[test]
    fn test_human_readable_rejects_wrong_length_array() {
        assert!(serde_json::from_str::<MagicBytes>("[1,2,3]").is_err());
        assert!(serde_json::from_str::<MagicBytes>("[1,2,3,4,5]").is_err());
    }
}
