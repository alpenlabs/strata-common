//! Serde serialization implementations for SSZ-generated types.

use crate::{CompactMmr64, MerkleProof, RawMerkleProof};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl<H> Serialize for CompactMmr64<H>
where
    H: Serialize + ssz::Encode + ssz::Decode,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CompactMmr64", 2)?;
        state.serialize_field("entries", &self.entries)?;
        // Convert VariableList to Vec for serialization
        let roots_vec: Vec<&H> = self.roots.iter().collect();
        state.serialize_field("roots", &roots_vec)?;
        state.end()
    }
}

impl<'de, H> Deserialize<'de> for CompactMmr64<H>
where
    H: Deserialize<'de> + ssz::Encode + ssz::Decode,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct CompactMmr64Visitor<H>(std::marker::PhantomData<H>);

        impl<'de, H> Visitor<'de> for CompactMmr64Visitor<H>
        where
            H: Deserialize<'de> + ssz::Encode + ssz::Decode,
        {
            type Value = CompactMmr64<H>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct CompactMmr64")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CompactMmr64<H>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut entries = None;
                let mut roots = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "entries" => {
                            if entries.is_some() {
                                return Err(de::Error::duplicate_field("entries"));
                            }
                            entries = Some(map.next_value()?);
                        }
                        "roots" => {
                            if roots.is_some() {
                                return Err(de::Error::duplicate_field("roots"));
                            }
                            let roots_vec: Vec<H> = map.next_value()?;
                            roots = Some(ssz_types::VariableList::new(roots_vec).map_err(|e| {
                                de::Error::custom(format!("invalid roots length: {e:?}"))
                            })?);
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let entries = entries.ok_or_else(|| de::Error::missing_field("entries"))?;
                let roots = roots.ok_or_else(|| de::Error::missing_field("roots"))?;
                Ok(CompactMmr64 { entries, roots })
            }
        }

        deserializer.deserialize_struct(
            "CompactMmr64",
            &["entries", "roots"],
            CompactMmr64Visitor(std::marker::PhantomData),
        )
    }
}

impl<H> Serialize for RawMerkleProof<H>
where
    H: Serialize + ssz::Encode + ssz::Decode,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RawMerkleProof", 1)?;
        let cohashes_vec: Vec<&H> = self.cohashes.iter().collect();
        state.serialize_field("cohashes", &cohashes_vec)?;
        state.end()
    }
}

impl<'de, H> Deserialize<'de> for RawMerkleProof<H>
where
    H: Deserialize<'de> + ssz::Encode + ssz::Decode,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct RawMerkleProofVisitor<H>(std::marker::PhantomData<H>);

        impl<'de, H> Visitor<'de> for RawMerkleProofVisitor<H>
        where
            H: Deserialize<'de> + ssz::Encode + ssz::Decode,
        {
            type Value = RawMerkleProof<H>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct RawMerkleProof")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RawMerkleProof<H>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut cohashes = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "cohashes" => {
                            if cohashes.is_some() {
                                return Err(de::Error::duplicate_field("cohashes"));
                            }
                            let cohashes_vec: Vec<H> = map.next_value()?;
                            cohashes =
                                Some(ssz_types::VariableList::new(cohashes_vec).map_err(|e| {
                                    de::Error::custom(format!("invalid cohashes length: {e:?}"))
                                })?);
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let cohashes = cohashes.ok_or_else(|| de::Error::missing_field("cohashes"))?;
                Ok(RawMerkleProof { cohashes })
            }
        }

        deserializer.deserialize_struct(
            "RawMerkleProof",
            &["cohashes"],
            RawMerkleProofVisitor(std::marker::PhantomData),
        )
    }
}

impl<H> Serialize for MerkleProof<H>
where
    H: Serialize + ssz::Encode + ssz::Decode,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MerkleProof", 2)?;
        state.serialize_field("inner", &self.inner)?;
        state.serialize_field("index", &self.index)?;
        state.end()
    }
}

impl<'de, H> Deserialize<'de> for MerkleProof<H>
where
    H: Deserialize<'de> + ssz::Encode + ssz::Decode,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct MerkleProofVisitor<H>(std::marker::PhantomData<H>);

        impl<'de, H> Visitor<'de> for MerkleProofVisitor<H>
        where
            H: Deserialize<'de> + ssz::Encode + ssz::Decode,
        {
            type Value = MerkleProof<H>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct MerkleProof")
            }

            fn visit_map<V>(self, mut map: V) -> Result<MerkleProof<H>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut inner = None;
                let mut index = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "inner" => {
                            if inner.is_some() {
                                return Err(de::Error::duplicate_field("inner"));
                            }
                            inner = Some(map.next_value()?);
                        }
                        "index" => {
                            if index.is_some() {
                                return Err(de::Error::duplicate_field("index"));
                            }
                            index = Some(map.next_value()?);
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let inner = inner.ok_or_else(|| de::Error::missing_field("inner"))?;
                let index = index.ok_or_else(|| de::Error::missing_field("index"))?;
                Ok(MerkleProof { inner, index })
            }
        }

        deserializer.deserialize_struct(
            "MerkleProof",
            &["inner", "index"],
            MerkleProofVisitor(std::marker::PhantomData),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::VariableList;

    type TestHash = [u8; 32];

    #[test]
    fn test_compact_mmr_serde_roundtrip() {
        let roots = VariableList::new(vec![[1u8; 32], [2u8; 32], [3u8; 32]]).unwrap();

        let mmr = CompactMmr64 { entries: 7, roots };

        let json = serde_json::to_string(&mmr).unwrap();
        let decoded: CompactMmr64<TestHash> = serde_json::from_str(&json).unwrap();

        assert_eq!(mmr.entries, decoded.entries);
        assert_eq!(mmr.roots.len(), decoded.roots.len());
        for (a, b) in mmr.roots.iter().zip(decoded.roots.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_raw_merkle_proof_serde_roundtrip() {
        let cohashes = VariableList::new(vec![[1u8; 32], [2u8; 32]]).unwrap();

        let proof = RawMerkleProof { cohashes };

        let json = serde_json::to_string(&proof).unwrap();
        let decoded: RawMerkleProof<TestHash> = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.cohashes.len(), decoded.cohashes.len());
        for (a, b) in proof.cohashes.iter().zip(decoded.cohashes.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_merkle_proof_serde_roundtrip() {
        let cohashes = VariableList::new(vec![[1u8; 32], [2u8; 32]]).unwrap();
        let inner = RawMerkleProof { cohashes };

        let proof = MerkleProof { inner, index: 42 };

        let json = serde_json::to_string(&proof).unwrap();
        let decoded: MerkleProof<TestHash> = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.index, decoded.index);
        assert_eq!(proof.inner.cohashes.len(), decoded.inner.cohashes.len());
        for (a, b) in proof
            .inner
            .cohashes
            .iter()
            .zip(decoded.inner.cohashes.iter())
        {
            assert_eq!(a, b);
        }
    }
}
