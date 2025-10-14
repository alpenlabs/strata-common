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
}
