use borsh::{BorshDeserialize, BorshSerialize};

use crate::MagicBytes;
use crate::magic::MAGIC_BYTES_LEN;

impl BorshSerialize for MagicBytes {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.as_bytes())
    }
}

impl BorshDeserialize for MagicBytes {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = <[u8; MAGIC_BYTES_LEN]>::deserialize_reader(reader)?;
        Ok(MagicBytes::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_borsh_roundtrip() {
        let magic = MagicBytes::new(*b"STRA");
        let encoded = borsh::to_vec(&magic).unwrap();
        assert_eq!(encoded, b"STRA");
        let back: MagicBytes = borsh::from_slice(&encoded).unwrap();
        assert_eq!(magic, back);
    }

    #[test]
    fn test_borsh_roundtrip_non_utf8() {
        let magic = MagicBytes::new([0xFF, 0xFE, 0x00, 0x01]);
        let encoded = borsh::to_vec(&magic).unwrap();
        let back: MagicBytes = borsh::from_slice(&encoded).unwrap();
        assert_eq!(magic, back);
    }

    #[test]
    fn test_borsh_deserialize_too_short() {
        let result = borsh::from_slice::<MagicBytes>(&[0x01, 0x02]);
        assert!(result.is_err());
    }
}
