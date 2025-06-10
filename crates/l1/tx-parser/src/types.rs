use bitcoin::{ScriptBuf, opcodes::all::OP_RETURN, script::PushBytesBuf};

use crate::{
    consts::MAGIC_BYTES,
    error::{EncodeResult, SPS50EncodeError},
};

/// Subprotocol id type alias.
pub type SubprotocolId = u8;

/// A parsed SPS-50 tag payload (excluding the 4 byte magic and subprotocol ID),
/// containing the subprotocol-specific transaction type and any auxiliary data.
///
/// This struct represents everything in the OP_RETURN after the first 6 bytes:
/// 1. Byte 0: subprotocol-defined transaction type
/// 2. Bytes 1…: auxiliary payload (type-specific)
#[derive(Debug)]
pub struct TagPayload<'p> {
    /// The transaction type as defined by the SPS-50 subprotocol.
    tx_type: u8,

    /// The remaining, type-specific payload for this transaction.
    auxiliary_data: &'p [u8],
}

impl<'p> TagPayload<'p> {
    /// Constructs a new `Sps50TagPayload`.
    pub fn new(tx_type: u8, auxiliary_data: &'p [u8]) -> Self {
        Self {
            tx_type,
            auxiliary_data,
        }
    }

    /// Returns the subprotocol-defined transaction type.
    pub fn tx_type(&self) -> u8 {
        self.tx_type
    }

    /// Returns the auxiliary data slice associated with this tag.
    pub fn aux_data(&self) -> &[u8] {
        self.auxiliary_data
    }

    /// Encodes the transaction into a Bitcoin `OP_RETURN` script with a subprotocol ID.
    ///
    /// The format is:
    /// - 4-byte magic prefix
    /// - 1 byte for subprotocol ID
    /// - 1 byte for transaction type
    /// - N bytes of auxiliary data
    ///
    /// Fails if the payload (excluding the magic) exceeds 80 bytes.
    pub fn to_op_return_script(&self, subproto_id: SubprotocolId) -> EncodeResult<ScriptBuf> {
        let data_len = self.auxiliary_data.len() + 2; // 1 byte for tx type, 1 byte for subproto id
        let magic_len = MAGIC_BYTES.len();
        if data_len > 80 {
            return Err(SPS50EncodeError::BytesLimitExceed(80));
        }
        let mut data = Vec::with_capacity(data_len + magic_len);

        data.extend_from_slice(MAGIC_BYTES);
        data.push(subproto_id);
        data.push(self.tx_type());
        data.extend_from_slice(self.aux_data());

        let buf = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(data)?)
            .into_script();
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::opcodes::all::OP_RETURN;

    use super::*;

    /// Checks raw script bytes for valid data. It checks the pushbytes opcode and finds out the
    /// data start position.
    fn assert_valid_data(script_bytes: &[u8], sub_id: u8, tx_type: u8, aux_data: &[u8]) {
        let data_start = if script_bytes[1] > 75 { 3 } else { 2 }; // After OP_RETURN and length byte(s)
        let data = &script_bytes[data_start..];

        assert_eq!(&data[0..MAGIC_BYTES.len()], MAGIC_BYTES);
        assert_eq!(data[MAGIC_BYTES.len()], sub_id);
        assert_eq!(data[MAGIC_BYTES.len() + 1], tx_type); // tx_type
        assert_eq!(&data[MAGIC_BYTES.len() + 2..], aux_data);
    }

    #[test]
    fn test_to_op_return_script_success() {
        // Check from aux size 0 to upto the maximum possible size i.e. 78.
        for size in 0..=(80 - 2) {
            let aux_data = vec![0xaa; size];
            let payload = TagPayload::new(123, &aux_data);
            let subproto_id: SubprotocolId = 42;

            let result = payload.to_op_return_script(subproto_id);
            assert!(result.is_ok());

            let script = result.unwrap();

            // Verify it's an OP_RETURN script
            assert!(script.is_op_return());

            // Extract and verify the data
            let script_bytes = script.as_bytes();
            assert_eq!(script_bytes[0], OP_RETURN.to_u8());

            assert_valid_data(script_bytes, subproto_id, 123, &aux_data);
        }
    }

    #[test]
    fn test_to_op_return_script_size_limit_exceeded() {
        // Create aux_data that will exceed 80 byte limit
        let oversized_aux_data = vec![0xFF; 79]; // 79 + 2 = 81 bytes > 80
        let payload = TagPayload::new(1, &oversized_aux_data);
        let subproto_id: SubprotocolId = 1;

        let result = payload.to_op_return_script(subproto_id);
        assert!(result.is_err());

        match result.unwrap_err() {
            SPS50EncodeError::BytesLimitExceed(limit) => {
                assert_eq!(limit, 80);
            }
            _ => panic!("Expected BytesLimitExceed error"),
        }
    }

    #[test]
    fn test_to_op_return_script_different_subproto_ids() {
        let aux_data = b"test";
        let tx_type = 50;
        let payload = TagPayload::new(tx_type, aux_data);

        // Test with different subprotocol IDs
        for subproto_id in 0..=255 {
            let result = payload.to_op_return_script(subproto_id);
            assert!(result.is_ok());

            let script = result.unwrap();
            let script_bytes = script.as_bytes();

            assert_valid_data(script_bytes, subproto_id, tx_type, aux_data);
        }
    }

    #[test]
    fn test_to_op_return_script_various_tx_types() {
        let aux_data = b"data";
        let subproto_id: SubprotocolId = 42;

        // Test with different transaction types
        for tx_type in 0..=255 {
            let payload = TagPayload::new(tx_type, aux_data);
            let result = payload.to_op_return_script(subproto_id);
            assert!(result.is_ok());

            let script = result.unwrap();
            let script_bytes = script.as_bytes();

            assert_valid_data(script_bytes, subproto_id, tx_type, aux_data);
        }
    }
}
