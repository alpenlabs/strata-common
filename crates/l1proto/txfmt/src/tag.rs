//! Parsing logic for SPS-50 tx headers.
//!
//! The SPS-50 header MUST be encoded as an `OP_RETURN` in output index 0, with payload:
//!
//! ```text
//! [0..4]   ASCII 4 byte magic
//! [4]      subprotocol type (u8)
//! [5]      tx type (u8)
//! [6..]    auxiliary data (ignored here)
//! ```

use bitcoin::{
    Transaction, opcodes::all::OP_RETURN, script::Instruction, script::PushBytesBuf,
    script::ScriptBuf,
};

use crate::error::{TxFmtError, TxFmtResult};
use crate::types::{MagicBytes, SubprotocolId, TxType};

/// Minimum length of a valid header tag.
const MIN_TAG_LEN: usize = 6;

/// Maximum length of aux data.
const MAX_AUX_LEN: usize = 74;

/// Maximum length of an OP_RETURN.
const MAX_OP_RETURN_LEN: usize = MIN_TAG_LEN + MAX_AUX_LEN;

/// Data extracted from a tx's tag, without the magic bytes.
#[derive(Debug)]
pub struct TagDataRef<'tx> {
    /// The subprotocol ID that recognizes this tx.
    subproto_id: SubprotocolId,

    /// The operation type of the tx within the subprotocol spec.
    tx_type: TxType,

    /// Any auxiliary data passed in the rest of the OP_RETURN data.
    aux_data: &'tx [u8],
}

/// Owned version of tag data extracted from a tx's tag, without the magic bytes.
///
/// This should be used when creating transactions and passing tag data around,
/// not during extraction/parsing where [`TagDataRef`] is more efficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagData {
    /// The subprotocol ID that recognizes this tx.
    subproto_id: SubprotocolId,

    /// The operation type of the tx within the subprotocol spec.
    tx_type: TxType,

    /// Any auxiliary data passed in the rest of the OP_RETURN data.
    aux_data: Vec<u8>,
}

impl<'tx> TagDataRef<'tx> {
    /// Constructs a new instance from data fields, checking that they are
    /// compliant.
    pub fn new(
        subproto_id: SubprotocolId,
        tx_type: TxType,
        aux_data: &'tx [u8],
    ) -> TxFmtResult<Self> {
        if aux_data.len() > MAX_AUX_LEN {
            return Err(TxFmtError::AuxTooLong);
        }

        Ok(Self {
            subproto_id,
            tx_type,
            aux_data,
        })
    }

    /// Constructs a new instance from data fields, without validating them.
    #[cfg(test)]
    pub(crate) fn new_unchecked(
        subproto_id: SubprotocolId,
        tx_type: TxType,
        aux_data: &'tx [u8],
    ) -> Self {
        Self {
            subproto_id,
            tx_type,
            aux_data,
        }
    }

    /// Gets the subprotocol ID.
    pub fn subproto_id(&self) -> SubprotocolId {
        self.subproto_id
    }

    /// Gets the tx type field.
    pub fn tx_type(&self) -> u8 {
        self.tx_type
    }

    /// Gets the aux data slice.
    pub fn aux_data(&self) -> &[u8] {
        self.aux_data
    }

    /// Converts this borrowed tag data into an owned version.
    pub fn to_owned(&self) -> TagData {
        TagData {
            subproto_id: self.subproto_id,
            tx_type: self.tx_type,
            aux_data: self.aux_data.to_vec(),
        }
    }
}

impl TagData {
    /// Constructs a new instance from data fields, checking that they are
    /// compliant.
    pub fn new(
        subproto_id: SubprotocolId,
        tx_type: TxType,
        aux_data: Vec<u8>,
    ) -> TxFmtResult<Self> {
        if aux_data.len() > MAX_AUX_LEN {
            return Err(TxFmtError::AuxTooLong);
        }

        Ok(Self {
            subproto_id,
            tx_type,
            aux_data,
        })
    }

    /// Gets the subprotocol ID.
    pub fn subproto_id(&self) -> SubprotocolId {
        self.subproto_id
    }

    /// Gets the tx type field.
    pub fn tx_type(&self) -> u8 {
        self.tx_type
    }

    /// Gets the aux data slice.
    pub fn aux_data(&self) -> &[u8] {
        &self.aux_data
    }

    /// Borrows this owned tag data as a reference.
    pub fn as_ref(&self) -> TagDataRef<'_> {
        TagDataRef {
            subproto_id: self.subproto_id,
            tx_type: self.tx_type,
            aux_data: &self.aux_data,
        }
    }
}

/// Extracts magic bytes and tag data from a transaction without validating them.
///
/// This reads the first output of the given transaction and attempts to decode
/// an SPS-50 OP_RETURN tag, returning both the discovered magic bytes and the
/// remaining tag data on success. Returns an error if the transaction is
/// missing output 0, is not an OP_RETURN, or the payload is malformed. Callers
/// can use the returned magic value to decide whether the transaction belongs
/// to a known subprotocol.
///
/// to a known subprotocol.
pub fn extract_tx_magic_and_tag<'t>(
    tx: &'t Transaction,
) -> TxFmtResult<(MagicBytes, TagDataRef<'t>)> {
    let first_out = tx.output.first().ok_or(TxFmtError::MissingOutput0)?;
    let data = extract_tag_data_from_script(&first_out.script_pubkey)?;
    extract_magic_and_tag_from_buf(data)
}

/// Config for parsing txs.
#[derive(Clone, Debug)]
pub struct ParseConfig {
    magic_bytes: MagicBytes,
}

impl ParseConfig {
    /// Constructs a new instance.
    pub fn new(magic_bytes: MagicBytes) -> Self {
        Self { magic_bytes }
    }

    /// Attempts to parse a SPS-50 L1 transaction header from a [`Transaction`].
    pub fn try_parse_tx<'t>(&self, tx: &'t Transaction) -> TxFmtResult<TagDataRef<'t>> {
        try_parse_tx_header_tag(tx, self)
    }

    /// Attempts to parse the SPS-50 tag data from a [`ScriptBuf`, which we
    /// presume to be an OP_RETURN output.
    pub fn try_parse_script<'b>(&self, script: &'b ScriptBuf) -> TxFmtResult<TagDataRef<'b>> {
        try_parse_script_buf(script, self)
    }

    /// Attempts to parse the SPS-50 tag data from a buffer, which would be in
    /// the first output of a transaction.
    pub fn try_parse_buf<'b>(&self, buf: &'b [u8]) -> TxFmtResult<TagDataRef<'b>> {
        try_parse_buf(buf, self)
    }

    /// Constructs a [`ScriptBuf`] out of an existing tag data ref.  This MUST
    /// be attached as the first output of a transaction in order to be
    /// recognized correctly.
    pub fn encode_script_buf<'t>(&self, td: &TagDataRef<'t>) -> TxFmtResult<ScriptBuf> {
        let buf = self.encode_tag_buf(td)?;
        let pushbytes = PushBytesBuf::try_from(buf).expect("tag: invalid buf");

        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(pushbytes)
            .into_script();

        Ok(script)
    }

    /// Constructs a tag buffer from a [`TagDataRef`].
    pub fn encode_tag_buf<'t>(&self, td: &TagDataRef<'t>) -> TxFmtResult<Vec<u8>> {
        if td.aux_data.len() > MAX_AUX_LEN {
            return Err(TxFmtError::AuxTooLong);
        }

        let mut buf = Vec::with_capacity(MIN_TAG_LEN + td.aux_data.len());
        buf.extend_from_slice(&self.magic_bytes);
        buf.push(td.subproto_id);
        buf.push(td.tx_type);
        buf.extend_from_slice(td.aux_data);

        // Sanity check.
        assert!(buf.len() <= MAX_OP_RETURN_LEN, "tag: invalid buf");

        Ok(buf)
    }
}

fn try_parse_tx_header_tag<'t>(
    tx: &'t Transaction,
    config: &ParseConfig,
) -> TxFmtResult<TagDataRef<'t>> {
    let (magic, tag) = extract_tx_magic_and_tag(tx)?;
    if magic != config.magic_bytes {
        return Err(TxFmtError::MismatchMagic(magic));
    }

    Ok(tag)
}

fn try_parse_script_buf<'t>(
    script: &'t ScriptBuf,
    config: &ParseConfig,
) -> TxFmtResult<TagDataRef<'t>> {
    let data = extract_tag_data_from_script(script)?;
    try_parse_buf(data, config)
}

fn extract_tag_data_from_script(script: &ScriptBuf) -> TxFmtResult<&[u8]> {
    // 2) Iterate instructions: expect first to be the OP_RETURN opcode
    let mut instrs = script.instructions();
    match instrs.next() {
        Some(Ok(Instruction::Op(op))) if op == OP_RETURN => {}
        _ => return Err(TxFmtError::NotOpret),
    }

    // 3) Next instruction must push the header bytes (>= 6 bytes)
    let data = match instrs.next() {
        Some(Ok(Instruction::PushBytes(d))) => d,
        _ => return Err(TxFmtError::MalformedOpret),
    };

    Ok(data.as_bytes())
}

fn try_parse_buf<'t>(buf: &'t [u8], config: &ParseConfig) -> TxFmtResult<TagDataRef<'t>> {
    let (magic, tag) = extract_magic_and_tag_from_buf(buf)?;
    if magic != config.magic_bytes {
        return Err(TxFmtError::MismatchMagic(magic));
    }

    Ok(tag)
}

fn extract_magic_and_tag_from_buf<'t>(buf: &'t [u8]) -> TxFmtResult<(MagicBytes, TagDataRef<'t>)> {
    if buf.len() < MIN_TAG_LEN {
        return Err(TxFmtError::MalformedOpret);
    }

    let mut magic = [0; 4];
    magic.copy_from_slice(&buf[..4]);

    let subproto_id = buf[4];
    let tx_type = buf[5];
    let aux_data = &buf[MIN_TAG_LEN..];

    if aux_data.len() >= MAX_AUX_LEN {
        return Err(TxFmtError::AuxTooLong);
    }

    Ok((
        magic,
        TagDataRef {
            subproto_id,
            tx_type,
            aux_data,
        },
    ))
}

#[cfg(test)]
mod test {
    use bitcoin::{
        Amount, Transaction, TxOut, absolute,
        opcodes::all::{OP_DUP, OP_RETURN},
        script::PushBytesBuf,
        transaction::Version,
    };

    use super::*;

    const MAGIC_BYTES: &[u8; 4] = &[1, 2, 3, 4];

    fn parse_script<'t>(script: &'t ScriptBuf) -> TxFmtResult<TagDataRef<'t>> {
        let config = ParseConfig {
            magic_bytes: *MAGIC_BYTES,
        };

        config.try_parse_script(script)
    }

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
    fn parse_valid_script() {
        let magic = MAGIC_BYTES;
        let subproto_id = 42u8;
        let tx_type = 1u8;
        let aux_data = b"abc";

        let mut payload = Vec::new();
        payload.extend_from_slice(magic);
        payload.push(subproto_id);
        payload.push(tx_type);
        payload.extend_from_slice(aux_data);

        eprintln!("{payload:?}");

        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload).unwrap())
            .into_script();

        let tag = parse_script(&script).expect("test: should parse");
        assert_eq!(tag.subproto_id(), subproto_id);
        assert_eq!(tag.tx_type(), tx_type);
        assert_eq!(tag.aux_data(), aux_data);
    }

    #[test]
    fn parse_tx_without_magic_validation() {
        let magic = MAGIC_BYTES;
        let subproto_id = 7u8;
        let tx_type = 11u8;
        let aux_data = b"xyz";

        let mut payload = Vec::new();
        payload.extend_from_slice(magic);
        payload.push(subproto_id);
        payload.push(tx_type);
        payload.extend_from_slice(aux_data);

        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload).unwrap())
            .into_script();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: script,
            }],
        };

        let (magic_bytes, tag) = extract_tx_magic_and_tag(&tx).expect("test: should parse");
        assert_eq!(magic_bytes, *MAGIC_BYTES);
        assert_eq!(tag.subproto_id(), subproto_id);
        assert_eq!(tag.tx_type(), tx_type);
        assert_eq!(tag.aux_data(), aux_data);
    }

    #[test]
    fn parse_missing_op_return_fails() {
        let script = ScriptBuf::builder()
            .push_opcode(OP_DUP) // not OP_RETURN
            .into_script();

        assert!(parse_script(&script).is_err());
    }

    #[test]
    fn parse_too_short_push_fails() {
        let too_short = &[0x00, 0x01]; // much less than magic + 2
        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::from(too_short))
            .into_script();

        assert!(parse_script(&script).is_err());
    }

    #[test]
    fn parse_invalid_magic_fails() {
        let mut magic = MAGIC_BYTES.to_vec();
        magic[0] ^= 0xff; // Invert first byte to ensure this is bad magic

        let mut payload = magic;
        payload.extend_from_slice(b"abc");

        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload).unwrap())
            .into_script();

        assert!(parse_script(&script).is_err());
    }

    #[test]
    fn parse_with_extra_aux_data() {
        let mut payload = Vec::new();
        payload.extend_from_slice(MAGIC_BYTES);
        payload.push(1); // subproto
        payload.push(2); // tx_type
        payload.extend_from_slice(b"hello_world");

        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload).unwrap())
            .into_script();

        let tag = parse_script(&script).unwrap();
        assert_eq!(tag.aux_data(), b"hello_world");
    }

    #[test]
    fn test_roundtrip() {
        let aux_data = [0x22; 10];
        let exp_subproto_id = 3;
        let exp_tag = TagDataRef::new(exp_subproto_id, 1, &aux_data).unwrap();

        let config = ParseConfig::new(*MAGIC_BYTES);
        let script = config.encode_script_buf(&exp_tag).unwrap();

        let tag = parse_script(&script).unwrap();
        assert_eq!(tag.subproto_id(), exp_subproto_id);
        assert_eq!(tag.tx_type(), exp_tag.tx_type());
        assert_eq!(tag.aux_data(), exp_tag.aux_data());
    }

    #[test]
    fn test_to_op_return_script_success() {
        let config = ParseConfig::new(*MAGIC_BYTES);

        // Check from aux size 0 to upto the maximum possible size i.e. 74.
        for size in 0..=MAX_AUX_LEN {
            let aux_data = vec![0xaa; size];
            let subproto_id: SubprotocolId = 42;
            let tag = TagDataRef::new(subproto_id, 123, &aux_data).unwrap();

            let script = config.encode_script_buf(&tag).unwrap();

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
        let config = ParseConfig::new(*MAGIC_BYTES);

        // Create aux_data that will exceed 80 byte limit
        let oversized_aux_data = vec![0xFF; 79]; // 79 + 2 = 81 bytes > 80
        let subproto_id: SubprotocolId = 1;
        let tag = TagDataRef::new_unchecked(subproto_id, 1, &oversized_aux_data);

        let result = config.encode_script_buf(&tag);
        assert!(result.is_err());

        match result.unwrap_err() {
            TxFmtError::AuxTooLong => {}
            e => panic!("test: expected AuxTooLong error (got {e:?})"),
        }
    }

    #[test]
    fn test_to_op_return_script_different_subproto_ids() {
        let config = ParseConfig::new(*MAGIC_BYTES);

        let aux_data = b"test";
        let tx_type = 50;

        // Test with different subprotocol IDs
        for subproto_id in 0..=255 {
            let tag = TagDataRef::new(subproto_id, tx_type, aux_data).unwrap();

            let result = config.encode_script_buf(&tag);
            assert!(result.is_ok());

            let script = result.unwrap();
            let script_bytes = script.as_bytes();

            assert_valid_data(script_bytes, subproto_id, tx_type, aux_data);
        }
    }

    #[test]
    fn test_to_op_return_script_various_tx_types() {
        let config = ParseConfig::new(*MAGIC_BYTES);
        let aux_data = b"data";

        // Test with different transaction types
        for tx_type in 0..=255 {
            let subproto_id: SubprotocolId = 42;
            let tag = TagDataRef::new(subproto_id, tx_type, aux_data).unwrap();
            let result = config.encode_script_buf(&tag);
            assert!(result.is_ok());

            let script = result.unwrap();
            let script_bytes = script.as_bytes();

            assert_valid_data(script_bytes, subproto_id, tx_type, aux_data);
        }
    }
}
