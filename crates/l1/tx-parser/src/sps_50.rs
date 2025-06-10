use bitcoin::{
    ScriptBuf, Transaction,
    opcodes::{Class, ClassifyContext},
    script::Instruction,
};

use crate::{
    consts::MAGIC_BYTES,
    types::{SubprotocolId, TagPayload},
};

/// Attempt to parse the SPS-50 L1 transaction header from the first output of a Bitcoin
/// `Transaction`.
///
/// The SPS-50 header MUST be encoded as an `OP_RETURN` in output index 0, with payload:
/// ```text
/// [0..4]   ASCII 4 byte magic
/// [4]      subprotocol type (u8)
/// [5]      tx type (u8)
/// [6..]    auxiliary data (ignored here)
/// ```
pub fn parse_sps50_header(tx: &Transaction) -> Option<(SubprotocolId, TagPayload<'_>)> {
    // Ensure there's an output 0
    let first_out = tx.output.first()?;
    let script = &first_out.script_pubkey;

    parse_script(script)
}

fn parse_script(script: &ScriptBuf) -> Option<(SubprotocolId, TagPayload<'_>)> {
    // 1) Iterate instructions: expect first to be the OP_RETURN opcode
    let mut instrs = script.instructions();
    let first_op = instrs.next()?.ok()?.opcode()?;
    if first_op.classify(ClassifyContext::Legacy) != Class::ReturnOp {
        return None;
    }

    // 2) Next instruction must push the header bytes
    let magic_len = MAGIC_BYTES.len();
    let data = match instrs.next()?.ok()? {
        Instruction::PushBytes(d) if d.len() >= magic_len + 2 => d,
        _ => return None,
    };

    let (magic, payload) = data.as_bytes().split_at(MAGIC_BYTES.len());
    // 3) Verify magic bytes
    if magic != MAGIC_BYTES {
        return None;
    }

    // 4) Extract subprotocol and tx type
    let (header, aux) = payload.split_at(2);
    let subproto_id = header[0];
    let txtype = header[1];

    let sps_50_payload = TagPayload::new(txtype, aux);
    Some((subproto_id, sps_50_payload))
}

#[cfg(test)]
mod test {
    use bitcoin::{
        opcodes::all::{OP_DUP, OP_RETURN},
        script::PushBytesBuf,
    };

    use super::*;

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

        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload).unwrap())
            .into_script();

        let (parsed_subproto, tag) = parse_script(&script).expect("should parse");

        assert_eq!(parsed_subproto, subproto_id);
        assert_eq!(tag.tx_type(), tx_type);
        assert_eq!(tag.aux_data(), aux_data);
    }

    #[test]
    fn parse_missing_op_return_fails() {
        let script = ScriptBuf::builder()
            .push_opcode(OP_DUP) // not OP_RETURN
            .into_script();

        assert!(parse_script(&script).is_none());
    }

    #[test]
    fn parse_too_short_push_fails() {
        let too_short = &[0x00, 0x01]; // much less than magic + 2
        let script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::from(too_short))
            .into_script();

        assert!(parse_script(&script).is_none());
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

        assert!(parse_script(&script).is_none());
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

        let (_, tag) = parse_script(&script).unwrap();
        assert_eq!(tag.aux_data(), b"hello_world");
    }

    #[test]
    fn test_roundtrip() {
        let aux_data = [0x22; 10];
        let exp_payload = TagPayload::new(1, &aux_data);
        let exp_subproto_id = 3;

        let script = exp_payload.to_op_return_script(exp_subproto_id).unwrap();
        let (sub_id, payload) = parse_script(&script).unwrap();
        assert_eq!(sub_id, exp_subproto_id);
        assert_eq!(payload.tx_type(), exp_payload.tx_type());
        assert_eq!(payload.aux_data(), exp_payload.aux_data());
    }
}
