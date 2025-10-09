use bitcoin::{
    Opcode, ScriptBuf,
    opcodes::{
        OP_0, OP_FALSE,
        all::{OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF},
    },
    script::{Instruction, Instructions},
};

use crate::errors::EnvelopeParseError;

/// Extracts the next instruction from the iterator and attempts to parse it as an opcode.
fn next_op(instructions: &mut Instructions<'_>) -> Option<Opcode> {
    match instructions.next() {
        Some(Ok(Instruction::Op(opcode))) => Some(opcode),
        _ => None,
    }
}

/// Parses and extracts the payload from a Bitcoin script envelope.
///
/// Extracts the raw payload bytes from a script containing an envelope structure
/// with the format: `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if the script doesn't contain a valid envelope structure
/// or if the payload data is malformed.
pub fn parse_envelope_payload(script: &ScriptBuf) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut instructions = script.instructions();
    enter_envelope(&mut instructions)?;
    extract_until_op_endif(&mut instructions)
}

/// Parses and extracts all payloads from a script with multiple envelopes.
///
/// Extracts payloads from a script containing multiple sequential envelopes.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if no valid envelopes are found, if any envelope
/// structure is invalid, or if any payload data is malformed.
pub fn parse_multi_envelope_payloads(
    script: &ScriptBuf,
) -> Result<Vec<Vec<u8>>, EnvelopeParseError> {
    let mut instructions = script.instructions();
    let mut payloads = Vec::new();

    while enter_envelope(&mut instructions).is_ok() {
        let payload = extract_until_op_endif(&mut instructions)?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Err(EnvelopeParseError::NoEnvelopesFound);
    }

    Ok(payloads)
}

/// Parses an envelope container and extracts the pubkey and all payloads.
///
/// Parses a script with the structure:
/// ```text
/// <pubkey>
/// CHECKSIGVERIFY
/// <envelope_0>
/// ...
/// <envelope_n>
/// ```
///
/// Returns a tuple containing the pubkey and a vector of all envelope payloads.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if the container structure is invalid, if no valid
/// envelopes are found, or if any payload data is malformed.
pub fn parse_envelope_container(
    script: &ScriptBuf,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), EnvelopeParseError> {
    let mut instructions = script.instructions();

    // Extract pubkey
    let pubkey = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes().to_vec(),
        _ => return Err(EnvelopeParseError::MissingPubkey),
    };

    // Verify CHECKSIGVERIFY
    if next_op(&mut instructions) != Some(OP_CHECKSIGVERIFY) {
        return Err(EnvelopeParseError::MissingChecksigverify);
    }

    // Extract all envelopes
    let mut payloads = Vec::new();
    while enter_envelope(&mut instructions).is_ok() {
        let payload = extract_until_op_endif(&mut instructions)?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Err(EnvelopeParseError::NoEnvelopesFound);
    }

    Ok((pubkey, payloads))
}

/// Locates and validates the envelope start sequence (`OP_FALSE OP_IF`).
fn enter_envelope(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    // Search for OP_FALSE, which can appear in multiple equivalent forms:
    // - Instruction::Op(OP_FALSE) - the OP_FALSE opcode constant
    // - Instruction::Op(OP_0) - OP_0 is an alias for OP_FALSE
    // - Instruction::PushBytes(empty) - OP_FALSE is encoded as OP_PUSHBYTES_0
    //
    // Note: OP_FALSE pushes an empty byte array to the stack. When a script is parsed,
    // it typically appears as Instruction::PushBytes with empty bytes, but we check all
    // forms for maximum compatibility.
    loop {
        match instructions.next() {
            None => return Err(EnvelopeParseError::MissingOpFalse),
            Some(Ok(Instruction::Op(op))) if op == OP_FALSE => break,
            Some(Ok(Instruction::Op(op))) if op == OP_0 => break,
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes().is_empty() => break,
            _ => continue,
        }
    }

    // Verify OP_FALSE is followed by OP_IF
    if next_op(instructions) != Some(OP_IF) {
        return Err(EnvelopeParseError::MissingOpIf);
    }
    Ok(())
}

/// Extracts payload data from push instructions until `OP_ENDIF`.
fn extract_until_op_endif(
    instructions: &mut Instructions<'_>,
) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut payload_data = Vec::new();
    let mut found_endif = false;

    for instruction_result in instructions {
        match instruction_result {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {
                found_endif = true;
                break;
            }
            Ok(Instruction::PushBytes(bytes)) => {
                payload_data.extend_from_slice(bytes.as_bytes());
            }
            _ => return Err(EnvelopeParseError::UnexpectedOpcodeInPayload),
        }
    }

    if !found_endif {
        return Err(EnvelopeParseError::MissingOpEndif);
    }

    Ok(payload_data)
}

#[cfg(test)]
mod tests {
    use crate::builder::{build_envelope_container, build_envelope_script};

    use super::*;

    #[test]
    fn test_parse_envelope_data() {
        let small_envelope = vec![0, 1, 2, 3];
        let script = build_envelope_script(&small_envelope).unwrap();
        let result = parse_envelope_payload(&script).unwrap();

        assert_eq!(result, small_envelope);

        // Try with larger size
        let large_envelope = vec![1; 2000];
        let script = build_envelope_script(&large_envelope).unwrap();

        let result = parse_envelope_payload(&script).unwrap();
        assert_eq!(result, large_envelope);
    }

    #[test]
    fn test_parse_envelope_container() {
        let pubkey = vec![0x02; 33];
        let payloads = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let script = build_envelope_container(&pubkey, &payloads).unwrap();
        let (extracted_pubkey, extracted_payloads) = parse_envelope_container(&script).unwrap();

        assert_eq!(extracted_pubkey, pubkey);
        assert_eq!(extracted_payloads, payloads);
    }

    #[test]
    fn test_parse_single_envelope_in_container() {
        let pubkey = vec![0x03; 33];
        let payloads = vec![vec![9, 8, 7, 6, 5]];
        let script = build_envelope_container(&pubkey, &payloads).unwrap();
        let (extracted_pubkey, extracted_payloads) = parse_envelope_container(&script).unwrap();

        assert_eq!(extracted_pubkey, pubkey);
        assert_eq!(extracted_payloads, payloads);
    }

    #[test]
    fn test_parse_envelope_missing_op_endif() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::{OP_FALSE, all::OP_IF};

        // Build a malformed script: OP_FALSE OP_IF <data> (no OP_ENDIF)
        let malformed_script = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([1, 2, 3])
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(result, Err(EnvelopeParseError::MissingOpEndif)));
    }

    #[test]
    fn test_parse_envelope_missing_op_false() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::all::{OP_ENDIF, OP_IF};

        // Build a malformed script: OP_IF <data> OP_ENDIF (no OP_FALSE)
        let malformed_script = script::Builder::new()
            .push_opcode(OP_IF)
            .push_slice([1, 2, 3])
            .push_opcode(OP_ENDIF)
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(result, Err(EnvelopeParseError::MissingOpFalse)));
    }

    #[test]
    fn test_parse_envelope_missing_op_if() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::{OP_FALSE, all::OP_ENDIF};

        // Build a malformed script: OP_FALSE <data> OP_ENDIF (no OP_IF)
        let malformed_script = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_slice([1, 2, 3])
            .push_opcode(OP_ENDIF)
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(result, Err(EnvelopeParseError::MissingOpIf)));
    }

    #[test]
    fn test_parse_envelope_invalid_payload_instruction() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::{
            OP_FALSE,
            all::{OP_ADD, OP_ENDIF, OP_IF},
        };

        // Build a malformed script with non-push instruction in payload
        let malformed_script = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([1, 2, 3])
            .push_opcode(OP_ADD) // Invalid: non-push opcode in payload
            .push_opcode(OP_ENDIF)
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(
            result,
            Err(EnvelopeParseError::UnexpectedOpcodeInPayload)
        ));
    }

    #[test]
    fn test_parse_envelope_accepts_all_op_false_forms() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::{
            OP_FALSE,
            all::{OP_ENDIF, OP_IF},
        };

        let payload_data = [1u8, 2, 3, 4, 5];

        // Test 1: OP_FALSE from builder (encoded as OP_PUSHBYTES_0)
        let script1 = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(payload_data)
            .push_opcode(OP_ENDIF)
            .into_script();

        let result1 = parse_envelope_payload(&script1).unwrap();
        assert_eq!(result1, payload_data);

        // Test 2: Manually constructed with empty push bytes (same as OP_FALSE)
        let script2 = script::Builder::new()
            .push_slice([]) // Empty push = OP_FALSE
            .push_opcode(OP_IF)
            .push_slice(payload_data)
            .push_opcode(OP_ENDIF)
            .into_script();

        let result2 = parse_envelope_payload(&script2).unwrap();
        assert_eq!(result2, payload_data);

        // All forms should produce the same result
        assert_eq!(result1, result2);
    }
}
