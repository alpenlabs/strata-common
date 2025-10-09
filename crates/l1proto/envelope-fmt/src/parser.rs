use bitcoin::{
    Opcode, ScriptBuf,
    opcodes::all::{OP_ENDIF, OP_IF},
    script::{Instruction, Instructions},
};

use crate::errors::EnvelopeParseError;
/// Extract next instruction and try to parse it as an opcode
pub fn next_op(instructions: &mut Instructions<'_>) -> Option<Opcode> {
    let nxt = instructions.next();
    match nxt {
        Some(Ok(Instruction::Op(op))) => Some(op),
        _ => None,
    }
}

/// Parse envelope payload from a script
///
/// Extracts the raw payload bytes from a script containing an envelope structure.
/// The envelope is expected to be wrapped in `OP_FALSE OP_IF ... OP_ENDIF`.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if the script does not contain a valid envelope structure
/// or if the payload cannot be extracted.
pub fn parse_envelope_payload(script: &ScriptBuf) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut instructions = script.instructions();

    enter_envelope(&mut instructions)?;

    // Parse payload
    let payload = extract_until_op_endif(&mut instructions)?;
    Ok(payload)
}

/// Check for consecutive `OP_FALSE` and `OP_IF` that marks the beginning of an envelope
pub fn enter_envelope(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    // loop until OP_FALSE is found
    loop {
        let next = instructions.next();
        match next {
            None => {
                return Err(EnvelopeParseError::InvalidEnvelope);
            }
            // OP_FALSE is basically empty PushBytes
            Some(Ok(Instruction::PushBytes(bytes))) => {
                if bytes.as_bytes().is_empty() {
                    break;
                }
            }
            _ => {
                // Just carry on until OP_FALSE is found
            }
        }
    }

    // Check if next opcode is OP_IF
    let op_if = next_op(instructions);
    if op_if != Some(OP_IF) {
        return Err(EnvelopeParseError::InvalidEnvelope);
    }
    Ok(())
}

/// Extract bytes of `size` from the remaining instructions
pub fn extract_until_op_endif(
    instructions: &mut Instructions<'_>,
) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut data = vec![];
    for elem in instructions {
        match elem {
            Ok(Instruction::Op(OP_ENDIF)) => {
                break;
            }
            Ok(Instruction::PushBytes(b)) => {
                data.extend_from_slice(b.as_bytes());
            }
            _ => {
                return Err(EnvelopeParseError::InvalidPayload);
            }
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {

    use crate::builder::build_envelope_script;

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
}
