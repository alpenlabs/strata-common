use bitcoin::{
    Opcode, ScriptBuf,
    opcodes::all::{OP_ENDIF, OP_IF},
    script::{Instruction, Instructions},
};

use crate::errors::EnvelopeParseError;

/// Extracts the next instruction from the iterator and attempts to parse it as an opcode.
///
/// This helper function consumes the next instruction from the script instruction iterator
/// and returns the opcode if the instruction is a valid operation. Returns `None` if the
/// next instruction is not an opcode (e.g., it's a data push) or if there are no more
/// instructions.
///
/// # Arguments
///
/// * `instructions` - Mutable reference to a Bitcoin script instruction iterator
///
/// # Returns
///
/// * `Some(Opcode)` - If the next instruction is a valid opcode
/// * `None` - If the next instruction is not an opcode or the iterator is exhausted
pub fn next_op(instructions: &mut Instructions<'_>) -> Option<Opcode> {
    let next_instruction = instructions.next();
    match next_instruction {
        Some(Ok(Instruction::Op(opcode))) => Some(opcode),
        _ => None,
    }
}

/// Parses and extracts the payload from a Bitcoin script envelope.
///
/// This function extracts the raw payload bytes from a script containing an envelope
/// structure. The envelope must follow the format: `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`.
///
/// The function will search for the envelope start marker (`OP_FALSE OP_IF`) and extract
/// all data push instructions until it encounters the closing `OP_ENDIF` opcode.
///
/// # Arguments
///
/// * `script` - A reference to the script buffer to parse
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The extracted payload bytes on success
/// * `Err(EnvelopeParseError)` - If the envelope structure is invalid or payload cannot be extracted
///
/// # Errors
///
/// * [`EnvelopeParseError::InvalidEnvelope`] - If the script doesn't contain a valid `OP_FALSE OP_IF` sequence
/// * [`EnvelopeParseError::InvalidPayload`] - If the payload data is malformed or contains invalid instructions
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::parser::parse_envelope_payload;
/// use strata_l1_envelope_fmt::builder::build_envelope_script;
///
/// let payload = vec![1, 2, 3, 4, 5];
/// let script = build_envelope_script(&payload).unwrap();
/// let extracted = parse_envelope_payload(&script).unwrap();
/// assert_eq!(payload, extracted);
/// ```
pub fn parse_envelope_payload(script: &ScriptBuf) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut instructions = script.instructions();

    // Locate and validate the envelope start sequence (OP_FALSE OP_IF)
    enter_envelope(&mut instructions)?;

    // Extract all payload data until OP_ENDIF
    let payload = extract_until_op_endif(&mut instructions)?;
    Ok(payload)
}

/// Locates and validates the envelope start sequence in a script instruction stream.
///
/// This function searches for the envelope start marker, which consists of `OP_FALSE`
/// followed by `OP_IF`. In Bitcoin scripts, `OP_FALSE` is represented as an empty
/// push bytes instruction.
///
/// The function will iterate through all instructions until it finds an empty push
/// (representing `OP_FALSE`), then verifies that the next instruction is `OP_IF`.
///
/// # Arguments
///
/// * `instructions` - Mutable reference to the script instruction iterator
///
/// # Returns
///
/// * `Ok(())` - If a valid envelope start sequence is found
/// * `Err(EnvelopeParseError::InvalidEnvelope)` - If no valid sequence is found
///
/// # Errors
///
/// Returns [`EnvelopeParseError::InvalidEnvelope`] if:
/// - The iterator is exhausted before finding `OP_FALSE`
/// - The instruction following `OP_FALSE` is not `OP_IF`
pub fn enter_envelope(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    // Search for OP_FALSE (represented as an empty PushBytes instruction)
    loop {
        let next_instruction = instructions.next();
        match next_instruction {
            None => {
                // Reached end of script without finding OP_FALSE
                return Err(EnvelopeParseError::InvalidEnvelope);
            }
            // OP_FALSE is encoded as an empty PushBytes instruction
            Some(Ok(Instruction::PushBytes(bytes))) => {
                if bytes.as_bytes().is_empty() {
                    break;
                }
                // Non-empty push bytes, continue searching
            }
            _ => {
                // Other instructions, continue searching
            }
        }
    }

    // Verify that OP_FALSE is followed by OP_IF
    let following_opcode = next_op(instructions);
    if following_opcode != Some(OP_IF) {
        return Err(EnvelopeParseError::InvalidEnvelope);
    }
    Ok(())
}

/// Extracts payload data from script instructions until `OP_ENDIF` is encountered.
///
/// This function iterates through the remaining script instructions, collecting all
/// data from push byte instructions and concatenating them into a single payload.
/// The extraction stops when an `OP_ENDIF` opcode is found, which marks the end
/// of the envelope.
///
/// # Arguments
///
/// * `instructions` - Mutable reference to the script instruction iterator, positioned
///   after the envelope start sequence
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The concatenated payload data from all push instructions
/// * `Err(EnvelopeParseError::InvalidPayload)` - If invalid instructions are encountered
///
/// # Errors
///
/// Returns [`EnvelopeParseError::InvalidPayload`] if:
/// - A non-data instruction (other than `OP_ENDIF`) is encountered
/// - An instruction cannot be properly decoded
/// - The instruction stream contains unexpected opcodes within the envelope
pub fn extract_until_op_endif(
    instructions: &mut Instructions<'_>,
) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut payload_data = Vec::new();

    for instruction_result in instructions {
        match instruction_result {
            // Found the envelope closing marker, stop extraction
            Ok(Instruction::Op(OP_ENDIF)) => {
                break;
            }
            // Accumulate data from push instructions
            Ok(Instruction::PushBytes(bytes)) => {
                payload_data.extend_from_slice(bytes.as_bytes());
            }
            // Any other instruction type is invalid within the envelope payload
            _ => {
                return Err(EnvelopeParseError::InvalidPayload);
            }
        }
    }

    Ok(payload_data)
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
