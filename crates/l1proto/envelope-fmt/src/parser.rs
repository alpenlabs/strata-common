use bitcoin::{
    Opcode, ScriptBuf,
    opcodes::all::{OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF},
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
/// # Arguments
///
/// * `script` - A reference to the script buffer to parse
///
/// # Errors
///
/// * [`EnvelopeParseError::InvalidEnvelope`] - If the script doesn't contain a valid `OP_FALSE OP_IF` sequence
/// * [`EnvelopeParseError::InvalidPayload`] - If the payload data is malformed
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
    enter_envelope(&mut instructions)?;
    extract_until_op_endif(&mut instructions)
}

/// Parses and extracts all payloads from a script with multiple envelopes.
///
/// Extracts payloads from a script containing multiple sequential envelopes.
///
/// # Arguments
///
/// * `script` - A reference to the script buffer to parse
///
/// # Errors
///
/// * [`EnvelopeParseError::InvalidEnvelope`] - If any envelope structure is invalid
/// * [`EnvelopeParseError::InvalidPayload`] - If any payload data is malformed
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::parser::parse_multi_envelope_payloads;
/// use strata_l1_envelope_fmt::builder::build_multi_envelope_script;
///
/// let payloads = vec![vec![1, 2, 3], vec![4, 5, 6]];
/// let script = build_multi_envelope_script(&payloads).unwrap();
/// let extracted = parse_multi_envelope_payloads(&script).unwrap();
/// assert_eq!(payloads, extracted);
/// ```
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
        return Err(EnvelopeParseError::InvalidEnvelope);
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
/// # Arguments
///
/// * `script` - A reference to the script buffer to parse
///
/// # Returns
///
/// A tuple containing the pubkey and a vector of all envelope payloads.
///
/// # Errors
///
/// * [`EnvelopeParseError::InvalidEnvelope`] - If the container structure is invalid
/// * [`EnvelopeParseError::InvalidPayload`] - If any payload data is malformed
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::parser::parse_envelope_container;
/// use strata_l1_envelope_fmt::builder::build_envelope_container;
///
/// let pubkey = vec![0x02; 33];
/// let payloads = vec![vec![1, 2, 3]];
/// let script = build_envelope_container(&pubkey, &payloads).unwrap();
/// let (extracted_pubkey, extracted_payloads) = parse_envelope_container(&script).unwrap();
/// assert_eq!(pubkey, extracted_pubkey);
/// assert_eq!(payloads, extracted_payloads);
/// ```
pub fn parse_envelope_container(
    script: &ScriptBuf,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), EnvelopeParseError> {
    let mut instructions = script.instructions();

    // Extract pubkey
    let pubkey = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes().to_vec(),
        _ => return Err(EnvelopeParseError::InvalidEnvelope),
    };

    // Verify CHECKSIGVERIFY
    if next_op(&mut instructions) != Some(OP_CHECKSIGVERIFY) {
        return Err(EnvelopeParseError::InvalidEnvelope);
    }

    // Extract all envelopes
    let mut payloads = Vec::new();
    while enter_envelope(&mut instructions).is_ok() {
        let payload = extract_until_op_endif(&mut instructions)?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Err(EnvelopeParseError::InvalidEnvelope);
    }

    Ok((pubkey, payloads))
}

/// Locates and validates the envelope start sequence (`OP_FALSE OP_IF`).
fn enter_envelope(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    // Search for OP_FALSE (encoded as empty PushBytes)
    loop {
        match instructions.next() {
            None => return Err(EnvelopeParseError::InvalidEnvelope),
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes().is_empty() => break,
            _ => continue,
        }
    }

    // Verify OP_FALSE is followed by OP_IF
    if next_op(instructions) != Some(OP_IF) {
        return Err(EnvelopeParseError::InvalidEnvelope);
    }
    Ok(())
}

/// Extracts payload data from push instructions until `OP_ENDIF`.
fn extract_until_op_endif(
    instructions: &mut Instructions<'_>,
) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut payload_data = Vec::new();

    for instruction_result in instructions {
        match instruction_result {
            Ok(Instruction::Op(OP_ENDIF)) => break,
            Ok(Instruction::PushBytes(bytes)) => {
                payload_data.extend_from_slice(bytes.as_bytes());
            }
            _ => return Err(EnvelopeParseError::InvalidPayload),
        }
    }

    Ok(payload_data)
}

#[cfg(test)]
mod tests {
    use crate::builder::{
        build_envelope_container, build_envelope_script, build_multi_envelope_script,
    };

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
    fn test_parse_multi_envelope() {
        let payloads = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7; 1000]];
        let script = build_multi_envelope_script(&payloads).unwrap();
        let result = parse_multi_envelope_payloads(&script).unwrap();

        assert_eq!(result, payloads);
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
}
