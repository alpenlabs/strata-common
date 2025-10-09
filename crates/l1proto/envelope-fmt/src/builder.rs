use bitcoin::{
    ScriptBuf,
    blockdata::script,
    constants::MAX_SCRIPT_ELEMENT_SIZE,
    opcodes::{
        OP_FALSE,
        all::{OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF},
    },
    script::PushBytesBuf,
};

use crate::errors::EnvelopeBuildError;

/// Builds a Bitcoin script containing an envelope with the given payload.
///
/// Creates a script with the structure: `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`.
/// The payload is automatically split into chunks of up to [`MAX_SCRIPT_ELEMENT_SIZE`] bytes to comply
/// with Bitcoin's consensus rules.
///
/// # Errors
///
/// Returns [`EnvelopeBuildError`] if a payload chunk cannot be converted to a `PushBytesBuf`.
pub fn build_envelope_script(payload: &[u8]) -> Result<ScriptBuf, EnvelopeBuildError> {
    let builder = script::Builder::new();
    let builder = push_envelope(builder, payload)?;
    Ok(builder.into_script())
}

/// Builds an envelope container with a pubkey and CHECKSIGVERIFY.
///
/// Creates a script with the structure:
/// ```text
/// <pubkey>
/// CHECKSIGVERIFY
/// <envelope_0>
/// ...
/// <envelope_n>
/// ```
///
/// The container makes the script spendable and the signature transitively signs
/// the contained envelopes.
///
/// # Errors
///
/// Returns [`EnvelopeBuildError`] if the pubkey or any payload chunk cannot be
/// converted to a `PushBytesBuf`.
pub fn build_envelope_container(
    pubkey: &[u8],
    payloads: &[Vec<u8>],
) -> Result<ScriptBuf, EnvelopeBuildError> {
    let pubkey_bytes = PushBytesBuf::try_from(pubkey.to_vec())
        .map_err(|_| EnvelopeBuildError::PubkeyConversion)?;

    let mut builder = script::Builder::new()
        .push_slice(pubkey_bytes)
        .push_opcode(OP_CHECKSIGVERIFY);

    // Add all envelopes
    for payload in payloads {
        builder = push_envelope(builder, payload)?;
    }

    Ok(builder.into_script())
}

/// Helper function to add envelope opcodes and payload chunks to a builder.
///
/// Takes a mutable builder and a payload, and extends the builder with:
/// `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`
fn push_envelope(
    mut builder: script::Builder,
    payload: &[u8],
) -> Result<script::Builder, EnvelopeBuildError> {
    builder = builder.push_opcode(OP_FALSE).push_opcode(OP_IF);

    for chunk in payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
        let push_bytes = PushBytesBuf::try_from(chunk.to_vec()).map_err(|_| {
            EnvelopeBuildError::PayloadChunkConversion {
                chunk_size: chunk.len(),
            }
        })?;
        builder = builder.push_slice(push_bytes);
    }

    builder = builder.push_opcode(OP_ENDIF);
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        opcodes::all::{OP_ENDIF, OP_IF},
        script::Instruction,
    };

    /// Test that validates the envelope structure uses correct opcodes.
    ///
    /// Verifies that:
    /// - Envelope starts with OP_FALSE (not just any empty push)
    /// - OP_FALSE is followed by OP_IF
    /// - Payload chunks are data pushes
    /// - Envelope ends with OP_ENDIF
    #[test]
    fn test_envelope_structure_opcodes() {
        let payload = vec![1, 2, 3, 4, 5];
        let script = build_envelope_script(&payload).unwrap();

        let mut instructions = script.instructions();

        // First instruction should be OP_FALSE (encoded as empty push)
        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => {
                assert!(bytes.as_bytes().is_empty(), "OP_FALSE should be empty push");
            }
            other => panic!("Expected OP_FALSE (empty push), got {other:?}"),
        }

        // Second instruction should be OP_IF
        match instructions.next() {
            Some(Ok(Instruction::Op(op))) => {
                assert_eq!(op, OP_IF, "Second opcode should be OP_IF");
            }
            other => panic!("Expected OP_IF, got {other:?}"),
        }

        // Middle instructions should be data pushes (the payload)
        let mut collected_data = Vec::new();
        loop {
            match instructions.next() {
                Some(Ok(Instruction::PushBytes(bytes))) => {
                    collected_data.extend_from_slice(bytes.as_bytes());
                }
                Some(Ok(Instruction::Op(op))) if op == OP_ENDIF => break,
                other => panic!("Expected data push or OP_ENDIF, got {other:?}"),
            }
        }

        assert_eq!(
            collected_data, payload,
            "Collected payload should match input"
        );
        assert!(
            instructions.next().is_none(),
            "Should be no instructions after OP_ENDIF"
        );
    }

    /// Test that validates payload chunking behavior for various sizes.
    ///
    /// This test ensures that payloads are correctly split into chunks of 520 bytes
    /// or less, and that the resulting script contains the expected number and size
    /// of data pushes.
    #[test]
    fn test_payload_chunking() {
        let test_cases = vec![
            (0, vec![]),                      // Empty payload: no data chunks
            (1, vec![1]),                     // 1 byte: single 1-byte chunk
            (520, vec![520]),                 // Exactly 520: single 520-byte chunk
            (521, vec![520, 1]),              // 521: 520 bytes + 1 byte
            (1040, vec![520, 520]),           // Exactly 2 chunks: 520 + 520
            (1041, vec![520, 520, 1]),        // 2 chunks + 1: 520 + 520 + 1
            (1560, vec![520, 520, 520]),      // Exactly 3 chunks
            (2000, vec![520, 520, 520, 440]), // Large payload with partial last chunk
        ];

        for (payload_size, expected_chunk_sizes) in test_cases {
            // Create a payload with sequential bytes for easy verification
            let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();

            let script = build_envelope_script(&payload)
                .unwrap_or_else(|_| panic!("Failed to build envelope for {payload_size} bytes"));

            // Extract only the data push sizes (skip OP_FALSE, OP_IF, OP_ENDIF)
            let mut instructions = script.instructions();

            // Skip OP_FALSE
            assert!(matches!(
                instructions.next(),
                Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes().is_empty()
            ));

            // Skip OP_IF
            assert!(matches!(
                instructions.next(),
                Some(Ok(Instruction::Op(op))) if op == OP_IF
            ));

            // Collect payload chunk sizes
            let mut chunk_sizes = Vec::new();
            for inst in instructions {
                match inst {
                    Ok(Instruction::PushBytes(bytes)) => {
                        chunk_sizes.push(bytes.len());
                    }
                    Ok(Instruction::Op(op)) if op == OP_ENDIF => break,
                    other => panic!("Unexpected instruction: {other:?}"),
                }
            }

            assert_eq!(
                chunk_sizes, expected_chunk_sizes,
                "Payload size {payload_size}: expected chunks {expected_chunk_sizes:?}, got {chunk_sizes:?}"
            );

            // Verify the total data size equals the original payload size
            let total_data_size: usize = chunk_sizes.iter().sum();
            assert_eq!(
                total_data_size, payload_size,
                "Total data size mismatch for payload size {payload_size}"
            );
        }
    }
}
