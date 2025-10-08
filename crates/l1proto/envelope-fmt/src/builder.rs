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
    use bitcoin::blockdata::script::Instruction::PushBytes;

    /// Test that validates payload chunking behavior for various sizes.
    ///
    /// This test ensures that payloads are correctly split into chunks of 520 bytes
    /// or less, and that the resulting script contains the expected number and size
    /// of data pushes.
    ///
    /// Note: Each expected vector starts with 0 because OP_FALSE (at the beginning
    /// of each envelope) is interpreted as pushing an empty byte array when iterating
    /// through script instructions.
    #[test]
    fn test_payload_chunking() {
        let test_cases = vec![
            (0, vec![0]),                        // Empty payload: only OP_FALSE
            (1, vec![0, 1]),                     // 1 byte: OP_FALSE + 1 byte chunk
            (520, vec![0, 520]),                 // Exactly 520: OP_FALSE + 520 byte chunk
            (521, vec![0, 520, 1]),              // 521: OP_FALSE + 520 bytes + 1 byte
            (1040, vec![0, 520, 520]),           // Exactly 2 chunks: OP_FALSE + 520 + 520
            (1041, vec![0, 520, 520, 1]),        // 2 chunks + 1: OP_FALSE + 520 + 520 + 1
            (1560, vec![0, 520, 520, 520]),      // Exactly 3 chunks
            (2000, vec![0, 520, 520, 520, 440]), // Large payload with partial last chunk
        ];

        for (payload_size, expected_pushes) in test_cases {
            // Create a payload with sequential bytes for easy verification
            let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();

            let script = build_envelope_script(&payload)
                .unwrap_or_else(|_| panic!("Failed to build envelope for {} bytes", payload_size));

            // Extract data push sizes from the script
            let instructions: Vec<_> = script.instructions().collect();
            let data_pushes: Vec<_> = instructions
                .iter()
                .filter_map(|inst| {
                    if let Ok(PushBytes(data)) = inst {
                        Some(data.len())
                    } else {
                        None
                    }
                })
                .collect();

            assert_eq!(
                data_pushes, expected_pushes,
                "Payload size {}: expected pushes {:?}, got {:?}",
                payload_size, expected_pushes, data_pushes
            );

            // Verify the total data pushed (excluding OP_FALSE's empty push) equals the original payload size
            let total_data_size: usize = data_pushes.iter().skip(1).sum();
            assert_eq!(
                total_data_size, payload_size,
                "Total data size mismatch for payload size {}",
                payload_size
            );
        }
    }
}
