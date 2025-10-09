use bitcoin::{
    ScriptBuf,
    blockdata::script,
    constants::MAX_SCRIPT_ELEMENT_SIZE,
    opcodes::{
        OP_FALSE,
        all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    },
    script::PushBytesBuf,
};

use crate::errors::EnvelopeBuildError;

/// Minimum recommended total envelope payload size in bytes.
/// Below this size, it's more efficient to use the SPS-50 aux field.
pub const MIN_ENVELOPE_PAYLOAD_SIZE: usize = 126;

/// Maximum allowed total envelope payload size in bytes.
/// Must be under 395 KB to stay comfortably below Bitcoin's 400 KB transaction standardness limit.
pub const MAX_ENVELOPE_PAYLOAD_SIZE: usize = 395_000;

/// Builder for constructing envelope container scripts with multiple payloads.
///
/// This builder helps create scripts containing envelope data that can be placed
/// in a transaction input's script_sig. The envelope container includes:
/// - A pubkey and CHECKSIGVERIFY for spendability
/// - One or more envelope payloads
///
/// # Structure
///
/// ```text
/// <pubkey>
/// CHECKSIGVERIFY
/// OP_FALSE OP_IF <payload_0> OP_ENDIF
/// OP_FALSE OP_IF <payload_1> OP_ENDIF
/// ...
/// ```
///
/// # Size constraints
///
/// - Minimum total payload size: 126 bytes (use SPS-50 aux field for smaller data)
/// - Maximum total payload size: 395,000 bytes (Bitcoin standardness limit)
///
/// # Example
///
/// ```
/// use strata_l1_envelope_fmt::builder::EnvelopeScriptBuilder;
///
/// let pubkey = vec![0x02; 33];
/// let payload1 = vec![1; 150];
/// let payload2 = vec![2; 150];
///
/// let script = EnvelopeScriptBuilder::with_pubkey(&pubkey)
///     .unwrap()
///     .add_envelope(&payload1).unwrap()
///     .add_envelope(&payload2).unwrap()
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct EnvelopeScriptBuilder {
    builder: script::Builder,
    total_payload_size: usize,
}

impl EnvelopeScriptBuilder {
    /// Creates a new envelope script builder with the given pubkey.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - Pubkey bytes (typically 33 bytes for compressed) for the envelope container
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeBuildError::PubkeyConversion`] if the pubkey cannot be converted to a `PushBytesBuf`.
    pub fn with_pubkey(pubkey: &[u8]) -> Result<Self, EnvelopeBuildError> {
        let pubkey_bytes = PushBytesBuf::try_from(pubkey.to_vec())
            .map_err(|_| EnvelopeBuildError::PubkeyConversion)?;

        let builder = script::Builder::new()
            .push_slice(pubkey_bytes)
            .push_opcode(OP_CHECKSIG);

        Ok(Self {
            builder,
            total_payload_size: 0,
        })
    }

    /// Adds an envelope payload to be included in the script.
    ///
    /// Multiple envelopes can be added and will be combined into a single script
    /// when `build()` is called.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeBuildError::PayloadTooLarge`] if adding this envelope would exceed the maximum total payload size.
    pub fn add_envelope(mut self, payload: &[u8]) -> Result<Self, EnvelopeBuildError> {
        self.total_payload_size += payload.len();

        if self.total_payload_size > MAX_ENVELOPE_PAYLOAD_SIZE {
            return Err(EnvelopeBuildError::PayloadTooLarge {
                total_size: self.total_payload_size,
                max: MAX_ENVELOPE_PAYLOAD_SIZE,
            });
        }

        self.builder = push_envelope(self.builder, payload)?;
        Ok(self)
    }

    /// Adds multiple envelope payloads at once.
    ///
    /// This is a convenience method for adding multiple envelopes in a single call.
    /// Accepts any iterator of byte slices.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeBuildError::PayloadTooLarge`] if adding these envelopes would exceed the maximum total payload size.
    pub fn add_envelopes<I>(mut self, payloads: I) -> Result<Self, EnvelopeBuildError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        for payload in payloads {
            self = self.add_envelope(payload.as_ref())?;
        }
        Ok(self)
    }

    /// Builds the envelope container script.
    ///
    /// Creates a script with the pubkey, CHECKSIGVERIFY, and all envelope payloads.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeBuildError::PayloadTooSmall`] if total payload size < 126 bytes.
    pub fn build(self) -> Result<ScriptBuf, EnvelopeBuildError> {
        // Validate envelope payload sizes
        if self.total_payload_size < MIN_ENVELOPE_PAYLOAD_SIZE {
            return Err(EnvelopeBuildError::PayloadTooSmall {
                total_size: self.total_payload_size,
                min: MIN_ENVELOPE_PAYLOAD_SIZE,
            });
        }

        Ok(self.builder.into_script())
    }
}

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

    #[test]
    fn test_envelope_script_builder_minimal() {
        let pubkey = vec![0x02; 33];
        let payload = vec![1; 200];

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelope(&payload)
            .unwrap()
            .build();

        assert!(result.is_ok());
        let script = result.unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_envelope_script_builder_multiple_envelopes() {
        let pubkey = [0x02; 33];

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelope(&[1; 50])
            .unwrap()
            .add_envelope(&[2; 50])
            .unwrap()
            .add_envelope(&[3; 50])
            .unwrap()
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_envelope_script_builder_payload_too_small() {
        let pubkey = vec![0x02; 33];

        let test_cases = vec![
            (0, "no envelopes"),
            (1, "1 byte"),
            (50, "50 bytes"),
            (100, "100 bytes"),
            (125, "125 bytes (just below minimum)"),
        ];

        for (payload_size, description) in test_cases {
            let payload = vec![1; payload_size];

            let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
                .unwrap()
                .add_envelope(&payload)
                .unwrap()
                .build();

            assert!(
                matches!(
                    result,
                    Err(EnvelopeBuildError::PayloadTooSmall {
                        total_size,
                        min: 126
                    }) if total_size == payload_size
                ),
                "Failed for case: {description} (size={payload_size})"
            );
        }
    }

    #[test]
    fn test_envelope_script_builder_payload_minimum_valid() {
        let pubkey = vec![0x02; 33];
        let valid_payload = vec![1; 126];

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelope(&valid_payload)
            .unwrap()
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_envelope_script_builder_payload_maximum_valid() {
        let pubkey = vec![0x02; 33];
        let max_payload = vec![1; 395_000];

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelope(&max_payload)
            .unwrap()
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_envelope_script_builder_payload_too_large() {
        let pubkey = vec![0x02; 33];

        let test_cases = vec![
            (395_001, "1 byte over maximum"),
            (400_000, "400 KB"),
            (500_000, "500 KB"),
        ];

        for (payload_size, description) in test_cases {
            let payload = vec![1; payload_size];

            let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
                .unwrap()
                .add_envelope(&payload);

            assert!(
                matches!(
                    result,
                    Err(EnvelopeBuildError::PayloadTooLarge {
                        total_size,
                        max: 395_000
                    }) if total_size == payload_size
                ),
                "Failed for case: {description} (size={payload_size})"
            );
        }
    }

    #[test]
    fn test_envelope_script_builder_multiple_payloads_size_validation() {
        let pubkey = vec![0x02; 33];

        // Test cases for PayloadTooSmall: (payload_sizes, description, expected_total)
        let too_small_cases = vec![
            (vec![30, 30, 30], "too small (90 total)", 90),
            (vec![40, 40, 40], "too small (120 total)", 120),
        ];

        for (payload_sizes, description, expected_total) in too_small_cases {
            let mut builder = EnvelopeScriptBuilder::with_pubkey(&pubkey).unwrap();

            for size in payload_sizes {
                builder = builder.add_envelope(&vec![1; size]).unwrap();
            }

            let result = builder.build();

            assert!(
                matches!(
                    result,
                    Err(EnvelopeBuildError::PayloadTooSmall {
                        total_size,
                        min: 126
                    }) if total_size == expected_total
                ),
                "Failed for case: {description}"
            );
        }

        // Test cases for valid sizes: (payload_sizes, description)
        let valid_cases = vec![
            (vec![50, 50, 26], "exactly minimum (126 total)"),
            (vec![60, 60, 60], "valid (180 total)"),
        ];

        for (payload_sizes, description) in valid_cases {
            let mut builder = EnvelopeScriptBuilder::with_pubkey(&pubkey).unwrap();

            for size in payload_sizes {
                builder = builder.add_envelope(&vec![1; size]).unwrap();
            }

            let result = builder.build();
            assert!(result.is_ok(), "Failed for case: {description}");
        }
    }

    #[test]
    fn test_envelope_script_builder_multiple_payloads_exceeds_maximum() {
        let pubkey = vec![0x02; 33];

        // Test case: adding multiple envelopes that together exceed the maximum
        let payload1 = vec![1; 200_000];
        let payload2 = vec![2; 195_001]; // Total will be 395,001

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelope(&payload1)
            .unwrap()
            .add_envelope(&payload2);

        // Second envelope pushes total to 395,001 which exceeds max of 395,000
        assert!(
            matches!(
                result,
                Err(EnvelopeBuildError::PayloadTooLarge {
                    total_size: 395_001,
                    max: 395_000
                })
            ),
            "Should fail when multiple envelopes exceed maximum total size"
        );
    }

    #[test]
    fn test_add_envelopes_batch() {
        let pubkey = vec![0x02; 33];
        let payloads: Vec<Vec<u8>> = vec![vec![1; 50], vec![2; 50], vec![3; 50]];

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelopes(payloads)
            .unwrap()
            .build();

        assert!(result.is_ok());
        let script = result.unwrap();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_add_envelopes_exceeds_maximum() {
        let pubkey = vec![0x02; 33];
        let payloads: Vec<Vec<u8>> = vec![vec![1; 200_000], vec![2; 195_001]];

        let result = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelopes(payloads);

        assert!(
            matches!(
                result,
                Err(EnvelopeBuildError::PayloadTooLarge {
                    total_size: 395_001,
                    max: 395_000
                })
            ),
            "Should fail when batch envelopes exceed maximum total size"
        );
    }
}
