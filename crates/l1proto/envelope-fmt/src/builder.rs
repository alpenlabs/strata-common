use bitcoin::{
    ScriptBuf,
    blockdata::script,
    opcodes::{
        OP_FALSE,
        all::{OP_ENDIF, OP_IF},
    },
    script::PushBytesBuf,
};

use crate::errors::EnvelopeBuildError;

/// Maximum push size allowed in Bitcoin scripts (in bytes).
///
/// Bitcoin's consensus rules limit individual push operations to 520 bytes.
/// Larger payloads must be split into multiple push operations.
const MAX_PUSH_SIZE: usize = 520;

/// Builds a Bitcoin script containing an envelope with the given payload.
///
/// Creates a script with the structure: `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`.
/// The payload is automatically split into chunks of up to 520 bytes (Bitcoin's
/// maximum push size) to comply with consensus rules.
///
/// # Arguments
///
/// * `payload` - The raw bytes to encapsulate in the envelope
///
/// # Returns
///
/// A [`ScriptBuf`] containing the envelope structure on success, or an
/// [`EnvelopeBuildError`] if the payload cannot be properly encoded.
///
/// # Errors
///
/// Returns [`EnvelopeBuildError::PushBytesConversion`] if a payload chunk cannot
/// be converted to a `PushBytesBuf`. This should not occur in normal operation
/// since chunks are kept within the valid size limit.
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::builder::build_envelope_script;
///
/// // Small payload
/// let payload = vec![1, 2, 3, 4, 5];
/// let script = build_envelope_script(&payload).unwrap();
///
/// // Large payload (automatically chunked)
/// let large_payload = vec![0u8; 2000];
/// let script = build_envelope_script(&large_payload).unwrap();
/// ```
pub fn build_envelope_script(payload: &[u8]) -> Result<ScriptBuf, EnvelopeBuildError> {
    let mut builder = script::Builder::new()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    // Split payload into chunks of MAX_PUSH_SIZE and push each chunk
    for chunk in payload.chunks(MAX_PUSH_SIZE) {
        let push_bytes = PushBytesBuf::try_from(chunk.to_vec()).map_err(|e| {
            EnvelopeBuildError::PushBytesConversion(format!(
                "failed to convert {} byte chunk: {}",
                chunk.len(),
                e
            ))
        })?;
        builder = builder.push_slice(push_bytes);
    }

    builder = builder.push_opcode(OP_ENDIF);
    Ok(builder.into_script())
}
