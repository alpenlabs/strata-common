use bitcoin::{
    ScriptBuf,
    blockdata::script,
    opcodes::{
        OP_FALSE,
        all::{OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF},
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
/// The payload is automatically split into chunks of up to 520 bytes to comply
/// with Bitcoin's consensus rules.
///
/// # Arguments
///
/// * `payload` - The raw bytes to encapsulate in the envelope
///
/// # Errors
///
/// Returns [`EnvelopeBuildError::PushBytesConversion`] if a payload chunk cannot
/// be converted to a `PushBytesBuf`.
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::builder::build_envelope_script;
///
/// let payload = vec![1, 2, 3, 4, 5];
/// let script = build_envelope_script(&payload).unwrap();
/// ```
pub fn build_envelope_script(payload: &[u8]) -> Result<ScriptBuf, EnvelopeBuildError> {
    let mut builder = script::Builder::new()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    // Split payload into chunks of MAX_PUSH_SIZE and push each chunk
    for chunk in payload.chunks(MAX_PUSH_SIZE) {
        let push_bytes = PushBytesBuf::try_from(chunk.to_vec()).map_err(|e| {
            EnvelopeBuildError::PushBytesConversion(format!(
                "failed to convert {} byte chunk: {e}",
                chunk.len()
            ))
        })?;
        builder = builder.push_slice(push_bytes);
    }

    builder = builder.push_opcode(OP_ENDIF);
    Ok(builder.into_script())
}

/// Builds multiple envelopes in a single script.
///
/// Creates a script containing multiple sequential envelopes, each with the structure
/// `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`.
///
/// # Arguments
///
/// * `payloads` - Slice of payloads to encapsulate as separate envelopes
///
/// # Errors
///
/// Returns [`EnvelopeBuildError::PushBytesConversion`] if any payload chunk cannot
/// be converted to a `PushBytesBuf`.
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::builder::build_multi_envelope_script;
///
/// let payloads = vec![vec![1, 2, 3], vec![4, 5, 6]];
/// let script = build_multi_envelope_script(&payloads).unwrap();
/// ```
pub fn build_multi_envelope_script(payloads: &[Vec<u8>]) -> Result<ScriptBuf, EnvelopeBuildError> {
    let mut builder = script::Builder::new();

    for payload in payloads {
        builder = builder.push_opcode(OP_FALSE).push_opcode(OP_IF);

        for chunk in payload.chunks(MAX_PUSH_SIZE) {
            let push_bytes = PushBytesBuf::try_from(chunk.to_vec()).map_err(|e| {
                EnvelopeBuildError::PushBytesConversion(format!(
                    "failed to convert {} byte chunk: {e}",
                    chunk.len()
                ))
            })?;
            builder = builder.push_slice(push_bytes);
        }

        builder = builder.push_opcode(OP_ENDIF);
    }

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
/// # Arguments
///
/// * `pubkey` - The public key that controls the spend
/// * `payloads` - Slice of payloads to encapsulate as envelopes
///
/// # Errors
///
/// Returns [`EnvelopeBuildError::PushBytesConversion`] if any payload chunk cannot
/// be converted to a `PushBytesBuf`.
///
/// # Examples
///
/// ```
/// use strata_l1_envelope_fmt::builder::build_envelope_container;
///
/// let pubkey = vec![0x02; 33]; // Compressed pubkey
/// let payloads = vec![vec![1, 2, 3]];
/// let script = build_envelope_container(&pubkey, &payloads).unwrap();
/// ```
pub fn build_envelope_container(
    pubkey: &[u8],
    payloads: &[Vec<u8>],
) -> Result<ScriptBuf, EnvelopeBuildError> {
    let pubkey_bytes = PushBytesBuf::try_from(pubkey.to_vec()).map_err(|e| {
        EnvelopeBuildError::PushBytesConversion(format!("failed to convert pubkey: {e}"))
    })?;

    let mut builder = script::Builder::new()
        .push_slice(pubkey_bytes)
        .push_opcode(OP_CHECKSIGVERIFY);

    // Add all envelopes
    for payload in payloads {
        builder = builder.push_opcode(OP_FALSE).push_opcode(OP_IF);

        for chunk in payload.chunks(MAX_PUSH_SIZE) {
            let push_bytes = PushBytesBuf::try_from(chunk.to_vec()).map_err(|e| {
                EnvelopeBuildError::PushBytesConversion(format!(
                    "failed to convert {} byte chunk: {e}",
                    chunk.len()
                ))
            })?;
            builder = builder.push_slice(push_bytes);
        }

        builder = builder.push_opcode(OP_ENDIF);
    }

    Ok(builder.into_script())
}
