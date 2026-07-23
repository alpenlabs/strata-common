use thiserror::Error;

/// Errors that can occur while parsing Bitcoin script envelopes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnvelopeParseError {
    /// No envelopes found in the script.
    #[error("no envelopes found in script")]
    NoEnvelopesFound,

    /// Missing or invalid pubkey before `OP_CHECKSIG`.
    #[error("missing or invalid pubkey before OP_CHECKSIG")]
    MissingPubkey,

    /// Missing `OP_CHECKSIG` after the pubkey.
    #[error("missing OP_CHECKSIG after pubkey")]
    MissingChecksig,

    /// Missing OP_FALSE at the start of an envelope.
    #[error("missing OP_FALSE at envelope start")]
    MissingOpFalse,

    /// OP_FALSE not followed by OP_IF in envelope structure.
    #[error("OP_FALSE must be followed by OP_IF")]
    MissingOpIf,

    /// Non-push opcode found in envelope payload section.
    /// Only data push instructions are allowed between OP_IF and OP_ENDIF.
    #[error("unexpected opcode in payload section; only data pushes allowed")]
    UnexpectedOpcodeInPayload,

    /// Missing OP_ENDIF at the end of an envelope.
    #[error("missing OP_ENDIF at envelope end")]
    MissingOpEndif,

    /// Pubkey push in a signed envelope leaf has invalid length.
    ///
    /// Only raised by the strict leaf parser, which requires exactly
    /// [`SIGNED_LEAF_PUBKEY_LEN`](crate::SIGNED_LEAF_PUBKEY_LEN) bytes.
    /// Under BIP342 a tapscript pubkey that is neither empty nor x-only sized
    /// is an unknown public key type, for which `OP_CHECKSIG` succeeds without
    /// verifying any signature. Accepting such a leaf would void the
    /// authentication the envelope shape is meant to provide, so the strict
    /// parser rejects it rather than reporting a pubkey the caller might
    /// compare against.
    #[error("signed envelope leaf pubkey must be exactly {expected} bytes, found {found}")]
    InvalidPubkeyLength {
        /// The required pubkey length.
        expected: usize,

        /// Length of the offending pubkey push.
        found: usize,
    },

    /// Instructions remain after the envelope's OP_ENDIF.
    ///
    /// Only raised by the strict leaf parser, which requires the envelope to be
    /// the entire script. This rejects trailing opcodes that could discard or
    /// override the `OP_CHECKSIG` result, and additional envelopes beyond the
    /// first.
    #[error("unexpected instructions after envelope OP_ENDIF")]
    UnexpectedTrailingInstructions,

    /// Total envelope payload size exceeds the maximum allowed.
    #[error("total envelope payload size ({total_size} bytes) exceeds maximum ({max} bytes)")]
    PayloadTooLarge {
        /// Total payload size decoded before the limit was exceeded.
        total_size: usize,

        /// The maximum allowed size.
        max: usize,
    },

    /// Script could not be decoded into instructions.
    #[error("malformed script")]
    MalformedScript,
}

/// Errors that can occur while building Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeBuildError {
    /// Failed to convert a payload chunk into `PushBytesBuf`.
    #[error("failed to convert {chunk_size} byte payload chunk to push bytes buffer")]
    PayloadChunkConversion {
        /// Size of the chunk that failed to convert.
        chunk_size: usize,
    },

    /// Failed to convert a pubkey into `PushBytesBuf`.
    #[error("failed to convert pubkey to push bytes buffer")]
    PubkeyConversion,

    /// Total envelope payload size is below the recommended minimum.
    /// It would be more efficient to pass small data in the SPS-50 aux field.
    #[error(
        "total envelope payload size ({total_size} bytes) is below recommended minimum ({min} bytes)"
    )]
    PayloadTooSmall {
        /// The actual total size of all payloads.
        total_size: usize,

        /// The minimum recommended size.
        min: usize,
    },

    /// Total envelope payload size exceeds the maximum allowed.
    /// Must be under 395 KB to stay below Bitcoin's 400 KB transaction standardness limit.
    #[error("total envelope payload size ({total_size} bytes) exceeds maximum ({max} bytes)")]
    PayloadTooLarge {
        /// The actual total size of all payloads.
        total_size: usize,

        /// The maximum allowed size.
        max: usize,
    },
}
