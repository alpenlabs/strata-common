use thiserror::Error;

/// Errors that can occur while parsing Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeParseError {
    /// The script does not contain a valid `OP_FALSE OP_IF ... OP_ENDIF` envelope structure.
    #[error("invalid or missing envelope structure (no OP_FALSE OP_IF...OP_ENDIF block found)")]
    InvalidEnvelope,

    /// The envelope does not contain a valid type tag.
    #[error("invalid or missing type tag in envelope")]
    InvalidTypeTag,

    /// The envelope structure is malformed or does not follow the expected format.
    #[error("invalid envelope format")]
    InvalidFormat,

    /// The payload data is missing, corrupted, or does not match the expected size.
    #[error("invalid or corrupted payload data")]
    InvalidPayload,
}

/// Errors that can occur while building Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeBuildError {
    /// The payload chunk size exceeds Bitcoin's maximum push size limit (520 bytes).
    ///
    /// This error should not occur in normal operation as chunks are automatically
    /// split to respect this limit.
    #[error("payload chunk size {size} exceeds maximum push size of 520 bytes")]
    ChunkSizeExceedsLimit {
        /// The size of the chunk that exceeded the limit.
        size: usize,
    },

    /// Failed to convert payload chunk into `PushBytesBuf`.
    #[error("failed to create push bytes buffer: {0}")]
    PushBytesConversion(String),
}
