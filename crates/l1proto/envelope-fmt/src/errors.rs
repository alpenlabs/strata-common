use thiserror::Error;

/// Errors that can occur while parsing Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeParseError {
    /// The script does not contain a valid envelope structure.
    #[error("invalid or missing envelope structure")]
    InvalidEnvelope,

    /// The payload data is malformed.
    #[error("invalid payload data")]
    InvalidPayload,
}

/// Errors that can occur while building Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeBuildError {
    /// Failed to convert data into `PushBytesBuf`.
    #[error("failed to create push bytes buffer: {0}")]
    PushBytesConversion(String),
}
