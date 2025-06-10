use bitcoin::script::PushBytesError;
use thiserror::Error;

/// Errors for encoding payload as SPS-50 script buffers.
#[derive(Debug, Error)]
pub enum SPS50EncodeError {
    /// Error while converting data to `PushByteBuf`, typically dueto invalid length.
    #[error("{0}")]
    PushBytesError(#[from] PushBytesError),

    /// The encoded payload exceeds the mxximum allowed size, typically 80 bytes
    #[error("Exceeded {0} bytes limit")]
    BytesLimitExceed(u16),
}

/// Result corresponding to SPS-50 encoding.
pub type EncodeResult<T> = Result<T, SPS50EncodeError>;
