use thiserror::Error;

/// Errors from strata-codec.
#[derive(Debug, Error)]
pub enum CodecError {
    /// If we read a container length that was longer than allowed.
    #[error("overflow container")]
    OverflowContainer,

    /// If we tried to read past the end of the underlying buffer.
    #[error("would overrun end of input")]
    OverrunInput,

    /// If there was extra data in a buffer than we didn't consume reading a
    /// message.
    #[error("extra unnecessary input leftover")]
    ExtraInput,
}
