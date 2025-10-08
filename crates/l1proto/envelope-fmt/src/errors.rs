use thiserror::Error;

/// Errors that can be generated while parsing envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeParseError {
    /// Does not have an `OP_IF..OP_ENDIF` block
    #[error("Invalid/Missing envelope(NO OP_IF..OP_ENDIF): ")]
    InvalidEnvelope,
    /// Does not have a valid type tag
    #[error("Invalid/Missing type tag")]
    InvalidTypeTag,
    /// Does not have a valid format
    #[error("Invalid Format")]
    InvalidFormat,
    /// Does not have a payload data of expected size
    #[error("Invalid Payload")]
    InvalidPayload,
}
