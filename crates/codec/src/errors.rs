use thiserror::Error;

/// Errors from strata-codec.
#[derive(Debug, Error)]
pub enum CodecError {
    /// For use when we read a container length field that implies a container
    /// of a larger size than allowed in the context.
    #[error("overflow container")]
    OverflowContainer,

    /// For use when an invalid variant selector is encountered.
    #[error("invalid '{0}' variant selector")]
    InvalidVariant(&'static str),

    /// For use when an some integer is out of some allowed bounds, although
    /// container sizes should use [`CodecError::OverflowContainer`].
    #[error("integer out of bounds")]
    OobInteger,

    /// For use when a field imposes some nontrivial validity constraints that
    /// were violated.
    ///
    /// See also [`CodecError::NonUtf8String`].
    #[error("malformed {0} type field")]
    MalformedField(&'static str),

    /// For use when a container requires that its entries be sorted when
    /// encoded, but we encountered unsorted fields when decoding.
    #[error("unsorted container entries")]
    UnsortedContainer,

    /// For use when a we're trying to parse a string but it's invalid UTF-8.
    #[error("non-UTF-8 string")]
    NonUtf8String,

    /// If we tried to read past the end of the underlying buffer.
    #[error("would overrun end of input")]
    OverrunInput,

    /// If there was extra data in a buffer than we didn't consume reading a
    /// message.
    #[error("extra unnecessary input leftover")]
    ExtraInput,
}
