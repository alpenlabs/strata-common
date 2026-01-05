use bitcoin::script::PushBytesError;
use thiserror::Error;

use crate::MagicBytes;

/// Errors for decoding tx format types.
#[derive(Debug, Error)]
pub enum TxFmtError {
    /// Tx is missing output 0.
    #[error("tx missing output 0")]
    MissingOutput0,

    /// Tx output 0 is not an OP_RETURN output.
    #[error("tag output not OP_RETURN")]
    NotOpret,

    /// OP_RETURN output is malformed.
    #[error("tag output malformed OP_RETURN")]
    MalformedOpret,

    /// Tag had unexpected magic value.
    #[error("tx had incorrect magic (found {0:?})")]
    MismatchMagic(MagicBytes),

    /// Tag aux data too long.
    #[error("aux data was too long")]
    AuxTooLong,

    /// The encoded payload exceeds the mxximum allowed size, typically 80 bytes
    #[error("exceeded {0} bytes limit")]
    BytesLimitExceed(u16),

    /// Error while converting data to `PushByteBuf`, typically dueto invalid length.
    #[error("pushbytes: {0}")]
    PushBytes(#[from] PushBytesError),
}

/// Wrapper result type.
pub type TxFmtResult<T> = Result<T, TxFmtError>;
