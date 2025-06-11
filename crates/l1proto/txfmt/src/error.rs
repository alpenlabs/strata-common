use bitcoin::script::PushBytesError;
use thiserror::Error;

use crate::types::MagicBytes;

/// Errors for decoding tx format types.
#[derive(Debug, Error)]
pub enum TxFmtError {
    #[error("tx missing output 0")]
    MissingOutput0,

    #[error("tag output not OP_RETURN")]
    NotOpret,

    #[error("tag output malformed OP_RETURN")]
    MalformedOpret,

    #[error("tx had incorrect magic (found {0:?})")]
    MismatchMagic(MagicBytes),

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
