//! Errors during parsing/handling/conversion of Bitcoin types.

use bitcoin::{AddressType, address, secp256k1};
use strata_identifiers::Buf32;
use thiserror::Error;

/// Parsing errors that can occur with L1 primitives,
/// such as addresses, pubkeys, and scripts.
#[derive(Debug, Clone, Error)]
pub enum ParseError {
    /// The provided pubkey is invalid.
    #[error("supplied pubkey is invalid")]
    InvalidPubkey(#[from] secp256k1::Error),

    /// The provided address is invalid.
    #[error("supplied address is invalid")]
    InvalidAddress(#[from] address::ParseError),

    /// The provided script is invalid.
    #[error("supplied script is invalid")]
    InvalidScript(#[from] address::FromScriptError),

    /// The provided script exceeds the maximum encodable size.
    #[error("script of {size} bytes exceeds the maximum of {max} bytes")]
    ScriptTooLarge {
        /// Size of the offending script, in bytes.
        size: usize,
        /// Maximum allowed script size, in bytes (`MAX_SCRIPT_SIZE`).
        max: usize,
    },

    /// The provided amount exceeds the maximum bitcoin money supply
    /// (`Amount::MAX_MONEY`).
    #[error("amount of {sats} sats exceeds the maximum of {max} sats")]
    AmountTooLarge {
        /// The offending amount, in satoshis.
        sats: u64,
        /// Maximum allowed amount, in satoshis (`Amount::MAX_MONEY`).
        max: u64,
    },

    /// The provided 32-byte buffer is not a valid point on the curve.
    #[error("not a valid point on the curve: {0}")]
    InvalidPoint(Buf32),

    /// Converting from an unsupported [`Address`](bitcoin::Address) type for a [`Buf32`].
    #[error("only taproot addresses are supported but found {0:?}")]
    UnsupportedAddress(Option<AddressType>),

    /// Could not get a network address from descriptor
    /// Using String error as [`bitcoin_bosd::DescriptorError`] does not impl Clone
    #[error("descriptor: {0}")]
    Descriptor(String),
}
