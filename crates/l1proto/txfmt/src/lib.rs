//! This crate contains all the types and logic related to encoding and parsing SPS-50 headers.

#[cfg(feature = "arbitrary")]
mod arbitrary;
#[cfg(feature = "borsh")]
mod borsh;
mod error;
mod magic;
#[cfg(feature = "serde")]
mod serde;
mod tag;
mod types;

pub use error::{TxFmtError, TxFmtResult};
pub use magic::{MAGIC_BYTES_LEN, MagicBytes};
pub use tag::{ParseConfig, TagData, TagDataRef, extract_tx_magic_and_tag};
pub use types::{SubprotocolId, TxType};
