//! This crate contains all the types and logic related to encoding and parsing SPS-50 headers.

mod error;
mod tag;
mod types;

pub use error::{TxFmtError, TxFmtResult};
pub use tag::{ParseConfig, TagData, TagDataRef};
pub use types::{MagicBytes, SubprotocolId, TxType};
