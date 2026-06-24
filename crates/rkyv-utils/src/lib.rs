//! Various utils for working with [`rkyv`].

#[cfg(feature = "ssz")]
extern crate ssz_derive as _;

mod rk;

pub use rk::{Rk, RkBox, RkRef, RkVec};

#[cfg(feature = "ssz")]
mod ssz_shims;

#[cfg(feature = "ssz")]
pub use ssz_shims::{RkSsz, SszBuf};

#[cfg(feature = "codec")]
mod codec_shims;

#[cfg(feature = "codec")]
pub use codec_shims::{CodecBuf, RkCodec};
