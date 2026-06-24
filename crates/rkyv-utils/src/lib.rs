//! Various utils for working with [`rkyv`].

// `ssz_derive` is a dev-dependency used only by the `ssz` feature's tests.
// Dev-dependencies can't be feature-gated, so reference it here when that
// feature is off to keep test builds clear of the unused-crate lint.
#[cfg(all(test, not(feature = "ssz")))]
use ssz_derive as _;

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
