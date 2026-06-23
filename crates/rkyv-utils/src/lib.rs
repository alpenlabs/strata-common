//! Various utils for working with [`rkyv`].

#[cfg(feature = "ssz")]
extern crate ssz_derive as _;

#[cfg(feature = "codec")]
extern crate strata_codec as _;

mod rk;

pub use rk::{Rk, RkBox, RkRef, RkVec};

#[cfg(feature = "ssz")]
mod ssz_shims;

#[cfg(feature = "ssz")]
pub use ssz_shims::{RkSsz, SszBuf, SszBufExt};
