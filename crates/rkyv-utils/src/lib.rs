//! Various utils for working with [`rkyv`].
//!
//! # Alignment mode
//!
//! This crate mirrors upstream rkyv's own feature rules: the archived format is
//! selected by a single additive `unaligned` feature.
//!
//! - **default** (no feature) selects rkyv's native format.  In-guest reads are cheaper, but the
//!   backing buffer must be aligned or [`rkyv::access_unchecked`] (which backs [`Rk`]'s `AsRef<T>`)
//!   is undefined behaviour.  In this mode the [`Rk`] constructors guard against misaligned
//!   buffers.
//! - **`unaligned`** enables `rkyv/unaligned`, making archived multibyte primitives alignment-1. An
//!   archived value can then live zero-copy inside any plain `Vec<u8>` / `Box<[u8]>` with no
//!   alignment requirement.
//!
//! Note that Cargo features are *additive and unified across the dependency
//! graph*: if any crate anywhere enables `rkyv/unaligned`, rkyv is built
//! unaligned for everyone, regardless of whether this crate's own `unaligned`
//! feature is on.  That can never make access *unsound*, because every runtime
//! alignment check keys off `align_of::<T>()`, which always reflects rkyv's
//! actual format, a graph-wide override only relaxes enforcement, it doesn't
//! introduce UB.

// `ssz_derive` is a dev-dependency used only by the `ssz` feature's tests.
// Dev-dependencies can't be feature-gated, so reference it here when that
// feature is off to keep test builds clear of the unused-crate lint.
#[cfg(all(test, not(feature = "ssz")))]
use ssz_derive as _;

pub(crate) mod raw_vec;
mod rk;
mod stable_buf;

pub use raw_vec::{RAW_VEC_ALIGN, RawRkVec};
pub use rk::{Rk, RkBox, RkRef, RkVec};
pub use stable_buf::StableBuf;

#[cfg(feature = "ssz")]
mod ssz_shims;

#[cfg(feature = "ssz")]
pub use ssz_shims::{RkSsz, SszBuf};

#[cfg(feature = "codec")]
mod codec_shims;

#[cfg(feature = "codec")]
pub use codec_shims::{CodecBuf, RkCodec};
