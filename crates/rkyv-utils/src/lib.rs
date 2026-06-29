//! Various utils for working with [`rkyv`].
//!
//! # Alignment mode
//!
//! This crate exposes two mutually-exclusive, no-default Cargo features that
//! select rkyv's archived format:
//!
//! - **`unaligned`** enables `rkyv/unaligned`, making archived multibyte primitives alignment-1. An
//!   archived value can then live zero-copy inside any plain `Vec<u8>` / `Box<[u8]>` with no
//!   alignment requirement.
//! - **`aligned`** selects rkyv's native format.  In-guest reads are cheaper, but the backing
//!   buffer must be aligned or [`rkyv::access_unchecked`] (which backs [`Rk`]'s `AsRef<T>`) is
//!   undefined behaviour.  In this mode the [`Rk`] constructors guard against misaligned buffers.
//!
//! Exactly one must be enabled; the guards below turn a wrong selection into a
//! compile error.
//!
//! Note that Cargo features are *additive and unified across the dependency
//! graph*: if any crate anywhere enables `rkyv/unaligned`, rkyv is built
//! unaligned for everyone, regardless of what `aligned`/`unaligned` this crate
//! selects.  The `compile_error!` guards only enforce a consistent choice
//! *within this crate's own* feature set.  This can never make access
//! *unsound*, because every runtime alignment check keys off `align_of::<T>()`,
//! which always reflects rkyv's actual format — a graph-wide override only
//! relaxes enforcement, it doesn't introduce UB.

#[cfg(all(feature = "aligned", feature = "unaligned"))]
compile_error!(
    "`strata-rkyv-utils`: the `aligned` and `unaligned` features are mutually \
     exclusive; enable exactly one (e.g. `default-features = false`)"
);
#[cfg(not(any(feature = "aligned", feature = "unaligned")))]
compile_error!(
    "`strata-rkyv-utils`: enable exactly one of the `aligned` or `unaligned` \
     features"
);

// `ssz_derive` is a dev-dependency used only by the `ssz` feature's tests.
// Dev-dependencies can't be feature-gated, so reference it here when that
// feature is off to keep test builds clear of the unused-crate lint.
#[cfg(all(test, not(feature = "ssz")))]
use ssz_derive as _;

pub(crate) mod raw_vec;
mod rk;

pub use raw_vec::RawRkVec;
pub use rk::{Rk, RkBox, RkRef, RkVec};

#[cfg(feature = "ssz")]
mod ssz_shims;

#[cfg(feature = "ssz")]
pub use ssz_shims::{RkSsz, SszBuf};

#[cfg(feature = "codec")]
mod codec_shims;

#[cfg(feature = "codec")]
pub use codec_shims::{CodecBuf, RkCodec};
