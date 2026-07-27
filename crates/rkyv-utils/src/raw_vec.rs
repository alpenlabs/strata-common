//! Backing-buffer plumbing for [`RkVec`](crate::RkVec).
//!
//! An [`RkVec`](crate::RkVec)'s owned buffer type, and the serializer scratch
//! buffer it is built from, depend on the alignment mode, and turning rkyv's
//! [`AlignedVec`] into that buffer involves some `unsafe` allocation handling.
//! This module isolates that machinery so the [`rk`](crate::rk) module can stay
//! focused on the [`Rk`](crate::Rk) wrapper itself.

// The buffer-type aliases and conversions are the only mode-dependent pieces;
// each alignment mode gets its own `imp` module so the `#[cfg]` lives in one
// place per mode rather than on every item.  Exactly one is ever compiled, keyed
// off the additive `unaligned` feature.
pub use imp::*;
use rkyv::util::AlignedVec;

/// Per-mode buffer machinery for the default (aligned) mode.
#[cfg(not(feature = "unaligned"))]
mod imp {
    use super::AlignedVec;

    /// The owned buffer backing an [`RkVec`](crate::RkVec): an [`AlignedVec`]
    /// (default alignment 16, which covers every standard archived primitive),
    /// so a freshly-encoded `RkVec` is alignment-guaranteed by construction.
    pub type RawRkVec = AlignedVec;

    /// The alignment a [`RawRkVec`] allocation is *guaranteed* to have, and thus
    /// the largest `align_of::<T>()` that can soundly be placed in one without
    /// checking the resulting address.
    pub const RAW_VEC_ALIGN: usize = 16;

    /// The scratch buffer [`RkVec::from_val`](crate::RkVec::from_val) serializes
    /// into: the default [`AlignedVec`] (alignment 16 == the [`RawRkVec`]
    /// backing), kept as-is.
    pub(crate) type SerVec = AlignedVec;

    /// Converts the freshly-serialized [`SerVec`] into the [`RawRkVec`] backing
    /// (a no-op: same type).
    pub(crate) fn ser_buf_into_raw(buf: SerVec) -> RawRkVec {
        buf
    }

    /// Converts a caller-provided [`AlignedVec`] into the [`RawRkVec`] backing (a
    /// no-op: same type).
    pub(crate) fn into_raw_buf(buf: AlignedVec) -> RawRkVec {
        buf
    }

    /// Copies a byte slice into a fresh, 16-aligned [`RawRkVec`].
    pub(crate) fn raw_from_slice(bytes: &[u8]) -> RawRkVec {
        let mut buf = AlignedVec::new();
        buf.extend_from_slice(bytes);
        buf
    }
}

/// Per-mode buffer machinery for the `unaligned` feature.
#[cfg(feature = "unaligned")]
mod imp {
    use super::AlignedVec;

    /// The owned buffer backing an [`RkVec`](crate::RkVec): a plain `Vec<u8>` —
    /// the archived format has no alignment requirement under `unaligned`, so the
    /// simpler/cheaper buffer suffices.
    pub type RawRkVec = Vec<u8>;

    /// The alignment a [`RawRkVec`] allocation is *guaranteed* to have, and thus
    /// the largest `align_of::<T>()` that can soundly be placed in one without
    /// checking the resulting address.  A `Vec<u8>` promises only 1, which is
    /// all the archived format needs under `unaligned`, since that makes rkyv's
    /// own primitives alignment-1.
    pub const RAW_VEC_ALIGN: usize = 1;

    /// The scratch buffer [`RkVec::from_val`](crate::RkVec::from_val) serializes
    /// into: an `AlignedVec<1>`.  Its buffer is allocated by the global allocator
    /// with `Layout(cap, 1)`, byte-for-byte the layout a `Vec<u8>` uses, so
    /// [`ser_buf_into_raw`] can move it into the `Vec<u8>` backing with no copy.
    pub(crate) type SerVec = AlignedVec<1>;

    /// Moves the freshly-serialized [`SerVec`] into the `Vec<u8>` [`RawRkVec`]
    /// backing without copying.
    pub(crate) fn ser_buf_into_raw(buf: SerVec) -> RawRkVec {
        let (ptr, len, cap) = buf.into_parts();
        // SAFETY: `buf` is an `AlignedVec<1>`, so `ptr` was allocated by the
        // global allocator with `Layout(cap, 1)` == `Layout::array::<u8>(cap)` —
        // exactly the layout `Vec<u8>` uses to grow and free its buffer.
        // `len <= cap`, the first `len` bytes are initialized, and `cap` is the
        // true allocation capacity.  These are precisely `Vec::from_raw_parts`'s
        // requirements, so ownership of the allocation (including its eventual
        // dealloc) transfers soundly to the `Vec<u8>` with no copy.
        unsafe { Vec::from_raw_parts(ptr.as_ptr(), len, cap) }
    }

    /// Converts a caller-provided [`AlignedVec`] (alignment 16, e.g. straight
    /// from `rkyv::to_bytes`) into the `Vec<u8>` [`RawRkVec`] backing.  This must
    /// copy, because an align-16 allocation cannot be handed to a `Vec<u8>`
    /// (which would free it as align-1, UB).
    pub(crate) fn into_raw_buf(buf: AlignedVec) -> RawRkVec {
        buf.into_vec()
    }

    /// Copies a byte slice into a fresh `Vec<u8>` [`RawRkVec`].
    pub(crate) fn raw_from_slice(bytes: &[u8]) -> RawRkVec {
        bytes.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_from_slice_preserves_bytes() {
        let raw = raw_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(&raw[..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn ser_buf_into_raw_preserves_bytes_and_owns_allocation() {
        let mut scratch = SerVec::new();
        scratch.extend_from_slice(&[10, 20, 30, 40]);

        let mut raw = ser_buf_into_raw(scratch);
        assert_eq!(&raw[..], &[10, 20, 30, 40]);

        // Grow the converted buffer to force a reallocation/deallocation through
        // the destination buffer's own allocator path.  Under `unaligned` this
        // is exactly the moved-from-`AlignedVec<1>` allocation, so this exercises
        // that the ownership transfer is sound (a layout mismatch would surface
        // here under a strict allocator / Miri).
        raw.extend_from_slice(&[50, 60]);
        assert_eq!(&raw[..], &[10, 20, 30, 40, 50, 60]);
    }

    /// [`RAW_VEC_ALIGN`] is what the *unvalidated* [`RkVec`](crate::RkVec)
    /// constructors ([`from_val`](crate::RkVec::from_val),
    /// [`to_rkvec`](crate::Rk::to_rkvec)) rest on: they place an archived value
    /// into one of these buffers and later read it back through
    /// `access_unchecked`, having only const-checked the type's alignment
    /// against this constant.  So every path that produces a [`RawRkVec`] has to
    /// actually deliver that alignment, or the guard is checking against a
    /// promise the backing doesn't keep.
    #[test]
    fn every_backing_path_meets_raw_vec_align() {
        let from_slice = raw_from_slice(&[1u8; 64]);
        assert!((from_slice.as_ptr() as usize).is_multiple_of(RAW_VEC_ALIGN));

        let mut scratch = SerVec::new();
        scratch.extend_from_slice(&[2u8; 64]);
        let from_ser = ser_buf_into_raw(scratch);
        assert!((from_ser.as_ptr() as usize).is_multiple_of(RAW_VEC_ALIGN));

        let mut aligned = AlignedVec::new();
        aligned.extend_from_slice(&[3u8; 64]);
        let from_aligned = into_raw_buf(aligned);
        assert!((from_aligned.as_ptr() as usize).is_multiple_of(RAW_VEC_ALIGN));
    }

    #[test]
    fn into_raw_buf_preserves_bytes() {
        let mut aligned = AlignedVec::new();
        aligned.extend_from_slice(&[7, 8, 9]);

        let raw = into_raw_buf(aligned);
        assert_eq!(&raw[..], &[7, 8, 9]);
    }
}
