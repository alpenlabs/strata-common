//! The [`StableBuf`] and [`CloneBuf`] marker traits.

use std::rc::Rc;
use std::sync::Arc;

use rkyv::util::AlignedVec;

/// A byte buffer whose bytes stay put: [`AsRef<[u8]>`] yields the same slice,
/// same base pointer, same length, same contents, on every call and for as long
/// as the buffer is neither mutated nor dropped, *including across moves of the
/// buffer value itself*.
///
/// [`Rk`](crate::Rk) validates a buffer once at construction and then serves
/// every [`as_ref`](crate::Rk::as_ref) from [`rkyv::access_unchecked`], which requires
/// the bytes it reads to be the bytes that were validated, at the address they
/// were validated at.  Plain `AsRef` guarantees neither:
///
/// - the trait promises nothing about repeated calls, so a *safe* impl can hand out a different
///   slice each time (e.g. by picking between two owned buffers with a `Cell` counter);
/// - and for a buffer that stores its bytes *inline*, like `[u8; N]`, the slice moves with the
///   value, so the address validated inside [`from_buf`](crate::Rk::from_buf) is not the address
///   the returned (and subsequently moved) [`Rk`](crate::Rk) reads from.
///
/// Either one would let entirely safe code, `Rk::from_buf(..)` followed by
/// `.as_ref()`, validate one thing and then read another, which is undefined
/// behaviour.
///
/// So the safe constructors require this trait, and it is `unsafe` to implement
/// because soundness depends on it.  The unchecked constructor
/// ([`Rk::new_unchecked`](crate::Rk::new_unchecked)) stays generic over plain
/// `AsRef<[u8]>`, since there the obligation is already the caller's.
///
/// Inline byte arrays are deliberately *not* implementors, in either owned or
/// borrowed form.  Wrap the bytes in an indirection or reslice them instead:
///
/// ```compile_fail
/// # use rkyv::rancor::Error;
/// # use strata_rkyv_utils::Rk;
/// let bytes = [0u8; 64];
/// // `[u8; 64]` is not a `StableBuf`: its bytes move with the value.
/// let rk = Rk::<[u8; 64], rkyv::Archived<u64>>::from_buf::<Error>(bytes);
/// ```
///
/// ```
/// # use rkyv::rancor::Error;
/// # use strata_rkyv_utils::{Rk, RkVec};
/// # let owned = RkVec::<rkyv::Archived<u64>>::from_val(&7u64);
/// # let mut bytes = [0u8; 8];
/// # bytes.copy_from_slice(owned.as_slice());
/// // Reslicing to `&[u8]` borrows the array in place, which is stable.
/// let rk = Rk::<&[u8], rkyv::Archived<u64>>::from_buf::<Error>(&bytes[..]);
/// ```
///
/// # Safety
///
/// Implementors must guarantee both of:
///
/// - repeated `as_ref` calls on an unmutated value return an identical slice.  In particular the
///   impl must not use interior mutability, randomness, or any other state to vary what it returns.
/// - that slice's address does not depend on where the buffer value itself lives, i.e. the bytes
///   sit behind an indirection and survive a move of the `Self` value.
///
/// ## `Deref<Target = [u8]>` is *not* sufficient
///
/// It is tempting to read "derefs to a slice" as "the bytes live elsewhere", but
/// that does not follow.  Inline-capable containers deref to a `[u8]` whose
/// address still moves with the container:
///
/// ```text
/// ArrayVec<u8, 32>          0x744662ffe420 -> 0x74465c000c44   MOVED
/// SmallVec<[u8; 32]> inline 0x74465bffe3a1 -> 0x74464c000ce1   MOVED
/// SmallVec<[u8; 32]> spilled 0x744650000ce0 -> 0x744650000ce0  stable
/// bytes::Bytes              0x744654000c40 -> 0x744654000c40   stable
/// ```
///
/// (each address is the buffer's data pointer before and after moving the
/// container into a `Box`.)
///
/// So `SmallVec`, `ArrayVec` and `TinyVec` must not implement this trait, even
/// though they satisfy `Deref<Target = [u8]>` and look like ordinary byte
/// vectors.  Note the two `SmallVec` rows in particular: stability there is a
/// property of the *value*, not the type, so no correct impl for it exists at
/// all.  Note also the inline address `..e3a1`, which is not even 2-aligned.
///
/// `bytes::Bytes` is the shape that is fine: the bytes live in a refcounted
/// allocation the handle merely points at, so moving the handle leaves them put.
pub unsafe trait StableBuf: AsRef<[u8]> {}

// SAFETY (all impls below): each of these is a plain owned or borrowed byte
// buffer whose `as_ref` is a direct projection to its own storage, with no
// interior mutability or other state involved, so it returns the same slice
// every time.  Each also holds its bytes behind an indirection (a heap
// allocation, or a borrow of one), so moving the buffer value leaves the bytes
// where they are.
unsafe impl StableBuf for [u8] {}
unsafe impl StableBuf for Vec<u8> {}
unsafe impl<const A: usize> StableBuf for AlignedVec<A> {}
unsafe impl StableBuf for Box<[u8]> {}
unsafe impl StableBuf for Arc<[u8]> {}
unsafe impl StableBuf for Rc<[u8]> {}

// SAFETY: a shared reference forwards `as_ref` to the referent, which is itself
// stable, and the referent can neither be mutated nor moved through the shared
// borrow.
unsafe impl<B: ?Sized + StableBuf> StableBuf for &B {}

/// A [`StableBuf`] that can be cloned without weakening the alignment its bytes
/// are laid out at.
///
/// [`Rk`](crate::Rk) validates a buffer's *address* once and never re-checks it,
/// so cloning the handle must not silently move the archive to a less-aligned
/// address: a `Vec<u8>` or `Box<[u8]>` that happened to be allocated 8-aligned
/// (and therefore validated fine for an archived `u64`) clones into a fresh
/// allocation with only byte alignment, and reading through that clone would be
/// undefined behaviour.
///
/// [`CLONE_ALIGN`](CloneBuf::CLONE_ALIGN) records what a clone does guarantee, and
/// [`Rk`](crate::Rk)'s [`Clone`] impl checks the archived type's alignment against
/// it at compile time.  When that check fails, copy into an owned
/// [`RkVec`](crate::RkVec) with [`to_rkvec`](crate::Rk::to_rkvec) instead, which
/// allocates a backing the active alignment mode guarantees.
///
/// # Safety
///
/// A clone must satisfy the [`StableBuf`] contract *and* start at an address
/// aligned to at least [`CLONE_ALIGN`](CloneBuf::CLONE_ALIGN) bytes.  Using
/// [`usize::MAX`] is only correct when cloning shares the original allocation,
/// so the clone's bytes are literally the original's.
///
/// Whether that holds is a property of the [`Clone`] impl, not of how the type
/// looks.  Two types from the same crate can differ:
///
/// ```text
/// bytes::Bytes::clone     src=0x73ba6c000ce0 clone=0x73ba6c000ce0  shares    -> usize::MAX
/// bytes::BytesMut::clone  src=0x73ba6c000d50 clone=0x73ba6c000da0  reallocs  -> 1
/// ```
///
/// Both are refcount-flavoured byte buffers and both are sound [`StableBuf`]s,
/// but only the shared-allocation one carries the original's alignment into its
/// clone.  When in doubt, report the alignment the clone's *allocation* is made
/// with (1 for anything going through the global allocator as bytes) rather
/// than the alignment the original happened to have.
pub unsafe trait CloneBuf: StableBuf + Clone {
    /// The alignment a *clone*'s base pointer is guaranteed to have, or
    /// [`usize::MAX`] when cloning shares the original allocation and so
    /// inherits whatever alignment the original was validated at.
    const CLONE_ALIGN: usize;
}

// SAFETY: cloning an `Arc`/`Rc` bumps a refcount and shares the very same
// allocation, so the clone's bytes are at the original's address and keep
// whatever alignment it was validated at.
unsafe impl CloneBuf for Arc<[u8]> {
    const CLONE_ALIGN: usize = usize::MAX;
}

unsafe impl CloneBuf for Rc<[u8]> {
    const CLONE_ALIGN: usize = usize::MAX;
}

// SAFETY: cloning a shared reference copies the pointer, so the clone addresses
// the exact same bytes as the original.
unsafe impl<B: ?Sized + StableBuf> CloneBuf for &B {
    const CLONE_ALIGN: usize = usize::MAX;
}

// SAFETY: `AlignedVec<A>` reallocates on clone, but always through
// `Layout::from_size_align(cap, A)`, so the clone's base pointer is `A`-aligned.
unsafe impl<const A: usize> CloneBuf for AlignedVec<A> {
    const CLONE_ALIGN: usize = A;
}

// SAFETY: these reallocate on clone through the global allocator with a
// `Layout::array::<u8>` layout, which promises alignment 1 and nothing more.
unsafe impl CloneBuf for Vec<u8> {
    const CLONE_ALIGN: usize = 1;
}

unsafe impl CloneBuf for Box<[u8]> {
    const CLONE_ALIGN: usize = 1;
}

// Whichever backing the active mode picks for `RkVec`, cloning it has to keep at
// least the alignment the *unvalidated* `RkVec` constructors already bank on
// (see `RAW_VEC_ALIGN`), or `RkVec::from_val(..).clone()` would quietly hand
// `access_unchecked` a weaker-aligned buffer than `from_val` guaranteed.
const _: () = assert!(crate::RawRkVec::CLONE_ALIGN >= crate::RAW_VEC_ALIGN);

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_stable<B: StableBuf>() {}

    fn assert_clone_align<B: CloneBuf>(expected: usize) {
        assert_eq!(B::CLONE_ALIGN, expected);
    }

    /// The buffer types the crate's own aliases and constructors are built
    /// around have to stay `StableBuf`, or the safe constructors silently stop
    /// accepting them.
    #[test]
    fn supported_buffer_types_are_stable() {
        // Backs `RkVec` in one mode or the other.
        assert_stable::<crate::RawRkVec>();
        assert_stable::<Vec<u8>>();
        assert_stable::<AlignedVec>();
        assert_stable::<AlignedVec<1>>();

        // Backs `RkBox` / `RkRef`.
        assert_stable::<Box<[u8]>>();
        assert_stable::<&[u8]>();

        // Shared-ownership buffers callers commonly reach for.
        assert_stable::<Arc<[u8]>>();
        assert_stable::<Rc<[u8]>>();

        // Note the absence of `[u8; N]` and `&[u8; N]`: an array stores its
        // bytes inline, so they move with the value and the address `from_buf`
        // validated isn't the one `as_ref` later reads.  Callers reslice to
        // `&[u8]` instead.
    }

    /// Every clonable backing has to report the alignment its *clone* actually
    /// guarantees, since `Rk`'s `Clone` impl const-checks the archived type
    /// against exactly this number.
    #[test]
    fn clone_align_matches_backing_guarantee() {
        // Sharing the allocation preserves the validated address outright.
        assert_clone_align::<Arc<[u8]>>(usize::MAX);
        assert_clone_align::<Rc<[u8]>>(usize::MAX);
        assert_clone_align::<&[u8]>(usize::MAX);

        // `AlignedVec` reallocates, but at its own const alignment.
        assert_clone_align::<AlignedVec>(16);
        assert_clone_align::<AlignedVec<1>>(1);

        // Plain allocations reallocate with no alignment promise at all.
        assert_clone_align::<Vec<u8>>(1);
        assert_clone_align::<Box<[u8]>>(1);
    }

    /// The point of `CLONE_ALIGN`: a reallocating clone really can land on a
    /// weaker alignment than the original, which is what the compile-time guard
    /// in `Rk::clone` exists to catch.
    #[test]
    fn aligned_vec_clone_keeps_its_alignment() {
        let mut buf = AlignedVec::<16>::new();
        buf.extend_from_slice(&[7u8; 64]);

        let cloned = buf.clone();
        assert!((cloned.as_ptr() as usize).is_multiple_of(AlignedVec::<16>::CLONE_ALIGN));
        assert_eq!(cloned.as_slice(), buf.as_slice());
    }
}
