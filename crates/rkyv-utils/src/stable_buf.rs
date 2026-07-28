//! The [`StableBuf`] marker trait.

use std::rc::Rc;
use std::sync::Arc;

use rkyv::util::AlignedVec;

/// A byte buffer whose [`AsRef<[u8]>`] impl is *stable*: every call returns the
/// same slice, same base pointer, same length, same contents, for as long as
/// the buffer is not mutated.
///
/// [`Rk`](crate::Rk) validates a buffer once at construction and then serves
/// every [`as_ref`](crate::Rk::as_ref) from [`rkyv::access_unchecked`], which requires
/// the bytes it reads to be the bytes that were validated.  Plain `AsRef` is not
/// enough to guarantee that: the trait promises nothing about repeated calls,
/// and a *safe* impl can hand out a different slice each time (e.g. by picking
/// between two owned buffers with a `Cell` counter).  Such a buffer would let
/// entirely safe code, `Rk::from_buf(..)` followed by `.as_ref()`, validate
/// one buffer and then read another, which is undefined behaviour.
///
/// So the safe constructors require this trait, and it is `unsafe` to implement
/// because soundness depends on it.  The unchecked constructor
/// ([`Rk::new_unchecked`](crate::Rk::new_unchecked)) stays generic over plain
/// `AsRef<[u8]>`, since there the obligation is already the caller's.
///
/// # Safety
///
/// Implementors must guarantee that repeated `as_ref` calls on an unmutated
/// value return an identical slice.  In particular the impl must not use
/// interior mutability, randomness, or any other state to vary what it returns.
pub unsafe trait StableBuf: AsRef<[u8]> {}

// SAFETY (all impls below): each of these is a plain owned or borrowed byte
// buffer whose `as_ref` is a direct projection to its own storage, with no
// interior mutability or other state involved, so it returns the same slice
// every time.
unsafe impl StableBuf for [u8] {}
unsafe impl<const N: usize> StableBuf for [u8; N] {}
unsafe impl StableBuf for Vec<u8> {}
unsafe impl<const A: usize> StableBuf for AlignedVec<A> {}
unsafe impl StableBuf for Box<[u8]> {}
unsafe impl StableBuf for Arc<[u8]> {}
unsafe impl StableBuf for Rc<[u8]> {}

// SAFETY: a shared reference forwards `as_ref` to the referent, which is itself
// stable, and the referent cannot be mutated through the shared borrow.
unsafe impl<B: ?Sized + StableBuf> StableBuf for &B {}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_stable<B: StableBuf>() {}

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

        // Shared-ownership and inline buffers callers commonly reach for.
        assert_stable::<Arc<[u8]>>();
        assert_stable::<Rc<[u8]>>();
        assert_stable::<[u8; 32]>();
    }
}
