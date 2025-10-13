//! Varint-length vec used for container that are optimized towards short
//! lengths.

use crate::errors::CodecError;
use crate::types::{Codec, Decoder, Encoder};
use crate::varint::{VARINT_MAX, Varint};

/// Vec that ensures capacity stays within bounds of a simple varint.  In
/// practice, this means it has a max capacity of 0x3fffffff, or about 1
/// billion.  It will never reach this size for our purposes.  This
/// exposes most of the same functions as `Vec` does, but with the bounds
/// checking needed to ensure we stay under this size limit.
///
/// There is an optional lower length bound that can be set with the `BOUND`
/// const generic param.  This uses `u32::MAX` as a default, which lets it be
/// the technical limit enforced by the varint format.  Other length bounds over
/// the varint limit are possible, but they don't do anything differently than
/// `u32::MAX`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VarVec<T, const BOUND: u32 = { u32::MAX }> {
    inner: Vec<T>,
}

impl<T, const BOUND: u32> VarVec<T, BOUND> {
    /// Convenience function to construct a new instance without doing the
    /// bounds checking.
    fn new_unchecked(inner: Vec<T>) -> Self {
        Self { inner }
    }

    /// Constructs a new empty varvec.
    pub fn new() -> Self {
        Self::new_unchecked(Vec::new())
    }

    /// Returns the effective max size for this type.
    pub const fn max_len() -> usize {
        if BOUND < VARINT_MAX {
            BOUND as usize
        } else {
            VARINT_MAX as usize
        }
    }

    /// Constructs a new empty varvec with enough preallocated space to store
    /// the provided number of entries, if it's in bounds.
    pub fn with_capacity(capacity: usize) -> Option<Self> {
        if capacity > Self::max_len() {
            return None;
        }

        Some(Self::new_unchecked(Vec::with_capacity(capacity)))
    }

    /// Constructs a new empty varvec by wrapping another vec, but only if it's
    /// in bounds.
    pub fn from_vec(inner: Vec<T>) -> Option<Self> {
        if inner.len() > Self::max_len() {
            return None;
        }

        Some(Self::new_unchecked(inner))
    }

    /// Gets an ref to the inner vec.
    pub fn inner(&self) -> &Vec<T> {
        &self.inner
    }

    /// Takes out the inner vec.
    pub fn into_inner(self) -> Vec<T> {
        self.inner
    }

    /// Gets the len of the vec.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Gets the len of the vec as a checked varint.
    fn len_varint(&self) -> Varint {
        Varint::new_usize(self.inner().len()).expect("varint_vec: internal vec oversized")
    }

    /// Returns if the vec is empty.
    pub fn is_empty(&self) -> bool {
        self.inner().is_empty()
    }

    /// Pushes a new element, if there's space for it.
    pub fn push(&mut self, v: T) -> bool {
        if self.inner.len() + 1 > Self::max_len() {
            return false;
        }

        self.inner.push(v);
        true
    }

    /// Extends the vec by cloning out of a slice.  Does nothing if there is not
    /// enough space.
    pub fn extend_from_slice_clone(&mut self, slice: &[T]) -> bool
    where
        T: Clone,
    {
        let new_len = self.inner.len() + slice.len();
        if new_len > Self::max_len() {
            return false;
        }

        self.inner.extend(slice.iter().cloned());

        #[cfg(test)]
        self.sanity_check();

        true
    }

    /// Pushes a new element by calling a constructor fn, if there's space for
    /// it.
    pub fn push_with(&mut self, f: impl Fn() -> T) -> bool {
        if self.inner.len() + 1 > Self::max_len() {
            return false;
        }

        self.inner.push(f());
        true
    }

    /// Pops an element.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    /// Removes all elements.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Returns the inner vec's capacity, as a usize.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Reserves additional space in the underlying vec.  This will not reserve
    /// more space than the max length would allow.
    pub fn reserve(&mut self, additional: usize) -> bool {
        if self.inner.len() + additional > Self::max_len() {
            return false;
        }

        self.inner.reserve(additional);
        true
    }

    /// Truncates the vec to a shorter length.
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Resizes the vec, checkedly.
    pub fn resize(&mut self, new_len: usize, value: T) -> bool
    where
        T: Clone,
    {
        if new_len > Self::max_len() {
            return false;
        }

        self.inner.resize(new_len, value);

        #[cfg(test)]
        self.sanity_check();

        true
    }

    /// Resizes the vec, checkedly.
    pub fn resize_with<F>(&mut self, new_len: usize, f: F) -> bool
    where
        F: FnMut() -> T,
    {
        if new_len > Self::max_len() {
            return false;
        }

        self.inner.resize_with(new_len, f);

        #[cfg(test)]
        self.sanity_check();

        true
    }

    /// Gets an index.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Gets a mut ref to an index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.inner.get_mut(index)
    }

    /// Iterates over each item.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    /// Iterates over a mut ref to each item.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.inner.iter_mut()
    }

    /// Gets a slice of the entries in the vec.
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Gets a mut slice of the entries in the vec.
    pub fn as_slice_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }

    /// Checks if the vec's length is in-bounds.
    #[cfg(test)]
    fn sanity_check(&self) {
        assert!(
            self.len() <= Self::max_len(),
            "varint_vec: length out of bounds"
        );
    }
}

impl<T, const BOUND: u32> Default for VarVec<T, BOUND> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const BOUND: u32> std::ops::Deref for VarVec<T, BOUND> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, const BOUND: u32> std::ops::DerefMut for VarVec<T, BOUND> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T, const BOUND: u32> AsRef<[T]> for VarVec<T, BOUND> {
    fn as_ref(&self) -> &[T] {
        &self.inner
    }
}

impl<T, const BOUND: u32> AsMut<[T]> for VarVec<T, BOUND> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T: Codec, const BOUND: u32> Codec for VarVec<T, BOUND> {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let len = Varint::decode(dec)?;
        let len_usize = len.inner() as usize;

        // Check against the effective max length.
        if len_usize > Self::max_len() {
            return Err(CodecError::OverflowContainer);
        }

        let mut vec = Vec::with_capacity(len_usize);
        for _ in 0..len_usize {
            vec.push(T::decode(dec)?);
        }

        Ok(Self { inner: vec })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.len_varint().encode(enc)?;

        for item in &self.inner {
            item.encode(enc)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Most of these tests were written by Claude.

    use crate::{decode_buf_exact, encode_to_vec};

    use super::*;

    #[test]
    fn test_varvec_new() {
        let vec: VarVec<u32> = VarVec::new();
        assert!(vec.is_empty());
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn test_varvec_from_vec() {
        let inner = vec![1u32, 2, 3, 4, 5];
        let varvec: VarVec<u32> = VarVec::from_vec(inner.clone()).unwrap();
        assert_eq!(varvec.len(), 5);
        assert_eq!(varvec.inner(), &inner[..]);
    }

    #[test]
    fn test_varvec_push_pop() {
        let mut vec: VarVec<u32> = VarVec::new();
        assert!(vec.push(1));
        assert!(vec.push(2));
        assert!(vec.push(3));

        assert_eq!(vec.len(), 3);
        assert_eq!(vec.pop(), Some(3));
        assert_eq!(vec.pop(), Some(2));
        assert_eq!(vec.pop(), Some(1));
        assert_eq!(vec.pop(), None);
        assert!(vec.is_empty());
    }

    #[test]
    fn test_varvec_clear() {
        let mut vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3]).unwrap();
        assert!(!vec.is_empty());
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_varvec_truncate() {
        let mut vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3, 4, 5]).unwrap();
        vec.truncate(3);
        assert_eq!(vec.len(), 3);
        vec.sanity_check();
        assert_eq!(vec.inner(), &[1, 2, 3]);
    }

    #[test]
    fn test_varvec_encode_decode_empty() {
        let vec: VarVec<u32> = VarVec::new();
        let buf = encode_to_vec(&vec).unwrap();

        let decoded: VarVec<u32> = decode_buf_exact(&buf).unwrap();
        assert_eq!(decoded.len(), 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_varvec_encode_decode_small() {
        let vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3]).unwrap();
        let buf = encode_to_vec(&vec).unwrap();

        let decoded: VarVec<u32> = decode_buf_exact(&buf).unwrap();
        decoded.sanity_check();
        assert_eq!(decoded.inner(), vec.inner());
    }

    #[test]
    fn test_varvec_encode_decode_u8() {
        let vec: VarVec<u8> = VarVec::from_vec(vec![1u8, 2, 3, 255]).unwrap();
        let buf = encode_to_vec(&vec).unwrap();

        let decoded: VarVec<u8> = decode_buf_exact(&buf).unwrap();
        assert_eq!(decoded.inner(), vec.inner());
    }

    #[test]
    fn test_varvec_encode_decode_large_len() {
        // Test with length that requires 2-byte varint
        let data = vec![42u8; 200];
        let vec: VarVec<u8> = VarVec::from_vec(data.clone()).unwrap();
        let buf = encode_to_vec(&vec).unwrap();

        let decoded: VarVec<u8> = decode_buf_exact(&buf).unwrap();
        assert_eq!(decoded.len(), 200);
        assert_eq!(decoded.inner(), &data[..]);
    }

    #[test]
    fn test_varvec_with_capacity() {
        let vec: VarVec<u32> = VarVec::with_capacity(10).unwrap();
        assert!(vec.is_empty());
        assert!(vec.capacity() >= 10);
    }

    #[test]
    fn test_varvec_reserve() {
        let mut vec: VarVec<u32> = VarVec::new();
        assert!(vec.reserve(100));
        assert!(vec.capacity() >= 100);
    }

    #[test]
    fn test_varvec_max_size_check() {
        // Verify that attempting to create a VarVec larger than VARINT_MAX fails
        let large_size = (VARINT_MAX as usize) + 1;
        assert!(VarVec::<u8>::with_capacity(large_size).is_none());
    }

    #[test]
    fn test_varvec_into_inner() {
        let data = vec![1u32, 2, 3];
        let vec: VarVec<u32> = VarVec::from_vec(data.clone()).unwrap();
        let inner = vec.into_inner();
        assert_eq!(inner, data);
    }

    #[test]
    fn test_varvec_resize() {
        let mut vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3]).unwrap();
        assert!(vec.resize(5, 99));
        assert_eq!(vec.len(), 5);
        assert_eq!(vec.inner(), &[1, 2, 3, 99, 99]);

        assert!(vec.resize(2, 0));
        assert_eq!(vec.len(), 2);
        assert_eq!(vec.inner(), &[1, 2]);
    }

    #[test]
    fn test_varvec_resize_with() {
        let mut vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3]).unwrap();
        let mut counter = 10;
        assert!(vec.resize_with(5, || {
            counter += 1;
            counter
        }));
        assert_eq!(vec.len(), 5);
        assert_eq!(vec.inner(), &[1, 2, 3, 11, 12]);
    }

    #[test]
    fn test_varvec_resize_too_large() {
        let mut vec: VarVec<u32> = VarVec::new();
        assert!(!vec.resize((VARINT_MAX as usize) + 1, 0));
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn test_varvec_resize_with_too_large() {
        let mut vec: VarVec<u32> = VarVec::new();
        assert!(!vec.resize_with((VARINT_MAX as usize) + 1, || 0));
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn test_varvec_reserve_too_large() {
        let mut vec: VarVec<u32> = VarVec::from_vec(vec![1u32; 100]).unwrap();
        // Try to reserve enough to exceed VARINT_MAX
        assert!(!vec.reserve(VARINT_MAX as usize));
        // Vec should be unchanged
        assert_eq!(vec.len(), 100);
    }

    #[test]
    fn test_varvec_push_at_limit() {
        // Create a VarVec at VARINT_MAX capacity
        let data = vec![42u8; VARINT_MAX as usize];
        let mut vec: VarVec<u8> = VarVec::from_vec(data).unwrap();
        vec.sanity_check();
        assert_eq!(vec.len(), VARINT_MAX as usize);

        // Pushing should fail
        assert!(!vec.push(99));
        assert_eq!(vec.len(), VARINT_MAX as usize);
        vec.sanity_check();
    }

    #[test]
    fn test_varvec_push_with_at_limit() {
        let data = vec![42u8; VARINT_MAX as usize];
        let mut vec: VarVec<u8> = VarVec::from_vec(data).unwrap();

        assert!(!vec.push_with(|| 99));
        assert_eq!(vec.len(), VARINT_MAX as usize);
    }

    #[test]
    fn test_varvec_as_slice() {
        let vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3, 4, 5]).unwrap();
        let slice = vec.as_slice();
        assert_eq!(slice, &[1, 2, 3, 4, 5]);

        // Test that methods like strip_prefix work
        assert_eq!(slice.strip_prefix(&[1, 2]), Some(&[3, 4, 5][..]));
        vec.sanity_check();
    }

    #[test]
    fn test_varvec_new_too_large() {
        let oversize_limit = VARINT_MAX as usize + 1;
        let data = vec![42u8; oversize_limit];
        let should_be_none: Option<VarVec<u8>> = VarVec::from_vec(data);
        assert!(should_be_none.is_none(), "test: created invalid vector");
    }

    #[test]
    #[should_panic]
    fn test_varvec_sanity_check_fail() {
        let oversize_limit = VARINT_MAX as usize + 1;
        let vec: VarVec<u8> = VarVec::new_unchecked(vec![42u8; oversize_limit]);
        vec.sanity_check();
    }

    #[test]
    fn test_varvec_extend_from_slice_clone() {
        let mut vec: VarVec<u32> = VarVec::from_vec(vec![1u32, 2, 3]).unwrap();
        let slice = &[4, 5, 6];
        assert!(vec.extend_from_slice_clone(slice));
        assert_eq!(vec.len(), 6);
        assert_eq!(vec.inner(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_varvec_extend_from_slice_clone_at_limit() {
        let data = vec![42u8; VARINT_MAX as usize];
        let mut vec: VarVec<u8> = VarVec::from_vec(data).unwrap();
        let slice = &[99, 100];

        // Should fail because adding 2 elements would exceed VARINT_MAX
        assert!(!vec.extend_from_slice_clone(slice));

        // Vec should be unchanged
        assert_eq!(vec.len(), VARINT_MAX as usize);
        vec.sanity_check();
    }

    #[test]
    fn test_varvec_extend_from_slice_clone_exceed_limit() {
        let data = vec![42u8; VARINT_MAX as usize - 5];
        let mut vec: VarVec<u8> = VarVec::from_vec(data).unwrap();
        let slice = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Should fail because adding 10 elements would exceed VARINT_MAX
        assert!(!vec.extend_from_slice_clone(slice));

        // Vec should be unchanged
        assert_eq!(vec.len(), VARINT_MAX as usize - 5);
        vec.sanity_check();
    }

    // Tests for custom BOUND parameter

    #[test]
    fn test_varvec_bound_max_len() {
        // Test that max_len() returns the correct value for different BOUNDs
        assert_eq!(VarVec::<u32, 10>::max_len(), 10);
        assert_eq!(VarVec::<u32, 100>::max_len(), 100);
        assert_eq!(VarVec::<u32, 1000>::max_len(), 1000);
        // When BOUND is u32::MAX, should use VARINT_MAX
        assert_eq!(VarVec::<u32>::max_len(), VARINT_MAX as usize);
        // When BOUND is greater than VARINT_MAX, should use VARINT_MAX
        assert_eq!(VarVec::<u32, VARINT_MAX>::max_len(), VARINT_MAX as usize);
    }

    #[test]
    fn test_varvec_bound_from_vec() {
        type BoundedVec = VarVec<u32, 10>;

        // Should succeed with vec of length 10
        let vec10 = vec![1u32; 10];
        assert!(BoundedVec::from_vec(vec10).is_some());

        // Should fail with vec of length 11
        let vec11 = vec![1u32; 11];
        assert!(BoundedVec::from_vec(vec11).is_none());

        // Should succeed with smaller vec
        let vec5 = vec![1u32; 5];
        assert!(BoundedVec::from_vec(vec5).is_some());
    }

    #[test]
    fn test_varvec_bound_push() {
        type BoundedVec = VarVec<u32, 5>;
        let mut vec = BoundedVec::new();

        // Push 5 elements should succeed
        for i in 0..5 {
            assert!(vec.push(i));
        }
        assert_eq!(vec.len(), 5);
        vec.sanity_check();

        // Pushing the 6th element should fail
        assert!(!vec.push(99));
        assert_eq!(vec.len(), 5);
    }

    #[test]
    fn test_varvec_bound_with_capacity() {
        type BoundedVec = VarVec<u32, 20>;

        // Should succeed with capacity <= bound
        assert!(BoundedVec::with_capacity(20).is_some());
        assert!(BoundedVec::with_capacity(10).is_some());

        // Should fail with capacity > bound
        assert!(BoundedVec::with_capacity(21).is_none());
    }

    #[test]
    fn test_varvec_bound_reserve() {
        type BoundedVec = VarVec<u32, 15>;
        let mut vec = BoundedVec::from_vec(vec![1u32; 10]).unwrap();

        // Should succeed to reserve up to bound
        assert!(vec.reserve(5));

        // Should fail to reserve beyond bound
        assert!(!vec.reserve(6));
        assert_eq!(vec.len(), 10);
    }

    #[test]
    fn test_varvec_bound_resize() {
        type BoundedVec = VarVec<u32, 8>;
        let mut vec = BoundedVec::from_vec(vec![1u32; 3]).unwrap();

        // Should succeed to resize up to bound
        assert!(vec.resize(8, 99));
        assert_eq!(vec.len(), 8);
        vec.sanity_check();

        // Should fail to resize beyond bound
        assert!(!vec.resize(9, 99));
        assert_eq!(vec.len(), 8);
    }

    #[test]
    fn test_varvec_bound_resize_with() {
        type BoundedVec = VarVec<u32, 6>;
        let mut vec = BoundedVec::from_vec(vec![1u32, 2]).unwrap();

        // Should succeed to resize up to bound
        let mut counter = 10;
        assert!(vec.resize_with(6, || {
            counter += 1;
            counter
        }));
        assert_eq!(vec.len(), 6);
        assert_eq!(vec.inner(), &[1, 2, 11, 12, 13, 14]);

        // Should fail to resize beyond bound
        assert!(!vec.resize_with(7, || 99));
        assert_eq!(vec.len(), 6);
    }

    #[test]
    fn test_varvec_bound_extend_from_slice_clone() {
        type BoundedVec = VarVec<u32, 10>;
        let mut vec = BoundedVec::from_vec(vec![1u32, 2, 3]).unwrap();

        // Should succeed to extend up to bound
        let slice = &[4, 5, 6, 7, 8, 9, 10];
        assert!(vec.extend_from_slice_clone(slice));
        assert_eq!(vec.len(), 10);
        vec.sanity_check();

        // Should fail to extend beyond bound
        let slice2 = &[11];
        assert!(!vec.extend_from_slice_clone(slice2));
        assert_eq!(vec.len(), 10);
    }

    #[test]
    fn test_varvec_bound_push_with() {
        type BoundedVec = VarVec<u32, 3>;
        let mut vec = BoundedVec::from_vec(vec![1u32, 2]).unwrap();

        // Should succeed to push up to bound
        assert!(vec.push_with(|| 3));
        assert_eq!(vec.len(), 3);

        // Should fail to push beyond bound
        assert!(!vec.push_with(|| 4));
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn test_varvec_bound_encode_decode() {
        type BoundedVec = VarVec<u32, 5>;

        // Encode a vec within bounds
        let vec = BoundedVec::from_vec(vec![1u32, 2, 3, 4, 5]).unwrap();
        let buf = encode_to_vec(&vec).unwrap();

        // Should decode successfully
        let decoded: BoundedVec = decode_buf_exact(&buf).unwrap();
        assert_eq!(decoded.inner(), vec.inner());
        decoded.sanity_check();
    }

    #[test]
    fn test_varvec_bound_decode_overflow() {
        type BoundedVec = VarVec<u32, 5>;

        // Create a vec with 6 elements (exceeds bound)
        let unbounded_vec = VarVec::<u32>::from_vec(vec![1u32, 2, 3, 4, 5, 6]).unwrap();
        let buf = encode_to_vec(&unbounded_vec).unwrap();

        // Should fail to decode into bounded vec
        let result: Result<BoundedVec, _> = decode_buf_exact(&buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CodecError::OverflowContainer));
    }

    #[test]
    fn test_varvec_bound_sanity_check() {
        type BoundedVec = VarVec<u32, 7>;
        let vec = BoundedVec::from_vec(vec![1u32; 7]).unwrap();
        vec.sanity_check();

        let vec2 = BoundedVec::from_vec(vec![1u32; 5]).unwrap();
        vec2.sanity_check();
    }

    #[test]
    #[should_panic]
    fn test_varvec_bound_sanity_check_fail() {
        type BoundedVec = VarVec<u32, 5>;
        // Use new_unchecked to create an invalid vec
        let vec = BoundedVec::new_unchecked(vec![1u32; 6]);
        vec.sanity_check();
    }
}
