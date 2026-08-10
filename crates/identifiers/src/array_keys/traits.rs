//! Utilities for working with identifiers as database keys.

/// Used for types that can be represented as a flat array of bytes, as would be
/// used for binary database keys.
///
/// Unfortunately, `generic_const_exprs` is not stable, so we can't make this
/// interface *really* nice, we just have to hope that LLVM realizes that it can
/// eliminate all these bounds checks.
pub trait ArrayKey {
    /// The size of an array that contains this key byte.
    const BYTES: usize;

    /// Copies the key bytes into the array.
    ///
    /// This MUST be big-endian for integer-like types.
    ///
    /// # Panics
    ///
    /// If called with a slice that is not [`Self::BYTES`] bytes.
    fn copy_into(&self, buf: &mut [u8]);

    /// Constructs an instance of the key by decoding from bytes.
    ///
    /// # Panics
    ///
    /// If called with a slice that is not [`Self::BYTES`] bytes.
    fn copy_from(buf: &[u8]) -> Self;
}

/// General impl for all bytebufs since they're already of the right structure.
impl<const N: usize> ArrayKey for [u8; N] {
    const BYTES: usize = N;

    fn copy_into(&self, buf: &mut [u8]) {
        assert_buf_len_eq::<Self>(buf);
        buf.copy_from_slice(self);
    }

    fn copy_from(buf: &[u8]) -> Self {
        assert_buf_len_eq::<Self>(buf);
        buf.try_into().unwrap()
    }
}

/// Extension trait for "buffer types" that we might want to decode as an [`ArrayKey`].
pub trait ArrayKeyBuf {
    /// Attempts to decode the buf into an [`ArrayKey`] type.
    ///
    /// Returns `None` if the array is not the right size.
    fn try_into_key<K: ArrayKey>(&self) -> Option<K>;
}

impl<T: AsRef<[u8]>> ArrayKeyBuf for T {
    fn try_into_key<K: ArrayKey>(&self) -> Option<K> {
        let buf = <Self as AsRef<[u8]>>::as_ref(self);
        if buf.len() == K::BYTES {
            Some(K::copy_from(buf))
        } else {
            None
        }
    }
}

/// Extension trait for array types that we might want to decode as an [`ArrayKey`].
///
/// Unlike [`ArrayKeyBuf`], this is infallible, since the array length is known
/// statically and MUST be checked at compile time.
///
/// You shouldn't have to implement this on your own types, it's just so we can
/// add trait member fn to `[u8; N]`.
pub trait ArrayKeyArr<const N: usize> {
    /// Decodes the array into an [`ArrayKey`] type of exactly the same size.
    ///
    /// Instantiating this with a key type whose width isn't `N` MUST fail to
    /// compile.
    fn into_key<K: ArrayKey>(self) -> K;

    /// Constructs a new instance of the array from an [`ArrayKey`] type of
    /// exactly the same size.
    ///
    /// Instantiating this with a key type whose width isn't `N` MUST fail to
    /// compile.
    fn from_key<K: ArrayKey>(k: &K) -> Self;
}

/// Impl for `[u8; N]` arrays that provides the guarantees we expect.
impl<const N: usize> ArrayKeyArr<N> for [u8; N] {
    fn into_key<K: ArrayKey>(self) -> K {
        // Ideally this would be a bound like `K: ArrayKey<BYTES = { N }>`, but
        // that needs `associated_const_equality`, which isn't stable.  An
        // inline const inherits the generics of the fn it's in, so we can check
        // the same thing here, just at monomorphization time instead of when
        // typechecking the call.
        assert_arraykey_bytes::<N, K>();
        K::copy_from(&self)
    }

    fn from_key<K: ArrayKey>(k: &K) -> Self {
        assert_arraykey_bytes::<N, K>();
        let mut buf = [0; N];
        k.copy_into(&mut buf[..]);
        buf
    }
}

/// Fails to compile if `K` is not exactly `N` bytes wide.  Does nothing at
/// run-time.
///
/// This triggers an error during constant propagation (rather than at type
/// checking), so it only fires where this is actually instantiated.  That's
/// every real call, but it does mean a bad instantiation sitting in generic
/// code that's never called goes unreported.
#[inline(always)]
fn assert_arraykey_bytes<const N: usize, K: ArrayKey>() {
    const {
        // Can't be `assert_eq!` because of const eval issues.
        assert!(
            N == K::BYTES,
            "arraykey: array length does not match key width"
        )
    };
}

/// Asserts that a buffer is exactly as wide as the key type `K` expects.
///
/// # Panics
///
/// If the buffer length doesn't match [`ArrayKey::BYTES`].
#[inline(always)]
pub(crate) fn assert_buf_len_eq<K: ArrayKey>(arr: &[u8]) {
    let len = arr.len();
    assert_eq!(
        arr.len(),
        K::BYTES,
        "arraykey: passed invalid array (exp {}, got {len})",
        K::BYTES
    );
}

/// Extension trait for [`ArrayKey`] with convenience fns.
pub trait ArrayKeyExt: ArrayKey {
    /// Encodes the key into a `Vec<u8>`.
    fn to_vec(&self) -> Vec<u8>;
}

impl<T: ArrayKey> ArrayKeyExt for T {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = vec![0; Self::BYTES];
        self.copy_into(&mut vec[..]);
        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_key_arr() {
        // Arrays are their own key type, so this is just a passthrough.
        assert_eq!(<[u8; 4]>::from_key(&[1u8, 2, 3, 4]), [1, 2, 3, 4]);
        assert_eq!(<[u8; 0]>::from_key(&[]), [0u8; 0]);

        // Ints encode big-endian, matching `copy_into`.
        assert_eq!(
            <[u8; 4]>::from_key(&0x01020304u32),
            [0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(<[u8; 1]>::from_key(&0xffu8), [0xff]);
    }

    #[test]
    fn test_from_key_is_inverse_of_into_key() {
        let arr = [0x11u8, 0x22, 0x33, 0x44];
        let k = arr.into_key::<u32>();
        assert_eq!(<[u8; 4]>::from_key(&k), arr);
    }

    #[test]
    fn test_to_vec_matches_copy_into() {
        let k = 0x01020304u32;
        let mut buf = [0u8; 4];
        k.copy_into(&mut buf);
        assert_eq!(k.to_vec(), buf.to_vec());

        let arr = [0xaa, 0xbb, 0xcc];
        assert_eq!(arr.to_vec(), vec![0xaa, 0xbb, 0xcc]);

        let empty: [u8; 0] = [];
        assert_eq!(empty.to_vec(), Vec::<u8>::new());
    }
}
