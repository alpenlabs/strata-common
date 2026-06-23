//! [`Rk`] wrapper type.

use std::marker::PhantomData;

use rkyv::api::high::{HighSerializer, HighValidator};
use rkyv::bytecheck::CheckBytes;
use rkyv::rancor::{Error, Source};
use rkyv::ser::allocator::ArenaHandle;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Portable, Serialize};

/// A `Vec<u8>` containing a valid [`Archived`] instance of `T`.
pub type RkVec<T> = Rk<Vec<u8>, T>;

/// A `Box<[u8]>` containing a valid [`Archived`] instance of `T`.
pub type RkBox<T> = Rk<Box<[u8]>, T>;

/// A `&[u8]` containing a valid [`Archived`] instance of `T`.
pub type RkRef<'a, T> = Rk<&'a [u8], T>;

/// Wrapper type around some buffer that is known to contain a valid
/// `rkyv`-decodable value.
///
/// This means we can freely return a pointer to the value as its [`Archived`]
/// form.
///
/// This is meant to be pronounced "arc", but more acutely than how you'd
/// pronounce `Arc`, so that it's easy to tell the difference.
#[derive(Copy, Clone, Debug)]
pub struct Rk<B: AsRef<[u8]>, T: Portable>(B, PhantomData<T>);

impl<B: AsRef<[u8]>, T: Portable> Rk<B, T> {
    fn new_unchecked(buf: B) -> Self {
        Self(buf, PhantomData)
    }

    /// Validates that the buffer contains a valid instance of `T::Archived` and
    /// returns itself wrapping the underlying buffer.
    pub fn from_buf<E: Source>(buf: B) -> Result<Self, E>
    where
        T: for<'a> CheckBytes<HighValidator<'a, E>>,
    {
        rkyv::access::<T, E>(buf.as_ref())?;
        Ok(Self::new_unchecked(buf))
    }

    /// Returns the underlying buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Copies the underlying buffer to a newly-allocated owned buffer.
    pub fn to_rkbox(&self) -> RkBox<T> {
        RkBox::new_unchecked(Box::from(self.as_slice()))
    }
}

impl<B: AsRef<[u8]>, T: Portable> AsRef<T> for Rk<B, T> {
    fn as_ref(&self) -> &T {
        // SAFETY: we already checked it in all constructors
        unsafe { rkyv::access_unchecked(self.as_slice()) }
    }
}

/// Helper impl.
impl<T: Portable> RkVec<T> {
    /// Encodes a value whose [`Archived`](Archive::Archived) form is `T` into a
    /// freshly-allocated buffer and returns it as a [`RkVec`].
    ///
    /// # Panics
    ///
    /// If serialization fails (which for the in-memory serializer only happens
    /// on allocation failure).
    pub fn from_val<S>(val: &S) -> Self
    where
        S: Archive<Archived = T>
            + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, Error>>,
    {
        let buf = rkyv::to_bytes::<Error>(val).expect("rkyv-utils: serialization failed");
        Self::new_unchecked(buf.into_vec())
    }

    /// Converts the [`RkVec`] into an [`RkBox`].
    pub fn into_rkbox(self) -> RkBox<T> {
        let Self(vec, _) = self;
        RkBox::new_unchecked(vec.into_boxed_slice())
    }
}

/// Helper impl.
impl<T: Portable> RkBox<T> {
    /// Encodes a value whose [`Archived`](Archive::Archived) form is `T` into a
    /// freshly-allocated buffer and returns it as a [`RkBox`].  This goes
    /// through a `Vec` under the hood so it's not really much cheaper but it
    /// may be more ergonomic.
    ///
    /// # Panics
    ///
    /// If serialization fails (which for the in-memory serializer only happens
    /// on allocation failure).
    pub fn from_val<S>(val: &S) -> Self
    where
        S: Archive<Archived = T>
            + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, Error>>,
    {
        RkVec::from_val(val).into_rkbox()
    }
}

#[cfg(test)]
mod tests {
    use rkyv::rancor::Error;
    use rkyv::{Archive, Deserialize, Serialize};

    use super::{RkBox, RkRef, RkVec};

    #[derive(Archive, Serialize, Deserialize, Debug, PartialEq)]
    struct Example {
        name: String,
        value: u32,
    }

    fn sample() -> Example {
        Example {
            name: "pi".to_owned(),
            value: 31415926,
        }
    }

    /// Reference bytes produced directly by `rkyv`, used to cross-check the
    /// buffers our `encode` helpers produce.
    fn reference_bytes() -> Vec<u8> {
        rkyv::to_bytes::<Error>(&sample()).unwrap().into_vec()
    }

    #[test]
    fn vec_encode_matches_rkyv_and_roundtrips() {
        let val = sample();
        let rk = RkVec::<ArchivedExample>::from_val(&val);

        // Buffer is exactly what rkyv would produce.
        assert_eq!(rk.as_slice(), reference_bytes().as_slice());

        // Archived view is accessible without re-validation.
        let archived = rk.as_ref();
        assert_eq!(archived.name.as_str(), val.name);
        assert_eq!(archived.value.to_native(), val.value);

        // Full deserialization roundtrips back to the original.
        let de = rkyv::deserialize::<Example, Error>(rk.as_ref()).unwrap();
        assert_eq!(de, val);
    }

    #[test]
    fn box_encode_matches_rkyv_and_roundtrips() {
        let val = sample();
        let rk = RkBox::<ArchivedExample>::from_val(&val);

        assert_eq!(rk.as_slice(), reference_bytes().as_slice());

        let archived = rk.as_ref();
        assert_eq!(archived.name.as_str(), val.name);
        assert_eq!(archived.value.to_native(), val.value);
    }

    #[test]
    fn from_buf_accepts_valid_owned_buffer() {
        let buf = reference_bytes();
        let rk = RkVec::<ArchivedExample>::from_buf::<Error>(buf).unwrap();
        assert_eq!(rk.as_ref().value.to_native(), sample().value);
    }

    #[test]
    fn from_buf_accepts_valid_borrowed_buffer() {
        let buf = reference_bytes();
        let rk = RkRef::<ArchivedExample>::from_buf::<Error>(&buf).unwrap();
        assert_eq!(rk.as_ref().name.as_str(), sample().name);
    }

    #[test]
    fn from_buf_rejects_garbage() {
        let garbage = vec![0xffu8; 4];
        let res = RkVec::<ArchivedExample>::from_buf::<Error>(garbage);
        assert!(res.is_err());
    }
}
