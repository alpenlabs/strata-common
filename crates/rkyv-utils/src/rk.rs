//! [`Rk`] wrapper type.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
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
/// `rkyv`-decodable value.  Implements `Eq`, `PartialEq`, `Ord`, `PartialOrd`,
/// and `Hash` according to the underlying values, not the backing buffers.
///
/// This means we can freely return a pointer to the value as its [`Archived`]
/// form.
///
/// This is meant to be pronounced "arc", but more acutely than how you'd
/// pronounce `Arc`, so that it's easy to tell the difference.
pub struct Rk<B: AsRef<[u8]>, T: Portable>(B, PhantomData<T>);

// `Copy`/`Clone` are bounded only on the backing buffer `B`, never on the
// archived type `T` (which lives only in `PhantomData` and is frequently not
// `Clone`, e.g. `ArchivedString`).  A `#[derive]` would wrongly add a `T: Clone`
// bound.  This is what lets, say, an `Rk<Arc<[u8]>, _>` clone by simply bumping
// the `Arc` refcount.
impl<B: AsRef<[u8]> + Copy, T: Portable> Copy for Rk<B, T> {}

impl<B: AsRef<[u8]> + Clone, T: Portable> Clone for Rk<B, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<B: AsRef<[u8]>, T: Portable> Rk<B, T> {
    /// Constructs a new instance without checking.
    ///
    /// This is equivalent to calling [`rkyv::access_unchecked`] without
    /// checking, so has the same safety guarantees.
    pub unsafe fn new_unchecked(buf: B) -> Self {
        Self(buf, PhantomData)
    }

    /// Validates that the buffer contains a valid instance of `T::Archived` and
    /// returns itself wrapping the underlying buffer.
    pub fn from_buf<E: Source>(buf: B) -> Result<Self, E>
    where
        T: for<'a> CheckBytes<HighValidator<'a, E>>,
    {
        rkyv::access::<T, E>(buf.as_ref())?;
        // SAFETY: we just checked it
        Ok(unsafe { Self::new_unchecked(buf) })
    }

    /// Exposes the backing buffer natively.
    pub fn inner(&self) -> &B {
        &self.0
    }

    /// Unwraps the [`Rk`] and returns the backing buffer natively.
    pub fn into_inner(self) -> B {
        self.0
    }

    /// Returns the underlying buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Copies the underlying buffer to a newly-allocated owned buffer.
    pub fn to_rkbox(&self) -> RkBox<T> {
        // SAFETY: buffer is known to be valid already
        unsafe { RkBox::new_unchecked(Box::from(self.as_slice())) }
    }

    /// Borrows the underlying buffer as a lifetime-bound [`RkRef`].
    ///
    /// This is `O(1)`: it just wraps a borrow of the existing bytes without
    /// copying or re-validating them.
    pub fn as_rkref(&self) -> RkRef<'_, T> {
        // SAFETY: buffer is known to be valid already
        unsafe { RkRef::new_unchecked(self.as_slice()) }
    }
}

impl<B: AsRef<[u8]>, T: Portable> AsRef<T> for Rk<B, T> {
    fn as_ref(&self) -> &T {
        // SAFETY: we already checked it in all constructors
        unsafe { rkyv::access_unchecked(self.as_slice()) }
    }
}

/// Compares the archived values, regardless of the buffer types backing them.
impl<B1, B2, T> PartialEq<Rk<B2, T>> for Rk<B1, T>
where
    B1: AsRef<[u8]>,
    B2: AsRef<[u8]>,
    T: Portable + PartialEq,
{
    fn eq(&self, other: &Rk<B2, T>) -> bool {
        AsRef::<T>::as_ref(self) == AsRef::<T>::as_ref(other)
    }
}

impl<B: AsRef<[u8]>, T: Portable + Eq> Eq for Rk<B, T> {}

/// Orders by the archived values, regardless of the buffer types backing them.
impl<B1, B2, T> PartialOrd<Rk<B2, T>> for Rk<B1, T>
where
    B1: AsRef<[u8]>,
    B2: AsRef<[u8]>,
    T: Portable + PartialOrd,
{
    fn partial_cmp(&self, other: &Rk<B2, T>) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.as_ref(), other.as_ref())
    }
}

impl<B: AsRef<[u8]>, T: Portable + Ord> Ord for Rk<B, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(self.as_ref(), other.as_ref())
    }
}

/// Formats the archived value, ignoring the buffer type backing it.
impl<B: AsRef<[u8]>, T: Portable + fmt::Debug> fmt::Debug for Rk<B, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), f)
    }
}

/// Formats the archived value, ignoring the buffer type backing it.
impl<B: AsRef<[u8]>, T: Portable + fmt::Display> fmt::Display for Rk<B, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), f)
    }
}

/// Hashes the archived value, regardless of the buffer type backing it.
impl<B: AsRef<[u8]>, T: Portable + Hash> Hash for Rk<B, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        AsRef::<T>::as_ref(self).hash(state);
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
        // SAFETY: we just encoded it validly
        unsafe { Self::new_unchecked(buf.into_vec()) }
    }

    /// Converts the [`RkVec`] into an [`RkBox`].
    pub fn into_rkbox(self) -> RkBox<T> {
        // SAFETY: buffer is known to be valid already
        unsafe { RkBox::new_unchecked(self.into_inner().into_boxed_slice()) }
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
    use std::hash::{Hash, Hasher};

    use rkyv::rancor::Error;
    use rkyv::{Archive, Deserialize, Serialize};

    use super::{Rk, RkBox, RkRef, RkVec};

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
    fn as_rkref_borrows_same_bytes() {
        let owned = RkVec::<ArchivedExample>::from_val(&sample());
        let borrowed = owned.as_rkref();

        // Shares the exact same backing bytes (same pointer), no copy.
        assert_eq!(borrowed.as_slice().as_ptr(), owned.as_slice().as_ptr());
        assert_eq!(borrowed.as_slice(), owned.as_slice());

        // Archived view is accessible through the borrowed handle.
        assert_eq!(borrowed.as_ref().value.to_native(), sample().value);
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
    fn clone_shares_arc_backing_buffer() {
        use std::sync::Arc;

        // Back an `Rk` with a refcounted `Arc<[u8]>` buffer holding a nontrivial
        // archived value (a `String`, a `u64`, and a `Vec<String>`).
        let val = keyed("alpha", 7, &["x", "y", "z"]);
        let bytes = rkyv::to_bytes::<Error>(&val).unwrap().into_vec();
        let arc: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
        assert_eq!(Arc::strong_count(&arc), 1);

        let rk = Rk::<Arc<[u8]>, ArchivedKeyed>::from_buf::<Error>(arc).unwrap();
        // The `Rk` now holds the sole strong reference.
        assert_eq!(Arc::strong_count(rk.inner()), 1);

        // Cloning the `Rk` should just bump the `Arc` refcount, not copy the
        // backing bytes.
        let cloned = rk.clone();
        assert_eq!(Arc::strong_count(rk.inner()), 2);
        assert_eq!(Arc::strong_count(cloned.inner()), 2);

        // Both handles point at the exact same buffer (no copy happened).
        assert_eq!(rk.as_slice().as_ptr(), cloned.as_slice().as_ptr());

        // ...and both still resolve to the original archived value.
        assert_eq!(rk.as_ref().label.as_str(), "alpha");
        assert_eq!(rk.as_ref(), cloned.as_ref());
        assert_eq!(cloned.as_ref().id.to_native(), 7);

        // Dropping one clone returns the count to a single strong reference.
        drop(cloned);
        assert_eq!(Arc::strong_count(rk.inner()), 1);
    }

    #[test]
    fn from_buf_rejects_garbage() {
        let garbage = vec![0xffu8; 4];
        let res = RkVec::<ArchivedExample>::from_buf::<Error>(garbage);
        assert!(res.is_err());
    }

    #[test]
    fn debug_and_display_pass_through_to_archived() {
        // Debug delegates to the archived struct (which derives `Debug`).
        let rk = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 7, &["x"]));
        let dbg = format!("{rk:?}");
        assert!(dbg.contains("alpha"), "got {dbg:?}");
        assert!(dbg.contains('7'), "got {dbg:?}");

        // Display delegates to the archived primitive's own `Display`.
        let num = RkVec::<rkyv::Archived<u64>>::from_val(&31415926u64);
        assert_eq!(format!("{num}"), "31415926");
        assert_eq!(format!("{num:?}"), format!("{:?}", 31415926u64));
    }

    #[derive(Archive, Serialize, Deserialize, Debug)]
    #[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
    struct Keyed {
        label: String,
        id: u64,
        tags: Vec<String>,
    }

    fn keyed(label: &str, id: u64, tags: &[&str]) -> Keyed {
        Keyed {
            label: label.to_owned(),
            id,
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn eq_compares_archived_values() {
        let a = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 7, &["x", "y"]));
        let a2 = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 7, &["x", "y"]));
        let b = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 7, &["x", "z"]));

        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn ord_compares_archived_values() {
        // Lexicographic by field order: `label`, then `id`, then `tags`.
        let a = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 2, &[]));
        let b = RkVec::<ArchivedKeyed>::from_val(&keyed("beta", 1, &[]));

        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Less);

        let mut v = vec![
            RkVec::<ArchivedKeyed>::from_val(&keyed("gamma", 1, &[])),
            RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 9, &[])),
            RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 1, &[])),
        ];
        v.sort();
        let sorted: Vec<(String, u64)> = v
            .iter()
            .map(|rk| {
                let a = rk.as_ref();
                (a.label.as_str().to_owned(), a.id.to_native())
            })
            .collect();
        assert_eq!(
            sorted,
            [
                ("alpha".to_owned(), 1),
                ("alpha".to_owned(), 9),
                ("gamma".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn hash_matches_for_equal_archived_values() {
        use std::collections::HashSet;

        let as_vec = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]));
        let as_box = RkBox::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]));
        let other = RkVec::<ArchivedKeyed>::from_val(&keyed("beta", 5, &["t"]));

        // Equal archived values hash equally, even across buffer types.
        let mut set: HashSet<RkVec<ArchivedKeyed>> = HashSet::new();
        assert!(set.insert(as_vec));
        assert!(!set.insert(RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]))));
        assert!(set.insert(other));

        fn hash(rk: &impl Hash) -> u64 {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            rk.hash(&mut h);
            h.finish()
        }
        let in_vec = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]));
        assert_eq!(hash(&in_vec), hash(&as_box));
    }

    #[test]
    fn from_buf_validates_at_varying_offsets() {
        // A nontrivial archived value: a string, a wide integer, and a list.
        let val = keyed("alpha", 0xDEAD_BEEF_CAFE_F00D, &["one", "two", "three"]);
        let encoded = rkyv::to_bytes::<Error>(&val).unwrap().into_vec();

        // Reference instance every offset is compared against.
        let reference = RkVec::<ArchivedKeyed>::from_val(&val);

        // Place the archive at a range of offsets inside a larger buffer (padded
        // with filler bytes), so it starts at a variety of mostly-unaligned
        // addresses.  With the `unaligned` format each one must validate and
        // resolve to the same value regardless of alignment.
        for offset in 0..16 {
            let mut buf = vec![0xA5u8; offset];
            buf.extend_from_slice(&encoded);

            let rk = RkRef::<ArchivedKeyed>::from_buf::<Error>(&buf[offset..])
                .unwrap_or_else(|e: Error| panic!("offset {offset} failed to validate: {e}"));

            // Matches the reference archived value regardless of offset.
            assert_eq!(rk, reference.as_rkref(), "mismatch at offset {offset}");

            // ...and fully deserializes back to the original.
            let de = rkyv::deserialize::<Keyed, Error>(rk.as_ref()).unwrap();
            assert_eq!(de.label, val.label, "offset {offset}");
            assert_eq!(de.id, val.id, "offset {offset}");
            assert_eq!(de.tags, val.tags, "offset {offset}");
        }
    }

    #[test]
    fn compares_across_buffer_types() {
        let as_vec = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]));
        let as_box = RkBox::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]));
        let bigger_box = RkBox::<ArchivedKeyed>::from_val(&keyed("alpha", 6, &["t"]));

        assert_eq!(as_vec, as_box);
        assert!(as_vec < bigger_box);
        assert_eq!(
            as_vec.partial_cmp(&bigger_box),
            Some(std::cmp::Ordering::Less)
        );
    }
}
