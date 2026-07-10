//! [`Rk`] wrapper type.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use rkyv::api::high::{HighSerializer, HighValidator, to_bytes_in};
use rkyv::bytecheck::CheckBytes;
use rkyv::rancor::{Error, Source};
use rkyv::ser::allocator::ArenaHandle;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Portable, Serialize};

use crate::raw_vec::{RawRkVec, SerVec, into_raw_buf, raw_from_slice, ser_buf_into_raw};

/// A [`RawRkVec`] containing a valid [`Archived`] instance of `T`.
///
/// The backing buffer type adapts to the alignment mode (see [`RawRkVec`]), so
/// [`from_val`](RkVec::from_val) is always sound and infallible.
pub type RkVec<T> = Rk<RawRkVec, T>;

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
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `buf` contains a valid archived `T` *and*
    /// that its base pointer is aligned to `align_of::<T>()` (trivially true
    /// under the `unaligned` feature, where that alignment is 1).  Both are
    /// required for the [`AsRef<T>`](Rk::as_ref) accessor — which calls
    /// [`rkyv::access_unchecked`] — to be sound.
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

    /// Copies the underlying buffer to a newly-allocated, owned [`RkVec`].
    ///
    /// This is the owned-copy path that is sound under both alignment modes: the
    /// fresh [`RawRkVec`] carries whatever alignment the active mode requires
    /// (16-aligned [`AlignedVec`] under `aligned`, plain `Vec<u8>` under
    /// `unaligned`).
    pub fn to_rkvec(&self) -> RkVec<T> {
        // SAFETY: the bytes are a copy of an already-valid archive, and
        // `raw_from_slice` produces a buffer with the required alignment.
        unsafe { RkVec::new_unchecked(raw_from_slice(self.as_slice())) }
    }

    /// Borrows the underlying buffer as a lifetime-bound [`RkRef`].
    ///
    /// This is `O(1)`: it just wraps a borrow of the existing bytes without
    /// copying or re-validating them.
    pub fn as_rkref(&self) -> RkRef<'_, T> {
        // SAFETY: buffer is known to be valid already
        unsafe { RkRef::new_unchecked(self.as_slice()) }
    }

    /// Borrows a sub-value `U` that lives *inside* this archive as an independent
    /// [`RkRef`], backed by a subslice of this buffer.
    ///
    /// `field` must be a reference into this archive — typically obtained by
    /// traversing [`as_ref`](Rk::as_ref), e.g.
    /// `rk.as_rkref_of(&rk.as_ref().some_field)`.  The returned handle borrows
    /// `self` and resolves to the same bytes `field` already pointed at, with no
    /// copy or re-serialization.
    ///
    /// The projected subslice runs from the *start* of the buffer up to the end
    /// of `field`, rather than just `field`'s own bytes.  That whole prefix is
    /// required: rkyv stores a value's out-of-line data (a `String`'s
    /// characters, a `Vec`'s elements) at *lower* addresses than the value that
    /// points at it, and the archived value's relative pointers — offsets from
    /// their own address — must still resolve.  Keeping the prefix preserves
    /// both those targets and the field's alignment, so this works for any
    /// field (primitive, `String`, `Vec`, nested struct) and composes
    /// recursively.
    ///
    /// This validates the projected subslice (via [`from_buf`](Rk::from_buf)), so
    /// a `field` that does not point within this buffer is reported as an `Err`
    /// rather than causing undefined behavior.  For the unchecked, allocation-
    /// and validation-free counterpart see
    /// [`as_rkref_of_unchecked`](Rk::as_rkref_of_unchecked).
    pub fn as_rkref_of<U, E>(&self, field: &U) -> Result<RkRef<'_, U>, E>
    where
        U: Portable + for<'a> CheckBytes<HighValidator<'a, E>>,
        E: Source,
    {
        let buf = self.as_slice();
        let end = projected_prefix_len::<U, E>(buf, field)?;
        RkRef::<U>::from_buf::<E>(&buf[..end])
    }

    /// Borrows a sub-value `U` inside this archive as an [`RkRef`] without any
    /// validation — the unchecked counterpart of
    /// [`as_rkref_of`](Rk::as_rkref_of).
    ///
    /// # Safety
    ///
    /// `field` must be a reference obtained by traversing
    /// [`as_ref`](Rk::as_ref) (i.e. it genuinely points at an archived `U`
    /// inside this buffer).  Then the prefix `&buf[..off + size_of::<U>()]` is a
    /// valid archive of `U` whose root sits at the end, so the resulting
    /// handle's [`AsRef<U>`](Rk::as_ref) accessor — which calls
    /// [`rkyv::access_unchecked`] — is sound.
    pub unsafe fn as_rkref_of_unchecked<U: Portable>(&self, field: &U) -> RkRef<'_, U> {
        let buf = self.as_slice();
        let off = (field as *const U as usize) - (buf.as_ptr() as usize);
        let end = off + core::mem::size_of::<U>();
        // SAFETY: the caller guarantees `field` points at an archived `U` within
        // this buffer, so `end <= buf.len()` and the prefix is a valid archive of
        // `U` with its root at the end.
        unsafe { RkRef::new_unchecked(buf.get_unchecked(..end)) }
    }
}

impl<B: AsRef<[u8]>, T: Portable> AsRef<T> for Rk<B, T> {
    fn as_ref(&self) -> &T {
        // SAFETY: every *safe* constructor (`from_buf`, `RkVec::from_val`,
        // `from_aligned_vec`, `from_unaligned_buf`, `to_rkvec`, `as_rkref`)
        // guarantees both validity and alignment; the `unsafe` `new_unchecked`
        // pushes those obligations onto the caller.  So `access_unchecked` is
        // always sound.
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
    /// freshly-allocated [`RawRkVec`] and returns it as a [`RkVec`].
    ///
    /// This is sound and infallible in both modes, and never copies: the value
    /// is serialized straight into the [`RawRkVec`] backing.  Under `aligned`
    /// that is the [`AlignedVec`] the serializer produces anyway (alignment
    /// guaranteed); under `unaligned` it is serialized into an `AlignedVec<1>`
    /// whose allocation is moved into the `Vec<u8>` backing without copying (see
    /// [`SerVec`]).
    ///
    /// # Panics
    ///
    /// If serialization fails (which for the in-memory serializer only happens
    /// on allocation failure).
    pub fn from_val<S>(val: &S) -> Self
    where
        S: Archive<Archived = T>
            + for<'a> Serialize<HighSerializer<SerVec, ArenaHandle<'a>, Error>>,
    {
        let buf =
            to_bytes_in::<_, Error>(val, SerVec::new()).expect("rkyv-utils: serialization failed");
        // SAFETY: we just encoded it validly, and `ser_buf_into_raw` preserves
        // the alignment guarantee the active mode requires.
        unsafe { Self::new_unchecked(ser_buf_into_raw(buf)) }
    }

    /// Validates that an [`AlignedVec`] contains a valid archived `T` and wraps
    /// it as a [`RkVec`].
    ///
    /// Like [`from_buf`](Rk::from_buf) it runs full structural validation, but
    /// because the input is aligned to 16 it is *guaranteed never to return an
    /// alignment error* — any error is a structural/content one.  Under
    /// `unaligned` the buffer is copied down into the plain `Vec<u8>` backing.
    pub fn from_aligned_vec<E: Source>(buf: AlignedVec) -> Result<Self, E>
    where
        T: for<'a> CheckBytes<HighValidator<'a, E>>,
    {
        Self::from_buf(into_raw_buf(buf))
    }

    /// Copies arbitrary (possibly misaligned) bytes into a fresh [`RawRkVec`],
    /// validates them, and wraps the result.
    ///
    /// This is the explicit opt-in copy: unlike the borrowing/zero-copy
    /// constructors it always allocates, but in exchange it accepts any input
    /// buffer and is *guaranteed never to return an alignment error* in either
    /// mode.
    pub fn from_unaligned_buf<E: Source>(buf: impl AsRef<[u8]>) -> Result<Self, E>
    where
        T: for<'a> CheckBytes<HighValidator<'a, E>>,
    {
        Self::from_buf(raw_from_slice(buf.as_ref()))
    }
}

/// Error returned by [`as_rkref_of`](Rk::as_rkref_of) when `field` does not point
/// within the backing buffer.
#[derive(Debug)]
struct ProjectionOutOfBounds;

impl fmt::Display for ProjectionOutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rkyv-utils: projected reference is not within the backing buffer")
    }
}

impl std::error::Error for ProjectionOutOfBounds {}

/// Computes the length of the prefix subslice `&buf[..end]` that exposes `field`
/// as a root archived `U`, bounds-checking that `field` lies fully within `buf`.
///
/// The prefix ends at `field`'s last byte (`off + size_of::<U>()`) and begins at
/// the buffer start so that `field`'s relative pointers — which target lower
/// addresses — still resolve.  Returns an error (rather than a panic or UB) if
/// `field` starts before the buffer or extends past its end.
fn projected_prefix_len<U, E: Source>(buf: &[u8], field: &U) -> Result<usize, E> {
    let base = buf.as_ptr() as usize;
    let addr = field as *const U as usize;
    let off = addr
        .checked_sub(base)
        .ok_or_else(|| E::new(ProjectionOutOfBounds))?;
    let end = off
        .checked_add(core::mem::size_of::<U>())
        .ok_or_else(|| E::new(ProjectionOutOfBounds))?;
    if end > buf.len() {
        return Err(E::new(ProjectionOutOfBounds));
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use std::hash::{Hash, Hasher};
    use std::mem::align_of;

    use rkyv::rancor::Error;
    use rkyv::util::AlignedVec;
    use rkyv::{Archive, Deserialize, Serialize};

    use super::{Rk, RkBox, RkRef, RkVec};

    // --- fixtures ---

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

    /// A nontrivial value mixing a `String`, a wide integer, and a list, with the
    /// archived form deriving the comparison/hash traits the `Rk` impls delegate
    /// to.
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

    /// Builds a `Box<[u8]>`-backed [`RkBox`] from a [`Keyed`] value, for the
    /// cross-buffer-type tests.  Goes through `from_buf` (the only owned-`RkBox`
    /// constructor), so it works in both alignment modes.
    fn keyed_box(label: &str, id: u64, tags: &[&str]) -> RkBox<ArchivedKeyed> {
        let bytes = rkyv::to_bytes::<Error>(&keyed(label, id, tags))
            .unwrap()
            .into_vec()
            .into_boxed_slice();
        RkBox::<ArchivedKeyed>::from_buf::<Error>(bytes).unwrap()
    }

    /// Reference bytes produced directly by `rkyv`, used to cross-check the
    /// buffers our `encode` helpers produce.
    fn reference_bytes() -> Vec<u8> {
        rkyv::to_bytes::<Error>(&sample()).unwrap().into_vec()
    }

    // --- construction & round-trip ---

    #[test]
    fn from_val_matches_rkyv_aligned_and_roundtrips() {
        let val = sample();
        let rk = RkVec::<ArchivedExample>::from_val(&val);

        // Buffer is exactly what rkyv would produce.
        assert_eq!(rk.as_slice(), reference_bytes().as_slice());

        // The backing buffer always satisfies the archived type's alignment.
        assert_eq!(
            rk.as_slice().as_ptr() as usize % align_of::<ArchivedExample>(),
            0
        );

        // Archived view is accessible without re-validation.
        let archived = rk.as_ref();
        assert_eq!(archived.name.as_str(), val.name);
        assert_eq!(archived.value.to_native(), val.value);

        // Full deserialization roundtrips back to the original.
        let de = rkyv::deserialize::<Example, Error>(rk.as_ref()).unwrap();
        assert_eq!(de, val);
    }

    #[test]
    fn from_buf_accepts_valid_owned_buffer() {
        // `RkBox` keeps a fixed `Box<[u8]>` backing in both modes, so this
        // exercises `from_buf` on an owned buffer regardless of alignment mode.
        let buf: Box<[u8]> = reference_bytes().into_boxed_slice();
        let rk = RkBox::<ArchivedExample>::from_buf::<Error>(buf).unwrap();
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
        let garbage: Box<[u8]> = vec![0xffu8; 4].into_boxed_slice();
        let res = RkBox::<ArchivedExample>::from_buf::<Error>(garbage);
        assert!(res.is_err());
    }

    #[test]
    fn from_aligned_vec_validates_and_never_misaligns() {
        // Build an `AlignedVec` straight from rkyv's serializer.
        let val = keyed("beta", 7, &["x", "y", "z"]);
        let aligned: AlignedVec = rkyv::to_bytes::<Error>(&val).unwrap();

        let rk = RkVec::<ArchivedKeyed>::from_aligned_vec::<Error>(aligned).unwrap();
        assert_eq!(
            rk.as_slice().as_ptr() as usize % align_of::<ArchivedKeyed>(),
            0
        );
        assert_eq!(rk.as_ref().id.to_native(), 7);

        // Garbage still fails structural validation (but never on alignment).
        let mut garbage = AlignedVec::new();
        garbage.extend_from_slice(&[0xffu8; 8]);
        assert!(RkVec::<ArchivedKeyed>::from_aligned_vec::<Error>(garbage).is_err());
    }

    #[test]
    fn from_unaligned_buf_copies_validates_and_aligns() {
        let val = keyed("gamma", 99, &["q"]);
        let encoded = rkyv::to_bytes::<Error>(&val).unwrap().into_vec();

        // Feed a deliberately misaligned borrow (offset 1 into a padded buffer);
        // the copy into the mode's backing makes the result sound regardless.
        let mut padded = vec![0xA5u8];
        padded.extend_from_slice(&encoded);
        let misaligned = &padded[1..];

        let rk = RkVec::<ArchivedKeyed>::from_unaligned_buf::<Error>(misaligned).unwrap();
        assert_eq!(
            rk.as_slice().as_ptr() as usize % align_of::<ArchivedKeyed>(),
            0
        );

        let de = rkyv::deserialize::<Keyed, Error>(rk.as_ref()).unwrap();
        assert_eq!(de.label, val.label);
        assert_eq!(de.id, val.id);
        assert_eq!(de.tags, val.tags);
    }

    // --- borrowing & cheap handles ---

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

    // --- value semantics (delegate to the archived value) ---

    #[test]
    fn ord_compares_archived_values() {
        // Lexicographic by field order: `label`, then `id`, then `tags`.
        let a = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 2, &[]));
        let b = RkVec::<ArchivedKeyed>::from_val(&keyed("beta", 1, &[]));

        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Less);

        let mut v = [
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
        let as_box = keyed_box("alpha", 5, &["t"]);
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

    #[test]
    fn compares_across_buffer_types() {
        // Equality and ordering delegate to the archived value, regardless of
        // the (here, differing) backing buffer types.
        let as_vec = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 5, &["t"]));
        let as_box = keyed_box("alpha", 5, &["t"]);
        let bigger_vec = RkVec::<ArchivedKeyed>::from_val(&keyed("alpha", 6, &["t"]));

        // Equal archived values compare equal across buffer types...
        assert_eq!(as_vec, as_box);
        // ...and unequal ones compare unequal.
        assert_ne!(as_vec, bigger_vec);

        assert!(as_vec < bigger_vec);
        assert_eq!(
            as_vec.partial_cmp(&bigger_vec),
            Some(std::cmp::Ordering::Less)
        );
    }

    // --- alignment behavior ---

    #[test]
    fn from_buf_validates_at_varying_offsets() {
        // A nontrivial archived value: a string, a wide integer, and a list.
        let val = keyed("alpha", 0xDEAD_BEEF_CAFE_F00D, &["one", "two", "three"]);
        let encoded = rkyv::to_bytes::<Error>(&val).unwrap().into_vec();

        // Reference instance every offset is compared against.  `RkVec`'s
        // mode-adaptive backing keeps this infallible in both modes.
        let reference = RkVec::<ArchivedKeyed>::from_val(&val);

        // Place the archive at a range of offsets inside a larger buffer (padded
        // with filler bytes), so it starts at a variety of mostly-unaligned
        // addresses.  `from_buf` validates each one and — crucially — reports an
        // error (rather than UB or a panic) when the start address is not
        // aligned for the archived type.  Under the `unaligned` feature the
        // required alignment is 1 so every offset validates; under `aligned` only
        // the offsets whose address satisfies the alignment do.
        let required = align_of::<ArchivedKeyed>();
        for offset in 0..16 {
            let mut buf = vec![0xA5u8; offset];
            buf.extend_from_slice(&encoded);
            let slice = &buf[offset..];

            let is_aligned = (slice.as_ptr() as usize) & (required - 1) == 0;
            let res = RkRef::<ArchivedKeyed>::from_buf::<Error>(slice);

            if is_aligned {
                let rk = res.unwrap_or_else(|e: Error| {
                    panic!("offset {offset} (aligned) failed to validate: {e}")
                });

                // Matches the reference archived value regardless of offset.
                assert_eq!(rk, reference.as_rkref(), "mismatch at offset {offset}");

                // ...and fully deserializes back to the original.
                let de = rkyv::deserialize::<Keyed, Error>(rk.as_ref()).unwrap();
                assert_eq!(de.label, val.label, "offset {offset}");
                assert_eq!(de.id, val.id, "offset {offset}");
                assert_eq!(de.tags, val.tags, "offset {offset}");
            } else {
                // Misaligned start (only reachable under `aligned`): graceful
                // error, no panic or UB.
                assert!(
                    res.is_err(),
                    "offset {offset} is misaligned (required {required}) yet validated"
                );
            }
        }
    }

    // --- projection (`as_rkref_of`) ---

    /// Deeply nested fixture: an `Outer` owning a wide integer, a nested struct
    /// (itself holding a `String` and a `Vec`), and a `Vec<String>`.  Lets the
    /// projection tests reach sub-values at several levels, including ones whose
    /// archived form stores out-of-line data.
    #[derive(Archive, Serialize, Deserialize, Debug, PartialEq)]
    #[rkyv(derive(Debug, PartialEq))]
    struct Inner {
        tag: String,
        nums: Vec<u32>,
    }

    #[derive(Archive, Serialize, Deserialize, Debug, PartialEq)]
    #[rkyv(derive(Debug, PartialEq))]
    struct Outer {
        id: u64,
        inner: Inner,
        names: Vec<String>,
    }

    fn outer() -> Outer {
        Outer {
            id: 0xDEAD_BEEF_CAFE_F00D,
            inner: Inner {
                tag: "the-inner-tag".to_owned(),
                nums: vec![1, 1, 2, 3, 5, 8, 13],
            },
            names: vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()],
        }
    }

    #[test]
    fn project_primitive_field() {
        let val = outer();
        let rk = RkVec::<ArchivedOuter>::from_val(&val);

        let id_ref = &rk.as_ref().id;
        let id_rk = rk.as_rkref_of::<_, Error>(id_ref).unwrap();

        // Reads back the right value.
        assert_eq!(id_rk.as_ref().to_native(), val.id);

        // The projected subslice is the prefix ending exactly at the field's end
        // and shares the original buffer's base pointer.
        let base = rk.as_slice().as_ptr() as usize;
        let off = (id_ref as *const _ as usize) - base;
        assert_eq!(id_rk.as_slice().as_ptr(), rk.as_slice().as_ptr());
        assert_eq!(
            id_rk.as_slice().len(),
            off + std::mem::size_of::<rkyv::Archived<u64>>()
        );
    }

    #[test]
    fn project_string_field_with_out_of_line_data() {
        // The acid test for the *prefix* approach: a `String` field's characters
        // live before the field, so a naive tight subslice would slice them away
        // and reading the string would be UB / wrong.
        let val = outer();
        let rk = RkVec::<ArchivedOuter>::from_val(&val);

        let tag_ref = &rk.as_ref().inner.tag;
        let tag_rk = rk.as_rkref_of::<_, Error>(tag_ref).unwrap();

        assert_eq!(tag_rk.as_ref().as_str(), val.inner.tag);
        let de = rkyv::deserialize::<String, Error>(tag_rk.as_ref()).unwrap();
        assert_eq!(de, val.inner.tag);
    }

    #[test]
    fn project_vec_field() {
        let val = outer();
        let rk = RkVec::<ArchivedOuter>::from_val(&val);

        let names_rk = rk.as_rkref_of::<_, Error>(&rk.as_ref().names).unwrap();

        // Element-by-element match against the original.
        let archived = names_rk.as_ref();
        assert_eq!(archived.len(), val.names.len());
        for (a, b) in archived.iter().zip(&val.names) {
            assert_eq!(a.as_str(), b);
        }

        let de = rkyv::deserialize::<Vec<String>, Error>(names_rk.as_ref()).unwrap();
        assert_eq!(de, val.names);
    }

    #[test]
    fn project_nested_struct_field_and_cross_check() {
        let val = outer();
        let rk = RkVec::<ArchivedOuter>::from_val(&val);

        let inner_rk = rk.as_rkref_of::<_, Error>(&rk.as_ref().inner).unwrap();

        // Deserializing the projected nested struct matches the original whole.
        let de = rkyv::deserialize::<Inner, Error>(inner_rk.as_ref()).unwrap();
        assert_eq!(de, val.inner);
    }

    #[test]
    fn project_recursively() {
        // Projections compose: project to `inner`, then project again to a field
        // *of that projection* and confirm the (out-of-line) string still
        // resolves.
        let val = outer();
        let rk = RkVec::<ArchivedOuter>::from_val(&val);

        let inner_rk = rk.as_rkref_of::<_, Error>(&rk.as_ref().inner).unwrap();
        let tag_rk = inner_rk
            .as_rkref_of::<_, Error>(&inner_rk.as_ref().tag)
            .unwrap();
        assert_eq!(tag_rk.as_ref().as_str(), val.inner.tag);

        let nums_rk = inner_rk
            .as_rkref_of::<_, Error>(&inner_rk.as_ref().nums)
            .unwrap();
        let de = rkyv::deserialize::<Vec<u32>, Error>(nums_rk.as_ref()).unwrap();
        assert_eq!(de, val.inner.nums);
    }

    #[test]
    fn project_out_of_buffer_ref_errors() {
        let rk = RkVec::<ArchivedOuter>::from_val(&outer());

        // A reference to a value that does *not* live in `rk`'s buffer must be
        // reported as an error, not a panic or UB.
        let stray: rkyv::Archived<u64> = 7u64.into();
        let res = rk.as_rkref_of::<_, Error>(&stray);
        assert!(res.is_err());
    }

    #[test]
    fn project_unchecked_matches_checked() {
        let val = outer();
        let rk = RkVec::<ArchivedOuter>::from_val(&val);

        let checked = rk.as_rkref_of::<_, Error>(&rk.as_ref().inner).unwrap();
        // SAFETY: `&rk.as_ref().inner` genuinely points within `rk`'s archive.
        let unchecked = unsafe { rk.as_rkref_of_unchecked(&rk.as_ref().inner) };

        // Same backing bytes and same archived value.
        assert_eq!(unchecked.as_slice(), checked.as_slice());
        let de_a = rkyv::deserialize::<Inner, Error>(checked.as_ref()).unwrap();
        let de_b = rkyv::deserialize::<Inner, Error>(unchecked.as_ref()).unwrap();
        assert_eq!(de_a, de_b);
        assert_eq!(de_a, val.inner);
    }
}
