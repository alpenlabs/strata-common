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
    /// This must be big-endian.
    ///
    /// # Panics
    ///
    /// If called with a slice that is not [`Self::WIDTH`] bytes.
    fn copy_into(&self, buf: &mut [u8]);

    /// Constructs an instance of the key by decoding from bytes.
    ///
    /// # Panics
    ///
    /// If called with a slice that is not [`Self::WIDTH`] bytes.
    fn copy_from(buf: &[u8]) -> Self;
}

/// General impl for all bytebufs since they're already of the right format.
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
    /// Decodes the array into an [`ArrayKey`] type of exactly the same width.
    ///
    /// Instantiating this with a key type whose width isn't `N` MUST fail to
    /// compile.
    fn into_key<K: ArrayKey>(self) -> K;
}

/// Impl for `[u8; N]` arrays that provides the guarantees we expect.
impl<const N: usize> ArrayKeyArr<N> for [u8; N] {
    fn into_key<K: ArrayKey>(self) -> K {
        // Ideally this would be a bound like `K: ArrayKey<BYTES = { N }>`, but
        // that needs `associated_const_equality`, which isn't stable.  An
        // inline const inherits the generics of the fn it's in, so we can check
        // the same thing here, just at monomorphization time instead of when
        // typechecking the call.
        assert_key_width_eq::<N, K>();
        K::copy_from(&self)
    }
}

/// Fails to compile if `K` is not exactly `N` bytes wide.
///
/// This is a post-monomorphization error, so it only fires where this is
/// actually instantiated.  That's every real call, but it does mean a bad
/// instantiation sitting in generic code that's never called goes unreported.
#[inline(always)]
fn assert_key_width_eq<const N: usize, K: ArrayKey>() {
    const {
        assert!(
            N == K::BYTES,
            "arraykey: array length does not match key width"
        )
    };
}

/// Declares an [`ArrayKey`] impl for a tuple of the arity implied by the number
/// of type parameter names passed to it.
///
/// The fields are laid out in the buffer in order, each taking up as many bytes
/// as its own impl says it does.
macro_rules! decl_array_key_tuple_impl {
    ($($ty:ident),+ $(,)?) => {
        // The type param names are also reused as value bindings, which is what
        // the lint allowance is for.
        #[allow(non_snake_case)]
        impl<$($ty: ArrayKey),+> ArrayKey for ($($ty,)+) {
            const BYTES: usize = 0 $(+ <$ty as ArrayKey>::BYTES)+;

            fn copy_into(&self, buf: &mut [u8]) {
                assert_buf_len_eq::<Self>(buf);
                let ($($ty,)+) = self;
                let mut rest = buf;
                $(
                    let (cur, next) = core::mem::take(&mut rest)
                        .split_at_mut(<$ty as ArrayKey>::BYTES);
                    $ty.copy_into(cur);
                    rest = next;
                )+
                debug_assert!(rest.is_empty());
            }

            fn copy_from(buf: &[u8]) -> Self {
                assert_buf_len_eq::<Self>(buf);
                let mut rest = buf;
                $(
                    let (cur, next) = rest.split_at(<$ty as ArrayKey>::BYTES);
                    let $ty = <$ty as ArrayKey>::copy_from(cur);
                    rest = next;
                )+
                debug_assert!(rest.is_empty());
                ($($ty,)+)
            }
        }
    };
}

decl_array_key_tuple_impl!(A, B);
decl_array_key_tuple_impl!(A, B, C);
decl_array_key_tuple_impl!(A, B, C, D);
decl_array_key_tuple_impl!(A, B, C, D, E);
decl_array_key_tuple_impl!(A, B, C, D, E, F);

/// Declares an [`ArrayKey`] impl for an integer type, encoding it big-endian.
macro_rules! decl_array_key_int_impl {
    ($ty:ty) => {
        impl ArrayKey for $ty {
            const BYTES: usize = core::mem::size_of::<$ty>();

            fn copy_into(&self, buf: &mut [u8]) {
                assert_buf_len_eq::<Self>(buf);
                buf.copy_from_slice(&<$ty>::to_be_bytes(*self)[..]);
            }

            fn copy_from(buf: &[u8]) -> Self {
                assert_buf_len_eq::<Self>(buf);
                <$ty>::from_be_bytes(buf.try_into().unwrap())
            }
        }
    };
}

decl_array_key_int_impl!(u8);
decl_array_key_int_impl!(u16);
decl_array_key_int_impl!(u32);
decl_array_key_int_impl!(u64);
decl_array_key_int_impl!(u128);

decl_array_key_int_impl!(i8);
decl_array_key_int_impl!(i16);
decl_array_key_int_impl!(i32);
decl_array_key_int_impl!(i64);
decl_array_key_int_impl!(i128);

/// Declares an [`ArrayKey`] impl for a newtype wrapping another key type,
/// giving it exactly the same encoding as the type it wraps.
///
/// This must be a newtype a la `struct Foo(Bar);`.
macro_rules! decl_array_key_wrapper_impl {
    ($ty:ty => $inner:ty) => {
        impl $crate::ArrayKey for $ty {
            const BYTES: usize = <$inner as $crate::ArrayKey>::BYTES;

            fn copy_into(&self, buf: &mut [u8]) {
                <$inner as $crate::ArrayKey>::copy_into(&self.0, buf);
            }

            fn copy_from(buf: &[u8]) -> Self {
                Self(<$inner as $crate::ArrayKey>::copy_from(buf))
            }
        }
    };
}

/// Declares an [`ArrayKey`] impl for a struct with named fields, encoding the
/// fields in the order they're listed in.
///
/// Since each field is encoded big-endian with no padding, the byte ordering of
/// the key matches the ordering of the fields as listed, which is usually what
/// we want out of a composite database key.
macro_rules! decl_array_key_struct_impl {
    ($ty:ty, [$($field:ident: $field_ty:ty),+ $(,)?]) => {
        impl $crate::ArrayKey for $ty {
            const BYTES: usize = 0 $(+ <$field_ty as $crate::ArrayKey>::BYTES)+;

            fn copy_into(&self, buf: &mut [u8]) {
                $crate::key_types::assert_buf_len_eq::<Self>(buf);
                let mut rest = buf;
                $(
                    let (cur, next) = core::mem::take(&mut rest)
                        .split_at_mut(<$field_ty as $crate::ArrayKey>::BYTES);
                    <$field_ty as $crate::ArrayKey>::copy_into(&self.$field, cur);
                    rest = next;
                )+
                debug_assert!(rest.is_empty());
            }

            fn copy_from(buf: &[u8]) -> Self {
                $crate::key_types::assert_buf_len_eq::<Self>(buf);
                let mut rest = buf;
                $(
                    let (cur, next) = rest.split_at(<$field_ty as $crate::ArrayKey>::BYTES);
                    let $field = <$field_ty as $crate::ArrayKey>::copy_from(cur);
                    rest = next;
                )+
                debug_assert!(rest.is_empty());
                Self { $($field,)+ }
            }
        }
    };
}

pub(crate) use decl_array_key_struct_impl;
pub(crate) use decl_array_key_wrapper_impl;

#[inline(always)]
pub(crate) fn assert_buf_len_eq<K: ArrayKey>(arr: &[u8]) {
    #[cfg(debug_assertions)]
    {
        let len = arr.len();
        assert_eq!(
            arr.len(),
            K::BYTES,
            "arraykey: passed invalid array (exp {}, got {len})",
            K::BYTES
        );
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod tests {
    use arbitrary::{Arbitrary, Unstructured};

    use super::*;

    /// Number of instances we check per type.
    const ROUNDS: usize = 64;

    /// Encodes a key and decodes it again, checking we get the same value back
    /// and that we used exactly the number of bytes we said we would.
    fn check_roundtrip<K: ArrayKey + Eq + core::fmt::Debug>(k: K) -> Vec<u8> {
        let mut buf = vec![0u8; K::BYTES];
        k.copy_into(&mut buf);
        let dec = K::copy_from(&buf);
        assert_eq!(dec, k, "test: roundtrip mismatch (buf {buf:?})");
        buf
    }

    /// Generates a bunch of arbitrary instances of a key type and roundtrips
    /// each of them.
    fn check_roundtrips_arb<'a, K>(u: &mut Unstructured<'a>)
    where
        K: ArrayKey + Arbitrary<'a> + Eq + core::fmt::Debug,
    {
        for _ in 0..ROUNDS {
            let k = K::arbitrary(u).expect("test: generate key");
            check_roundtrip(k);
        }
    }

    /// Deterministic pseudorandom byte source so that failures are reproducible.
    fn gen_entropy(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn test_roundtrip_ints() {
        let ent = gen_entropy(0x1234, 16 * 1024);
        let u = &mut Unstructured::new(&ent);

        check_roundtrips_arb::<u8>(u);
        check_roundtrips_arb::<u16>(u);
        check_roundtrips_arb::<u32>(u);
        check_roundtrips_arb::<u64>(u);
        check_roundtrips_arb::<u128>(u);

        check_roundtrips_arb::<i8>(u);
        check_roundtrips_arb::<i16>(u);
        check_roundtrips_arb::<i32>(u);
        check_roundtrips_arb::<i64>(u);
        check_roundtrips_arb::<i128>(u);
    }

    #[test]
    fn test_roundtrip_arrays() {
        let ent = gen_entropy(0x5678, 16 * 1024);
        let u = &mut Unstructured::new(&ent);

        check_roundtrips_arb::<[u8; 0]>(u);
        check_roundtrips_arb::<[u8; 1]>(u);
        check_roundtrips_arb::<[u8; 4]>(u);
        check_roundtrips_arb::<[u8; 20]>(u);
        check_roundtrips_arb::<[u8; 32]>(u);
    }

    #[test]
    fn test_roundtrip_tuples() {
        let ent = gen_entropy(0x9abc, 64 * 1024);
        let u = &mut Unstructured::new(&ent);

        // Simple cases for each arity we declared impls for.
        check_roundtrips_arb::<(u32, [u8; 32])>(u);
        check_roundtrips_arb::<(u64, u32, [u8; 20])>(u);
        check_roundtrips_arb::<(u8, u16, u32, u64)>(u);
        check_roundtrips_arb::<(i8, u16, [u8; 3], u64, u128)>(u);
        check_roundtrips_arb::<(u8, u16, u32, u64, u128, [u8; 7])>(u);

        // Weirder cases, mostly to make sure composition and zero-width members
        // behave.
        check_roundtrips_arb::<([u8; 0], u32, [u8; 0])>(u);
        check_roundtrips_arb::<((u8, u16), (u32, u64))>(u);
        check_roundtrips_arb::<(u64, ([u8; 4], (i16, [u8; 0])), [u8; 1])>(u);
        check_roundtrips_arb::<((((u8, u8), u8), u8), u8)>(u);
    }

    /// Newtype to exercise `decl_array_key_wrapper_impl`.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Arbitrary)]
    struct TestWrapper([u8; 12]);

    decl_array_key_wrapper_impl!(TestWrapper => [u8; 12]);

    /// Struct to exercise `decl_array_key_struct_impl`, mixing widths and
    /// including a wrapper member.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Arbitrary)]
    struct TestStruct {
        idx: u32,
        pad: [u8; 0],
        id: TestWrapper,
        flag: u8,
    }

    decl_array_key_struct_impl!(
        TestStruct,
        [idx: u32, pad: [u8; 0], id: TestWrapper, flag: u8]
    );

    #[test]
    fn test_roundtrip_wrapper_and_struct() {
        let ent = gen_entropy(0xdef0, 16 * 1024);
        let u = &mut Unstructured::new(&ent);

        check_roundtrips_arb::<TestWrapper>(u);
        check_roundtrips_arb::<TestStruct>(u);

        // They compose with the other impls like anything else.
        check_roundtrips_arb::<(TestWrapper, u64)>(u);
        check_roundtrips_arb::<(TestStruct, [u8; 3])>(u);
    }

    #[test]
    fn test_wrapper_and_struct_layout() {
        assert_eq!(TestWrapper::BYTES, 12);
        assert_eq!(TestStruct::BYTES, 17);

        // A wrapper encodes exactly like the value it wraps.
        let inner = [0x11u8; 12];
        assert_eq!(
            check_roundtrip(TestWrapper(inner)),
            check_roundtrip(inner),
            "wrapper should not change the encoding"
        );

        // A struct encodes exactly like a tuple of its fields, in order.
        let s = TestStruct {
            idx: 0x01020304,
            pad: [],
            id: TestWrapper(inner),
            flag: 0xff,
        };
        assert_eq!(
            check_roundtrip(s),
            check_roundtrip((s.idx, s.pad, s.id, s.flag)),
            "struct should encode as its fields in order"
        );
    }

    #[test]
    fn test_into_key_from_arr() {
        // Arrays are their own key type, so this is just a passthrough.
        assert_eq!([1u8, 2, 3, 4].into_key::<[u8; 4]>(), [1, 2, 3, 4]);
        assert_eq!([].into_key::<[u8; 0]>(), [0u8; 0]);

        // Ints decode big-endian, matching `copy_from`.
        assert_eq!([0x01u8, 0x02, 0x03, 0x04].into_key::<u32>(), 0x01020304);
        assert_eq!([0xffu8].into_key::<i8>(), -1);

        // Composites work too, which is the case a length marker trait
        // couldn't have covered.
        let (a, b) = [0x01u8, 0x02, 0x03, 0x04, 0x05].into_key::<(u8, u32)>();
        assert_eq!((a, b), (0x01, 0x02030405));

        let w = [0x11u8; 12].into_key::<TestWrapper>();
        assert_eq!(w, TestWrapper([0x11; 12]));

        // ...and it agrees with going through `copy_from` directly.
        let buf = [0xa5u8; 17];
        assert_eq!(buf.into_key::<TestStruct>(), TestStruct::copy_from(&buf));
    }

    #[test]
    fn test_bytes_widths() {
        assert_eq!(<(u32, [u8; 32])>::BYTES, 36);
        assert_eq!(<([u8; 0], u32, [u8; 0])>::BYTES, 4);
        assert_eq!(<(u8, u16, u32, u64, u128, [u8; 7])>::BYTES, 38);
        assert_eq!(<(u64, ([u8; 4], (i16, [u8; 0])), [u8; 1])>::BYTES, 15);
    }

    #[test]
    fn test_layout_is_flat_be_concat() {
        // Members are laid out in order, big-endian, with no padding.
        let buf = check_roundtrip((0x01u8, 0x0203u16, [0x04u8, 0x05]));
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04, 0x05]);

        // ...so nesting doesn't change the encoding, only the type.
        let nested = check_roundtrip((0x01u8, (0x0203u16, [0x04u8, 0x05])));
        assert_eq!(nested, buf);
    }
}
