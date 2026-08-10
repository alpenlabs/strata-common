//! Macros for declaring [`ArrayKey`] impls, along with the impls we declare
//! with them for the primitive types.

use super::traits::{ArrayKey, assert_buf_len_eq};

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
                $crate::array_keys::assert_buf_len_eq::<Self>(buf);
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
                $crate::array_keys::assert_buf_len_eq::<Self>(buf);
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::array_keys::traits::ArrayKeyArr;

    /// Encodes a key and decodes it again, checking we get the same value back
    /// and that we used exactly the number of bytes we said we would.
    fn check_roundtrip<K: ArrayKey + Eq + core::fmt::Debug>(k: K) -> Vec<u8> {
        let mut buf = vec![0u8; K::BYTES];
        k.copy_into(&mut buf);
        let dec = K::copy_from(&buf);
        assert_eq!(dec, k, "test: roundtrip mismatch (buf {buf:?})");
        buf
    }

    /// Newtype to exercise `decl_array_key_wrapper_impl`.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    struct TestWrapper([u8; 12]);

    decl_array_key_wrapper_impl!(TestWrapper => [u8; 12]);

    fn arb_test_wrapper() -> impl Strategy<Value = TestWrapper> {
        any::<[u8; 12]>().prop_map(TestWrapper)
    }

    /// Struct to exercise `decl_array_key_struct_impl`, mixing widths and
    /// including a wrapper member.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

    fn arb_test_struct() -> impl Strategy<Value = TestStruct> {
        (
            any::<u32>(),
            any::<[u8; 0]>(),
            arb_test_wrapper(),
            any::<u8>(),
        )
            .prop_map(|(idx, pad, id, flag)| TestStruct { idx, pad, id, flag })
    }

    proptest! {
        #[test]
        fn test_roundtrip_ints(a in any::<u8>(), b in any::<u16>(), c in any::<u32>(), d in any::<u64>(), e in any::<u128>()) {
            check_roundtrip(a);
            check_roundtrip(b);
            check_roundtrip(c);
            check_roundtrip(d);
            check_roundtrip(e);
        }

        #[test]
        fn test_roundtrip_arrays(a0 in any::<[u8; 0]>(), a1 in any::<[u8; 1]>(), a4 in any::<[u8; 4]>(), a20 in any::<[u8; 20]>(), a32 in any::<[u8; 32]>()) {
            check_roundtrip(a0);
            check_roundtrip(a1);
            check_roundtrip(a4);
            check_roundtrip(a20);
            check_roundtrip(a32);
        }

        #[test]
        fn test_roundtrip_tuples(
            t1 in any::<(u32, [u8; 32])>(),
            t2 in any::<(u64, u32, [u8; 20])>(),
            t3 in any::<(u8, u16, u32, u64)>(),
            t4 in any::<(u8, u16, [u8; 3], u64, u128)>(),
            t5 in any::<(u8, u16, u32, u64, u128, [u8; 7])>(),
            // Weirder cases, mostly to make sure composition and zero-width
            // members behave.
            t6 in any::<([u8; 0], u32, [u8; 0])>(),
            t7 in any::<((u8, u16), (u32, u64))>(),
            t8 in any::<(u64, ([u8; 4], (u16, [u8; 0])), [u8; 1])>(),
            t9 in any::<((((u8, u8), u8), u8), u8)>(),
        ) {
            check_roundtrip(t1);
            check_roundtrip(t2);
            check_roundtrip(t3);
            check_roundtrip(t4);
            check_roundtrip(t5);
            check_roundtrip(t6);
            check_roundtrip(t7);
            check_roundtrip(t8);
            check_roundtrip(t9);
        }

        #[test]
        fn test_roundtrip_wrapper_and_struct(
            w in arb_test_wrapper(),
            s in arb_test_struct(),
            wt in (arb_test_wrapper(), any::<u64>()),
            st in (arb_test_struct(), any::<[u8; 3]>()),
        ) {
            check_roundtrip(w);
            check_roundtrip(s);

            // They compose with the other impls like anything else.
            check_roundtrip(wt);
            check_roundtrip(st);
        }
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
        assert_eq!([0xffu8].into_key::<u8>(), 0xff);

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
        assert_eq!(<(u64, ([u8; 4], (u16, [u8; 0])), [u8; 1])>::BYTES, 15);
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
