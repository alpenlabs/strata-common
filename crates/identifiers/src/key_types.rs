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

#[inline(always)]
fn assert_buf_len_eq<K: ArrayKey>(arr: &[u8]) {
    #[cfg(debug_assertions)]
    {
        let len = arr.len();
        assert_eq!(
            arr.len(),
            K::BYTES,
            "dbkey: passed invalid array (exp {}, got {len})",
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
        assert_eq!(dec, k, "dbkey: roundtrip mismatch (buf {buf:?})");
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
