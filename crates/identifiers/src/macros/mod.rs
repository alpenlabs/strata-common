#[macro_use]
pub(crate) mod buf;
#[cfg(feature = "serde")]
#[macro_use]
pub(crate) mod serde_impl;
#[cfg(feature = "ssz")]
#[macro_use]
pub(crate) mod ssz;
#[macro_use]
mod wrapper;

#[cfg(test)]
mod tests {
    #[derive(PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[cfg_attr(feature = "codec", derive(strata_codec::Codec))]
    pub struct TestBuf20(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; 20]);

    crate::macros::buf::impl_buf_core!(TestBuf20, 20);
    crate::macros::buf::impl_buf_fmt!(TestBuf20, 20);

    #[test]
    fn test_from_into_array() {
        let buf = TestBuf20::new([5u8; 20]);
        let arr: [u8; 20] = buf.into();
        assert_eq!(arr, [5; 20]);
    }

    #[test]
    fn test_from_array_ref() {
        let arr = [2u8; 20];
        let buf: TestBuf20 = TestBuf20::from(&arr);
        assert_eq!(buf.as_slice(), &arr);
    }

    #[test]
    fn test_default() {
        let buf = TestBuf20::default();
        assert_eq!(buf.as_slice(), &[0; 20]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_hex() {
        let data = [1u8; 20];
        let buf = TestBuf20(data);
        let json = serde_json::to_string(&buf).unwrap();
        // Since we serialize as a string, json should be the hex-encoded string wrapped in quotes.
        let expected = format!("\"{}\"", hex::encode(data));
        assert_eq!(json, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize_hex_without_prefix() {
        let data = [2u8; 20];
        let hex_str = hex::encode(data);
        let json = format!("\"{hex_str}\"");
        let buf: TestBuf20 = serde_json::from_str(&json).unwrap();
        assert_eq!(buf, TestBuf20(data));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_bincode_roundtrip() {
        let data = [9u8; 20];
        let buf = TestBuf20(data);
        let encoded = bincode::serialize(&buf).expect("bincode serialization failed");
        let decoded: TestBuf20 =
            bincode::deserialize(&encoded).expect("bincode deserialization failed");
        assert_eq!(buf, decoded);
    }

    #[cfg(feature = "ssz")]
    mod ssz_wrapper_tests {
        use ssz::{Decode, Encode};
        use ssz_derive::{Decode, Encode};

        use crate::buf::Buf32;

        #[derive(Copy, Clone, Debug, Eq, PartialEq, Encode, Decode)]
        #[ssz(struct_behaviour = "transparent")]
        struct TestBuf32Wrapper(Buf32);

        crate::impl_ssz_transparent_wrapper!(TestBuf32Wrapper, Buf32);

        #[test]
        fn test_ssz_transparent_wrapper_roundtrip() {
            let data = [42u8; 32];
            let wrapper = TestBuf32Wrapper(Buf32::new(data));

            // Test SSZ encoding/decoding
            let encoded = wrapper.as_ssz_bytes();
            let decoded = TestBuf32Wrapper::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(wrapper, decoded);
        }

        #[test]
        fn test_ssz_transparent_wrapper_tree_hash() {
            use tree_hash::{Sha256Hasher, TreeHash};

            let data = [42u8; 32];
            let wrapper = TestBuf32Wrapper(Buf32::new(data));
            let inner = Buf32::new(data);

            // TreeHash should be the same as inner type (transparent)
            let wrapper_hash = TreeHash::tree_hash_root::<Sha256Hasher>(&wrapper);
            let inner_hash = TreeHash::tree_hash_root::<Sha256Hasher>(&inner);
            assert_eq!(wrapper_hash, inner_hash);
        }

        #[test]
        fn test_ssz_transparent_wrapper_to_owned() {
            use ssz_types::view::ToOwnedSsz;

            let data = [42u8; 32];
            let wrapper = TestBuf32Wrapper(Buf32::new(data));

            // ToOwnedSsz should return a copy
            let owned = ToOwnedSsz::to_owned(&wrapper);
            assert_eq!(wrapper, owned);
        }
    }
}
