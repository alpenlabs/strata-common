//! Property testing macros and utilities for strata-codec.
//!
//! This crate provides macros to generate comprehensive property tests for types
//! that implement the `Codec` trait from strata-codec. The main export is the
//! `generate_codec_tests!` macro.

// Re-export dependencies for macro usage
pub use paste;
pub use proptest;
pub use strata_codec;

/// Generates property tests for a type that implements `Codec` using proptest.
///
/// This macro creates comprehensive property-based tests to verify that:
/// 1. Encoding then decoding produces the original value (round-trip property)
/// 2. The encoding is deterministic (same input always produces same output)
/// 3. Different inputs produce different encodings (when feasible)
///
/// # Requirements
///
/// The type must implement:
/// - `strata_codec::Codec` - for encoding/decoding
/// - `proptest::arbitrary::Arbitrary` - for generating test values
/// - `Debug + PartialEq` - for test assertions
///
/// # Example
/// ```rust,no_run
/// use strata_codec_tests::generate_codec_tests;
/// use strata_codec::{Codec, CodecError, Decoder, Encoder};
/// use proptest::prelude::*;
///
/// #[derive(Debug, Clone, PartialEq)]
/// struct MyType {
///     field: u32,
/// }
///
/// impl Codec for MyType {
///     fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
///         let field = u32::decode(dec)?;
///         Ok(MyType { field })
///     }
///
///     fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
///         self.field.encode(enc)
///     }
/// }
///
/// impl Arbitrary for MyType {
///     type Parameters = ();
///     type Strategy = BoxedStrategy<MyType>;
///
///     fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
///         any::<u32>().prop_map(|field| MyType { field }).boxed()
///     }
/// }
///
/// // Generate comprehensive property tests
/// generate_codec_tests!(MyType, "my_type");
/// ```
#[macro_export]
macro_rules! generate_codec_tests {
    ($type:ty, $name:expr) => {
        $crate::paste::paste! {
            mod [<proptest_ $name _codec>] {
                use super::*;
                use $crate::proptest::{prelude::{prop_assert_eq, prop_assert_ne, prop_assume}, proptest, strategy::Strategy};
                use $crate::strata_codec::{encode_to_vec, decode_buf_exact};

                $crate::proptest::proptest! {
                    #[test]
                    fn [<test_codec_roundtrip>](value in any::<$type>()) {
                        let encoded = encode_to_vec(&value).expect("test: encoding should succeed");
                        let decoded = decode_buf_exact::<$type>(&encoded).expect("test: decoding should succeed");
                        prop_assert_eq!(value, decoded);
                    }

                    #[test]
                    fn [<test_codec_deterministic>](value in any::<$type>()) {
                        let encoded1 = encode_to_vec(&value).expect("encoding should succeed");
                        let encoded2 = encode_to_vec(&value).expect("encoding should succeed");
                        prop_assert_eq!(encoded1, encoded2, "test: unexpected inequality");
                    }

                    #[test]
                    fn [<test_codec_different_inputs>](
                        value1 in any::<$type>(),
                        value2 in any::<$type>()
                    ) {
                        prop_assume!(value1 != value2);
                        let encoded1 = encode_to_vec(&value1).expect("test: encoding should succeed");
                        let encoded2 = encode_to_vec(&value2).expect("test: encoding should succeed");
                        prop_assert_ne!(encoded1, encoded2, "test: unexpected equality");
                    }
                }
            }
        }
    };
}
