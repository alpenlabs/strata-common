//! Integration tests for basic codec types using proptest.

#![expect(missing_docs, reason = "test repo")]
#![expect(unused_crate_dependencies, reason = "macro hacks")]

use strata_codec_tests::{
    generate_codec_tests, proptest::prelude::*, strata_codec::impl_type_flat_struct,
};

// Test coordinate struct from the original examples
impl_type_flat_struct! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub struct Coordinate {
        x: i32,
        y: i32,
        theta: u16,
    }
}

impl Arbitrary for Coordinate {
    type Parameters = ();
    type Strategy = BoxedStrategy<Coordinate>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<i32>(), any::<i32>(), any::<u16>())
            .prop_map(|(x, y, theta)| Coordinate { x, y, theta })
            .boxed()
    }
}

// Generate property tests for the custom Coordinate struct
generate_codec_tests!(Coordinate, "coordinate");

// Generate property tests for built-in types
generate_codec_tests!(bool, "bool");
generate_codec_tests!(u8, "u8");
generate_codec_tests!(i8, "i8");
generate_codec_tests!(u16, "u16");
generate_codec_tests!(i16, "i16");
generate_codec_tests!(u32, "u32");
generate_codec_tests!(i32, "i32");
generate_codec_tests!(u64, "u64");
generate_codec_tests!(i64, "i64");

// Test array types of various sizes
generate_codec_tests!([u8; 1], "u8_array_1");
generate_codec_tests!([u8; 4], "u8_array_4");
generate_codec_tests!([u8; 32], "u8_array_32");
