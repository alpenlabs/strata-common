//! Integration tests for complex codec types using proptest.

#![expect(missing_docs, reason = "test repo")]
#![expect(unused_crate_dependencies, reason = "macro hacks")]

use strata_codec_tests::{
    generate_codec_tests,
    proptest::prelude::*,
    strata_codec::{Codec, impl_type_flat_struct},
};

// Example 1: Simple 3D point struct
impl_type_flat_struct! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct Point3D {
        x: i32,
        y: i32,
        z: i32,
    }
}

impl Arbitrary for Point3D {
    type Parameters = ();
    type Strategy = BoxedStrategy<Point3D>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<i32>(), any::<i32>(), any::<i32>())
            .prop_map(|(x, y, z)| Point3D { x, y, z })
            .boxed()
    }
}

// Generate comprehensive property tests for Point3D
generate_codec_tests!(Point3D, "point3d");

// Example 2: Enum with manual codec implementation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Color {
    Red,
    Green,
    Blue,
    Custom(u8, u8, u8),
}

impl Codec for Color {
    fn decode(
        dec: &mut impl strata_codec_tests::strata_codec::Decoder,
    ) -> Result<Self, strata_codec_tests::strata_codec::CodecError> {
        let variant = u8::decode(dec)?;
        match variant {
            0 => Ok(Color::Red),
            1 => Ok(Color::Green),
            2 => Ok(Color::Blue),
            3 => {
                let r = u8::decode(dec)?;
                let g = u8::decode(dec)?;
                let b = u8::decode(dec)?;
                Ok(Color::Custom(r, g, b))
            }
            _ => Err(strata_codec_tests::strata_codec::CodecError::InvalidVariant("Color")),
        }
    }

    fn encode(
        &self,
        enc: &mut impl strata_codec_tests::strata_codec::Encoder,
    ) -> Result<(), strata_codec_tests::strata_codec::CodecError> {
        match self {
            Color::Red => 0u8.encode(enc),
            Color::Green => 1u8.encode(enc),
            Color::Blue => 2u8.encode(enc),
            Color::Custom(r, g, b) => {
                3u8.encode(enc)?;
                r.encode(enc)?;
                g.encode(enc)?;
                b.encode(enc)
            }
        }
    }
}

impl Arbitrary for Color {
    type Parameters = ();
    type Strategy = BoxedStrategy<Color>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Color::Red),
            Just(Color::Green),
            Just(Color::Blue),
            (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(r, g, b)| Color::Custom(r, g, b)),
        ]
        .boxed()
    }
}

// Generate tests with custom name to avoid conflicts
generate_codec_tests!(Color, "color_enum");

// Example 3: Complex nested structure
impl_type_flat_struct! {
    #[derive(Clone, Debug, PartialEq)]
    pub struct ComplexData {
        id: u64,
        active: bool,
        position: Point3D,
        checksum: [u8; 4],
    }
}

impl Arbitrary for ComplexData {
    type Parameters = ();
    type Strategy = BoxedStrategy<ComplexData>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<u64>(),
            any::<bool>(),
            any::<Point3D>(),
            any::<[u8; 4]>(),
        )
            .prop_map(|(id, active, position, checksum)| ComplexData {
                id,
                active,
                position,
                checksum,
            })
            .boxed()
    }
}

generate_codec_tests!(ComplexData, "complex_data");
