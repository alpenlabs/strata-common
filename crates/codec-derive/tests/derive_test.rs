//! Integration tests for the Codec derive macro.

// Suppress unused dependency warnings for proc-macro dependencies
use quote as _;
use syn as _;

use strata_codec::{CodecError, decode_buf_exact, encode_to_vec};
// Import both the trait and the derive macro with distinct names
use strata_codec::Codec as CodecTrait;
use strata_codec_derive::Codec;

/// Test deriving Codec for a named struct
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct NamedStruct {
    a: u32,
    b: u64,
    c: u8,
}

#[test]
fn test_named_struct() {
    let original = NamedStruct {
        a: 42,
        b: 1234567890,
        c: 255,
    };

    // Encode
    let encoded = encode_to_vec(&original).expect("encoding should succeed");

    // Decode
    let decoded: NamedStruct = decode_buf_exact(&encoded).expect("decoding should succeed");

    // Verify round-trip
    assert_eq!(original, decoded);
}

/// Test deriving Codec for a tuple struct
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct TupleStruct(u16, i32, [u8; 4]);

#[test]
fn test_tuple_struct() {
    let original = TupleStruct(65535, -123456, [1, 2, 3, 4]);

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: TupleStruct = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
}

/// Test deriving Codec for a unit struct
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct UnitStruct;

#[test]
fn test_unit_struct() {
    let original = UnitStruct;

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: UnitStruct = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
    // Unit struct should encode to empty bytes
    assert_eq!(encoded.len(), 0);
}

/// Test struct with nested types that implement Codec
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct NestedStruct {
    inner: InnerStruct,
    value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct InnerStruct {
    x: i16,
    y: i16,
}

#[test]
fn test_nested_structs() {
    let original = NestedStruct {
        inner: InnerStruct { x: -100, y: 200 },
        value: 999,
    };

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: NestedStruct = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
}

/// Test struct with byte arrays (only [u8; N] arrays have Codec impl)
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct StructWithArrays {
    bytes: [u8; 32],
    more_bytes: [u8; 3],
}

#[test]
fn test_struct_with_arrays() {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes[31] = 255;

    let original = StructWithArrays {
        bytes,
        more_bytes: [100, 200, 255],
    };

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: StructWithArrays = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
}

/// Test generic struct (T must implement Codec)
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct GenericStruct<T: CodecTrait> {
    value: T,
    count: u32,
}

#[test]
fn test_generic_struct() {
    let original = GenericStruct {
        value: 42u64,
        count: 10,
    };

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: GenericStruct<u64> = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
}

/// Test generic struct with bounds - using VarVec instead of Vec
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct BoundedGeneric<T: CodecTrait + Clone> {
    data: T,
}

#[test]
fn test_bounded_generic() {
    use strata_codec::VarVec;

    let original = BoundedGeneric {
        data: VarVec::from_vec(vec![1u8, 2, 3, 4]).expect("valid vec"),
    };

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: BoundedGeneric<VarVec<u8>> =
        decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
}

/// Test empty named struct
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct EmptyNamedStruct {}

#[test]
fn test_empty_named_struct() {
    let original = EmptyNamedStruct {};

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: EmptyNamedStruct = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
    assert_eq!(encoded.len(), 0);
}

/// Test tuple struct with single field
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct SingleFieldTuple(u64);

#[test]
fn test_single_field_tuple() {
    let original = SingleFieldTuple(0xDEADBEEFCAFEBABE);

    let encoded = encode_to_vec(&original).expect("encoding should succeed");
    let decoded: SingleFieldTuple = decode_buf_exact(&encoded).expect("decoding should succeed");

    assert_eq!(original, decoded);
}

/// Test that field order is preserved
#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderTest {
    first: u8,
    second: u16,
    third: u32,
}

// Manual implementation to compare against
impl CodecTrait for OrderTest {
    fn decode(dec: &mut impl strata_codec::Decoder) -> Result<Self, CodecError> {
        Ok(Self {
            first: u8::decode(dec)?,
            second: u16::decode(dec)?,
            third: u32::decode(dec)?,
        })
    }

    fn encode(&self, enc: &mut impl strata_codec::Encoder) -> Result<(), CodecError> {
        self.first.encode(enc)?;
        self.second.encode(enc)?;
        self.third.encode(enc)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct OrderTestDerived {
    first: u8,
    second: u16,
    third: u32,
}

#[test]
fn test_field_order_preservation() {
    let manual = OrderTest {
        first: 1,
        second: 256,
        third: 65536,
    };

    let derived = OrderTestDerived {
        first: 1,
        second: 256,
        third: 65536,
    };

    let manual_encoded = encode_to_vec(&manual).expect("encoding should succeed");
    let derived_encoded = encode_to_vec(&derived).expect("encoding should succeed");

    // The encoded bytes should be identical
    assert_eq!(manual_encoded, derived_encoded);

    // Cross-decode to verify compatibility
    let decoded_as_manual: OrderTest =
        decode_buf_exact(&derived_encoded).expect("decoding should succeed");
    assert_eq!(manual, decoded_as_manual);
}
