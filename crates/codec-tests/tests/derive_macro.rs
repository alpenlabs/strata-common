//! Tests for the Codec derive macro functionality.

#![expect(unused_crate_dependencies, reason = "test dependencies")]

use strata_codec::{Codec, decode_buf_exact, encode_to_vec};

#[test]
fn test_derive_basic_struct() {
    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct BasicStruct {
        a: u32,
        b: [u8; 16],
        c: bool,
    }

    let original = BasicStruct {
        a: 0xDEADBEEF,
        b: [0x42; 16],
        c: true,
    };

    let encoded = encode_to_vec(&original).expect("encoding should work");
    let decoded: BasicStruct = decode_buf_exact(&encoded).expect("decoding should work");
    assert_eq!(original, decoded);
}

#[test]
fn test_derive_macro_reexport() {
    // Verify the Codec derive macro is properly re-exported through strata_codec
    #[derive(Debug, Clone, PartialEq, Eq, strata_codec::Codec)]
    struct ReexportTest {
        value: u64,
    }

    let test = ReexportTest { value: 999 };
    let encoded = encode_to_vec(&test).unwrap();
    let decoded: ReexportTest = decode_buf_exact(&encoded).unwrap();
    assert_eq!(test, decoded);
}

#[test]
fn test_derive_tuple_struct() {
    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct TupleStruct(u32, u64, bool);

    let original = TupleStruct(42, 84, false);
    let encoded = encode_to_vec(&original).unwrap();
    let decoded: TupleStruct = decode_buf_exact(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_derive_unit_struct() {
    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct UnitStruct;

    let original = UnitStruct;
    let encoded = encode_to_vec(&original).unwrap();
    assert!(encoded.is_empty());
    let decoded: UnitStruct = decode_buf_exact(&encoded).unwrap();
    assert_eq!(format!("{:?}", original), format!("{:?}", decoded));
}

#[test]
fn test_derive_nested_structs() {
    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct Inner {
        x: i32,
        y: i32,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct Outer {
        inner: Inner,
        z: u64,
    }

    let original = Outer {
        inner: Inner { x: -10, y: 20 },
        z: 1000,
    };

    let encoded = encode_to_vec(&original).unwrap();
    let decoded: Outer = decode_buf_exact(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_derive_with_varvec() {
    use strata_codec::VarVec;

    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct WithVarVec {
        data: VarVec<u8>,
        count: u32,
    }

    let original = WithVarVec {
        data: VarVec::from_vec(vec![1, 2, 3, 4, 5]).unwrap(),
        count: 5,
    };

    let encoded = encode_to_vec(&original).unwrap();
    let decoded: WithVarVec = decode_buf_exact(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_compatibility_with_manual_impl() {
    // Manual implementation
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ManualImpl {
        a: u16,
        b: u32,
    }

    impl Codec for ManualImpl {
        fn decode(dec: &mut impl strata_codec::Decoder) -> Result<Self, strata_codec::CodecError> {
            Ok(Self {
                a: Codec::decode(dec)?,
                b: Codec::decode(dec)?,
            })
        }

        fn encode(&self, enc: &mut impl strata_codec::Encoder) -> Result<(), strata_codec::CodecError> {
            self.a.encode(enc)?;
            self.b.encode(enc)?;
            Ok(())
        }
    }

    // Derived implementation
    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct DerivedImpl {
        a: u16,
        b: u32,
    }

    let manual = ManualImpl { a: 100, b: 200 };
    let derived = DerivedImpl { a: 100, b: 200 };

    let manual_encoded = encode_to_vec(&manual).unwrap();
    let derived_encoded = encode_to_vec(&derived).unwrap();

    // The encoded bytes should be identical
    assert_eq!(manual_encoded, derived_encoded);

    // Cross-decode to verify format compatibility
    let manual_bytes = encode_to_vec(&manual).unwrap();
    let decoded_as_derived: DerivedImpl = decode_buf_exact(&manual_bytes).unwrap();
    assert_eq!(decoded_as_derived.a, manual.a);
    assert_eq!(decoded_as_derived.b, manual.b);
}