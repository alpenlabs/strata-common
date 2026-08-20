//! Tests for the schema encoding and migration machinery.

use ssz::Encode as SszEncodeTrait;
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};
use strata_codec::{Codec, CodecError};

use crate::*;

// A schema pinned to SSZ by using SSZ's own error type.

struct SszSchema;

impl Schema for SszSchema {
    const KEY: &str = "test-ssz";
    type Error = ssz::DecodeError;
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
struct SszV1 {
    a: u64,
    b: u32,
}

decl_schema_version!(SszV1, schema = SszSchema, version = 1, format = ssz);

// A schema pinned to strata-codec by using the codec's own error type.

struct CodecSchema;

impl Schema for CodecSchema {
    const KEY: &str = "test-codec";
    type Error = CodecError;
}

#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct CodecV1 {
    a: u32,
}

decl_schema_version!(CodecV1, schema = CodecSchema, version = 1, format = codec);

#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct CodecV2 {
    a: u32,
    b: u64,
}

decl_schema_version!(CodecV2, schema = CodecSchema, version = 2, format = codec);

#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct CodecV3 {
    a: u32,
    b: u64,
    c: u16,
}

decl_schema_version!(CodecV3, schema = CodecSchema, version = 3, format = codec);

fn codec_v1_to_v2(v: CodecV1) -> CodecV2 {
    CodecV2 { a: v.a, b: 100 }
}

fn codec_v2_to_v3(v: CodecV2) -> CodecV3 {
    CodecV3 {
        a: v.a,
        b: v.b,
        c: 7,
    }
}

fn codec_migrator() -> Migrator {
    let mut m = Migrator::new();
    m.register::<CodecSchema, _, _>(codec_v1_to_v2);
    m.register::<CodecSchema, _, _>(codec_v2_to_v3);
    m
}

/// A schema that changes encoding format mid-life, so it needs the wrapper
/// error.
///
/// This only makes sense with the `ssz` feature on, since that is what gives
/// [`SchemaError`] its SSZ variant.  Without it, mixing formats in one schema
/// is supposed to fail to compile.
#[cfg(feature = "ssz")]
mod mixed_format {
    use super::*;

    struct MixedSchema;

    impl Schema for MixedSchema {
        const KEY: &str = "test-mixed";
        type Error = SchemaError;
    }

    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct MixedV1 {
        a: u32,
    }

    decl_schema_version!(MixedV1, schema = MixedSchema, version = 1, format = codec);

    #[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
    struct MixedV2 {
        a: u32,
        b: u64,
    }

    decl_schema_version!(MixedV2, schema = MixedSchema, version = 2, format = ssz);

    #[test]
    fn test_mixed_format_schema_roundtrip() {
        let v1 = MixedV1 { a: 5 };
        let c1 = OwnedValueContainer::encode_value::<MixedSchema, _>(&v1).expect("test: encode v1");
        assert_eq!(
            c1.try_decode_as_ver::<MixedSchema, MixedV1>()
                .expect("test: decode v1"),
            v1,
            "test: mixed v1 roundtrip"
        );

        let v2 = MixedV2 { a: 5, b: 9 };
        let c2 = OwnedValueContainer::encode_value::<MixedSchema, _>(&v2).expect("test: encode v2");
        assert_eq!(
            c2.try_decode_as_ver::<MixedSchema, MixedV2>()
                .expect("test: decode v2"),
            v2,
            "test: mixed v2 roundtrip"
        );
    }
}

#[test]
fn test_ssz_container_roundtrip() {
    let val = SszV1 { a: 42, b: 7 };
    let cont = OwnedValueContainer::encode_value::<SszSchema, _>(&val).expect("test: encode");

    assert_eq!(cont.version(), 1, "test: container version");

    let decoded = cont
        .try_decode_as_ver::<SszSchema, SszV1>()
        .expect("test: decode");
    assert_eq!(decoded, val, "test: ssz roundtrip");
}

#[test]
fn test_codec_container_roundtrip() {
    let val = CodecV1 { a: 1337 };
    let cont = OwnedValueContainer::encode_value::<CodecSchema, _>(&val).expect("test: encode");

    assert_eq!(cont.version(), 1, "test: container version");

    let decoded = cont
        .try_decode_as_ver::<CodecSchema, CodecV1>()
        .expect("test: decode");
    assert_eq!(decoded, val, "test: codec roundtrip");
}

#[test]
fn test_payload_has_no_added_framing() {
    // The container already delimits the payload, so the bytes must be exactly
    // what the underlying format produces, with no length prefix.
    let sv = SszV1 { a: 42, b: 7 };
    let sc = OwnedValueContainer::encode_value::<SszSchema, _>(&sv).expect("test: encode ssz");
    assert_eq!(
        sc.payload(),
        sv.as_ssz_bytes().as_slice(),
        "test: ssz payload should be bare ssz bytes"
    );

    let cv = CodecV1 { a: 1337 };
    let cc = OwnedValueContainer::encode_value::<CodecSchema, _>(&cv).expect("test: encode codec");
    assert_eq!(
        cc.payload(),
        strata_codec::encode_to_vec(&cv)
            .expect("test: encode ref")
            .as_slice(),
        "test: codec payload should be bare codec bytes"
    );
}

#[test]
fn test_owned_container_serde_roundtrip() {
    let val = SszV1 { a: 42, b: 7 };
    let cont = OwnedValueContainer::encode_value::<SszSchema, _>(&val).expect("test: encode");

    let mut buf = Vec::new();
    ciborium::into_writer(&cont, &mut buf).expect("test: serialize container");

    let de: OwnedValueContainer =
        ciborium::from_reader(buf.as_slice()).expect("test: deserialize container");
    assert_eq!(de, cont, "test: container serde roundtrip");

    // The payload has to survive as an opaque blob, so it should come back out
    // of the container decodable as the value we put in.
    let decoded = de
        .try_decode_as_ver::<SszSchema, SszV1>()
        .expect("test: decode");
    assert_eq!(decoded, val, "test: value through container serde");
}

#[test]
fn test_container_ref_decodes() {
    let val = SszV1 { a: 3, b: 4 };
    let buf = val.as_ssz_bytes();
    let cont = ValueContainerRef::new(1, &buf);

    let decoded = cont
        .try_decode_as_ver::<SszSchema, SszV1>()
        .expect("test: decode");
    assert_eq!(decoded, val, "test: borrowed container roundtrip");
}

#[test]
fn test_version_mismatch_is_an_error() {
    let val = CodecV1 { a: 1 };
    let cont = OwnedValueContainer::encode_value::<CodecSchema, _>(&val).expect("test: encode");

    let res = cont.try_decode_as_ver::<CodecSchema, CodecV2>();
    match res {
        Err(DecodeValueError::VersionMismatch { expected, got }) => {
            assert_eq!(expected, 2, "test: expected version");
            assert_eq!(got, 1, "test: container version");
        }
        _ => panic!("test: should have reported a version mismatch"),
    }
}

#[test]
fn test_truncated_payload_is_an_error() {
    let val = SszV1 { a: 42, b: 7 };
    let mut buf = val.as_ssz_bytes();
    buf.truncate(buf.len() - 1);
    let cont = OwnedValueContainer::new(1, buf);

    assert!(
        cont.try_decode_as_ver::<SszSchema, SszV1>().is_err(),
        "test: truncated ssz payload should fail to decode"
    );
}

#[test]
fn test_trailing_bytes_are_an_error() {
    // Both formats are whole-buffer, so leftover input is a decode failure
    // rather than something silently ignored.
    let sv = SszV1 { a: 42, b: 7 };
    let mut sbuf = sv.as_ssz_bytes();
    sbuf.push(0);
    assert!(
        OwnedValueContainer::new(1, sbuf)
            .try_decode_as_ver::<SszSchema, SszV1>()
            .is_err(),
        "test: trailing ssz bytes should fail to decode"
    );

    let cv = CodecV1 { a: 1337 };
    let mut cbuf = strata_codec::encode_to_vec(&cv).expect("test: encode");
    cbuf.push(0);
    assert!(
        OwnedValueContainer::new(1, cbuf)
            .try_decode_as_ver::<CodecSchema, CodecV1>()
            .is_err(),
        "test: trailing codec bytes should fail to decode"
    );
}

#[test]
fn test_migrate_all_the_way_chain() {
    let m = codec_migrator();

    let v1 = CodecV1 { a: 3 };
    let cont = OwnedValueContainer::encode_value::<CodecSchema, _>(&v1).expect("test: encode");

    let migrated = m
        .migrate_all_the_way::<CodecSchema>(&cont)
        .expect("test: migrate");
    assert_eq!(migrated.version(), 3, "test: should reach the last version");

    let val = migrated
        .try_decode_as_ver::<CodecSchema, CodecV3>()
        .expect("test: decode");
    assert_eq!(val, CodecV3 { a: 3, b: 100, c: 7 }, "test: migrated value");
}

#[test]
fn test_migrate_from_middle_of_chain() {
    let m = codec_migrator();

    let v2 = CodecV2 { a: 8, b: 9 };
    let cont = OwnedValueContainer::encode_value::<CodecSchema, _>(&v2).expect("test: encode");

    let val = m
        .migrate_and_decode::<CodecSchema, CodecV3>(&cont)
        .expect("test: migrate");
    assert_eq!(val, CodecV3 { a: 8, b: 9, c: 7 }, "test: migrated value");
}

#[test]
fn test_migrate_already_highest_is_unchanged() {
    let m = codec_migrator();

    let v3 = CodecV3 { a: 1, b: 2, c: 3 };
    let cont = OwnedValueContainer::encode_value::<CodecSchema, _>(&v3).expect("test: encode");

    let migrated = m
        .migrate_all_the_way::<CodecSchema>(&cont)
        .expect("test: migrate");
    assert_eq!(migrated, cont, "test: highest version should be unchanged");
}

#[test]
fn test_migrate_unknown_schema_is_unchanged() {
    // A schema with no migrations registered at all must not be an error.
    let m = codec_migrator();

    let val = SszV1 { a: 42, b: 7 };
    let cont = OwnedValueContainer::encode_value::<SszSchema, _>(&val).expect("test: encode");

    let migrated = m
        .migrate_all_the_way::<SszSchema>(&cont)
        .expect("test: migrate");
    assert_eq!(migrated, cont, "test: unknown schema should be unchanged");
}

#[test]
fn test_migrate_and_decode_without_migrations() {
    let m = Migrator::new();

    let val = SszV1 { a: 42, b: 7 };
    let cont = OwnedValueContainer::encode_value::<SszSchema, _>(&val).expect("test: encode");

    let decoded = m
        .migrate_and_decode::<SszSchema, SszV1>(&cont)
        .expect("test: decode");
    assert_eq!(decoded, val, "test: value should pass through");
}

#[test]
fn test_migrate_and_decode_wrong_target_version() {
    let m = codec_migrator();

    let v1 = CodecV1 { a: 3 };
    let cont = OwnedValueContainer::encode_value::<CodecSchema, _>(&v1).expect("test: encode");

    // The chain ends at v3, so asking for v2 has no path.
    let res = m.migrate_and_decode::<CodecSchema, CodecV2>(&cont);
    assert!(
        matches!(res, Err(MigrationError::NoPath { .. })),
        "test: should have reported no path"
    );
}

#[test]
fn test_migrate_once() {
    let m = codec_migrator();

    let v1 = CodecV1 { a: 3 };
    let buf = strata_codec::encode_to_vec(&v1).expect("test: encode");

    let out = m
        .migrate_once::<CodecSchema, CodecV1, CodecV2>(&buf)
        .expect("test: migrate");

    let v2 = CodecV2::decode_payload(&out).expect("test: decode");
    assert_eq!(v2, CodecV2 { a: 3, b: 100 }, "test: migrated value");
}

#[test]
fn test_migrate_once_missing_is_an_error() {
    let m = Migrator::new();
    let buf = strata_codec::encode_to_vec(&CodecV1 { a: 3 }).expect("test: encode");

    let res = m.migrate_once::<CodecSchema, CodecV1, CodecV2>(&buf);
    assert!(
        matches!(res, Err(MigrationError::NoPath { .. })),
        "test: should have reported no path"
    );
}

#[test]
#[should_panic(expected = "adjacent versions")]
fn test_register_nonadjacent_panics() {
    fn v1_to_v3(v: CodecV1) -> CodecV3 {
        CodecV3 { a: v.a, b: 0, c: 0 }
    }

    let mut m = Migrator::new();
    m.register::<CodecSchema, _, _>(v1_to_v3);
}

#[test]
#[should_panic(expected = "duplicate migration")]
fn test_register_duplicate_panics() {
    let mut m = codec_migrator();
    m.register::<CodecSchema, _, _>(codec_v1_to_v2);
}

#[test]
fn test_version_key() {
    let k = VersionKey::of::<CodecSchema, CodecV2>();
    assert_eq!(k.key(), "test-codec", "test: schema key");
    assert_eq!(k.version(), 2, "test: version id");
}
