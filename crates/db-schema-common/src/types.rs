//! Core schema types.

use std::any::{Any, TypeId};

/// Opaque version ID.
pub type VersionId = u32;

/// Defines a schema.
///
/// This is meant to be used on a unit type, as below.
///
/// ```
/// use strata_db_schema_common::Schema;
///
/// struct Foo;
///
/// impl Schema for Foo {
///     const KEY: &str = "foo";
///     type Error = strata_codec::CodecError;
/// }
/// ```
///
/// # Choosing an error type
///
/// [`Error`](Schema::Error) doubles as the schema's encoding format constraint.
/// Each version's payload impl requires that this type can be built from the
/// error of the format that version uses, so naming a single format's native
/// error — `ssz::DecodeError` or [`CodecError`](strata_codec::CodecError) —
/// pins the whole schema to that format: adding a version in another format
/// then fails to compile at the impl site.
///
/// A schema that really does need to change format between versions uses
/// [`SchemaError`](crate::SchemaError), which converts from both.
pub trait Schema: 'static {
    /// Human-readable label for values under this schema.
    ///
    /// Runtime identity uses the schema's Rust type, so distinct schemas may
    /// reuse this label without sharing migrations or version keys.
    const KEY: &str;

    /// Error used in encoding/decoding.
    type Error: core::error::Error + Send + Sync + 'static;
}

/// Defines a version of a schema.
///
/// This is meant to be implemented on a real type that represents a version of
/// a particular schema, along with how that type maps to and from the bytes we
/// store for it.
///
/// Most impls should be generated with
/// [`decl_schema_version!`](crate::decl_schema_version), which fills in the
/// payload fns for a known encoding format.  Implementing it by hand, as below,
/// is the escape hatch for a version whose stored form does not line up with a
/// plain derive.
///
/// ```
/// use strata_codec::CodecError;
/// use strata_db_schema_common::{Schema, SchemaVersion, VersionId};
///
/// struct Foo;
///
/// impl Schema for Foo {
///     const KEY: &str = "foo";
///     type Error = CodecError;
/// }
///
/// struct FooV1(u32);
///
/// impl SchemaVersion<Foo> for FooV1 {
///     const VERSION: VersionId = 1;
///
///     fn decode_payload(buf: &[u8]) -> Result<Self, CodecError> {
///         strata_codec::decode_buf_exact(buf).map(Self)
///     }
///
///     fn encode_payload(&self) -> Result<Vec<u8>, CodecError> {
///         strata_codec::encode_to_vec(&self.0)
///     }
/// }
/// ```
///
/// # Payload framing
///
/// The buffer passed to [`decode_payload`](SchemaVersion::decode_payload) is
/// exactly the bytes [`encode_payload`](SchemaVersion::encode_payload)
/// produced, no more and no less — the container it came out of already
/// delimits it.  Impls must NOT add their own length prefix, and must reject
/// trailing bytes.
pub trait SchemaVersion<S: Schema>: Any + Sized {
    /// The version of the schema this type embodies.
    const VERSION: VersionId;

    /// Decodes the value from a stored payload buffer.
    fn decode_payload(buf: &[u8]) -> Result<Self, S::Error>;

    /// Encodes the value into a stored payload buffer.
    fn encode_payload(&self) -> Result<Vec<u8>, S::Error>;
}

/// Defines a type that contains variants for each possible schema version.
pub trait SchemaSeries<S: Schema> {
    /// The ID of the version this variant currently is.
    fn version(&self) -> VersionId;
}

/// Unique key for a specific version of a specific schema.
///
/// Includes the schema's Rust type identity, so schemas with the same
/// [`Schema::KEY`] and version remain distinct in maps and sets. The key string
/// is retained for diagnostics.
///
/// This is an in-memory identifier. Its [`TypeId`]-based hashes and ordering
/// are not stable across Rust releases and must not be used as a persisted ID.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct VersionKey {
    key: &'static str,
    version: VersionId,
    schema: TypeId,
}

impl VersionKey {
    /// Creates a [`VersionKey`] of a version of a schema.
    pub fn of<S: Schema, V: SchemaVersion<S>>() -> Self {
        Self {
            key: S::KEY,
            version: V::VERSION,
            schema: TypeId::of::<S>(),
        }
    }

    /// Gets the schema key.
    pub fn key(&self) -> &'static str {
        self.key
    }

    /// Gets the version ID.
    pub fn version(&self) -> VersionId {
        self.version
    }
}
