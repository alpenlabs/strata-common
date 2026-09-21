//! Macros for declaring schema versions.

/// Implements [`SchemaVersion`](crate::SchemaVersion) for a type, deriving the
/// payload fns from a known encoding format.
///
/// # Formats
///
/// | `format =` | Requires | Payload bytes |
/// |---|---|---|
/// | `ssz` | `ssz::Encode + ssz::Decode` | `as_ssz_bytes` / `from_ssz_bytes` |
/// | `codec` | `strata_codec::Codec` | `encode_to_vec` / `decode_buf_exact` |
///
/// In both cases the payload is the bare encoding with no added length prefix,
/// since the container the payload lives in already delimits it.  This is why
/// the SSZ arm does NOT go through
/// [`CodecSsz`](https://docs.rs/strata-codec-utils) — that wrapper's varint
/// prefix is for embedding SSZ inside a codec stream, which is a different job.
///
/// # Errors
///
/// Each arm requires the schema's [`Error`](crate::Schema::Error) to be
/// constructible from its format's error, so a schema pinned to one format's
/// native error rejects versions in the other format at compile time.  See
/// [`Schema`](crate::Schema) for how to opt out of that.
///
/// # Example
///
/// ```
/// use ssz_derive::{Decode, Encode};
/// use strata_db_schema_common::{Schema, decl_schema_version};
///
/// struct Blocks;
///
/// impl Schema for Blocks {
///     const KEY: &str = "blocks";
///     type Error = ssz::DecodeError;
/// }
///
/// #[derive(Debug, Encode, Decode)]
/// struct BlocksV1 {
///     height: u64,
/// }
///
/// decl_schema_version!(BlocksV1, schema = Blocks, version = 1, format = ssz);
/// ```
#[macro_export]
macro_rules! decl_schema_version {
    ($ty:ty, schema = $schema:ty, version = $ver:expr, format = ssz) => {
        impl $crate::SchemaVersion<$schema> for $ty {
            const VERSION: $crate::VersionId = $ver;

            fn decode_payload(
                buf: &[u8],
            ) -> ::core::result::Result<Self, <$schema as $crate::Schema>::Error> {
                <Self as ::ssz::Decode>::from_ssz_bytes(buf).map_err(::core::convert::Into::into)
            }

            fn encode_payload(
                &self,
            ) -> ::core::result::Result<::std::vec::Vec<u8>, <$schema as $crate::Schema>::Error>
            {
                // SSZ encoding is infallible.
                ::core::result::Result::Ok(<Self as ::ssz::Encode>::as_ssz_bytes(self))
            }
        }
    };

    ($ty:ty, schema = $schema:ty, version = $ver:expr, format = codec) => {
        impl $crate::SchemaVersion<$schema> for $ty {
            const VERSION: $crate::VersionId = $ver;

            fn decode_payload(
                buf: &[u8],
            ) -> ::core::result::Result<Self, <$schema as $crate::Schema>::Error> {
                ::strata_codec::decode_buf_exact::<Self>(buf).map_err(::core::convert::Into::into)
            }

            fn encode_payload(
                &self,
            ) -> ::core::result::Result<::std::vec::Vec<u8>, <$schema as $crate::Schema>::Error>
            {
                ::strata_codec::encode_to_vec(self).map_err(::core::convert::Into::into)
            }
        }
    };
}
