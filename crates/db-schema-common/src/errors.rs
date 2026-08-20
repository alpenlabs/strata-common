//! Error types.

use thiserror::Error;

use crate::types::VersionId;

/// Payload error for schemas whose versions span more than one encoding format.
///
/// A schema that uses a single encoding format throughout should prefer that
/// format's native error type as its [`Schema::Error`](crate::Schema::Error) —
/// `ssz::DecodeError` for SSZ, [`CodecError`](strata_codec::CodecError) for
/// strata-codec — which avoids this wrapper entirely and makes adding a version
/// in a different format a compile error.
///
/// This type exists for the schemas that genuinely do need to change format
/// between versions.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Error decoding an SSZ payload.
    #[cfg(feature = "ssz")]
    #[error("ssz: {0}")]
    Ssz(#[from] ssz::DecodeError),

    /// Error encoding or decoding a strata-codec payload.
    #[error("codec: {0}")]
    Codec(#[from] strata_codec::CodecError),
}

/// Error decoding a value out of a container as a specific schema version.
///
/// Generic over the schema's own error type so that checking the version tag
/// does not force schemas to widen their payload error.
#[derive(Debug, Error)]
pub enum DecodeValueError<E> {
    /// The container's version tag did not match the version we tried to decode
    /// it as.
    #[error("expected version {expected}, container has {got}")]
    VersionMismatch {
        /// The version we tried to decode as.
        expected: VersionId,

        /// The version the container is actually tagged with.
        got: VersionId,
    },

    /// The payload itself failed to decode.
    #[error("payload: {0}")]
    Payload(#[source] E),
}

/// Error from the migration machinery.
///
/// The payload variant is boxed because [`Migrator`](crate::Migrator) erases
/// the schema type, so it cannot name any particular schema's error type.
/// Migration is a cold path, so the allocation is not a concern.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// No migration was registered to get from one version to another.
    #[error("schema '{schema}': no migration from {from} to {to}")]
    NoPath {
        /// The schema key.
        schema: &'static str,

        /// The version we were migrating from.
        from: VersionId,

        /// The version we wanted to reach.
        to: VersionId,
    },

    /// Two migrations registered around the same version boundary disagreed
    /// about the type at that version.
    #[error("schema '{schema}': migration chain type mismatch at version {at}")]
    ChainTypeMismatch {
        /// The schema key.
        schema: &'static str,

        /// The version the chain broke at.
        at: VersionId,
    },

    /// A payload failed to encode or decode partway through a migration.
    #[error("payload: {0}")]
    Payload(#[source] Box<dyn core::error::Error + Send + Sync>),
}

impl MigrationError {
    /// Wraps a schema's payload error into the erased payload variant.
    pub(crate) fn payload(e: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self::Payload(Box::new(e))
    }
}
