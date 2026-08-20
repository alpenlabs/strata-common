//! Containers for versioned, opaquely-encoded values.

use serde::{Deserialize, Serialize};

use crate::errors::DecodeValueError;
use crate::types::*;

/// Represents some container that has a well-defined version and a payload,
/// which may store anything.
///
/// What kind of value it stores depends on the context and is assumed to be known.
pub trait ValueContainer {
    /// Gets the version this container has.
    fn version(&self) -> VersionId;

    /// Gets the encoded data.
    fn payload(&self) -> &[u8];
}

/// Opaque container for a versioned value.
///
/// This stores the version it was stored as as a well-defined value, so that
/// the higher machinery knows how to interpret the data.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct OwnedValueContainer {
    ver: VersionId,
    pl: Vec<u8>,
}

impl OwnedValueContainer {
    /// Creates a new instance.
    pub fn new(ver: VersionId, pl: Vec<u8>) -> Self {
        Self { ver, pl }
    }

    /// Encodes a schema version value into a new container, tagged with that
    /// version.
    pub fn encode_value<S: Schema, V: SchemaVersion<S>>(v: &V) -> Result<Self, S::Error> {
        Ok(Self::new(V::VERSION, v.encode_payload()?))
    }

    /// Copies any other container into an owned one.
    pub fn from_container(cont: &impl ValueContainer) -> Self {
        Self::new(cont.version(), cont.payload().to_vec())
    }

    /// Consumes the container, returning the raw payload.
    pub fn into_payload(self) -> Vec<u8> {
        self.pl
    }
}

impl ValueContainer for OwnedValueContainer {
    fn version(&self) -> VersionId {
        self.ver
    }

    fn payload(&self) -> &[u8] {
        &self.pl
    }
}

/// Borrowed version of [`ValueContainer`] to reduce copies during the first
/// deserialization passes before we deserialize it to a concrete value.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct ValueContainerRef<'b> {
    ver: VersionId,
    pl: &'b [u8],
}

impl<'b> ValueContainerRef<'b> {
    /// Creates a new instance.
    pub fn new(ver: VersionId, pl: &'b [u8]) -> Self {
        Self { ver, pl }
    }
}

impl<'b> ValueContainer for ValueContainerRef<'b> {
    fn version(&self) -> VersionId {
        self.ver
    }

    fn payload(&self) -> &[u8] {
        self.pl
    }
}

/// Extension trait for [`ValueContainer`] to provide convenience fns.
pub trait ValueContainerExt {
    /// Attempts to decode the payload as a particular schema version, checking
    /// that the container is actually tagged with that version.
    ///
    /// A container whose version does not match is a data-level condition, not
    /// a programming error, so this reports it as
    /// [`DecodeValueError::VersionMismatch`] rather than panicking.
    fn try_decode_as_ver<S: Schema, V: SchemaVersion<S>>(
        &self,
    ) -> Result<V, DecodeValueError<S::Error>>;

    /// Decodes the payload as a particular schema version without checking the
    /// container's version tag.
    ///
    /// Use this when the version has already been established, e.g. right after
    /// a migration.  Otherwise prefer
    /// [`try_decode_as_ver`](ValueContainerExt::try_decode_as_ver).
    fn decode_payload_as<S: Schema, V: SchemaVersion<S>>(&self) -> Result<V, S::Error>;
}

impl<T: ValueContainer> ValueContainerExt for T {
    fn try_decode_as_ver<S: Schema, V: SchemaVersion<S>>(
        &self,
    ) -> Result<V, DecodeValueError<S::Error>> {
        if V::VERSION != self.version() {
            return Err(DecodeValueError::VersionMismatch {
                expected: V::VERSION,
                got: self.version(),
            });
        }

        self.decode_payload_as::<S, V>()
            .map_err(DecodeValueError::Payload)
    }

    fn decode_payload_as<S: Schema, V: SchemaVersion<S>>(&self) -> Result<V, S::Error> {
        V::decode_payload(self.payload())
    }
}
