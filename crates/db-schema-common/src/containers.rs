//! Containers for versioned, opaquely-encoded values.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

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
    pl: ByteBuf,
}

impl OwnedValueContainer {
    /// Creates a new instance.
    pub fn new(ver: VersionId, pl: Vec<u8>) -> Self {
        Self { ver, pl: pl.into() }
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

    /// Borrows the version and payload without copying the payload.
    pub fn as_container_ref(&self) -> ValueContainerRef<'_> {
        ValueContainerRef::new(self.ver, &self.pl)
    }

    /// Consumes the container, returning the raw payload.
    pub fn into_payload(self) -> Vec<u8> {
        self.pl.into_vec()
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

/// Borrowed view of a version and its encoded payload.
///
/// Ciborium deserializes into owned data. Decode CBOR into an
/// [`OwnedValueContainer`], then use [`OwnedValueContainer::as_container_ref`]
/// to borrow its payload without another copy. This view serializes in the
/// same format as the owned container, but does not implement [`Deserialize`].
///
/// ```
/// use strata_db_schema_common::{OwnedValueContainer, ValueContainer};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let original = OwnedValueContainer::new(1, vec![0, 128, 255]);
/// let mut bytes = Vec::new();
/// ciborium::into_writer(&original.as_container_ref(), &mut bytes)?;
/// let decoded: OwnedValueContainer = ciborium::from_reader(bytes.as_slice())?;
/// let view = decoded.as_container_ref();
/// assert_eq!(view.version(), 1);
/// assert_eq!(view.payload(), original.payload());
/// # Ok(())
/// # }
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValueContainerRef<'b> {
    ver: VersionId,

    #[serde(with = "serde_bytes")]
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
