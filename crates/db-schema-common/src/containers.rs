use serde::{Deserialize, Serialize};

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
    /// Attempts to decode the payload as a particular schema version.
    ///
    /// # Panics
    ///
    /// If the version does not match.
    fn try_decode_as_ver<S: Schema, V: SchemaVersion<S>>(&self) -> Result<V, S::Error>;
}

impl<T: ValueContainer> ValueContainerExt for T {
    fn try_decode_as_ver<S: Schema, V: SchemaVersion<S>>(&self) -> Result<V, S::Error> {
        assert_eq!(V::VERSION, self.version(), "schema: version mismatch");
        unimplemented!()
    }
}
