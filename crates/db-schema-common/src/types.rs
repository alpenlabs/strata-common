//! Core schema types.

use std::any::{Any, TypeId};

/// Opaque version ID.
pub type VersionId = u32;

/// Defines a schema.
///
/// This is meant to be used on a unit type, as below.
///
/// ```
/// struct Foo;
///
/// impl Schema for Foo {
///     const KEY: &str = "foo";
/// }
/// ```
pub trait Schema: 'static {
    /// Universal key type.
    const KEY: &str;

    /// Error used in encoding/decoding.
    type Error;
}

/// Defines a version of a schema.
///
/// This is meant to be implemented on a real type that represents a version of
/// a particular schema.
///
/// ```
/// struct Foo;
///
/// impl Schema for Foo {
///     const KEY: &str = "foo";
/// }
///
/// struct FooV1;
///
/// impl SchemaVersion<Foo> for FooV1 {
///     const VERSION: VersionId = 1;
/// }
/// ```
pub trait SchemaVersion<S: Schema>: Any {
    /// The version of the schema this type embodies.
    const VERSION: VersionId;
}

/// Defines a type that contains variants for each possible schema version.
// TODO(trey): a lot of this is speculative
pub trait SchemaEnum<S: Schema> {
    /// Exposes the newest type.
    type Highest: SchemaVersion<S>;

    /// The ID of the version this variant currently is.
    fn version(&self) -> VersionId;

    /// If possible, upgrades to the next-newest version.
    ///
    /// If this is already the highest version, this MUST return `self` unchanged.
    fn upgrade(self) -> Self;

    /// If this is the highest currently available version of the schema.
    ///
    /// If this is false, it implies that `upgrade` should probably be called.
    fn is_highest(&self) -> bool;

    /// If this value contains a "highest version" of a schema, returns the
    /// value.
    fn as_highest(&self) -> Option<&Self::Highest>;
}

/// Unique key for a specific version of a specific schema.
///
/// This can be used to compare schema versions across contexts in a compact and
/// printable way.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct VersionKey(&'static str, VersionId);

impl VersionKey {
    /// Creates a [`VersionKey`] of a version of a schema.
    pub fn of<S: Schema, V: SchemaVersion<S>>() -> Self {
        Self(S::KEY, V::VERSION)
    }

    /// Gets the schema key.
    pub fn key(&self) -> &'static str {
        self.0
    }

    /// Gets the version ID.
    pub fn version(&self) -> VersionId {
        self.1
    }
}
