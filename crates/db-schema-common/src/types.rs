//! Core schema types.

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
pub trait Schema {
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
pub trait SchemaVersion<S: Schema> {
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
