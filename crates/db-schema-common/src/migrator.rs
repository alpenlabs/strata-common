//! Migration support library.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::containers::*;
use crate::errors::MigrationError;
use crate::types::*;

/// Opaque migration trait that we put behind a `Box<dyn Migration>` to hide the
/// schema version-specific generics in `FnMigration`.
///
/// The three steps are separated so that a chain of migrations can decode once
/// at the head and encode once at the tail, applying each intermediate step in
/// value space instead of round-tripping through bytes at every version.
trait Migration: 'static {
    /// Decodes a payload buffer as the migration's source version.
    fn decode_src(&self, buf: &[u8]) -> Result<Box<dyn Any>, MigrationError>;

    /// Applies the migration to a value of the source version, producing a
    /// value of the destination version.
    fn apply(&self, val: Box<dyn Any>) -> Result<Box<dyn Any>, MigrationError>;

    /// Encodes a value of the migration's destination version.
    fn encode_dst(&self, val: &dyn Any) -> Result<Vec<u8>, MigrationError>;
}

/// A value that has been migrated at least one step, still in value space.
///
/// Holds the last migration that was applied to it, since that is the only
/// thing around that knows how to encode a value of whatever version we ended
/// up at when the caller didn't name it statically.
struct MigratedValue<'m> {
    /// The version we ended up at.
    version: VersionId,

    /// The value, as the type of that version.
    value: Box<dyn Any>,

    /// The last migration applied, which knows how to encode `value`.
    last: &'m dyn Migration,
}

impl<'m> MigratedValue<'m> {
    /// Takes the value out as the concrete type of the version we ended at.
    fn into_value<V: Any>(self, schema: &'static str) -> Result<V, MigrationError> {
        let version = self.version;
        self.value
            .downcast::<V>()
            .map(|v| *v)
            .map_err(|_| MigrationError::ChainTypeMismatch {
                schema,
                at: version,
            })
    }

    /// Re-encodes the value into a container tagged with the version we ended
    /// at.
    fn into_container(self) -> Result<OwnedValueContainer, MigrationError> {
        let buf = self.last.encode_dst(self.value.as_ref())?;
        Ok(OwnedValueContainer::new(self.version, buf))
    }
}

/// Highest version ID we accept a migration around.
///
/// Each schema's migrations live in a flat vec indexed by source version, so
/// this is what keeps a typo'd version ID from asking for a multi-gigabyte
/// allocation.  Schemas have a handful of versions in practice, so a real one
/// will never come close to this.
pub const MAX_VERSION_ID: VersionId = 1024;

/// Per-schema migration table, indexed by version ID.
///
/// Slots that sit before the first version or in a gap in the chain are empty,
/// which reads the same as "no migration out of here" and just ends a walk.
#[derive(Default)]
struct SchemaMigrationTable {
    /// State of each version we know something about.
    slots: Vec<VersionSlot>,
}

/// What we know about a single version of a schema.
#[derive(Default)]
struct VersionSlot {
    /// The Rust type that embodies this version, once some migration into or
    /// out of it has told us.
    ty: Option<TypeId>,

    /// Migration out of this version, if we have one.
    out: Option<Box<dyn Migration>>,
}

impl SchemaMigrationTable {
    /// Looks up the migration out of a version.
    fn get(&self, version: VersionId) -> Option<&dyn Migration> {
        self.slots.get(version as usize)?.out.as_deref()
    }

    /// Gets the slot for a version, growing the table as needed.
    fn slot_mut(&mut self, version: VersionId) -> &mut VersionSlot {
        let idx = version as usize;
        if idx >= self.slots.len() {
            self.slots.resize_with(idx + 1, VersionSlot::default);
        }

        &mut self.slots[idx]
    }

    /// Records the type at a version.
    ///
    /// Returns `false` if a different type was already recorded there.
    fn set_type(&mut self, version: VersionId, ty: TypeId) -> bool {
        let slot = self.slot_mut(version);
        match slot.ty {
            Some(existing) => existing == ty,
            None => {
                slot.ty = Some(ty);
                true
            }
        }
    }

    /// Inserts the migration out of a version.
    ///
    /// Returns `false` without inserting if that slot was already filled.
    fn insert(&mut self, version: VersionId, m: Box<dyn Migration>) -> bool {
        let slot = self.slot_mut(version);
        if slot.out.is_some() {
            return false;
        }

        slot.out = Some(m);
        true
    }
}

/// Handles migration mapping.
///
/// Migrations are registered between adjacent versions only, so the table is
/// keyed by source version and every chain is just a walk of consecutive
/// version IDs.
///
/// There are two ways to run a migration, differing in where they stop:
///
/// * [`migrate_to`](Self::migrate_to) goes to a version named statically and hands back the decoded
///   value of that type.
/// * [`migrate_to_latest`](Self::migrate_to_latest) goes as far as the registered migrations reach
///   and hands back a re-encoded container, since there's no static type to name.
///
/// Anything else composes out of those and the container fns, e.g. a
/// re-encoded container at a specific version is
/// `OwnedValueContainer::encode_value(&m.migrate_to::<S, V>(&cont)?)`.
#[expect(missing_debug_implementations, reason = "it's not")]
pub struct Migrator {
    tbl: HashMap<&'static str, SchemaMigrationTable>,
}

impl Migrator {
    /// Creates a new empty instance.
    pub fn new() -> Self {
        Self {
            tbl: HashMap::new(),
        }
    }

    /// Registers a migration fn taking a value from version `A` to version `B`.
    ///
    /// # Panics
    ///
    /// If `B` is not exactly one version after `A`, if either version is above
    /// [`MAX_VERSION_ID`], if a migration out of `A` has already been
    /// registered, or if `A` or `B` disagrees with a previously registered
    /// migration about which type embodies that version.
    pub fn register<S: Schema, A: SchemaVersion<S>, B: SchemaVersion<S>>(&mut self, f: fn(A) -> B) {
        assert!(
            A::VERSION.checked_add(1) == Some(B::VERSION),
            "schema/migrator: migrations must be between adjacent versions (got {} -> {})",
            A::VERSION,
            B::VERSION
        );

        // This also bounds how far a chain walk can run, since it can only
        // proceed through versions we have an entry for.
        assert!(
            B::VERSION <= MAX_VERSION_ID,
            "schema/migrator: version {} is above the max version {MAX_VERSION_ID}",
            B::VERSION
        );

        let sch_tbl = self.tbl.entry(S::KEY).or_default();

        // Checking the types here means a chain can't break with a
        // `ChainTypeMismatch` partway through a walk later; a disagreement
        // shows up at startup instead.
        for (ver, ty) in [
            (A::VERSION, TypeId::of::<A>()),
            (B::VERSION, TypeId::of::<B>()),
        ] {
            assert!(
                sch_tbl.set_type(ver, ty),
                "schema/migrator: schema '{}' version {ver} already has a different type",
                S::KEY
            );
        }

        let migration = FnMigration::<S, A, B>::new(f);
        let inserted = sch_tbl.insert(A::VERSION, Box::new(migration));
        assert!(
            inserted,
            "schema/migrator: duplicate migration out of version {}",
            A::VERSION
        );
    }

    /// Gets the version that [`migrate_to_latest`](Self::migrate_to_latest)
    /// would land on for a container at version `from`.
    ///
    /// This is `from` itself if there is no migration out of it.
    pub fn latest_from<S: Schema>(&self, from: VersionId) -> VersionId {
        let Some(sch_tbl) = self.tbl.get(S::KEY) else {
            return from;
        };

        let mut version = from;
        while sch_tbl.get(version).is_some() {
            // `register` caps versions at `MAX_VERSION_ID`, so the lookup above
            // can never succeed where this would overflow.
            version += 1;
        }

        version
    }

    /// Migrates the container's value to exactly version `V` and decodes it.
    ///
    /// A container already at `V` is just decoded, and the migrated value is
    /// never re-encoded along the way, so this is the fn to reach for when
    /// reading a stored value into memory.
    ///
    /// # Errors
    ///
    /// * [`MigrationError::NewerThanTarget`] if the container is at a version above `V`, which
    ///   usually means the data was written by newer code.
    /// * [`MigrationError::NoPath`] if the registered migrations run out before reaching `V`.
    pub fn migrate_to<S: Schema, V: SchemaVersion<S>>(
        &self,
        cont: &impl ValueContainer,
    ) -> Result<V, MigrationError> {
        if cont.version() > V::VERSION {
            return Err(MigrationError::NewerThanTarget {
                schema: S::KEY,
                have: cont.version(),
                want: V::VERSION,
            });
        }

        match self.walk::<S>(cont, Some(V::VERSION))? {
            None => V::decode_payload(cont.payload()).map_err(MigrationError::payload),
            Some(mv) => mv.into_value(S::KEY),
        }
    }

    /// Applies every registered migration out of the container's version and
    /// re-encodes the result into a container tagged with the version it
    /// reached.
    ///
    /// A container with no migration out of its version, including one whose
    /// schema has no migrations registered at all, is returned unchanged.  See
    /// [`latest_from`](Self::latest_from) to find out where this will end up
    /// without running it.
    pub fn migrate_to_latest<S: Schema>(
        &self,
        cont: &impl ValueContainer,
    ) -> Result<OwnedValueContainer, MigrationError> {
        match self.walk::<S>(cont, None)? {
            None => Ok(OwnedValueContainer::from_container(cont)),
            Some(mv) => mv.into_container(),
        }
    }

    /// Walks the chain of adjacent migrations from the container's version,
    /// staying in value space.
    ///
    /// With `Some(to)`, stops on reaching `to` and errors if the chain runs dry
    /// first.  With `None`, runs until there is no migration out of the
    /// current version.  Either way, returns `None` if no migration was
    /// applied at all, in which case the container's payload is already at the
    /// final version.
    fn walk<S: Schema>(
        &self,
        cont: &impl ValueContainer,
        to: Option<VersionId>,
    ) -> Result<Option<MigratedValue<'_>>, MigrationError> {
        let from = cont.version();
        let no_path = |at: VersionId, to: VersionId| MigrationError::NoPath {
            schema: S::KEY,
            from: at,
            to,
        };

        // Already there, so don't take a step just because one is available.
        if to == Some(from) {
            return Ok(None);
        }

        let sch_tbl = self.tbl.get(S::KEY);
        let Some(mut m) = sch_tbl.and_then(|t| t.get(from)) else {
            return match to {
                Some(to) => Err(no_path(from, to)),
                None => Ok(None),
            };
        };
        let sch_tbl = sch_tbl.expect("schema/migrator: just found a migration in it");

        // Decode once at the head, then stay in value space.
        let mut value = m.decode_src(cont.payload())?;
        let mut version = from;

        loop {
            value = m.apply(value)?;
            // `register` caps versions at `MAX_VERSION_ID`, so the lookup below
            // can never succeed where this would overflow.
            version += 1;

            if to == Some(version) {
                break;
            }

            match sch_tbl.get(version) {
                Some(next) => m = next,
                None => match to {
                    Some(to) => return Err(no_path(version, to)),
                    None => break,
                },
            }
        }

        Ok(Some(MigratedValue {
            version,
            value,
            last: m,
        }))
    }
}

impl Default for Migrator {
    fn default() -> Self {
        Self::new()
    }
}

/// A migration that just wraps a plain (non-closure) fn.
struct FnMigration<S, A, B> {
    f: fn(A) -> B,
    _pd: PhantomData<S>,
}

impl<S: Schema, A: SchemaVersion<S>, B: SchemaVersion<S>> FnMigration<S, A, B> {
    fn new(f: fn(A) -> B) -> Self {
        Self {
            f,
            _pd: PhantomData,
        }
    }
}

impl<S: Schema, A: SchemaVersion<S>, B: SchemaVersion<S>> Migration for FnMigration<S, A, B> {
    fn decode_src(&self, buf: &[u8]) -> Result<Box<dyn Any>, MigrationError> {
        let v = A::decode_payload(buf).map_err(MigrationError::payload)?;
        Ok(Box::new(v))
    }

    fn apply(&self, val: Box<dyn Any>) -> Result<Box<dyn Any>, MigrationError> {
        let a = val
            .downcast::<A>()
            .map_err(|_| MigrationError::ChainTypeMismatch {
                schema: S::KEY,
                at: A::VERSION,
            })?;

        Ok(Box::new((self.f)(*a)))
    }

    fn encode_dst(&self, val: &dyn Any) -> Result<Vec<u8>, MigrationError> {
        let b = val
            .downcast_ref::<B>()
            .ok_or(MigrationError::ChainTypeMismatch {
                schema: S::KEY,
                at: B::VERSION,
            })?;

        b.encode_payload().map_err(MigrationError::payload)
    }
}
