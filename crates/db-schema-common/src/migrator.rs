//! Migration support library.

use std::any::Any;
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

/// Opaque wrapper around a decoded schema type, including the last migration
/// that we applied to it, so that we could re-encode it if we wanted to.
struct MigratedValue<'m> {
    /// The version we ended up at.
    version: VersionId,

    /// The value, as the type of that version.
    value: Box<dyn Any>,

    /// The last migration applied, which knows how to encode `value`.
    last: &'m dyn Migration,
}

#[allow(unused)] // will get made public later
impl<'m> MigratedValue<'m> {
    fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.value.downcast_ref()
    }

    fn downcast<T: Any>(self) -> Option<Box<T>> {
        self.value.downcast().ok()
    }

    fn encode(&self) -> Result<Vec<u8>, MigrationError> {
        self.last.encode_dst(&self.value)
    }
}

/// Highest version ID we accept a migration around.
///
/// Each schema's migrations live in a flat vec indexed by source version, so
/// this is what keeps a typo'd version ID from asking for a multi-gigabyte
/// allocation.  Schemas have a handful of versions in practice, so a real one
/// will never come close to this.
pub const MAX_VERSION_ID: VersionId = 1024;

/// Per-schema migration table, indexed by source version ID.
///
/// Slots that sit before the first version or in a gap in the chain are `None`,
/// which reads the same as "no migration out of here" and just ends a walk.
#[derive(Default)]
struct SchemaMigrationTable {
    /// Migration out of each version, if we have one.
    migrations: Vec<Option<Box<dyn Migration>>>,
}

impl SchemaMigrationTable {
    /// Looks up the migration out of a version.
    fn get(&self, version: VersionId) -> Option<&dyn Migration> {
        self.migrations.get(version as usize)?.as_deref()
    }

    /// Inserts the migration out of a version, growing the table as needed.
    ///
    /// Returns `false` without inserting if that slot was already filled.
    fn insert(&mut self, version: VersionId, m: Box<dyn Migration>) -> bool {
        let idx = version as usize;
        if idx >= self.migrations.len() {
            self.migrations.resize_with(idx + 1, || None);
        }

        let slot = &mut self.migrations[idx];
        if slot.is_some() {
            return false;
        }

        *slot = Some(m);
        true
    }
}

/// Handles migration mapping.
///
/// Migrations are registered between adjacent versions only, so the table is
/// keyed by source version and every chain is just a walk of consecutive
/// version IDs.
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
    /// [`MAX_VERSION_ID`], or if a migration out of `A` has already been
    /// registered.
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

        let migration = FnMigration::<S, A, B>::new(f);
        let sch_tbl = self.tbl.entry(S::KEY).or_default();
        let inserted = sch_tbl.insert(A::VERSION, Box::new(migration));
        assert!(
            inserted,
            "schema/migrator: duplicate migration out of version {}",
            A::VERSION
        );
    }

    /// Looks up the migration out of a version, if there is one.
    fn get_migrator_from(&self, sch_key: &str, from_id: VersionId) -> Option<&dyn Migration> {
        self.tbl.get(sch_key)?.get(from_id)
    }

    /// Performs a single migration, taking the value from `A` to `B`.
    pub fn migrate_once<S: Schema, A: SchemaVersion<S>, B: SchemaVersion<S>>(
        &self,
        buf: &[u8],
    ) -> Result<Vec<u8>, MigrationError> {
        let m = self
            .get_migrator_from(S::KEY, A::VERSION)
            .ok_or(MigrationError::NoPath {
                schema: S::KEY,
                from: A::VERSION,
                to: B::VERSION,
            })?;

        let val = m.decode_src(buf)?;
        let val = m.apply(val)?;
        m.encode_dst(val.as_ref())
    }

    /// Applies every migration reachable from the container's version, leaving
    /// the result as a value rather than re-encoding it.
    ///
    /// Returns `None` if no migrations applied at all, in which case the
    /// container is already at the highest version we know about and its
    /// payload should be used as-is.
    fn migrate_up_from_cont<S: Schema>(
        &self,
        cont: &impl ValueContainer,
    ) -> Result<Option<MigratedValue<'_>>, MigrationError> {
        let Some(sch_tbl) = self.tbl.get(S::KEY) else {
            return Ok(None);
        };

        // Walk the chain of adjacent migrations from the container's version.
        // TODO(trey): make this not alloc a vec here, that's silly
        let mut chain: Vec<&dyn Migration> = Vec::new();
        let mut version = cont.version();
        while let Some(m) = sch_tbl.get(version) {
            chain.push(m);
            // `register` caps versions at `MAX_VERSION_ID`, so the lookup above
            // can never succeed where this would overflow.
            version += 1;
        }

        let Some(last) = chain.last().copied() else {
            return Ok(None);
        };

        // Decode once at the head, then stay in value space.
        let mut value = chain[0].decode_src(cont.payload())?;
        for m in &chain {
            value = m.apply(value)?;
        }

        Ok(Some(MigratedValue {
            version,
            value,
            last,
        }))
    }

    /// Migrates the value contained in the container until we run out of
    /// migrations to apply, returning a new [`OwnedValueContainer`].
    ///
    /// A container that is already at the highest version, or whose schema has
    /// no migrations registered at all, is returned unchanged.
    pub fn migrate_all_the_way<S: Schema>(
        &self,
        cont: &impl ValueContainer,
    ) -> Result<OwnedValueContainer, MigrationError> {
        match self.migrate_up_from_cont::<S>(cont)? {
            None => Ok(OwnedValueContainer::from_container(cont)),
            Some(mv) => {
                let buf = mv.last.encode_dst(mv.value.as_ref())?;
                Ok(OwnedValueContainer::new(mv.version, buf))
            }
        }
    }

    /// Migrates the value contained in the container as far as it goes and
    /// decodes it as `V`, which must be the version the chain ends at.
    ///
    /// This never re-encodes the migrated value, so it is the fn to reach for
    /// when reading a stored value into memory.
    // FIXME(trey): I don't know if this is actually doing the thing we want it
    // to do, do we only want to migrate it "as far as" V?
    pub fn migrate_and_decode<S: Schema, V: SchemaVersion<S>>(
        &self,
        cont: &impl ValueContainer,
    ) -> Result<V, MigrationError> {
        match self.migrate_up_from_cont::<S>(cont)? {
            // Nothing to migrate, so decode the container's payload directly.
            None => {
                if cont.version() != V::VERSION {
                    return Err(MigrationError::NoPath {
                        schema: S::KEY,
                        from: cont.version(),
                        to: V::VERSION,
                    });
                }

                V::decode_payload(cont.payload()).map_err(MigrationError::payload)
            }

            Some(mv) => {
                let version = mv.version;

                // If it didn't change then we couldn't figure out the path and
                // something is probably misconfigured.
                // TODO(trey): should this just panic?
                if version != V::VERSION {
                    return Err(MigrationError::NoPath {
                        schema: S::KEY,
                        from: mv.version,
                        to: V::VERSION,
                    });
                }

                mv.downcast::<V>()
                    .map(|v| *v)
                    .ok_or_else(|| MigrationError::ChainTypeMismatch {
                        schema: S::KEY,
                        at: version,
                    })
            }
        }
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
