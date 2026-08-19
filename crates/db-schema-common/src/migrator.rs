//! Migration support library.
#![allow(unused)]

use std::collections::*;
use std::marker::PhantomData;

use crate::containers::*;
use crate::types::*;

/// Opaque migration trait that we put behind a `Box<dyn Migration>` to hide the
/// schema version-specific generics in `FnMigration`.
trait Migration: 'static {
    fn migrate_encoded(&self, buf: &[u8]) -> Vec<u8>;

    // TODO(trey) figure out how to do this so that we don't have to decode and re-encode when
    // there's a plausible migration we could make work
    //
    //fn migrate_value(&self, val: Box<dyn Any>) -> Box<dyn Any>;
}

/// Handles migration mapping.
#[expect(missing_debug_implementations, reason = "it's not")]
pub struct Migrator {
    tbl: HashMap<&'static str, HashMap<(VersionId, VersionId), Box<dyn Migration>>>,
}

impl Migrator {
    /// Creates a new empty instance.
    pub fn new() -> Self {
        Self {
            tbl: HashMap::new(),
        }
    }

    /// Registers a migration fn.
    pub fn register<S: Schema, A: SchemaVersion<S>, B: SchemaVersion<S>>(&mut self, f: fn(A) -> B) {
        assert!(
            A::VERSION < B::VERSION,
            "schema/migrator: nonsensical versions"
        );

        let k = (A::VERSION, B::VERSION);
        let migration = FnMigration::new(f);
        let sch_tbl = self.tbl.entry(S::KEY).or_default();
        sch_tbl.insert(k, Box::new(migration));
    }

    fn migrate_once_internal(
        &self,
        sch_key: &str,
        from_id: VersionId,
        to_id: VersionId,
        buf: &[u8],
    ) -> Option<Vec<u8>> {
        let sch_tbl = self.tbl.get(sch_key)?;
        let migrator = sch_tbl.get(&(from_id, to_id))?;
        Some(migrator.migrate_encoded(buf))
    }

    /// Performs a single migration, taking the value from `A` to `B`, if this
    /// migration exists.
    pub fn migrate_once<S: Schema, A: SchemaVersion<S>, B: SchemaVersion<S>>(
        &self,
        buf: &[u8],
    ) -> Option<Vec<u8>> {
        self.migrate_once_internal(S::KEY, A::VERSION, B::VERSION, buf)
    }

    /// Migrates the value contained in the container until we run out of
    /// migrations to apply, returning a new [`OwnedValueContainer`].
    pub fn migrate_all_the_way<S: Schema>(
        &self,
        cont: &impl ValueContainer,
    ) -> Option<OwnedValueContainer> {
        let sch_tbl = self.tbl.get(S::KEY)?;
        let mut cur_ver = cont.version();

        // Repeatedly apply migrations.
        //
        // I hate how this looks.  It uses an `Option` and does a lot of allocs,
        // we could probably be better about this, but it's not that big of a
        // deal.
        let mut buf: Option<Vec<u8>> = None;
        while let Some(m) = sch_tbl.get(&(cur_ver, cur_ver + 1)) {
            let dbuf = m.migrate_encoded(buf.as_deref().unwrap_or(cont.payload()));
            cur_ver += 1;
            buf = Some(dbuf);
        }

        Some(OwnedValueContainer::new(cur_ver, buf.unwrap()))
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
    fn migrate_encoded(&self, buf: &[u8]) -> Vec<u8> {
        // TODO(trey): decode A, migrate to B, encode B
        unimplemented!()
    }
}
