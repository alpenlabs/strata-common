//! Integration tests for the `#[gen_proxy]` attribute macro.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use strata_db_macros::gen_proxy;
use tokio::runtime::Handle;
// `proc_macro2`/`quote`/`syn` (normal deps of the proc-macro crate) and the
// `tracing`/`tracing-subscriber` dev-deps (exercised by `tests/instrumentation.rs`) are
// visible to — but unused by — this integration target; silence the workspace
// `unused_crate_dependencies` lint.
use {proc_macro2 as _, quote as _, syn as _, tracing as _, tracing_subscriber as _};

/// Result alias mirroring the `DbResult<T>` shape used by real database traits.
type DbResult<T> = Result<T, DbError>;

/// Error type that can absorb a blocking-task join failure.
#[derive(Debug)]
enum DbError {
    NotFound,
    Join(String),
}

impl From<tokio::task::JoinError> for DbError {
    fn from(err: tokio::task::JoinError) -> Self {
        DbError::Join(err.to_string())
    }
}

#[gen_proxy(error = DbError)]
trait CounterDb: Send + Sync + 'static {
    /// Adds `by` to the counter and returns the new value.
    fn increment(&self, by: u64) -> DbResult<u64>;

    /// Returns the current counter value.
    fn get(&self) -> DbResult<u64>;

    /// Resets the counter to zero (exercises the unit-success path).
    fn reset(&self) -> DbResult<()>;

    /// Always fails (exercises the domain-error path).
    fn fail(&self) -> DbResult<u64>;

    /// Panics (exercises the `JoinError` mapping path).
    fn boom(&self) -> DbResult<u64>;

    /// Qualifies for proxying but is explicitly opted out via `#[gen_proxy(skip)]`,
    /// so only the trait method exists (no `*_blocking`/`*_async`/`*_chan` variants).
    #[gen_proxy(skip)]
    #[expect(dead_code, reason = "skipped and unused")]
    fn skipped(&self) -> DbResult<u64>;

    /// A non-`&self` method that should be left trait-only, not proxied.
    ///
    /// It carries `where Self: Sized` so the trait stays object-safe (the proxy
    /// holds a `dyn CounterDb`).
    fn describe() -> &'static str
    where
        Self: Sized,
    {
        "counter"
    }
}

/// In-memory counter backing the trait.
struct MemCounter {
    value: AtomicU64,
}

impl CounterDb for MemCounter {
    fn increment(&self, by: u64) -> DbResult<u64> {
        Ok(self.value.fetch_add(by, Ordering::SeqCst) + by)
    }

    fn get(&self) -> DbResult<u64> {
        Ok(self.value.load(Ordering::SeqCst))
    }

    fn reset(&self) -> DbResult<()> {
        self.value.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn fail(&self) -> DbResult<u64> {
        Err(DbError::NotFound)
    }

    fn boom(&self) -> DbResult<u64> {
        panic!("boom")
    }

    fn skipped(&self) -> DbResult<u64> {
        Ok(42)
    }
}

fn proxy() -> CounterDbProxy {
    let db = Arc::new(MemCounter {
        value: AtomicU64::new(0),
    });
    CounterDbProxy::new(Handle::current(), db)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_async_and_chan_variants_agree() {
    let proxy = proxy();

    // Blocking runs inline on the calling thread.
    assert_eq!(proxy.increment_blocking(5).unwrap(), 5);

    // Async offloads to a blocking task and awaits it.
    assert_eq!(proxy.increment_async(3).await.unwrap(), 8);

    // Channel variant returns a handle awaited via `recv`.
    let pending = proxy.get_chan();
    assert_eq!(pending.recv().await.unwrap(), 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unit_success_path() {
    let proxy = proxy();
    proxy.increment_blocking(7).unwrap();

    proxy.reset_async().await.unwrap();
    assert_eq!(proxy.get_blocking().unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_error_propagates() {
    let proxy = proxy();
    assert!(matches!(proxy.fail_async().await, Err(DbError::NotFound)));
    assert!(matches!(
        proxy.fail_chan().recv().await,
        Err(DbError::NotFound)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_panic_maps_to_join_error() {
    let proxy = proxy();
    match proxy.boom_async().await {
        Err(DbError::Join(msg)) => assert!(!msg.is_empty()),
        other => panic!("expected a join error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clone_shares_underlying_state() {
    let proxy = proxy();
    let clone = proxy.clone();

    clone.increment_blocking(10).unwrap();
    assert_eq!(proxy.get_async().await.unwrap(), 10);
}

#[test]
fn non_self_method_is_not_proxied() {
    // `describe` has no `&self` receiver, so only the trait method exists.
    assert_eq!(<MemCounter as CounterDb>::describe(), "counter");
}
