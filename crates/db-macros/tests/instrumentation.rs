//! Integration tests for the `tracing_component` instrumentation of `#[gen_proxy]`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use strata_db_macros::gen_proxy;
use tokio::runtime::Handle;
// `proc_macro2`/`quote`/`syn` are normal dependencies of `strata-db-macros` (the
// proc-macro crate) and are visible to — but unused by — this integration target;
// silence the workspace `unused_crate_dependencies` lint.
use {proc_macro2 as _, quote as _, syn as _};

/// Result alias mirroring the `DbResult<T>` shape used by real database traits.
type DbResult<T> = Result<T, DbError>;

/// Error type that can absorb a blocking-task join failure.
#[derive(Debug)]
enum DbError {
    // The payload is only surfaced via `Debug`; no test in this file inspects it.
    #[expect(dead_code, reason = "join detail only read through Debug")]
    Join(String),
}

impl From<tokio::task::JoinError> for DbError {
    fn from(err: tokio::task::JoinError) -> Self {
        DbError::Join(err.to_string())
    }
}

// An instrumented trait: the `tracing_component` argument wraps each method's blocking
// work in a tracing span. This exercises that the instrumented codegen compiles and
// behaves identically to the uninstrumented variant.
#[gen_proxy(error = DbError, tracing_component = "test:metric")]
trait MetricDb: Send + Sync + 'static {
    /// Records a value and returns the running total.
    fn record(&self, value: u64) -> DbResult<u64>;

    /// Returns the running total.
    fn total(&self) -> DbResult<u64>;
}

/// In-memory counter backing the trait.
struct MemCounter {
    value: AtomicU64,
}

impl MetricDb for MemCounter {
    fn record(&self, value: u64) -> DbResult<u64> {
        Ok(self.value.fetch_add(value, Ordering::SeqCst) + value)
    }

    fn total(&self) -> DbResult<u64> {
        Ok(self.value.load(Ordering::SeqCst))
    }
}

fn metric_proxy() -> MetricDbProxy {
    let db = Arc::new(MemCounter {
        value: AtomicU64::new(0),
    });
    MetricDbProxy::new(Handle::current(), db)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instrumented_variants_agree() {
    let proxy = metric_proxy();

    assert_eq!(proxy.record_blocking(5).unwrap(), 5);
    assert_eq!(proxy.record_async(3).await.unwrap(), 8);
    assert_eq!(proxy.total_chan().recv().await.unwrap(), 8);
}

// Captures `(span name, parent span name)` for every span created under the global
// subscriber, used to assert cross-thread span parenting.
static CAPTURED_SPANS: std::sync::Mutex<Vec<(String, Option<String>)>> =
    std::sync::Mutex::new(Vec::new());

struct CaptureLayer;

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        _attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let name = span.name().to_string();
            let parent = span.parent().map(|p| p.name().to_string());
            CAPTURED_SPANS.lock().unwrap().push((name, parent));
        }
    }
}

/// Installs the global `CaptureLayer` subscriber so spans created on `spawn_blocking`
/// threads are recorded too. Idempotent across tests: only the first call wins, but once
/// installed the layer captures spans process-wide.
fn install_capturing_subscriber() {
    use tracing_subscriber::layer::SubscriberExt;

    let subscriber = tracing_subscriber::registry().with(CaptureLayer);
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Asserts that a `record` span parented to `parent_name` was captured. Uses `any` so it is
/// robust to spans emitted by other concurrently-running tests sharing `CAPTURED_SPANS`.
fn assert_record_span_parented_to(parent_name: &str) {
    let captured = CAPTURED_SPANS.lock().unwrap();
    assert!(
        captured
            .iter()
            .any(|(name, parent)| name == "record" && parent.as_deref() == Some(parent_name)),
        "expected a `record` span parented to `{parent_name}`, got: {captured:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instrumented_span_is_parented_to_caller() {
    install_capturing_subscriber();

    let proxy = metric_proxy();

    // Issue the call from within a known parent span. `record_chan` captures the current
    // span synchronously (here, `caller_parent`); the spawned shim re-enters it before
    // creating the `record` span on the blocking thread.
    let parent = tracing::info_span!("caller_parent");
    let pending = parent.in_scope(|| proxy.record_chan(5));
    assert_eq!(pending.recv().await.unwrap(), 5);

    assert_record_span_parented_to("caller_parent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instrumented_span_generated_for_every_entrypoint() {
    use tracing::Instrument;

    install_capturing_subscriber();

    let proxy = metric_proxy();

    // `_blocking` runs the instrumented shim inline on the calling thread, so its `record`
    // span is created directly under the ambient current span.
    tracing::info_span!("caller_blocking").in_scope(|| proxy.record_blocking(1).unwrap());

    // `_chan` captures the current span synchronously and re-enters it on the blocking thread.
    let pending = tracing::info_span!("caller_chan").in_scope(|| proxy.record_chan(1));
    pending.recv().await.unwrap();

    // `_async` delegates to `_chan`, but the captured span must survive across the await:
    // instrument the future so the caller span is entered when the inner `_chan` call reads
    // `Span::current()`.
    proxy
        .record_async(1)
        .instrument(tracing::info_span!("caller_async"))
        .await
        .unwrap();

    // Every entrypoint must have produced a `record` span parented to its own caller.
    for caller in ["caller_blocking", "caller_chan", "caller_async"] {
        assert_record_span_parented_to(caller);
    }
}
