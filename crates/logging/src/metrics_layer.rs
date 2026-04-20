//! Tracing layer that records span busy/idle time as `metrics` histograms.

use std::time::{Duration, Instant};

use tracing::Subscriber;
use tracing::span::{Attributes, Id};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Per-span timing state tracked across enter/exit events.
struct SpanTiming {
    created_at: Instant,
    busy: Duration,
    last_entered: Instant,
}

/// A tracing [`Layer`] that records span busy/idle time as `metrics` histograms.
///
/// For every span that closes, two histograms are recorded (microseconds):
///
/// - `strata_span_busy_us{span="<name>"}` — time the span was actively executing.
/// - `strata_span_idle_us{span="<name>"}` — wall time the span existed but was not executing.
///
/// The layer always emits these via the `metrics` facade. If no recorder is
/// installed, the calls are cheap no-ops, but the per-span state is still
/// allocated. Callers who never run with a recorder should install this layer
/// conditionally (see [`LoggerConfig::enable_metrics_layer`][super::LoggerConfig]).
///
/// Timing assumes each span is entered and exited in balanced pairs, which is
/// the contract `tracing` guarantees for correctly instrumented async code.
#[derive(Debug)]
pub struct MetricsLayer;

impl<S> Layer<S> for MetricsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let now = Instant::now();
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanTiming {
                created_at: now,
                busy: Duration::ZERO,
                last_entered: now,
            });
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(timing) = span.extensions_mut().get_mut::<SpanTiming>()
        {
            timing.last_entered = Instant::now();
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(timing) = span.extensions_mut().get_mut::<SpanTiming>()
        {
            timing.busy += timing.last_entered.elapsed();
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id)
            && let Some(timing) = span.extensions().get::<SpanTiming>()
        {
            let total = timing.created_at.elapsed();
            let busy = timing.busy;
            let idle = total.saturating_sub(busy);
            let name = span.name().to_string();

            metrics::histogram!("strata_span_busy_us", "span" => name.clone())
                .record(busy.as_micros() as f64);
            metrics::histogram!("strata_span_idle_us", "span" => name)
                .record(idle.as_micros() as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing::{info_span, subscriber};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::registry;

    use super::*;

    /// Exercising the layer without a metrics recorder installed should not
    /// panic — `metrics::histogram!` is a no-op in that case.
    #[test]
    fn records_without_panicking_when_no_recorder_is_installed() {
        let subscriber = registry().with(MetricsLayer);
        subscriber::with_default(subscriber, || {
            let span = info_span!("test_span");
            let _guard = span.enter();
        });
    }
}
