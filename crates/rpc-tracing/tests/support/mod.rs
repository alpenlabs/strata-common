use std::sync::Once;

use opentelemetry::trace::{SpanKind, TracerProvider as _};
use opentelemetry::{Value, global};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tracing::subscriber::{DefaultGuard, set_default};
use tracing_subscriber::layer::SubscriberExt;

static INSTALL_PROPAGATOR: Once = Once::new();

pub(crate) struct TestTracing {
    exporter: InMemorySpanExporter,
    provider: SdkTracerProvider,
    subscriber_guard: Option<DefaultGuard>,
}

impl TestTracing {
    pub(crate) fn init(instrumentation_name: &'static str) -> Self {
        INSTALL_PROPAGATOR.call_once(|| {
            global::set_text_map_propagator(TraceContextPropagator::new());
        });

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = provider.tracer(instrumentation_name);
        let subscriber =
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));
        let subscriber_guard = set_default(subscriber);

        Self {
            exporter,
            provider,
            subscriber_guard: Some(subscriber_guard),
        }
    }

    pub(crate) fn finish(mut self) -> Vec<SpanData> {
        drop(self.subscriber_guard.take());
        self.provider
            .force_flush()
            .expect("test spans should flush");
        let spans = self
            .exporter
            .get_finished_spans()
            .expect("test spans should be readable");
        self.provider
            .shutdown()
            .expect("test tracer provider should shut down");
        spans
    }
}

pub(crate) fn find_named_span<'a>(spans: &'a [SpanData], span_name: &str) -> &'a SpanData {
    spans
        .iter()
        .find(|span| span.name == span_name)
        .unwrap_or_else(|| panic!("span `{span_name}` should be exported"))
}

pub(crate) fn find_rpc_span<'a>(
    spans: &'a [SpanData],
    span_kind: SpanKind,
    method: &str,
) -> &'a SpanData {
    let method_value = Value::String(method.to_owned().into());
    spans
        .iter()
        .find(|span| {
            span.span_kind == span_kind
                && span.attributes.iter().any(|attribute| {
                    attribute.key.as_str() == "rpc.method" && attribute.value == method_value
                })
        })
        .unwrap_or_else(|| panic!("{span_kind:?} span for `{method}` should be exported"))
}

pub(crate) fn assert_parent_child(parent: &SpanData, child: &SpanData) {
    assert_eq!(
        child.span_context.trace_id(),
        parent.span_context.trace_id()
    );
    assert_eq!(child.parent_span_id, parent.span_context.span_id());
}
