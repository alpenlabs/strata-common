//! Logging initialization and shutdown management.

use std::env;
use std::sync::OnceLock;

use metrics_exporter_otel::OpenTelemetryRecorder;
use opentelemetry::InstrumentationScope;
use opentelemetry::global::{set_meter_provider, set_text_map_propagator};
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::*;
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use super::metrics_layer::MetricsLayer;
use super::types::LoggerConfig;

/// Global tracer provider for proper shutdown
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Global meter provider for proper shutdown.
///
/// When the OTLP endpoint is configured, [`init`] builds an
/// [`SdkMeterProvider`] alongside the tracer provider, sets it as the global
/// meter provider, and installs a `metrics`-crate recorder that bridges
/// `metrics::counter!` / `gauge!` / `histogram!` calls into the OpenTelemetry
/// meter. This means hand-written `metrics::*!` calls, reth's free metrics,
/// span timings via [`MetricsLayer`], and `strata-service` framework
/// instrumentation all flow through one OpenTelemetry pipeline.
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

/// Initializes the logging subsystem with the provided config.
pub fn init(config: LoggerConfig) {
    // Set the global trace context propagator for distributed tracing
    set_text_map_propagator(TraceContextPropagator::new());

    // Build the filter from any consumer-supplied directives plus the value of
    // `RUST_LOG`. Consumers are expected to pass directives such as
    // `sp1_core_executor=warn` or `jsonrpsee_server::server=warn` themselves;
    // this crate is intentionally agnostic about which dependencies are noisy.
    // `RUST_LOG` still wins on conflicts because it is appended last.
    let filt = build_env_filter(
        &config.extra_filter_directives,
        env::var(EnvFilter::DEFAULT_ENV).ok().as_deref(),
    );

    // Configure stdout logging with JSON or compact format
    let stdout_sub = if config.stdout_config.json_format {
        layer()
            .json()
            .with_span_events(config.stdout_config.fmt_span)
            .with_filter(filt.clone())
            .boxed()
    } else {
        layer()
            .compact()
            .with_span_events(config.stdout_config.fmt_span)
            .with_filter(filt.clone())
            .boxed()
    };

    // Build optional file logging layer
    let file_layer = config.file_logging_config.as_ref().map(|file_config| {
        let file_appender = RollingFileAppender::new(
            file_config.rotation.clone(),
            &file_config.directory,
            &file_config.file_name_prefix,
        );

        if file_config.json_format {
            layer()
                .json()
                .with_writer(file_appender)
                .with_ansi(false) // No color codes in files
                .with_filter(filt.clone())
                .boxed()
        } else {
            layer()
                .compact()
                .with_writer(file_appender)
                .with_ansi(false) // No color codes in files
                .with_filter(filt.clone())
                .boxed()
        }
    });

    // Build optional OpenTelemetry layer plus the meter provider and the
    // metrics-crate recorder bridge. Both pipelines share the same OTLP gRPC
    // endpoint and Resource. The Collector demuxes by signal type.
    let otel_layer = config.otel_url.as_ref().map(|otel_url| {
        let resource = config.resource.build_resource();

        // Trace pipeline. tonic is the gRPC exporter; its underlying client
        // has built-in retry logic.
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(otel_url)
            .with_timeout(config.otlp_export_config.timeout)
            .build()
            .expect("init: failed to build OTLP span exporter");

        let tp = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter)
            .build();

        if TRACER_PROVIDER.set(tp.clone()).is_err() {
            error!("Failed to set global tracer provider");
        }

        // Metric pipeline. PeriodicReader exports on a default interval; the
        // SDK handles batching.
        let metric_exporter = MetricExporter::builder()
            .with_tonic()
            .with_endpoint(otel_url)
            .with_timeout(config.otlp_export_config.timeout)
            .build()
            .expect("init: failed to build OTLP metric exporter");

        let mp = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_periodic_exporter(metric_exporter)
            .build();

        set_meter_provider(mp.clone());

        // Bridge `metrics`-crate calls into the OpenTelemetry meter. After
        // this, every `metrics::counter!` / `gauge!` / `histogram!` site,
        // including reth's internals and the [`MetricsLayer`] span timings,
        // flows through OTLP push to the collector. Using `meter_with_scope`
        // (instead of `global::meter`) lets the meter name come from a
        // runtime String without leaking via `&'static str`.
        let meter_scope = InstrumentationScope::builder(config.meter_name.clone()).build();
        let recorder = OpenTelemetryRecorder::new(mp.meter_with_scope(meter_scope));

        if METER_PROVIDER.set(mp).is_err() {
            error!("Failed to set global meter provider");
        }
        if let Err(e) = metrics::set_global_recorder(recorder) {
            error!(err = %e, "failed to install metrics-otel recorder");
        }

        let tt = tp.tracer("alpen-tracer");
        tracing_opentelemetry::layer().with_tracer(tt)
    });

    let metrics_layer = config.enable_metrics_layer.then_some(MetricsLayer);

    // Register all layers - with() accepts Option<Layer> so this scales cleanly
    tracing_subscriber::registry()
        .with(stdout_sub)
        .with(file_layer)
        .with(otel_layer)
        .with(metrics_layer)
        .init();

    info!(
        service_name = %config.resource.service_name,
        service_version = ?config.resource.service_version,
        deployment_environment = ?config.resource.deployment_environment,
        "logging initialized"
    );
}

fn build_env_filter(extra_directives: &[String], env_filter: Option<&str>) -> EnvFilter {
    let extras = extra_directives
        .iter()
        .map(String::as_str)
        .filter(|d| !d.trim().is_empty())
        .collect::<Vec<_>>()
        .join(",");

    let directives = match (extras.is_empty(), env_filter) {
        (true, Some(env)) if !env.trim().is_empty() => env.to_string(),
        (true, _) => String::new(),
        (false, Some(env)) if !env.trim().is_empty() => format!("{extras},{env}"),
        (false, _) => extras,
    };

    let builder = EnvFilter::builder().with_default_directive(tracing::Level::INFO.into());
    if directives.is_empty() {
        builder.parse_lossy("")
    } else {
        builder.parse_lossy(directives)
    }
}

/// Shuts down the logging subsystem, flushing pending spans and tearing down resources.
///
/// This function should be called before application exit to ensure all spans are flushed
/// to the OTLP collector. It will timeout after 10 seconds.
pub fn finalize() {
    info!("shutting down logging");

    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            error!(err = %e, "failed to shut down tracer provider");
        } else {
            info!("tracer provider shut down successfully");
        }
    } else {
        debug!("no tracer provider to shut down");
    }

    if let Some(provider) = METER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            error!(err = %e, "failed to shut down meter provider");
        } else {
            info!("meter provider shut down successfully");
        }
    } else {
        debug!("no meter provider to shut down");
    }
}
