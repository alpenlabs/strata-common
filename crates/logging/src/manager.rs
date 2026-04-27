//! Logging initialization and shutdown management.

use std::sync::OnceLock;

use opentelemetry::global::set_text_map_propagator;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::*;
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::metrics_layer::MetricsLayer;
use super::types::LoggerConfig;

/// Global tracer provider for proper shutdown
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Initializes the logging subsystem with the provided config.
pub fn init(config: LoggerConfig) {
    // Set the global trace context propagator for distributed tracing
    set_text_map_propagator(TraceContextPropagator::new());

    // Default filter suppresses verbose SP1 executor logs below WARN (so TRACE, INFO and DEBUG
    // are filtered out).
    // It still allows further override via RUST_LOG.
    let filt = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy()
        .add_directive("sp1_core_executor=warn".parse().unwrap());

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

    // Build optional OpenTelemetry layer
    let otel_layer = config.otel_url.as_ref().map(|otel_url| {
        let resource = config.resource.build_resource();

        // Configure exporter with timeout. tonic is the gRPC exporter; the
        // underlying tonic client has built-in retry logic.
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(otel_url)
            .with_timeout(config.otlp_export_config.timeout)
            .build()
            .expect("init: failed to build OTLP span exporter");

        let tp = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build();

        // Store tracer provider for shutdown
        if TRACER_PROVIDER.set(tp.clone()).is_err() {
            error!("Failed to set global tracer provider");
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

/// Shuts down the logging subsystem, flushing pending spans and tearing down resources.
///
/// This function should be called before application exit to ensure all spans are flushed
/// to the OTLP collector. It will timeout after 10 seconds.
pub fn finalize() {
    info!("shutting down logging");

    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            error!("failed to shut down tracer provider: {:?}", e);
        } else {
            info!("tracer provider shut down successfully");
        }
    } else {
        // No OTLP configured, nothing to shut down
        debug!("no tracer provider to shut down");
    }
}
