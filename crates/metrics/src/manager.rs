//! Metrics recorder initialization and shutdown management.

#[cfg(feature = "otlp")]
use std::sync::OnceLock;

#[cfg(any(feature = "otlp", feature = "prometheus"))]
use metrics::Recorder;
#[cfg(feature = "otlp")]
use metrics_exporter_otel::OpenTelemetryRecorder;
#[cfg(feature = "prometheus")]
use metrics_exporter_prometheus::PrometheusBuilder;
#[cfg(any(feature = "otlp", feature = "prometheus"))]
use metrics_util::layers::FanoutBuilder;
#[cfg(feature = "otlp")]
use opentelemetry::InstrumentationScope;
#[cfg(feature = "otlp")]
use opentelemetry::global::set_meter_provider;
#[cfg(feature = "otlp")]
use opentelemetry::metrics::MeterProvider;
#[cfg(feature = "otlp")]
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
#[cfg(feature = "otlp")]
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tokio::runtime::Handle;
#[cfg(feature = "otlp")]
use tracing::error;
use tracing::{debug, info};

use crate::types::MetricsInitConfig;

/// Global meter provider for proper shutdown.
#[cfg(feature = "otlp")]
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

/// Metrics initialization error.
#[derive(Debug, thiserror::Error)]
pub enum MetricsInitError {
    /// OTLP metrics were requested but the crate was compiled without OTLP support.
    #[error("OTLP metrics exporter requested but strata-metrics was compiled without `otlp`")]
    OtlpDisabled,
    /// Prometheus metrics were requested but the crate was compiled without Prometheus support.
    #[error(
        "Prometheus metrics exporter requested but strata-metrics was compiled without `prometheus`"
    )]
    PrometheusDisabled,
    /// Failed to build the OTLP metrics exporter.
    #[error("failed to build OTLP metrics exporter: {0}")]
    BuildOtlpExporter(String),
    /// Failed to build the Prometheus metrics exporter.
    #[error("failed to build Prometheus metrics exporter: {0}")]
    BuildPrometheusExporter(String),
    /// Failed to install the process-global metrics recorder.
    #[error(
        "failed to install {recorder_name} metrics recorder because a global recorder is already installed"
    )]
    SetRecorder {
        /// Recorder backend name.
        recorder_name: &'static str,
    },
}

/// Initializes process-global metrics with the provided config.
///
/// Call this once from the process entrypoint. Library crates should not call
/// it; they should emit `metrics` instruments and rely on the binary to install
/// the recorder.
pub fn init(config: MetricsInitConfig, runtime_handle: &Handle) -> Result<(), MetricsInitError> {
    validate_enabled_features(&config)?;

    #[cfg(not(any(feature = "otlp", feature = "prometheus")))]
    let _ = runtime_handle;

    #[cfg(any(feature = "otlp", feature = "prometheus"))]
    let mut recorder_count = 0;
    #[cfg(any(feature = "otlp", feature = "prometheus"))]
    let mut fanout = FanoutBuilder::default();

    #[cfg(feature = "otlp")]
    if config.metrics_config.uses_otlp() {
        let otlp = build_otlp_metrics_recorder(&config, runtime_handle)?;
        fanout = fanout.add_recorder(otlp);
        recorder_count += 1;
    }

    #[cfg(feature = "prometheus")]
    if let Some(listen_addr) = config.metrics_config.prometheus_listen_addr() {
        let prometheus = build_prometheus_recorder(listen_addr, runtime_handle)?;
        fanout = fanout.add_recorder(prometheus);
        recorder_count += 1;
    }

    #[cfg(any(feature = "otlp", feature = "prometheus"))]
    if recorder_count > 0 {
        install_global_metrics_recorder(fanout.build(), "fanout")?;
    }

    if config.metrics_config.uses_otlp() {
        info!("using OpenTelemetry metrics output");
    }
    if let Some(listen_addr) = config.metrics_config.prometheus_listen_addr() {
        info!(%listen_addr, "using Prometheus metrics output");
    }

    Ok(())
}

fn validate_enabled_features(_config: &MetricsInitConfig) -> Result<(), MetricsInitError> {
    #[cfg(not(feature = "otlp"))]
    if _config.metrics_config.uses_otlp() {
        return Err(MetricsInitError::OtlpDisabled);
    }

    #[cfg(not(feature = "prometheus"))]
    if _config.metrics_config.prometheus_listen_addr().is_some() {
        return Err(MetricsInitError::PrometheusDisabled);
    }

    Ok(())
}

#[cfg(any(feature = "otlp", feature = "prometheus"))]
fn install_global_metrics_recorder<R>(
    recorder: R,
    recorder_name: &'static str,
) -> Result<(), MetricsInitError>
where
    R: Recorder + Sync + 'static,
{
    metrics::set_global_recorder(recorder)
        .map_err(|_source| MetricsInitError::SetRecorder { recorder_name })
}

#[cfg(feature = "otlp")]
fn build_otlp_metrics_recorder(
    config: &MetricsInitConfig,
    runtime_handle: &Handle,
) -> Result<OpenTelemetryRecorder, MetricsInitError> {
    let Some(otel_url) = config.metrics_config.otlp_endpoint() else {
        unreachable!("OTLP recorder is only built when an OTLP endpoint is configured");
    };

    let _runtime_guard = runtime_handle.enter();
    let metric_exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(otel_url)
        .with_timeout(config.otlp_export_config.timeout)
        .build()
        .map_err(|err| MetricsInitError::BuildOtlpExporter(err.to_string()))?;

    let mp = SdkMeterProvider::builder()
        .with_resource(config.resource.build_resource())
        .with_periodic_exporter(metric_exporter)
        .build();

    set_meter_provider(mp.clone());

    let meter_scope = InstrumentationScope::builder(config.meter_name.clone()).build();
    let recorder = OpenTelemetryRecorder::new(mp.meter_with_scope(meter_scope));

    if METER_PROVIDER.set(mp).is_err() {
        error!("failed to set global meter provider");
    }

    Ok(recorder)
}

#[cfg(feature = "prometheus")]
fn build_prometheus_recorder(
    listen_addr: std::net::SocketAddr,
    runtime_handle: &Handle,
) -> Result<metrics_exporter_prometheus::PrometheusRecorder, MetricsInitError> {
    let (recorder, exporter) = PrometheusBuilder::new()
        .with_http_listener(listen_addr)
        .build()
        .map_err(|err| MetricsInitError::BuildPrometheusExporter(err.to_string()))?;

    runtime_handle.spawn(exporter);

    Ok(recorder)
}

/// Shuts down the metrics subsystem, flushing pending OTLP metrics.
pub fn finalize() {
    info!("shutting down metrics");

    #[cfg(feature = "otlp")]
    if let Some(provider) = METER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            error!(err = %e, "failed to shut down meter provider");
        } else {
            info!("meter provider shut down successfully");
        }
    } else {
        debug!("no meter provider to shut down");
    }

    #[cfg(not(feature = "otlp"))]
    debug!("no meter provider to shut down");
}
