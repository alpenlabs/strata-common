//! Metrics recorder initialization and shutdown management.

use std::net::SocketAddr;
use std::sync::OnceLock;

use metrics::Recorder;
use metrics_exporter_otel::OpenTelemetryRecorder;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::layers::FanoutBuilder;
use opentelemetry::InstrumentationScope;
use opentelemetry::global::set_meter_provider;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tracing::{debug, error, info};

use crate::types::MetricsInitConfig;

/// Global meter provider for proper shutdown.
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

/// Initializes process-global metrics with the provided config.
///
/// Call this once from the process entrypoint. Library crates should not call
/// it; they should emit `metrics` instruments and rely on the binary to install
/// the recorder.
pub fn init(config: MetricsInitConfig) {
    let metrics_config = config.metrics_config.resolve(config.otlp_url.is_some());
    let otlp_recorder = metrics_config
        .uses_otlp()
        .then(|| build_otlp_metrics_recorder(&config));
    let prometheus_recorder = metrics_config
        .prometheus_listen_addr()
        .map(build_prometheus_recorder);

    match (otlp_recorder, prometheus_recorder) {
        (Some(otlp), Some(prometheus)) => {
            let recorder = FanoutBuilder::default()
                .add_recorder(otlp)
                .add_recorder(prometheus)
                .build();
            install_global_metrics_recorder(recorder, "fanout");
        }
        (Some(otlp), None) => {
            install_global_metrics_recorder(otlp, "metrics-otel");
        }
        (None, Some(prometheus)) => {
            install_global_metrics_recorder(prometheus, "Prometheus");
        }
        (None, None) => {}
    }

    if metrics_config.uses_otlp() {
        info!("using OpenTelemetry metrics output");
    }
    if let Some(listen_addr) = metrics_config.prometheus_listen_addr() {
        info!(%listen_addr, "using Prometheus metrics output");
    }
}

fn install_global_metrics_recorder<R>(recorder: R, recorder_name: &str)
where
    R: Recorder + Sync + 'static,
{
    if let Err(e) = metrics::set_global_recorder(recorder) {
        panic!("metrics init: failed to install {recorder_name} metrics recorder: {e}");
    }
}

fn build_otlp_metrics_recorder(config: &MetricsInitConfig) -> OpenTelemetryRecorder {
    let Some(otel_url) = config.otlp_url.as_ref() else {
        panic!("metrics init: OTLP metrics requested without an OTLP endpoint URL");
    };

    let metric_exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(otel_url)
        .with_timeout(config.otlp_export_config.timeout)
        .build()
        .expect("metrics init: failed to build OTLP metric exporter");

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

    recorder
}

fn build_prometheus_recorder(
    listen_addr: SocketAddr,
) -> metrics_exporter_prometheus::PrometheusRecorder {
    tokio::runtime::Handle::try_current()
        .expect("metrics init: Prometheus metrics exporter requires an active Tokio runtime");

    let (recorder, exporter) = PrometheusBuilder::new()
        .with_http_listener(listen_addr)
        .build()
        .expect("metrics init: failed to build Prometheus metrics exporter");

    tokio::spawn(exporter);

    recorder
}

/// Shuts down the metrics subsystem, flushing pending OTLP metrics.
pub fn finalize() {
    info!("shutting down metrics");

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
