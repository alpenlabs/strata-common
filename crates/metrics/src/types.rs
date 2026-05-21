//! Configuration types for metrics exporters.

use std::net::SocketAddr;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;

/// Configuration for OTLP exporter retry and timeout.
#[derive(Debug, Clone)]
pub struct OtlpExportConfig {
    /// Timeout for export requests.
    pub timeout: Duration,
    /// Maximum number of retry attempts.
    pub max_retries: u32,
}

impl Default for OtlpExportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_retries: 3,
        }
    }
}

/// Metrics exporter configuration.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum MetricsConfig {
    /// Preserve default metrics behavior for the configured backend.
    ///
    /// When an OTLP endpoint is configured, this installs the OTLP metrics
    /// recorder. Otherwise, it leaves metrics disabled.
    #[default]
    Default,
    /// Do not install a `metrics` recorder.
    Disabled,
    /// Export metrics through the configured OTLP endpoint.
    Otlp,
    /// Expose metrics through a Prometheus scrape endpoint.
    Prometheus {
        /// Address used by the Prometheus HTTP listener.
        listen_addr: SocketAddr,
    },
    /// Export metrics through OTLP and expose them through Prometheus.
    OtlpAndPrometheus {
        /// Address used by the Prometheus HTTP listener.
        listen_addr: SocketAddr,
    },
}

impl MetricsConfig {
    /// Builds a metrics configuration from explicit exporter inputs.
    pub const fn from_exporters(
        otlp_enabled: bool,
        prometheus_listen_addr: Option<SocketAddr>,
    ) -> Self {
        match (otlp_enabled, prometheus_listen_addr) {
            (true, Some(listen_addr)) => Self::OtlpAndPrometheus { listen_addr },
            (true, None) => Self::Otlp,
            (false, Some(listen_addr)) => Self::Prometheus { listen_addr },
            (false, None) => Self::Disabled,
        }
    }

    /// Resolves default behavior against the configured OTLP endpoint.
    pub const fn resolve(self, otlp_endpoint_configured: bool) -> Self {
        match (self, otlp_endpoint_configured) {
            (Self::Default, true) => Self::Otlp,
            (Self::Default, false) => Self::Disabled,
            (config, _) => config,
        }
    }

    /// Returns `true` when this config explicitly enables a metrics recorder.
    pub const fn is_explicitly_enabled(self) -> bool {
        matches!(
            self,
            Self::Otlp | Self::Prometheus { .. } | Self::OtlpAndPrometheus { .. }
        )
    }

    /// Returns `true` when metrics should be exported over OTLP.
    pub const fn uses_otlp(self) -> bool {
        matches!(self, Self::Otlp | Self::OtlpAndPrometheus { .. })
    }

    /// Returns the Prometheus listener address, if configured.
    pub const fn prometheus_listen_addr(self) -> Option<SocketAddr> {
        match self {
            Self::Prometheus { listen_addr } | Self::OtlpAndPrometheus { listen_addr } => {
                Some(listen_addr)
            }
            Self::Default | Self::Disabled | Self::Otlp => None,
        }
    }
}

/// Resource attributes following OpenTelemetry semantic conventions.
#[derive(Debug, Clone)]
pub struct ResourceConfig {
    /// Service name.
    pub service_name: String,
    /// Service version.
    pub service_version: Option<String>,
    /// Deployment environment.
    pub deployment_environment: Option<String>,
    /// Service instance ID.
    pub service_instance_id: Option<String>,
    /// Additional custom attributes.
    pub custom_attributes: Vec<KeyValue>,
}

impl ResourceConfig {
    /// Creates a new resource configuration with the given service name.
    pub fn new(service_name: String) -> Self {
        Self {
            service_name,
            service_version: None,
            deployment_environment: None,
            service_instance_id: None,
            custom_attributes: Vec::new(),
        }
    }

    /// Builds an OpenTelemetry resource from config.
    pub fn build_resource(&self) -> Resource {
        let ResourceConfig {
            service_name,
            service_version,
            deployment_environment,
            service_instance_id,
            custom_attributes,
        } = self;

        let mut attributes = vec![KeyValue::new("service.name", service_name.clone())];

        if let Some(version) = service_version {
            attributes.push(KeyValue::new("service.version", version.clone()));
        }

        if let Some(env) = deployment_environment {
            attributes.push(KeyValue::new("deployment.environment", env.clone()));
        }

        if let Some(instance_id) = service_instance_id {
            attributes.push(KeyValue::new("service.instance.id", instance_id.clone()));
        }

        attributes.extend(custom_attributes.iter().cloned());

        Resource::builder().with_attributes(attributes).build()
    }
}

/// Process-level metrics initialization config.
#[derive(Debug, Clone)]
pub struct MetricsInitConfig {
    /// Resource configuration used for OTLP metrics.
    pub resource: ResourceConfig,
    /// OTLP endpoint URL.
    pub otlp_url: Option<String>,
    /// OTLP export configuration.
    pub otlp_export_config: OtlpExportConfig,
    /// Metrics exporter configuration.
    pub metrics_config: MetricsConfig,
    /// Name of the OpenTelemetry instrumentation scope used by the metrics
    /// facade bridge.
    pub meter_name: String,
}

impl MetricsInitConfig {
    /// Creates a metrics initialization config with defaults.
    pub fn new(service_name: String) -> Self {
        Self {
            resource: ResourceConfig::new(service_name),
            otlp_url: None,
            otlp_export_config: OtlpExportConfig::default(),
            metrics_config: MetricsConfig::default(),
            meter_name: "strata".to_string(),
        }
    }

    /// Sets the OTLP endpoint URL.
    pub fn with_otlp_url(mut self, url: String) -> Self {
        self.otlp_url = Some(url);
        self
    }

    /// Sets the metrics exporter configuration.
    pub fn with_metrics_config(mut self, config: MetricsConfig) -> Self {
        self.metrics_config = config;
        self
    }

    /// Sets the OTLP export configuration.
    pub fn with_otlp_export_config(mut self, config: OtlpExportConfig) -> Self {
        self.otlp_export_config = config;
        self
    }

    /// Sets the meter name used by the `metrics` facade to OpenTelemetry bridge.
    pub fn with_meter_name(mut self, name: String) -> Self {
        self.meter_name = name;
        self
    }
}
