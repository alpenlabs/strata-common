//! Configuration types for metrics exporters.

use std::net::SocketAddr;
#[cfg(feature = "otlp")]
use std::time::Duration;

#[cfg(feature = "otlp")]
use opentelemetry::KeyValue;
#[cfg(feature = "otlp")]
use opentelemetry_sdk::Resource;

/// Configuration for OTLP exporter retry and timeout.
#[cfg(feature = "otlp")]
#[derive(Debug, Clone)]
pub struct OtlpExportConfig {
    /// Timeout for export requests.
    pub timeout: Duration,
    /// Maximum number of retry attempts.
    pub max_retries: u32,
}

#[cfg(feature = "otlp")]
impl Default for OtlpExportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_retries: 3,
        }
    }
}

/// Metrics exporter configuration.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct MetricsConfig {
    /// OTLP endpoint URL used for push-based metrics export.
    pub otlp_endpoint: Option<String>,
    /// Address used by the Prometheus HTTP listener.
    pub prometheus_listener_addr: Option<SocketAddr>,
}

impl MetricsConfig {
    /// Creates a disabled metrics exporter configuration.
    pub const fn disabled() -> Self {
        Self {
            otlp_endpoint: None,
            prometheus_listener_addr: None,
        }
    }

    /// Builds a metrics configuration from explicit exporter inputs.
    pub fn from_exporters(
        otlp_endpoint: Option<String>,
        prometheus_listener_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            otlp_endpoint,
            prometheus_listener_addr,
        }
    }

    /// Sets the OTLP endpoint URL.
    pub fn with_otlp_endpoint(mut self, endpoint: String) -> Self {
        self.otlp_endpoint = Some(endpoint);
        self
    }

    /// Sets the Prometheus listener address.
    pub const fn with_prometheus_listener(mut self, listen_addr: SocketAddr) -> Self {
        self.prometheus_listener_addr = Some(listen_addr);
        self
    }

    /// Returns `true` when this config enables at least one metrics exporter.
    pub fn is_enabled(&self) -> bool {
        self.otlp_endpoint.is_some() || self.prometheus_listener_addr.is_some()
    }

    /// Returns `true` when this config explicitly enables a metrics recorder.
    pub fn is_explicitly_enabled(&self) -> bool {
        self.is_enabled()
    }

    /// Returns `true` when metrics should be exported over OTLP.
    pub fn uses_otlp(&self) -> bool {
        self.otlp_endpoint.is_some()
    }

    /// Returns the OTLP endpoint URL, if configured.
    pub fn otlp_endpoint(&self) -> Option<&str> {
        self.otlp_endpoint.as_deref()
    }

    /// Returns the Prometheus listener address, if configured.
    pub const fn prometheus_listen_addr(&self) -> Option<SocketAddr> {
        self.prometheus_listener_addr
    }
}

/// Resource attributes following OpenTelemetry semantic conventions.
#[cfg(feature = "otlp")]
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

#[cfg(feature = "otlp")]
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
    #[cfg(feature = "otlp")]
    pub resource: ResourceConfig,
    /// OTLP export configuration.
    #[cfg(feature = "otlp")]
    pub otlp_export_config: OtlpExportConfig,
    /// Name of the OpenTelemetry instrumentation scope used by the metrics
    /// facade bridge.
    #[cfg(feature = "otlp")]
    pub meter_name: String,
    /// Metrics exporter configuration.
    pub metrics_config: MetricsConfig,
}

impl MetricsInitConfig {
    /// Creates a metrics initialization config with defaults.
    pub fn new(service_name: String) -> Self {
        #[cfg(not(feature = "otlp"))]
        let _ = service_name;

        Self {
            #[cfg(feature = "otlp")]
            resource: ResourceConfig::new(service_name),
            #[cfg(feature = "otlp")]
            otlp_export_config: OtlpExportConfig::default(),
            #[cfg(feature = "otlp")]
            meter_name: "strata".to_string(),
            metrics_config: MetricsConfig::default(),
        }
    }

    /// Sets the OTLP endpoint URL.
    pub fn with_otlp_url(mut self, url: String) -> Self {
        self.metrics_config = self.metrics_config.with_otlp_endpoint(url);
        self
    }

    /// Sets the OTLP endpoint URL.
    pub fn with_otlp_endpoint(self, url: String) -> Self {
        self.with_otlp_url(url)
    }

    /// Sets the metrics exporter configuration.
    pub fn with_metrics_config(mut self, config: MetricsConfig) -> Self {
        self.metrics_config = config;
        self
    }

    /// Sets the OTLP export configuration.
    #[cfg(feature = "otlp")]
    pub fn with_otlp_export_config(mut self, config: OtlpExportConfig) -> Self {
        self.otlp_export_config = config;
        self
    }

    /// Sets the meter name used by the `metrics` facade to OpenTelemetry bridge.
    #[cfg(feature = "otlp")]
    pub fn with_meter_name(mut self, name: String) -> Self {
        self.meter_name = name;
        self
    }
}
