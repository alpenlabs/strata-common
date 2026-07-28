//! Common logging and tracing initialization for binaries.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::info;

use super::{BoxedLayer, FileLoggingConfig, LoggerConfig, format_service_name, init_with_layers};

/// Configuration parameters for logging initialization.
///
/// Embed this in the binary's config struct (e.g. as a `[logging]` TOML
/// section) or populate it from CLI flags, then call [`init`](Self::init) /
/// [`init_with_layers`](Self::init_with_layers) once at process startup.
///
/// Every field is optional, so a partial section deserializes cleanly. For an
/// *omitted* section to also work, the embedding field must carry its own
/// `#[serde(default)]` (as in the example below) — the `#[serde(default)]` on
/// this struct only fills in missing fields once the section itself is
/// present. With everything unset, logs go to the console in compact text
/// format at `info` level (override via `RUST_LOG`); file logging and
/// OpenTelemetry export stay disabled until [`log_dir`](Self::log_dir) /
/// [`otlp_url`](Self::otlp_url) are set.
///
/// # Example
///
/// A `[logging]` section an operator might write:
///
/// ```toml
/// [logging]
/// service_label = "prod"
/// otlp_url = "http://localhost:4317"
/// log_dir = "/var/log/strata"
/// extra_filter_directives = ["jsonrpsee_server=warn"]
/// ```
///
/// Wiring it up in the binary — the `#[serde(default)]` on the field is what
/// lets the whole `[logging]` section be omitted:
///
/// ```no_run
/// use serde::Deserialize;
/// use strata_logging::LoggingInitConfig;
///
/// #[derive(Deserialize)]
/// struct Config {
///     #[serde(default)]
///     logging: LoggingInitConfig,
/// }
///
/// # fn load_config() -> Config { Config { logging: LoggingInitConfig::default() } }
/// let config: Config = load_config();
/// config.logging.init("strata-client", "strata");
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingInitConfig {
    /// Label identifying this deployment (e.g. `"prod"`, `"dev"`), appended to
    /// the base service name in log output and the OpenTelemetry
    /// `service.name`. When unset, the base name is used as-is.
    pub service_label: Option<String>,
    /// OpenTelemetry collector endpoint traces are exported to over gRPC
    /// (e.g. `"http://localhost:4317"`). When unset, no traces are exported.
    pub otlp_url: Option<String>,
    /// Directory to write rolling log files into, rotated daily. When unset,
    /// file logging is disabled.
    pub log_dir: Option<PathBuf>,
    /// Filename prefix for the rolling log files (they are named
    /// `<prefix>.<date>`). When unset, the binary's default prefix is used.
    pub log_file_prefix: Option<String>,
    /// Emit console logs as JSON instead of compact text. Defaults to compact
    /// text. File logs are unaffected and always use compact text.
    pub json_format: Option<bool>,
    /// Additional log-filter directives in `RUST_LOG` syntax (e.g.
    /// `"sp1_core_executor=warn"`), typically used to silence noisy
    /// dependencies by default. `RUST_LOG` still wins on conflicts.
    pub extra_filter_directives: Vec<String>,
}

impl LoggingInitConfig {
    /// Initializes process-global logging from this config.
    ///
    /// Call this once from the process entrypoint; libraries should emit
    /// `tracing` events and leave subscriber installation to the binary. When
    /// [`otlp_url`](Self::otlp_url) is set, this must run inside a Tokio
    /// runtime (the OTLP exporter runs on it), and the binary should call
    /// [`finalize`](crate::finalize) before exiting to flush pending spans.
    ///
    /// `service_base_name` is the service name reported in log output and
    /// OpenTelemetry metadata; `default_log_prefix` names the log files when
    /// [`log_file_prefix`](Self::log_file_prefix) is unset. Both are fixed
    /// per binary, which is why they are arguments here rather than fields
    /// in the serialized config.
    pub fn init(&self, service_base_name: &str, default_log_prefix: &str) {
        self.init_with_layers(service_base_name, default_log_prefix, Vec::new());
    }

    /// Like [`init`](Self::init), but installs additional subscriber layers.
    pub fn init_with_layers(
        &self,
        service_base_name: &str,
        default_log_prefix: &str,
        extra_layers: Vec<BoxedLayer>,
    ) {
        let extra_filter_directives: Vec<&str> = self
            .extra_filter_directives
            .iter()
            .map(String::as_str)
            .collect();
        init_logging_from_config_with_layers(
            LoggingInitConfigRef {
                service_base_name,
                service_label: self.service_label.as_deref(),
                otlp_url: self.otlp_url.as_deref(),
                log_dir: self.log_dir.as_ref(),
                log_file_prefix: self.log_file_prefix.as_deref(),
                json_format: self.json_format,
                default_log_prefix,
                extra_filter_directives: &extra_filter_directives,
            },
            extra_layers,
        );
    }
}

/// Zero-copy view of [`LoggingInitConfig`], consumed by
/// [`init_logging_from_config`] / [`init_logging_from_config_with_layers`].
///
/// Prefer [`LoggingInitConfig`] for config-file / CLI wiring. Reach for this
/// only when assembling the parameters transiently at the call site (e.g.
/// mixing CLI args with compile-time string literals).
#[derive(Debug)]
pub struct LoggingInitConfigRef<'a> {
    /// Base service name
    pub service_base_name: &'a str,
    /// Optional service label to append like prod or dev
    pub service_label: Option<&'a str>,
    /// OpenTelemetry OTLP endpoint URL
    pub otlp_url: Option<&'a str>,
    /// Directory for file-based logging
    pub log_dir: Option<&'a PathBuf>,
    /// Prefix for log file names
    pub log_file_prefix: Option<&'a str>,
    /// Use JSON format instead of compact
    pub json_format: Option<bool>,
    /// Default log file prefix if not specified in config
    pub default_log_prefix: &'a str,
    /// Extra `EnvFilter` directives to merge before `RUST_LOG`.
    ///
    /// Forwarded to [`LoggerConfig::extra_filter_directives`]. Use this from
    /// the binary to silence noisy dependencies (e.g.
    /// `["sp1_core_executor=warn", "jsonrpsee_server::server=warn"]`).
    pub extra_filter_directives: &'a [&'a str],
}

/// Initialize process-global logging from configuration with all standard setup.
///
/// This function encapsulates the common logging initialization logic used
/// across binaries. It should be called once from a process entrypoint, not
/// from libraries.
pub fn init_logging_from_config(config: LoggingInitConfigRef<'_>) {
    init_logging_from_config_with_layers(config, Vec::new());
}

/// Initialize process-global logging from configuration with extra subscriber layers.
///
/// This keeps logging initialization centralized while allowing companion crates
/// to provide tracing layers without making this crate depend on them.
pub fn init_logging_from_config_with_layers(
    config: LoggingInitConfigRef<'_>,
    extra_layers: Vec<BoxedLayer>,
) {
    // Construct service name with optional label
    let service_name = format_service_name(config.service_base_name, config.service_label);

    let mut lconfig = LoggerConfig::new(service_name);

    // Configure OTLP if URL provided
    if let Some(url) = config.otlp_url {
        lconfig.set_otlp_url(url.to_string());
    }

    // Configure file logging if log directory provided
    // TODO: `json_format` only applies to the console layer; file logs are
    // always compact even though `FileLoggingConfig::with_json_format` exists.
    // Consider exposing a knob for JSON file logs if a consumer needs it.
    let file_logging_config = config.log_dir.map(|dir| {
        let prefix = config
            .log_file_prefix
            .unwrap_or(config.default_log_prefix)
            .to_string();
        FileLoggingConfig::new(dir.clone(), prefix)
    });

    if let Some(file_config) = &file_logging_config {
        lconfig = lconfig.with_file_logging(file_config.clone());
    }

    // Configure JSON format if specified
    if let Some(json_format) = config.json_format {
        lconfig = lconfig.with_json_logging(json_format);
    }

    if !config.extra_filter_directives.is_empty() {
        lconfig =
            lconfig.with_extra_filter_directives(config.extra_filter_directives.iter().copied());
    }

    // Initialize logging
    init_with_layers(lconfig, extra_layers);

    // Log configuration after init
    if let Some(url) = config.otlp_url {
        info!(%url, "using OpenTelemetry tracing output");
    }
    if let Some(file_config) = &file_logging_config {
        info!(
            log_dir = %file_config.directory.display(),
            log_prefix = %file_config.file_name_prefix,
            "file logging enabled"
        );
    }
}
