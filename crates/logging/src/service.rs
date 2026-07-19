//! Common logging and tracing initialization for binaries.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::info;

use super::{BoxedLayer, FileLoggingConfig, LoggerConfig, format_service_name, init_with_layers};

/// Owned, serde-serializable logging configuration.
///
/// This is the type binaries should embed in their own config structs (e.g. a
/// `[logging]` TOML section) or populate from CLI flags. Every field is
/// optional, so a partial or omitted section deserializes cleanly and falls
/// back to the crate defaults.
///
/// It carries only the operator-tunable subset of the settings. The two
/// binary-provided constants — the base service name and the default log-file
/// prefix — are passed to [`init`](Self::init) / [`init_with_layers`](Self::init_with_layers)
/// as arguments rather than serialized, so they never leak into a user's config
/// file.
///
/// Under the hood these methods build a [`LoggingInitConfigRef`] (the borrowed,
/// zero-copy view the init routines consume) and forward to
/// [`init_logging_from_config`] / [`init_logging_from_config_with_layers`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingInitConfig {
    /// Optional service label appended to the service name (e.g. `"prod"`, `"dev"`).
    pub service_label: Option<String>,
    /// OpenTelemetry OTLP collector endpoint. When set, OTLP export is enabled.
    pub otlp_url: Option<String>,
    /// Directory to write rolling log files into. When unset, file logging is disabled.
    pub log_dir: Option<PathBuf>,
    /// Filename prefix for rolling log files. Falls back to the binary's default prefix.
    pub log_file_prefix: Option<String>,
    /// Use JSON output format instead of the compact text format.
    pub json_format: Option<bool>,
    /// Extra `EnvFilter` directives applied before `RUST_LOG` (e.g. to silence
    /// noisy dependencies). Empty when omitted.
    pub extra_filter_directives: Vec<String>,
}

impl LoggingInitConfig {
    /// Initialize process-global logging from this config.
    ///
    /// `service_base_name` and `default_log_prefix` are binary-provided
    /// constants (not part of the serialized config). Must be called once from
    /// a process entrypoint, inside a Tokio runtime context when `otlp_url` is
    /// set (the OTLP exporter is built on the reactor).
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

/// Borrowed, zero-copy view of the parameters [`init_logging_from_config`]
/// consumes.
///
/// Prefer the owned [`LoggingInitConfig`] for config-file / CLI wiring. Reach
/// for this only when you are assembling the parameters transiently at the call
/// site (e.g. mixing borrowed CLI args with compile-time string literals) and
/// don't want an owning struct.
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
