//! Process-level logging and tracing initialization.
//!
//! This crate installs global `tracing` state. Binaries should initialize it
//! once at process startup. Libraries should emit `tracing` spans/events and let
//! the owning binary decide where they are exported.

pub mod manager;
pub mod service;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export main types and functions
pub use manager::{BoxedLayer, finalize, init, init_with_layers};
pub use service::{
    LoggingInitConfig, init_logging_from_config, init_logging_from_config_with_layers,
};
// Re-export tracing-appender types for convenience
pub use tracing_appender::rolling::Rotation;
pub use types::{FileLoggingConfig, LoggerConfig, OtlpExportConfig, ResourceConfig, StdoutConfig};

/// Formats a service name with an optional label suffix.
pub fn format_service_name(base: &str, label: Option<&str>) -> String {
    match label {
        Some(label) => format!("{base}%{label}"),
        None => base.to_owned(),
    }
}
