//! Process-level metrics initialization.
//!
//! This crate installs the process-global `metrics` recorder and optional
//! metrics exporter tasks. Binaries should initialize it once at process
//! startup. Library crates should only emit metrics instruments.

pub mod manager;
pub mod metrics_layer;
pub mod types;

#[cfg(test)]
mod tests;

pub use manager::{finalize, init};
pub use metrics_layer::MetricsLayer;
pub use types::{MetricsConfig, MetricsInitConfig, OtlpExportConfig, ResourceConfig};
