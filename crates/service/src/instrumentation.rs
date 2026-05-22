//! Service instrumentation for automatic metrics and tracing.
//!
//! This module provides automatic instrumentation for all services built with
//! the service framework. It tracks:
//! - Message processing metrics (count, latency, errors)
//! - Service lifecycle metrics (launches, shutdowns)
//! - Distributed tracing with proper span hierarchy
//!
//! All services automatically get:
//! 1. Parent span wrapping entire service lifecycle
//! 2. Child spans for launch, message processing, shutdown
//! 3. Automatic metrics collection through the `metrics` facade

use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;

use metrics::{counter, describe_counter, describe_histogram, histogram};
use tracing::Span as TracingSpan;

/// Result of an operation (success or error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationResult {
    /// Operation completed successfully.
    Success,
    /// Operation failed with an error.
    Error,
}

impl OperationResult {
    /// Returns the string representation for metrics labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

impl Display for OperationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OperationResult {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "error" => Ok(Self::Error),
            _ => Err(format!("Invalid OperationResult: '{}'", s)),
        }
    }
}

impl From<bool> for OperationResult {
    fn from(success: bool) -> Self {
        if success {
            Self::Success
        } else {
            Self::Error
        }
    }
}

impl<T, E> From<&Result<T, E>> for OperationResult {
    fn from(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Success,
            Err(_) => Self::Error,
        }
    }
}

/// Reason for service shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Normal graceful shutdown.
    Normal,
    /// Shutdown due to error.
    Error,
    /// Shutdown due to external signal.
    Signal,
}

impl ShutdownReason {
    /// Returns the string representation for metrics labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Error => "error",
            Self::Signal => "signal",
        }
    }
}

impl Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ShutdownReason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "normal" => Ok(Self::Normal),
            "error" => Ok(Self::Error),
            "signal" => Ok(Self::Signal),
            _ => Err(format!("Invalid ShutdownReason: '{}'", s)),
        }
    }
}

/// Service instrumentation context.
///
/// This struct encapsulates the service name used when recording service
/// lifecycle metrics. Metrics are emitted through the `metrics` facade so the
/// process entrypoint can choose an OTLP, Prometheus, or fanout recorder.
pub struct ServiceInstrumentation {
    /// Service name label value reused across metric recordings.
    service_name: String,
}

impl ServiceInstrumentation {
    /// Creates a new service instrumentation context.
    pub fn new(service_name: &str) -> Self {
        describe_service_metrics();
        Self {
            service_name: service_name.to_owned(),
        }
    }

    /// Creates a lifecycle span wrapping the entire service lifetime.
    ///
    /// This should be created once at service startup and remain active until
    /// the service shuts down. All other spans (launch, message processing,
    /// shutdown) should be children of this span.
    ///
    /// # Arguments
    ///
    /// * `span_prefix` - Domain-specific prefix (e.g., "asm", "csm", "chain")
    /// * `service_name` - Name of the service (from `ServiceState::name()`)
    /// * `service_type` - Type of service ("async" or "sync")
    ///
    /// # Returns
    ///
    /// A tracing span that should be entered immediately and held for the
    /// service lifetime.
    pub fn create_lifecycle_span(
        &self,
        span_prefix: &str,
        service_name: &str,
        service_type: &'static str,
    ) -> TracingSpan {
        tracing::info_span!(
            target: "strata_service",
            parent: None,
            "service.lifecycle",
            span_prefix = %span_prefix,
            service.name = %service_name,
            service.type = %service_type,
        )
    }

    /// Records a message processing operation.
    pub fn record_message(&self, duration: Duration, result: OperationResult) {
        counter!(
            "strata_service_messages_processed_total",
            "service_name" => self.service_name.clone(),
            "operation_result" => result.as_str(),
        )
        .increment(1);
        histogram!(
            "strata_service_message_duration_seconds",
            "service_name" => self.service_name.clone(),
            "operation_result" => result.as_str(),
        )
        .record(duration.as_secs_f64());
    }

    /// Records a service launch operation.
    pub fn record_launch(&self, duration: Duration, result: OperationResult) {
        counter!(
            "strata_service_launches_total",
            "service_name" => self.service_name.clone(),
            "operation_result" => result.as_str(),
        )
        .increment(1);
        histogram!(
            "strata_service_launch_duration_seconds",
            "service_name" => self.service_name.clone(),
            "operation_result" => result.as_str(),
        )
        .record(duration.as_secs_f64());
    }

    /// Records a service shutdown operation.
    pub fn record_shutdown(&self, duration: Duration, reason: ShutdownReason) {
        counter!(
            "strata_service_shutdowns_total",
            "service_name" => self.service_name.clone(),
            "shutdown_reason" => reason.as_str(),
        )
        .increment(1);
        histogram!(
            "strata_service_shutdown_duration_seconds",
            "service_name" => self.service_name.clone(),
            "shutdown_reason" => reason.as_str(),
        )
        .record(duration.as_secs_f64());
    }
}

fn describe_service_metrics() {
    describe_counter!(
        "strata_service_messages_processed_total",
        "Total number of messages processed by the service"
    );
    describe_counter!(
        "strata_service_launches_total",
        "Total number of service launches"
    );
    describe_counter!(
        "strata_service_shutdowns_total",
        "Total number of service shutdowns"
    );
    describe_histogram!(
        "strata_service_message_duration_seconds",
        "Duration of message processing in seconds"
    );
    describe_histogram!(
        "strata_service_launch_duration_seconds",
        "Duration of service launch phase in seconds"
    );
    describe_histogram!(
        "strata_service_shutdown_duration_seconds",
        "Duration of service shutdown phase in seconds"
    );
}

/// Common logic for recording shutdown metrics and logging results.
///
/// This is called by both async and sync handle_shutdown functions after
/// executing the service's before_shutdown hook.
pub(crate) fn record_shutdown_result(
    service_name: &str,
    shutdown_result: anyhow::Result<()>,
    duration: Duration,
    instrumentation: &ServiceInstrumentation,
    shutdown_reason: ShutdownReason,
) {
    instrumentation.record_shutdown(duration, shutdown_reason);

    if let Err(e) = shutdown_result {
        tracing::error!(
            service.name = %service_name,
            %e,
            "unhandled error while shutting down"
        );
    } else {
        tracing::info!(
            service.name = %service_name,
            duration_ms = duration.as_millis(),
            "service shutdown completed"
        );
    }
}

impl std::fmt::Debug for ServiceInstrumentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceInstrumentation")
            .field("service_name", &self.service_name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_result_display() {
        assert_eq!(OperationResult::Success.to_string(), "success");
        assert_eq!(OperationResult::Error.to_string(), "error");
    }

    #[test]
    fn test_operation_result_from_str() {
        assert_eq!(
            "success".parse::<OperationResult>().unwrap(),
            OperationResult::Success
        );
        assert_eq!(
            "error".parse::<OperationResult>().unwrap(),
            OperationResult::Error
        );
        assert!("invalid".parse::<OperationResult>().is_err());
    }

    #[test]
    fn test_operation_result_from_bool() {
        assert_eq!(OperationResult::from(true), OperationResult::Success);
        assert_eq!(OperationResult::from(false), OperationResult::Error);
    }

    #[test]
    fn test_operation_result_from_result() {
        let ok_result: Result<(), &str> = Ok(());
        let err_result: Result<(), &str> = Err("error");

        assert_eq!(OperationResult::from(&ok_result), OperationResult::Success);
        assert_eq!(OperationResult::from(&err_result), OperationResult::Error);
    }

    #[test]
    fn test_operation_result_as_str() {
        assert_eq!(OperationResult::Success.as_str(), "success");
        assert_eq!(OperationResult::Error.as_str(), "error");
    }

    #[test]
    fn test_shutdown_reason_as_str() {
        assert_eq!(ShutdownReason::Normal.as_str(), "normal");
        assert_eq!(ShutdownReason::Error.as_str(), "error");
        assert_eq!(ShutdownReason::Signal.as_str(), "signal");
    }

    #[test]
    fn test_instrumentation_new_without_recorder() {
        let instrumentation = ServiceInstrumentation::new("test_service");

        assert_eq!(instrumentation.service_name, "test_service");
    }

    #[test]
    fn test_instrumentation_record_message() {
        let instrumentation = ServiceInstrumentation::new("test_service");

        instrumentation.record_message(Duration::from_millis(100), OperationResult::Success);
        instrumentation.record_message(Duration::from_millis(200), OperationResult::Error);
    }

    #[test]
    fn test_instrumentation_record_launch() {
        let instrumentation = ServiceInstrumentation::new("test_service");

        instrumentation.record_launch(Duration::from_millis(50), OperationResult::Success);
        instrumentation.record_launch(Duration::from_millis(100), OperationResult::Error);
    }

    #[test]
    fn test_instrumentation_record_shutdown() {
        let instrumentation = ServiceInstrumentation::new("test_service");

        instrumentation.record_shutdown(Duration::from_millis(10), ShutdownReason::Normal);
        instrumentation.record_shutdown(Duration::from_millis(20), ShutdownReason::Error);
        instrumentation.record_shutdown(Duration::from_millis(15), ShutdownReason::Signal);
    }

    #[test]
    fn test_lifecycle_span_creation() {
        let instrumentation = ServiceInstrumentation::new("test_service");

        let _async_span =
            instrumentation.create_lifecycle_span("test_service", "test_service", "async");
        let _sync_span =
            instrumentation.create_lifecycle_span("test_service", "test_service", "sync");
    }

    #[test]
    fn test_instrumentation_debug_impl() {
        let instrumentation = ServiceInstrumentation::new("test_service");

        let debug_str = format!("{:?}", instrumentation);
        assert!(debug_str.contains("ServiceInstrumentation"));
        assert!(debug_str.contains("service_name"));
    }

    #[test]
    fn test_multiple_instrumentation_instances() {
        let inst1 = ServiceInstrumentation::new("service1");
        let inst2 = ServiceInstrumentation::new("service2");

        inst1.record_message(Duration::from_millis(10), OperationResult::Success);
        inst2.record_message(Duration::from_millis(20), OperationResult::Success);

        assert_eq!(inst1.service_name, "service1");
        assert_eq!(inst2.service_name, "service2");
    }

    #[test]
    fn test_pre_allocated_service_name() {
        let instrumentation = ServiceInstrumentation::new("my_test_service");

        assert_eq!(instrumentation.service_name, "my_test_service");
    }
}
