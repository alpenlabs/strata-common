//! Service instrumentation for automatic metrics and tracing.
//!
//! This module provides automatic OpenTelemetry-based instrumentation for all services
//! built with the service framework. It tracks:
//! - Message processing metrics (count, latency, errors)
//! - Service lifecycle metrics (launches, shutdowns)
//! - Distributed tracing with proper span hierarchy
//!
//! ## Design
//!
//! All services automatically get:
//! 1. Parent span wrapping entire service lifecycle
//! 2. Child spans for launch, message processing, shutdown
//! 3. Automatic metrics collection (counters and histograms)
//!
//! ## Naming Conventions
//!
//! Following OpenTelemetry Semantic Conventions:
//! - Span names: `{service_name}.{operation}` (e.g., `asm_worker.process_message`)
//! - Metric names: `service.{noun}.{unit}` (e.g., `service.messages.processed`)
//! - Attributes: snake_case (e.g., `service.name`, `operation.result`)

use std::time::Duration;

use opentelemetry::{
    global,
    metrics::{Counter, Histogram},
    KeyValue,
};
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

/// Service instrumentation context.
///
/// This struct encapsulates all OpenTelemetry instrumentation for a service,
/// including both tracing and metrics. It's automatically created in worker
/// tasks and used to record service lifecycle events.
///
/// Note: Tracing spans are created using the `tracing` crate, which integrates
/// with OpenTelemetry through the tracing-opentelemetry layer. Metrics are
/// created directly using the OpenTelemetry API.
pub struct ServiceInstrumentation {
    /// Pre-allocated service name attribute for reuse across metric recordings.
    /// This avoids allocating a new string on every metric call.
    service_name_attr: KeyValue,

    // Counters
    /// Counter for total messages processed.
    messages_processed: Counter<u64>,

    /// Counter for total service launches.
    launches_total: Counter<u64>,

    /// Counter for total service shutdowns.
    shutdowns_total: Counter<u64>,

    // Histograms
    /// Histogram for message processing duration.
    message_duration: Histogram<f64>,

    /// Histogram for service launch duration.
    launch_duration: Histogram<f64>,

    /// Histogram for service shutdown duration.
    shutdown_duration: Histogram<f64>,
}

impl ServiceInstrumentation {
    /// Creates a new service instrumentation context for a specific service.
    ///
    /// This uses the global OpenTelemetry provider to obtain meters and
    /// pre-allocates the service name attribute for efficient metric recording.
    ///
    /// # Arguments
    ///
    /// * `service_name` - Name of the service (from `ServiceState::name()`)
    ///
    /// # Panics
    ///
    /// This function may panic if the global OpenTelemetry provider is not properly
    /// initialized. Ensure `opentelemetry::global::set_meter_provider` is called
    /// at application startup.
    pub fn new(service_name: &str) -> Self {
        let meter = global::meter("strata-service");

        // Pre-allocate service name attribute to avoid allocations on every metric call
        let service_name_attr = KeyValue::new("service.name", service_name.to_string());

        // Create counters
        let messages_processed = meter
            .u64_counter("service.messages.processed")
            .with_description("Total number of messages processed by the service")
            .with_unit("messages")
            .init();

        let launches_total = meter
            .u64_counter("service.launches.total")
            .with_description("Total number of service launches")
            .with_unit("launches")
            .init();

        let shutdowns_total = meter
            .u64_counter("service.shutdowns.total")
            .with_description("Total number of service shutdowns")
            .with_unit("shutdowns")
            .init();

        // Create histograms with reasonable buckets optimized for typical latencies
        // Message processing: 1ms to 60s range (0.001, 0.01, 0.1, 1, 10, 60)
        let message_duration = meter
            .f64_histogram("service.message.duration")
            .with_description("Duration of message processing")
            .with_unit("s")
            .with_boundaries(vec![0.001, 0.01, 0.1, 1.0, 10.0, 60.0])
            .init();

        // Launch: typically sub-second to a few seconds (0.01, 0.1, 1, 5, 10)
        let launch_duration = meter
            .f64_histogram("service.launch.duration")
            .with_description("Duration of service launch phase")
            .with_unit("s")
            .with_boundaries(vec![0.01, 0.1, 1.0, 5.0, 10.0])
            .init();

        // Shutdown: typically very fast (0.001, 0.01, 0.1, 1, 5)
        let shutdown_duration = meter
            .f64_histogram("service.shutdown.duration")
            .with_description("Duration of service shutdown phase")
            .with_unit("s")
            .with_boundaries(vec![0.001, 0.01, 0.1, 1.0, 5.0])
            .init();

        Self {
            service_name_attr,
            messages_processed,
            launches_total,
            shutdowns_total,
            message_duration,
            launch_duration,
            shutdown_duration,
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
    /// * `service_name` - Name of the service (from `ServiceState::name()`)
    /// * `service_type` - Type of service ("async" or "sync")
    ///
    /// # Returns
    ///
    /// A tracing span that should be entered immediately and held for the
    /// service lifetime.
    pub fn create_lifecycle_span(
        &self,
        service_name: &str,
        service_type: &'static str,
    ) -> TracingSpan {
        tracing::info_span!(
            "service.lifecycle",
            service.name = %service_name,
            service.type = %service_type,
        )
    }

    /// Records a message processing operation.
    ///
    /// This increments the messages processed counter and records the duration
    /// histogram. The service name is pre-allocated in the struct to avoid
    /// allocations on every call.
    ///
    /// # Arguments
    ///
    /// * `duration` - Time taken to process the message
    /// * `result` - Whether the processing succeeded or failed
    pub fn record_message(&self, duration: Duration, result: OperationResult) {
        let attrs = &[
            self.service_name_attr.clone(),
            KeyValue::new("operation.result", result.as_str()),
        ];

        self.messages_processed.add(1, attrs);
        self.message_duration
            .record(duration.as_secs_f64(), attrs);
    }

    /// Records a service launch operation.
    ///
    /// This increments the launches counter and records the duration histogram.
    /// The service name is pre-allocated in the struct to avoid allocations.
    ///
    /// # Arguments
    ///
    /// * `duration` - Time taken to launch the service
    /// * `result` - Whether the launch succeeded or failed
    pub fn record_launch(&self, duration: Duration, result: OperationResult) {
        let attrs = &[
            self.service_name_attr.clone(),
            KeyValue::new("operation.result", result.as_str()),
        ];

        self.launches_total.add(1, attrs);
        self.launch_duration.record(duration.as_secs_f64(), attrs);
    }

    /// Records a service shutdown operation.
    ///
    /// This increments the shutdowns counter and records the duration histogram.
    /// The service name is pre-allocated in the struct to avoid allocations.
    ///
    /// # Arguments
    ///
    /// * `duration` - Time taken to shut down the service
    /// * `reason` - Reason for shutdown (normal, error, signal)
    pub fn record_shutdown(&self, duration: Duration, reason: ShutdownReason) {
        let attrs = &[
            self.service_name_attr.clone(),
            KeyValue::new("shutdown.reason", reason.as_str()),
        ];

        self.shutdowns_total.add(1, attrs);
        self.shutdown_duration.record(duration.as_secs_f64(), attrs);
    }
}

impl std::fmt::Debug for ServiceInstrumentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceInstrumentation")
            .field("service_name_attr", &self.service_name_attr)
            .field("messages_processed", &"<counter>")
            .field("launches_total", &"<counter>")
            .field("shutdowns_total", &"<counter>")
            .field("message_duration", &"<histogram>")
            .field("launch_duration", &"<histogram>")
            .field("shutdown_duration", &"<histogram>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
