//! Unit tests for the metrics subsystem.

use std::net::SocketAddr;

use opentelemetry::KeyValue;
use tracing::{info_span, subscriber};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry;

use super::metrics_layer::MetricsLayer;
use super::types::*;

#[test]
fn test_resource_config_new() {
    let config = ResourceConfig::new("test-service".to_string());
    assert_eq!(config.service_name, "test-service");
    assert_eq!(config.service_version, None);
    assert_eq!(config.deployment_environment, None);
    assert_eq!(config.service_instance_id, None);
    assert!(config.custom_attributes.is_empty());
}

#[test]
fn test_resource_config_build_minimal() {
    let config = ResourceConfig::new("test-service".to_string());
    let resource = config.build_resource();

    let attrs: Vec<_> = resource.iter().collect();
    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "service.name" && value.as_str() == "test-service")
    );
}

#[test]
fn test_resource_config_build_with_all_semantic_conventions() {
    let config = ResourceConfig {
        service_name: "test-service".to_string(),
        service_version: Some("1.0.0".to_string()),
        deployment_environment: Some("production".to_string()),
        service_instance_id: Some("instance-123".to_string()),
        custom_attributes: vec![
            KeyValue::new("custom.key1", "value1"),
            KeyValue::new("custom.key2", "value2"),
        ],
    };

    let resource = config.build_resource();
    let attrs: Vec<_> = resource.iter().collect();

    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "service.name" && value.as_str() == "test-service")
    );
    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "service.version" && value.as_str() == "1.0.0")
    );
    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "deployment.environment"
                && value.as_str() == "production")
    );
    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "service.instance.id"
                && value.as_str() == "instance-123")
    );
    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "custom.key1" && value.as_str() == "value1")
    );
    assert!(
        attrs
            .iter()
            .any(|(key, value)| key.as_str() == "custom.key2" && value.as_str() == "value2")
    );
}

#[test]
fn test_metrics_config_helpers() {
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 9615));

    assert!(!MetricsConfig::Default.is_explicitly_enabled());
    assert!(!MetricsConfig::Default.uses_otlp());
    assert_eq!(MetricsConfig::Default.prometheus_listen_addr(), None);
    assert_eq!(
        MetricsConfig::Default.resolve(false),
        MetricsConfig::Disabled
    );
    assert_eq!(MetricsConfig::Default.resolve(true), MetricsConfig::Otlp);

    assert!(!MetricsConfig::Disabled.is_explicitly_enabled());
    assert!(!MetricsConfig::Disabled.uses_otlp());
    assert_eq!(MetricsConfig::Disabled.prometheus_listen_addr(), None);

    assert!(MetricsConfig::Otlp.is_explicitly_enabled());
    assert!(MetricsConfig::Otlp.uses_otlp());
    assert_eq!(MetricsConfig::Otlp.prometheus_listen_addr(), None);

    let prometheus = MetricsConfig::Prometheus { listen_addr };
    assert!(prometheus.is_explicitly_enabled());
    assert!(!prometheus.uses_otlp());
    assert_eq!(prometheus.prometheus_listen_addr(), Some(listen_addr));

    let fanout = MetricsConfig::OtlpAndPrometheus { listen_addr };
    assert!(fanout.is_explicitly_enabled());
    assert!(fanout.uses_otlp());
    assert_eq!(fanout.prometheus_listen_addr(), Some(listen_addr));
}

#[test]
fn test_metrics_config_from_exporters() {
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 9615));

    assert_eq!(
        MetricsConfig::from_exporters(false, None),
        MetricsConfig::Disabled
    );
    assert_eq!(
        MetricsConfig::from_exporters(true, None),
        MetricsConfig::Otlp
    );
    assert_eq!(
        MetricsConfig::from_exporters(false, Some(listen_addr)),
        MetricsConfig::Prometheus { listen_addr }
    );
    assert_eq!(
        MetricsConfig::from_exporters(true, Some(listen_addr)),
        MetricsConfig::OtlpAndPrometheus { listen_addr }
    );
}

#[test]
fn test_metrics_init_config_builder_pattern() {
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 9615));
    let config = MetricsInitConfig::new("test-service".to_string())
        .with_otlp_url("http://127.0.0.1:4317".to_string())
        .with_metrics_config(MetricsConfig::Prometheus { listen_addr })
        .with_meter_name("test-meter".to_string());

    assert_eq!(config.resource.service_name, "test-service");
    assert_eq!(config.otlp_url, Some("http://127.0.0.1:4317".to_string()));
    assert_eq!(
        config.metrics_config,
        MetricsConfig::Prometheus { listen_addr }
    );
    assert_eq!(config.meter_name, "test-meter");
}

#[test]
fn span_metrics_layer_records_without_panicking_when_no_recorder_is_installed() {
    let subscriber = registry().with(MetricsLayer);
    subscriber::with_default(subscriber, || {
        let span = info_span!("test_span");
        let _guard = span.enter();
    });
}
