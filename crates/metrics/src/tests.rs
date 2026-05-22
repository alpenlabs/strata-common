//! Unit tests for the metrics subsystem.

use std::net::SocketAddr;

#[cfg(feature = "otlp")]
use opentelemetry::KeyValue;
use tracing::{info_span, subscriber};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry;

use super::metrics_layer::MetricsLayer;
use super::types::*;

#[cfg(feature = "otlp")]
#[test]
fn test_resource_config_new() {
    let config = ResourceConfig::new("test-service".to_string());
    assert_eq!(config.service_name, "test-service");
    assert_eq!(config.service_version, None);
    assert_eq!(config.deployment_environment, None);
    assert_eq!(config.service_instance_id, None);
    assert!(config.custom_attributes.is_empty());
}

#[cfg(feature = "otlp")]
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

#[cfg(feature = "otlp")]
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
    let otlp_endpoint = "http://127.0.0.1:4317".to_string();

    let disabled = MetricsConfig::default();
    assert!(!disabled.is_explicitly_enabled());
    assert!(!disabled.uses_otlp());
    assert_eq!(disabled.otlp_endpoint(), None);
    assert_eq!(disabled.prometheus_listen_addr(), None);
    assert_eq!(MetricsConfig::disabled(), disabled);

    let otlp = MetricsConfig::default().with_otlp_endpoint(otlp_endpoint.clone());
    assert!(otlp.is_explicitly_enabled());
    assert!(otlp.uses_otlp());
    assert_eq!(otlp.otlp_endpoint(), Some(otlp_endpoint.as_str()));
    assert_eq!(otlp.prometheus_listen_addr(), None);

    let prometheus = MetricsConfig::default().with_prometheus_listener(listen_addr);
    assert!(prometheus.is_explicitly_enabled());
    assert!(!prometheus.uses_otlp());
    assert_eq!(prometheus.otlp_endpoint(), None);
    assert_eq!(prometheus.prometheus_listen_addr(), Some(listen_addr));

    let fanout = MetricsConfig::from_exporters(Some(otlp_endpoint.clone()), Some(listen_addr));
    assert!(fanout.is_explicitly_enabled());
    assert!(fanout.uses_otlp());
    assert_eq!(fanout.otlp_endpoint(), Some(otlp_endpoint.as_str()));
    assert_eq!(fanout.prometheus_listen_addr(), Some(listen_addr));
}

#[test]
fn test_metrics_config_from_exporters() {
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 9615));
    let otlp_endpoint = "http://127.0.0.1:4317".to_string();

    assert_eq!(
        MetricsConfig::from_exporters(None, None),
        MetricsConfig::disabled()
    );
    assert_eq!(
        MetricsConfig::from_exporters(Some(otlp_endpoint.clone()), None),
        MetricsConfig {
            otlp_endpoint: Some(otlp_endpoint.clone()),
            prometheus_listener_addr: None,
        }
    );
    assert_eq!(
        MetricsConfig::from_exporters(None, Some(listen_addr)),
        MetricsConfig {
            otlp_endpoint: None,
            prometheus_listener_addr: Some(listen_addr),
        }
    );
    assert_eq!(
        MetricsConfig::from_exporters(Some(otlp_endpoint.clone()), Some(listen_addr)),
        MetricsConfig {
            otlp_endpoint: Some(otlp_endpoint),
            prometheus_listener_addr: Some(listen_addr),
        }
    );
}

#[test]
fn test_metrics_init_config_builder_pattern() {
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 9615));
    let otlp_endpoint = "http://127.0.0.1:4317".to_string();
    let config = MetricsInitConfig::new("test-service".to_string())
        .with_otlp_endpoint(otlp_endpoint.clone())
        .with_metrics_config(MetricsConfig::from_exporters(
            Some(otlp_endpoint.clone()),
            Some(listen_addr),
        ));

    #[cfg(feature = "otlp")]
    assert_eq!(config.resource.service_name, "test-service");
    assert_eq!(
        config.metrics_config,
        MetricsConfig::from_exporters(Some(otlp_endpoint), Some(listen_addr))
    );
}

#[test]
fn test_metrics_init_config_otlp_url_alias() {
    let otlp_endpoint = "http://127.0.0.1:4317".to_string();
    let config =
        MetricsInitConfig::new("test-service".to_string()).with_otlp_url(otlp_endpoint.clone());

    assert_eq!(
        config.metrics_config.otlp_endpoint(),
        Some(otlp_endpoint.as_str())
    );
}

#[cfg(feature = "otlp")]
#[test]
fn test_metrics_init_config_meter_name_builder() {
    let config = MetricsInitConfig::new("test-service".to_string())
        .with_meter_name("test-meter".to_string());

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
