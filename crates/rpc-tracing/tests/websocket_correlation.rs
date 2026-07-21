//! WebSocket transport-correlation tests.

mod support;

use http::{HeaderMap, HeaderValue};
use jsonrpsee::core::client::{ClientT, Error as RpcClientError};
use jsonrpsee::core::params::BatchRequestBuilder;
use jsonrpsee::rpc_params;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::ErrorObject;
use jsonrpsee::ws_client::WsClientBuilder;
use opentelemetry::Value;
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry_sdk::trace::SpanData;
use serde_json as _;
use strata_rpc_tracing::{
    TracedWsClient, http_trace_context_server_middleware, rpc_trace_context_server_middleware,
    rpc_trace_context_ws_client_middleware,
};
use support::{TestTracing, assert_parent_child, find_named_span, find_rpc_span};
use tower as _;
use tracing::Instrument;

#[tokio::test(flavor = "current_thread")]
async fn reused_websocket_propagates_each_rpc_operation() {
    const HANDSHAKE_TRACE_ID: &str = "11111111111111111111111111111111";
    const HANDSHAKE_TRACEPARENT: &str = "00-11111111111111111111111111111111-2222222222222222-01";

    let tracing = TestTracing::init("strata-rpc-tracing-websocket-test");
    let server = ServerBuilder::new()
        .set_http_middleware(http_trace_context_server_middleware())
        .set_rpc_middleware(rpc_trace_context_server_middleware())
        .build("127.0.0.1:0")
        .await
        .expect("WebSocket test server should start");
    let server_address = server
        .local_addr()
        .expect("WebSocket test server should expose its address");

    let mut module = RpcModule::new(());
    module
        .register_method("first", |_, _, _| 1_u64)
        .expect("first method should register");
    module
        .register_method("second", |_, _, _| 2_u64)
        .expect("second method should register");
    module
        .register_method("fail", |_, _, _| {
            ErrorObject::owned(-32042, "request rejected", None::<()>)
        })
        .expect("failing method should register");
    module
        .register_method("handshake_only", |_, _, _| "untraced")
        .expect("handshake-only method should register");
    let server_handle = server.start(module);
    let server_url = format!("ws://{server_address}");

    let mut handshake_headers = HeaderMap::new();
    handshake_headers.insert(
        "traceparent",
        HeaderValue::from_static(HANDSHAKE_TRACEPARENT),
    );
    let client: TracedWsClient = WsClientBuilder::default()
        .set_headers(handshake_headers.clone())
        .set_rpc_middleware(rpc_trace_context_ws_client_middleware())
        .build(&server_url)
        .await
        .expect("traced WebSocket client should connect");

    let first_caller = tracing::info_span!("first_operation", otel.name = "first_operation");
    let first: u64 = async { client.request("first", rpc_params![]).await }
        .instrument(first_caller.clone())
        .await
        .expect("first request should succeed");
    assert_eq!(first, 1);

    let second_caller = tracing::info_span!("second_operation", otel.name = "second_operation");
    let second: u64 = async { client.request("second", rpc_params![]).await }
        .instrument(second_caller.clone())
        .await
        .expect("second request should succeed");
    assert_eq!(second, 2);

    let notification_caller = tracing::info_span!(
        "notification_operation",
        otel.name = "notification_operation"
    );
    async { client.notification("notify", rpc_params![]).await }
        .instrument(notification_caller.clone())
        .await
        .expect("notification should be sent");

    let mut batch = BatchRequestBuilder::new();
    batch
        .insert("first", rpc_params![])
        .expect("first batch entry should serialize");
    batch
        .insert("second", rpc_params![])
        .expect("second batch entry should serialize");
    let batch_caller = tracing::info_span!("batch_operation", otel.name = "batch_operation");
    let batch_response = async { client.batch_request::<u64>(batch).await }
        .instrument(batch_caller.clone())
        .await
        .expect("batch request should succeed");
    assert_eq!(batch_response.num_successful_calls(), 2);

    let error = client
        .request::<String, _>("fail", rpc_params![])
        .await
        .expect_err("failing request should return an error");
    assert!(matches!(
        error,
        RpcClientError::Call(ref error) if error.code() == -32042
    ));

    let handshake_only_client = WsClientBuilder::default()
        .set_headers(handshake_headers)
        .build(&server_url)
        .await
        .expect("handshake-only WebSocket client should connect");
    let response: String = handshake_only_client
        .request("handshake_only", rpc_params![])
        .await
        .expect("handshake-only request should succeed");
    assert_eq!(response, "untraced");

    drop(handshake_only_client);
    drop(client);
    drop(first_caller);
    drop(second_caller);
    drop(notification_caller);
    drop(batch_caller);
    server_handle
        .stop()
        .expect("WebSocket test server should stop");
    server_handle.stopped().await;
    let spans = tracing.finish();

    let first_server = assert_rpc_chain(&spans, "first_operation", "first");
    let second_server = assert_rpc_chain(&spans, "second_operation", "second");
    assert_ne!(
        first_server.span_context.trace_id(),
        second_server.span_context.trace_id()
    );
    for server_span in [first_server, second_server] {
        assert_ne!(
            server_span.span_context.trace_id().to_string(),
            HANDSHAKE_TRACE_ID
        );
    }

    assert_rpc_chain(&spans, "notification_operation", "notify");

    let batch_caller = find_named_span(&spans, "batch_operation");
    let batch_client = find_span(&spans, SpanKind::Client, "jsonrpc");
    let batch_server = find_span(&spans, SpanKind::Server, "jsonrpc");
    assert_parent_child(batch_caller, batch_client);
    assert_parent_child(batch_client, batch_server);
    assert!(batch_server.parent_span_is_remote);

    let failing_client = find_rpc_span(&spans, SpanKind::Client, "fail");
    let failing_server = find_rpc_span(&spans, SpanKind::Server, "fail");
    assert_parent_child(failing_client, failing_server);
    assert_rpc_error_code(failing_client, "-32042");
    assert_rpc_error_code(failing_server, "-32042");

    let handshake_only_server = find_rpc_span(&spans, SpanKind::Server, "handshake_only");
    assert_ne!(
        handshake_only_server.span_context.trace_id().to_string(),
        HANDSHAKE_TRACE_ID
    );
    assert!(!handshake_only_server.parent_span_is_remote);
}

fn assert_rpc_chain<'a>(spans: &'a [SpanData], caller_name: &str, method: &str) -> &'a SpanData {
    let caller = find_named_span(spans, caller_name);
    let client = find_rpc_span(spans, SpanKind::Client, method);
    let server = find_rpc_span(spans, SpanKind::Server, method);
    assert_parent_child(caller, client);
    assert_parent_child(client, server);
    assert!(server.parent_span_is_remote);
    server
}

fn find_span<'a>(spans: &'a [SpanData], span_kind: SpanKind, span_name: &str) -> &'a SpanData {
    spans
        .iter()
        .find(|span| span.span_kind == span_kind && span.name == span_name)
        .unwrap_or_else(|| panic!("{span_kind:?} span `{span_name}` should be exported"))
}

fn assert_rpc_error_code(span: &SpanData, expected_error_code: &str) {
    let expected_value = Value::String(expected_error_code.to_owned().into());
    for attribute_name in ["rpc.response.status_code", "error.type"] {
        assert!(
            span.attributes.iter().any(|attribute| {
                attribute.key.as_str() == attribute_name && attribute.value == expected_value
            }),
            "span should record `{attribute_name}` as `{expected_error_code}`"
        );
    }
    assert!(matches!(&span.status, Status::Error { .. }));
}
