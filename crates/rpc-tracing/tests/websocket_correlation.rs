//! WebSocket transport tests.
//!
//! Cross-service propagation over WebSocket requires per-message JSON-RPC
//! request extensions ([paritytech/jsonrpsee#1647]) and is intentionally not
//! performed yet. These tests pin the interim behavior: client spans are
//! created per operation, and the connection handshake headers never become
//! RPC span parents.
//!
//! [paritytech/jsonrpsee#1647]: https://github.com/paritytech/jsonrpsee/pull/1647

mod support;

use http::{HeaderMap, HeaderValue};
use jsonrpsee::core::client::{ClientT, Error as RpcClientError};
use jsonrpsee::rpc_params;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::ErrorObject;
use jsonrpsee::ws_client::WsClientBuilder;
use opentelemetry::Value;
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry_sdk::trace::SpanData;
use strata_rpc_tracing::{
    TracedWsClient, http_trace_context_server_middleware, rpc_trace_context_server_middleware,
    rpc_trace_context_ws_client_middleware,
};
use support::{TestTracing, assert_parent_child, find_named_span, find_rpc_span};
use tower as _;
use tracing::Instrument;

#[tokio::test(flavor = "current_thread")]
async fn websocket_operations_are_traced_without_handshake_parents() {
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
        .register_method("fail", |_, _, _| {
            ErrorObject::owned(-32042, "request rejected", None::<()>)
        })
        .expect("failing method should register");
    let server_handle = server.start(module);
    let server_url = format!("ws://{server_address}");

    let mut handshake_headers = HeaderMap::new();
    handshake_headers.insert(
        "traceparent",
        HeaderValue::from_static(HANDSHAKE_TRACEPARENT),
    );
    let client: TracedWsClient = WsClientBuilder::default()
        .set_headers(handshake_headers)
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

    let error = client
        .request::<String, _>("fail", rpc_params![])
        .await
        .expect_err("failing request should return an error");
    assert!(matches!(
        error,
        RpcClientError::Call(ref error) if error.code() == -32042
    ));

    drop(client);
    drop(first_caller);
    server_handle
        .stop()
        .expect("WebSocket test server should stop");
    server_handle.stopped().await;
    let spans = tracing.finish();

    // Client spans are created per operation and parented by the caller.
    let caller = find_named_span(&spans, "first_operation");
    let client_span = find_rpc_span(&spans, SpanKind::Client, "first");
    assert_parent_child(caller, client_span);

    // Server spans are local roots: neither the handshake headers nor the
    // client span may parent them until per-message propagation lands.
    for method in ["first", "fail"] {
        let server_span = find_rpc_span(&spans, SpanKind::Server, method);
        assert!(!server_span.parent_span_is_remote);
        assert_ne!(
            server_span.span_context.trace_id().to_string(),
            HANDSHAKE_TRACE_ID
        );
    }

    let failing_client = find_rpc_span(&spans, SpanKind::Client, "fail");
    let failing_server = find_rpc_span(&spans, SpanKind::Server, "fail");
    assert_rpc_error_code(failing_client, "-32042");
    assert_rpc_error_code(failing_server, "-32042");
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
