//! HTTP cross-service trace correlation tests.

mod support;

use http::{HeaderMap, HeaderValue};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use opentelemetry::trace::SpanKind;
use serde_json as _;
use strata_rpc_tracing::{
    TracedHttpClient, http_trace_context_client_middleware, http_trace_context_server_middleware,
    rpc_trace_context_http_client_middleware, rpc_trace_context_server_middleware,
};
use support::{TestTracing, assert_parent_child, find_named_span, find_rpc_span};
use tower as _;
use tracing::Instrument;

#[tokio::test(flavor = "current_thread")]
async fn checkpoint_request_correlates_prover_and_strata_over_http() {
    const STATIC_TRACE_ID: &str = "11111111111111111111111111111111";
    const STATIC_TRACEPARENT: &str = "00-11111111111111111111111111111111-2222222222222222-01";

    let tracing = TestTracing::init("strata-rpc-tracing-http-test");
    let server = ServerBuilder::new()
        .set_http_middleware(http_trace_context_server_middleware())
        .set_rpc_middleware(rpc_trace_context_server_middleware())
        .build("127.0.0.1:0")
        .await
        .expect("HTTP test server should start");
    let server_address = server
        .local_addr()
        .expect("HTTP test server should expose its address");
    let mut module = RpcModule::new(());
    module
        .register_method("get_checkpoint_info", |_, _, _| "checkpoint")
        .expect("checkpoint method should register");
    let server_handle = server.start(module);

    let mut static_headers = HeaderMap::new();
    static_headers.insert("traceparent", HeaderValue::from_static(STATIC_TRACEPARENT));
    let client: TracedHttpClient = HttpClientBuilder::default()
        .set_headers(static_headers)
        .set_http_middleware(http_trace_context_client_middleware())
        .set_rpc_middleware(rpc_trace_context_http_client_middleware())
        .build(format!("http://{server_address}"))
        .expect("HTTP test client should build");

    let caller_span =
        tracing::info_span!("prover.fetch_checkpoint", otel.name = "fetch_checkpoint");
    let response: String = async {
        client
            .request("get_checkpoint_info", rpc_params![42_u64])
            .await
    }
    .instrument(caller_span.clone())
    .await
    .expect("checkpoint request should succeed");
    assert_eq!(response, "checkpoint");

    drop(client);
    drop(caller_span);
    server_handle.stop().expect("HTTP test server should stop");
    server_handle.stopped().await;
    let spans = tracing.finish();

    let caller = find_named_span(&spans, "fetch_checkpoint");
    let client = find_rpc_span(&spans, SpanKind::Client, "get_checkpoint_info");
    let server = find_rpc_span(&spans, SpanKind::Server, "get_checkpoint_info");
    assert_parent_child(caller, client);
    assert_parent_child(client, server);
    assert!(server.parent_span_is_remote);
    assert_ne!(server.span_context.trace_id().to_string(), STATIC_TRACE_ID);
}
