# JSON-RPC tracing

`strata-rpc-tracing` creates OpenTelemetry client/server spans and propagates
W3C Trace Context across jsonrpsee service boundaries. HTTP carries context in
request headers; WebSocket carries context in each JSON-RPC message so a reused
connection cannot make unrelated operations share a parent.

The crate uses the process-global propagator and active tracing subscriber. A
binary must configure those through `strata-logging`, including a distinct
`service.name`; this crate does not install exporters or global telemetry state.

## Server

Every HTTP or WebSocket server installs both layers:

```rust,ignore
let server = ServerBuilder::new()
    .set_http_middleware(http_trace_context_server_middleware())
    .set_rpc_middleware(rpc_trace_context_server_middleware())
    .build(address)
    .await?;
```

Servers with existing HTTP middleware can compose the exported layer directly:

```rust,ignore
let http_middleware = ServiceBuilder::new()
    .layer(HttpServerTraceContextLayer)
    .layer(HealthHttpLayer::new(health_registry));
```

The HTTP layer deliberately ignores WebSocket upgrade headers. The RPC layer
therefore uses HTTP context for ordinary requests and per-message context for
WebSocket calls, notifications, subscriptions, and batches.

## Clients

HTTP clients install an RPC layer to create the client span and an HTTP layer to
inject that span into the outgoing request:

```rust,ignore
let client: TracedHttpClient = HttpClientBuilder::default()
    .set_headers(headers)
    .set_http_middleware(http_trace_context_client_middleware())
    .set_rpc_middleware(rpc_trace_context_http_client_middleware())
    .build(url)?;
```

WebSocket clients inject the client span into each JSON-RPC message:

```rust,ignore
let client: TracedWsClient = WsClientBuilder::default()
    .set_headers(handshake_headers)
    .set_rpc_middleware(rpc_trace_context_ws_client_middleware())
    .build(url)
    .await?;
```

[`TracedHttpClient`] and [`TracedWsClient`] hide jsonrpsee's nested middleware
types, allowing binaries and shared crates to store and pass traced clients
without duplicating fragile type aliases.

Per-message WebSocket context currently depends on a pinned jsonrpsee fork. A
consumer that also depends on jsonrpsee must patch its complete jsonrpsee graph
to the same revision until the request-extension support lands upstream;
crates.io and Git sources produce incompatible Rust types.

RPC spans use static tracing names and record the method, span kind, JSON-RPC
error code, and failure status. Batches create one boundary span because
jsonrpsee dispatches a batch through one middleware call. Conflicting entry
contexts are rejected instead of choosing an arbitrary parent.

Do not put trace IDs in metric labels. Use the trace backend for individual
operations and bounded RPC method/status attributes for aggregate metrics.
