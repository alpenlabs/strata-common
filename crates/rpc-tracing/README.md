# JSON-RPC tracing

`strata-rpc-tracing` creates OpenTelemetry client/server spans for jsonrpsee
services and propagates W3C Trace Context across HTTP service boundaries in
request headers.

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

The HTTP layer deliberately ignores WebSocket upgrade headers: a pooled
connection carries unrelated operations, so the handshake must never become
their shared parent.

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

WebSocket clients create a client span per RPC operation on the shared
connection:

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

## WebSocket propagation status

Cross-service context is currently propagated over HTTP only. WebSocket
operations get client and server spans, but the server spans are local roots:
per-operation context on a shared connection must travel inside each JSON-RPC
message rather than in connection headers. The candidate mechanisms are the
request-extension API proposed upstream in
[paritytech/jsonrpsee#1647](https://github.com/paritytech/jsonrpsee/pull/1647)
(fits positional-parameter APIs, not yet released) and MCP-style
`traceparent`/`tracestate` members inside `params._meta` (works on stock
jsonrpsee, named-parameter APIs only). Per-message WebSocket propagation lands
as a follow-up once one of these is settled.

RPC spans use static tracing names and record the method, span kind, JSON-RPC
error code, and failure status. Batches create one boundary span because
jsonrpsee dispatches a batch through one middleware call.

Do not put trace IDs in metric labels. Use the trace backend for individual
operations and bounded RPC method/status attributes for aggregate metrics.
