#![doc = include_str!("../README.md")]

mod client;
mod context;
mod server;
mod transport;

pub use client::{
    TracedHttpClient, TracedWsClient, rpc_trace_context_http_client_middleware,
    rpc_trace_context_ws_client_middleware,
};
pub use server::rpc_trace_context_server_middleware;
pub use transport::{
    HttpServerTraceContextLayer, http_trace_context_client_middleware,
    http_trace_context_server_middleware,
};
#[cfg(test)]
use {opentelemetry_sdk as _, tokio as _, tracing_subscriber as _};
