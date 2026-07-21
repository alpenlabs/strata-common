use std::future::Future;

use jsonrpsee::core::client::{
    Error as RpcClientError, MiddlewareBatchResponse, MiddlewareMethodResponse,
    MiddlewareNotifResponse,
};
use jsonrpsee::core::middleware::{
    Batch, BatchEntry, Notification, Request, RpcServiceBuilder, RpcServiceT,
};
use jsonrpsee::http_client::transport::HttpBackend;
use jsonrpsee::http_client::{HttpClient, RpcService as HttpRpcService};
use jsonrpsee::ws_client::{RpcService as WsRpcService, WsClient};
use opentelemetry::trace::Status;
use tower::Layer;
use tower::layer::util::{Identity, Stack};
use tracing::{Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::context::inject_context_into_message;
use crate::transport::HttpClientTraceContextService;

/// jsonrpsee client middleware that creates client spans and propagates their context.
#[derive(Clone, Debug)]
pub struct RpcClientTraceLayer {
    inject_message_context: bool,
}

impl<S> Layer<S> for RpcClientTraceLayer {
    type Service = RpcClientTraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcClientTraceService {
            inner,
            inject_message_context: self.inject_message_context,
        }
    }
}

/// Service used by the JSON-RPC client tracing middleware.
#[derive(Clone, Debug)]
pub struct RpcClientTraceService<S> {
    inner: S,
    inject_message_context: bool,
}

/// RPC middleware stack used by jsonrpsee clients.
pub(crate) type RpcTraceContextClientMiddleware =
    RpcServiceBuilder<Stack<RpcClientTraceLayer, Identity>>;

/// HTTP client with both RPC spans and W3C trace-context propagation installed.
pub type TracedHttpClient =
    HttpClient<RpcClientTraceService<HttpRpcService<HttpClientTraceContextService<HttpBackend>>>>;

/// WebSocket client with RPC spans and per-message trace-context propagation installed.
pub type TracedWsClient = WsClient<RpcClientTraceService<WsRpcService>>;

/// Creates RPC middleware for a jsonrpsee HTTP client.
///
/// Pair this with `http_trace_context_client_middleware` so the client span is
/// injected into the HTTP request headers.
pub fn rpc_trace_context_http_client_middleware() -> RpcTraceContextClientMiddleware {
    RpcServiceBuilder::new().layer(RpcClientTraceLayer {
        inject_message_context: false,
    })
}

/// Creates RPC middleware for a jsonrpsee WebSocket client.
///
/// Context is injected into every JSON-RPC message because WebSocket handshake
/// headers belong to the connection rather than an individual operation.
pub fn rpc_trace_context_ws_client_middleware() -> RpcTraceContextClientMiddleware {
    RpcServiceBuilder::new().layer(RpcClientTraceLayer {
        inject_message_context: true,
    })
}

impl<S> RpcServiceT for RpcClientTraceService<S>
where
    S: RpcServiceT<
            MethodResponse = Result<MiddlewareMethodResponse, RpcClientError>,
            BatchResponse = Result<MiddlewareBatchResponse, RpcClientError>,
            NotificationResponse = Result<MiddlewareNotifResponse, RpcClientError>,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = Result<MiddlewareMethodResponse, RpcClientError>;
    type BatchResponse = Result<MiddlewareBatchResponse, RpcClientError>;
    type NotificationResponse = Result<MiddlewareNotifResponse, RpcClientError>;

    fn call<'a>(
        &self,
        mut request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let span = client_span(request.method_name());
        if self.inject_message_context {
            inject_context_into_message(&span.context(), request.request_extensions_mut());
        }

        let response_span = span.clone();
        let response = self.inner.call(request);
        async move {
            let response = response.await;
            record_method_response(&response_span, &response);
            response
        }
        .instrument(span)
    }

    fn batch<'a>(
        &self,
        mut requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let span = client_batch_span();
        if self.inject_message_context {
            let context = span.context();
            for entry in requests.iter_mut().flatten() {
                match entry {
                    BatchEntry::Call(request) => {
                        inject_context_into_message(&context, request.request_extensions_mut());
                    }
                    BatchEntry::Notification(notification) => {
                        inject_context_into_message(
                            &context,
                            notification.request_extensions_mut(),
                        );
                    }
                }
            }
        }

        let response_span = span.clone();
        let response = self.inner.batch(requests);
        async move {
            let response = response.await;
            record_batch_response(&response_span, &response);
            response
        }
        .instrument(span)
    }

    fn notification<'a>(
        &self,
        mut notification: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        let span = client_span(notification.method_name());
        if self.inject_message_context {
            inject_context_into_message(&span.context(), notification.request_extensions_mut());
        }

        let response_span = span.clone();
        let response = self.inner.notification(notification);
        async move {
            let response = response.await;
            if let Err(error) = &response {
                record_client_error(&response_span, error);
            }
            response
        }
        .instrument(span)
    }
}

fn client_span(method: &str) -> Span {
    tracing::info_span!(
        "rpc.client",
        otel.name = %method,
        otel.kind = "client",
        rpc.system.name = "jsonrpc",
        rpc.method = %method
    )
}

fn client_batch_span() -> Span {
    tracing::info_span!(
        "rpc.client.batch",
        otel.name = "jsonrpc",
        otel.kind = "client",
        rpc.system.name = "jsonrpc"
    )
}

fn record_method_response(
    span: &Span,
    response: &Result<MiddlewareMethodResponse, RpcClientError>,
) {
    match response {
        Ok(response) => {
            if let Some(error) = response.as_error() {
                record_rpc_error_code(span, error.code());
            }
        }
        Err(error) => record_client_error(span, error),
    }
}

fn record_batch_response(span: &Span, response: &Result<MiddlewareBatchResponse, RpcClientError>) {
    match response {
        Ok(responses) => {
            if let Some(error_code) = responses
                .iter()
                .find_map(|response| response.as_error().map(|error| error.code()))
            {
                record_rpc_error_code(span, error_code);
            }
        }
        Err(error) => record_client_error(span, error),
    }
}

fn record_client_error(span: &Span, error: &RpcClientError) {
    if let RpcClientError::Call(error_object) = error {
        record_rpc_error_code(span, error_object.code());
        return;
    }

    let error_type = match error {
        RpcClientError::Transport(_) => "jsonrpsee.transport",
        _ => "jsonrpsee.client",
    };
    span.set_attribute("error.type", error_type);
    span.set_status(Status::error(error.to_string()));
}

fn record_rpc_error_code(span: &Span, error_code: i32) {
    let error_code = error_code.to_string();
    span.set_attribute("rpc.response.status_code", error_code.clone());
    span.set_attribute("error.type", error_code.clone());
    span.set_status(Status::error(format!("JSON-RPC error {error_code}")));
}
