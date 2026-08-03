use std::future::Future;

use http::Extensions;
use jsonrpsee::MethodResponse;
use jsonrpsee::core::middleware::{Batch, Notification, Request, RpcServiceBuilder, RpcServiceT};
use opentelemetry::trace::Status;
use tower::Layer;
use tower::layer::util::{Identity, Stack};
use tracing::{Instrument, Span, debug, warn};
use tracing_opentelemetry::{OpenTelemetrySpanExt, SetParentError};

use crate::context::RemoteTraceContext;

/// jsonrpsee server middleware that creates remotely parented RPC spans.
#[derive(Clone, Debug, Default)]
pub struct RpcServerTraceLayer;

impl<S> Layer<S> for RpcServerTraceLayer {
    type Service = RpcServerTraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcServerTraceService { inner }
    }
}

/// Service used by the JSON-RPC server tracing middleware.
#[derive(Clone, Debug)]
pub struct RpcServerTraceService<S> {
    inner: S,
}

/// RPC middleware stack used by jsonrpsee servers.
pub(crate) type RpcTraceContextServerMiddleware =
    RpcServiceBuilder<Stack<RpcServerTraceLayer, Identity>>;

/// Creates middleware that extracts remote context and traces jsonrpsee server requests.
pub fn rpc_trace_context_server_middleware() -> RpcTraceContextServerMiddleware {
    RpcServiceBuilder::new().layer(RpcServerTraceLayer)
}

impl<S> RpcServiceT for RpcServerTraceService<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = S::MethodResponse;
    type BatchResponse = S::BatchResponse;
    type NotificationResponse = S::NotificationResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let remote_context = extract_request_context(request.extensions());
        let span = server_span(request.method_name(), remote_context.as_ref());
        let response_span = span.clone();
        let response = self.inner.call(request);

        async move {
            let response = response.await;
            record_response(&response_span, &response);
            response
        }
        .instrument(span)
    }

    fn batch<'a>(
        &self,
        mut requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let remote_context = extract_request_context(requests.extensions());
        let span = tracing::info_span!(
            "rpc.server.batch",
            otel.name = "jsonrpc",
            otel.kind = "server",
            rpc.system.name = "jsonrpc"
        );
        if let Some(remote_context) = remote_context {
            set_remote_parent(&span, remote_context, "batch");
        }

        let response_span = span.clone();
        let response = self.inner.batch(requests);
        async move {
            let response = response.await;
            record_response(&response_span, &response);
            response
        }
        .instrument(span)
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        let remote_context = extract_request_context(notification.extensions());
        let span = server_span(notification.method_name(), remote_context.as_ref());
        let response_span = span.clone();
        let response = self.inner.notification(notification);

        async move {
            let response = response.await;
            record_response(&response_span, &response);
            response
        }
        .instrument(span)
    }
}

fn extract_request_context(extensions: &Extensions) -> Option<RemoteTraceContext> {
    extensions.get::<RemoteTraceContext>().cloned()
}

fn server_span(method: &str, remote_context: Option<&RemoteTraceContext>) -> Span {
    let span = tracing::info_span!(
        "rpc.server",
        otel.name = %method,
        otel.kind = "server",
        rpc.system.name = "jsonrpc",
        rpc.method = %method
    );
    if let Some(remote_context) = remote_context {
        set_remote_parent(&span, remote_context.clone(), method);
    }
    span
}

fn set_remote_parent(span: &Span, remote_context: RemoteTraceContext, method: &str) {
    match span.set_parent(remote_context.0) {
        Ok(()) => {}
        Err(SetParentError::LayerNotFound) => {
            debug!(%method, "OpenTelemetry layer is disabled; RPC trace parent was not attached");
        }
        Err(SetParentError::SpanDisabled) => {
            debug!(%method, "RPC server span is disabled; trace parent was not attached");
        }
        Err(SetParentError::AlreadyStarted) => {
            warn!(%method, "RPC server span started before its remote trace parent was attached");
        }
    }
}

fn record_response(span: &Span, response: &MethodResponse) {
    if let Some(error_code) = response.as_error_code() {
        let error_code = error_code.to_string();
        span.set_attribute("rpc.response.status_code", error_code.clone());
        span.set_attribute("error.type", error_code.clone());
        span.set_status(Status::error(format!("JSON-RPC error {error_code}")));
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::types::Id;
    use opentelemetry::Context as OtelContext;
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };

    use super::*;

    #[test]
    fn batch_context_comes_from_shared_request_extensions() {
        let mut batch = Batch::new();
        batch.push(request_with_context("first", 1));
        batch.push(request_with_context("second", 2));

        let context = extract_request_context(batch.extensions())
            .expect("batch entries carry a remote context");
        assert_eq!(
            context.0.span().span_context().trace_id(),
            TraceId::from_bytes([1; 16])
        );
    }

    fn request_with_context(method: &'static str, id: u64) -> Request<'static> {
        let span_context = SpanContext::new(
            TraceId::from_bytes([1; 16]),
            SpanId::from_bytes([7; 8]),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        );
        let mut request = Request::borrowed(method, None, Id::Number(id));
        request.extensions_mut().insert(RemoteTraceContext(
            OtelContext::new().with_remote_span_context(span_context),
        ));
        request
    }
}
