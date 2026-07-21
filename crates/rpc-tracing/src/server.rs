use std::future::Future;

use http::Extensions;
use jsonrpsee::MethodResponse;
use jsonrpsee::core::middleware::{
    Batch, BatchEntry, Notification, Request, RequestExtensions, RpcServiceBuilder, RpcServiceT,
};
use opentelemetry::trace::{Status, TraceContextExt};
use tower::Layer;
use tower::layer::util::{Identity, Stack};
use tracing::{Instrument, Span, debug, warn};
use tracing_opentelemetry::{OpenTelemetrySpanExt, SetParentError};

use crate::context::{RemoteTraceContext, extract_context_from_message};

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
        let remote_context =
            extract_request_context(request.request_extensions(), request.extensions());
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
        requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let remote_context = extract_batch_context(&requests);
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
        let remote_context =
            extract_request_context(notification.request_extensions(), notification.extensions());
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

fn extract_request_context(
    request_extensions: Option<&RequestExtensions>,
    extensions: &Extensions,
) -> Option<RemoteTraceContext> {
    extensions
        .get::<RemoteTraceContext>()
        .cloned()
        .or_else(|| extract_context_from_message(request_extensions))
}

fn extract_batch_entry_context(entry: &BatchEntry<'_>) -> Option<RemoteTraceContext> {
    match entry {
        BatchEntry::Call(request) => {
            extract_request_context(request.request_extensions(), request.extensions())
        }
        BatchEntry::Notification(notification) => {
            extract_request_context(notification.request_extensions(), notification.extensions())
        }
    }
}

fn extract_batch_context(requests: &Batch<'_>) -> Option<RemoteTraceContext> {
    let mut contexts = requests
        .iter()
        .flatten()
        .filter_map(extract_batch_entry_context);
    let first_context = contexts.next()?;
    let first_span_context = first_context.0.span().span_context().clone();

    if contexts.any(|context| context.0.span().span_context() != &first_span_context) {
        warn!("ignoring conflicting trace contexts in JSON-RPC batch");
        return None;
    }

    Some(first_context)
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
    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};

    use super::*;

    #[test]
    fn batch_context_requires_one_parent() {
        let mut consistent_batch = Batch::new();
        consistent_batch.push(request_with_context("first", 1, 1));
        consistent_batch.push(request_with_context("second", 2, 1));
        assert!(extract_batch_context(&consistent_batch).is_some());

        let mut conflicting_batch = Batch::new();
        conflicting_batch.push(request_with_context("first", 1, 1));
        conflicting_batch.push(request_with_context("second", 2, 2));
        assert!(extract_batch_context(&conflicting_batch).is_none());
    }

    fn request_with_context(method: &'static str, id: u64, trace_id: u8) -> Request<'static> {
        let span_context = SpanContext::new(
            TraceId::from_bytes([trace_id; 16]),
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
