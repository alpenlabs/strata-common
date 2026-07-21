use std::task::{Context as TaskContext, Poll};

use http::Request as HttpRequest;
use jsonrpsee::server::ws::is_upgrade_request;
use tower::layer::util::{Identity, Stack};
use tower::{Layer, Service, ServiceBuilder};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::context::{extract_context_from_headers, inject_context_into_headers};

/// HTTP server middleware that extracts trace context from non-WebSocket requests.
#[derive(Clone, Debug, Default)]
pub struct HttpServerTraceContextLayer;

impl<S> Layer<S> for HttpServerTraceContextLayer {
    type Service = HttpServerTraceContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpServerTraceContextService { inner }
    }
}

/// Service produced by [`HttpServerTraceContextLayer`].
#[derive(Clone, Debug)]
pub struct HttpServerTraceContextService<S> {
    inner: S,
}

impl<S, B> Service<HttpRequest<B>> for HttpServerTraceContextService<S>
where
    S: Service<HttpRequest<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: HttpRequest<B>) -> Self::Future {
        if !is_upgrade_request(&request)
            && let Some(remote_context) = extract_context_from_headers(request.headers())
        {
            request.extensions_mut().insert(remote_context);
        }

        self.inner.call(request)
    }
}

/// HTTP client middleware that injects the current span context into each request.
#[derive(Clone, Debug, Default)]
pub struct HttpClientTraceContextLayer;

impl<S> Layer<S> for HttpClientTraceContextLayer {
    type Service = HttpClientTraceContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpClientTraceContextService { inner }
    }
}

/// Service produced by [`HttpClientTraceContextLayer`].
#[derive(Clone, Debug)]
pub struct HttpClientTraceContextService<S> {
    inner: S,
}

impl<S, B> Service<HttpRequest<B>> for HttpClientTraceContextService<S>
where
    S: Service<HttpRequest<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: HttpRequest<B>) -> Self::Future {
        inject_context_into_headers(&Span::current().context(), request.headers_mut());
        self.inner.call(request)
    }
}

/// HTTP middleware stack used by jsonrpsee servers.
pub(crate) type HttpServerTraceContextMiddleware =
    ServiceBuilder<Stack<HttpServerTraceContextLayer, Identity>>;

/// HTTP middleware stack used by jsonrpsee HTTP clients.
pub(crate) type HttpClientTraceContextMiddleware =
    ServiceBuilder<Stack<HttpClientTraceContextLayer, Identity>>;

/// Creates the transport middleware for a jsonrpsee HTTP/WebSocket server.
pub fn http_trace_context_server_middleware() -> HttpServerTraceContextMiddleware {
    ServiceBuilder::new().layer(HttpServerTraceContextLayer)
}

/// Creates middleware that injects trace context into each HTTP client request.
pub fn http_trace_context_client_middleware() -> HttpClientTraceContextMiddleware {
    ServiceBuilder::new().layer(HttpClientTraceContextLayer)
}
