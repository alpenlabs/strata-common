use http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TraceContextExt;
use opentelemetry::{Context, global};
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub(crate) struct RemoteTraceContext(pub(crate) Context);

pub(crate) fn inject_context_into_headers(context: &Context, headers: &mut HeaderMap) {
    global::get_text_map_propagator(|propagator| {
        for field in propagator.fields() {
            headers.remove(field);
        }
        propagator.inject_context(context, &mut HeaderInjector(headers));
    });
}

pub(crate) fn extract_context_from_headers(headers: &HeaderMap) -> Option<RemoteTraceContext> {
    global::get_text_map_propagator(|propagator| {
        valid_remote_context(propagator.extract(&HeaderExtractor(headers)))
    })
}

fn valid_remote_context(context: Context) -> Option<RemoteTraceContext> {
    context
        .span()
        .span_context()
        .is_valid()
        .then_some(RemoteTraceContext(context))
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| match value.to_str() {
            Ok(value) => Some(value),
            Err(error) => {
                debug!(%error, %key, "ignoring malformed RPC trace-context header");
                None
            }
        })
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        let header_name = match HeaderName::from_bytes(key.as_bytes()) {
            Ok(header_name) => header_name,
            Err(error) => {
                warn!(%error, %key, "failed to encode RPC trace-context header name");
                return;
            }
        };
        let header_value = match HeaderValue::from_str(&value) {
            Ok(header_value) => header_value,
            Err(error) => {
                warn!(%error, %key, "failed to encode RPC trace-context header value");
                return;
            }
        };
        self.0.insert(header_name, header_value);
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    use super::*;

    #[test]
    fn malformed_header_context_is_not_accepted() {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", HeaderValue::from_static("not-a-traceparent"));

        assert!(extract_context_from_headers(&headers).is_none());
    }
}
