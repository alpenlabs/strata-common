use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::core::middleware::RequestExtensions;
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TraceContextExt;
use opentelemetry::{Context, global};
use serde_json::Value;
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

pub(crate) fn inject_context_into_message(
    context: &Context,
    request_extensions: &mut RequestExtensions,
) {
    global::get_text_map_propagator(|propagator| {
        for field in propagator.fields() {
            request_extensions.remove(field);
        }
        propagator.inject_context(context, &mut MessageInjector(request_extensions));
    });
}

pub(crate) fn extract_context_from_headers(headers: &HeaderMap) -> Option<RemoteTraceContext> {
    global::get_text_map_propagator(|propagator| {
        valid_remote_context(propagator.extract(&HeaderExtractor(headers)))
    })
}

pub(crate) fn extract_context_from_message(
    request_extensions: Option<&RequestExtensions>,
) -> Option<RemoteTraceContext> {
    request_extensions.and_then(|request_extensions| {
        global::get_text_map_propagator(|propagator| {
            valid_remote_context(propagator.extract(&MessageExtractor(request_extensions)))
        })
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

struct MessageExtractor<'a>(&'a RequestExtensions);

impl Extractor for MessageExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| match value.as_str() {
            Some(value) => Some(value),
            None => {
                debug!(%key, "ignoring non-string RPC trace-context field");
                None
            }
        })
    }

    fn keys(&self) -> Vec<&str> {
        self.0.iter().map(|(key, _)| key).collect()
    }
}

struct MessageInjector<'a>(&'a mut RequestExtensions);

impl Injector for MessageInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Err(error) = self.0.insert(key, Value::String(value)) {
            warn!(%error, %key, "failed to encode RPC trace-context field");
        }
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    use super::*;

    #[test]
    fn malformed_message_context_is_not_accepted() {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let mut extensions = RequestExtensions::default();
        extensions
            .insert("traceparent", Value::String("not-a-traceparent".into()))
            .expect("traceparent is not a reserved JSON-RPC field");

        assert!(extract_context_from_message(Some(&extensions)).is_none());
    }
}
