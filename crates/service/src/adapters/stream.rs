use std::future::Future;

use futures::stream::{Stream, StreamExt};

use crate::{AsyncServiceInput, ServiceInput, ServiceMsg};

/// Adapter for using an arbitrary [`Stream`] impl as an input.
pub struct StreamInput<S> {
    stream: S,
    closed: bool,
}

impl<S> StreamInput<S> {
    /// Constructs a new unclosed instance from a stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            closed: false,
        }
    }
}

impl<S: Stream + Sync + Send + 'static> ServiceInput for StreamInput<S>
where
    S::Item: ServiceMsg,
{
    type Msg = S::Item;
}

impl<S: Stream + Unpin + Sync + Send + 'static> AsyncServiceInput for StreamInput<S>
where
    S::Item: ServiceMsg,
{
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            // We fuse it off ourselves just in case, it'd be weird not to.
            if self.closed {
                return Ok(None);
            }

            let item = self.stream.next().await;
            self.closed |= item.is_none();
            Ok(item)
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::stream;

    use super::*;

    #[tokio::test]
    async fn test_stream_input() {
        let v = 3;
        let stream = stream::repeat(v);
        let mut inp = StreamInput::new(stream);

        let rv = inp
            .recv_next()
            .await
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }
}
