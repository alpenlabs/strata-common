use std::future::Future;

use tokio::sync::mpsc;

use crate::{AsyncServiceInput, ServiceInput, ServiceMsg, SyncServiceInput};

/// Adapter for using a mpsc receiver as a input.
///
/// This is needed because [`mpsc::Receiver`] does not natively implement
/// [`futures::stream::Stream`] and it avoids having to use the Tokio wrapper.
pub struct TokioMpscInput<T> {
    rx: mpsc::Receiver<T>,
    closed: bool,
}

impl<T> TokioMpscInput<T> {
    /// Constructs a new uncloesed input from a channel.
    pub fn new(rx: mpsc::Receiver<T>) -> Self {
        Self { rx, closed: false }
    }
}

impl<T: ServiceMsg> ServiceInput for TokioMpscInput<T> {
    type Msg = T;
}

impl<T: ServiceMsg> AsyncServiceInput for TokioMpscInput<T> {
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            // We fuse it off ourselves just in case, it'd be weird not to.
            if self.closed {
                return Ok(None);
            }

            let item = self.rx.recv().await;
            self.closed |= item.is_none();
            Ok(item)
        }
    }
}

/// This impl is technically redundant since we can use the type as an
/// [`Iterator`], but someone might find it useful and it's easy enough to
/// implement.
impl<T: ServiceMsg> SyncServiceInput for TokioMpscInput<T> {
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>> {
        // We fuse it off ourselves just in case, it'd be weird not to.
        if self.closed {
            return Ok(None);
        }

        let item = self.rx.blocking_recv();
        self.closed |= item.is_none();
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn test_mpsc_input_async() {
        let v = 3;

        let (tx, rx) = mpsc::channel(10);
        let mut inp = TokioMpscInput::new(rx);

        tx.send(v).await.expect("test: send input");

        let rv = AsyncServiceInput::recv_next(&mut inp)
            .await
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }

    #[test]
    fn test_mpsc_input_blocking() {
        let v = 3;

        let (tx, rx) = mpsc::channel(10);
        let mut inp = TokioMpscInput::new(rx);

        tx.blocking_send(v).expect("test: send input");

        let rv = SyncServiceInput::recv_next(&mut inp)
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }
}
