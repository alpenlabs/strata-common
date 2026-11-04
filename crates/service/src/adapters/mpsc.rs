use std::future::Future;

use futures::FutureExt;
use tokio::sync::mpsc;

use crate::{AsyncGuard, AsyncServiceInput, ServiceInput, ServiceMsg, SyncServiceInput};

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

impl<T: ServiceMsg> SyncServiceInput for TokioMpscInput<T> {
    fn recv_next(&mut self, shutdown: &impl AsyncGuard) -> anyhow::Result<Option<Self::Msg>> {
        if self.closed {
            return Ok(None);
        }

        // A command channel is held open by its senders for the life of the
        // process, so a plain `blocking_recv` would park until the next message
        // no matter what else is going on.  Wait on the shutdown signal
        // alongside it instead.
        //
        // `futures::executor::block_on` rather than a tokio runtime, because a
        // sync worker's thread may have no runtime entered. This relies on the
        // guard contract documented on `SyncExecutor::ShutdownGuard`.
        let recv = async {
            futures::select_biased! {
                // Biased so that once shutdown is signalled, a queued message
                // stays in the channel rather than being dequeued and dropped
                // by the caller.
                _ = shutdown.wait_for_shutdown().fuse() => None,
                item = self.rx.recv().fuse() => Some(item),
            }
        };

        match futures::executor::block_on(recv) {
            // Channel produced something, or closed on its own.
            Some(item) => {
                self.closed |= item.is_none();
                Ok(item)
            }
            // Shutdown won the race. The channel itself is untouched, so this
            // does not mark the input closed.
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;
    use crate::flag_shutdown::FlagShutdown;

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

        let rv = SyncServiceInput::recv_next(&mut inp, &FlagShutdown::default())
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }

    #[test]
    fn recv_blocking_leaves_queued_message_once_shutdown_is_set() {
        let (tx, rx) = mpsc::channel(10);
        let mut inp = TokioMpscInput::new(rx);
        let shutdown = FlagShutdown::default();

        tx.blocking_send(7).expect("test: send input");
        shutdown.trigger();

        let rv = SyncServiceInput::recv_next(&mut inp, &shutdown).expect("test: recv input");
        assert_eq!(rv, None, "shutdown should win over a queued message");
        assert!(!inp.closed, "shutdown must not mark the input closed");

        let rv = AsyncServiceInput::recv_next(&mut inp)
            .now_or_never()
            .expect("test: message should be ready")
            .expect("test: recv input");
        assert_eq!(rv, Some(7), "queued message should still be in the channel");
    }

    #[test]
    fn recv_blocking_closes_when_senders_drop() {
        let (tx, rx) = mpsc::channel::<u32>(10);
        let mut inp = TokioMpscInput::new(rx);
        let shutdown = FlagShutdown::default();

        drop(tx);

        let rv = SyncServiceInput::recv_next(&mut inp, &shutdown).expect("test: recv input");
        assert_eq!(rv, None);
        assert!(inp.closed, "a closed channel should mark the input closed");
    }
}
