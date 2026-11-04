use std::any::Any;
use std::future::Future;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::flag_shutdown::FlagShutdown;
use crate::{AsyncServiceInput, ServiceError, ServiceInput, ServiceMsg, SyncServiceInput};

/// Adapter for using a sync service input as an async one.
pub struct AsyncSyncInput<I> {
    // This is really annoying that it has to work this way.  Hopefully we won't
    // ever have to use this impl.
    inner: Arc<Mutex<I>>,
}

impl<I> AsyncSyncInput<I> {
    /// Constructs a new instance.
    ///
    /// This will use the blocking threadpool of the async runtime it's used in.
    pub fn new(inner: I) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl<I: ServiceInput> ServiceInput for AsyncSyncInput<I>
where
    I::Msg: ServiceMsg,
{
    type Msg = I::Msg;
}

impl<I: SyncServiceInput> AsyncServiceInput for AsyncSyncInput<I>
where
    I::Msg: ServiceMsg,
{
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        let inner = self.inner.clone();
        async move {
            // An async worker stops on shutdown by dropping this future. Dropping
            // it does not stop the blocking thread, so tell the inner input to
            // stop as well. Otherwise the thread stays parked in it, holding the
            // lock, and takes the next message for a caller that has gone away.
            let stop = FlagShutdown::default();
            let _stop_on_drop = TriggerOnDrop(stop.clone());

            let res = tokio::task::spawn_blocking(move || {
                let mut inner_lock = inner.blocking_lock();
                inner_lock.recv_next(&stop)
            })
            .await;

            match res {
                Ok(res) => res,
                Err(je) => {
                    let e = if je.is_cancelled() {
                        // How could this ever happen?
                        ServiceError::WaitCancelled
                    } else if je.is_panic() {
                        let panic = je.into_panic();
                        ServiceError::BlockingThreadPanic(
                            try_conv_panic(&panic).unwrap_or_default(),
                        )
                    } else {
                        ServiceError::UnknownInputErr
                    };

                    Err(e.into())
                }
            }
        }
    }
}

struct TriggerOnDrop(FlagShutdown);

impl Drop for TriggerOnDrop {
    fn drop(&mut self) {
        self.0.trigger();
    }
}

pub(super) fn try_conv_panic(panic: &dyn Any) -> Option<String> {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&String>().cloned().cloned())
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::TokioMpscInput;

    #[tokio::test]
    async fn dropped_recv_releases_the_inner_input() {
        let (tx, rx) = mpsc::channel(4);
        let mut inp = AsyncSyncInput::new(TokioMpscInput::new(rx));

        // Nothing is queued, so this parks until the timeout drops it.
        let first = timeout(Duration::from_millis(100), inp.recv_next()).await;
        assert!(first.is_err(), "test: nothing should have been received");

        tx.send(7).await.expect("test: send input");

        let rv = timeout(Duration::from_secs(5), inp.recv_next())
            .await
            .expect("inner input still held by the dropped call")
            .expect("test: recv input");
        assert_eq!(rv, Some(7));
    }
}
