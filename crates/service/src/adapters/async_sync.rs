use std::{any::Any, future::Future, sync::Arc};

use tokio::sync::Mutex;

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
            let res = tokio::task::spawn_blocking(move || {
                let mut inner_lock = inner.blocking_lock();
                inner_lock.recv_next()
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

pub(super) fn try_conv_panic(panic: &dyn Any) -> Option<String> {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&String>().cloned().cloned())
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
}
