use futures::FutureExt;

use crate::{AsyncGuard, AsyncServiceInput, ServiceInput, ServiceMsg, SyncServiceInput};

/// Adapter for using an async service input as a sync one.
pub struct SyncAsyncInput<I> {
    inner: I,
    handle: tokio::runtime::Handle,
}

impl<I> SyncAsyncInput<I> {
    /// Constructs a new instance using a runtime handle.
    pub fn new(inner: I, handle: tokio::runtime::Handle) -> Self {
        Self { inner, handle }
    }
}

impl<I: ServiceInput> ServiceInput for SyncAsyncInput<I>
where
    I::Msg: ServiceMsg,
{
    type Msg = I::Msg;
}

impl<I: AsyncServiceInput> SyncServiceInput for SyncAsyncInput<I> {
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>> {
        self.handle.block_on(self.inner.recv_next())
    }

    fn recv_next_until_shutdown(
        &mut self,
        shutdown: &impl AsyncGuard,
    ) -> anyhow::Result<Option<Self::Msg>> {
        // The wrapped input may park indefinitely, so race it against shutdown
        // rather than blocking on it alone.
        self.handle.block_on(async {
            futures::select_biased! {
                _ = shutdown.wait_for_shutdown().fuse() => Ok(None),
                item = self.inner.recv_next().fuse() => item,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc as std_mpsc;
    use std::thread;
    use std::time::Duration;

    use tokio::runtime;
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_utils::FlagShutdown;
    use crate::TokioMpscInput;

    #[test]
    fn recv_until_shutdown_wakes_on_shutdown_while_parked() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("test: build runtime");
        // Held for the whole test, so only the shutdown signal can end the wait.
        let (_tx, rx) = mpsc::channel::<u32>(4);
        let mut inp = SyncAsyncInput::new(TokioMpscInput::new(rx), rt.handle().clone());
        let shutdown = FlagShutdown::default();

        let (done_tx, done_rx) = std_mpsc::channel();
        let worker_shutdown = shutdown.clone();
        thread::spawn(move || {
            let res = inp.recv_next_until_shutdown(&worker_shutdown);
            let _ = done_tx.send(res);
        });

        // Give the thread time to park, so the signal has to wake it.
        thread::sleep(Duration::from_millis(100));
        shutdown.trigger();

        let rv = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("input did not wake on the shutdown signal")
            .expect("test: recv input");
        assert_eq!(rv, None);
    }
}
