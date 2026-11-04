use std::any::Any;
use std::future::Future;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::flag_shutdown::FlagShutdown;
use crate::{
    AsyncServiceInput, ServiceError, ServiceInput, ServiceMsg, SyncGuard, SyncServiceInput,
};

/// Adapter for using a sync service input as an async one.
pub struct AsyncSyncInput<I: ServiceInput> {
    // This is really annoying that it has to work this way.  Hopefully we won't
    // ever have to use this impl.
    shared: Arc<Mutex<Shared<I>>>,
}

/// State shared with the blocking thread that reads the inner input.
struct Shared<I: ServiceInput> {
    input: I,

    /// Result the blocking thread received but no caller has taken yet.
    ///
    /// The thread stores its result here instead of returning it, so a result
    /// that arrives after its caller was dropped goes to the next call instead
    /// of being lost.
    pending: Option<anyhow::Result<Option<I::Msg>>>,
}

impl<I: ServiceInput> AsyncSyncInput<I> {
    /// Constructs a new instance.
    ///
    /// This will use the blocking threadpool of the async runtime it's used in.
    pub fn new(inner: I) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared {
                input: inner,
                pending: None,
            })),
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
        let shared = self.shared.clone();
        async move {
            // An async worker stops on shutdown by dropping this future. Dropping
            // it does not stop the blocking thread, so tell the inner input to
            // stop as well. Otherwise the thread stays parked in it, holding the
            // lock, and the next call waits behind it.
            let stop = FlagShutdown::default();
            let _stop_on_drop = TriggerOnDrop(stop.clone());

            let thread_shared = shared.clone();
            let res = tokio::task::spawn_blocking(move || {
                let mut shared = thread_shared.blocking_lock();
                // A dropped call's thread may have stored a result already.
                // Leave it for this call to take.
                if shared.pending.is_some() {
                    return;
                }
                let res = shared.input.recv_next(&stop);
                // `Ok(None)` after the stop signal only means the inner input
                // gave up waiting. Storing it would tell the next caller the
                // input has ended. The stop signal only fires once this call
                // is dropped, so a live caller always gets a result.
                if !(stop.should_shutdown() && matches!(res, Ok(None))) {
                    shared.pending = Some(res);
                }
            })
            .await;

            match res {
                Ok(()) => shared
                    .lock()
                    .await
                    .pending
                    .take()
                    .expect("blocking thread stores a result before it returns"),
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
    use std::collections::VecDeque;
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::{AsyncGuard, TokioMpscInput};

    /// Blocking queue that ignores shutdown, like an `IterInput` over a
    /// channel receiver.
    #[derive(Clone, Default)]
    struct BlockingQueue(Arc<(StdMutex<QueueState>, Condvar)>);

    #[derive(Default)]
    struct QueueState {
        items: VecDeque<u32>,
        closed: bool,
    }

    impl BlockingQueue {
        fn push(&self, v: u32) {
            let (state, ready) = &*self.0;
            state.lock().expect("test: lock queue").items.push_back(v);
            ready.notify_all();
        }

        /// Wakes every parked reader, so no blocking thread outlives the test.
        /// The runtime waits for those threads when it is dropped.
        fn close(&self) {
            let (state, ready) = &*self.0;
            state.lock().expect("test: lock queue").closed = true;
            ready.notify_all();
        }
    }

    impl ServiceInput for BlockingQueue {
        type Msg = u32;
    }

    impl SyncServiceInput for BlockingQueue {
        fn recv_next(&mut self, _shutdown: &impl AsyncGuard) -> anyhow::Result<Option<u32>> {
            let (state, ready) = &*self.0;
            let mut state = state.lock().expect("test: lock queue");
            loop {
                if let Some(v) = state.items.pop_front() {
                    return Ok(Some(v));
                }
                if state.closed {
                    return Ok(None);
                }
                state = ready.wait(state).expect("test: wait on queue");
            }
        }
    }

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

    #[tokio::test]
    async fn result_after_a_dropped_recv_goes_to_the_next_call() {
        let queue = BlockingQueue::default();
        let mut inp = AsyncSyncInput::new(queue.clone());

        // The inner input ignores the stop signal, so its thread stays parked
        // after the timeout drops this call.
        let first = timeout(Duration::from_millis(100), inp.recv_next()).await;
        assert!(first.is_err(), "test: nothing should have been received");

        // The dropped call's thread takes this message.
        queue.push(7);

        let rv = timeout(Duration::from_secs(5), inp.recv_next()).await;
        queue.close();

        let rv = rv
            .expect("message taken by the dropped call was lost")
            .expect("test: recv input");
        assert_eq!(rv, Some(7));
    }
}
