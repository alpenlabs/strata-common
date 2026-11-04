//! A shutdown guard driven by a flag.

use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use crate::{AsyncGuard, SyncGuard};

/// Shutdown guard driven by a flag that its owner flips with
/// [`trigger`](Self::trigger).
///
/// Its wait future is woken only through its waker, so it meets the guard
/// contract on [`SyncExecutor::ShutdownGuard`](crate::SyncExecutor::ShutdownGuard).
/// Tests also use it to drive inputs directly. Worker-level tests should go
/// through a real `strata_tasks` executor instead.
#[derive(Clone, Default)]
pub(crate) struct FlagShutdown {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl FlagShutdown {
    pub(crate) fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

impl SyncGuard for FlagShutdown {
    fn should_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl AsyncGuard for FlagShutdown {
    async fn wait_for_shutdown(&self) {
        let mut notified = pin!(self.notify.notified());
        loop {
            notified.as_mut().enable();
            if self.should_shutdown() {
                return;
            }
            notified.as_mut().await;
            notified.set(self.notify.notified());
        }
    }
}
