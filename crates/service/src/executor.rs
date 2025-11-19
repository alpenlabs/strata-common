//! Traits for service executors.
use std::future::Future;

/// Executor for synchronous workers.
pub trait SyncExecutor {
    /// To get shutdown signal notification.
    type ShutdownGuard: SyncGuard + Send + 'static;

    /// Spawn a sync worker task.
    fn spawn_sync(
        &self,
        name: &'static str,
        worker: impl FnOnce(Self::ShutdownGuard) -> anyhow::Result<()> + Send + 'static,
    );
}

/// Executor for asynchronous workers.
pub trait AsyncExecutor {
    /// To get shutdown signal notification.
    type ShutdownGuard: AsyncGuard + Send + 'static;

    /// Spawn a future as a worker task.
    fn spawn_async<F>(
        &self,
        name: &'static str,
        worker: impl FnOnce(Self::ShutdownGuard) -> F + Send + 'static,
    ) where
        F: Future<Output = anyhow::Result<()>> + Send + 'static;
}

/// Provide shutdown signal to a sync worker task.
pub trait SyncGuard {
    /// Check if shutdown signal has been sent.
    fn should_shutdown(&self) -> bool;
}

/// Provide shutdown signal to an async worker task.
pub trait AsyncGuard {
    /// Returns a future that resolves when shutdown signal is sent.
    fn wait_for_shutdown(&self) -> impl Future<Output = ()> + Send;
}

impl SyncGuard for strata_tasks::ShutdownGuard {
    fn should_shutdown(&self) -> bool {
        strata_tasks::ShutdownGuard::should_shutdown(self)
    }
}

impl AsyncGuard for strata_tasks::ShutdownGuard {
    fn wait_for_shutdown(&self) -> impl Future<Output = ()> {
        strata_tasks::ShutdownGuard::wait_for_shutdown(self)
    }
}

impl SyncExecutor for strata_tasks::TaskExecutor {
    type ShutdownGuard = strata_tasks::ShutdownGuard;

    fn spawn_sync(
        &self,
        name: &'static str,
        func: impl FnOnce(Self::ShutdownGuard) -> anyhow::Result<()> + Send + 'static,
    ) {
        self.spawn_critical(name, func);
    }
}

impl AsyncExecutor for strata_tasks::TaskExecutor {
    type ShutdownGuard = strata_tasks::ShutdownGuard;

    fn spawn_async<F>(&self, name: &'static str, async_func: impl FnOnce(Self::ShutdownGuard) -> F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.spawn_critical_async_with_shutdown(name, async_func);
    }
}
