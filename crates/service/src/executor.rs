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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use serde::Serialize;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{AsyncService, Response, ServiceBuilder, ServiceState, TokioMpscInput};

    /// A minimal async guard backed by a shared flag.
    struct MockGuard {
        flag: Arc<AtomicBool>,
    }

    impl AsyncGuard for MockGuard {
        async fn wait_for_shutdown(&self) {
            // Poll until the flag is set.  In a real impl this would be
            // notification-based; good enough for a test.
            loop {
                if self.flag.load(Ordering::Relaxed) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        }
    }

    /// A minimal async executor that spawns via `tokio::spawn`.
    struct MockExecutor {
        shutdown: Arc<AtomicBool>,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                shutdown: Arc::new(AtomicBool::new(false)),
            }
        }

        fn trigger_shutdown(&self) {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }

    impl AsyncExecutor for MockExecutor {
        type ShutdownGuard = MockGuard;

        fn spawn_async<F>(
            &self,
            _name: &'static str,
            worker: impl FnOnce(Self::ShutdownGuard) -> F + Send + 'static,
        ) where
            F: Future<Output = anyhow::Result<()>> + Send + 'static,
        {
            let guard = MockGuard {
                flag: self.shutdown.clone(),
            };
            tokio::spawn(worker(guard));
        }
    }

    // ---- trivial service definition ----

    #[derive(Clone, Debug, Serialize)]
    struct TestStatus;

    struct TestState;

    impl ServiceState for TestState {
        fn name(&self) -> &str {
            "test"
        }
    }

    struct TestService;

    impl crate::Service for TestService {
        type State = TestState;
        type Msg = u32;
        type Status = TestStatus;

        fn get_status(_s: &Self::State) -> Self::Status {
            TestStatus
        }
    }

    impl AsyncService for TestService {
        async fn process_input(_state: &mut TestState, _input: u32) -> anyhow::Result<Response> {
            Ok(Response::Continue)
        }
    }

    /// Service framework works with a non-`strata_tasks` executor.
    #[tokio::test]
    async fn launch_async_with_mock_executor() {
        let executor = MockExecutor::new();

        let (tx, rx) = mpsc::channel(10);
        let input = TokioMpscInput::new(rx);

        let _monitor = ServiceBuilder::<TestService, _>::new()
            .with_state(TestState)
            .with_input(input)
            .launch_async("test_svc", &executor)
            .await
            .unwrap();

        // Send a message through the service.
        tx.send(42).await.unwrap();

        // Trigger shutdown and let the worker exit.
        executor.trigger_shutdown();

        // Drop the sender so the worker's input stream also ends.
        drop(tx);

        // Give the spawned task a moment to complete.
        tokio::task::yield_now().await;
    }
}
