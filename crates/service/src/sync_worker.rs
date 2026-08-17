//! Blocking worker task.

use std::time::Instant;

use tokio::sync::watch;
use tracing::*;

use crate::instrumentation::{
    record_shutdown_result, OperationResult, ServiceInstrumentation, ShutdownReason,
};
use crate::{AsyncGuard, Response, ServiceState, SyncGuard, SyncService, SyncServiceInput};

pub(crate) fn worker_task<S: SyncService, I>(
    mut state: S::State,
    mut inp: I,
    status_tx: watch::Sender<S::Status>,
    shutdown_guard: impl SyncGuard + AsyncGuard + Sync,
) -> anyhow::Result<()>
where
    I: SyncServiceInput<Msg = S::Msg>,
{
    let service_name = state.name().to_string();
    let span_prefix = state.span_prefix().to_string();
    let instrumentation = ServiceInstrumentation::new(&service_name);

    // Create parent lifecycle span wrapping entire service lifetime
    let lifecycle_span = instrumentation.create_lifecycle_span(&span_prefix, &service_name, "sync");
    let _lifecycle_guard = lifecycle_span.enter();

    info!(service.name = %service_name, "service starting");

    // Perform startup logic.  If this errors we propagate it immediately and
    // crash the task.
    {
        let launch_span = info_span!(
            "service.launch",
            span_prefix = %span_prefix,
            service.name = %service_name,
        );
        let _g = launch_span.enter();
        let start = Instant::now();

        let launch_result = S::on_launch(&mut state);
        let duration = start.elapsed();
        let result = OperationResult::from(&launch_result);

        instrumentation.record_launch(duration, result);

        launch_result?;
        info!(service.name = %service_name, duration_ms = duration.as_millis(), "service launch completed");
    }

    // Process each message in a loop.  We do a shutdown check after each
    // possibly long-running call.
    //
    // The wait for input is itself shutdown-aware: this worker owns a plain
    // thread that nothing can cancel from outside, so a plain blocking receive
    // would sit through a shutdown until the next message arrived (for a command
    // channel, possibly never).
    let mut err = None;
    while let Some(input) = inp.recv_next_until_shutdown(&shutdown_guard)? {
        // Check after getting a new input.
        if shutdown_guard.should_shutdown() {
            info!(service.name = %service_name, "shutdown signal received");
            break;
        }

        let msg_span = trace_span!(
            "service.process_message",
            span_prefix = %span_prefix,
            service.name = %service_name,
        );
        let _g = msg_span.enter();
        let start = Instant::now();

        // Process the input.
        let res = S::process_input(&mut state, input);

        let duration = start.elapsed();
        let result = OperationResult::from(&res);

        // Record metrics
        instrumentation.record_message(duration, result);

        // Handle processing result
        let res = match res {
            Ok(res) => res,
            Err(e) => {
                error!(
                    service.name = %service_name,
                    duration_ms = duration.as_millis(),
                    %e,
                    "failed to process message"
                );
                // TODO support optional retry
                err = Some(e);
                break;
            }
        };

        // Also check after processing input before trying to get a new one.
        if shutdown_guard.should_shutdown() {
            info!(service.name = %service_name, "shutdown signal received");
            break;
        }

        // Update the status.
        let status = S::get_status(&state);
        let _ = status_tx.send(status);

        if res == Response::ShouldExit {
            break;
        }
    }

    // Perform shutdown handling.
    let shutdown_reason = if err.is_some() {
        ShutdownReason::Error
    } else {
        ShutdownReason::Normal
    };

    handle_shutdown::<S>(
        &mut state,
        err.as_ref(),
        &instrumentation,
        shutdown_reason,
        &span_prefix,
    );

    info!(service.name = %service_name, "service stopped");

    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Handles service shutdown cleanup and instrumentation.
///
/// Executes the service's shutdown logic, measures cleanup duration, and records
/// shutdown metrics. This runs on every service exit (normal shutdown, error, or signal).
/// Unclean exits (SIGKILL, panic, OOM) may skip this handler entirely.
fn handle_shutdown<S: SyncService>(
    state: &mut S::State,
    err: Option<&anyhow::Error>,
    instrumentation: &ServiceInstrumentation,
    shutdown_reason: ShutdownReason,
    span_prefix: &str,
) {
    let service_name = state.name().to_string();
    let shutdown_span = info_span!(
        "service.shutdown",
        span_prefix = %span_prefix,
        service.name = %service_name,
    );
    let _g = shutdown_span.enter();
    let start = Instant::now();

    let shutdown_result = S::before_shutdown(state, err);

    let duration = start.elapsed();

    record_shutdown_result(
        &service_name,
        shutdown_result,
        duration,
        instrumentation,
        shutdown_reason,
    );
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use serde::Serialize;
    use tokio::sync::{mpsc, watch, Notify};

    use super::*;
    use crate::{SyncGuard, TokioMpscInput, VecInput};

    /// Guard that never signals shutdown.
    struct NeverShutdown;

    impl SyncGuard for NeverShutdown {
        fn should_shutdown(&self) -> bool {
            false
        }
    }

    impl AsyncGuard for NeverShutdown {
        async fn wait_for_shutdown(&self) {
            std::future::pending().await
        }
    }

    #[derive(Clone, Debug, Serialize)]
    struct TestStatus;

    struct TestState;

    impl ServiceState for TestState {
        fn name(&self) -> &str {
            "test-sync"
        }
    }

    struct FailingService;

    impl crate::Service for FailingService {
        type State = TestState;
        type Msg = u32;
        type Status = TestStatus;

        fn get_status(_s: &Self::State) -> Self::Status {
            TestStatus
        }
    }

    impl SyncService for FailingService {
        fn process_input(_state: &mut TestState, _input: u32) -> anyhow::Result<Response> {
            anyhow::bail!("sync process error")
        }
    }

    struct OkService;

    impl crate::Service for OkService {
        type State = TestState;
        type Msg = u32;
        type Status = TestStatus;

        fn get_status(_s: &Self::State) -> Self::Status {
            TestStatus
        }
    }

    impl SyncService for OkService {
        fn process_input(_state: &mut TestState, _input: u32) -> anyhow::Result<Response> {
            Ok(Response::Continue)
        }
    }

    #[test]
    fn worker_task_propagates_inner_error() {
        let inp = VecInput::from_iter([1u32]);
        let (status_tx, _status_rx) = watch::channel(TestStatus);

        let result = worker_task::<FailingService, _>(TestState, inp, status_tx, NeverShutdown);

        let err = result.expect_err("worker_task should return Err on process_input failure");
        assert!(
            err.to_string().contains("sync process error"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn worker_task_returns_ok_on_complete_without_error() {
        let inp = VecInput::from_iter([1u32, 2, 3]);
        let (status_tx, _status_rx) = watch::channel(TestStatus);

        let result = worker_task::<OkService, _>(TestState, inp, status_tx, NeverShutdown);

        result.expect("worker_task should return Ok when all inputs succeed");
    }

    /// Guard whose shutdown is driven by a flag we flip from the test.
    #[derive(Clone, Default)]
    struct FlagShutdown {
        flag: Arc<AtomicBool>,
        notify: Arc<Notify>,
    }

    impl FlagShutdown {
        fn trigger(&self) {
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
            while !self.should_shutdown() {
                self.notify.notified().await;
            }
        }
    }

    /// A worker parked on an idle command channel must stop when shutdown is
    /// signalled. Nothing can cancel the worker's thread from outside, so if the
    /// wait for input ignored the guard the worker would sit here until the next
    /// message — which, on a command channel whose senders are held for the life
    /// of the process, may be never.
    #[test]
    fn worker_task_exits_while_parked_on_idle_input() {
        // Sender stays alive for the whole test, so the channel never closes on
        // its own and only the shutdown signal can end the wait.
        let (_tx, rx) = mpsc::channel::<u32>(4);
        let inp = TokioMpscInput::new(rx);
        let (status_tx, _status_rx) = watch::channel(TestStatus);
        let shutdown = FlagShutdown::default();

        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            worker_task::<OkService, _>(TestState, inp, status_tx, worker_shutdown)
        });

        // Let the worker reach the parked state before signalling, so we are
        // testing the wait rather than the pre-loop check.
        thread::sleep(Duration::from_millis(100));
        assert!(
            !worker.is_finished(),
            "worker should be parked on the input"
        );

        shutdown.trigger();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !worker.is_finished() {
            assert!(
                Instant::now() < deadline,
                "worker did not wake on the shutdown signal",
            );
            thread::sleep(Duration::from_millis(10));
        }

        worker
            .join()
            .expect("worker thread panicked")
            .expect("a shutdown is a normal exit, not an error");
    }
}
