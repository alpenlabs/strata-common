//! Async service worker task.

use std::time::Instant;

use futures::FutureExt;
use tokio::sync::watch;
use tracing::*;

use crate::{
    instrumentation::{
        record_shutdown_result, OperationResult, ServiceInstrumentation, ShutdownReason,
    },
    AsyncService, AsyncServiceInput, Response, ServiceState,
};

/// Async worker task.
pub(crate) async fn worker_task<S: AsyncService, I>(
    mut state: S::State,
    mut inp: I,
    status_tx: watch::Sender<S::Status>,
    shutdown_guard: strata_tasks::ShutdownGuard,
) -> anyhow::Result<()>
where
    I: AsyncServiceInput<Msg = S::Msg>,
{
    let service_name = state.name().to_string();
    let span_prefix = state.span_prefix().to_string();
    let instrumentation = ServiceInstrumentation::new(&service_name);

    // Create parent lifecycle span wrapping entire service lifetime
    let lifecycle_span =
        instrumentation.create_lifecycle_span(&span_prefix, &service_name, "async");
    let _lifecycle_guard = lifecycle_span.enter();

    info!(service.name = %service_name, "service starting");

    // Perform startup logic.  If this errors we propagate it immediately and
    // crash the task.
    {
        let launch_span = info_span!("{}.launch", span_prefix, service.name = %service_name);
        let start = Instant::now();

        let launch_result = S::on_launch(&mut state).instrument(launch_span).await;
        let duration = start.elapsed();
        let result = OperationResult::from(&launch_result);

        instrumentation.record_launch(duration, result);

        launch_result?;
        info!(service.name = %service_name, duration_ms = duration.as_millis(), "service launch completed");
    }

    // Wrapping for the worker task to respect shutdown requests.
    let err = {
        let mut exit_fut = Box::pin(shutdown_guard.wait_for_shutdown().fuse());
        let mut wkr_fut = Box::pin(
            worker_task_inner::<S, I>(
                &mut state,
                &mut inp,
                &status_tx,
                &instrumentation,
                &span_prefix,
            )
            .fuse(),
        );

        futures::select! {
            _ = exit_fut => {
                info!(service.name = %service_name, "shutdown signal received");
                None
            },
            res = wkr_fut => res.err(),
        }
    };

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
    )
    .await;

    info!(service.name = %service_name, "service stopped");

    Ok(())
}

async fn worker_task_inner<S: AsyncService, I>(
    state: &mut S::State,
    inp: &mut I,
    status_tx: &watch::Sender<S::Status>,
    instrumentation: &ServiceInstrumentation,
    span_prefix: &str,
) -> anyhow::Result<()>
where
    I: AsyncServiceInput<Msg = S::Msg>,
{
    let service_name = state.name().to_string();

    // Process messages in a loop
    while let Some(input) = inp.recv_next().await? {
        let msg_span = debug_span!(
            "{}.process_message", span_prefix,
            service.name = %service_name
        );
        let start = Instant::now();

        // Process the input.
        let res = S::process_input(state, &input).instrument(msg_span).await;

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
                    ?input,
                    duration_ms = duration.as_millis(),
                    %e,
                    "failed to process message"
                );
                // TODO support optional retry
                return Err(e);
            }
        };

        // Update the status.
        let status = S::get_status(state);
        let _ = status_tx.send(status);

        if res == Response::ShouldExit {
            break;
        }
    }

    Ok(())
}

/// Handles service shutdown cleanup and instrumentation.
///
/// Executes the service's shutdown logic, measures cleanup duration, and records
/// shutdown metrics. This runs on every service exit (normal shutdown, error, or signal).
/// Unclean exits (SIGKILL, panic, OOM) may skip this handler entirely.
async fn handle_shutdown<S: AsyncService>(
    state: &mut S::State,
    err: Option<&anyhow::Error>,
    instrumentation: &ServiceInstrumentation,
    shutdown_reason: ShutdownReason,
    span_prefix: &str,
) {
    let service_name = state.name().to_string();
    let shutdown_span = info_span!("{}.shutdown", span_prefix, service.name = %service_name);
    let start = Instant::now();

    let shutdown_result = S::before_shutdown(state, err)
        .instrument(shutdown_span)
        .await;

    let duration = start.elapsed();

    record_shutdown_result(
        &service_name,
        shutdown_result,
        duration,
        instrumentation,
        shutdown_reason,
    );
}
