//! Blocking worker task.

use std::time::Instant;

use tokio::sync::watch;
use tracing::*;

use crate::{
    instrumentation::{
        record_shutdown_result, OperationResult, ServiceInstrumentation, ShutdownReason,
    },
    Response, ServiceState, SyncService, SyncServiceInput,
};

pub(crate) fn worker_task<S: SyncService, I>(
    ctx: S::Context,
    mut state: S::State,
    mut inp: I,
    status_tx: watch::Sender<S::Status>,
    shutdown_guard: strata_tasks::ShutdownGuard,
) -> anyhow::Result<()>
where
    I: SyncServiceInput<Msg = S::Msg>,
{
    let service_name = state.name().to_string();
    let span_prefix = S::span_prefix().to_string();
    let instrumentation = ServiceInstrumentation::new(&service_name);

    // Create parent lifecycle span wrapping entire service lifetime
    let lifecycle_span = instrumentation.create_lifecycle_span(&span_prefix, &service_name, "sync");
    let _lifecycle_guard = lifecycle_span.enter();

    info!(service.name = %service_name, "service starting");

    // Perform startup logic.  If this errors we propagate it immediately and
    // crash the task.
    {
        let launch_span = info_span!("{}.launch", span_prefix, service.name = %service_name);
        let _g = launch_span.enter();
        let start = Instant::now();

        let launch_result = S::on_launch(&ctx, &mut state);
        let duration = start.elapsed();
        let result = OperationResult::from(&launch_result);

        instrumentation.record_launch(duration, result);

        launch_result?;
        info!(service.name = %service_name, duration_ms = duration.as_millis(), "service launch completed");
    }

    // Process each message in a loop.  We do a shutdown check after each
    // possibly long-running call.
    let mut err = None;
    while let Some(input) = inp.recv_next()? {
        // Check after getting a new input.
        if shutdown_guard.should_shutdown() {
            info!(service.name = %service_name, "shutdown signal received");
            break;
        }

        let msg_span = debug_span!(
            "{}.process_message", span_prefix,
            service.name = %service_name
        );
        let _g = msg_span.enter();
        let start = Instant::now();

        // Process the input.
        let res = S::process_input(&ctx, &mut state, &input);

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
        &ctx,
        &mut state,
        err.as_ref(),
        &instrumentation,
        shutdown_reason,
        &span_prefix,
    );

    info!(service.name = %service_name, "service stopped");

    Ok(())
}

/// Handles service shutdown cleanup and instrumentation.
///
/// Executes the service's shutdown logic, measures cleanup duration, and records
/// shutdown metrics. This runs on every service exit (normal shutdown, error, or signal).
/// Unclean exits (SIGKILL, panic, OOM) may skip this handler entirely.
fn handle_shutdown<S: SyncService>(
    ctx: &S::Context,
    state: &mut S::State,
    err: Option<&anyhow::Error>,
    instrumentation: &ServiceInstrumentation,
    shutdown_reason: ShutdownReason,
    span_prefix: &str,
) {
    let service_name = state.name().to_string();
    let shutdown_span = info_span!("{}.shutdown", span_prefix, service.name = %service_name);
    let _g = shutdown_span.enter();
    let start = Instant::now();

    let shutdown_result = S::before_shutdown(ctx, state, err);

    let duration = start.elapsed();

    record_shutdown_result(
        &service_name,
        shutdown_result,
        duration,
        instrumentation,
        shutdown_reason,
    );
}
