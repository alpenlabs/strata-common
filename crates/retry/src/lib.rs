//! Retry-with-backoff helpers.
//!
//! Wrap a fallible async call with [`retry_with_backoff_async`], pick a
//! [`Backoff`] implementation (e.g. [`ExponentialBackoff`]), and the helper
//! handles delays, logging, and exhaustion. [`RetryConfig`] is a serde-friendly
//! way to carry the parameters through configuration files.
//!
//! Consolidated from the per-repo copies that previously lived in
//! `strata_common::retry` (alpen) and `bin/asm-runner/src/retry.rs` (asm).

pub mod config;
pub mod policies;

use std::fmt;
use std::future::Future;
use std::time::Duration;

pub use config::RetryConfig;
pub use policies::ExponentialBackoff;
use tokio::time::sleep as async_sleep;
use tracing::{error, warn};

/// Backoff schedule: each implementation decides how the delay grows.
pub trait Backoff {
    /// Base delay in ms.
    fn base_delay_ms(&self) -> u64;

    /// Generates next delay given current delay.
    fn next_delay_ms(&self, curr_delay_ms: u64) -> u64;
}

/// Runs a fallible async operation with a backoff retry.
///
/// Retries the given async `operation` up to `max_retries` times with delays
/// increasing according to the provided [`Backoff`] implementation.
///
/// Logs a warning on each failure and an error if all retries are exhausted.
///
/// # Parameters
///
/// - `name`: Identifier used in logs for the operation.
/// - `max_retries`: Maximum number of retry attempts (not counting the initial attempt).
/// - `backoff`: Backoff configuration for computing delay.
/// - `operation`: Closure returning a Future that resolves to `Result`; retried on `Err`.
pub async fn retry_with_backoff_async<R, E, F, Fut>(
    name: &str,
    max_retries: u16,
    backoff: &impl Backoff,
    operation: F,
) -> Result<R, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, E>>,
    E: fmt::Debug,
{
    let mut delay = backoff.base_delay_ms();

    for attempt in 0..=max_retries {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < max_retries => {
                warn!(
                    attempt = attempt + 1,
                    %name,
                    delay_ms = delay,
                    ?err,
                    "operation failed, retrying"
                );
                async_sleep(Duration::from_millis(delay)).await;
                delay = backoff.next_delay_ms(delay);
            }
            Err(err) => {
                error!(%name, max_retries, ?err, "max retries exceeded, returning last error");
                return Err(err);
            }
        }
    }

    // Loop above always returns inside the match.
    unreachable!()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn retries_until_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let backoff = ExponentialBackoff::new(1, 10, 10, Some(10));
        let attempts_clone = attempts.clone();
        let result: Result<&'static str, &'static str> =
            retry_with_backoff_async("test", 5, &backoff, || {
                let attempts = attempts_clone.clone();
                async move {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    if n == 2 {
                        Ok("ok")
                    } else {
                        Err("not yet")
                    }
                }
            })
            .await;
        assert_eq!(result, Ok("ok"));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn exhausts_and_returns_last_error() {
        let backoff = ExponentialBackoff::new(1, 10, 10, Some(10));
        let result: Result<(), &'static str> =
            retry_with_backoff_async("test", 2, &backoff, || async { Err("nope") }).await;
        assert_eq!(result, Err("nope"));
    }
}
