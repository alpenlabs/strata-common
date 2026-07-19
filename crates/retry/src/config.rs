//! Serde-friendly retry configuration.

use serde::{Deserialize, Serialize};

use crate::policies::ExponentialBackoff;

/// Default retry attempts after the initial call.
const DEFAULT_MAX_RETRIES: u16 = 10;
/// Default initial delay before the first retry, in milliseconds.
const DEFAULT_BASE_DELAY_MS: u64 = 1_000;
/// Default backoff multiplier numerator (paired with [`DEFAULT_MULTIPLIER_BASE`]
/// for a 2× growth factor).
const DEFAULT_MULTIPLIER: u64 = 20;
/// Default backoff multiplier denominator.
const DEFAULT_MULTIPLIER_BASE: u64 = 10;
/// Default cap on the delay between retries, in milliseconds.
const DEFAULT_MAX_DELAY_MS: u64 = 60_000;

/// Serde-friendly configuration for [`retry_with_backoff_async`] +
/// [`ExponentialBackoff`]. Mirrors `ExponentialBackoff`'s fields (so it can
/// build one) and adds the `max_retries` count consumed by the retry helper.
///
/// See the `DEFAULT_*` consts in this module for the default values; together
/// they give roughly 17 minutes of patience.
///
/// [`retry_with_backoff_async`]: crate::retry_with_backoff_async
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts after the initial call.
    #[serde(default = "RetryConfig::default_max_retries")]
    pub max_retries: u16,
    /// Initial delay before the first retry, in milliseconds.
    #[serde(default = "RetryConfig::default_base_delay_ms")]
    pub base_delay_ms: u64,
    /// Numerator of the backoff multiplier (paired with `multiplier_base`).
    #[serde(default = "RetryConfig::default_multiplier")]
    pub multiplier: u64,
    /// Denominator of the backoff multiplier.
    #[serde(default = "RetryConfig::default_multiplier_base")]
    pub multiplier_base: u64,
    /// Maximum delay between retries, in milliseconds. Caps the exponential
    /// growth so long retry sequences don't produce absurd waits or overflow.
    #[serde(default = "RetryConfig::default_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl RetryConfig {
    fn default_max_retries() -> u16 {
        DEFAULT_MAX_RETRIES
    }
    fn default_base_delay_ms() -> u64 {
        DEFAULT_BASE_DELAY_MS
    }
    fn default_multiplier() -> u64 {
        DEFAULT_MULTIPLIER
    }
    fn default_multiplier_base() -> u64 {
        DEFAULT_MULTIPLIER_BASE
    }
    fn default_max_delay_ms() -> u64 {
        DEFAULT_MAX_DELAY_MS
    }

    /// Build an [`ExponentialBackoff`] from this config.
    pub fn backoff(&self) -> ExponentialBackoff {
        ExponentialBackoff::new(
            self.base_delay_ms,
            self.multiplier,
            self.multiplier_base,
            Some(self.max_delay_ms),
        )
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: Self::default_max_retries(),
            base_delay_ms: Self::default_base_delay_ms(),
            multiplier: Self::default_multiplier(),
            multiplier_base: Self::default_multiplier_base(),
            max_delay_ms: Self::default_max_delay_ms(),
        }
    }
}
