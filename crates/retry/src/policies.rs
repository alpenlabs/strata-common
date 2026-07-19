//! [`Backoff`] implementations.

use crate::Backoff;

/// Configuration for exponential retry backoff.
///
/// Uses a fixed-point multiplier (`multiplier / multiplier_base`) to avoid
/// floating-point math. For example, `multiplier = 150` with
/// `multiplier_base = 100` represents a 1.5× multiplier.
///
/// Carries an optional `max_delay_ms` cap so delays don't explode when retrying
/// for long durations. Without a cap, a 2× multiplier starting at 1 s reaches
/// ~17 minutes by attempt 11 and overflows `u64` not long after; for
/// resilience-oriented retry budgets the cap is essential.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    base_delay_ms: u64,
    multiplier: u64,
    multiplier_base: u64,
    max_delay_ms: Option<u64>,
}

impl ExponentialBackoff {
    /// Builds a new [`ExponentialBackoff`].
    ///
    /// # Panics
    ///
    /// Panics if `multiplier_base` is zero.
    pub fn new(
        base_delay_ms: u64,
        multiplier: u64,
        multiplier_base: u64,
        max_delay_ms: Option<u64>,
    ) -> Self {
        assert!(multiplier_base != 0, "multiplier_base must be non-zero");
        Self {
            base_delay_ms,
            multiplier,
            multiplier_base,
            max_delay_ms,
        }
    }
}

impl Backoff for ExponentialBackoff {
    fn base_delay_ms(&self) -> u64 {
        self.base_delay_ms
    }

    fn next_delay_ms(&self, curr_delay_ms: u64) -> u64 {
        let next = curr_delay_ms.saturating_mul(self.multiplier) / self.multiplier_base;
        match self.max_delay_ms {
            Some(cap) => next.min(cap),
            None => next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_grows_then_caps() {
        let b = ExponentialBackoff::new(1000, 20, 10, Some(60_000));
        let d1 = b.next_delay_ms(b.base_delay_ms());
        assert_eq!(d1, 2000);
        let d2 = b.next_delay_ms(d1);
        assert_eq!(d2, 4000);
        // Saturates at the cap.
        let mut d = d2;
        for _ in 0..20 {
            d = b.next_delay_ms(d);
        }
        assert_eq!(d, 60_000);
    }

    #[test]
    fn exponential_without_cap_grows_unbounded() {
        let b = ExponentialBackoff::new(1000, 20, 10, None);
        assert_eq!(b.next_delay_ms(1000), 2000);
        assert_eq!(b.next_delay_ms(2000), 4000);
    }

    #[test]
    #[should_panic]
    fn zero_multiplier_base_panics() {
        let _ = ExponentialBackoff::new(1000, 20, 0, None);
    }
}
