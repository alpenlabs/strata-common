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
        // Clamp so `max_delay_ms` is a real upper bound from the first retry
        // onward, not just once `next_delay_ms()` has had a chance to apply it.
        let base_delay_ms = match max_delay_ms {
            Some(cap) => base_delay_ms.min(cap),
            None => base_delay_ms,
        };
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
        // Widen to u128 before multiplying: a u64 `saturating_mul` can clip the
        // product to u64::MAX ahead of the division, distorting the fixed-point
        // ratio (e.g. multiplier == multiplier_base == u64::MAX, which should be
        // a 1x no-op, would otherwise collapse to a near-zero delay).
        let product = curr_delay_ms as u128 * self.multiplier as u128;
        let next = (product / self.multiplier_base as u128).min(u64::MAX as u128) as u64;
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
    fn base_delay_above_cap_is_clamped() {
        let b = ExponentialBackoff::new(100_000, 20, 10, Some(60_000));
        assert_eq!(b.base_delay_ms(), 60_000);
    }

    #[test]
    fn ratio_survives_multiplication_overflow() {
        // multiplier == multiplier_base is a 1x ratio; with u64 math the
        // product would saturate to u64::MAX and divide back down to ~1ms.
        let b = ExponentialBackoff::new(1000, u64::MAX, u64::MAX, None);
        assert_eq!(b.next_delay_ms(1000), 1000);
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
