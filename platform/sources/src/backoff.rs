//! Exponential backoff with jitter, shared by every [`LogSource`] impl.
//!
//! Generalizes the backoff policy from
//! `app/src-tauri/src/sentinel_connector.rs` into a reusable component:
//!
//! - Exponential delay growth (configurable base + multiplier).
//! - Optional jitter (multiplicative, uniform in `[1.0, 1.0+jitter]`).
//! - Hard cap on max delay.
//! - Strike counter with a hard stop threshold (the 3-strike auth breaker
//!   from the Sentinel polling loop).
//!
//! The type is intentionally plain (no async) so it composes with both the
//! polling loop (`tokio::time::sleep(backoff.next())`) and synchronous
//! retry helpers. Jitter uses a tiny LCG-based RNG so this module has no
//! dependency on `rand` (keeps graph_hunter_core's dep surface small).
//!
//! Defaults match the existing Sentinel connector so Phase 3 source impls
//! are behavior-preserving when the policy is plugged in.
//!
//! [`LogSource`]: crate::LogSource

use std::time::Duration;

/// Defaults from `app/src-tauri/src/sentinel_connector.rs`.
pub const DEFAULT_BASE_DELAY: Duration = Duration::from_secs(3);
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(300);
pub const DEFAULT_MULTIPLIER: f64 = 3.0;
pub const DEFAULT_JITTER: f64 = 0.5; // ±50%
pub const DEFAULT_MAX_AUTH_FAILURES: u32 = 3;

/// Backoff policy state. Not async; callers combine it with
/// `tokio::time::sleep` (or any other sleep) to implement the actual
/// delay.
///
/// Use [`ExponentialBackoff::next_delay`] to compute the next delay and
/// advance the internal strike counter, or [`ExponentialBackoff::reset`]
/// to clear the counter after a successful call.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    base: Duration,
    max: Duration,
    multiplier: f64,
    jitter: f64,
    max_strikes: u32,
    strike: u32,
    // Tiny deterministic-ish RNG state seeded from the current time.
    // Using a full RNG crate for this one-off jitter would be overkill.
    rng_state: u64,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl ExponentialBackoff {
    /// Constructs a new backoff policy with the `DEFAULT_*` constants.
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xDEADBEEF);
        Self {
            base: DEFAULT_BASE_DELAY,
            max: DEFAULT_MAX_DELAY,
            multiplier: DEFAULT_MULTIPLIER,
            jitter: DEFAULT_JITTER,
            max_strikes: DEFAULT_MAX_AUTH_FAILURES,
            strike: 0,
            rng_state: seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1),
        }
    }

    /// Constructs a policy with an explicit seed for deterministic tests.
    pub fn with_seed(seed: u64) -> Self {
        let mut b = Self::new();
        b.rng_state = seed;
        b
    }

    pub fn with_base(mut self, base: Duration) -> Self {
        self.base = base;
        self
    }

    pub fn with_max(mut self, max: Duration) -> Self {
        self.max = max;
        self
    }

    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Sets the jitter fraction. `0.0` disables jitter (delays are
    /// deterministic); `0.5` means each delay is scaled by a uniform
    /// random factor in `[1.0, 1.5]`.
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.max(0.0);
        self
    }

    pub fn with_max_strikes(mut self, strikes: u32) -> Self {
        self.max_strikes = strikes;
        self
    }

    /// Returns the next delay and advances the strike counter. Returns
    /// `None` once the strike count has reached `max_strikes` — the
    /// caller should stop retrying and surface the failure to the user
    /// (this is the 3-strike auth breaker).
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.strike >= self.max_strikes {
            return None;
        }
        // delay = base * multiplier^strike, capped at max
        let raw_secs = self.base.as_secs_f64() * self.multiplier.powi(self.strike as i32);
        let capped = raw_secs.min(self.max.as_secs_f64());

        // Apply multiplicative jitter: factor in [1.0, 1.0 + jitter].
        let jitter_factor = if self.jitter > 0.0 {
            1.0 + self.jitter * self.next_unit()
        } else {
            1.0
        };
        let with_jitter = capped * jitter_factor;
        // Re-cap after jitter so very small jitters don't overshoot the
        // hard max.
        let final_secs = with_jitter.min(self.max.as_secs_f64());

        self.strike += 1;
        Some(Duration::from_secs_f64(final_secs))
    }

    /// Resets the strike counter. Call this after a successful request
    /// so the next failure starts from base delay again.
    pub fn reset(&mut self) {
        self.strike = 0;
    }

    /// Returns the current strike count without advancing.
    pub fn strike_count(&self) -> u32 {
        self.strike
    }

    /// Returns `true` if the policy is exhausted (strike >= max_strikes).
    pub fn is_exhausted(&self) -> bool {
        self.strike >= self.max_strikes
    }

    /// Draws a uniform `f64` in `[0, 1)` from the internal LCG. Same
    /// constants as the well-known `rand::rngs::SmallRng` (a.k.a. Xorshift
    /// 64*). Not cryptographically secure — it only needs to spread
    /// retries across a small window.
    fn next_unit(&mut self) -> f64 {
        self.rng_state ^= self.rng_state >> 12;
        self.rng_state ^= self.rng_state << 25;
        self.rng_state ^= self.rng_state >> 27;
        let x = self.rng_state.wrapping_mul(0x2545F4914F6CDD1D);
        // Take the top 53 bits and divide by 2^53 for a uniform [0,1).
        ((x >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_grow_exponentially_without_jitter() {
        let mut b = ExponentialBackoff::new()
            .with_base(Duration::from_secs(2))
            .with_max(Duration::from_secs(1000))
            .with_multiplier(3.0)
            .with_jitter(0.0)
            .with_max_strikes(5);

        // base=2, mult=3 → 2, 6, 18, 54, 162
        let d1 = b.next_delay().unwrap();
        let d2 = b.next_delay().unwrap();
        let d3 = b.next_delay().unwrap();
        let d4 = b.next_delay().unwrap();
        let d5 = b.next_delay().unwrap();

        assert_eq!(d1, Duration::from_secs(2));
        assert_eq!(d2, Duration::from_secs(6));
        assert_eq!(d3, Duration::from_secs(18));
        assert_eq!(d4, Duration::from_secs(54));
        assert_eq!(d5, Duration::from_secs(162));
    }

    #[test]
    fn delays_are_capped_at_max() {
        let mut b = ExponentialBackoff::new()
            .with_base(Duration::from_secs(1))
            .with_max(Duration::from_secs(10))
            .with_multiplier(10.0)
            .with_jitter(0.0)
            .with_max_strikes(5);

        // 1, 10, 100 → 1, 10, 10 (capped), 10, 10
        assert_eq!(b.next_delay().unwrap(), Duration::from_secs(1));
        assert_eq!(b.next_delay().unwrap(), Duration::from_secs(10));
        assert_eq!(b.next_delay().unwrap(), Duration::from_secs(10));
        assert_eq!(b.next_delay().unwrap(), Duration::from_secs(10));
        assert_eq!(b.next_delay().unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn max_strikes_exhausts_policy() {
        let mut b = ExponentialBackoff::new()
            .with_base(Duration::from_millis(10))
            .with_jitter(0.0)
            .with_max_strikes(3);

        assert!(!b.is_exhausted());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.is_exhausted());
        assert!(b.next_delay().is_none());
        assert!(b.next_delay().is_none());
    }

    #[test]
    fn reset_restores_base_delay() {
        let mut b = ExponentialBackoff::new()
            .with_base(Duration::from_secs(2))
            .with_multiplier(3.0)
            .with_jitter(0.0)
            .with_max_strikes(5);

        b.next_delay(); // 2s
        b.next_delay(); // 6s
        assert_eq!(b.strike_count(), 2);

        b.reset();
        assert_eq!(b.strike_count(), 0);

        let d = b.next_delay().unwrap();
        assert_eq!(d, Duration::from_secs(2));
    }

    #[test]
    fn jitter_stays_within_expected_band() {
        let mut b = ExponentialBackoff::with_seed(0x1234_5678_DEAD_BEEF)
            .with_base(Duration::from_secs(10))
            .with_max(Duration::from_secs(100))
            .with_multiplier(1.0)
            .with_jitter(0.5)
            .with_max_strikes(1000);

        // Draw 200 delays. With base=10, mult=1, each should be in
        // [10s, 15s] inclusive.
        for _ in 0..200 {
            let d = b.next_delay().unwrap();
            assert!(d >= Duration::from_secs(10), "delay {:?} below base", d);
            assert!(
                d <= Duration::from_secs_f64(15.0001),
                "delay {:?} above base + jitter",
                d
            );
        }
    }

    #[test]
    fn defaults_match_sentinel_connector() {
        let b = ExponentialBackoff::new();
        assert_eq!(b.base, Duration::from_secs(3));
        assert_eq!(b.max, Duration::from_secs(300));
        assert_eq!(b.multiplier, 3.0);
        assert_eq!(b.jitter, 0.5);
        assert_eq!(b.max_strikes, 3);
    }
}
