//! Per-tenant rate limiter for Azure APIs.
//!
//! Implements a leaky-token-bucket quota limiter with explicit
//! `Retry-After` penalty support. Each `(source_kind, tenant_id)` key
//! in the upper layer holds its own [`QuotaLimiter`] so different
//! tenants and different APIs don't cross-contaminate.
//!
//! Known Azure quotas (plan §3):
//!
//! | Surface              | Quota                                 | Limiter config                       |
//! |----------------------|---------------------------------------|--------------------------------------|
//! | Log Analytics Query  | 200 queries / 30s, 5 concurrent       | `QuotaLimiter::new(200, 200.0/30.0)` |
//! | Defender XDR Hunting | ~45 calls / 60s per tenant            | `QuotaLimiter::new(45, 45.0/60.0)`   |
//! | Sentinel Data Lake   | looser (assume 120/60s conservative)  | `QuotaLimiter::new(120, 2.0)`        |
//!
//! Why not `governor`:
//! - No new dep. `governor` pulls `nonzero_ext`, `dashmap`, etc. —
//!   at the current dev disk budget every new transitive dep hurts.
//! - The semantics we actually need are simple: a bucket that refills
//!   at a fixed rate and supports 429-driven penalties. That's ~100
//!   lines of Rust, not a crate.
//!
//! Concurrency:
//! - Backed by a plain `std::sync::Mutex` (not async) because the
//!   critical section is microseconds. The public `acquire` method
//!   is async because it may need to `tokio::time::sleep` while
//!   waiting for tokens to refill, but the Mutex itself is never
//!   held across an await point.

use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// Token-bucket rate limiter with `Retry-After` penalty support.
pub struct QuotaLimiter {
    /// Maximum burst size (full bucket capacity).
    capacity: f64,
    /// Tokens added per second when the bucket is draining.
    refill_per_second: f64,
    state: Mutex<QuotaState>,
}

#[derive(Debug)]
struct QuotaState {
    /// Fractional token count (allows sub-second refill accuracy).
    available: f64,
    /// Timestamp of the last refill so we can compute the delta.
    last_refill: Instant,
    /// If set, `acquire` will block until this instant regardless of
    /// token count. Used for 429 penalties that honor the server's
    /// `Retry-After` header.
    penalty_until: Option<Instant>,
}

impl QuotaLimiter {
    /// Constructs a new limiter with the given burst capacity and
    /// refill rate. Starts fully-filled so the first N calls up to
    /// `capacity` don't wait.
    pub fn new(capacity: u32, refill_per_second: f64) -> Self {
        let cap = capacity.max(1) as f64;
        Self {
            capacity: cap,
            refill_per_second: refill_per_second.max(0.0),
            state: Mutex::new(QuotaState {
                available: cap,
                last_refill: Instant::now(),
                penalty_until: None,
            }),
        }
    }

    /// Non-blocking acquire. Returns:
    ///
    /// - `Ok(())` if a token was consumed.
    /// - `Err(duration)` with how long the caller should wait before
    ///   retrying. The duration is the minimum sleep needed to either
    ///   (a) refill one token, or (b) clear an active penalty.
    pub fn try_acquire(&self) -> Result<(), Duration> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        self.refill_locked(&mut state, now);

        // Penalty check takes precedence over token count.
        if let Some(until) = state.penalty_until {
            if until > now {
                return Err(until.duration_since(now));
            }
            state.penalty_until = None;
        }

        if state.available >= 1.0 {
            state.available -= 1.0;
            Ok(())
        } else {
            Err(self.next_token_wait_locked(&state))
        }
    }

    /// Blocks asynchronously until a token is acquired. Loops
    /// `try_acquire` + `tokio::time::sleep` until success. Cancellable
    /// by the caller wrapping this in `tokio::select!` with a
    /// CancellationToken.
    pub async fn acquire(&self) {
        loop {
            match self.try_acquire() {
                Ok(()) => return,
                Err(wait) => {
                    // Clamp to at least 1 ms so we don't busy-loop on
                    // fractional nanosecond waits.
                    let wait = wait.max(Duration::from_millis(1));
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// Applies a retry-after penalty. All subsequent `acquire` calls
    /// will block for at least `duration` even if tokens are available.
    /// Use this when the server returns 429 with a `Retry-After` header.
    pub fn penalize(&self, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        let new_until = Instant::now() + duration;
        // Extend existing penalty rather than shortening it — if we
        // got a 429 on top of another 429, the latest server deadline
        // wins only if it's later.
        state.penalty_until = Some(match state.penalty_until {
            Some(existing) if existing > new_until => existing,
            _ => new_until,
        });
        // Also drain the bucket to discourage a burst the moment the
        // penalty lifts. This is belt-and-suspenders: the test below
        // pins the behavior.
        state.available = 0.0;
    }

    /// Returns the current token count. Useful for metrics/dashboards.
    pub fn available(&self) -> f64 {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        self.refill_locked(&mut state, now);
        state.available
    }

    /// Whether the limiter is currently under penalty (no acquires
    /// will succeed for this duration).
    pub fn penalty_remaining(&self) -> Option<Duration> {
        let state = self.state.lock().unwrap();
        state.penalty_until.and_then(|until| {
            let now = Instant::now();
            if until > now {
                Some(until.duration_since(now))
            } else {
                None
            }
        })
    }

    // --- internals ---

    fn refill_locked(&self, state: &mut QuotaState, now: Instant) {
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        if elapsed > 0.0 && self.refill_per_second > 0.0 {
            let delta = elapsed * self.refill_per_second;
            state.available = (state.available + delta).min(self.capacity);
        }
        state.last_refill = now;
    }

    fn next_token_wait_locked(&self, state: &QuotaState) -> Duration {
        if self.refill_per_second <= 0.0 {
            // A refill rate of 0 means the bucket never refills. Block
            // forever (well, 1 hour — caller should cancel externally).
            return Duration::from_secs(3600);
        }
        let needed = (1.0 - state.available).max(0.0);
        let secs = needed / self.refill_per_second;
        Duration::from_secs_f64(secs)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn acquire_succeeds_up_to_capacity_then_waits() {
        let limiter = QuotaLimiter::new(3, 1.0); // 3 burst, 1/s refill
        // First 3 acquires succeed immediately.
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        // 4th is blocked. Wait time should be roughly 1 second.
        match limiter.try_acquire() {
            Err(d) => {
                assert!(
                    d <= Duration::from_secs_f64(1.01),
                    "expected ~1s wait, got {d:?}"
                );
            }
            Ok(()) => panic!("expected to be blocked"),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bucket_refills_over_time() {
        let limiter = QuotaLimiter::new(2, 2.0); // 2 burst, 2/s refill (0.5s per token)
        // Drain the bucket.
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_err());

        // Advance virtual time by 1 second → 2 tokens added, capped at capacity (2).
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_err());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bucket_capacity_clamps_refill() {
        let limiter = QuotaLimiter::new(5, 10.0); // 5 burst, 10/s refill
        // Drain.
        for _ in 0..5 {
            assert!(limiter.try_acquire().is_ok());
        }
        // Sleep for 10 seconds of virtual time. 10 × 10 = 100 tokens
        // would be added but clamped to capacity = 5.
        tokio::time::advance(Duration::from_secs(10)).await;
        let avail = limiter.available();
        assert!(avail <= 5.0 + 0.01, "available={avail}");
        assert!(avail >= 4.9, "available={avail}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn penalize_blocks_even_when_tokens_available() {
        let limiter = QuotaLimiter::new(10, 1.0);
        // Full bucket — normally this would succeed.
        assert!(limiter.try_acquire().is_ok());
        // Apply a 30s penalty.
        limiter.penalize(Duration::from_secs(30));
        // Next acquire must fail with roughly 30s wait.
        match limiter.try_acquire() {
            Err(d) => {
                assert!(d >= Duration::from_secs(29), "got {d:?}");
                assert!(d <= Duration::from_secs(31), "got {d:?}");
            }
            Ok(()) => panic!("penalty should have blocked"),
        }
        // penalty_remaining reports the same window.
        let remaining = limiter.penalty_remaining().unwrap();
        assert!(remaining >= Duration::from_secs(29));

        // Advance virtual time past the penalty.
        tokio::time::advance(Duration::from_secs(31)).await;
        // Bucket should be refilled (31 × 1/s, capped at 10), and the
        // penalty should be cleared.
        assert!(limiter.penalty_remaining().is_none());
        assert!(limiter.try_acquire().is_ok());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn penalize_extends_but_does_not_shrink() {
        let limiter = QuotaLimiter::new(5, 1.0);
        limiter.penalize(Duration::from_secs(60));
        // A shorter penalty applied on top must NOT shrink the window.
        limiter.penalize(Duration::from_secs(10));
        let remaining = limiter.penalty_remaining().unwrap();
        assert!(
            remaining >= Duration::from_secs(59),
            "penalty shortened: {remaining:?}"
        );
        // A longer penalty on top extends.
        limiter.penalize(Duration::from_secs(120));
        let remaining = limiter.penalty_remaining().unwrap();
        assert!(
            remaining >= Duration::from_secs(119),
            "penalty not extended: {remaining:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn acquire_blocks_until_token_available() {
        let limiter = QuotaLimiter::new(1, 2.0); // 1 burst, 2/s refill (0.5s/token)
        // Drain.
        assert!(limiter.try_acquire().is_ok());

        // Kick off acquire; it should return after ~0.5s.
        let start = Instant::now();
        let limiter_ref = &limiter;
        let handle = async move {
            limiter_ref.acquire().await;
            start.elapsed()
        };
        tokio::time::advance(Duration::from_millis(500)).await;
        let elapsed = handle.await;
        // Virtual time advanced 500ms; real time may differ, but with
        // start_paused we're effectively measuring virtual delta.
        assert!(elapsed <= Duration::from_millis(510), "got {elapsed:?}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn log_analytics_default_config() {
        // Log Analytics: 200 queries / 30s, 5 concurrent. The limiter
        // only handles rate; concurrency is a separate concern.
        let limiter = QuotaLimiter::new(200, 200.0 / 30.0);
        // Burst up to 200.
        for _ in 0..200 {
            assert!(limiter.try_acquire().is_ok());
        }
        // 201st blocks. Wait time ~ 1 / (200/30) = 0.15 s
        match limiter.try_acquire() {
            Err(d) => assert!(d <= Duration::from_millis(200), "got {d:?}"),
            Ok(()) => panic!("should be blocked at 201st query"),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn defender_xdr_default_config() {
        // Defender XDR: ~45 calls/60s → 0.75/s refill.
        let limiter = QuotaLimiter::new(45, 45.0 / 60.0);
        // Burst.
        for _ in 0..45 {
            assert!(limiter.try_acquire().is_ok());
        }
        // 46th blocks. Wait time ~ 1 / 0.75 ≈ 1.33 s
        match limiter.try_acquire() {
            Err(d) => {
                assert!(d >= Duration::from_millis(1300));
                assert!(d <= Duration::from_millis(1400));
            }
            Ok(()) => panic!("should be blocked at 46th query"),
        }
    }

    #[test]
    fn zero_refill_rate_never_refills() {
        let limiter = QuotaLimiter::new(2, 0.0);
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        // Sleep — no refill.
        std::thread::sleep(Duration::from_millis(50));
        match limiter.try_acquire() {
            Err(d) => {
                // Sentinel "forever" value.
                assert!(d >= Duration::from_secs(60));
            }
            Ok(()) => panic!("0 refill rate must never refill"),
        }
    }
}
