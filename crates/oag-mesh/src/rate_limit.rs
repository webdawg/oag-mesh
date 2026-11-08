//! A tiny in-memory token bucket for the one endpoint that can turn a single request into
//! real outbound network traffic (`POST /oag-mesh/v1/route-search`).
//!
//! This is deliberately not a general-purpose rate limiter: it has no requester identity, no
//! persistence, and no configuration surface. It exists because `spec/13-distributed-route-
//! search.md`'s "Anti-amplification" section names a concrete gap -- a query can fan out across
//! `branching_factor^hops` in the worst case -- and a node-wide token bucket is the smallest
//! honest answer that does not pretend to authenticate anyone this transport cannot identify.
//!
//! The bucket is in-memory only, so a restart resets it. That is stated rather than hidden: this
//! raises the cost of triggering fan-out, it does not bound it absolutely.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A token bucket with a fixed capacity and a constant refill rate.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Creates a full bucket holding `capacity` tokens, refilling at `refill_per_sec` tokens per
    /// second. A non-positive refill rate creates a bucket that never refills.
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity as f64,
            tokens: capacity as f64,
            refill_per_sec: refill_per_sec.max(0.0),
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Takes one token if one is available. Returns `false` when the bucket is empty.
    pub fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    /// `try_take` at an explicit instant, so tests can advance time without sleeping.
    pub fn try_take_at(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How long a caller should wait before retrying, once the bucket is empty.
    pub fn retry_after(&self) -> Duration {
        self.retry_after_at(Instant::now())
    }

    /// `retry_after` at an explicit instant, so tests can assert the reported wait. Accounts
    /// for the tokens that would have refilled by `now` without mutating the bucket.
    pub fn retry_after_at(&self, now: Instant) -> Duration {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if tokens >= 1.0 {
            return Duration::ZERO;
        }
        if self.refill_per_sec <= 0.0 {
            return Duration::from_secs(60);
        }
        Duration::from_secs_f64(((1.0 - tokens) / self.refill_per_sec).max(0.001))
    }
}

/// A fixed-window rate limiter keyed by an arbitrary string, matching the base project's
/// `RateLimiter` pattern (`spec/18-rate-limiting-and-resource-limits.md` there). Used where the
/// key is a real identity -- a responder's `PeerId` -- unlike `TokenBucket`, which this crate
/// uses for the node-wide route-search limit because that surface has no requester identity.
///
/// The tracking map is bounded: once it exceeds `max_entries`, entries whose window has already
/// expired are swept, and a new key is refused rather than growing the map without bound. That
/// is the same unbounded-map lesson the base project recorded, applied here to a mesh where a
/// griefer could mint identities to grow the map.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max_requests: u32,
    entries: RwLock<HashMap<String, (Instant, u32)>>,
    max_entries: usize,
}

impl RateLimiter {
    pub fn new(window: Duration, max_requests: u32) -> Self {
        Self {
            window,
            max_requests,
            entries: RwLock::new(HashMap::new()),
            max_entries: 10_000,
        }
    }

    /// Counts one request for `key`. Returns `Err(retry_after)` when the key's current window is
    /// already at its cap, or when the tracking map is full of live windows and cannot admit a
    /// new key without growing without bound.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut entries = self.entries.write().unwrap();
        if entries.len() >= self.max_entries {
            entries.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            if entries.len() >= self.max_entries {
                return Err(self.window);
            }
        }
        let entry = entries.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.max_requests {
            let elapsed = now.duration_since(entry.0).as_secs_f64();
            let retry = (self.window.as_secs_f64() - elapsed).max(0.001);
            return Err(Duration::from_secs_f64(retry));
        }
        entry.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_bucket_allows_up_to_capacity() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(3, 0.0);
        assert!(bucket.try_take_at(start));
        assert!(bucket.try_take_at(start));
        assert!(bucket.try_take_at(start));
        assert!(!bucket.try_take_at(start));
    }

    #[test]
    fn an_empty_bucket_refills_at_the_configured_rate() {
        let mut bucket = TokenBucket::new(1, 2.0);
        let start = Instant::now();
        assert!(bucket.try_take_at(start));
        assert!(!bucket.try_take_at(start));

        // Half a second at two tokens per second is exactly one token.
        assert!(bucket.try_take_at(start + Duration::from_millis(500)));
        assert!(!bucket.try_take_at(start + Duration::from_millis(500)));
    }

    #[test]
    fn retry_after_reports_a_wait_when_empty() {
        let mut bucket = TokenBucket::new(1, 2.0);
        let start = Instant::now();
        bucket.try_take_at(start);
        let retry_after = bucket.retry_after_at(start);
        assert!(retry_after > Duration::ZERO);
        assert_eq!(retry_after, Duration::from_millis(500));
    }

    #[test]
    fn a_rate_limiter_allows_up_to_the_window_cap() {
        let limiter = RateLimiter::new(Duration::from_millis(100), 2);
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_err());
        // A different key has its own window.
        assert!(limiter.check("b").is_ok());
    }

    #[test]
    fn a_rate_limiter_resets_after_the_window() {
        let limiter = RateLimiter::new(Duration::from_millis(50), 1);
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_err());
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check("a").is_ok());
    }

    #[test]
    fn a_rate_limiter_reports_the_remaining_window() {
        let limiter = RateLimiter::new(Duration::from_millis(500), 1);
        limiter.check("a").unwrap();
        let retry_after = limiter.check("a").unwrap_err();
        assert!(retry_after > Duration::ZERO);
        assert!(retry_after <= Duration::from_millis(500));
    }

    #[test]
    fn a_bucket_never_exceeds_its_capacity() {
        let mut bucket = TokenBucket::new(2, 100.0);
        let start = Instant::now();
        bucket.try_take_at(start);
        bucket.try_take_at(start);
        // Still only two tokens after a long idle period, not 1000.
        assert!(bucket.try_take_at(start + Duration::from_secs(10)));
        assert!(bucket.try_take_at(start + Duration::from_secs(10)));
        assert!(!bucket.try_take_at(start + Duration::from_secs(10)));
    }
}
