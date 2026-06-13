//! A tiny per-IP token-bucket accept limiter.
//!
//! Checked before the TLS handshake (and on raw-TCP tunnel ports) so a single
//! source cannot exhaust the relay with connection floods. Hand-rolled to avoid
//! a dependency; the map is swept and capped so it cannot grow without bound.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-IP token bucket: `rate` tokens/sec refill, up to `burst` capacity.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    max_entries: usize,
}

impl RateLimiter {
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate: rate_per_sec as f64,
            burst: burst as f64,
            buckets: Mutex::new(HashMap::new()),
            max_entries: 65_536,
        }
    }

    /// Try to admit a connection from `ip`. Returns false if the bucket is dry.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.buckets.lock().unwrap();

        // Bound memory: if the map is huge, drop everything that's full (idle).
        if map.len() >= self.max_entries {
            map.retain(|_, b| {
                let refilled =
                    b.tokens + (now.saturating_duration_since(b.last)).as_secs_f64() * self.rate;
                refilled < self.burst
            });
        }

        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets that have fully refilled (idle), to reclaim memory.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        map.retain(|_, b| {
            let refilled =
                b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * self.rate;
            refilled < self.burst
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn burst_then_throttle_then_refill() {
        let rl = RateLimiter::new(10, 5); // 10/s, burst 5
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let t0 = Instant::now();

        // Burst of 5 admitted, 6th denied.
        for _ in 0..5 {
            assert!(rl.check_at(ip, t0));
        }
        assert!(
            !rl.check_at(ip, t0),
            "6th in the same instant must be denied"
        );

        // After 1s, ~10 tokens refilled (capped at burst 5) → admits again.
        let t1 = t0 + Duration::from_secs(1);
        assert!(rl.check_at(ip, t1));
    }

    #[test]
    fn independent_per_ip() {
        let rl = RateLimiter::new(1, 1);
        let a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let t = Instant::now();
        assert!(rl.check_at(a, t));
        assert!(!rl.check_at(a, t)); // a is dry
        assert!(rl.check_at(b, t)); // b is independent
    }
}
