//! A tiny per-IP token-bucket accept limiter.
//!
//! Checked before the TLS handshake (and on raw-TCP tunnel ports) so a single
//! source cannot exhaust the relay with connection floods. Hand-rolled to avoid
//! a dependency; the map is swept and capped so it cannot grow without bound.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Collapse an address to its limiter key. IPv6 is masked to its /64 — the
/// smallest block routinely assigned to a single subscriber — so an attacker
/// with a /64 (or larger) cannot mint unlimited distinct keys by rotating the
/// host bits. IPv4 is used whole.
pub fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in octets.iter_mut().skip(8) {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

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
    /// The address is collapsed via [`limiter_key`] so IPv6 is throttled per /64.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(limiter_key(ip), Instant::now())
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

/// Bounds the number of *concurrent* live connections, process-wide and per
/// source key, complementing the accept-*rate* [`RateLimiter`]. A rate limit
/// alone can't stop a flood of slow-but-established connections from exhausting
/// fds/memory; this can. Per-key counts use the same /64-collapsed key as the
/// rate limiter, so IPv6 rotation can't bypass the per-source cap either.
pub struct ConnLimiter {
    global: Arc<Semaphore>,
    per_key: Mutex<HashMap<IpAddr, u32>>,
    per_key_max: u32,
}

impl ConnLimiter {
    pub fn new(global_max: usize, per_key_max: u32) -> Arc<Self> {
        // `Semaphore::MAX_PERMITS` is huge; a 0 config would wedge the relay, so
        // clamp to at least 1.
        let global_max = global_max.clamp(1, Semaphore::MAX_PERMITS);
        Arc::new(Self {
            global: Arc::new(Semaphore::new(global_max)),
            per_key: Mutex::new(HashMap::new()),
            per_key_max: per_key_max.max(1),
        })
    }

    /// Try to admit a connection from `ip`. Returns a permit that releases both
    /// the global slot and the per-key count when dropped, or `None` if either
    /// the global or the per-key ceiling is already reached.
    pub fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<ConnPermit> {
        let global = Arc::clone(&self.global).try_acquire_owned().ok()?;
        let key = limiter_key(ip);
        let mut map = self.per_key.lock().unwrap();
        let count = map.entry(key).or_insert(0);
        if *count >= self.per_key_max {
            return None; // `global` drops here, releasing the slot it took
        }
        *count += 1;
        Some(ConnPermit {
            _global: global,
            limiter: Arc::clone(self),
            key,
        })
    }
}

/// Held for a connection's lifetime; releases its global + per-key slot on drop.
pub struct ConnPermit {
    _global: OwnedSemaphorePermit,
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut map = self.limiter.per_key.lock().unwrap();
        if let Some(count) = map.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.key);
            }
        }
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

    #[test]
    fn ipv6_collapses_to_slash_64() {
        use std::net::Ipv6Addr;
        let a: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:abcd:2::1".parse().unwrap();
        // Same /64 -> same key; different /64 -> different key.
        assert_eq!(limiter_key(a), limiter_key(b));
        assert_ne!(limiter_key(a), limiter_key(other));
        // The key zeroes the host bits.
        assert_eq!(
            limiter_key(a),
            IpAddr::V6("2001:db8:abcd:1::".parse::<Ipv6Addr>().unwrap())
        );
        // IPv4 is untouched.
        let v4 = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(limiter_key(v4), v4);
    }

    #[test]
    fn conn_limiter_global_and_per_key_caps() {
        // Global cap 3, per-key cap 2.
        let cl = ConnLimiter::new(3, 2);
        let a1: IpAddr = "2001:db8:1:1::1".parse().unwrap();
        let a2: IpAddr = "2001:db8:1:1::2".parse().unwrap(); // same /64 as a1
        let b: IpAddr = "203.0.113.7".parse().unwrap();

        let p1 = cl.try_admit(a1).expect("1st from a");
        let p2 = cl.try_admit(a2).expect("2nd from a's /64");
        // Per-key cap (2) reached for a's /64, even from a different host bit.
        assert!(
            cl.try_admit(a1).is_none(),
            "per-key cap should block a's 3rd"
        );

        let _p3 = cl
            .try_admit(b)
            .expect("1st from b fills the global cap (3)");
        // Global cap (3) reached.
        assert!(cl.try_admit(b).is_none(), "global cap should block the 4th");

        // Dropping a permit frees both a global slot and a per-key slot.
        drop(p1);
        let _p4 = cl.try_admit(b).expect("slot freed -> b admitted");
        drop(p2);
    }

    #[test]
    fn session_limiter_caps_and_recovers() {
        // A SECOND, independent ConnLimiter instance models the live-session cap
        // (max_sessions / max_sessions_per_ip). It must enforce the same
        // global + per-/64 ceilings and release on ConnPermit drop, proving the
        // primitive supports two independent limiters in one process.
        let sessions = ConnLimiter::new(2, 1); // global 2, per-key 1
        let a: IpAddr = "2001:db8:7:7::1".parse().unwrap();
        let a2: IpAddr = "2001:db8:7:7::99".parse().unwrap(); // same /64
        let b: IpAddr = "198.51.100.5".parse().unwrap();

        let pa = sessions.try_admit(a).expect("1st session from a");
        // Per-key cap (1) blocks a's /64 even from a different host bit.
        assert!(
            sessions.try_admit(a2).is_none(),
            "per-key session cap should block a's 2nd"
        );
        let _pb = sessions.try_admit(b).expect("session from b fills global cap (2)");
        // Global cap (2) reached.
        assert!(
            sessions.try_admit(b).is_none(),
            "global session cap should block the 3rd"
        );
        // Releasing a's permit frees a global + per-key slot, admitting a's /64.
        drop(pa);
        let _pa2 = sessions
            .try_admit(a2)
            .expect("slot freed -> a's /64 admitted again");
    }
}
