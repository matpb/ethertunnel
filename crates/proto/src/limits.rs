//! Shared protocol limits and tuning constants.
//!
//! Both halves import these so they agree by construction. Memory-bounding
//! values (the yamux windows) are the load-bearing ones: they cap how much a
//! slow peer can make us buffer, regardless of stream count.

use std::time::Duration;

/// Max control-frame payload (postcard bytes, excluding the 4-byte length).
/// Control frames are tiny; this is an anti-abuse ceiling, not a target.
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;

/// Max data-stream preamble payload. A `StreamHeader` is a handful of fields.
pub const MAX_STREAM_HEADER: usize = 4 * 1024;

/// Per-yamux-stream receive window (the yamux default). Bounds buffering for a
/// single visitor request/connection; backpressure propagates to the origin
/// once it fills and the reader stops consuming.
pub const STREAM_RECEIVE_WINDOW: usize = 256 * 1024;

/// Max concurrent yamux streams per session. Caps simultaneous in-flight
/// visitor requests on one tunnel — generous for browser request bursts.
pub const MAX_STREAMS_PER_CONNECTION: usize = 128;

/// Per-connection (whole session) receive window cap. Worst-case unconsumed
/// memory for one daemon session is bounded by this regardless of traffic.
/// yamux requires `>= STREAM_RECEIVE_WINDOW * MAX_STREAMS_PER_CONNECTION`, so
/// these two constants are intentionally locked together (128 * 256 KiB).
pub const CONNECTION_RECEIVE_WINDOW: usize = STREAM_RECEIVE_WINDOW * MAX_STREAMS_PER_CONNECTION;

/// Largest single WebSocket binary message we will send. yamux frames are
/// chunked under this so a fast writer cannot produce an oversized WS message.
pub const MAX_WS_MESSAGE: usize = 1024 * 1024;

/// Daemon heartbeat interval. Also serves as NAT/middlebox keepalive on the
/// outbound WSS connection.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

/// A session with no control frame for this long is considered dead and killed.
pub const SESSION_DEAD_AFTER: Duration = Duration::from_secs(90);

/// A daemon must send `Hello` within this window of opening the control stream.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Max number of resources (hostnames + tcp_ports) a single `Claim` may carry.
/// A 64 KiB control frame can otherwise pack thousands of tiny entries, each of
/// which the relay lowercases and ownership-checks; this bounds that per-claim
/// work. A daemon needing more simply sends additional claims.
pub const MAX_CLAIM_ENTRIES: usize = 256;

/// Default idle timeout for a visitor splice / body: tear it down after this
/// long with zero bytes in *either* direction. Reset-on-activity, so a busy
/// long-lived WebSocket is never cut. The relay config can override (0 = off).
pub const PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default absolute ceiling on a single visitor splice regardless of activity.
/// Shipped DISABLED by default (the relay config maps 0 -> off) so no legitimate
/// long-lived tunnel is ever severed; documented hardened value is 3600s.
pub const PROXY_ABSOLUTE_MAX: Duration = Duration::from_secs(3600);

/// Default cadence at which an established control session re-validates its
/// bearer token against the registry, so an admin revocation takes effect within
/// one interval instead of persisting until the daemon disconnects.
pub const TOKEN_REVALIDATE_INTERVAL: Duration = Duration::from_secs(60);

/// TCP keepalive idle time on relay-side visitor + raw-TCP sockets. After this
/// long with no data, the kernel starts probing the peer. This reclaims sockets
/// whose peer vanished without a FIN/RST (the visitor data planes are opaque
/// byte pipes, so we cannot ping/pong inside them the way the control channel
/// does) WITHOUT ever cutting a live-but-idle tunnel — a live peer answers the
/// kernel probes. Pairs with the (default-off) app idle timeout, never replacing
/// the rule that quiet-but-alive connections must survive.
pub const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);

/// Interval between TCP keepalive probes once the idle time has elapsed. With the
/// OS default probe count, a truly-dead peer is detected and dropped a few
/// minutes after it goes silent.
pub const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
