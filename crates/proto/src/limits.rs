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
