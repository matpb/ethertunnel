//! Wire frames for the control channel and data-stream preambles.
//!
//! Encoded with postcard (compact, serde-native) and length-prefixed by the
//! [`crate::codec`]. Stability rules (enforced by review, not the compiler):
//!
//! * The bootstrap set — the control preamble plus `Hello`, `Welcome`,
//!   `Denied` and their fields — is **frozen forever**. They must decode the
//!   same way on every version so the two ends can always negotiate.
//! * Within a protocol version, enum variants are **append-only** and existing
//!   variant fields are immutable. Any other change bumps
//!   [`crate::PROTOCOL_VERSION`] and is gated by the Hello/Welcome exchange.
//!
//! Because postcard is not self-describing, reordering variants or fields is a
//! silent wire break — hence the rules above.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// A string that never reveals itself in `Debug`/log output (e.g. bearer
/// tokens). Serializes transparently as the inner string.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl Secret {
    /// Borrow the underlying secret. Only call where the value is actually used.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_owned())
    }
}

/// A claimable resource: a public hostname or a public TCP port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    Host(String),
    Port(u16),
}

/// Why a `Hello` or `Claim` was rejected. `AuthFailed` deliberately unifies
/// bad/revoked/unknown token so it cannot be used as an oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyCode {
    AuthFailed,
    VersionUnsupported,
    NotOwner,
    UnknownHostname,
    PortNotReserved,
    PortUnavailable,
    LimitExceeded,
    ProtocolError,
}

/// Non-fatal diagnostic codes carried by [`ControlFrame::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    MalformedClaim,
    Internal,
}

/// Frames exchanged on the control stream (the first stream the daemon opens).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlFrame {
    /// Daemon → relay. Must arrive within [`crate::limits::HELLO_TIMEOUT`].
    Hello {
        token: Secret,
        agent_version: String,
        proto_min: u16,
        proto_max: u16,
    },
    /// Relay → daemon. Authentication succeeded; the session is established.
    Welcome {
        proto: u16,
        server_version: String,
        session_id: u64,
    },
    /// Relay → daemon. Terminal for a failed `Hello`; non-terminal reply to a
    /// failed `Claim`.
    Denied { code: DenyCode, message: String },
    /// Daemon → relay. Atomic, idempotent claim of hostnames and TCP ports.
    Claim {
        hostnames: Vec<String>,
        tcp_ports: Vec<u16>,
    },
    /// Relay → daemon. Echoes exactly what is now routed to this session.
    Granted {
        hostnames: Vec<String>,
        tcp_ports: Vec<u16>,
    },
    /// Daemon → relay heartbeat (also NAT keepalive).
    Ping { nonce: u64 },
    /// Relay → daemon heartbeat echo.
    Pong { nonce: u64 },
    /// Relay → daemon. A resource was taken over by a newer session of the same
    /// user. Informational; in-flight streams continue.
    Superseded { resource: Resource },
    /// Daemon → relay. Graceful shutdown; release my claims now.
    Goodbye,
    /// Relay → daemon. Relay is going down; reconnect with backoff.
    Shutdown { reason: String },
    /// Either direction. Non-fatal diagnostic.
    Error { code: ErrorCode, message: String },
    // --- protocol v2 (append-only; only exchanged once Welcome negotiates >= 2) ---
    /// Daemon → relay. Release these *owned* resources: drop their registry rows
    /// and tear down any live routes. Only resources the caller actually owns are
    /// affected; unknown or not-owned entries are silently ignored. Idempotent.
    /// This is the server-side counterpart to `etun remove`/`etun release`, so a
    /// user can free a label/port (and the cap slot it holds) without an admin.
    Release {
        hostnames: Vec<String>,
        tcp_ports: Vec<u16>,
    },
    /// Relay → daemon. Echoes exactly what was released (the subset the caller
    /// owned and that is now gone).
    Released {
        hostnames: Vec<String>,
        tcp_ports: Vec<u16>,
    },
    /// Daemon → relay. Ask for the caller's authoritative owned-resource set, so
    /// the client can reconcile its local config against what the relay actually
    /// holds (surface orphans, self-heal after a plan downgrade pruned a tunnel).
    ListOwned,
    /// Relay → daemon. The caller's currently-owned hostnames + TCP ports.
    Owned {
        hostnames: Vec<String>,
        tcp_ports: Vec<u16>,
    },
}

/// Preamble written by the relay on every data stream it opens, identifying
/// which tunnel the stream belongs to. Followed by opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamHeader {
    Http {
        host: String,
        peer_ip: IpAddr,
        peer_port: u16,
    },
    Tcp {
        port: u16,
        peer_ip: IpAddr,
        peer_port: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_redacts_in_debug() {
        let s = Secret::from("etun_supersecret");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.expose(), "etun_supersecret");
    }

    #[test]
    fn hello_debug_does_not_leak_token() {
        let f = ControlFrame::Hello {
            token: Secret::from("etun_leakme"),
            agent_version: "0.1.0".into(),
            proto_min: 1,
            proto_max: 1,
        };
        let dbg = format!("{f:?}");
        assert!(!dbg.contains("leakme"), "token leaked in Debug: {dbg}");
        assert!(dbg.contains("Secret(***)"));
    }

    /// The v2 frames must survive a postcard encode/decode round-trip exactly —
    /// they ride the same length-prefixed codec as every other control frame.
    #[test]
    fn v2_frames_roundtrip() {
        for f in [
            ControlFrame::Release {
                hostnames: vec!["a.ethertunnel.com".into(), "b.ethertunnel.com".into()],
                tcp_ports: vec![20001, 20002],
            },
            ControlFrame::Released {
                hostnames: vec!["a.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
            ControlFrame::ListOwned,
            ControlFrame::Owned {
                hostnames: vec!["a.ethertunnel.com".into()],
                tcp_ports: vec![20001],
            },
        ] {
            let bytes = postcard::to_allocvec(&f).unwrap();
            let back: ControlFrame = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(format!("{f:?}"), format!("{back:?}"));
        }
    }
}
