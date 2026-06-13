//! EtherTunnel relay server.
//!
//! Terminates public TLS for `*.<domain>`, routes visitor traffic by `Host`
//! header to client daemons connected over multiplexed reverse tunnels.
//!
//! Built incrementally — see the milestone plan. M0 established the workspace
//! and the proto transport seam. M1 adds the routing table, the per-session
//! actor, and the control protocol (auth, claims, supersede, heartbeat). The
//! public TLS listener and HTTP proxy path land in M2/M3.

pub mod auth;
pub mod router;
pub mod session;
