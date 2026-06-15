//! EtherTunnel relay server.
//!
//! Terminates public TLS for `*.<domain>`, routes visitor traffic by `Host`
//! header to client daemons connected over multiplexed reverse tunnels.
//!
//! Built incrementally — see the milestone plan. M0 established the proto
//! transport seam; M1 added the routing table, session actor, and control
//! protocol; M2 adds the `:443` TLS listener and the WebSocket-upgrade path
//! that turns an inbound connection into a session. The HTTP proxy lands in M3.

pub mod acme;
pub mod admin_http;
pub mod auth;
pub mod config;
pub mod dns_cloudflare;
pub mod doctor;
pub mod entitlement;
pub mod listener;
pub mod proxy;
pub mod ratelimit;
pub mod registry;
pub mod router;
pub mod session;
pub mod tcp;
pub mod tls;

pub use config::{Config, TlsMode};
pub use listener::{serve, serve_with, RelayHandle, TlsMaterial};
pub use router::Router;
pub use session::SessionCtx;
