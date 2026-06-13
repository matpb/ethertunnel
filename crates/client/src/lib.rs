//! EtherTunnel client daemon.
//!
//! Opens a single outbound WebSocket to the relay (no inbound ports, no
//! firewall changes) and exposes local services as public HTTPS endpoints.
//!
//! Built incrementally — see the milestone plan. M2 adds the TLS client config
//! and the connection supervisor (connect, authenticate, claim, heartbeat,
//! reconnect). Local proxying lands in M3; config/credentials files, IPC, and
//! service install follow in M5/M7.

pub mod commands;
pub mod config;
pub mod creds;
pub mod doctor;
pub mod login;
pub mod paths;
pub mod proxy;
pub mod status;
pub mod supervisor;
pub mod tls;

pub use config::{FileConfig, Protocol, TunnelConfig};
pub use supervisor::{ClientConfig, ConnState, DaemonStatus, HttpTunnel, TcpTunnel};
pub use tls::TrustMode;
