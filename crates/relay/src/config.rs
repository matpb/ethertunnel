//! Relay configuration (TOML).
//!
//! M2 wires the fields the listener and TLS layer need. The ACME/registry/TCP
//! sections fill in at their milestones; unknown fields are tolerated so older
//! configs keep loading.

use std::net::SocketAddr;

use serde::Deserialize;

/// Top-level relay configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    /// Base domain. Tunnels live at `<label>.<domain>`; the daemon control
    /// endpoint is `connect.<domain>`.
    pub domain: String,
    /// Public listen address. One socket serves visitors and daemon control.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Body returned for a plain GET on the apex.
    #[serde(default = "default_apex_response")]
    pub apex_response: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
}

/// How the relay obtains its TLS certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Auto wildcard via ACME DNS-01 (production). Implemented in M6.
    Acme,
    /// Generate a self-signed cert for the domain (dev/tests).
    #[default]
    SelfSigned,
    /// Operator-provided cert/key files.
    Manual,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:443".parse().expect("valid default listen addr")
}

fn default_apex_response() -> String {
    "EtherTunnel relay".to_owned()
}

impl Config {
    /// The control endpoint hostname daemons connect to.
    pub fn connect_host(&self) -> String {
        format!("connect.{}", self.server.domain)
    }

    /// The apex hostname.
    pub fn apex(&self) -> &str {
        &self.server.domain
    }

    /// The tunnel-hostname suffix, including the leading dot.
    pub fn suffix(&self) -> String {
        format!(".{}", self.server.domain)
    }

    /// True if `host` is a valid tunnel hostname under this relay (a label
    /// directly below the apex, excluding the reserved control endpoint).
    pub fn is_tunnel_host(&self, host: &str) -> bool {
        host != self.connect_host() && host.ends_with(&self.suffix()) && host != self.server.domain
    }
}
