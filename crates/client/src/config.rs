//! The client's on-disk configuration: which relay, and which tunnels.
//!
//! This file carries no secrets (the bearer token lives in `credentials.toml`),
//! so it is safe to commit to a dotfiles repo or sync between machines. Unknown
//! fields are ignored so a newer config still loads on an older binary.

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::paths;
use crate::supervisor::{ClientConfig, HttpTunnel, TcpTunnel};
use crate::tls::TrustMode;

/// The protocol a tunnel forwards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Http,
    Tcp,
}

/// One configured tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Stable name (used for `remove`, status, and as the default hostname label).
    pub name: String,
    /// Local port to forward to.
    pub port: u16,
    /// Local host to forward to.
    #[serde(default = "default_local_host")]
    pub local_host: String,
    #[serde(default)]
    pub protocol: Protocol,
    /// HTTP only: the public label below the relay apex (defaults to `name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// TCP only: the public port on the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
}

fn default_local_host() -> String {
    "127.0.0.1".to_owned()
}

/// The full client config file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileConfig {
    /// Relay base domain (control endpoint is `connect.<relay>`). Empty until
    /// the first `login`.
    #[serde(default)]
    pub relay: String,
    /// Trust this PEM CA/cert instead of the public root set — for self-hosters
    /// running a private-CA or self-signed relay. Omit for Let's Encrypt relays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_ca: Option<std::path::PathBuf>,
    #[serde(default, rename = "tunnels")]
    pub tunnels: Vec<TunnelConfig>,
}

impl FileConfig {
    /// The TLS trust policy for this relay: a pinned CA if `relay_ca` is set,
    /// otherwise the public root set (Let's Encrypt).
    pub fn trust_mode(&self) -> anyhow::Result<TrustMode> {
        match &self.relay_ca {
            None => Ok(TrustMode::System),
            Some(path) => {
                let pem = std::fs::read(path)
                    .with_context(|| format!("reading relay_ca {}", path.display()))?;
                let der = rustls_pemfile_first_cert(&pem)
                    .with_context(|| format!("parsing relay_ca {}", path.display()))?;
                Ok(TrustMode::CustomRoot(der))
            }
        }
    }
}

/// Extract the first certificate (DER) from a PEM blob.
fn rustls_pemfile_first_cert(pem: &[u8]) -> anyhow::Result<Vec<u8>> {
    rustls_pemfile::certs(&mut &pem[..])
        .next()
        .and_then(|r| r.ok())
        .map(|c| c.as_ref().to_vec())
        .context("no certificate found in relay_ca PEM")
}

impl FileConfig {
    /// Load the config file, or a default (empty) config if it does not exist.
    pub fn load() -> anyhow::Result<Self> {
        let path = paths::config_file()?;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }

    /// Persist the config file (world-readable; no secrets here).
    pub fn save(&self) -> anyhow::Result<()> {
        let path = paths::config_file()?;
        let text = toml::to_string_pretty(self).context("serializing config")?;
        paths::atomic_write(&path, text.as_bytes(), 0o644)
    }

    /// Find a tunnel by name.
    pub fn tunnel(&self, name: &str) -> Option<&TunnelConfig> {
        self.tunnels.iter().find(|t| t.name == name)
    }

    /// The fully-qualified public hostname for an HTTP tunnel.
    pub fn fqdn(&self, t: &TunnelConfig) -> String {
        let label = t.hostname.as_deref().unwrap_or(&t.name);
        format!("{label}.{}", self.relay)
    }

    /// Build the runtime [`ClientConfig`] the supervisor consumes.
    pub fn to_client_config(
        &self,
        token: String,
        trust: TrustMode,
    ) -> anyhow::Result<ClientConfig> {
        if self.relay.is_empty() {
            bail!("no relay configured; run `etun login` first");
        }
        let mut http = Vec::new();
        let mut tcp = Vec::new();
        for t in &self.tunnels {
            match t.protocol {
                Protocol::Http => http.push(HttpTunnel {
                    hostname: self.fqdn(t),
                    local_host: t.local_host.clone(),
                    local_port: t.port,
                }),
                Protocol::Tcp => {
                    let public_port = t
                        .public_port
                        .with_context(|| format!("tcp tunnel `{}` needs a public_port", t.name))?;
                    tcp.push(TcpTunnel {
                        public_port,
                        local_host: t.local_host.clone(),
                        local_port: t.port,
                    });
                }
            }
        }
        Ok(ClientConfig {
            relay_host: self.relay.clone(),
            relay_addr: None,
            token,
            http_tunnels: http,
            tcp_tunnels: tcp,
            trust,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_uses_hostname_then_name() {
        let mut cfg = FileConfig {
            relay: "ethertunnel.com".into(),
            relay_ca: None,
            tunnels: vec![],
        };
        let t = TunnelConfig {
            name: "demo".into(),
            port: 8080,
            local_host: "127.0.0.1".into(),
            protocol: Protocol::Http,
            hostname: None,
            public_port: None,
        };
        assert_eq!(cfg.fqdn(&t), "demo.ethertunnel.com");
        let t2 = TunnelConfig {
            hostname: Some("api".into()),
            ..t.clone()
        };
        assert_eq!(cfg.fqdn(&t2), "api.ethertunnel.com");
        cfg.tunnels.push(t);
        assert!(cfg.tunnel("demo").is_some());
    }

    #[test]
    fn tcp_without_public_port_errors() {
        let cfg = FileConfig {
            relay: "ethertunnel.com".into(),
            relay_ca: None,
            tunnels: vec![TunnelConfig {
                name: "ssh".into(),
                port: 22,
                local_host: "127.0.0.1".into(),
                protocol: Protocol::Tcp,
                hostname: None,
                public_port: None,
            }],
        };
        assert!(cfg
            .to_client_config("etun_x".into(), TrustMode::System)
            .is_err());
    }
}
