//! Relay configuration (TOML).
//!
//! M2 wires the fields the listener and TLS layer need. The ACME/registry/TCP
//! sections fill in at their milestones; unknown fields are tolerated so older
//! configs keep loading.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// Top-level relay configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(default)]
    pub tcp: TcpConfig,
    /// keygate licensing integration. Absent => no entitlement enforcement.
    #[serde(default)]
    pub keygate: Option<KeygateConfig>,
}

/// keygate licensing integration. When present, the relay pulls signed
/// entitlement envelopes and enforces a per-customer `max_tunnels` cap at claim
/// time. Absent => no enforcement (self-host / pre-billing), identical to the
/// relay's pre-integration behavior.
#[derive(Clone, Debug, Deserialize)]
pub struct KeygateConfig {
    /// keygate base URL, e.g. "https://license.ethertunnel.com".
    pub base_url: String,
    /// File holding the consumer bearer token (kept out of the config so the
    /// secret never lands in a world-readable file).
    pub consumer_token_file: PathBuf,
    /// keygate's pinned Ed25519 public key (base64, standard) for verifying
    /// entitlement envelopes offline.
    pub public_key: String,
    /// The signing key id the relay accepts (rotation guard).
    pub key_id: String,
    /// Product key entitlements are scoped to.
    #[serde(default = "default_keygate_product")]
    pub product: String,
    /// How often to pull the entitlement snapshot from keygate.
    #[serde(default = "default_keygate_poll_secs")]
    pub poll_interval_secs: u64,
    /// Honor a cached envelope at most this many seconds past its `expires_at`.
    #[serde(default = "default_keygate_staleness_secs")]
    pub staleness_ceiling_secs: i64,
    /// Deny users with no fresh cached entitlement (default false: allow them
    /// through unenforced, so unprovisioned/self-host users are never blocked).
    #[serde(default)]
    pub require_entitlement: bool,
}

impl KeygateConfig {
    /// Read and trim the consumer bearer token from `consumer_token_file`.
    pub fn token(&self) -> anyhow::Result<String> {
        let raw = std::fs::read_to_string(&self.consumer_token_file)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", self.consumer_token_file.display()))?;
        Ok(raw.trim().to_owned())
    }
}

fn default_keygate_product() -> String {
    "ethertunnel".to_owned()
}

fn default_keygate_poll_secs() -> u64 {
    60
}

fn default_keygate_staleness_secs() -> i64 {
    259_200 // 3 days
}

/// Raw-TCP tunnel settings.
#[derive(Clone, Debug, Deserialize)]
pub struct TcpConfig {
    /// Inclusive `[low, high]` range of public ports daemons may reserve. Keeps
    /// tunnels off privileged/service ports by construction.
    #[serde(default = "default_port_range")]
    pub port_range: [u16; 2],
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            port_range: default_port_range(),
        }
    }
}

impl TcpConfig {
    pub fn in_range(&self, port: u16) -> bool {
        port >= self.port_range[0] && port <= self.port_range[1]
    }
}

fn default_port_range() -> [u16; 2] {
    [20000, 20999]
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegistryConfig {
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
        }
    }
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/ethertunnel/registry.db")
}

impl Config {
    /// Load and parse a relay config from a TOML file.
    pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.as_ref().display()))?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config: {e}"))
    }
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

#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
    /// Where issued certs and the ACME account are cached.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// ACME settings (required when `mode = "acme"`).
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// Operator-provided cert/key (required when `mode = "manual"`).
    #[serde(default)]
    pub manual: Option<ManualConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            state_dir: default_state_dir(),
            acme: None,
            manual: None,
        }
    }
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/ethertunnel/tls")
}

/// ACME issuance via Let's Encrypt DNS-01 (Cloudflare-hosted zone).
#[derive(Clone, Debug, Deserialize)]
pub struct AcmeConfig {
    /// Contact email registered with the ACME account.
    pub email: String,
    /// Use the Let's Encrypt staging environment (untrusted certs, high rate
    /// limits) — always issue against staging first on a fresh deployment.
    #[serde(default)]
    pub staging: bool,
    pub cloudflare: CloudflareConfig,
}

/// Cloudflare credentials for the DNS-01 challenge.
#[derive(Clone, Debug, Deserialize)]
pub struct CloudflareConfig {
    /// The zone id for the relay's base domain.
    pub zone_id: String,
    /// File containing a Cloudflare API token with Zone:DNS:Edit on the zone.
    /// Kept out of the config so the token never lands in a world-readable file.
    pub api_token_file: PathBuf,
}

impl CloudflareConfig {
    /// Read and trim the API token from `api_token_file`.
    pub fn token(&self) -> anyhow::Result<String> {
        let raw = std::fs::read_to_string(&self.api_token_file)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", self.api_token_file.display()))?;
        Ok(raw.trim().to_owned())
    }
}

/// Operator-provided certificate files.
#[derive(Clone, Debug, Deserialize)]
pub struct ManualConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
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

    /// True if `host` is a valid tunnel hostname under this relay: a single,
    /// non-reserved label directly below the apex. Excludes the control endpoint
    /// AND every other reserved label (api, admin, www, ...), not just `connect`.
    pub fn is_tunnel_host(&self, host: &str) -> bool {
        if host == self.connect_host() || host == self.server.domain {
            return false;
        }
        let Some(label) = host.strip_suffix(&self.suffix()) else {
            return false;
        };
        if label.is_empty() || label.contains('.') {
            return false; // apex-only or deeper than one level
        }
        !crate::registry::RESERVED_LABELS.contains(&label)
    }
}
