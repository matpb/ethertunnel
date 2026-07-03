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
    /// Polar.sh licensing integration. Absent => no license enforcement
    /// (self-host); clients authenticate by local `etun admin` tokens only.
    #[serde(default)]
    pub polar: Option<PolarConfig>,
    /// Connection-admission and anti-DoS limits for the public listener.
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Anti-DoS admission limits for the `:443` listener. All have safe defaults so
/// an existing config keeps working; tune them per deployment.
#[derive(Clone, Debug, Deserialize)]
pub struct LimitsConfig {
    /// Hard ceiling on concurrent connections process-wide. Bounds fd/memory
    /// exhaustion; excess connections are dropped at accept.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Max concurrent connections per source key (IPv6 is keyed by /64, so a
    /// single allocation can't bypass this by rotating addresses).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    /// Deadline for a visitor to finish sending its HTTP request headers after
    /// the TLS handshake. Bounds slowloris; 0 disables.
    #[serde(default = "default_header_read_timeout_secs")]
    pub header_read_timeout_secs: u64,
    /// Hard ceiling on concurrent *live* daemon control sessions process-wide.
    /// A control session holds its permit for its whole lifetime (not just the
    /// pre-upgrade HTTP phase), so this is what actually bounds the post-101
    /// daemon population. Defaults to `max_connections`.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Max concurrent live control sessions per source key (IPv6 keyed by /64).
    /// Defaults to `max_connections_per_ip`.
    #[serde(default = "default_max_sessions_per_ip")]
    pub max_sessions_per_ip: u32,
    /// Tear down a visitor splice / proxied body after this many seconds with
    /// zero bytes in *either* direction. Reset-on-activity, so busy long-lived
    /// WebSockets are unaffected. 0 disables — and 0 is the default: idle
    /// connections are NEVER reaped out of the box (a quiet-but-alive raw-TCP /
    /// SSH / DB tunnel must survive). The now-enforced concurrency caps bound the
    /// DoS; set this (e.g. 60) only on relays that serve solely keepalive traffic.
    #[serde(default = "default_proxy_idle_timeout_secs")]
    pub proxy_idle_timeout_secs: u64,
    /// Absolute ceiling (seconds) on a single visitor splice regardless of
    /// activity. 0 disables — the default, so legitimate long-lived tunnels are
    /// never severed out of the box (3600 is the documented hardened value).
    #[serde(default = "default_proxy_absolute_max_secs")]
    pub proxy_absolute_max_secs: u64,
    /// How often (seconds) an established control session re-validates its bearer
    /// token, so an admin revocation takes effect within one interval. 0 disables.
    #[serde(default = "default_token_revalidate_interval_secs")]
    pub token_revalidate_interval_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            header_read_timeout_secs: default_header_read_timeout_secs(),
            max_sessions: default_max_sessions(),
            max_sessions_per_ip: default_max_sessions_per_ip(),
            proxy_idle_timeout_secs: default_proxy_idle_timeout_secs(),
            proxy_absolute_max_secs: default_proxy_absolute_max_secs(),
            token_revalidate_interval_secs: default_token_revalidate_interval_secs(),
        }
    }
}

fn default_max_connections() -> usize {
    4096
}

fn default_max_connections_per_ip() -> u32 {
    64
}

fn default_header_read_timeout_secs() -> u64 {
    10
}

fn default_max_sessions() -> usize {
    4096
}

fn default_max_sessions_per_ip() -> u32 {
    64
}

fn default_proxy_idle_timeout_secs() -> u64 {
    0
}

fn default_proxy_absolute_max_secs() -> u64 {
    0
}

fn default_token_revalidate_interval_secs() -> u64 {
    60
}

/// Polar.sh licensing integration. When present, the relay authenticates
/// clients by their Polar license key (validated against the no-secret
/// customer-portal endpoint) in addition to local tokens, and enforces the
/// per-plan `max_tunnels` cap from the `[polar.benefits]` map at claim time.
/// Absent => no enforcement (self-host), identical to the pre-Polar relay.
///
/// The operator's real values (organization id, benefit ids) live only in the
/// deployed, git-ignored relay.toml — never committed to this repo.
#[derive(Clone, Debug, Deserialize)]
pub struct PolarConfig {
    /// The Polar organization whose keys this relay accepts. Public
    /// identifier (it rides in every customer-portal request body), but
    /// operator-supplied: no default, never committed.
    pub organization_id: String,
    /// Polar API base. Sandbox: "https://sandbox-api.polar.sh".
    #[serde(default = "default_polar_api_base")]
    pub api_base: String,
    /// Re-validate a cached key over HTTP at most this often (seconds).
    /// Keeps the relay far inside Polar's burst rate limits.
    #[serde(default = "default_polar_cache_ttl_secs")]
    pub cache_ttl_secs: i64,
    /// Honor a cached "granted" this long past its last successful
    /// validation when Polar is unreachable (bounded fail-open window).
    #[serde(default = "default_polar_staleness_secs")]
    pub staleness_secs: i64,
    /// Enforce `limit_activations` (device binding) by calling Polar
    /// activate()/deactivate() around claim/release.
    #[serde(default = "default_polar_activate_on_claim")]
    pub activate_on_claim: bool,
    /// `benefit_id -> max_tunnels`. The relay's ONLY source of per-plan
    /// capacity (the validate response has no product_id and keys carry no
    /// metadata, so capacity is keyed on the License Key *benefit* id).
    /// A granted key whose benefit is missing from this map is denied.
    #[serde(default)]
    pub benefits: std::collections::HashMap<String, i64>,
}

fn default_polar_api_base() -> String {
    "https://api.polar.sh".to_owned()
}

fn default_polar_cache_ttl_secs() -> i64 {
    300
}

fn default_polar_staleness_secs() -> i64 {
    259_200 // 3 days
}

fn default_polar_activate_on_claim() -> bool {
    true
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay.toml written before the security hardening (no `[limits]` block,
    /// or a `[limits]` block missing the new fields) must still load, with every
    /// new knob falling back to its ratified default.
    #[test]
    fn limits_back_compat_old_config_loads_with_defaults() {
        // No [limits] table at all — the whole section is `#[serde(default)]`.
        let toml = r#"
            [server]
            domain = "example.com"
        "#;
        let cfg: Config = toml::from_str(toml).expect("old config without [limits] loads");
        let l = &cfg.limits;
        assert_eq!(l.max_connections, 4096);
        assert_eq!(l.max_connections_per_ip, 64);
        assert_eq!(l.header_read_timeout_secs, 10);
        // New fields default to the ratified values.
        assert_eq!(l.max_sessions, 4096);
        assert_eq!(l.max_sessions_per_ip, 64);
        assert_eq!(l.proxy_idle_timeout_secs, 0); // idle reaping OFF by default — never kill idle connections
        assert_eq!(l.proxy_absolute_max_secs, 0); // disabled by default
        assert_eq!(l.token_revalidate_interval_secs, 60);
    }

    /// A `[limits]` block that sets only the *old* fields still loads; the new
    /// fields are filled field-by-field from their defaults.
    #[test]
    fn limits_partial_block_fills_new_fields() {
        let toml = r#"
            [server]
            domain = "example.com"

            [limits]
            max_connections = 1000
            max_connections_per_ip = 10
        "#;
        let cfg: Config = toml::from_str(toml).expect("partial [limits] loads");
        let l = &cfg.limits;
        assert_eq!(l.max_connections, 1000);
        assert_eq!(l.max_connections_per_ip, 10);
        // Untouched new knobs keep their defaults.
        assert_eq!(l.max_sessions, 4096);
        assert_eq!(l.max_sessions_per_ip, 64);
        assert_eq!(l.proxy_idle_timeout_secs, 0); // idle reaping OFF by default
        assert_eq!(l.proxy_absolute_max_secs, 0);
        assert_eq!(l.token_revalidate_interval_secs, 60);
    }

    /// The `[polar]` block parses with per-field defaults; only
    /// `organization_id` is required. The `[polar.benefits]` map is the
    /// benefit_id -> max_tunnels capacity source.
    #[test]
    fn polar_block_parses_with_defaults_and_benefits() {
        let toml = r#"
            [server]
            domain = "example.com"

            [polar]
            organization_id = "00000000-0000-0000-0000-000000000000"

            [polar.benefits]
            "11111111-1111-1111-1111-111111111111" = 1
            "22222222-2222-2222-2222-222222222222" = 3
        "#;
        let cfg: Config = toml::from_str(toml).expect("[polar] block loads");
        let p = cfg.polar.expect("polar present");
        assert_eq!(p.organization_id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(p.api_base, "https://api.polar.sh");
        assert_eq!(p.cache_ttl_secs, 300);
        assert_eq!(p.staleness_secs, 259_200);
        assert!(p.activate_on_claim);
        assert_eq!(
            p.benefits.get("11111111-1111-1111-1111-111111111111"),
            Some(&1)
        );
        assert_eq!(
            p.benefits.get("22222222-2222-2222-2222-222222222222"),
            Some(&3)
        );
    }

    /// No `[polar]` block => None (self-host: local tokens only, no caps).
    /// A legacy config still carrying the removed `[keygate]`/`[provision]`
    /// sections must keep loading — unknown tables are tolerated.
    #[test]
    fn no_polar_block_is_none_and_legacy_keygate_is_ignored() {
        let toml = r#"
            [server]
            domain = "example.com"

            [keygate]
            base_url = "https://license.example.com"
            consumer_token_file = "/etc/ethertunnel/keygate.token"
            public_key = "legacy"
            key_id = "kg-2026-06"

            [provision]
            token_file = "/etc/ethertunnel/provision.token"
        "#;
        let cfg: Config = toml::from_str(toml).expect("legacy config loads");
        assert!(cfg.polar.is_none());
    }
}
