//! Polar.sh license-key integration: validation client, local cache, and the
//! claim-time capacity gate.
//!
//! When `[polar]` is configured, the hosted relay authenticates daemons by
//! their Polar license key: the key presented in `Hello.token` is validated
//! against Polar's no-secret customer-portal endpoint, a relay account is
//! provisioned implicitly (keyed by the Polar `customer_id`), and the
//! per-plan tunnel cap comes from the operator's `[polar.benefits]`
//! `benefit_id -> max_tunnels` map. Local `etun admin` tokens keep working
//! unchanged (they are checked first, without any network call), so the
//! self-host path and operator access are never coupled to Polar.
//!
//! Operational constraints this module encodes (verified against the live
//! sandbox, 2026-07-03):
//!
//!  * The customer-portal validate endpoint is rate-limited and 429s on
//!    bursts with a long cooldown, so validation results are cached in a
//!    small local SQLite ([`LicenseCache`], sibling of the registry) and a
//!    key is re-validated over HTTP at most once per `cache_ttl_secs`.
//!  * A revoked key answers **404** ("License key is no longer active"),
//!    indistinguishable from an invalid key. Both map to
//!    [`ValidateOutcome::NotLicensed`].
//!  * The validate response carries `benefit_id` but **no** `product_id`,
//!    so capacity is keyed on the benefit.
//!  * If Polar is unreachable, a previously-granted key is honored for up to
//!    `staleness_secs` past its last successful validation (fail-open,
//!    bounded), mirroring the old entitlement-cache staleness ceiling.
//!  * `limit_activations` (device binding) is enforced by calling
//!    `activate` on the first claim and remembering our `activation_id`, so
//!    a reconnecting daemon re-uses its activation instead of tripping the
//!    limit it created.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::auth::AuthedUser;
#[cfg(test)]
use crate::auth::Authenticator as _;

/// The decision the gate hands the claim path for a given user. Same
/// semantics as the old entitlement gate: `Allow` = no cap applies (local
/// token / ops), `Cap(n)` = at most n owned resources, `DenyAll` = no new
/// claims (revoked license, or a benefit this relay has no cap mapping for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapDecision {
    Allow,
    Cap(i64),
    DenyAll,
}

/// Current unix wall-clock seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hash_key(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

/// Policy derived from the `[polar]` config block.
#[derive(Clone)]
pub struct PolarPolicy {
    pub organization_id: String,
    /// Re-validate a cached key over HTTP at most this often (seconds).
    pub cache_ttl_secs: i64,
    /// Honor a cached "granted" this long past its last successful
    /// validation if Polar is unreachable (fail-open window, seconds).
    pub staleness_secs: i64,
    /// How long a key still counts toward its customer's pooled cap for the
    /// purposes of the **destructive** downgrade prune. Deliberately much
    /// longer than `staleness_secs`: the cache stores only key hashes, so a
    /// key nobody presents can never be re-validated, and a daemon that is
    /// merely offline is indistinguishable from a cancelled one. Denying new
    /// claims on that evidence is reversible; hard-deleting globally-unique
    /// labels is not. [`PolarGate::new`] clamps it up to `staleness_secs`, so
    /// the prune can never be stricter than the gate that authorized the
    /// claim.
    pub cap_prune_grace_secs: i64,
    /// Enforce `limit_activations` by calling activate()/deactivate().
    pub activate_on_claim: bool,
    /// `benefit_id -> max_tunnels`: the relay's only source of capacity.
    pub benefits: HashMap<String, i64>,
}

/// What a validate round-trip concluded about a key.
#[derive(Debug)]
pub enum ValidateOutcome {
    /// `200` with `status == "granted"`.
    Granted {
        customer_id: String,
        benefit_id: String,
    },
    /// Definitively not usable: invalid, revoked, disabled (404 / 403 /
    /// 200-with-non-granted-status / 4xx).
    NotLicensed,
    /// Indeterminate: network error, 5xx, or rate-limited (429). The caller
    /// decides whether a cached grant still applies.
    Unavailable(String),
}

/// What an activate round-trip concluded.
#[derive(Debug)]
pub enum ActivateOutcome {
    Activated {
        activation_id: String,
    },
    /// `403` — the key's activation limit is already consumed elsewhere.
    LimitReached,
    Unavailable(String),
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The Polar API surface the gate needs, as a seam so tests can swap in a
/// deterministic mock instead of live HTTP.
pub trait PolarBackend: Send + Sync + 'static {
    fn validate<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ValidateOutcome>;
    fn activate<'a>(&'a self, key: &'a str, label: &'a str) -> BoxFuture<'a, ActivateOutcome>;
    fn deactivate<'a>(
        &'a self,
        key: &'a str,
        activation_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;
}

/// Live HTTP backend for the customer-portal license-key endpoints. Same
/// hyper-rustls (ring) stack as the ACME/Cloudflare paths so no second TLS
/// backend leaks into the static musl build. No Authorization header is ever
/// sent: these endpoints authenticate by the key itself plus the public
/// organization id.
pub struct PolarHttpClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    api_base: String,
    organization_id: String,
}

impl PolarHttpClient {
    pub fn new(api_base: String, organization_id: String) -> Self {
        crate::tls::ensure_crypto_provider();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Self {
            client,
            api_base: api_base.trim_end_matches('/').to_owned(),
            organization_id,
        }
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<(StatusCode, Bytes), String> {
        let url = format!("{}{path}", self.api_base);
        let req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "ethertunnel-relay/1")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| e.to_string())?;
        let resp = self.client.request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, bytes))
    }
}

/// The subset of the validate response the relay consumes. Verified against
/// the live sandbox: `benefit_id` is present, `product_id` is NOT.
#[derive(Deserialize)]
struct ValidateResp {
    customer_id: String,
    benefit_id: String,
    status: String,
}

#[derive(Deserialize)]
struct ActivateResp {
    id: String,
}

impl PolarBackend for PolarHttpClient {
    fn validate<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ValidateOutcome> {
        Box::pin(async move {
            let body = serde_json::json!({
                "key": key,
                "organization_id": self.organization_id,
            });
            match self
                .post_json("/v1/customer-portal/license-keys/validate", body)
                .await
            {
                Ok((status, bytes)) if status.is_success() => {
                    match serde_json::from_slice::<ValidateResp>(&bytes) {
                        Ok(v) if v.status == "granted" => ValidateOutcome::Granted {
                            customer_id: v.customer_id,
                            benefit_id: v.benefit_id,
                        },
                        // revoked / disabled — definitive.
                        Ok(_) => ValidateOutcome::NotLicensed,
                        Err(e) => ValidateOutcome::Unavailable(format!("bad validate body: {e}")),
                    }
                }
                // 429 and 5xx are transient; every other status (404 invalid-
                // or-revoked, 403, 422 malformed key) is a definitive no.
                Ok((status, _)) if status.as_u16() == 429 || status.is_server_error() => {
                    ValidateOutcome::Unavailable(format!("polar validate: {status}"))
                }
                Ok(_) => ValidateOutcome::NotLicensed,
                Err(e) => ValidateOutcome::Unavailable(e),
            }
        })
    }

    fn activate<'a>(&'a self, key: &'a str, label: &'a str) -> BoxFuture<'a, ActivateOutcome> {
        Box::pin(async move {
            let body = serde_json::json!({
                "key": key,
                "organization_id": self.organization_id,
                "label": label,
            });
            match self
                .post_json("/v1/customer-portal/license-keys/activate", body)
                .await
            {
                Ok((status, bytes)) if status.is_success() => {
                    match serde_json::from_slice::<ActivateResp>(&bytes) {
                        Ok(a) => ActivateOutcome::Activated {
                            activation_id: a.id,
                        },
                        Err(e) => ActivateOutcome::Unavailable(format!("bad activate body: {e}")),
                    }
                }
                Ok((status, _)) if status == StatusCode::FORBIDDEN => ActivateOutcome::LimitReached,
                Ok((status, _)) => {
                    ActivateOutcome::Unavailable(format!("polar activate: {status}"))
                }
                Err(e) => ActivateOutcome::Unavailable(e),
            }
        })
    }

    fn deactivate<'a>(
        &'a self,
        key: &'a str,
        activation_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let body = serde_json::json!({
                "key": key,
                "organization_id": self.organization_id,
                "activation_id": activation_id,
            });
            match self
                .post_json("/v1/customer-portal/license-keys/deactivate", body)
                .await
            {
                Ok((status, _)) if status.is_success() => Ok(()),
                Ok((status, _)) => Err(format!("polar deactivate: {status}")),
                Err(e) => Err(e),
            }
        })
    }
}

/// One cached validation result. Keys are stored only as SHA-256 (the
/// plaintext key is a live credential; sessions re-present it on every
/// connect, so the cache never needs it back).
#[derive(Debug, Clone)]
pub struct LicenseRow {
    pub key_hash: Vec<u8>,
    pub customer_id: String,
    pub benefit_id: String,
    /// Resolved from `[polar.benefits]` at validate time. `None` = the
    /// benefit is not in this relay's map (treated as DenyAll, loudly).
    pub max_tunnels: Option<i64>,
    /// `"granted"` or `"not_licensed"`.
    pub status: String,
    /// Our activation id for this key, once `activate` succeeded.
    pub activation_id: Option<String>,
    pub validated_at: i64,
}

/// What cap resolution needs to know about a customer, in one query: how many
/// keys the cache knows for them at all (zero = not a Polar customer, i.e. a
/// local `etun admin` token) and the largest cap among the keys that still
/// grant capacity (`None` = every known key is revoked, aged out, or on a
/// benefit this relay has no cap mapping for). The two signals must stay
/// apart: zero rows means Allow, rows-but-none-qualifying means DenyAll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomerCap {
    pub rows: i64,
    pub max_tunnels: Option<i64>,
}

/// Local SQLite cache of validation results. Its own database file (sibling
/// of the registry, 0600) so it never contends with the registry connection.
pub struct LicenseCache {
    conn: Mutex<Connection>,
}

impl LicenseCache {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rusqlite::Error> {
        let path = path.as_ref();
        let me = Self::init(Connection::open(path)?)?;
        // chmod after init() (journal_mode=WAL created the -wal/-shm). The
        // cache maps key hashes to customers — never world-readable.
        crate::registry::tighten_sqlite_perms(path);
        Ok(me)
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, rusqlite::Error> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS license_validation (
                key_hash      BLOB PRIMARY KEY,
                customer_id   TEXT NOT NULL,
                benefit_id    TEXT NOT NULL,
                max_tunnels   INTEGER,
                status        TEXT NOT NULL,
                activation_id TEXT,
                validated_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_license_customer
                ON license_validation(customer_id, validated_at);
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn get(&self, key_hash: &[u8]) -> Result<Option<LicenseRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT key_hash, customer_id, benefit_id, max_tunnels, status, activation_id, validated_at
             FROM license_validation WHERE key_hash = ?1",
            [key_hash],
            row_to_license,
        )
        .optional()
    }

    /// Resolve a customer's cap across every key they hold. All of one
    /// customer's keys collapse into ONE registry account and ONE tunnel
    /// pool, so the answer is the MAX over the keys that still qualify —
    /// granted, mapped to a cap, and validated at or after
    /// `min_validated_at`. MAX and not SUM: buying N cheap licenses must not
    /// stack into N times the capacity. The corollary is that any one of a
    /// customer's keys authorizes the customer's maximum capacity; per-key
    /// containment is `activate_on_claim` (device binding), not the cap.
    ///
    /// `min_validated_at` is the ONLY bound on an abandoned key's influence:
    /// the cache holds key hashes, never plaintext, so the relay can never
    /// re-validate a key nobody presents.
    pub fn cap_for_customer(
        &self,
        customer_id: &str,
        min_validated_at: i64,
    ) -> Result<CustomerCap, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*),
                    MAX(CASE WHEN status = 'granted'
                              AND max_tunnels IS NOT NULL
                              AND validated_at >= ?2
                             THEN max_tunnels END)
             FROM license_validation WHERE customer_id = ?1",
            rusqlite::params![customer_id, min_validated_at],
            |r| {
                Ok(CustomerCap {
                    rows: r.get(0)?,
                    max_tunnels: r.get(1)?,
                })
            },
        )
    }

    /// Insert or refresh a validation result, preserving a stored
    /// `activation_id` unless the caller supplies a new one.
    pub fn upsert(&self, row: &LicenseRow) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO license_validation
                (key_hash, customer_id, benefit_id, max_tunnels, status, activation_id, validated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(key_hash) DO UPDATE SET
                customer_id   = excluded.customer_id,
                benefit_id    = excluded.benefit_id,
                max_tunnels   = excluded.max_tunnels,
                status        = excluded.status,
                activation_id = COALESCE(excluded.activation_id, license_validation.activation_id),
                validated_at  = excluded.validated_at",
            rusqlite::params![
                row.key_hash,
                row.customer_id,
                row.benefit_id,
                row.max_tunnels,
                row.status,
                row.activation_id,
                row.validated_at,
            ],
        )?;
        Ok(())
    }

    pub fn set_activation(
        &self,
        key_hash: &[u8],
        activation_id: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE license_validation SET activation_id = ?2 WHERE key_hash = ?1",
            rusqlite::params![key_hash, activation_id],
        )?;
        Ok(())
    }
}

fn row_to_license(r: &rusqlite::Row<'_>) -> Result<LicenseRow, rusqlite::Error> {
    Ok(LicenseRow {
        key_hash: r.get(0)?,
        customer_id: r.get(1)?,
        benefit_id: r.get(2)?,
        max_tunnels: r.get(3)?,
        status: r.get(4)?,
        activation_id: r.get(5)?,
        validated_at: r.get(6)?,
    })
}

/// Actuator for cap enforcement against live state: the concrete registry
/// (user upsert + downgrade prune) and the router (route eviction), plus the
/// base domain to compose pruned labels back into FQDNs. Installed once at
/// startup; the gate is inert (authenticates nothing) until it is set.
pub struct Reconciler {
    pub registry: std::sync::Arc<crate::registry::Registry>,
    pub router: std::sync::Arc<crate::router::Router>,
    pub domain: String,
}

/// The Polar license gate: validation cache + policy + backend.
pub struct PolarGate {
    cache: LicenseCache,
    policy: PolarPolicy,
    backend: Box<dyn PolarBackend>,
    reconciler: arc_swap::ArcSwapOption<Reconciler>,
}

impl PolarGate {
    pub fn new(
        cache: LicenseCache,
        mut policy: PolarPolicy,
        backend: Box<dyn PolarBackend>,
    ) -> Self {
        // The prune's window must contain the claim gate's, or the relay hard
        // deletes labels its own gate would still authorize. Operators tune
        // `staleness_secs`, so clamp instead of trusting the two defaults to
        // stay ordered; a shorter grace is a misconfiguration, not a policy.
        if policy.cap_prune_grace_secs < policy.staleness_secs {
            tracing::warn!(
                cap_prune_grace_secs = policy.cap_prune_grace_secs,
                staleness_secs = policy.staleness_secs,
                "[polar] cap_prune_grace_secs is shorter than staleness_secs; clamping up to it"
            );
            policy.cap_prune_grace_secs = policy.staleness_secs;
        }
        Self {
            cache,
            policy,
            backend,
            reconciler: arc_swap::ArcSwapOption::empty(),
        }
    }

    /// Install the registry/router actuator. Until this is set the gate
    /// cannot resolve users and `authenticate` always fails.
    pub fn set_reconciler(&self, r: std::sync::Arc<Reconciler>) {
        self.reconciler.store(Some(r));
    }

    pub fn activate_on_claim(&self) -> bool {
        self.policy.activate_on_claim
    }

    /// Authenticate a presented credential as a Polar license key. Returns
    /// `None` for anything that is not a currently-granted key (the caller
    /// has already tried local tokens). HTTP is skipped entirely while the
    /// cached result is fresher than `cache_ttl_secs`; a previously-granted
    /// key is honored for `staleness_secs` past its last validation when
    /// Polar is unreachable.
    pub async fn authenticate(&self, key: &str) -> Option<AuthedUser> {
        let rec = self.reconciler.load_full()?;
        let key_hash = hash_key(key);
        let now = now_unix();

        let cached = self.cache.get(&key_hash).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "license cache read failed");
            None
        });

        // Fresh cache hit: no network round-trip, positive or negative.
        if let Some(row) = &cached {
            if now <= row.validated_at + self.policy.cache_ttl_secs {
                if row.status == "granted" && row.max_tunnels.is_some() {
                    return self.resolve_user(&rec, &row.customer_id);
                }
                return None;
            }
        }

        match self.backend.validate(key).await {
            ValidateOutcome::Granted {
                customer_id,
                benefit_id,
            } => {
                let cap = self.policy.benefits.get(&benefit_id).copied();
                if cap.is_none() {
                    tracing::error!(
                        benefit_id = %benefit_id,
                        "granted Polar key has a benefit with no [polar.benefits] cap \
                         mapping — denying; add the benefit id to relay.toml"
                    );
                }
                let row = LicenseRow {
                    key_hash: key_hash.clone(),
                    customer_id: customer_id.clone(),
                    benefit_id,
                    max_tunnels: cap,
                    status: "granted".into(),
                    activation_id: None, // preserved by the upsert COALESCE
                    validated_at: now,
                };
                if let Err(e) = self.cache.upsert(&row) {
                    tracing::warn!(error = %e, "license cache upsert failed");
                }
                let cap = cap?; // this key's benefit is unmapped -> deny this key
                let user = self.resolve_user(&rec, &customer_id)?;
                self.enforce_pooled_cap(&rec, &user, cap, now);
                Some(user)
            }
            ValidateOutcome::NotLicensed => {
                if let Some(mut row) = cached {
                    row.status = "not_licensed".into();
                    row.validated_at = now;
                    if let Err(e) = self.cache.upsert(&row) {
                        tracing::warn!(error = %e, "license cache upsert failed");
                    }
                }
                None
            }
            ValidateOutcome::Unavailable(why) => {
                // Fail-open, bounded: honor the last grant within staleness.
                if let Some(row) = cached {
                    if row.status == "granted"
                        && row.max_tunnels.is_some()
                        && now <= row.validated_at + self.policy.staleness_secs
                    {
                        tracing::warn!(
                            %why,
                            customer_id = %row.customer_id,
                            "polar unreachable; honoring cached grant within staleness window"
                        );
                        return self.resolve_user(&rec, &row.customer_id);
                    }
                }
                tracing::warn!(%why, "polar unreachable and no honorable cached grant; denying");
                None
            }
        }
    }

    /// The effective cap for a session user. Polar-authed users (name =
    /// customer_id) resolve through the validation cache; anyone else — a
    /// local `etun admin` token — has no cache row and is uncapped
    /// (`Allow`), exactly like the self-host path. A customer holding several
    /// keys gets the MAX of their caps: the keys share one registry account,
    /// so the cheapest one must not define the pool. The `ListOwned` advisory
    /// therefore reports the shared pool's cap, which may exceed the plan the
    /// presenting key belongs to — that is the number the relay enforces.
    pub fn cap_for(&self, user_name: &str, now: i64) -> CapDecision {
        // A grant nobody could re-validate for the whole staleness window is
        // no longer trustworthy. Live sessions re-validate every tick, so this
        // only bites when Polar has been unreachable for days.
        self.resolve_cap(user_name, now.saturating_sub(self.policy.staleness_secs))
    }

    /// Pooled cap for a customer, counting only keys validated at or after
    /// `min_validated_at`. Callers pick that cutoff by what their decision
    /// costs when it is wrong: [`cap_for`](Self::cap_for) and the route
    /// eviction in [`enforce_pooled_cap`](Self::enforce_pooled_cap) use
    /// `staleness_secs`, the hard delete a much longer grace.
    ///
    /// The cutoff is deliberately absolute. Qualifying rows by freshness
    /// *relative* to the customer's newest key would drop a legitimately
    /// offline daemon (laptop shut overnight) out of the MAX and re-create the
    /// very bug this resolution exists to fix.
    fn resolve_cap(&self, customer_id: &str, min_validated_at: i64) -> CapDecision {
        let resolved = match self.cache.cap_for_customer(customer_id, min_validated_at) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(customer_id, error = %e, "license cache read failed; allowing");
                return CapDecision::Allow;
            }
        };
        if resolved.rows == 0 {
            return CapDecision::Allow;
        }
        match resolved.max_tunnels {
            Some(m) => CapDecision::Cap(m),
            // Keys exist but none qualify: revoked, aged past the cutoff, or
            // on a benefit missing from [polar.benefits].
            None => CapDecision::DenyAll,
        }
    }

    /// Ensure the key holds its device activation before a claim proceeds.
    /// No-op (Ok) when activation is disabled, the credential is not a
    /// Polar-cached key (local token), or we already hold an activation id.
    /// `Err(msg)` means the claim must be denied.
    pub async fn ensure_activated(&self, key: &str) -> Result<(), String> {
        if !self.policy.activate_on_claim {
            return Ok(());
        }
        let key_hash = hash_key(key);
        let row = match self.cache.get(&key_hash) {
            Ok(Some(r)) if r.status == "granted" => r,
            // Not a Polar-managed credential (or not granted — auth already
            // handled that): nothing to activate.
            _ => return Ok(()),
        };
        if row.activation_id.is_some() {
            return Ok(());
        }
        let rec = self.reconciler.load_full();
        let label = rec
            .as_ref()
            .map(|r| format!("relay:{}", r.domain))
            .unwrap_or_else(|| "relay".to_owned());
        match self.backend.activate(key, &label).await {
            ActivateOutcome::Activated { activation_id } => {
                if let Err(e) = self.cache.set_activation(&key_hash, Some(&activation_id)) {
                    tracing::warn!(error = %e, "storing activation id failed");
                }
                tracing::info!(customer_id = %row.customer_id, "polar key activated for this relay");
                Ok(())
            }
            ActivateOutcome::LimitReached => Err(
                "license activation limit reached (key already active on another device/relay)"
                    .to_owned(),
            ),
            ActivateOutcome::Unavailable(why) => {
                // Never brick a paying customer on a Polar hiccup: the claim
                // proceeds unactivated and the next claim retries.
                tracing::warn!(%why, "polar activate unavailable; allowing claim without activation");
                Ok(())
            }
        }
    }

    /// Release our activation for a key (the daemon released its last owned
    /// resource). Best-effort: failures are logged, never surfaced.
    pub async fn release_activation(&self, key: &str) {
        let key_hash = hash_key(key);
        let Ok(Some(row)) = self.cache.get(&key_hash) else {
            return;
        };
        let Some(activation_id) = row.activation_id else {
            return;
        };
        match self.backend.deactivate(key, &activation_id).await {
            Ok(()) => {
                let _ = self.cache.set_activation(&key_hash, None);
                tracing::info!(customer_id = %row.customer_id, "polar activation released");
            }
            Err(why) => tracing::warn!(%why, "polar deactivate failed; keeping activation id"),
        }
    }

    /// Bring a customer's shared pool back in line with what their keys still
    /// buy, on the key that just re-validated. Two windows, because the two
    /// actions cost differently when the evidence is wrong: an abandoned key
    /// stops backing LIVE traffic after `staleness_secs` — the same window the
    /// claim gate uses, so the relay never routes what it would refuse to
    /// claim — while its hostname *reservations* survive until
    /// `cap_prune_grace_secs`, because releasing a globally-unique label back
    /// into a first-come-first-served pool is the one step nobody can undo.
    ///
    /// `cap` is the just-validated key's own cap, a floor under both windows:
    /// a failed upsert would otherwise leave its row out of the aggregate and
    /// tear down tunnels it pays for.
    fn enforce_pooled_cap(&self, rec: &Reconciler, user: &AuthedUser, cap: i64, now: i64) {
        let pooled_over = |window: i64| self.resolve_cap(&user.name, now.saturating_sub(window));
        // A non-`Cap` decision here means the cache could not answer — the
        // upsert above failed, or the read did. A broken cache must never tear
        // anything down, least of all to zero.
        if let CapDecision::Cap(pooled) = pooled_over(self.policy.cap_prune_grace_secs) {
            if pooled > cap {
                tracing::info!(
                    customer_id = %user.name,
                    key_cap = cap,
                    pooled,
                    "cap pooled from a sibling key on the same customer"
                );
            }
            self.reconcile_user_cap(rec, user.user_id, &user.name, pooled.max(cap));
        }
        if let CapDecision::Cap(live) = pooled_over(self.policy.staleness_secs) {
            self.evict_over_cap(rec, user.user_id, &user.name, live.max(cap));
        }
    }

    /// Prune a user's owned resources down to `cap` and tear down the routes
    /// of anything pruned (oldest-N grandfathered, newest dropped) — the
    /// same downgrade semantics the keygate reconciler had.
    fn reconcile_user_cap(&self, rec: &Reconciler, user_id: i64, user_name: &str, cap: i64) {
        let (labels, ports) = match rec.registry.prune_owned_to_cap(user_id, cap) {
            Ok(removed) => removed,
            Err(e) => {
                tracing::warn!(user_name, error = %e, "downgrade prune failed");
                return;
            }
        };
        if labels.is_empty() && ports.is_empty() {
            return;
        }
        let pruned = labels.len() + ports.len();
        Self::tear_down_routes(rec, &labels, &ports);
        tracing::info!(
            user_name,
            cap,
            pruned,
            "plan downgrade: pruned over-cap tunnels"
        );
    }

    /// Stop the traffic on a user's resources past `cap` while leaving the
    /// reservations intact. The daemon is told why; a reconnect re-claims and
    /// is refused by the same cap, so nothing silently comes back.
    fn evict_over_cap(&self, rec: &Reconciler, user_id: i64, user_name: &str, cap: i64) {
        let (labels, ports) = match rec.registry.owned_over_cap(user_id, cap) {
            Ok(over) => over,
            Err(e) => {
                tracing::warn!(user_name, error = %e, "over-cap route lookup failed");
                return;
            }
        };
        if labels.is_empty() && ports.is_empty() {
            return;
        }
        let evicted = Self::tear_down_routes(rec, &labels, &ports);
        if evicted > 0 {
            tracing::info!(
                user_name,
                cap,
                evicted,
                "plan downgrade: evicted over-cap routes (reservations kept)"
            );
        }
    }

    /// Drop the routes for `labels`/`ports` and tell whoever was serving them
    /// why. Returns how many live routes were actually torn down.
    fn tear_down_routes(rec: &Reconciler, labels: &[String], ports: &[u16]) -> usize {
        let fqdns: Vec<String> = labels
            .iter()
            .map(|label| format!("{label}.{}", rec.domain))
            .collect();
        let evicted = rec.router.evict_routes(&fqdns, ports);
        let count = evicted.len();
        for (handle, resource) in evicted {
            handle.send_ctrl(ethertunnel_proto::frames::ControlFrame::Denied {
                code: ethertunnel_proto::frames::DenyCode::LimitExceeded,
                // "stopped", not "pruned": the eviction caller keeps the
                // reservation, so the label may well still be theirs.
                message: format!("tunnel {resource:?} stopped: plan change reduced your limit"),
            });
        }
        count
    }

    /// Upsert-and-resolve the registry account for a Polar customer. The
    /// account name IS the Polar `customer_id` (opaque, stable, unique), so
    /// provisioning is implicit and idempotent.
    fn resolve_user(&self, rec: &Reconciler, customer_id: &str) -> Option<AuthedUser> {
        match rec.registry.lookup_user_id(customer_id) {
            Ok(Some(user_id)) => {
                return Some(AuthedUser {
                    user_id,
                    name: customer_id.to_owned(),
                })
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(customer_id, error = %e, "user lookup failed");
                return None;
            }
        }
        match rec.registry.add_user(customer_id) {
            Ok(user_id) => {
                tracing::info!(customer_id, "provisioned relay account for Polar customer");
                Some(AuthedUser {
                    user_id,
                    name: customer_id.to_owned(),
                })
            }
            // Raced another session of the same customer: re-resolve.
            Err(crate::registry::RegistryError::UserExists(_)) => rec
                .registry
                .lookup_user_id(customer_id)
                .ok()
                .flatten()
                .map(|user_id| AuthedUser {
                    user_id,
                    name: customer_id.to_owned(),
                }),
            Err(e) => {
                tracing::warn!(customer_id, error = %e, "user provisioning failed");
                None
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A deterministic mock backend for unit and session tests.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Scripted backend: maps keys to outcomes, counts calls.
    #[derive(Default)]
    pub struct MockBackend {
        /// key -> (customer_id, benefit_id); missing key => NotLicensed.
        pub granted: HashMap<String, (String, String)>,
        /// When set, every validate returns Unavailable with this message.
        pub outage: Option<String>,
        /// Keys whose activate() answers LimitReached.
        pub activation_exhausted: std::collections::HashSet<String>,
        pub validate_calls: AtomicUsize,
        pub activate_calls: AtomicUsize,
        pub deactivate_calls: AtomicUsize,
    }

    impl MockBackend {
        pub fn granting(key: &str, customer_id: &str, benefit_id: &str) -> Self {
            let mut granted = HashMap::new();
            granted.insert(
                key.to_owned(),
                (customer_id.to_owned(), benefit_id.to_owned()),
            );
            Self {
                granted,
                ..Default::default()
            }
        }

        /// Add another granted key: one customer can hold several keys on
        /// different benefits.
        pub fn grant(mut self, key: &str, customer_id: &str, benefit_id: &str) -> Self {
            self.granted.insert(
                key.to_owned(),
                (customer_id.to_owned(), benefit_id.to_owned()),
            );
            self
        }
    }

    /// Tests hold an `Arc<MockBackend>` to read the call counters after the
    /// gate boxes its copy, so the backend impl lives on the Arc.
    impl PolarBackend for std::sync::Arc<MockBackend> {
        fn validate<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ValidateOutcome> {
            Box::pin(async move {
                self.validate_calls.fetch_add(1, Ordering::Relaxed);
                if let Some(why) = &self.outage {
                    return ValidateOutcome::Unavailable(why.clone());
                }
                match self.granted.get(key) {
                    Some((customer_id, benefit_id)) => ValidateOutcome::Granted {
                        customer_id: customer_id.clone(),
                        benefit_id: benefit_id.clone(),
                    },
                    None => ValidateOutcome::NotLicensed,
                }
            })
        }

        fn activate<'a>(&'a self, key: &'a str, _label: &'a str) -> BoxFuture<'a, ActivateOutcome> {
            Box::pin(async move {
                self.activate_calls.fetch_add(1, Ordering::Relaxed);
                if self.activation_exhausted.contains(key) {
                    ActivateOutcome::LimitReached
                } else {
                    ActivateOutcome::Activated {
                        activation_id: format!("act-{}", &key[..key.len().min(8)]),
                    }
                }
            })
        }

        fn deactivate<'a>(
            &'a self,
            _key: &'a str,
            _activation_id: &'a str,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.deactivate_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        }
    }

    /// Seed (or overwrite) a validation-cache row directly, so session tests
    /// can model a licensed/lapsed customer without driving live validation.
    /// `key` is the plaintext credential the session will present.
    pub fn seed_license(
        gate: &PolarGate,
        key: &str,
        customer_id: &str,
        status: &str,
        max_tunnels: Option<i64>,
    ) {
        seed_license_at(gate, key, customer_id, status, max_tunnels, now_unix());
    }

    /// [`seed_license`] with an explicit `validated_at`, so a test can age a
    /// row past `cache_ttl_secs`, `staleness_secs`, or `cap_prune_grace_secs`.
    pub fn seed_license_at(
        gate: &PolarGate,
        key: &str,
        customer_id: &str,
        status: &str,
        max_tunnels: Option<i64>,
        validated_at: i64,
    ) {
        gate.cache
            .upsert(&LicenseRow {
                key_hash: hash_key(key),
                customer_id: customer_id.to_owned(),
                benefit_id: "ben_test".to_owned(),
                max_tunnels,
                status: status.to_owned(),
                activation_id: None,
                validated_at,
            })
            .unwrap();
    }

    /// The shipped defaults, as a policy a test can mutate to model a
    /// misconfigured relay.
    pub fn test_policy(benefits: &[(&str, i64)]) -> PolarPolicy {
        PolarPolicy {
            organization_id: "org-test".into(),
            cache_ttl_secs: 300,
            staleness_secs: 259_200,
            cap_prune_grace_secs: 2_592_000,
            activate_on_claim: true,
            benefits: benefits.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    /// A gate wired to an in-memory cache/registry/router, returning the
    /// pieces tests assert against. Pass an `Arc<MockBackend>` and keep a
    /// clone to read its call counters.
    pub fn gate_with(
        backend: std::sync::Arc<MockBackend>,
        benefits: &[(&str, i64)],
    ) -> (
        std::sync::Arc<PolarGate>,
        std::sync::Arc<crate::registry::Registry>,
        std::sync::Arc<crate::router::Router>,
    ) {
        gate_with_policy(backend, test_policy(benefits))
    }

    /// [`gate_with`] with an explicit policy.
    pub fn gate_with_policy(
        backend: std::sync::Arc<MockBackend>,
        policy: PolarPolicy,
    ) -> (
        std::sync::Arc<PolarGate>,
        std::sync::Arc<crate::registry::Registry>,
        std::sync::Arc<crate::router::Router>,
    ) {
        let registry = std::sync::Arc::new(
            crate::registry::Registry::open_in_memory("ethertunnel.com").unwrap(),
        );
        let router = std::sync::Arc::new(crate::router::Router::new());
        let gate = PolarGate::new(
            LicenseCache::open_in_memory().unwrap(),
            policy,
            Box::new(backend),
        );
        gate.set_reconciler(std::sync::Arc::new(Reconciler {
            registry: registry.clone(),
            router: router.clone(),
            domain: "ethertunnel.com".into(),
        }));
        (std::sync::Arc::new(gate), registry, router)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        gate_with, gate_with_policy, seed_license, seed_license_at, test_policy, MockBackend,
    };
    use super::*;
    use ethertunnel_proto::frames::{ControlFrame, DenyCode};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    const KEY: &str = "CMND-TEST-KEY-0001";

    #[tokio::test]
    async fn granted_key_provisions_user_and_caches() {
        let (gate, registry, _router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm")),
            &[("ben_cm", 1)],
        );

        let user = gate
            .authenticate(KEY)
            .await
            .expect("granted key authenticates");
        assert_eq!(user.name, "cust_1");
        // The account was implicitly provisioned in the registry.
        assert_eq!(
            registry.lookup_user_id("cust_1").unwrap(),
            Some(user.user_id)
        );
        // And the cap resolves from the benefits map.
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(1));

        // A second authenticate within the TTL is served from cache: same
        // user, no extra HTTP.
        let again = gate
            .authenticate(KEY)
            .await
            .expect("cached key authenticates");
        assert_eq!(again.user_id, user.user_id);
    }

    #[tokio::test]
    async fn cache_fresh_hit_skips_http() {
        let backend = Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm"));
        let (gate, _registry, _router) = gate_with(backend.clone(), &[("ben_cm", 1)]);
        gate.authenticate(KEY).await.unwrap();
        gate.authenticate(KEY).await.unwrap();
        gate.authenticate(KEY).await.unwrap();
        // Only the first authenticate hit the backend; the rest were cache
        // hits within cache_ttl_secs. This is what keeps the relay inside
        // Polar's burst rate limit.
        assert_eq!(backend.validate_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn unknown_key_is_denied() {
        let (gate, registry, _router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm")),
            &[("ben_cm", 1)],
        );
        assert!(gate.authenticate("CMND-WRONG").await.is_none());
        // No phantom account.
        assert_eq!(registry.lookup_user_id("cust_1").unwrap(), None);
    }

    #[tokio::test]
    async fn unknown_benefit_is_denied_loudly() {
        // Granted key, but the benefit id is missing from [polar.benefits].
        let (gate, _registry, _router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_unknown")),
            &[("ben_cm", 1)],
        );
        assert!(gate.authenticate(KEY).await.is_none());
        // The cache row exists (so cap_for is DenyAll, not Allow).
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::DenyAll);
    }

    #[tokio::test]
    async fn outage_honors_cached_grant_within_staleness() {
        // First: a successful validate seeds the cache.
        let (gate, _registry, _router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm")),
            &[("ben_cm", 1)],
        );
        gate.authenticate(KEY).await.expect("seed");

        // Age the row past the TTL (forces HTTP) but well within staleness,
        // then break the backend.
        let mut row = gate.cache.get(&hash_key(KEY)).unwrap().unwrap();
        row.validated_at = now_unix() - gate.policy.cache_ttl_secs - 10;
        gate.cache.upsert(&row).unwrap();
        // Rebuild the gate with an outage backend but the SAME cache is not
        // possible post-construction; instead simulate by swapping policy...
        // Simplest honest path: a fresh gate with an outage backend and a
        // pre-seeded cache row.
        let outage = MockBackend {
            outage: Some("connect refused".into()),
            ..Default::default()
        };
        let (gate2, _r2, _rt2) = gate_with(Arc::new(outage), &[("ben_cm", 1)]);
        gate2.cache.upsert(&row).unwrap();
        let user = gate2
            .authenticate(KEY)
            .await
            .expect("stale-but-honorable grant authenticates during outage");
        assert_eq!(user.name, "cust_1");

        // Past the staleness window the same outage denies.
        row.validated_at = now_unix() - gate2.policy.staleness_secs - 10;
        gate2.cache.upsert(&row).unwrap();
        assert!(gate2.authenticate(KEY).await.is_none());
    }

    #[tokio::test]
    async fn revoked_key_flips_to_denied_after_ttl() {
        let (gate, _registry, _router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm")),
            &[("ben_cm", 1)],
        );
        gate.authenticate(KEY).await.expect("seed");

        // Simulate revocation: fresh gate whose backend no longer grants,
        // sharing a pre-seeded, TTL-expired cache row.
        let mut row = gate.cache.get(&hash_key(KEY)).unwrap().unwrap();
        row.validated_at = now_unix() - 301;
        let (gate2, _r2, _rt2) = gate_with(Arc::new(MockBackend::default()), &[("ben_cm", 1)]);
        gate2.cache.upsert(&row).unwrap();

        assert!(
            gate2.authenticate(KEY).await.is_none(),
            "revoked key must deny"
        );
        assert_eq!(
            gate2.cap_for("cust_1", now_unix()),
            CapDecision::DenyAll,
            "the cached row flips to not_licensed so live sessions are torn down"
        );
    }

    #[tokio::test]
    async fn activation_lifecycle_and_limit() {
        let backend = Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm"));
        let (gate, _registry, _router) = gate_with(backend, &[("ben_cm", 1)]);
        gate.authenticate(KEY).await.expect("seed");

        // First claim activates and stores the id.
        gate.ensure_activated(KEY).await.expect("first activation");
        let row = gate.cache.get(&hash_key(KEY)).unwrap().unwrap();
        let act = row.activation_id.clone().expect("activation id stored");

        // A reconnect / re-claim re-uses it (no second activate call).
        gate.ensure_activated(KEY)
            .await
            .expect("idempotent re-claim");
        let row2 = gate.cache.get(&hash_key(KEY)).unwrap().unwrap();
        assert_eq!(row2.activation_id.as_deref(), Some(act.as_str()));

        // Releasing the activation clears the stored id.
        gate.release_activation(KEY).await;
        let row3 = gate.cache.get(&hash_key(KEY)).unwrap().unwrap();
        assert_eq!(row3.activation_id, None);
    }

    #[tokio::test]
    async fn activation_limit_reached_denies_claim() {
        let mut backend = MockBackend::granting(KEY, "cust_1", "ben_cm");
        backend.activation_exhausted.insert(KEY.to_owned());
        let (gate, _registry, _router) = gate_with(Arc::new(backend), &[("ben_cm", 1)]);
        gate.authenticate(KEY).await.expect("seed");
        let err = gate
            .ensure_activated(KEY)
            .await
            .expect_err("limit reached denies");
        assert!(err.contains("activation limit"));
    }

    #[tokio::test]
    async fn local_token_users_are_uncapped() {
        let (gate, _registry, _router) =
            gate_with(Arc::new(MockBackend::default()), &[("ben_cm", 1)]);
        // No cache row for this name (a local `etun admin` user).
        assert_eq!(gate.cap_for("mat", now_unix()), CapDecision::Allow);
        // ensure_activated on a non-Polar credential is a no-op Ok.
        gate.ensure_activated("etun_local_token")
            .await
            .expect("no-op");
    }

    #[tokio::test]
    async fn downgrade_prunes_over_cap_tunnels() {
        // Customer starts on a 3-tunnel benefit, owns 3 labels, then a
        // re-validate comes back with a 1-tunnel benefit (tier switch).
        let (gate, registry, router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_indie")),
            &[("ben_indie", 3), ("ben_cm", 1)],
        );
        let user = gate.authenticate(KEY).await.expect("seed");
        for label in ["a", "b", "c"] {
            registry.claim_label(user.user_id, label).unwrap();
        }
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 3);

        // The tier switch: same customer, new key on the 1-cap benefit.
        // gate2's cache is FRESH, so it holds no row for the old key — this
        // models a relay that has never seen it, not the shared-cache case.
        // That one is `genuine_downgrade_prunes_once_the_old_key_goes_stale`.
        let new_key = "CMND-NEW-KEY";
        let (gate2, _r, _rt) = gate_with(
            Arc::new(MockBackend::granting(new_key, "cust_1", "ben_cm")),
            &[("ben_indie", 3), ("ben_cm", 1)],
        );
        // Point gate2 at the SAME registry/router so the prune acts on the
        // real owned rows.
        gate2.set_reconciler(std::sync::Arc::new(Reconciler {
            registry: registry.clone(),
            router: router.clone(),
            domain: "ethertunnel.com".into(),
        }));
        let user2 = gate2
            .authenticate(new_key)
            .await
            .expect("new key authenticates");
        assert_eq!(user2.user_id, user.user_id, "same customer, same account");
        // Owned rows were pruned to the new cap (oldest kept).
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 1);
        assert!(registry.owns_hostname(user.user_id, "a.ethertunnel.com"));
    }

    /// Age `key`'s cached row past `cache_ttl_secs` and authenticate it, so
    /// the fresh-cache early return is skipped and the prune actually runs.
    async fn revalidate(gate: &PolarGate, key: &str) {
        let mut row = gate.cache.get(&hash_key(key)).unwrap().unwrap();
        row.validated_at = now_unix() - gate.policy.cache_ttl_secs - 1;
        gate.cache.upsert(&row).unwrap();
        gate.authenticate(key).await.expect("re-validate");
    }

    /// A live session handle plus the receiver its `Denied` frames land in.
    fn session_handle(
        user_id: i64,
    ) -> (crate::router::SessionHandle, mpsc::Receiver<ControlFrame>) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(16);
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        (
            crate::router::SessionHandle::new(1, user_id, ctrl_tx, cmd_tx),
            ctrl_rx,
        )
    }

    /// One Polar customer, two granted keys, one shared registry account:
    /// re-validating the smallest key must not shrink the pool the biggest
    /// one pays for. Another customer's keys stay out of it.
    #[tokio::test]
    async fn multi_key_customer_resolves_cap_as_max_across_keys() {
        const TEAM: &str = "CMND-TEAM-KEY";
        const CM: &str = "CMND-CORTEXMIND-KEY";
        let backend = Arc::new(
            MockBackend::granting(TEAM, "cust_1", "ben_team").grant(CM, "cust_1", "ben_cm"),
        );
        let (gate, registry, _router) = gate_with(backend, &[("ben_team", 30), ("ben_cm", 1)]);

        let user = gate.authenticate(TEAM).await.expect("team key");
        for label in ["a", "b", "c"] {
            registry.claim_label(user.user_id, label).unwrap();
        }

        let same = gate.authenticate(CM).await.expect("cortexmind key");
        assert_eq!(same.user_id, user.user_id);

        assert_eq!(
            registry.count_owned_resources(user.user_id).unwrap(),
            3,
            "the 1-tunnel key must not prune what the 30-tunnel key allows"
        );
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(30));

        seed_license(&gate, "K-OTHER", "cust_2", "granted", Some(99));
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(30));
        assert_eq!(gate.cap_for("cust_2", now_unix()), CapDecision::Cap(99));
        assert_eq!(
            gate.cap_for("mat", now_unix()),
            CapDecision::Allow,
            "a local token must stay uncapped however many customers the cache holds"
        );
    }

    /// The pooled cap is the number the prune ENFORCES, not merely a reason
    /// not to prune: 40 owned against a pooled 30 lands on 30, not on the
    /// presenting key's 1 and not untouched.
    #[tokio::test]
    async fn pooled_cap_is_the_enforced_prune_target() {
        const TEAM: &str = "CMND-TEAM-KEY";
        const CM: &str = "CMND-CORTEXMIND-KEY";
        let backend = Arc::new(
            MockBackend::granting(TEAM, "cust_1", "ben_team").grant(CM, "cust_1", "ben_cm"),
        );
        let (gate, registry, _router) = gate_with(backend, &[("ben_team", 30), ("ben_cm", 1)]);

        let user = gate.authenticate(TEAM).await.expect("team key");
        for i in 0..40 {
            registry
                .claim_label(user.user_id, &format!("h{i:02}"))
                .unwrap();
        }

        gate.authenticate(CM).await.expect("cortexmind key");
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 30);
        assert!(registry.owns_hostname(user.user_id, "h00.ethertunnel.com"));
        assert!(!registry.owns_hostname(user.user_id, "h39.ethertunnel.com"));
    }

    /// Enforcement splits by what it costs to be wrong: an abandoned sibling
    /// key stops backing LIVE traffic on the claim gate's window, while the
    /// hostname reservations it grandfathers survive to the far longer prune
    /// grace. Routing what the gate would refuse to claim is the regression.
    #[tokio::test]
    async fn stale_sibling_key_evicts_routes_but_keeps_reservations() {
        const OLD: &str = "CMND-OLD-INDIE-KEY";
        const NEW: &str = "CMND-NEW-CM-KEY";
        let backend = Arc::new(
            MockBackend::granting(OLD, "cust_1", "ben_indie").grant(NEW, "cust_1", "ben_cm"),
        );
        let (gate, registry, router) = gate_with(backend, &[("ben_indie", 3), ("ben_cm", 1)]);

        let user = gate.authenticate(OLD).await.expect("old key");
        let (handle, mut denied) = session_handle(user.user_id);
        let fqdns: Vec<String> = ["a", "b", "c"]
            .iter()
            .map(|l| {
                registry.claim_label(user.user_id, l).unwrap();
                format!("{l}.ethertunnel.com")
            })
            .collect();
        router.claim(&handle, &fqdns, &[]);

        // Both keys still presented: nothing moves.
        gate.authenticate(NEW).await.expect("new key");
        assert!(router.lookup_http("c.ethertunnel.com").is_some());

        // The old key is never presented again. Past the staleness window the
        // claim gate stops counting it, so its traffic stops with it.
        let past_staleness = now_unix() - gate.policy.staleness_secs - 1;
        seed_license_at(&gate, OLD, "cust_1", "granted", Some(3), past_staleness);
        revalidate(&gate, NEW).await;
        assert!(router.lookup_http("a.ethertunnel.com").is_some());
        assert!(router.lookup_http("b.ethertunnel.com").is_none());
        assert!(router.lookup_http("c.ethertunnel.com").is_none());
        assert!(matches!(
            denied.try_recv(),
            Ok(ControlFrame::Denied {
                code: DenyCode::LimitExceeded,
                ..
            })
        ));

        // The reservations are still theirs until the prune grace runs out.
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 3);
    }

    /// An operator who shortens the prune grace below the fail-open window
    /// must not get a prune stricter than the claim gate — that hard-deletes,
    /// every revalidation, exactly the labels the gate just authorized.
    #[tokio::test]
    async fn short_cap_prune_grace_cannot_outrun_the_claim_gate() {
        const OLD: &str = "CMND-OLD-INDIE-KEY";
        const NEW: &str = "CMND-NEW-CM-KEY";
        let backend = Arc::new(
            MockBackend::granting(OLD, "cust_1", "ben_indie").grant(NEW, "cust_1", "ben_cm"),
        );
        let mut policy = test_policy(&[("ben_indie", 3), ("ben_cm", 1)]);
        policy.cap_prune_grace_secs = 86_400;
        let (gate, registry, _router) = gate_with_policy(backend, policy);

        let user = gate.authenticate(OLD).await.expect("old key");
        for label in ["a", "b", "c"] {
            registry.claim_label(user.user_id, label).unwrap();
        }
        gate.authenticate(NEW).await.expect("new key");

        // Two days stale: inside the window the claim gate honors, outside the
        // grace the operator asked for.
        seed_license_at(
            &gate,
            OLD,
            "cust_1",
            "granted",
            Some(3),
            now_unix() - 172_800,
        );
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(3));

        revalidate(&gate, NEW).await;
        assert_eq!(
            registry.count_owned_resources(user.user_id).unwrap(),
            3,
            "the prune deleted labels the claim gate still authorizes"
        );
    }

    /// The MAX must not grandfather a plan the customer no longer holds — but
    /// silence is weak evidence: the claim gate stops counting an abandoned
    /// key after `staleness_secs` (reversible), while the hard delete waits
    /// for the far longer `cap_prune_grace_secs`.
    #[tokio::test]
    async fn genuine_downgrade_prunes_once_the_old_key_goes_stale() {
        const OLD: &str = "CMND-OLD-INDIE-KEY";
        const NEW: &str = "CMND-NEW-CM-KEY";
        let backend = Arc::new(
            MockBackend::granting(OLD, "cust_1", "ben_indie").grant(NEW, "cust_1", "ben_cm"),
        );
        let (gate, registry, _router) = gate_with(backend, &[("ben_indie", 3), ("ben_cm", 1)]);

        let user = gate.authenticate(OLD).await.expect("old key");
        for label in ["a", "b", "c"] {
            registry.claim_label(user.user_id, label).unwrap();
        }

        gate.authenticate(NEW).await.expect("new key");
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 3);
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(3));

        // The old key is never presented again. Past the staleness window the
        // claim gate stops counting it...
        let past_staleness = now_unix() - gate.policy.staleness_secs - 1;
        seed_license_at(&gate, OLD, "cust_1", "granted", Some(3), past_staleness);
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(1));

        // ...but the prune does not: a daemon merely offline for three days
        // must not lose its hostname reservations.
        revalidate(&gate, NEW).await;
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 3);

        // Past the prune grace the old plan is gone for real.
        let past_grace = now_unix() - gate.policy.cap_prune_grace_secs - 1;
        seed_license_at(&gate, OLD, "cust_1", "granted", Some(3), past_grace);
        revalidate(&gate, NEW).await;
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 1);
        assert!(registry.owns_hostname(user.user_id, "a.ethertunnel.com"));
    }

    /// The one downgrade shape that still enforces promptly: the same key
    /// returns on a smaller benefit, overwriting its own row, so the old cap
    /// leaves the pool the moment it re-validates.
    #[tokio::test]
    async fn same_key_benefit_change_prunes_immediately() {
        let (gate, registry, _router) = gate_with(
            Arc::new(MockBackend::granting(KEY, "cust_1", "ben_cm")),
            &[("ben_cm", 1)],
        );
        let user = gate.authenticate(KEY).await.expect("provision");
        for label in ["a", "b", "c"] {
            registry.claim_label(user.user_id, label).unwrap();
        }

        // Pre-switch state: this key's row still carries the old 3-tunnel cap,
        // aged past the TTL so the next authenticate re-validates.
        let ttl_expired = now_unix() - gate.policy.cache_ttl_secs - 1;
        seed_license_at(&gate, KEY, "cust_1", "granted", Some(3), ttl_expired);
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(3));

        gate.authenticate(KEY).await.expect("re-validate");
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 1);
        assert!(registry.owns_hostname(user.user_id, "a.ethertunnel.com"));
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(1));
    }

    #[tokio::test]
    async fn cap_ignores_keys_past_the_staleness_window() {
        let (gate, _registry, _router) = gate_with(Arc::new(MockBackend::default()), &[]);
        let now = now_unix();
        let staleness = gate.policy.staleness_secs;

        seed_license_at(&gate, "K-SMALL", "cust_1", "granted", Some(1), now);
        seed_license_at(
            &gate,
            "K-BIG",
            "cust_1",
            "granted",
            Some(30),
            now - staleness - 1,
        );
        assert_eq!(gate.cap_for("cust_1", now), CapDecision::Cap(1));

        // The window edge is inclusive.
        seed_license_at(
            &gate,
            "K-BIG",
            "cust_1",
            "granted",
            Some(30),
            now - staleness,
        );
        assert_eq!(gate.cap_for("cust_1", now), CapDecision::Cap(30));
    }

    /// Aging out is a third way to have rows and no capacity, and it must land
    /// on `DenyAll` like the other two. Qualifying rows by freshness in the
    /// aggregate's WHERE clause instead of its CASE would zero the row count
    /// and fail open to `Allow` — an uncapped lapsed customer.
    #[tokio::test]
    async fn a_customer_whose_only_key_aged_out_is_denied_not_uncapped() {
        let (gate, _registry, _router) = gate_with(Arc::new(MockBackend::default()), &[]);
        let now = now_unix();
        seed_license_at(
            &gate,
            "K-LAPSED",
            "cust_1",
            "granted",
            Some(30),
            now - gate.policy.staleness_secs - 1,
        );
        assert_eq!(gate.cap_for("cust_1", now), CapDecision::DenyAll);
        assert_eq!(gate.cap_for("mat", now), CapDecision::Allow);
    }

    #[tokio::test]
    async fn revoked_and_unmapped_keys_grant_no_capacity() {
        let (gate, _registry, _router) = gate_with(Arc::new(MockBackend::default()), &[]);
        let now = now_unix();

        seed_license(&gate, "K-REVOKED", "cust_1", "not_licensed", Some(30));
        seed_license(&gate, "K-UNMAPPED", "cust_1", "granted", None);
        assert_eq!(
            gate.cap_for("cust_1", now),
            CapDecision::DenyAll,
            "keys exist but none qualify — must deny, never fall through to Allow"
        );

        seed_license(&gate, "K-LIVE", "cust_1", "granted", Some(2));
        assert_eq!(gate.cap_for("cust_1", now), CapDecision::Cap(2));
    }

    #[tokio::test]
    async fn unmapped_benefit_denies_its_own_key_without_touching_the_pool() {
        const GOOD: &str = "CMND-GOOD-KEY";
        const BAD: &str = "CMND-UNMAPPED-KEY";
        let backend = Arc::new(MockBackend::granting(GOOD, "cust_1", "ben_cm").grant(
            BAD,
            "cust_1",
            "ben_unknown",
        ));
        let (gate, registry, _router) = gate_with(backend, &[("ben_cm", 5)]);

        let user = gate.authenticate(GOOD).await.expect("mapped key");
        for label in ["a", "b"] {
            registry.claim_label(user.user_id, label).unwrap();
        }

        assert!(gate.authenticate(BAD).await.is_none());
        assert_eq!(registry.count_owned_resources(user.user_id).unwrap(), 2);
        assert_eq!(gate.cap_for("cust_1", now_unix()), CapDecision::Cap(5));
    }

    /// On-disk license cache (+ WAL/SHM) must be 0600 — it maps key hashes
    /// to customers.
    #[cfg(unix)]
    #[test]
    fn open_chmods_cache_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicU64;
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("etun-test-polar-{}-{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let cache = LicenseCache::open(&path).unwrap();
        cache
            .upsert(&LicenseRow {
                key_hash: vec![1, 2, 3],
                customer_id: "cust".into(),
                benefit_id: "ben".into(),
                max_tunnels: Some(1),
                status: "granted".into(),
                activation_id: None,
                validated_at: 0,
            })
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "polar-cache.db must be 0600, was {mode:o}");
        for ext in ["-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(ext);
            let sib = std::path::Path::new(&p);
            if let Ok(meta) = std::fs::metadata(sib) {
                let m = meta.permissions().mode() & 0o777;
                assert_eq!(m, 0o600, "{} must be 0600, was {m:o}", sib.display());
            }
            let _ = std::fs::remove_file(sib);
        }
        drop(cache);
        let _ = std::fs::remove_file(&path);
    }
}
