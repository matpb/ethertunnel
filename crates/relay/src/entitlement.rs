//! keygate entitlement integration: cache, signature verification, and the
//! background sync poller.
//!
//! The relay enforces a per-customer `max_tunnels` cap at claim time. It must do
//! so WITHOUT a synchronous call to keygate on the hot path, so:
//!
//!  * A background task ([`spawn_sync`]) pulls Ed25519-signed entitlement
//!    envelopes from keygate's `/v1/entitlements/changes` endpoint and caches
//!    the verified `max_tunnels`/status per customer in a small local SQLite.
//!  * [`handle_claim`](crate::session) reads only the local cache. If keygate is
//!    down the relay keeps enforcing the last snapshot it pulled (fail-open),
//!    bounded by an absolute staleness ceiling so a cancelled customer cannot
//!    retain access forever.
//!
//! The signature is the only thing standing between a forged `max_tunnels` and
//! the cache, so [`canonical_bytes`] reproduces keygate's canonical
//! serialization byte-for-byte and [`verify_envelope`] checks it against
//! keygate's pinned public key.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;

/// The signed payload, mirroring keygate's `models::EntitlementPayload`. Field
/// names and types must match exactly — they are part of the signed canonical
/// form.
#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementPayload {
    pub customer_id: i64,
    pub external_ref: Option<String>,
    pub product: String,
    pub entitlements: BTreeMap<String, serde_json::Value>,
    pub status: String,
    pub issued_at: String,
    pub expires_at: String,
    pub key_id: String,
}

/// A signed envelope as returned by keygate's relay-facing API.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedEnvelope {
    pub payload: EntitlementPayload,
    /// base64 (standard) Ed25519 signature over [`canonical_bytes`] of `payload`.
    pub signature: String,
    pub key_id: String,
}

/// Reproduce keygate's canonical serialization of a payload: a compact JSON
/// object with top-level keys in lexicographic order and a nested, sorted
/// `entitlements` object. This MUST stay byte-identical to keygate
/// `signing::canonical_bytes` or every signature fails to verify.
pub fn canonical_bytes(p: &EntitlementPayload) -> Vec<u8> {
    // `entitlements` is already a BTreeMap (sorted); round-trip through to_value
    // exactly as keygate does so number/string reprs match.
    let ents: BTreeMap<&String, serde_json::Value> =
        p.entitlements.iter().map(|(k, v)| (k, v.clone())).collect();

    let mut top: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    top.insert("customer_id", serde_json::json!(p.customer_id));
    top.insert(
        "entitlements",
        serde_json::to_value(&ents).unwrap_or(serde_json::Value::Null),
    );
    top.insert(
        "expires_at",
        serde_json::Value::String(p.expires_at.clone()),
    );
    top.insert(
        "external_ref",
        match &p.external_ref {
            Some(r) => serde_json::Value::String(r.clone()),
            None => serde_json::Value::Null,
        },
    );
    top.insert("issued_at", serde_json::Value::String(p.issued_at.clone()));
    top.insert("key_id", serde_json::Value::String(p.key_id.clone()));
    top.insert("product", serde_json::Value::String(p.product.clone()));
    top.insert("status", serde_json::Value::String(p.status.clone()));

    serde_json::to_vec(&top).expect("canonical serialization")
}

/// Verify an envelope against keygate's pinned public key (base64, standard).
pub fn verify_envelope(env: &SignedEnvelope, public_key_b64: &str) -> bool {
    let Ok(pk_bytes) = base64::engine::general_purpose::STANDARD.decode(public_key_b64) else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(&env.signature) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&canonical_bytes(&env.payload), &sig).is_ok()
}

/// A cached, verified entitlement for one customer (keyed by `external_ref`,
/// which equals the relay registry's user name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlement {
    pub external_ref: String,
    pub customer_id: i64,
    /// `None` = no `max_tunnels` feature granted (treated as unlimited).
    pub max_tunnels: Option<i64>,
    pub status: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
}

/// The decision the gate hands the claim path for a given user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapDecision {
    /// No applicable entitlement (or stale beyond the ceiling, with
    /// `require_entitlement` off) — do not enforce; let the claim through.
    Allow,
    /// Cap concurrently-active tunnels at this number.
    Cap(i64),
    /// Deny all new claims (suspended, or unentitled with `require_entitlement`).
    DenyAll,
}

/// Current unix wall-clock seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Local SQLite cache of verified entitlements. Its own database file (sibling
/// of the registry), so it never contends with the registry's connection.
pub struct EntitlementCache {
    conn: Mutex<Connection>,
}

impl EntitlementCache {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rusqlite::Error> {
        let path = path.as_ref();
        let me = Self::init(Connection::open(path)?)?;
        // Same rationale as the registry: chmod after init() (journal_mode=WAL
        // created the -wal/-shm). The keygate cache holds customer entitlements.
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
            CREATE TABLE IF NOT EXISTS entitlements (
                external_ref TEXT PRIMARY KEY,
                customer_id  INTEGER NOT NULL,
                max_tunnels  INTEGER,
                status       TEXT NOT NULL,
                issued_at    INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                updated_at   INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert or replace the cached entitlement for a customer.
    pub fn upsert(&self, e: &Entitlement) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO entitlements
                (external_ref, customer_id, max_tunnels, status, issued_at, expires_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(external_ref) DO UPDATE SET
                customer_id = excluded.customer_id,
                max_tunnels = excluded.max_tunnels,
                status      = excluded.status,
                issued_at   = excluded.issued_at,
                expires_at  = excluded.expires_at,
                updated_at  = excluded.updated_at",
            rusqlite::params![
                e.external_ref,
                e.customer_id,
                e.max_tunnels,
                e.status,
                e.issued_at,
                e.expires_at,
                e.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, external_ref: &str) -> Result<Option<Entitlement>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT external_ref, customer_id, max_tunnels, status, issued_at, expires_at, updated_at
             FROM entitlements WHERE external_ref = ?1",
            [external_ref],
            |r| {
                Ok(Entitlement {
                    external_ref: r.get(0)?,
                    customer_id: r.get(1)?,
                    max_tunnels: r.get(2)?,
                    status: r.get(3)?,
                    issued_at: r.get(4)?,
                    expires_at: r.get(5)?,
                    updated_at: r.get(6)?,
                })
            },
        )
        .optional()
    }
}

/// Policy + pinned key for the gate, derived from `[keygate]` config.
#[derive(Clone)]
pub struct KeygatePolicy {
    pub product: String,
    pub public_key_b64: String,
    pub key_id: String,
    /// Honor a cached envelope at most this many seconds past its `expires_at`.
    pub staleness_ceiling_secs: i64,
    /// When true, a user with no (fresh) cached entitlement is denied; when
    /// false (default), such a user is allowed through unenforced.
    pub require_entitlement: bool,
}

/// The claim-time entitlement gate: a cache plus the policy that interprets it.
pub struct EntitlementGate {
    cache: EntitlementCache,
    policy: KeygatePolicy,
}

impl EntitlementGate {
    pub fn new(cache: EntitlementCache, policy: KeygatePolicy) -> Self {
        Self { cache, policy }
    }

    /// Decide the cap for `external_ref` (the registry user name) at `now`.
    /// Fails open: any cache read error yields [`CapDecision::Allow`] so a
    /// database hiccup never takes tunnels down.
    pub fn cap_for(&self, external_ref: &str, now: i64) -> CapDecision {
        let entry = match self.cache.get(external_ref) {
            Ok(Some(e)) => e,
            Ok(None) => return self.missing(),
            Err(e) => {
                tracing::warn!(external_ref, error = %e, "entitlement cache read failed; allowing");
                return CapDecision::Allow;
            }
        };

        // Past the absolute staleness ceiling the cached value is no longer
        // trustworthy: behave as if there is no entitlement.
        if now > entry.expires_at + self.policy.staleness_ceiling_secs {
            tracing::debug!(external_ref, "cached entitlement stale beyond ceiling");
            return self.missing();
        }

        match entry.status.as_str() {
            "suspended" => CapDecision::DenyAll,
            // active / past_due (grace) / anything else granting: enforce the cap.
            _ => match entry.max_tunnels {
                Some(m) => CapDecision::Cap(m),
                None => CapDecision::Allow,
            },
        }
    }

    fn missing(&self) -> CapDecision {
        if self.policy.require_entitlement {
            CapDecision::DenyAll
        } else {
            CapDecision::Allow
        }
    }

    /// Ingest a batch of envelopes from a sync pull: verify each, then cache the
    /// valid ones. Returns `(accepted, rejected)` counts.
    pub fn ingest(&self, envelopes: &[SignedEnvelope], now: i64) -> (usize, usize) {
        let mut accepted = 0;
        let mut rejected = 0;
        for env in envelopes {
            if !self.accept(env, now) {
                rejected += 1;
                continue;
            }
            accepted += 1;
        }
        (accepted, rejected)
    }

    /// Validate one envelope and upsert it. Returns false (and logs) on any
    /// validation failure.
    fn accept(&self, env: &SignedEnvelope, now: i64) -> bool {
        if env.key_id != self.policy.key_id || env.payload.key_id != self.policy.key_id {
            tracing::warn!(got = %env.key_id, want = %self.policy.key_id, "entitlement key_id mismatch");
            return false;
        }
        if env.payload.product != self.policy.product {
            return false;
        }
        if !verify_envelope(env, &self.policy.public_key_b64) {
            tracing::warn!("entitlement signature verification failed; dropping");
            return false;
        }
        let Some(external_ref) = env.payload.external_ref.clone() else {
            return false;
        };
        let (Some(issued_at), Some(expires_at)) = (
            parse_unix_z(&env.payload.issued_at),
            parse_unix_z(&env.payload.expires_at),
        ) else {
            tracing::warn!("entitlement has unparseable timestamps; dropping");
            return false;
        };
        let max_tunnels = env
            .payload
            .entitlements
            .get("max_tunnels")
            .and_then(|v| v.as_i64());

        let ent = Entitlement {
            external_ref,
            customer_id: env.payload.customer_id,
            max_tunnels,
            status: env.payload.status.clone(),
            issued_at,
            expires_at,
            updated_at: now,
        };
        if let Err(e) = self.cache.upsert(&ent) {
            tracing::warn!(error = %e, "entitlement upsert failed");
            return false;
        }
        true
    }
}

/// A minimal HTTP client for keygate's relay-facing API, reusing the same
/// hyper-rustls (ring) stack as the Cloudflare/ACME paths so no second TLS
/// backend leaks into the static musl build.
pub struct KeygateClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    base_url: String,
    token: String,
    product: String,
}

impl KeygateClient {
    pub fn new(base_url: String, token: String, product: String) -> Self {
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
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
            product,
        }
    }

    /// Pull all entitlement envelopes changed since `since` (unix seconds).
    /// `since = 0` returns the full snapshot.
    pub async fn fetch_changes(&self, since: i64) -> anyhow::Result<Vec<SignedEnvelope>> {
        let url = format!(
            "{}/v1/entitlements/changes?product={}&since={}",
            self.base_url, self.product, since
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", "ethertunnel-relay/0.1")
            .body(Full::new(Bytes::new()))?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            anyhow::bail!("keygate changes returned {status}");
        }
        #[derive(Deserialize)]
        struct ChangesResp {
            changes: Vec<SignedEnvelope>,
        }
        let parsed: ChangesResp = serde_json::from_slice(&bytes)?;
        Ok(parsed.changes)
    }
}

/// Spawn the background sync loop: every `interval`, pull the full entitlement
/// snapshot from keygate, verify + cache it. Errors are logged and the last good
/// cache is retained (fail-open). Runs for the process lifetime.
pub fn spawn_sync(
    gate: std::sync::Arc<EntitlementGate>,
    client: KeygateClient,
    interval: Duration,
) {
    tokio::spawn(async move {
        // A small initial delay lets the listener come up first.
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            match client.fetch_changes(0).await {
                Ok(envs) => {
                    let (ok, bad) = gate.ingest(&envs, now_unix());
                    tracing::info!(accepted = ok, rejected = bad, "keygate entitlement sync");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "keygate entitlement sync failed; keeping cache");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// Parse a strict `YYYY-MM-DDTHH:MM:SSZ` timestamp to unix seconds (UTC).
/// keygate always emits exactly this format. Returns `None` on any deviation.
fn parse_unix_z(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let mon: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hh: i64 = s.get(11..13)?.parse().ok()?;
    let mm: i64 = s.get(14..16)?.parse().ok()?;
    let ss: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&mon) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days_from_civil (Howard Hinnant), epoch 1970-01-01.
    let y = if mon <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if mon > 2 { mon - 3 } else { mon + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signer(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn payload(max: i64) -> EntitlementPayload {
        let mut ents = BTreeMap::new();
        ents.insert("max_tunnels".to_string(), serde_json::json!(max));
        EntitlementPayload {
            customer_id: 42,
            external_ref: Some("mat".to_string()),
            product: "ethertunnel".to_string(),
            entitlements: ents,
            status: "active".to_string(),
            issued_at: "2026-06-13T00:00:00Z".to_string(),
            expires_at: "2026-06-13T06:00:00Z".to_string(),
            key_id: "kg-2026-06".to_string(),
        }
    }

    fn envelope(sk: &SigningKey, p: EntitlementPayload) -> SignedEnvelope {
        let sig = sk.sign(&canonical_bytes(&p));
        SignedEnvelope {
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            key_id: p.key_id.clone(),
            payload: p,
        }
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let (sk, pk) = signer(3);
        let env = envelope(&sk, payload(10));
        assert!(verify_envelope(&env, &pk));

        let mut tampered = env.clone();
        tampered
            .payload
            .entitlements
            .insert("max_tunnels".to_string(), serde_json::json!(9999));
        assert!(!verify_envelope(&tampered, &pk), "tamper must fail");

        let (_other, other_pk) = signer(9);
        assert!(!verify_envelope(&env, &other_pk), "wrong key must fail");
    }

    #[test]
    fn parse_timestamps() {
        assert_eq!(parse_unix_z("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_unix_z("2000-01-01T00:00:00Z"), Some(946_684_800));
        assert_eq!(parse_unix_z("2026-06-13T00:00:00Z"), Some(1_781_308_800));
        assert_eq!(parse_unix_z("not-a-time"), None);
        assert_eq!(parse_unix_z("2026-06-13 00:00:00Z"), None); // missing T
        assert_eq!(parse_unix_z("2026-06-13T00:00:00"), None); // missing Z
    }

    #[test]
    fn ingest_caps_and_rejects() {
        let (sk, pk) = signer(7);
        let policy = KeygatePolicy {
            product: "ethertunnel".into(),
            public_key_b64: pk,
            key_id: "kg-2026-06".into(),
            staleness_ceiling_secs: 259_200,
            require_entitlement: false,
        };
        let gate = EntitlementGate::new(EntitlementCache::open_in_memory().unwrap(), policy);

        let env = envelope(&sk, payload(3));
        let (ok, bad) = gate.ingest(std::slice::from_ref(&env), now_unix());
        assert_eq!((ok, bad), (1, 0));

        // Fresh entry → cap of 3.
        assert_eq!(gate.cap_for("mat", now_unix()), CapDecision::Cap(3));
        // Unknown user → allow (require_entitlement off).
        assert_eq!(gate.cap_for("ghost", now_unix()), CapDecision::Allow);

        // A wrong-key envelope is rejected.
        let (bad_sk, _) = signer(11);
        let forged = envelope(&bad_sk, payload(9999));
        let (ok2, bad2) = gate.ingest(std::slice::from_ref(&forged), now_unix());
        assert_eq!((ok2, bad2), (0, 1));
        // Cache still holds the genuine value.
        assert_eq!(gate.cap_for("mat", now_unix()), CapDecision::Cap(3));
    }

    #[test]
    fn staleness_ceiling_and_status() {
        let (sk, pk) = signer(5);
        let policy = KeygatePolicy {
            product: "ethertunnel".into(),
            public_key_b64: pk,
            key_id: "kg-2026-06".into(),
            staleness_ceiling_secs: 100,
            require_entitlement: false,
        };
        let gate = EntitlementGate::new(EntitlementCache::open_in_memory().unwrap(), policy);
        let env = envelope(&sk, payload(5));
        gate.ingest(std::slice::from_ref(&env), now_unix());

        // expires_at = 2026-06-13T06:00:00Z = 1_781_308_800 + 6h.
        let expires = 1_781_308_800_i64 + 6 * 3600;
        assert_eq!(gate.cap_for("mat", expires + 50), CapDecision::Cap(5)); // within ceiling
        assert_eq!(gate.cap_for("mat", expires + 200), CapDecision::Allow); // past ceiling → missing

        // require_entitlement flips the missing case to DenyAll.
        let policy2 = KeygatePolicy {
            product: "ethertunnel".into(),
            public_key_b64: base64::engine::general_purpose::STANDARD
                .encode(sk.verifying_key().to_bytes()),
            key_id: "kg-2026-06".into(),
            staleness_ceiling_secs: 100,
            require_entitlement: true,
        };
        let gate2 = EntitlementGate::new(EntitlementCache::open_in_memory().unwrap(), policy2);
        assert_eq!(gate2.cap_for("nobody", now_unix()), CapDecision::DenyAll);
    }

    #[test]
    fn suspended_denies_all() {
        let (sk, pk) = signer(13);
        let policy = KeygatePolicy {
            product: "ethertunnel".into(),
            public_key_b64: pk,
            key_id: "kg-2026-06".into(),
            staleness_ceiling_secs: 259_200,
            require_entitlement: false,
        };
        let gate = EntitlementGate::new(EntitlementCache::open_in_memory().unwrap(), policy);
        let mut p = payload(10);
        p.status = "suspended".into();
        let env = envelope(&sk, p);
        gate.ingest(std::slice::from_ref(&env), now_unix());
        assert_eq!(gate.cap_for("mat", now_unix()), CapDecision::DenyAll);
    }

    /// On-disk entitlement cache (+ WAL/SHM) must be chmodded 0600 after open —
    /// it holds customer entitlements. (finding 12)
    #[cfg(unix)]
    #[test]
    fn open_chmods_cache_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("etun-test-keygate-{}-{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let cache = EntitlementCache::open(&path).unwrap();
        // Force a write so the WAL materializes.
        cache
            .upsert(&Entitlement {
                external_ref: "mat".into(),
                customer_id: 1,
                max_tunnels: Some(1),
                status: "active".into(),
                issued_at: 0,
                expires_at: i64::MAX,
                updated_at: 0,
            })
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keygate-cache.db must be 0600, was {mode:o}");
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
