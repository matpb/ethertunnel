//! The hostname/token registry, backed by SQLite.
//!
//! Holds users, their bearer tokens (stored only as SHA-256), and the
//! hostnames/ports they own. It implements [`Authenticator`], so the session
//! layer is unchanged from the in-memory version. Admin commands operate on the
//! same database directly (so they work whether or not the relay is running).
//!
//! Hostnames are stored as *labels* (the part below the apex), not FQDNs, so
//! the relay's base domain can change in config without a data migration.

use std::path::Path;
use std::sync::Mutex;

use base64::Engine;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::{AuthedUser, Authenticator, ClaimOutcome};

/// Errors from registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("no such user: {0}")]
    NoSuchUser(String),
    #[error("user {0} already exists")]
    UserExists(String),
    #[error("user {0} still owns tokens/hostnames/ports (use --force)")]
    UserNotEmpty(String),
    #[error("invalid label '{0}': {1}")]
    InvalidLabel(String, &'static str),
    #[error("label '{0}' is already taken")]
    LabelTaken(String),
    #[error("port {0} is reserved by another user")]
    PortTaken(u16),
    #[error("tunnel cap reached: already owns the maximum number of resources")]
    CapExceeded,
}

/// Reserved labels that may never be claimed as tunnel hostnames.
pub const RESERVED_LABELS: &[&str] = &["connect", "www", "admin", "api", "docs", "status", "mail"];

/// Validate a hostname label: a single DNS label, lowercase, not reserved.
pub fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() || label.len() > 63 {
        return Err("must be 1..=63 characters");
    }
    let bytes = label.as_bytes();
    let ok_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !ok_edge(bytes[0]) || !ok_edge(bytes[bytes.len() - 1]) {
        return Err("must start and end with a-z0-9");
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("only a-z, 0-9 and '-' are allowed");
    }
    if RESERVED_LABELS.contains(&label) {
        return Err("this label is reserved");
    }
    Ok(())
}

/// Generate a fresh bearer token: `etun_` + 32 URL-safe-base64 random bytes.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!(
        "etun_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// A row from `token list`.
#[derive(Debug)]
pub struct TokenRow {
    pub id: i64,
    pub user: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub revoked: bool,
}

/// The SQLite-backed registry.
pub struct Registry {
    conn: Mutex<Connection>,
    domain: String,
    suffix: String,
}

/// Best-effort tighten a SQLite database file (and its `-wal`/`-shm` siblings)
/// to owner-only (0600). Called AFTER `init()` runs `journal_mode=WAL`, because
/// that pragma is what creates the WAL/SHM files — tightening before would miss
/// them (and the WAL holds the freshest, uncommitted rows). Errors are swallowed:
/// the siblings may not exist yet (ENOENT) and a chmod failure must never block
/// startup. No-op on non-unix targets so the workspace still builds cross-platform.
#[cfg(unix)]
pub(crate) fn tighten_sqlite_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    for ext in ["-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(ext);
        let _ = std::fs::set_permissions(Path::new(&p), std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(not(unix))]
pub(crate) fn tighten_sqlite_perms(_path: &Path) {}

impl Registry {
    /// Open (creating if needed) the registry at `path` for `domain`.
    pub fn open(path: impl AsRef<Path>, domain: &str) -> Result<Self, RegistryError> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        let me = Self::init(conn, domain)?;
        // After init() (which created the -wal/-shm via journal_mode=WAL): the
        // DB holds token hashes + tenant topology and must never be world-readable.
        tighten_sqlite_perms(path);
        Ok(me)
    }

    /// An in-memory registry, for tests.
    pub fn open_in_memory(domain: &str) -> Result<Self, RegistryError> {
        Self::init(Connection::open_in_memory()?, domain)
    }

    fn init(conn: Connection, domain: &str) -> Result<Self, RegistryError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY,
                name       TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens (
                id         INTEGER PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                token_hash BLOB NOT NULL UNIQUE,
                label      TEXT,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS hostnames (
                id         INTEGER PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                label      TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tcp_ports (
                port       INTEGER PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                created_at INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            domain: domain.to_owned(),
            suffix: format!(".{domain}"),
        })
    }

    /// The relay's base domain this registry composes hostnames under.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Run `PRAGMA integrity_check` and return Ok only if the database is sound.
    pub fn integrity_check(&self) -> Result<(), RegistryError> {
        let conn = self.conn.lock().unwrap();
        let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(RegistryError::Db(rusqlite::Error::InvalidQuery))
        }
    }

    fn now() -> i64 {
        // Wall-clock seconds; only used for human-facing audit columns.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Resolve a user name (the keygate `external_ref`) to its registry user id,
    /// or `Ok(None)` if no such user exists. Used by the entitlement reconcile
    /// path, which is keyed by `external_ref` but prunes by `user_id`.
    pub fn lookup_user_id(&self, name: &str) -> Result<Option<i64>, RegistryError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0))
            .optional()
            .map_err(RegistryError::Db)
    }

    fn user_id(conn: &Connection, name: &str) -> Result<i64, RegistryError> {
        conn.query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0))
            .optional()?
            .ok_or_else(|| RegistryError::NoSuchUser(name.to_owned()))
    }

    // --- admin operations ---

    pub fn add_user(&self, name: &str) -> Result<i64, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row("SELECT 1 FROM users WHERE name = ?1", [name], |_| Ok(()))
            .optional()?
            .is_some();
        if exists {
            return Err(RegistryError::UserExists(name.to_owned()));
        }
        conn.execute(
            "INSERT INTO users (name, created_at) VALUES (?1, ?2)",
            rusqlite::params![name, Self::now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_users(&self) -> Result<Vec<(i64, String, i64)>, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name, created_at FROM users ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn remove_user(&self, name: &str, force: bool) -> Result<(), RegistryError> {
        let conn = self.conn.lock().unwrap();
        let id = Self::user_id(&conn, name)?;
        let owns: i64 = conn.query_row(
            "SELECT (SELECT COUNT(*) FROM tokens WHERE user_id=?1)
                  + (SELECT COUNT(*) FROM hostnames WHERE user_id=?1)
                  + (SELECT COUNT(*) FROM tcp_ports WHERE user_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if owns > 0 && !force {
            return Err(RegistryError::UserNotEmpty(name.to_owned()));
        }
        conn.execute("DELETE FROM tokens WHERE user_id = ?1", [id])?;
        conn.execute("DELETE FROM hostnames WHERE user_id = ?1", [id])?;
        conn.execute("DELETE FROM tcp_ports WHERE user_id = ?1", [id])?;
        conn.execute("DELETE FROM users WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Provision (idempotently) a user by name and mint a fresh bearer token.
    ///
    /// Used by the keygate-driven self-serve provisioning endpoint. The user is
    /// created if absent (returning `created = true`) or reused if it already
    /// exists (`created = false`); in both cases a *new* plaintext token is
    /// minted and returned exactly once (matching `create_token` semantics).
    ///
    /// Idempotent on `users.name`: a webhook retry against an existing ref mints
    /// an additional token rather than failing. keygate's `find_by_stripe_id`
    /// short-circuit prevents that from happening for the same buyer in practice.
    pub fn provision_user_token(&self, name: &str) -> Result<(String, bool), RegistryError> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<i64> = conn
            .query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0))
            .optional()?;
        let (id, created) = match existing {
            Some(id) => (id, false),
            None => {
                conn.execute(
                    "INSERT INTO users (name, created_at) VALUES (?1, ?2)",
                    rusqlite::params![name, Self::now()],
                )?;
                (conn.last_insert_rowid(), true)
            }
        };
        let token = generate_token();
        conn.execute(
            "INSERT INTO tokens (user_id, token_hash, label, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, hash_token(&token), Some("self-serve"), Self::now()],
        )?;
        Ok((token, created))
    }

    /// Rotate a user's bearer token: **revoke every currently-valid token** for
    /// the account, then mint exactly one fresh token. After this returns, the
    /// returned plaintext is the *only* credential that authenticates for the
    /// account — any token issued before now stops working immediately
    /// (`authenticate` matches `revoked_at IS NULL`).
    ///
    /// Used by the keygate-driven self-serve *recovery* path, where the security
    /// goal is that recovering an account kills any leaked/lost token. Contrast
    /// [`provision_user_token`], which *adds* a token and leaves old ones valid
    /// (correct for purchase-time provisioning).
    ///
    /// Idempotent on `users.name`: the account is created if absent (so recovery
    /// converges on "exactly one valid token" even for an account the relay has
    /// never seen). Returns the fresh plaintext token plus how many previously
    /// valid tokens were revoked.
    pub fn rotate_user_token(&self, name: &str) -> Result<(String, usize), RegistryError> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<i64> = conn
            .query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0))
            .optional()?;
        let id = match existing {
            Some(id) => id,
            None => {
                conn.execute(
                    "INSERT INTO users (name, created_at) VALUES (?1, ?2)",
                    rusqlite::params![name, Self::now()],
                )?;
                conn.last_insert_rowid()
            }
        };
        // Revoke all currently-valid tokens for this user, then mint one fresh.
        // Both run under the same connection mutex, so no token minted after the
        // revoke can be caught by it and no concurrent auth sees an empty window.
        let revoked = conn.execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE user_id = ?1 AND revoked_at IS NULL",
            rusqlite::params![id, Self::now()],
        )?;
        let token = generate_token();
        conn.execute(
            "INSERT INTO tokens (user_id, token_hash, label, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, hash_token(&token), Some("self-serve-recovery"), Self::now()],
        )?;
        Ok((token, revoked))
    }

    /// Release a user's claimed hostnames (and optionally their reserved TCP
    /// ports) back to the global pool, returning what was released. The user and
    /// their tokens are intentionally *kept*, so a resubscriber retains the same
    /// account/token; only the claimable namespace is reclaimed.
    ///
    /// Returns `NoSuchUser` if `name` is unknown so the caller (the keygate
    /// reaper) can treat that as already-released.
    pub fn release_user_hostnames(
        &self,
        name: &str,
        release_ports: bool,
    ) -> Result<(Vec<String>, Vec<u16>), RegistryError> {
        let conn = self.conn.lock().unwrap();
        let id = Self::user_id(&conn, name)?;
        let hostnames: Vec<String> = {
            let mut stmt = conn.prepare("SELECT label FROM hostnames WHERE user_id = ?1")?;
            let rows = stmt
                .query_map([id], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        conn.execute("DELETE FROM hostnames WHERE user_id = ?1", [id])?;
        let ports = if release_ports {
            let ports: Vec<u16> = {
                let mut stmt = conn.prepare("SELECT port FROM tcp_ports WHERE user_id = ?1")?;
                let rows = stmt
                    .query_map([id], |r| Ok(r.get::<_, i64>(0)? as u16))?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            conn.execute("DELETE FROM tcp_ports WHERE user_id = ?1", [id])?;
            ports
        } else {
            Vec::new()
        };
        Ok((hostnames, ports))
    }

    /// Count the resources `user_id` *owns* in the registry: claimed hostname
    /// labels plus reserved TCP ports. Tokens are deliberately excluded — they
    /// are credentials, not squattable namespace. This is the authoritative
    /// per-account tunnel cap measure (owned rows persist across disconnects,
    /// unlike the router's in-memory routed count).
    pub fn count_owned_resources(&self, user_id: i64) -> Result<i64, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT (SELECT COUNT(*) FROM hostnames WHERE user_id=?1)
                  + (SELECT COUNT(*) FROM tcp_ports WHERE user_id=?1)",
            [user_id],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    /// Register `label` to `user_id` if it is free (first-come-first-served from
    /// the global label pool). Returns:
    ///
    /// * `Ok(true)`  — the label was free and is now registered to this user.
    /// * `Ok(false)` — the label is already owned by *this* user (idempotent).
    /// * `Err(LabelTaken)` — the label is owned by someone else.
    /// * `Err(InvalidLabel)` — the label fails `validate_label` (reserved/malformed).
    ///
    /// Atomicity rests on the `UNIQUE(label)` index on `hostnames`: two daemons
    /// racing the same free label both attempt the INSERT; one wins, the other
    /// gets the UNIQUE violation surfaced as `LabelTaken`.
    pub fn claim_label(&self, user_id: i64, label: &str) -> Result<bool, RegistryError> {
        self.claim_label_capped(user_id, label, None)
    }

    /// Like [`claim_label`](Self::claim_label) but enforces a per-account cap on
    /// the number of *owned* resources, atomically with the insert.
    ///
    /// The cap check and the insert run under the same connection mutex, so the
    /// count-then-insert cannot race another claim from the same user: the
    /// connection mutex already serializes every registry call. Semantics:
    ///
    /// * already owned by this user → `Ok(false)` (idempotent no-op, allowed
    ///   regardless of `max` — re-claiming what you already own never counts).
    /// * owned by another user → `Err(LabelTaken)`.
    /// * free, `max == Some(m)`, and current owned count `>= m` → `Err(CapExceeded)`.
    /// * free and under cap (or `max == None`) → INSERT, with the UNIQUE-index
    ///   race still mapped to `LabelTaken`.
    pub fn claim_label_capped(
        &self,
        user_id: i64,
        label: &str,
        max: Option<i64>,
    ) -> Result<bool, RegistryError> {
        validate_label(label).map_err(|e| RegistryError::InvalidLabel(label.to_owned(), e))?;
        let conn = self.conn.lock().unwrap();
        // Fast path: already owned by this user → idempotent no-op. Re-claiming a
        // label you already hold never counts against the cap.
        let owner: Option<i64> = conn
            .query_row(
                "SELECT user_id FROM hostnames WHERE label = ?1",
                [label],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(owner_id) = owner {
            return if owner_id == user_id {
                Ok(false)
            } else {
                Err(RegistryError::LabelTaken(label.to_owned()))
            };
        }
        // Free label: enforce the cap against the owned-row count BEFORE the
        // insert, under this same lock so the check-then-act is atomic.
        if let Some(m) = max {
            let owned: i64 = conn.query_row(
                "SELECT (SELECT COUNT(*) FROM hostnames WHERE user_id=?1)
                      + (SELECT COUNT(*) FROM tcp_ports WHERE user_id=?1)",
                [user_id],
                |r| r.get(0),
            )?;
            if owned >= m {
                return Err(RegistryError::CapExceeded);
            }
        }
        // Attempt the insert. A concurrent writer may have claimed it between the
        // SELECT and here; the UNIQUE index makes the INSERT the real arbiter and
        // surfaces the race as LabelTaken.
        match conn.execute(
            "INSERT INTO hostnames (user_id, label, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![user_id, label, Self::now()],
        ) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(RegistryError::LabelTaken(label.to_owned()))
            }
            Err(e) => Err(RegistryError::Db(e)),
        }
    }

    /// Prune `user_id`'s owned resources down to `cap`, deleting the excess
    /// **deterministically**: the policy is grandfather-oldest — keep the oldest
    /// `cap` resources (by `created_at`, ties broken by the stable rowid/port key)
    /// and drop the newest over the cap. Hostnames and ports are pooled into one
    /// owned set and ordered together, so the newest acquisitions go first
    /// regardless of kind (matching the [`CapDecision`](crate::entitlement::CapDecision)
    /// "grandfather oldest-N, prune newest over cap" semantics).
    ///
    /// Runs under the connection mutex so the count-then-delete is atomic against
    /// any concurrent claim. Returns the labels and ports that were removed (so
    /// the caller can tear down the corresponding live routes). A `cap < 0` is
    /// clamped to 0 (deny-all → prune everything); `cap >= owned` is a no-op.
    pub fn prune_owned_to_cap(
        &self,
        user_id: i64,
        cap: i64,
    ) -> Result<(Vec<String>, Vec<u16>), RegistryError> {
        let cap = cap.max(0);
        let conn = self.conn.lock().unwrap();
        // Build the unified owned set, oldest first. `kind` (0 = host, 1 = port)
        // only breaks created_at ties deterministically; it is not a priority.
        #[derive(Debug)]
        enum Owned {
            Host(String),
            Port(u16),
        }
        let mut owned: Vec<(i64, i64, Owned)> = Vec::new(); // (created_at, key, res)
        {
            let mut stmt =
                conn.prepare("SELECT created_at, id, label FROM hostnames WHERE user_id = ?1")?;
            let rows = stmt.query_map([user_id], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, Owned::Host(r.get(2)?)))
            })?;
            for row in rows {
                owned.push(row?);
            }
        }
        {
            let mut stmt =
                conn.prepare("SELECT created_at, port FROM tcp_ports WHERE user_id = ?1")?;
            let rows = stmt.query_map([user_id], |r| {
                let port = r.get::<_, i64>(1)? as u16;
                Ok((r.get::<_, i64>(0)?, port as i64, Owned::Port(port)))
            })?;
            for row in rows {
                owned.push(row?);
            }
        }
        // Oldest first: created_at asc, then the stable key asc. Everything at
        // index >= cap is "newest over cap" and gets pruned.
        owned.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let cap = cap as usize;
        if owned.len() <= cap {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut removed_hosts = Vec::new();
        let mut removed_ports = Vec::new();
        for (_, _, res) in owned.into_iter().skip(cap) {
            match res {
                Owned::Host(label) => {
                    conn.execute("DELETE FROM hostnames WHERE label = ?1", [&label])?;
                    removed_hosts.push(label);
                }
                Owned::Port(port) => {
                    conn.execute("DELETE FROM tcp_ports WHERE port = ?1", [port as i64])?;
                    removed_ports.push(port);
                }
            }
        }
        Ok((removed_hosts, removed_ports))
    }

    /// Create a token for a user, returning the plaintext (shown once).
    pub fn create_token(&self, user: &str, label: Option<&str>) -> Result<String, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let id = Self::user_id(&conn, user)?;
        let token = generate_token();
        conn.execute(
            "INSERT INTO tokens (user_id, token_hash, label, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, hash_token(&token), label, Self::now()],
        )?;
        Ok(token)
    }

    pub fn list_tokens(&self, user: Option<&str>) -> Result<Vec<TokenRow>, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT t.id, u.name, t.label, t.created_at, t.revoked_at
             FROM tokens t JOIN users u ON u.id = t.user_id
             WHERE (?1 IS NULL OR u.name = ?1)
             ORDER BY t.id",
        )?;
        let rows = stmt
            .query_map([user], |r| {
                Ok(TokenRow {
                    id: r.get(0)?,
                    user: r.get(1)?,
                    label: r.get(2)?,
                    created_at: r.get(3)?,
                    revoked: r.get::<_, Option<i64>>(4)?.is_some(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn revoke_token(&self, id: i64) -> Result<bool, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            rusqlite::params![id, Self::now()],
        )?;
        Ok(n > 0)
    }

    pub fn add_hostname(&self, label: &str, user: &str) -> Result<(), RegistryError> {
        validate_label(label).map_err(|e| RegistryError::InvalidLabel(label.to_owned(), e))?;
        let conn = self.conn.lock().unwrap();
        let id = Self::user_id(&conn, user)?;
        let taken: bool = conn
            .query_row("SELECT 1 FROM hostnames WHERE label = ?1", [label], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if taken {
            return Err(RegistryError::LabelTaken(label.to_owned()));
        }
        conn.execute(
            "INSERT INTO hostnames (user_id, label, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, label, Self::now()],
        )?;
        Ok(())
    }

    pub fn list_hostnames(
        &self,
        user: Option<&str>,
    ) -> Result<Vec<(String, String)>, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT h.label, u.name FROM hostnames h JOIN users u ON u.id = h.user_id
             WHERE (?1 IS NULL OR u.name = ?1) ORDER BY h.label",
        )?;
        let rows = stmt
            .query_map([user], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn remove_hostname(&self, label: &str) -> Result<bool, RegistryError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM hostnames WHERE label = ?1", [label])? > 0)
    }

    pub fn add_port(&self, port: u16, user: &str) -> Result<(), RegistryError> {
        let conn = self.conn.lock().unwrap();
        let id = Self::user_id(&conn, user)?;
        let taken: Option<i64> = conn
            .query_row(
                "SELECT user_id FROM tcp_ports WHERE port = ?1",
                [port],
                |r| r.get(0),
            )
            .optional()?;
        if taken.is_some() {
            return Err(RegistryError::PortTaken(port));
        }
        conn.execute(
            "INSERT INTO tcp_ports (port, user_id, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![port, id, Self::now()],
        )?;
        Ok(())
    }

    pub fn list_ports(&self) -> Result<Vec<(u16, String)>, RegistryError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT p.port, u.name FROM tcp_ports p JOIN users u ON u.id = p.user_id ORDER BY p.port",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)? as u16, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn remove_port(&self, port: u16) -> Result<bool, RegistryError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM tcp_ports WHERE port = ?1", [port])? > 0)
    }

    /// Split a FQDN into its label if it sits directly under this relay's apex
    /// AND is a valid, non-reserved label. Authorization therefore fails closed
    /// for reserved/malformed labels regardless of what rows exist in the DB —
    /// defense in depth, since `validate_label` is otherwise only enforced at
    /// admin insert time.
    fn label_of(&self, fqdn: &str) -> Option<String> {
        let label = fqdn.strip_suffix(&self.suffix)?;
        if label.is_empty() || label.contains('.') {
            return None; // deeper than one level
        }
        if validate_label(label).is_err() {
            return None; // reserved or otherwise invalid
        }
        Some(label.to_owned())
    }
}

impl Authenticator for Registry {
    fn authenticate(&self, token: &str) -> Option<AuthedUser> {
        let hash = hash_token(token);
        let conn = self.conn.lock().unwrap();
        // Security rests on the 256-bit OsRng token: an attacker cannot guess one,
        // and only its SHA-256 is ever stored. The lookup matches on `token_hash`
        // over the UNIQUE index, so the row already byte-equals `hash`; the
        // `ct_eq` below is a belt-and-suspenders exact re-check, not a timing
        // mitigation (any timing oracle here would leak at most a few bytes of an
        // unguessable hash). See SECURITY_AUDIT P3-1.
        let row: (i64, String, Vec<u8>) = conn
            .query_row(
                "SELECT u.id, u.name, t.token_hash
                 FROM tokens t JOIN users u ON u.id = t.user_id
                 WHERE t.token_hash = ?1 AND t.revoked_at IS NULL",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()??;
        if row.2.ct_eq(&hash).into() {
            Some(AuthedUser {
                user_id: row.0,
                name: row.1,
            })
        } else {
            None
        }
    }

    fn owns_hostname(&self, user_id: i64, hostname: &str) -> bool {
        let Some(label) = self.label_of(hostname) else {
            return false;
        };
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM hostnames WHERE label = ?1 AND user_id = ?2",
            rusqlite::params![label, user_id],
            |_| Ok(()),
        )
        .optional()
        .map(|o| o.is_some())
        .unwrap_or(false)
    }

    fn owns_port(&self, user_id: i64, port: u16) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM tcp_ports WHERE port = ?1 AND user_id = ?2",
            rusqlite::params![port, user_id],
            |_| Ok(()),
        )
        .optional()
        .map(|o| o.is_some())
        .unwrap_or(false)
    }

    fn claim_hostname(&self, user_id: i64, hostname: &str, max: Option<i64>) -> ClaimOutcome {
        // Fail closed on anything that isn't a valid, non-reserved label under
        // this relay's apex (wrong apex, too deep, reserved, malformed) — the
        // same gate `owns_hostname` applies via `label_of`.
        let Some(label) = self.label_of(hostname) else {
            return ClaimOutcome::Invalid("not a valid hostname under this relay");
        };
        match self.claim_label_capped(user_id, &label, max) {
            Ok(_) => ClaimOutcome::Owned,
            Err(RegistryError::LabelTaken(_)) => ClaimOutcome::Taken,
            Err(RegistryError::CapExceeded) => ClaimOutcome::CapExceeded,
            Err(RegistryError::InvalidLabel(_, why)) => ClaimOutcome::Invalid(why),
            Err(e) => {
                tracing::error!(hostname, error = %e, "claim_hostname storage error");
                ClaimOutcome::Error
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn reg() -> Registry {
        Registry::open_in_memory("ethertunnel.com").unwrap()
    }

    #[test]
    fn label_validation() {
        assert!(validate_label("demo").is_ok());
        assert!(validate_label("my-app-2").is_ok());
        assert!(validate_label("").is_err());
        assert!(validate_label("-bad").is_err());
        assert!(validate_label("bad-").is_err());
        assert!(validate_label("UPPER").is_err());
        assert!(validate_label("has.dot").is_err());
        assert!(validate_label("connect").is_err()); // reserved
    }

    #[test]
    fn token_lifecycle_and_auth() {
        let r = reg();
        r.add_user("mat").unwrap();
        let token = r.create_token("mat", Some("laptop")).unwrap();
        assert!(token.starts_with("etun_"));

        let user = r.authenticate(&token).expect("token authenticates");
        assert_eq!(user.name, "mat");
        assert!(r.authenticate("etun_wrong").is_none());

        // Revoke kills it.
        let id = r.list_tokens(Some("mat")).unwrap()[0].id;
        assert!(r.revoke_token(id).unwrap());
        assert!(r.authenticate(&token).is_none());
    }

    #[test]
    fn hostname_ownership_by_fqdn() {
        let r = reg();
        let uid = r.add_user("mat").unwrap();
        let other = r.add_user("eve").unwrap();
        r.add_hostname("demo", "mat").unwrap();

        assert!(r.owns_hostname(uid, "demo.ethertunnel.com"));
        assert!(!r.owns_hostname(other, "demo.ethertunnel.com")); // not eve's
        assert!(!r.owns_hostname(uid, "demo.evil.com")); // wrong apex
        assert!(!r.owns_hostname(uid, "a.b.ethertunnel.com")); // too deep
        assert!(!r.owns_hostname(uid, "missing.ethertunnel.com"));

        // Duplicate label is rejected regardless of owner.
        assert!(matches!(
            r.add_hostname("demo", "eve"),
            Err(RegistryError::LabelTaken(_))
        ));
    }

    #[test]
    fn port_reservation() {
        let r = reg();
        let uid = r.add_user("mat").unwrap();
        r.add_port(20000, "mat").unwrap();
        assert!(r.owns_port(uid, 20000));
        assert!(matches!(
            r.add_port(20000, "mat"),
            Err(RegistryError::PortTaken(20000))
        ));
    }

    #[test]
    fn provision_user_token_is_idempotent_on_name() {
        let r = reg();
        // First provision creates the user.
        let (t1, created1) = r.provision_user_token("acct_abc").unwrap();
        assert!(created1, "first provision creates the user");
        assert!(t1.starts_with("etun_"));
        assert!(r.authenticate(&t1).is_some());

        // Second provision against the same ref reuses the user and mints a new
        // token (both tokens authenticate to the same user).
        let (t2, created2) = r.provision_user_token("acct_abc").unwrap();
        assert!(!created2, "second provision reuses the existing user");
        assert_ne!(t1, t2);
        assert_eq!(
            r.authenticate(&t1).unwrap().user_id,
            r.authenticate(&t2).unwrap().user_id
        );
        // Exactly one user row exists.
        assert_eq!(r.list_users().unwrap().len(), 1);
    }

    #[test]
    fn rotate_user_token_revokes_all_previous_tokens() {
        let r = reg();
        // Give the account two valid tokens the way the live system would: an
        // initial provision plus a webhook-retry / earlier-recovery addition.
        let (old1, _) = r.provision_user_token("acct_rot").unwrap();
        let (old2, _) = r.provision_user_token("acct_rot").unwrap();
        assert!(r.authenticate(&old1).is_some());
        assert!(r.authenticate(&old2).is_some());

        // Rotate: both prior tokens must die, exactly one fresh token is minted.
        let (fresh, revoked) = r.rotate_user_token("acct_rot").unwrap();
        assert_eq!(revoked, 2, "both previously-valid tokens are revoked");
        assert_ne!(fresh, old1);
        assert_ne!(fresh, old2);
        assert!(
            r.authenticate(&old1).is_none(),
            "an old token must fail auth after rotate"
        );
        assert!(r.authenticate(&old2).is_none());
        assert!(
            r.authenticate(&fresh).is_some(),
            "the rotated token authenticates"
        );
        // Still a single account; no duplicate user created.
        assert_eq!(r.list_users().unwrap().len(), 1);

        // Rotating again revokes the previous fresh token (count = 1) and issues
        // a new one; the just-superseded token stops working.
        let (fresh2, revoked2) = r.rotate_user_token("acct_rot").unwrap();
        assert_eq!(revoked2, 1);
        assert!(r.authenticate(&fresh).is_none());
        assert!(r.authenticate(&fresh2).is_some());
    }

    #[test]
    fn rotate_user_token_creates_account_if_absent() {
        let r = reg();
        // Recovery converges on "exactly one valid token" even for an account the
        // relay has never provisioned: rotate creates it, revoking nothing.
        let (tok, revoked) = r.rotate_user_token("acct_new").unwrap();
        assert_eq!(revoked, 0);
        assert!(r.authenticate(&tok).is_some());
        assert_eq!(r.list_users().unwrap().len(), 1);
    }

    #[test]
    fn release_user_hostnames_returns_and_empties() {
        let r = reg();
        let uid = r.add_user("acct_x").unwrap();
        r.add_hostname("alpha", "acct_x").unwrap();
        r.add_hostname("beta", "acct_x").unwrap();
        r.add_port(20001, "acct_x").unwrap();

        // Without releasing ports.
        let (mut hosts, ports) = r.release_user_hostnames("acct_x", false).unwrap();
        hosts.sort();
        assert_eq!(hosts, vec!["alpha".to_string(), "beta".to_string()]);
        assert!(ports.is_empty());
        assert!(r.list_hostnames(Some("acct_x")).unwrap().is_empty());
        // The user and the port survive.
        assert!(r.owns_port(uid, 20001));

        // Releasing again is a no-op (empty), and a label freed is reclaimable.
        let (hosts2, _) = r.release_user_hostnames("acct_x", true).unwrap();
        assert!(hosts2.is_empty());
        assert!(!r.owns_port(uid, 20001));

        // Unknown user → NoSuchUser (reaper treats as already released).
        assert!(matches!(
            r.release_user_hostnames("nobody", true),
            Err(RegistryError::NoSuchUser(_))
        ));
    }

    #[test]
    fn claim_label_free_own_taken() {
        let r = reg();
        let mat = r.add_user("acct_mat").unwrap();
        let eve = r.add_user("acct_eve").unwrap();

        // Free → registered.
        assert!(r.claim_label(mat, "myapp").unwrap());
        assert!(r.owns_hostname(mat, "myapp.ethertunnel.com"));

        // Already mine → idempotent false, no error.
        assert!(!r.claim_label(mat, "myapp").unwrap());

        // Owned by someone else → LabelTaken.
        assert!(matches!(
            r.claim_label(eve, "myapp"),
            Err(RegistryError::LabelTaken(_))
        ));

        // Reserved/invalid → InvalidLabel, nothing registered.
        assert!(matches!(
            r.claim_label(mat, "connect"),
            Err(RegistryError::InvalidLabel(_, _))
        ));
        assert!(matches!(
            r.claim_label(mat, "Bad_Label"),
            Err(RegistryError::InvalidLabel(_, _))
        ));
    }

    #[test]
    fn claim_label_capped_enforces_owned_count() {
        let r = reg();
        let mat = r.add_user("acct_mat").unwrap();

        // Cap of 2. Two fresh labels are fine and bring owned count to 2.
        assert!(r.claim_label_capped(mat, "one", Some(2)).unwrap());
        assert!(r.claim_label_capped(mat, "two", Some(2)).unwrap());
        assert_eq!(r.count_owned_resources(mat).unwrap(), 2);

        // (a) At the cap, a NEW free label is refused with CapExceeded and is
        // NOT registered (no leaked row).
        assert!(matches!(
            r.claim_label_capped(mat, "three", Some(2)),
            Err(RegistryError::CapExceeded)
        ));
        assert!(!r.owns_hostname(mat, "three.ethertunnel.com"));
        assert_eq!(r.count_owned_resources(mat).unwrap(), 2);

        // (b) The same user can still re-claim a label they already own, even at
        // the cap — idempotent no-op, no error.
        assert!(!r.claim_label_capped(mat, "one", Some(2)).unwrap());

        // (c) After releasing a hostname the user is back under cap and can claim
        // a new one again.
        assert!(r.remove_hostname("two").unwrap());
        assert_eq!(r.count_owned_resources(mat).unwrap(), 1);
        assert!(r.claim_label_capped(mat, "three", Some(2)).unwrap());
        assert_eq!(r.count_owned_resources(mat).unwrap(), 2);
    }

    #[test]
    fn claim_label_capped_max_none_is_uncapped() {
        let r = reg();
        let mat = r.add_user("acct_mat").unwrap();
        // (d) max=None never refuses on cap grounds, regardless of owned count.
        for label in ["a", "b", "c", "d", "e"] {
            assert!(r.claim_label_capped(mat, label, None).unwrap());
        }
        assert_eq!(r.count_owned_resources(mat).unwrap(), 5);
    }

    #[test]
    fn count_owned_resources_counts_hostnames_and_ports_not_tokens() {
        let r = reg();
        let mat = r.add_user("acct_mat").unwrap();
        assert_eq!(r.count_owned_resources(mat).unwrap(), 0);
        // Tokens do not count toward the owned-resource cap.
        let _ = r.create_token("acct_mat", Some("laptop")).unwrap();
        assert_eq!(r.count_owned_resources(mat).unwrap(), 0);
        // Hostnames and ports both count.
        r.add_hostname("alpha", "acct_mat").unwrap();
        r.add_port(20002, "acct_mat").unwrap();
        assert_eq!(r.count_owned_resources(mat).unwrap(), 2);
    }

    /// P1-D: prune_owned_to_cap keeps the OLDEST `cap` owned resources (by
    /// created_at) and deletes the newest over the cap, returning what it removed.
    /// We force distinct created_at values by writing them directly so ordering is
    /// deterministic regardless of wall-clock granularity.
    #[test]
    fn prune_owned_to_cap_keeps_oldest_drops_newest() {
        let r = reg();
        let mat = r.add_user("mat").unwrap();
        // Three hostnames + one port with explicit, increasing created_at.
        {
            let conn = r.conn.lock().unwrap();
            for (label, ts) in [("oldest", 100), ("middle", 200), ("newest", 300)] {
                conn.execute(
                    "INSERT INTO hostnames (user_id, label, created_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![mat, label, ts],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO tcp_ports (port, user_id, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![20500i64, mat, 250i64],
            )
            .unwrap();
        }
        assert_eq!(r.count_owned_resources(mat).unwrap(), 4);

        // Cap to 2: keep the two oldest (oldest@100, middle@200); drop port@250
        // and newest@300.
        let (hosts, ports) = r.prune_owned_to_cap(mat, 2).unwrap();
        let mut removed = hosts.clone();
        removed.sort();
        assert_eq!(removed, vec!["newest".to_string()]);
        assert_eq!(ports, vec![20500]);
        assert_eq!(r.count_owned_resources(mat).unwrap(), 2);
        assert!(r.owns_hostname(mat, "oldest.ethertunnel.com"));
        assert!(r.owns_hostname(mat, "middle.ethertunnel.com"));
        assert!(!r.owns_hostname(mat, "newest.ethertunnel.com"));
        assert!(!r.owns_port(mat, 20500));

        // Already within cap => no-op.
        let (h2, p2) = r.prune_owned_to_cap(mat, 5).unwrap();
        assert!(h2.is_empty() && p2.is_empty());

        // Cap 0 (deny-all) prunes everything remaining.
        let (h3, p3) = r.prune_owned_to_cap(mat, 0).unwrap();
        assert_eq!(h3.len() + p3.len(), 2);
        assert_eq!(r.count_owned_resources(mat).unwrap(), 0);
    }

    #[test]
    fn lookup_user_id_resolves_or_none() {
        let r = reg();
        let mat = r.add_user("acct_mat").unwrap();
        assert_eq!(r.lookup_user_id("acct_mat").unwrap(), Some(mat));
        assert_eq!(r.lookup_user_id("ghost").unwrap(), None);
    }

    #[test]
    fn remove_user_guards_owned_resources() {
        let r = reg();
        r.add_user("mat").unwrap();
        r.add_hostname("demo", "mat").unwrap();
        assert!(matches!(
            r.remove_user("mat", false),
            Err(RegistryError::UserNotEmpty(_))
        ));
        assert!(r.remove_user("mat", true).is_ok());
    }

    /// A unique temp path under the system temp dir (no tempfile dep available).
    /// Only the `#[cfg(unix)]` permission tests use this, so gate it too — else
    /// it's dead code on Windows and `-D warnings` fails the build.
    #[cfg(unix)]
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("etun-test-{tag}-{pid}-{n}.db"))
    }

    #[cfg(unix)]
    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        for ext in ["-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(ext);
            let _ = std::fs::remove_file(std::path::Path::new(&p));
        }
    }

    /// On-disk registry DB (and its WAL/SHM siblings) must be chmodded 0600 after
    /// open, so token hashes + tenant topology are never world-readable. (finding 12)
    ///
    /// We pin `umask` to 0o022 for the duration of the test so newly created
    /// files would default to 0o644 (world-readable) WITHOUT the chmod — that is
    /// what gives this test its discriminating power. If a developer's ambient
    /// umask were 0o077, files would land at 0o600 on their own and the test
    /// could pass even with the production chmod removed; setting umask here
    /// removes that ambiguity. We also assert the WAL/SHM siblings actually
    /// EXIST (journal_mode=WAL + a forced write materializes both) rather than
    /// silently skipping them.
    #[cfg(unix)]
    #[test]
    fn open_chmods_db_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: umask is a process-global; this test is the sole writer of the
        // value during its run and restores it before returning. Cargo runs unit
        // tests in threads of one process, so keep the window tiny.
        let prev_umask = unsafe { libc::umask(0o022) };

        let path = temp_db_path("registry");
        cleanup(&path);
        let r = Registry::open(&path, "ethertunnel.com").unwrap();
        // Force a write so the WAL (and its SHM index) actually materialize.
        r.add_user("mat").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "registry.db must be 0600, was {mode:o}");
        // Both siblings must exist under WAL mode after a write, and both must be
        // 0600 — no silent skip.
        for ext in ["-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(ext);
            let sib = std::path::Path::new(&p);
            let meta = std::fs::metadata(sib)
                .unwrap_or_else(|e| panic!("expected {} to exist: {e}", sib.display()));
            let m = meta.permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{} must be 0600, was {m:o}", sib.display());
        }
        drop(r);
        cleanup(&path);

        // Restore the ambient umask for any sibling tests in this process.
        unsafe { libc::umask(prev_umask) };
    }

    /// The in-memory variant has no file: opening it must not attempt a chmod or
    /// panic. (guards against calling the helper on the :memory: path)
    #[test]
    fn open_in_memory_does_not_chmod_or_panic() {
        let r = Registry::open_in_memory("ethertunnel.com").unwrap();
        r.add_user("mat").unwrap();
        assert_eq!(r.list_users().unwrap().len(), 1);
    }

    /// tighten_sqlite_perms is best-effort: a path whose -wal/-shm don't exist
    /// (and even a missing main file) must not error or panic.
    #[cfg(unix)]
    #[test]
    fn tighten_sqlite_perms_is_best_effort() {
        let missing = temp_db_path("nonexistent");
        cleanup(&missing);
        // Must not panic even though nothing exists at this path.
        super::tighten_sqlite_perms(&missing);
    }

    /// The auditor's exact concurrent-claim PoC, driven against the AUTHORITATIVE
    /// enforcement layer (`claim_label_capped`, not the racy router pre-check).
    /// 16 threads sharing one Registry each race a DISTINCT free label under a
    /// Barrier; the owned-row count must equal CAP exactly (never exceed it), and
    /// exactly CAP claims succeed. Pins the max_tunnels TOCTOU closed. (finding f7)
    #[test]
    fn concurrent_claims_never_exceed_cap() {
        use std::sync::Barrier;
        const THREADS: usize = 16;
        const CAP: i64 = 5;

        let r = Arc::new(Registry::open_in_memory("ethertunnel.com").unwrap());
        let mat = r.add_user("mat").unwrap();
        let barrier = Arc::new(Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let r = r.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    r.claim_label_capped(mat, &format!("h{i}"), Some(CAP))
                })
            })
            .collect();

        let mut granted = 0;
        let mut cap_exceeded = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(true) => granted += 1,
                Err(RegistryError::CapExceeded) => cap_exceeded += 1,
                other => panic!("unexpected claim outcome: {other:?}"),
            }
        }
        assert_eq!(granted as i64, CAP, "exactly CAP claims must succeed");
        assert_eq!(cap_exceeded, THREADS - CAP as usize, "the rest hit the cap");
        assert_eq!(
            r.count_owned_resources(mat).unwrap(),
            CAP,
            "owned-row count must equal CAP exactly, never exceed it"
        );
    }
}
