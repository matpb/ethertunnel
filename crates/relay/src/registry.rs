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

use crate::auth::{AuthedUser, Authenticator};

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

impl Registry {
    /// Open (creating if needed) the registry at `path` for `domain`.
    pub fn open(path: impl AsRef<Path>, domain: &str) -> Result<Self, RegistryError> {
        let conn = Connection::open(path)?;
        Self::init(conn, domain)
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
