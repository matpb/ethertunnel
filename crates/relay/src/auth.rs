//! Authentication and ownership checks for the relay.
//!
//! The session layer depends only on this trait, not on how credentials are
//! stored. M1 ships an in-memory implementation; M4 swaps in the SQLite-backed
//! registry behind the same interface. Methods are synchronous: they run only
//! at connect/claim time (never on the data path), so the cost is negligible.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// An authenticated user, resolved from a bearer token.
#[derive(Clone, Debug)]
pub struct AuthedUser {
    pub user_id: i64,
    pub name: String,
}

/// Outcome of an attempt to claim (self-register) a hostname under this relay's
/// apex. Returned by [`Authenticator::claim_hostname`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The label is now owned by this user — either it was free and we
    /// registered it, or it was already theirs (idempotent).
    Owned,
    /// The label is owned by a *different* user; the claim is refused.
    Taken,
    /// The hostname is not a valid claimable label under this relay (wrong apex,
    /// too deep, reserved, or malformed). The string is a human-readable reason.
    Invalid(&'static str),
    /// A storage error occurred; the claim could not be completed.
    Error,
}

/// Resolves tokens to users and answers ownership questions for hostnames and
/// TCP ports. Implementations must be cheap and side-effect free.
pub trait Authenticator: Send + Sync + 'static {
    /// Resolve a bearer token to a user, or `None` if it is unknown/revoked.
    /// Must not distinguish those cases to callers (no auth oracle).
    fn authenticate(&self, token: &str) -> Option<AuthedUser>;

    /// Whether `user_id` may claim the given fully-qualified hostname.
    fn owns_hostname(&self, user_id: i64, hostname: &str) -> bool;

    /// Whether `user_id` may claim the given public TCP port.
    fn owns_port(&self, user_id: i64, port: u16) -> bool;

    /// Self-register `hostname` to `user_id` from the global label pool
    /// (first-come-first-served), or confirm the user already owns it.
    ///
    /// The default implementation preserves the legacy "labels are
    /// admin-pre-registered" behavior: it never creates a label, only reporting
    /// `Owned` for one the user already holds, `Taken` otherwise. The SQLite
    /// registry overrides this to actually claim a free label.
    fn claim_hostname(&self, user_id: i64, hostname: &str) -> ClaimOutcome {
        if self.owns_hostname(user_id, hostname) {
            ClaimOutcome::Owned
        } else {
            ClaimOutcome::Taken
        }
    }
}

/// An in-memory `Authenticator` for tests and early milestones.
///
/// Stores fully-qualified hostnames directly (the SQLite registry in M4 will
/// store labels and compose FQDNs). Interior-mutable so tests can register
/// users after construction.
#[derive(Default)]
pub struct MemoryAuth {
    inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    next_user_id: i64,
    tokens: HashMap<String, i64>,             // token -> user_id
    users: HashMap<i64, String>,              // user_id -> name
    hostnames: HashMap<i64, HashSet<String>>, // user_id -> FQDNs
    ports: HashMap<i64, HashSet<u16>>,        // user_id -> ports
}

impl MemoryAuth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a user with a bearer token and return its id.
    pub fn add_user(&self, name: &str, token: &str) -> i64 {
        let mut g = self.inner.lock().unwrap();
        g.next_user_id += 1;
        let id = g.next_user_id;
        g.users.insert(id, name.to_owned());
        g.tokens.insert(token.to_owned(), id);
        id
    }

    /// Grant ownership of a fully-qualified hostname to a user.
    pub fn grant_hostname(&self, user_id: i64, hostname: &str) {
        self.inner
            .lock()
            .unwrap()
            .hostnames
            .entry(user_id)
            .or_default()
            .insert(hostname.to_owned());
    }

    /// Grant ownership of a public TCP port to a user.
    pub fn grant_port(&self, user_id: i64, port: u16) {
        self.inner
            .lock()
            .unwrap()
            .ports
            .entry(user_id)
            .or_default()
            .insert(port);
    }
}

impl Authenticator for MemoryAuth {
    fn authenticate(&self, token: &str) -> Option<AuthedUser> {
        let g = self.inner.lock().unwrap();
        let user_id = *g.tokens.get(token)?;
        let name = g.users.get(&user_id)?.clone();
        Some(AuthedUser { user_id, name })
    }

    fn owns_hostname(&self, user_id: i64, hostname: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .hostnames
            .get(&user_id)
            .is_some_and(|s| s.contains(hostname))
    }

    fn owns_port(&self, user_id: i64, port: u16) -> bool {
        self.inner
            .lock()
            .unwrap()
            .ports
            .get(&user_id)
            .is_some_and(|s| s.contains(&port))
    }

    fn claim_hostname(&self, user_id: i64, hostname: &str) -> ClaimOutcome {
        let mut g = self.inner.lock().unwrap();
        // Owned by someone? Decide based on who.
        let owner = g
            .hostnames
            .iter()
            .find(|(_, set)| set.contains(hostname))
            .map(|(uid, _)| *uid);
        match owner {
            Some(uid) if uid == user_id => ClaimOutcome::Owned,
            Some(_) => ClaimOutcome::Taken,
            None => {
                g.hostnames
                    .entry(user_id)
                    .or_default()
                    .insert(hostname.to_owned());
                ClaimOutcome::Owned
            }
        }
    }
}
