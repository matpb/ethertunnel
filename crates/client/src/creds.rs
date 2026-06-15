//! Bearer-token storage, kept apart from the shareable config.
//!
//! Tokens live in `credentials.toml` (0600 on unix), keyed by relay host so one
//! machine can hold credentials for several relays. `ETUN_TOKEN_FILE` (a path,
//! used by `--system` services via systemd `LoadCredential`) takes precedence
//! over `ETUN_TOKEN` (an inline value, handy for CI), which in turn overrides
//! the file.

use std::collections::BTreeMap;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CredFile {
    #[serde(default)]
    tokens: BTreeMap<String, String>,
}

impl CredFile {
    fn load() -> anyhow::Result<Self> {
        let path = paths::credentials_file()?;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }

    fn save(&self) -> anyhow::Result<()> {
        let path = paths::credentials_file()?;
        let text = toml::to_string_pretty(self).context("serializing credentials")?;
        paths::atomic_write(&path, text.as_bytes(), 0o600)
    }
}

/// Store (or replace) the token for `relay`.
pub fn store(relay: &str, token: &str) -> anyhow::Result<()> {
    let mut file = CredFile::load()?;
    file.tokens.insert(relay.to_owned(), token.to_owned());
    file.save()
}

/// Resolve the token for `relay`: `ETUN_TOKEN_FILE` (path) wins, then the
/// `ETUN_TOKEN` env value, else the file keyed by relay.
pub fn resolve(relay: &str) -> anyhow::Result<Option<String>> {
    if let Ok(p) = std::env::var("ETUN_TOKEN_FILE") {
        if !p.is_empty() {
            if let Ok(tok) = std::fs::read_to_string(&p) {
                let tok = tok.trim();
                if !tok.is_empty() {
                    return Ok(Some(tok.to_owned()));
                }
            }
        }
    }
    if let Ok(env) = std::env::var("ETUN_TOKEN") {
        if !env.is_empty() {
            return Ok(Some(env));
        }
    }
    Ok(CredFile::load()?.tokens.get(relay).cloned())
}
