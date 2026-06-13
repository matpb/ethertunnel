//! The runtime status snapshot the daemon publishes for `etun status`.
//!
//! A lightweight stand-in for a full IPC channel: `up` writes this JSON file
//! atomically whenever its state changes, and `status` reads it. Good enough to
//! answer "is my tunnel up and what's it serving?" without a socket protocol.

use serde::{Deserialize, Serialize};

use crate::paths;
use crate::supervisor::{ConnState, DaemonStatus};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// One of `connecting`, `connected`, `auth_failed`.
    pub state: String,
    pub relay: String,
    pub granted_hostnames: Vec<String>,
    pub granted_ports: Vec<u16>,
    pub reconnects: u32,
    /// PID of the daemon that wrote this snapshot.
    pub pid: u32,
}

impl StatusSnapshot {
    pub fn from_daemon(relay: &str, s: &DaemonStatus) -> Self {
        let state = match s.state {
            ConnState::Connecting => "connecting",
            ConnState::Connected => "connected",
            ConnState::AuthFailed => "auth_failed",
        };
        Self {
            state: state.to_owned(),
            relay: relay.to_owned(),
            granted_hostnames: s.granted_hostnames.clone(),
            granted_ports: s.granted_ports.clone(),
            reconnects: s.reconnects,
            pid: std::process::id(),
        }
    }

    /// Write the snapshot to the status file (best-effort, atomic).
    pub fn write(&self) -> anyhow::Result<()> {
        let path = paths::status_file()?;
        let json = serde_json::to_vec_pretty(self)?;
        paths::atomic_write(&path, &json, 0o644)
    }

    /// Read the last published snapshot, if any.
    pub fn read() -> anyhow::Result<Option<Self>> {
        let path = paths::status_file()?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }
}
