//! High-level implementations of the client subcommands. The CLI layer just
//! parses arguments and calls these, so the behaviour is testable and the binary
//! stays a thin dispatcher.

use std::io::{IsTerminal, Read};

use anyhow::{bail, Context};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config::{FileConfig, Protocol, TunnelConfig};
use crate::status::StatusSnapshot;
use crate::supervisor::{run_supervisor, ConnState, DaemonStatus};
use crate::{creds, login};

/// Hosted relay used when neither --relay nor a configured relay is present.
/// Baking this here makes `etun login` work out-of-the-box against the hosted
/// service; self-hosters override it by passing --relay <their-domain> once
/// (it is then persisted to config and reused).
pub const DEFAULT_RELAY: &str = "ethertunnel.com";

/// Resolve the relay to use: an explicit `--relay` wins, then a non-empty
/// configured relay, and finally [`DEFAULT_RELAY`] as the zero-config fallback.
fn resolve_relay(arg: Option<String>, configured: &str) -> String {
    arg.or_else(|| (!configured.is_empty()).then(|| configured.to_owned()))
        .unwrap_or_else(|| DEFAULT_RELAY.to_owned())
}

/// `etun login` — verify and store a bearer token for a relay.
pub async fn login(relay: Option<String>, token_stdin: bool) -> anyhow::Result<()> {
    let mut cfg = FileConfig::load()?;
    let used_default = relay.is_none() && cfg.relay.is_empty();
    let relay = resolve_relay(relay, &cfg.relay);

    let token = if token_stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading token from stdin")?;
        s.trim().to_owned()
    } else if let Ok(env) = std::env::var("ETUN_TOKEN") {
        env
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Paste your EtherTunnel token: ")
            .context("reading token from terminal")?
            .trim()
            .to_owned()
    } else {
        bail!("provide the token via --token-stdin or the ETUN_TOKEN env var");
    };
    if token.is_empty() {
        bail!("empty token");
    }

    if used_default {
        eprintln!("No relay set; defaulting to ethertunnel.com. Self-hosters: etun login --relay <your-domain>.");
    }
    println!("Verifying token against connect.{relay} ...");
    let ok = login::verify(&relay, &token, &cfg.trust_mode()?).await?;
    creds::store(&relay, &token)?;
    if cfg.relay.is_empty() {
        cfg.relay = relay.clone();
        cfg.save()?;
    }
    println!(
        "Logged in to {relay} (session {}, protocol {}). Token stored.",
        ok.session_id, ok.proto
    );
    Ok(())
}

/// `etun add` — append (or replace) a tunnel in the config.
pub fn add(
    name: String,
    port: u16,
    hostname: Option<String>,
    tcp_public_port: Option<u16>,
    local_host: Option<String>,
) -> anyhow::Result<()> {
    let mut cfg = FileConfig::load()?;
    let protocol = if tcp_public_port.is_some() {
        Protocol::Tcp
    } else {
        Protocol::Http
    };
    let local_host = local_host.unwrap_or_else(|| "127.0.0.1".to_owned());
    let tunnel = TunnelConfig {
        name: name.clone(),
        port,
        local_host: local_host.clone(),
        protocol,
        hostname,
        public_port: tcp_public_port,
    };
    cfg.tunnels.retain(|t| t.name != name);
    cfg.tunnels.push(tunnel);
    cfg.save()?;
    println!("added tunnel `{name}` -> {local_host}:{port}");
    Ok(())
}

/// `etun list` — show configured tunnels.
pub fn list(json: bool) -> anyhow::Result<()> {
    let cfg = FileConfig::load()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cfg.tunnels)?);
        return Ok(());
    }
    if cfg.tunnels.is_empty() {
        println!("no tunnels configured (use `etun add`)");
        return Ok(());
    }
    for t in &cfg.tunnels {
        match t.protocol {
            Protocol::Http => println!(
                "{:<14} https://{}  ->  {}:{}",
                t.name,
                cfg.fqdn(t),
                t.local_host,
                t.port
            ),
            Protocol::Tcp => println!(
                "{:<14} tcp {}:{}  ->  {}:{}",
                t.name,
                cfg.relay,
                t.public_port.unwrap_or(0),
                t.local_host,
                t.port
            ),
        }
    }
    Ok(())
}

/// `etun remove` — delete a tunnel by name.
pub fn remove(name: String) -> anyhow::Result<()> {
    let mut cfg = FileConfig::load()?;
    let before = cfg.tunnels.len();
    cfg.tunnels.retain(|t| t.name != name);
    if cfg.tunnels.len() == before {
        bail!("no such tunnel: {name}");
    }
    cfg.save()?;
    println!("removed tunnel `{name}`");
    Ok(())
}

/// `etun status` — print the last published daemon snapshot.
pub fn status(json: bool) -> anyhow::Result<()> {
    match StatusSnapshot::read()? {
        None => {
            println!("no running daemon (status file absent)");
            Ok(())
        }
        Some(s) if json => {
            println!("{}", serde_json::to_string_pretty(&s)?);
            Ok(())
        }
        Some(s) => {
            println!("state:      {}", s.state);
            println!("relay:      {}", s.relay);
            println!("pid:        {}", s.pid);
            println!("reconnects: {}", s.reconnects);
            for h in &s.granted_hostnames {
                println!("  https://{h}");
            }
            for p in &s.granted_ports {
                println!("  tcp {}:{p}", s.relay);
            }
            Ok(())
        }
    }
}

/// `etun logs` — show the daemon's logs from wherever this platform routes them.
pub async fn logs(follow: bool) -> anyhow::Result<()> {
    let dir = crate::paths::log_dir()?;
    // The daily appender writes `etun.log.YYYY-MM-DD`; pick the newest.
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(crate::paths::log_file_basename()))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let Some(latest) = files.last().cloned() else {
        println!(
            "no log files in {}.\n\
             If you installed a systemd service, logs go to journald:\n  \
             journalctl --user -u etun -f",
            dir.display()
        );
        return Ok(());
    };

    // Print existing contents, then optionally follow appended bytes.
    let mut pos = 0u64;
    pos += print_from(&latest, pos)?;
    if !follow {
        return Ok(());
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        pos += print_from(&latest, pos)?;
    }
}

/// Print bytes of `path` from byte offset `from`; return how many were printed.
fn print_from(path: &std::path::Path, from: u64) -> anyhow::Result<u64> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len <= from {
        return Ok(0);
    }
    f.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    std::io::stdout().write_all(&buf)?;
    std::io::stdout().flush()?;
    Ok(buf.len() as u64)
}

/// `etun up` — run the daemon in the foreground until interrupted.
pub async fn up() -> anyhow::Result<()> {
    let cfg = FileConfig::load()?;
    let token =
        creds::resolve(&cfg.relay)?.context("no token for this relay; run `etun login` first")?;
    let trust = cfg.trust_mode()?;
    let client_cfg = cfg.to_client_config(token, trust)?;

    let (tx, mut rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    let relay = cfg.relay.clone();

    let supervisor = {
        let cancel = cancel.clone();
        tokio::spawn(run_supervisor(client_cfg, tx, cancel))
    };

    // Publish status + print transitions until shutdown.
    let publisher = {
        let relay = relay.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut last = ConnState::Connecting;
            loop {
                let snap = StatusSnapshot::from_daemon(&relay, &rx.borrow());
                let _ = snap.write();
                if snap.state == "connected" && last != ConnState::Connected {
                    for h in &snap.granted_hostnames {
                        println!("  tunnel up:  https://{h}");
                    }
                    for p in &snap.granted_ports {
                        println!("  tunnel up:  tcp {relay}:{p}");
                    }
                    last = ConnState::Connected;
                } else if snap.state == "auth_failed" {
                    eprintln!("  authentication failed; check your token (`etun login`)");
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    changed = rx.changed() => {
                        if changed.is_err() { break; }
                    }
                }
            }
        })
    };

    println!("Connecting to {relay} ... (Ctrl-C to stop)");
    tokio::signal::ctrl_c().await.ok();
    println!("\nShutting down ...");
    cancel.cancel();
    let _ = supervisor.await;
    publisher.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_relay_is_hosted_domain() {
        assert_eq!(DEFAULT_RELAY, "ethertunnel.com");
    }

    #[test]
    fn relay_precedence_arg_beats_config_and_default() {
        // Explicit --relay always wins.
        assert_eq!(
            resolve_relay(Some("arg.example".to_owned()), "cfg.example"),
            "arg.example"
        );
        // A configured relay beats the baked-in default.
        assert_eq!(resolve_relay(None, "cfg.example"), "cfg.example");
        // Nothing set falls back to the hosted default.
        assert_eq!(resolve_relay(None, ""), DEFAULT_RELAY);
    }
}
