//! High-level implementations of the client subcommands. The CLI layer just
//! parses arguments and calls these, so the behaviour is testable and the binary
//! stays a thin dispatcher.

use std::io::Read;

use anyhow::{bail, Context};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config::{FileConfig, Protocol, TunnelConfig};
use crate::status::StatusSnapshot;
use crate::supervisor::{run_supervisor, ConnState, DaemonStatus};
use crate::{creds, login};

/// `etun login` — verify and store a bearer token for a relay.
pub async fn login(relay: Option<String>, token_stdin: bool) -> anyhow::Result<()> {
    let mut cfg = FileConfig::load()?;
    let relay = relay
        .or_else(|| (!cfg.relay.is_empty()).then(|| cfg.relay.clone()))
        .context("no relay set; pass --relay <domain>")?;

    let token = if token_stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading token from stdin")?;
        s.trim().to_owned()
    } else if let Ok(env) = std::env::var("ETUN_TOKEN") {
        env
    } else {
        bail!("provide the token via --token-stdin or the ETUN_TOKEN env var");
    };
    if token.is_empty() {
        bail!("empty token");
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

/// `etun up` — run the daemon in the foreground until interrupted.
pub async fn up() -> anyhow::Result<()> {
    let cfg = FileConfig::load()?;
    let token = creds::resolve(&cfg.relay)?
        .context("no token for this relay; run `etun login` first")?;
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
