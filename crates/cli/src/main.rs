//! `etun` — the EtherTunnel binary.
//!
//! M4 wires the relay's `serve` and registry `admin` surfaces. The client-side
//! commands (`login`/`up`/`status`/`service`/`doctor`) land in M5–M7.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use ethertunnel_relay::config::Config;
use ethertunnel_relay::registry::Registry;
use ethertunnel_relay::{serve, Router, SessionCtx};

#[derive(Parser)]
#[command(name = "etun", version, about = "Self-hosted reverse tunnels")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay server.
    Serve {
        /// Path to relay.toml.
        #[arg(long, default_value = "/etc/ethertunnel/relay.toml")]
        config: PathBuf,
        /// Validate config + database and exit.
        #[arg(long)]
        check: bool,
    },
    /// Administer the relay registry (users, tokens, hostnames, ports).
    Admin {
        /// Load db path + domain from this relay.toml.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Registry database path (overrides --config).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Relay base domain (overrides --config).
        #[arg(long)]
        domain: Option<String>,
        #[command(subcommand)]
        action: AdminAction,
    },
}

#[derive(Subcommand)]
enum AdminAction {
    /// Manage users.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage bearer tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Manage owned hostnames (labels below the apex).
    Hostname {
        #[command(subcommand)]
        cmd: HostnameCmd,
    },
    /// Manage reserved TCP ports.
    Port {
        #[command(subcommand)]
        cmd: PortCmd,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    Add {
        name: String,
    },
    Ls,
    Rm {
        name: String,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    Create {
        #[arg(long)]
        user: String,
        #[arg(long)]
        label: Option<String>,
    },
    Ls {
        #[arg(long)]
        user: Option<String>,
    },
    Revoke {
        id: i64,
    },
}

#[derive(Subcommand)]
enum HostnameCmd {
    Add {
        label: String,
        #[arg(long)]
        user: String,
    },
    Ls {
        #[arg(long)]
        user: Option<String>,
    },
    Rm {
        label: String,
    },
}

#[derive(Subcommand)]
enum PortCmd {
    Add {
        port: u16,
        #[arg(long)]
        user: String,
    },
    Ls,
    Rm {
        port: u16,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config, check } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_serve(config, check))
        }
        Command::Admin {
            config,
            db,
            domain,
            action,
        } => run_admin(config, db, domain, action),
    }
}

async fn run_serve(config_path: PathBuf, check: bool) -> anyhow::Result<()> {
    let config = Config::load(&config_path)?;
    let registry = Registry::open(&config.registry.db_path, &config.server.domain)
        .context("opening registry database")?;
    registry
        .integrity_check()
        .context("registry integrity check failed")?;

    if check {
        println!(
            "config OK: domain={}, db={}",
            config.server.domain,
            config.registry.db_path.display()
        );
        return Ok(());
    }

    let ctx = SessionCtx::new(
        Arc::new(Router::new()),
        Arc::new(registry),
        env!("CARGO_PKG_VERSION").to_owned(),
    );
    let handle = serve(Arc::new(config), ctx).await?;
    tracing::info!(addr = %handle.local_addr, "relay running; press Ctrl-C to stop");

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    handle.shutdown();
    Ok(())
}

fn run_admin(
    config: Option<PathBuf>,
    db: Option<PathBuf>,
    domain: Option<String>,
    action: AdminAction,
) -> anyhow::Result<()> {
    // Resolve db path + domain from explicit flags or the config file.
    let (db_path, domain) = match (db, domain) {
        (Some(db), Some(domain)) => (db, domain),
        (db_opt, domain_opt) => {
            let cfg = config
                .as_ref()
                .context("provide --config, or both --db and --domain")?;
            let cfg = Config::load(cfg)?;
            (
                db_opt.unwrap_or(cfg.registry.db_path),
                domain_opt.unwrap_or(cfg.server.domain),
            )
        }
    };

    let reg = Registry::open(&db_path, &domain).context("opening registry database")?;

    match action {
        AdminAction::User { cmd } => match cmd {
            UserCmd::Add { name } => {
                reg.add_user(&name)?;
                println!("added user {name}");
            }
            UserCmd::Ls => {
                for (id, name, _) in reg.list_users()? {
                    println!("{id}\t{name}");
                }
            }
            UserCmd::Rm { name, force } => {
                reg.remove_user(&name, force)?;
                println!("removed user {name}");
            }
        },
        AdminAction::Token { cmd } => match cmd {
            TokenCmd::Create { user, label } => {
                let token = reg.create_token(&user, label.as_deref())?;
                println!("token for {user} (shown once, store it now):\n\n  {token}\n");
            }
            TokenCmd::Ls { user } => {
                for t in reg.list_tokens(user.as_deref())? {
                    let state = if t.revoked { "revoked" } else { "active" };
                    println!(
                        "{}\t{}\t{}\t{}",
                        t.id,
                        t.user,
                        state,
                        t.label.unwrap_or_default()
                    );
                }
            }
            TokenCmd::Revoke { id } => {
                if reg.revoke_token(id)? {
                    println!("revoked token {id}");
                } else {
                    println!("token {id} not found or already revoked");
                }
            }
        },
        AdminAction::Hostname { cmd } => match cmd {
            HostnameCmd::Add { label, user } => {
                reg.add_hostname(&label, &user)?;
                println!("granted {label}.{domain} to {user}");
            }
            HostnameCmd::Ls { user } => {
                for (label, owner) in reg.list_hostnames(user.as_deref())? {
                    println!("{label}.{domain}\t{owner}");
                }
            }
            HostnameCmd::Rm { label } => {
                if reg.remove_hostname(&label)? {
                    println!("removed {label}.{domain}");
                } else {
                    println!("no such hostname: {label}");
                }
            }
        },
        AdminAction::Port { cmd } => match cmd {
            PortCmd::Add { port, user } => {
                reg.add_port(port, &user)?;
                println!("reserved port {port} for {user}");
            }
            PortCmd::Ls => {
                for (port, owner) in reg.list_ports()? {
                    println!("{port}\t{owner}");
                }
            }
            PortCmd::Rm { port } => {
                if reg.remove_port(port)? {
                    println!("released port {port}");
                } else {
                    println!("no such reserved port: {port}");
                }
            }
        },
    }
    Ok(())
}
