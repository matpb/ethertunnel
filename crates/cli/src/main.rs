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

    // --- client commands ---
    /// Verify and store a bearer token for a relay.
    Login {
        /// Relay base domain (e.g. ethertunnel.com). Defaults to the configured relay.
        #[arg(long)]
        relay: Option<String>,
        /// Read the token from stdin instead of the ETUN_TOKEN env var.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Add (or replace) a tunnel in the client config.
    Add {
        /// Stable name; also the default public label.
        name: String,
        /// Local port to forward to.
        port: u16,
        /// Public label below the relay apex (HTTP; defaults to <name>).
        #[arg(long)]
        hostname: Option<String>,
        /// Make this a raw-TCP tunnel on this public relay port.
        #[arg(long)]
        tcp: Option<u16>,
        /// Local host to forward to (default 127.0.0.1).
        #[arg(long)]
        local_host: Option<String>,
    },
    /// List configured tunnels.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove a tunnel from the config.
    Remove { name: String },
    /// Run the client daemon in the foreground.
    Up {
        /// Log for an init system (journald/rolling file) instead of a TTY.
        #[arg(long)]
        service_mode: bool,
    },
    /// Show the running daemon's last published status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Install/manage the daemon as a background service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Show the daemon's logs.
    Logs {
        /// Follow new output (like `tail -f`).
        #[arg(short, long)]
        follow: bool,
    },
    /// Diagnose this client's ability to reach and use its relay.
    Doctor,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Install and start the service.
    Install {
        /// Install a system-wide service (needs root) instead of per-user.
        #[arg(long)]
        system: bool,
    },
    /// Stop and remove the service.
    Uninstall {
        #[arg(long)]
        system: bool,
    },
    Start {
        #[arg(long)]
        system: bool,
    },
    Stop {
        #[arg(long)]
        system: bool,
    },
    Status {
        #[arg(long)]
        system: bool,
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
    /// Pre-flight diagnostics: DNS, registry, TLS material, ACME credentials.
    Doctor,
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
    let cli = Cli::parse();
    // Route logs by mode: a service uses journald (Linux) or a rolling file
    // (macOS/Windows); everything else logs to the TTY.
    let service_mode = matches!(cli.command, Command::Up { service_mode: true });
    init_logging(service_mode);

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

        Command::Login { relay, token_stdin } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(ethertunnel_client::commands::login(relay, token_stdin))
        }
        Command::Add {
            name,
            port,
            hostname,
            tcp,
            local_host,
        } => ethertunnel_client::commands::add(name, port, hostname, tcp, local_host),
        Command::List { json } => ethertunnel_client::commands::list(json),
        Command::Remove { name } => ethertunnel_client::commands::remove(name),
        Command::Up { .. } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(ethertunnel_client::commands::up())
        }
        Command::Status { json } => ethertunnel_client::commands::status(json),
        Command::Service { cmd } => {
            use ethertunnel_client::service;
            match cmd {
                ServiceCmd::Install { system } => service::install(system),
                ServiceCmd::Uninstall { system } => service::uninstall(system),
                ServiceCmd::Start { system } => service::start(system),
                ServiceCmd::Stop { system } => service::stop(system),
                ServiceCmd::Status { system } => service::status(system),
            }
        }
        Command::Logs { follow } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(ethertunnel_client::commands::logs(follow))
        }
        Command::Doctor => {
            let rt = tokio::runtime::Runtime::new()?;
            if !rt.block_on(ethertunnel_client::doctor::run()) {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// Initialise tracing for the chosen run mode.
fn init_logging(service_mode: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());

    if !service_mode {
        tracing_subscriber::fmt().with_env_filter(filter).init();
        return;
    }

    // Service mode. On Linux, systemd captures stderr into journald, so emit
    // plain lines with no ANSI or redundant timestamps. On macOS/Windows there
    // is no journal, so roll daily log files (keep 7).
    #[cfg(target_os = "linux")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .without_time()
            .init();
    }
    #[cfg(not(target_os = "linux"))]
    {
        match ethertunnel_client::paths::log_dir() {
            Ok(dir) => {
                let appender = tracing_appender::rolling::Builder::new()
                    .rotation(tracing_appender::rolling::Rotation::DAILY)
                    .filename_prefix(ethertunnel_client::paths::log_file_basename())
                    .max_log_files(7)
                    .build(&dir)
                    .expect("building rolling log appender");
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(false)
                    .with_writer(appender)
                    .init();
            }
            Err(_) => {
                tracing_subscriber::fmt().with_env_filter(filter).init();
            }
        }
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

    // Keep an Arc<Registry> clone so the provisioning control plane can reach the
    // concrete registry (the Authenticator trait object can't mint tokens).
    let registry = Arc::new(registry);
    let ctx = SessionCtx::new(
        Arc::new(Router::new()),
        registry.clone(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );

    // Wire the keygate→relay provisioning control plane when configured. Absent
    // => the `/admin/*` endpoints are not mounted (no inbound control API).
    if let Some(pv) = &config.provision {
        use ethertunnel_relay::admin_http::ProvisionState;
        let token = pv.token().context("reading provision token")?;
        ctx.set_provision(Arc::new(ProvisionState {
            registry: registry.clone(),
            token,
        }));
        tracing::info!("self-serve provisioning control plane enabled on connect host");
    }

    // Wire keygate entitlement enforcement when configured. Absent => no gate,
    // so the relay behaves exactly as before (every owned claim allowed).
    if let Some(kg) = &config.keygate {
        use ethertunnel_relay::entitlement::{
            spawn_sync, EntitlementCache, EntitlementGate, KeygateClient, KeygatePolicy,
        };
        let cache_path = config
            .registry
            .db_path
            .parent()
            .map(|p| p.join("keygate-cache.db"))
            .unwrap_or_else(|| PathBuf::from("keygate-cache.db"));
        let cache =
            EntitlementCache::open(&cache_path).context("opening keygate entitlement cache")?;
        let policy = KeygatePolicy {
            product: kg.product.clone(),
            public_key_b64: kg.public_key.clone(),
            key_id: kg.key_id.clone(),
            staleness_ceiling_secs: kg.staleness_ceiling_secs,
            require_entitlement: kg.require_entitlement,
        };
        let gate = Arc::new(EntitlementGate::new(cache, policy));
        ctx.set_entitlements(gate.clone());
        let client = KeygateClient::new(kg.base_url.clone(), kg.token()?, kg.product.clone());
        spawn_sync(
            gate,
            client,
            std::time::Duration::from_secs(kg.poll_interval_secs),
        );
        tracing::info!(
            base_url = %kg.base_url,
            product = %kg.product,
            "keygate entitlement enforcement enabled"
        );
    }

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
    // Doctor needs the whole config (TLS/ACME sections), not just db + domain.
    if matches!(&action, AdminAction::Doctor) {
        let cfg = config
            .as_ref()
            .context("doctor needs --config <relay.toml>")?;
        let cfg = Config::load(cfg)?;
        let rt = tokio::runtime::Runtime::new()?;
        let ok = rt.block_on(ethertunnel_relay::doctor::run(&cfg));
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }

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
        // Handled before the registry is opened (needs the full config).
        AdminAction::Doctor => unreachable!("doctor is dispatched earlier"),
    }
    Ok(())
}
