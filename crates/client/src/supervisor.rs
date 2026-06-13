//! The connection supervisor: keep one outbound tunnel to the relay alive.
//!
//! `run_supervisor` loops forever (until cancelled): connect, authenticate,
//! claim, heartbeat, and on any disconnect reconnect with jittered exponential
//! backoff. A bad token short-circuits to a long backoff and an `AuthFailed`
//! status so the daemon doesn't hammer the relay. Claims are sent on every
//! (re)connect, so recovery after a relay restart re-establishes hostnames
//! automatically — the relay's newest-wins semantics make that idempotent.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethertunnel_proto::codec::{self, CodecError};
use ethertunnel_proto::frames::{ControlFrame, DenyCode, Secret};
use ethertunnel_proto::limits::{HEARTBEAT_INTERVAL, MAX_CONTROL_FRAME, SESSION_DEAD_AFTER};
use ethertunnel_proto::transport::{mux_connection, mux_io_client};
use futures::future::poll_fn;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use crate::tls::{client_config, TrustMode};

/// One HTTP tunnel: a public hostname forwarding to a local address.
#[derive(Clone, Debug)]
pub struct HttpTunnel {
    /// Fully-qualified public hostname (e.g. `demo.ethertunnel.com`).
    pub hostname: String,
    /// Local address to forward to.
    pub local_host: String,
    pub local_port: u16,
}

/// One raw-TCP tunnel: a public port forwarding to a local address.
#[derive(Clone, Debug)]
pub struct TcpTunnel {
    /// Public TCP port on the relay.
    pub public_port: u16,
    pub local_host: String,
    pub local_port: u16,
}

/// What the daemon should connect and claim.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Relay base domain (the control endpoint is `connect.<relay_host>`).
    pub relay_host: String,
    /// Override the resolved address (tests / pinned IPs). `None` → DNS.
    pub relay_addr: Option<SocketAddr>,
    /// Bearer token presented in `Hello`.
    pub token: String,
    /// HTTP tunnels to claim and serve.
    pub http_tunnels: Vec<HttpTunnel>,
    /// Raw-TCP tunnels to claim and serve.
    pub tcp_tunnels: Vec<TcpTunnel>,
    /// How to trust the relay's TLS certificate.
    pub trust: TrustMode,
}

impl ClientConfig {
    fn connect_host(&self) -> String {
        format!("connect.{}", self.relay_host)
    }

    fn claim_hostnames(&self) -> Vec<String> {
        self.http_tunnels
            .iter()
            .map(|t| t.hostname.clone())
            .collect()
    }

    fn claim_ports(&self) -> Vec<u16> {
        self.tcp_tunnels.iter().map(|t| t.public_port).collect()
    }

    /// Build the forwarding tables for inbound streams.
    fn routes(&self) -> crate::proxy::Routes {
        use crate::proxy::{LocalTarget, RouteTable};
        let mut table = RouteTable::default();
        for t in &self.http_tunnels {
            table.http.insert(
                t.hostname.clone(),
                LocalTarget {
                    host: t.local_host.clone(),
                    port: t.local_port,
                },
            );
        }
        for t in &self.tcp_tunnels {
            table.tcp.insert(
                t.public_port,
                LocalTarget {
                    host: t.local_host.clone(),
                    port: t.local_port,
                },
            );
        }
        std::sync::Arc::new(table)
    }
}

/// Connection phase, surfaced to `status`/IPC consumers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnState {
    #[default]
    Connecting,
    Connected,
    AuthFailed,
}

/// A snapshot of the daemon's live state.
#[derive(Clone, Debug, Default)]
pub struct DaemonStatus {
    pub state: ConnState,
    pub granted_hostnames: Vec<String>,
    pub granted_ports: Vec<u16>,
    pub reconnects: u32,
}

#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("authentication failed")]
    Auth,
    #[error("disconnected")]
    Disconnected,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("tls/setup: {0}")]
    Setup(String),
    #[error("protocol: {0}")]
    Protocol(String),
}

impl ConnError {
    fn is_auth(&self) -> bool {
        matches!(self, ConnError::Auth)
    }
}

const BACKOFF_MAX: Duration = Duration::from_secs(60);
const BACKOFF_AUTH: Duration = Duration::from_secs(300);
const STABLE_RESET: Duration = Duration::from_secs(30);

/// Run the supervisor until `cancel` fires.
pub async fn run_supervisor(
    cfg: ClientConfig,
    status_tx: watch::Sender<DaemonStatus>,
    cancel: CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    let mut reconnects = 0u32;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        status_tx.send_modify(|s| s.state = ConnState::Connecting);

        let started = Instant::now();
        let outcome = tokio::select! {
            _ = cancel.cancelled() => break,
            r = connect_once(&cfg, &status_tx, &cancel) => r,
        };

        // Reset state for the next attempt.
        status_tx.send_modify(|s| {
            s.granted_hostnames.clear();
            s.granted_ports.clear();
        });

        let auth_failed = matches!(&outcome, Err(e) if e.is_auth());
        match &outcome {
            Ok(()) => tracing::debug!("connection closed cleanly"),
            Err(e) => tracing::debug!(error = %e, "connection ended"),
        }
        if cancel.is_cancelled() {
            break;
        }

        // A connection that lived a while resets the backoff.
        if !auth_failed && started.elapsed() > STABLE_RESET {
            backoff = Duration::from_secs(1);
        }
        let wait = if auth_failed {
            status_tx.send_modify(|s| s.state = ConnState::AuthFailed);
            BACKOFF_AUTH
        } else {
            backoff
        };

        reconnects += 1;
        status_tx.send_modify(|s| s.reconnects = reconnects);

        // Jittered sleep, interruptible by shutdown.
        let jitter = Duration::from_millis(rand::random::<u64>() % 500);
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(wait + jitter) => {}
        }
        if !auth_failed {
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }
    tracing::info!("supervisor stopped");
}

/// One full connection lifecycle: connect → handshake → claim → heartbeat,
/// returning when the connection ends (or `cancel` fires for a graceful close).
async fn connect_once(
    cfg: &ClientConfig,
    status_tx: &watch::Sender<DaemonStatus>,
    cancel: &CancellationToken,
) -> Result<(), ConnError> {
    let connect_host = cfg.connect_host();

    // Resolve + TCP connect.
    let addr = match cfg.relay_addr {
        Some(a) => a,
        None => tokio::net::lookup_host((connect_host.as_str(), 443))
            .await?
            .next()
            .ok_or_else(|| ConnError::Setup(format!("no address for {connect_host}")))?,
    };
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true).ok();

    // TLS.
    let connector =
        TlsConnector::from(client_config(&cfg.trust).map_err(|e| ConnError::Setup(e.to_string()))?);
    let server_name = ServerName::try_from(connect_host.clone())
        .map_err(|e| ConnError::Setup(format!("bad server name: {e}")))?;
    let tls = connector.connect(server_name, tcp).await?;

    // WebSocket upgrade + yamux.
    let url = format!("wss://{connect_host}/connect");
    let mux = mux_io_client(tls, &url)
        .await
        .map_err(|e| ConnError::Setup(format!("websocket handshake: {e}")))?;
    let mut conn = mux_connection(mux, yamux::Mode::Client);
    let control = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .map_err(|e| ConnError::Setup(format!("open control stream: {e}")))?;

    // Drive the connection in the background for the stream's lifetime,
    // dispatching each inbound stream (one per visitor connection) to the local
    // forwarder.
    let driver_cancel = cancel.child_token();
    let routes = cfg.routes();
    {
        let dc = driver_cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = dc.cancelled() => break,
                    next = poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                        match next {
                            Some(Ok(stream)) => {
                                tokio::spawn(crate::proxy::handle_inbound(stream, routes.clone()));
                            }
                            _ => break,
                        }
                    }
                }
            }
        });
    }

    let mut ctrl = control.compat();

    // Handshake.
    codec::write_preamble(&mut ctrl).await?;
    codec::write_frame(
        &mut ctrl,
        &ControlFrame::Hello {
            token: Secret::from(cfg.token.as_str()),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            proto_min: 1,
            proto_max: ethertunnel_proto::PROTOCOL_VERSION,
        },
        MAX_CONTROL_FRAME,
    )
    .await?;
    match codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME).await? {
        ControlFrame::Welcome {
            session_id, proto, ..
        } => {
            tracing::info!(session_id, proto, "authenticated with relay");
        }
        ControlFrame::Denied {
            code: DenyCode::AuthFailed,
            ..
        } => return Err(ConnError::Auth),
        ControlFrame::Denied { code, message } => {
            return Err(ConnError::Protocol(format!("{code:?}: {message}")))
        }
        other => {
            return Err(ConnError::Protocol(format!(
                "expected Welcome, got {other:?}"
            )))
        }
    }

    // Claim (if anything to claim).
    let claim_hostnames = cfg.claim_hostnames();
    let claim_ports = cfg.claim_ports();
    if !claim_hostnames.is_empty() || !claim_ports.is_empty() {
        codec::write_frame(
            &mut ctrl,
            &ControlFrame::Claim {
                hostnames: claim_hostnames,
                tcp_ports: claim_ports,
            },
            MAX_CONTROL_FRAME,
        )
        .await?;
        match codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME).await? {
            ControlFrame::Granted {
                hostnames,
                tcp_ports,
            } => {
                tracing::info!(?hostnames, ?tcp_ports, "tunnels granted");
                status_tx.send_modify(|s| {
                    s.state = ConnState::Connected;
                    s.granted_hostnames = hostnames;
                    s.granted_ports = tcp_ports;
                });
            }
            ControlFrame::Denied { code, message } => {
                tracing::warn!(?code, %message, "claim denied");
                status_tx.send_modify(|s| s.state = ConnState::Connected);
            }
            other => {
                return Err(ConnError::Protocol(format!(
                    "expected Granted, got {other:?}"
                )))
            }
        }
    } else {
        status_tx.send_modify(|s| s.state = ConnState::Connected);
    }

    // Steady state: a reader task (handles relay→daemon frames + dead-man) and
    // a heartbeat loop that owns the write half.
    let (mut rd, mut wr) = tokio::io::split(ctrl);
    let conn_dead = CancellationToken::new();
    let reader = {
        let conn_dead = conn_dead.clone();
        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(
                    SESSION_DEAD_AFTER,
                    codec::read_frame::<_, ControlFrame>(&mut rd, MAX_CONTROL_FRAME),
                )
                .await
                {
                    Err(_) => break, // no Pong within the dead-man window
                    Ok(Err(_)) => break,
                    Ok(Ok(frame)) => match frame {
                        ControlFrame::Pong { .. } => {}
                        ControlFrame::Superseded { resource } => {
                            tracing::warn!(?resource, "superseded by a newer session")
                        }
                        ControlFrame::Shutdown { reason } => {
                            tracing::info!(%reason, "relay is shutting down");
                            break;
                        }
                        _ => {}
                    },
                }
            }
            conn_dead.cancel();
        })
    };

    let mut nonce = 0u64;
    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = codec::write_frame(&mut wr, &ControlFrame::Goodbye, MAX_CONTROL_FRAME).await;
                let _ = wr.flush().await;
                break Ok(());
            }
            _ = conn_dead.cancelled() => break Err(ConnError::Disconnected),
            _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                nonce += 1;
                if codec::write_frame(&mut wr, &ControlFrame::Ping { nonce }, MAX_CONTROL_FRAME)
                    .await
                    .is_err()
                {
                    break Err(ConnError::Disconnected);
                }
            }
        }
    };

    driver_cancel.cancel();
    conn_dead.cancel();
    let _ = reader.await;
    result
}
