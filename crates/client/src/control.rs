//! One-shot authenticated control requests against the relay.
//!
//! `etun release` / `etun remove` / `etun list` need to talk to the relay
//! outside the long-running daemon: open a TLS+yamux control stream, do the
//! `Hello`→`Welcome` handshake, exchange a single request/reply, then `Goodbye`.
//! This mirrors [`crate::login::verify`] but generalizes the post-handshake step
//! so the owned-set reconcile (`ListOwned`) and server-side release (`Release`)
//! can reuse the same plumbing.
//!
//! All of these frames are protocol v2; against an older relay the negotiated
//! `proto` comes back `< 2` and we fail with a clear "relay too old" message
//! instead of sending a frame the relay cannot decode.

use std::time::Duration;

use anyhow::{bail, Context};
use ethertunnel_proto::codec;
use ethertunnel_proto::frames::{ControlFrame, DenyCode, Secret};
use ethertunnel_proto::limits::MAX_CONTROL_FRAME;
use ethertunnel_proto::transport::{mux_connection, mux_io_client};
use futures::future::poll_fn;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use crate::tls::{client_config, TrustMode};

/// Lowest protocol version that understands the owned-set control frames.
const PROTO_OWNED_SET: u16 = 2;

fn connect_host(relay: &str) -> String {
    format!("connect.{relay}")
}

/// An open, authenticated control stream plus the task driving its connection.
struct ControlSession {
    ctrl: Compat<yamux::Stream>,
    driver: tokio::task::JoinHandle<()>,
    proto: u16,
}

impl ControlSession {
    /// Send `Goodbye` and stop driving the connection.
    async fn close(mut self) {
        let _ = codec::write_frame(&mut self.ctrl, &ControlFrame::Goodbye, MAX_CONTROL_FRAME).await;
        self.driver.abort();
    }
}

/// Open a verified TLS connection to the relay control endpoint.
async fn tls_connect(
    relay: &str,
    trust: &TrustMode,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let host = connect_host(relay);
    let addr = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .with_context(|| format!("resolving {host}"))?
        .next()
        .with_context(|| format!("no address for {host}"))?;
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    tcp.set_nodelay(true).ok();
    let connector = TlsConnector::from(client_config(trust)?);
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| anyhow::anyhow!("bad server name {host}: {e}"))?;
    connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}"))
}

/// Connect, open a control stream, and complete the `Hello`→`Welcome`
/// handshake. The returned session is ready for request frames.
async fn open(relay: &str, token: &str, trust: &TrustMode) -> anyhow::Result<ControlSession> {
    let host = connect_host(relay);
    let tls = tls_connect(relay, trust).await?;
    let url = format!("wss://{host}/connect");
    let mux = mux_io_client(tls, &url)
        .await
        .map_err(|e| anyhow::anyhow!("websocket handshake: {e}"))?;
    let mut conn = mux_connection(mux, yamux::Mode::Client);
    let control = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .map_err(|e| anyhow::anyhow!("opening control stream: {e}"))?;
    let driver = tokio::spawn(async move {
        while let Some(Ok(_)) = poll_fn(|cx| conn.poll_next_inbound(cx)).await {}
    });

    let mut ctrl = control.compat();
    codec::write_preamble(&mut ctrl).await?;
    codec::write_frame(
        &mut ctrl,
        &ControlFrame::Hello {
            token: Secret::from(token),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            proto_min: 1,
            proto_max: ethertunnel_proto::PROTOCOL_VERSION,
        },
        MAX_CONTROL_FRAME,
    )
    .await?;

    let proto = match tokio::time::timeout(
        Duration::from_secs(10),
        codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME),
    )
    .await
    {
        Err(_) => bail!("relay did not respond to Hello within 10s"),
        Ok(Ok(ControlFrame::Welcome { proto, .. })) => proto,
        Ok(Ok(ControlFrame::Denied {
            code: DenyCode::AuthFailed,
            ..
        })) => bail!("relay rejected the token (run `etun login` again)"),
        Ok(Ok(ControlFrame::Denied { code, message })) => {
            bail!("relay denied the connection ({code:?}): {message}")
        }
        Ok(Ok(other)) => bail!("unexpected reply to Hello: {other:?}"),
        Ok(Err(e)) => bail!("reading relay reply: {e}"),
    };

    Ok(ControlSession {
        ctrl,
        driver,
        proto,
    })
}

/// Read one frame with a bounded timeout.
async fn read_reply(ctrl: &mut Compat<yamux::Stream>) -> anyhow::Result<ControlFrame> {
    match tokio::time::timeout(
        Duration::from_secs(10),
        codec::read_frame::<_, ControlFrame>(ctrl, MAX_CONTROL_FRAME),
    )
    .await
    {
        Err(_) => bail!("relay did not reply within 10s"),
        Ok(Ok(f)) => Ok(f),
        Ok(Err(e)) => bail!("reading relay reply: {e}"),
    }
}

/// The relay's authoritative owned set for the authenticated account.
pub struct OwnedSet {
    pub hostnames: Vec<String>,
    pub tcp_ports: Vec<u16>,
}

/// Fetch the caller's owned hostnames + ports from the relay (`ListOwned`).
pub async fn list_owned(relay: &str, token: &str, trust: &TrustMode) -> anyhow::Result<OwnedSet> {
    let mut session = open(relay, token, trust).await?;
    if session.proto < PROTO_OWNED_SET {
        session.close().await;
        bail!("relay is too old to report owned tunnels (needs protocol v{PROTO_OWNED_SET}+)");
    }
    codec::write_frame(&mut session.ctrl, &ControlFrame::ListOwned, MAX_CONTROL_FRAME).await?;
    let reply = read_reply(&mut session.ctrl).await;
    let out = match reply {
        Ok(ControlFrame::Owned {
            hostnames,
            tcp_ports,
        }) => Ok(OwnedSet {
            hostnames,
            tcp_ports,
        }),
        Ok(other) => Err(anyhow::anyhow!("unexpected reply to ListOwned: {other:?}")),
        Err(e) => Err(e),
    };
    session.close().await;
    out
}

/// Release `hostnames` + `tcp_ports` server-side (`Release`). Returns the subset
/// the relay actually freed (only resources the caller owned).
pub async fn release(
    relay: &str,
    token: &str,
    trust: &TrustMode,
    hostnames: Vec<String>,
    tcp_ports: Vec<u16>,
) -> anyhow::Result<OwnedSet> {
    let mut session = open(relay, token, trust).await?;
    if session.proto < PROTO_OWNED_SET {
        session.close().await;
        bail!("relay is too old to release tunnels remotely (needs protocol v{PROTO_OWNED_SET}+)");
    }
    codec::write_frame(
        &mut session.ctrl,
        &ControlFrame::Release {
            hostnames,
            tcp_ports,
        },
        MAX_CONTROL_FRAME,
    )
    .await?;
    let reply = read_reply(&mut session.ctrl).await;
    let out = match reply {
        Ok(ControlFrame::Released {
            hostnames,
            tcp_ports,
        }) => Ok(OwnedSet {
            hostnames,
            tcp_ports,
        }),
        Ok(other) => Err(anyhow::anyhow!("unexpected reply to Release: {other:?}")),
        Err(e) => Err(e),
    };
    session.close().await;
    out
}
