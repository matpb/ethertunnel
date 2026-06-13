//! Connection probes used by `login` and `doctor`.
//!
//! [`verify`] performs a real `Hello` round-trip so `etun login` only stores a
//! token the relay actually accepts. [`tls_probe`] does just the TLS handshake
//! and reports the served certificate, for `etun doctor`.

use std::time::Duration;

use anyhow::{bail, Context};
use ethertunnel_proto::codec::{self};
use ethertunnel_proto::frames::{ControlFrame, DenyCode, Secret};
use ethertunnel_proto::limits::MAX_CONTROL_FRAME;
use ethertunnel_proto::transport::{mux_connection, mux_io_client};
use futures::future::poll_fn;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_rustls::TlsConnector;

use crate::tls::{client_config, TrustMode};

/// Details about the relay learned during a successful login.
#[derive(Debug)]
pub struct VerifyOk {
    pub session_id: u64,
    pub proto: u16,
}

fn connect_host(relay: &str) -> String {
    format!("connect.{relay}")
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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}"))?;
    Ok(tls)
}

/// Authenticate `token` against `relay` with a real `Hello` round-trip.
pub async fn verify(relay: &str, token: &str, trust: &TrustMode) -> anyhow::Result<VerifyOk> {
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
    // Keep the connection driven for the brief handshake.
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

    let result = match tokio::time::timeout(
        Duration::from_secs(10),
        codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME),
    )
    .await
    {
        Err(_) => bail!("relay did not respond to Hello within 10s"),
        Ok(Ok(ControlFrame::Welcome {
            session_id, proto, ..
        })) => Ok(VerifyOk { session_id, proto }),
        Ok(Ok(ControlFrame::Denied {
            code: DenyCode::AuthFailed,
            ..
        })) => bail!("relay rejected the token (authentication failed)"),
        Ok(Ok(ControlFrame::Denied { code, message })) => {
            bail!("relay denied the connection ({code:?}): {message}")
        }
        Ok(Ok(other)) => bail!("unexpected reply to Hello: {other:?}"),
        Ok(Err(e)) => bail!("reading relay reply: {e}"),
    };

    // Say goodbye so the relay closes the session cleanly, then stop the driver.
    let _ = codec::write_frame(&mut ctrl, &ControlFrame::Goodbye, MAX_CONTROL_FRAME).await;
    driver.abort();
    result
}

/// What the TLS handshake told us about the relay certificate.
#[derive(Debug)]
pub struct TlsInfo {
    pub days_remaining: i64,
    pub expired: bool,
}

/// Do just the TLS handshake and read the served leaf certificate's expiry.
pub async fn tls_probe(relay: &str, trust: &TrustMode) -> anyhow::Result<TlsInfo> {
    let tls = tls_connect(relay, trust).await?;
    let (_, conn) = tls.get_ref();
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .context("relay presented no certificate")?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| anyhow::anyhow!("parsing relay certificate: {e}"))?;
    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days_remaining = (not_after - now) / 86400;
    Ok(TlsInfo {
        days_remaining,
        expired: not_after <= now,
    })
}
