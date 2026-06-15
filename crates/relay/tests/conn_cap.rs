//! Admission-cap integration test for the daemon control plane.
//!
//! This stands up a REAL relay via `serve_with` (self-signed TLS, loopback) and
//! drives genuine control-session WebSocket upgrades against its `connect.`
//! virtual host. It proves the *wiring* of the live-session cap — not the
//! `ConnLimiter` primitive in isolation (the ratelimit/proxy unit tests cover
//! that, and pass identically pre/post-fix). The property under test is that
//! `handle_control_upgrade` actually:
//!
//!   * acquires a live-session permit BEFORE the 101 and HOLDS it for the
//!     session's whole life, so a surplus upgrade from the same source is
//!     refused with `503 relay at capacity`, and
//!   * releases that permit when the session ends, so dropping one frees a slot.
//!
//! On the PRE-FIX code the permit was dropped at the 101 (no live-session
//! limiter existed), so the surplus upgrade would be admitted with a 101 — this
//! test would see a 101 instead of the 503 and FAIL.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ethertunnel_proto::codec::{self};
use ethertunnel_proto::frames::{ControlFrame, Secret};
use ethertunnel_proto::limits::MAX_CONTROL_FRAME;
use ethertunnel_proto::transport::{mux_connection, mux_io_client};
use ethertunnel_relay::auth::MemoryAuth;
use ethertunnel_relay::config::{Config, ServerConfig, TlsConfig, TlsMode};
use ethertunnel_relay::router::Router;
use ethertunnel_relay::session::SessionCtx;
use ethertunnel_relay::{serve_with, RelayHandle};
use futures::future::poll_fn;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "ethertunnel.com";
const CONNECT_HOST: &str = "connect.ethertunnel.com";
const HOST: &str = "demo.ethertunnel.com";
const TOKEN: &str = "etun_cap_token";

/// Relay config with TINY caps: at most ONE live control session per source IP
/// (and two globally). All loopback connections share the 127.0.0.1 per-key
/// bucket, so the second concurrent upgrade from the test must be refused.
fn relay_config(listen: SocketAddr) -> Arc<Config> {
    let mut config = Config {
        server: ServerConfig {
            domain: DOMAIN.to_owned(),
            listen,
            apex_response: "EtherTunnel".to_owned(),
        },
        tls: TlsConfig {
            mode: TlsMode::SelfSigned,
            ..Default::default()
        },
        registry: Default::default(),
        tcp: Default::default(),
        keygate: None,
        limits: Default::default(),
        provision: None,
    };
    config.limits.max_sessions = 2;
    config.limits.max_sessions_per_ip = 1;
    Arc::new(config)
}

fn fixture_ctx() -> (Arc<SessionCtx>, Arc<Router>, Arc<MemoryAuth>) {
    let auth = Arc::new(MemoryAuth::new());
    let uid = auth.add_user("mat", TOKEN);
    auth.grant_hostname(uid, HOST);
    let router = Arc::new(Router::new());
    let ctx = SessionCtx::new(router.clone(), auth.clone(), "test-relay".into());
    (ctx, router, auth)
}

async fn start_relay(ctx: Arc<SessionCtx>) -> RelayHandle {
    serve_with(relay_config("127.0.0.1:0".parse().unwrap()), ctx, None)
        .await
        .expect("relay starts")
}

/// A rustls client config that trusts only the relay's self-signed cert.
fn client_config(cert_der: &[u8]) -> Arc<ClientConfig> {
    ethertunnel_relay::tls::ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("self-signed cert is a valid root");
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Open a TLS connection to the relay's `connect.` host.
async fn tls_connect(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    tcp.set_nodelay(true).ok();
    let connector = TlsConnector::from(cfg);
    let server_name = ServerName::try_from(CONNECT_HOST.to_owned()).unwrap();
    connector.connect(server_name, tcp).await.expect("tls handshake")
}

/// A live, admitted control session: completes the WS upgrade + Hello/Welcome so
/// the relay has spawned `run_session` (which HOLDS the live-session permit). The
/// returned guard keeps the connection — and therefore the permit — alive until
/// dropped/cancelled.
struct HeldSession {
    cancel: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
    // Own the control stream so the yamux connection (and the session's permit)
    // stays alive for the guard's lifetime.
    _ctrl: tokio_util::compat::Compat<yamux::Stream>,
}

async fn open_held_session(addr: SocketAddr, cfg: Arc<ClientConfig>) -> HeldSession {
    let tls = tls_connect(addr, cfg).await;
    let url = format!("wss://{CONNECT_HOST}/connect");
    let mux = mux_io_client(tls, &url)
        .await
        .expect("ws upgrade should be admitted (101)");
    let mut conn = mux_connection(mux, yamux::Mode::Client);
    let ctrl = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .expect("open control stream");

    let cancel = CancellationToken::new();
    let driver_cancel = cancel.clone();
    let driver = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = driver_cancel.cancelled() => break,
                next = poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                    if next.is_none() { break; }
                }
            }
        }
    });

    let mut ctrl = ctrl.compat();
    codec::write_preamble(&mut ctrl).await.unwrap();
    codec::write_frame(
        &mut ctrl,
        &ControlFrame::Hello {
            token: Secret::from(TOKEN),
            agent_version: "cap-test".into(),
            proto_min: 1,
            proto_max: ethertunnel_proto::PROTOCOL_VERSION,
        },
        MAX_CONTROL_FRAME,
    )
    .await
    .unwrap();
    match codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME)
        .await
        .unwrap()
    {
        ControlFrame::Welcome { .. } => {}
        other => panic!("expected Welcome, got {other:?}"),
    }
    // Keep the control stream alive inside the guard so the yamux connection
    // (and thus the session + its permit) stays up until we cancel.
    HeldSession {
        cancel,
        _driver: driver,
        _ctrl: ctrl,
    }
}

/// Send a raw HTTP/1.1 WebSocket upgrade and return the parsed status code +
/// reason line. Used for the SURPLUS attempt so we can assert the exact 503
/// rather than relying on a tungstenite error mapping.
async fn raw_upgrade_status(addr: SocketAddr, cfg: Arc<ClientConfig>) -> (u16, String) {
    let mut tls = tls_connect(addr, cfg).await;
    let req = format!(
        "GET /connect HTTP/1.1\r\n\
         Host: {CONNECT_HOST}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    // Read until we have the full status line + headers (up to the blank line).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tls.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap_or("").to_string();
    // "HTTP/1.1 503 Service Unavailable"
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (code, text.into_owned())
}

#[tokio::test]
async fn surplus_control_upgrade_is_refused_then_recovers() {
    let (ctx, router, _auth) = fixture_ctx();
    let relay = start_relay(ctx).await;
    let addr = relay.local_addr;
    let cert = relay.cert_der.clone().expect("self-signed cert exposed");
    let cfg = client_config(&cert);

    // 1) First control session is admitted and HOLDS the only per-IP permit.
    let held = open_held_session(addr, cfg.clone()).await;
    assert!(
        router.lookup_http(HOST).is_none(),
        "session is up but hasn't claimed yet"
    );

    // 2) A SECOND upgrade from the same loopback source must be refused at the
    //    upgrade with 503 "relay at capacity" — the permit is still held by (1).
    let (code, body) = raw_upgrade_status(addr, cfg.clone()).await;
    assert_eq!(
        code, 503,
        "surplus control upgrade must be refused with 503, got status line in:\n{body}"
    );
    assert!(
        body.contains("relay at capacity"),
        "503 body should be 'relay at capacity', got:\n{body}"
    );

    // 3) Recovery: drop the held session, freeing its slot. A fresh upgrade from
    //    the same source must now be admitted (101 -> mux established).
    held.cancel.cancel();
    // Give the relay a moment to observe the close and release the permit.
    let admitted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let tls = tls_connect(addr, cfg.clone()).await;
            let url = format!("wss://{CONNECT_HOST}/connect");
            if mux_io_client(tls, &url).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        admitted.is_ok(),
        "after the held session is dropped, a new upgrade must be admitted (slot freed)"
    );

    relay.shutdown();
}
