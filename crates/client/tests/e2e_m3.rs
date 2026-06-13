//! M3 end-to-end: a visitor's HTTPS request reaches a local service through the
//! relay + daemon, and a down local service produces the branded 502.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ethertunnel_client::supervisor::{run_supervisor, ConnState, DaemonStatus};
use ethertunnel_client::{ClientConfig, HttpTunnel, TrustMode};
use ethertunnel_relay::auth::MemoryAuth;
use ethertunnel_relay::config::{Config, ServerConfig, TlsConfig, TlsMode};
use ethertunnel_relay::router::Router;
use ethertunnel_relay::session::SessionCtx;
use ethertunnel_relay::{serve, RelayHandle};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "ethertunnel.com";
const HOST: &str = "demo.ethertunnel.com";
const TOKEN: &str = "etun_m3_token";

fn fixture_ctx() -> (Arc<SessionCtx>, Arc<Router>) {
    let auth = Arc::new(MemoryAuth::new());
    let uid = auth.add_user("mat", TOKEN);
    auth.grant_hostname(uid, HOST);
    let router = Arc::new(Router::new());
    let ctx = SessionCtx::new(router.clone(), auth, "test-relay".into());
    (ctx, router)
}

async fn start_relay(ctx: Arc<SessionCtx>) -> RelayHandle {
    let config = Arc::new(Config {
        server: ServerConfig {
            domain: DOMAIN.to_owned(),
            listen: "127.0.0.1:0".parse().unwrap(),
            apex_response: "EtherTunnel".to_owned(),
        },
        tls: TlsConfig {
            mode: TlsMode::SelfSigned,
            ..Default::default()
        },
        registry: Default::default(),
        tcp: Default::default(),
    });
    serve(config, ctx).await.expect("relay starts")
}

/// A minimal local HTTP/1.1 server returning a fixed body. Loops so each proxied
/// connection (one per visitor request) is served.
async fn spawn_local_http(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Drain request headers up to the blank line.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    port
}

/// Bind a port then release it, yielding an address nothing is listening on.
async fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Make an HTTPS GET to the relay as a visitor (raw HTTP/1.1, Connection: close),
/// returning (head, body).
async fn visitor_get(relay_addr: SocketAddr, host: &str, cert_der: Vec<u8>) -> (String, String) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der)).unwrap();
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let tcp = TcpStream::connect(relay_addr).await.unwrap();
    let sni = ServerName::try_from(host.to_owned()).unwrap();
    let mut tls = connector.connect(sni, tcp).await.unwrap();

    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    (head.to_string(), body.to_string())
}

async fn run_daemon(
    relay: &RelayHandle,
    local_port: u16,
) -> (CancellationToken, watch::Receiver<DaemonStatus>) {
    let cfg = ClientConfig {
        relay_host: DOMAIN.to_owned(),
        relay_addr: Some(relay.local_addr),
        token: TOKEN.to_owned(),
        http_tunnels: vec![HttpTunnel {
            hostname: HOST.to_owned(),
            local_host: "127.0.0.1".to_owned(),
            local_port,
        }],
        tcp_tunnels: vec![],
        trust: TrustMode::CustomRoot(relay.cert_der.clone().unwrap()),
    };
    let (tx, mut rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    tokio::spawn(run_supervisor(cfg, tx, cancel.clone()));

    // Wait for the claim to be granted.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if rx.borrow().state == ConnState::Connected && !rx.borrow().granted_hostnames.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "daemon never connected"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
    }
    (cancel, rx)
}

#[tokio::test]
async fn http_request_proxied_to_local_service() {
    let local_port = spawn_local_http("hello from local").await;
    let (ctx, _router) = fixture_ctx();
    let relay = start_relay(ctx).await;
    let (cancel, _rx) = run_daemon(&relay, local_port).await;

    let (head, body) = visitor_get(relay.local_addr, HOST, relay.cert_der.clone().unwrap()).await;
    assert!(head.contains("200 OK"), "expected 200, head was:\n{head}");
    assert_eq!(body, "hello from local");

    cancel.cancel();
}

#[tokio::test]
async fn local_service_down_yields_branded_502() {
    let local_port = dead_port().await;
    let (ctx, _router) = fixture_ctx();
    let relay = start_relay(ctx).await;
    let (cancel, _rx) = run_daemon(&relay, local_port).await;

    let (head, body) = visitor_get(relay.local_addr, HOST, relay.cert_der.clone().unwrap()).await;
    assert!(head.contains("502"), "expected 502, head was:\n{head}");
    assert!(
        head.to_ascii_lowercase().contains("x-etun-error"),
        "expected the daemon's branded 502, head was:\n{head}"
    );
    assert!(
        body.contains("local service unavailable"),
        "body was:\n{body}"
    );

    cancel.cancel();
}

#[tokio::test]
async fn unknown_host_yields_relay_404() {
    let (ctx, _router) = fixture_ctx();
    let relay = start_relay(ctx).await;
    // No daemon, so nothing claims the host.
    let (head, _body) = visitor_get(
        relay.local_addr,
        "nope.ethertunnel.com",
        relay.cert_der.clone().unwrap(),
    )
    .await;
    assert!(head.contains("404"), "expected 404, head was:\n{head}");
}
