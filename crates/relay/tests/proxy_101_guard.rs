//! A daemon 101 to a non-upgrading visitor must become a 502, not a forward.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ethertunnel_proto::codec::{self};
use ethertunnel_proto::frames::{ControlFrame, Secret, StreamHeader};
use ethertunnel_proto::limits::{MAX_CONTROL_FRAME, MAX_STREAM_HEADER};
use ethertunnel_proto::transport::{mux_connection, mux_io_client};
use ethertunnel_relay::auth::MemoryAuth;
use ethertunnel_relay::config::{Config, ServerConfig, TlsConfig, TlsMode};
use ethertunnel_relay::router::Router;
use ethertunnel_relay::serve_with;
use ethertunnel_relay::session::SessionCtx;
use futures::future::poll_fn;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt;

const DOMAIN: &str = "ethertunnel.com";
const CONNECT_HOST: &str = "connect.ethertunnel.com";
const HOST: &str = "demo101.ethertunnel.com";
const TOKEN: &str = "etun_101_token";

fn relay_config(listen: SocketAddr) -> Arc<Config> {
    Arc::new(Config {
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
        polar: None,
        limits: Default::default(),
    })
}

fn client_config(cert_der: &[u8]) -> Arc<ClientConfig> {
    ethertunnel_relay::tls::ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der.to_vec())).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn tls_connect(
    addr: SocketAddr,
    host: &str,
    cfg: Arc<ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    tcp.set_nodelay(true).ok();
    let connector = TlsConnector::from(cfg);
    let server_name = ServerName::try_from(host.to_owned()).unwrap();
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake")
}

/// Claims HOST, then answers every data stream with a bare 101 regardless of
/// what the visitor's request looked like.
async fn run_fake_daemon(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
    claimed: tokio::sync::oneshot::Sender<()>,
) {
    let tls = tls_connect(addr, CONNECT_HOST, cfg).await;
    let url = format!("wss://{CONNECT_HOST}/connect");
    let mux = mux_io_client(tls, &url).await.expect("ws upgrade admitted");
    let mut conn = mux_connection(mux, yamux::Mode::Client);
    let ctrl = poll_fn(|cx| conn.poll_new_outbound(cx))
        .await
        .expect("open control stream");
    let mut ctrl = ctrl.compat();

    // The Connection must be driven continuously, not just once we get to the
    // data-stream loop below, or `ctrl` I/O never progresses.
    let (stream_tx, mut stream_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(Ok(stream)) = poll_fn(|cx| conn.poll_next_inbound(cx)).await {
            if stream_tx.send(stream).is_err() {
                break;
            }
        }
    });

    codec::write_preamble(&mut ctrl).await.unwrap();
    codec::write_frame(
        &mut ctrl,
        &ControlFrame::Hello {
            token: Secret::from(TOKEN),
            agent_version: "101-guard-test".into(),
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
    codec::write_frame(
        &mut ctrl,
        &ControlFrame::Claim {
            hostnames: vec![HOST.into()],
            tcp_ports: vec![],
        },
        MAX_CONTROL_FRAME,
    )
    .await
    .unwrap();
    match codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME)
        .await
        .unwrap()
    {
        ControlFrame::Granted { .. } => {}
        other => panic!("expected Granted, got {other:?}"),
    }
    let _ = claimed.send(());

    while let Some(stream) = stream_rx.recv().await {
        tokio::spawn(async move {
            let mut io = stream.compat();
            let _hdr: StreamHeader = codec::read_frame(&mut io, MAX_STREAM_HEADER)
                .await
                .expect("stream header");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = io.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = io
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .await;
            let _ = io.flush().await;
        });
    }
}

#[tokio::test]
async fn hundred_one_without_visitor_upgrade_becomes_502() {
    let auth = Arc::new(MemoryAuth::new());
    let uid = auth.add_user("mat101", TOKEN);
    auth.grant_hostname(uid, HOST);
    let router = Arc::new(Router::new());
    let ctx = SessionCtx::new(router, auth, "test-relay".into());

    let relay = serve_with(relay_config("127.0.0.1:0".parse().unwrap()), ctx, None)
        .await
        .expect("relay starts");
    let addr = relay.local_addr;
    let cert = relay.cert_der.clone().expect("self-signed cert exposed");
    let cfg = client_config(&cert);

    let (claimed_tx, claimed_rx) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(run_fake_daemon(addr, cfg.clone(), claimed_tx));
    tokio::select! {
        r = claimed_rx => { r.expect("daemon task dropped the claimed signal"); }
        r = daemon => { panic!("daemon task exited before claiming: {r:?}"); }
    }

    // Visitor sends a plain GET, no Connection/Upgrade — never asked to upgrade.
    let mut tls = tls_connect(addr, HOST, cfg).await;
    let req = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let read_all = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = tls.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    });
    read_all.await.expect("visitor response must arrive");

    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap_or("");
    assert!(
        status_line.contains("502"),
        "expected 502 (daemon 101 refused without a visitor upgrade), got: {status_line}\nfull:\n{text}"
    );

    relay.shutdown();
}
