//! M5 end-to-end: a raw TCP connection to a relay tunnel port reaches a local
//! TCP service and echoes back through the daemon.

use std::sync::Arc;
use std::time::Duration;

use ethertunnel_client::supervisor::{run_supervisor, ConnState, DaemonStatus};
use ethertunnel_client::{ClientConfig, TcpTunnel, TrustMode};
use ethertunnel_relay::auth::MemoryAuth;
use ethertunnel_relay::config::{Config, ServerConfig, TcpConfig, TlsConfig, TlsMode};
use ethertunnel_relay::router::Router;
use ethertunnel_relay::session::SessionCtx;
use ethertunnel_relay::{serve, RelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "ethertunnel.com";
const TOKEN: &str = "etun_m5_token";

/// A local TCP echo server. Returns its port.
async fn spawn_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Grab a currently-free port (raced, but fine for a test).
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_relay(ctx: Arc<SessionCtx>, pub_port: u16) -> RelayHandle {
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
        // Restrict the range to exactly the test's public port.
        tcp: TcpConfig {
            port_range: [pub_port, pub_port],
        },
        keygate: None,
        limits: Default::default(),
    });
    serve(config, ctx).await.expect("relay starts")
}

#[tokio::test]
async fn raw_tcp_tunnel_echoes() {
    let echo_port = spawn_echo().await;
    let pub_port = free_port().await;

    let auth = Arc::new(MemoryAuth::new());
    let uid = auth.add_user("mat", TOKEN);
    auth.grant_port(uid, pub_port);
    let router = Arc::new(Router::new());
    let ctx = SessionCtx::new(router.clone(), auth, "test".into());
    let relay = start_relay(ctx, pub_port).await;
    let relay_ip = relay.local_addr.ip();

    let cfg = ClientConfig {
        relay_host: DOMAIN.to_owned(),
        relay_addr: Some(relay.local_addr),
        token: TOKEN.to_owned(),
        http_tunnels: vec![],
        tcp_tunnels: vec![TcpTunnel {
            public_port: pub_port,
            local_host: "127.0.0.1".to_owned(),
            local_port: echo_port,
        }],
        trust: TrustMode::CustomRoot(relay.cert_der.clone().unwrap()),
    };
    let (tx, mut rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    tokio::spawn(run_supervisor(cfg, tx, cancel.clone()));

    // Wait until the port is granted (and thus bound by the relay).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if rx.borrow().state == ConnState::Connected
            && rx.borrow().granted_ports.contains(&pub_port)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "tcp port never granted; last = {:?}",
            *rx.borrow()
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
    }

    // Connect to the public TCP port and round-trip bytes through the tunnel.
    let mut conn = TcpStream::connect((relay_ip, pub_port)).await.unwrap();
    conn.write_all(b"ping over tcp").await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = [0u8; 13];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping over tcp");

    cancel.cancel();
}
