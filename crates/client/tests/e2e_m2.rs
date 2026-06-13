//! M2 end-to-end: a real client daemon connects to a real relay over loopback
//! TLS + WebSocket + yamux, authenticates, claims a hostname, heartbeats, and
//! reconnects + re-claims after the relay restarts.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ethertunnel_client::supervisor::{run_supervisor, ClientConfig, ConnState, DaemonStatus};
use ethertunnel_client::{HttpTunnel, TrustMode};
use ethertunnel_relay::auth::MemoryAuth;
use ethertunnel_relay::config::{Config, ServerConfig, TlsConfig, TlsMode};
use ethertunnel_relay::router::Router;
use ethertunnel_relay::session::SessionCtx;
use ethertunnel_relay::{serve, serve_with, RelayHandle};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "ethertunnel.com";
const HOST: &str = "demo.ethertunnel.com";
const TOKEN: &str = "etun_e2e_token";

fn relay_config(listen: SocketAddr) -> Arc<Config> {
    Arc::new(Config {
        server: ServerConfig {
            domain: DOMAIN.to_owned(),
            listen,
            apex_response: "EtherTunnel".to_owned(),
        },
        tls: TlsConfig {
            mode: TlsMode::SelfSigned,
        },
        registry: Default::default(),
        tcp: Default::default(),
    })
}

fn fixture_ctx() -> (Arc<SessionCtx>, Arc<Router>) {
    let auth = Arc::new(MemoryAuth::new());
    let uid = auth.add_user("mat", TOKEN);
    auth.grant_hostname(uid, HOST);
    let router = Arc::new(Router::new());
    let ctx = SessionCtx::new(router.clone(), auth, "test-relay".into());
    (ctx, router)
}

async fn start_relay(listen: SocketAddr, ctx: Arc<SessionCtx>) -> RelayHandle {
    serve(relay_config(listen), ctx)
        .await
        .expect("relay starts")
}

/// Wait until `pred` holds on the latest status, or panic after `timeout`.
async fn wait_until(
    rx: &mut watch::Receiver<DaemonStatus>,
    timeout: Duration,
    pred: impl Fn(&DaemonStatus) -> bool,
) -> DaemonStatus {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if pred(&rx.borrow()) {
            return rx.borrow().clone();
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for status; last = {:?}",
            *rx.borrow()
        );
        let _ = tokio::time::timeout(remaining, rx.changed()).await;
    }
}

#[tokio::test]
async fn daemon_connects_authenticates_and_claims() {
    let (ctx, router) = fixture_ctx();
    let relay = start_relay("127.0.0.1:0".parse().unwrap(), ctx).await;
    let cert = relay.cert_der.clone().expect("self-signed cert exposed");

    let cfg = ClientConfig {
        relay_host: DOMAIN.to_owned(),
        relay_addr: Some(relay.local_addr),
        token: TOKEN.to_owned(),
        tcp_tunnels: vec![],
        http_tunnels: vec![HttpTunnel {
            hostname: HOST.to_owned(),
            local_host: "127.0.0.1".to_owned(),
            local_port: 0,
        }],
        trust: TrustMode::CustomRoot(cert),
    };

    let (tx, mut rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    let sup = tokio::spawn(run_supervisor(cfg, tx, cancel.clone()));

    let status = wait_until(&mut rx, Duration::from_secs(10), |s| {
        s.state == ConnState::Connected && s.granted_hostnames.iter().any(|h| h == HOST)
    })
    .await;
    assert_eq!(status.state, ConnState::Connected);
    assert!(
        router.lookup_http(HOST).is_some(),
        "relay routes the hostname"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), sup).await;
}

#[tokio::test]
async fn bad_token_reports_auth_failed() {
    let (ctx, _router) = fixture_ctx();
    let relay = start_relay("127.0.0.1:0".parse().unwrap(), ctx).await;
    let cert = relay.cert_der.clone().unwrap();

    let cfg = ClientConfig {
        relay_host: DOMAIN.to_owned(),
        relay_addr: Some(relay.local_addr),
        token: "etun_wrong".to_owned(),
        http_tunnels: vec![],
        tcp_tunnels: vec![],
        trust: TrustMode::CustomRoot(cert),
    };

    let (tx, mut rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    let sup = tokio::spawn(run_supervisor(cfg, tx, cancel.clone()));

    let status = wait_until(&mut rx, Duration::from_secs(10), |s| {
        s.state == ConnState::AuthFailed
    })
    .await;
    assert_eq!(status.state, ConnState::AuthFailed);

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), sup).await;
}

#[tokio::test]
async fn daemon_reclaims_after_relay_restart() {
    // One fixed cert reused across both relay incarnations, so the single
    // client keeps trusting it and we genuinely test reconnect + re-claim.
    let material = ethertunnel_relay::tls::self_signed(DOMAIN).unwrap();
    let cert = material.1.clone();

    let (ctx1, _router1) = fixture_ctx();
    let relay1 = serve_with(
        relay_config("127.0.0.1:0".parse().unwrap()),
        ctx1,
        Some(material.clone()),
    )
    .await
    .unwrap();
    let addr = relay1.local_addr;

    let cfg = ClientConfig {
        relay_host: DOMAIN.to_owned(),
        relay_addr: Some(addr),
        token: TOKEN.to_owned(),
        tcp_tunnels: vec![],
        http_tunnels: vec![HttpTunnel {
            hostname: HOST.to_owned(),
            local_host: "127.0.0.1".to_owned(),
            local_port: 0,
        }],
        trust: TrustMode::CustomRoot(cert),
    };
    let (tx, mut rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    let sup = tokio::spawn(run_supervisor(cfg, tx, cancel.clone()));

    wait_until(&mut rx, Duration::from_secs(10), |s| {
        s.state == ConnState::Connected && !s.granted_hostnames.is_empty()
    })
    .await;

    // Take the relay down; bring a fresh one (fresh router) up on the same
    // address with the same cert. The existing supervisor must reconnect and
    // re-claim with no intervention.
    relay1.shutdown();
    drop(relay1);

    let (ctx2, router2) = fixture_ctx();
    let _relay2 = bind_retry(addr, ctx2, material).await;

    wait_until(&mut rx, Duration::from_secs(15), |s| {
        s.reconnects >= 1
            && s.state == ConnState::Connected
            && s.granted_hostnames.iter().any(|h| h == HOST)
    })
    .await;
    assert!(
        router2.lookup_http(HOST).is_some(),
        "restarted relay routes the reclaim"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), sup).await;
}

/// Bind a relay to a fixed address with fixed TLS material, retrying briefly
/// past TIME_WAIT.
async fn bind_retry(
    addr: SocketAddr,
    ctx: Arc<SessionCtx>,
    material: ethertunnel_relay::TlsMaterial,
) -> RelayHandle {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match serve_with(relay_config(addr), ctx.clone(), Some(material.clone())).await {
            Ok(h) => return h,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("relay failed to rebind {addr}: {e}"),
        }
    }
}
