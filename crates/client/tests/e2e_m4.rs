//! M4 end-to-end: the SQLite-backed registry is the live authenticator. A
//! registry-issued token connects, claims a registry-granted hostname, and
//! proxies; a token unknown to the registry is rejected.

use std::sync::Arc;
use std::time::Duration;

use ethertunnel_client::supervisor::{run_supervisor, ConnState, DaemonStatus};
use ethertunnel_client::{ClientConfig, HttpTunnel, TrustMode};
use ethertunnel_relay::config::{Config, ServerConfig, TlsConfig, TlsMode};
use ethertunnel_relay::registry::Registry;
use ethertunnel_relay::router::Router;
use ethertunnel_relay::session::SessionCtx;
use ethertunnel_relay::{serve, RelayHandle};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "ethertunnel.com";
const HOST: &str = "demo.ethertunnel.com";

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
        keygate: None,
        limits: Default::default(),
    });
    serve(config, ctx).await.expect("relay starts")
}

fn daemon(relay: &RelayHandle, token: &str) -> (CancellationToken, watch::Receiver<DaemonStatus>) {
    let cfg = ClientConfig {
        relay_host: DOMAIN.to_owned(),
        relay_addr: Some(relay.local_addr),
        token: token.to_owned(),
        http_tunnels: vec![HttpTunnel {
            hostname: HOST.to_owned(),
            local_host: "127.0.0.1".to_owned(),
            local_port: 0,
        }],
        tcp_tunnels: vec![],
        trust: TrustMode::CustomRoot(relay.cert_der.clone().unwrap()),
    };
    let (tx, rx) = watch::channel(DaemonStatus::default());
    let cancel = CancellationToken::new();
    tokio::spawn(run_supervisor(cfg, tx, cancel.clone()));
    (cancel, rx)
}

async fn wait_state(rx: &mut watch::Receiver<DaemonStatus>, want: ConnState) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while rx.borrow().state != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "never reached {want:?}; last = {:?}",
            *rx.borrow()
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
    }
}

#[tokio::test]
async fn registry_token_authenticates_and_claims() {
    let reg = Registry::open_in_memory(DOMAIN).unwrap();
    reg.add_user("mat").unwrap();
    let token = reg.create_token("mat", Some("laptop")).unwrap();
    reg.add_hostname("demo", "mat").unwrap();

    let router = Arc::new(Router::new());
    let ctx = SessionCtx::new(router.clone(), Arc::new(reg), "test".into());
    let relay = start_relay(ctx).await;

    let (cancel, mut rx) = daemon(&relay, &token);
    wait_state(&mut rx, ConnState::Connected).await;
    assert!(rx.borrow().granted_hostnames.iter().any(|h| h == HOST));
    assert!(router.lookup_http(HOST).is_some());
    cancel.cancel();
}

#[tokio::test]
async fn registry_rejects_unknown_token() {
    let reg = Registry::open_in_memory(DOMAIN).unwrap();
    reg.add_user("mat").unwrap();
    let _real = reg.create_token("mat", None).unwrap();

    let ctx = SessionCtx::new(Arc::new(Router::new()), Arc::new(reg), "test".into());
    let relay = start_relay(ctx).await;

    let (cancel, mut rx) = daemon(&relay, "etun_not_a_real_token");
    wait_state(&mut rx, ConnState::AuthFailed).await;
    cancel.cancel();
}
