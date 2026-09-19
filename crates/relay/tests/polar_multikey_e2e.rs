//! Sandboxed end-to-end proof of the pooled-cap fix, against a LOCAL mock
//! Polar endpoint on loopback. Nothing here touches api.polar.sh.
//!
//! It reproduces the production incident exactly: ONE Polar customer holding
//! TWO granted keys on different benefits (a Team key capped at 30, a
//! CortexMind key capped at 1). Both keys collapse into ONE registry account
//! (the account name IS the customer id), so they share ONE tunnel pool. When
//! the small key re-validated on its 5-minute cadence, the pre-fix relay
//! resolved the whole pool's cap from that single key and hard-deleted the
//! tunnels the big key pays for.
//!
//! WHAT IS REAL HERE: a relay started through `serve_with` on loopback with
//! self-signed TLS; two daemon control sessions over real TCP + TLS + the
//! WebSocket upgrade + yamux, exchanging real `ControlFrame`s; the real
//! `PolarGate`, `Registry`, `Router` and `Reconciler`; an on-disk SQLite
//! registry and license cache in a temp dir; the real periodic re-validation
//! loop in `session.rs`; and a real HTTP round-trip to a mock Polar server
//! that speaks the customer-portal request/response shapes.
//!
//! WHAT IS NOT: `polar::PolarHttpClient` itself. Its connector is built with
//! `.with_webpki_roots().https_only()`, so it can reach neither a plaintext
//! loopback listener nor one holding a locally-generated certificate, and it
//! exposes no seam to inject a root store. Driving it needs the real API,
//! which is what the `#[ignore]`d `tests/live_polar.rs` is for. The backend
//! below therefore speaks the same wire shapes over the same hyper client
//! stack, minus TLS.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ethertunnel_proto::codec;
use ethertunnel_proto::frames::{ControlFrame, Secret};
use ethertunnel_proto::limits::MAX_CONTROL_FRAME;
use ethertunnel_proto::transport::{mux_connection, mux_io_client};
use ethertunnel_relay::config::{Config, LimitsConfig, ServerConfig, TlsConfig, TlsMode};
use ethertunnel_relay::polar::{
    now_unix, ActivateOutcome, LicenseCache, PolarBackend, PolarGate, PolarPolicy, Reconciler,
    ValidateOutcome,
};
use ethertunnel_relay::registry::Registry;
use ethertunnel_relay::router::Router;
use ethertunnel_relay::session::SessionCtx;
use ethertunnel_relay::{serve_with, RelayHandle};
use futures::future::poll_fn;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "ethertunnel.com";
const CONNECT_HOST: &str = "connect.ethertunnel.com";
const ORG: &str = "org_sandbox";

/// One human, one Polar customer, two granted license keys.
const CUSTOMER: &str = "cust_1d39c89f";
const TEAM_KEY: &str = "ETUN-TEAM-SANDBOX-KEY";
const TEAM_BENEFIT: &str = "ben_team";
const TEAM_CAP: i64 = 30;
const CM_KEY: &str = "ETUN-CORTEXMIND-SANDBOX-KEY";
const CM_BENEFIT: &str = "ben_cortexmind";
const CM_CAP: i64 = 1;

const HOST_FIRST: &str = "cortex-tunnel.ethertunnel.com";
const HOST_SECOND: &str = "team-tunnel.ethertunnel.com";
const HOST_THIRD: &str = "extra-tunnel.ethertunnel.com";

const CACHE_TTL_SECS: i64 = 300;
const STALENESS_SECS: i64 = 259_200;
const CAP_PRUNE_GRACE_SECS: i64 = 2_592_000;

// ---------------------------------------------------------------------------
// Mock Polar: a real HTTP/1.1 server on loopback speaking the customer-portal
// license-key endpoints.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// key -> (customer_id, benefit_id). A key absent here answers 404, the
    /// status Polar returns for both invalid and revoked keys.
    granted: Mutex<HashMap<String, (String, String)>>,
    validate_calls: Mutex<HashMap<String, usize>>,
    activate_calls: AtomicUsize,
    /// Request-shape violations, asserted at the end of the test rather than
    /// panicking inside a connection task where the failure would be invisible.
    violations: Mutex<Vec<String>>,
}

impl MockState {
    fn validate_count(&self, key: &str) -> usize {
        self.validate_calls
            .lock()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(0)
    }
}

struct MockPolar {
    base_url: String,
    state: Arc<MockState>,
}

async fn start_mock_polar(grants: &[(&str, &str, &str)]) -> MockPolar {
    let state = Arc::new(MockState::default());
    {
        let mut g = state.granted.lock().unwrap();
        for (key, customer, benefit) in grants {
            g.insert(
                (*key).to_owned(),
                ((*customer).to_owned(), (*benefit).to_owned()),
            );
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().unwrap();
    let serve_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let conn_state = serve_state.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| handle_polar(conn_state.clone(), req)),
                    )
                    .await;
            });
        }
    });
    MockPolar {
        base_url: format!("http://{addr}"),
        state,
    }
}

async fn handle_polar(
    state: Arc<MockState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    let mut violations = Vec::new();
    if req.method() != Method::POST {
        violations.push(format!("{path}: method {}", req.method()));
    }
    if req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        != Some("application/json")
    {
        violations.push(format!("{path}: missing/!json content-type"));
    }
    // These endpoints authenticate by the key plus the public organization id.
    // A bearer token leaking into them would be a real defect.
    if req.headers().contains_key("authorization") {
        violations.push(format!("{path}: sent an Authorization header"));
    }
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    if body["organization_id"].as_str() != Some(ORG) {
        violations.push(format!(
            "{path}: organization_id {}",
            body["organization_id"]
        ));
    }
    let key = body["key"].as_str().unwrap_or_default().to_owned();
    state.violations.lock().unwrap().extend(violations);

    let resp = match path.as_str() {
        "/v1/customer-portal/license-keys/validate" => {
            *state
                .validate_calls
                .lock()
                .unwrap()
                .entry(key.clone())
                .or_insert(0) += 1;
            match state.granted.lock().unwrap().get(&key) {
                Some((customer_id, benefit_id)) => json_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "customer_id": customer_id,
                        "benefit_id": benefit_id,
                        "status": "granted",
                    }),
                ),
                None => json_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"detail": "License key is no longer active"}),
                ),
            }
        }
        "/v1/customer-portal/license-keys/activate" => {
            state.activate_calls.fetch_add(1, Ordering::Relaxed);
            json_response(
                StatusCode::OK,
                serde_json::json!({"id": format!("act-{key}")}),
            )
        }
        "/v1/customer-portal/license-keys/deactivate" => {
            json_response(StatusCode::OK, serde_json::json!({}))
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({"detail": "unknown endpoint"}),
        ),
    };
    Ok(resp)
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

// ---------------------------------------------------------------------------
// The gate's backend: the same hyper client stack `PolarHttpClient` uses, over
// plaintext loopback, emitting and interpreting the same wire shapes.
// ---------------------------------------------------------------------------

struct LoopbackPolarBackend {
    client: Client<HttpConnector, Full<Bytes>>,
    api_base: String,
}

impl LoopbackPolarBackend {
    fn new(api_base: String) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            api_base,
        }
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<(StatusCode, Bytes), String> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{path}", self.api_base))
            .header("Content-Type", "application/json")
            .header("User-Agent", "ethertunnel-relay/1")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| e.to_string())?;
        let resp = self.client.request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, bytes))
    }
}

impl PolarBackend for LoopbackPolarBackend {
    fn validate<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = ValidateOutcome> + Send + 'a>> {
        Box::pin(async move {
            let body = serde_json::json!({"key": key, "organization_id": ORG});
            match self
                .post_json("/v1/customer-portal/license-keys/validate", body)
                .await
            {
                Ok((status, bytes)) if status.is_success() => {
                    let v: serde_json::Value = match serde_json::from_slice(&bytes) {
                        Ok(v) => v,
                        Err(e) => return ValidateOutcome::Unavailable(e.to_string()),
                    };
                    if v["status"].as_str() == Some("granted") {
                        ValidateOutcome::Granted {
                            customer_id: v["customer_id"].as_str().unwrap_or_default().to_owned(),
                            benefit_id: v["benefit_id"].as_str().unwrap_or_default().to_owned(),
                        }
                    } else {
                        ValidateOutcome::NotLicensed
                    }
                }
                Ok((status, _)) if status.as_u16() == 429 || status.is_server_error() => {
                    ValidateOutcome::Unavailable(format!("polar validate: {status}"))
                }
                Ok(_) => ValidateOutcome::NotLicensed,
                Err(e) => ValidateOutcome::Unavailable(e),
            }
        })
    }

    fn activate<'a>(
        &'a self,
        key: &'a str,
        label: &'a str,
    ) -> Pin<Box<dyn Future<Output = ActivateOutcome> + Send + 'a>> {
        Box::pin(async move {
            let body = serde_json::json!({"key": key, "organization_id": ORG, "label": label});
            match self
                .post_json("/v1/customer-portal/license-keys/activate", body)
                .await
            {
                Ok((status, bytes)) if status.is_success() => {
                    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                    match v["id"].as_str() {
                        Some(id) => ActivateOutcome::Activated {
                            activation_id: id.to_owned(),
                        },
                        None => ActivateOutcome::Unavailable("bad activate body".into()),
                    }
                }
                Ok((status, _)) if status == StatusCode::FORBIDDEN => ActivateOutcome::LimitReached,
                Ok((status, _)) => {
                    ActivateOutcome::Unavailable(format!("polar activate: {status}"))
                }
                Err(e) => ActivateOutcome::Unavailable(e),
            }
        })
    }

    fn deactivate<'a>(
        &'a self,
        key: &'a str,
        activation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let body = serde_json::json!({
                "key": key, "organization_id": ORG, "activation_id": activation_id
            });
            match self
                .post_json("/v1/customer-portal/license-keys/deactivate", body)
                .await
            {
                Ok((status, _)) if status.is_success() => Ok(()),
                Ok((status, _)) => Err(format!("polar deactivate: {status}")),
                Err(e) => Err(e),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Relay + daemon-session plumbing (same shape as tests/conn_cap.rs).
// ---------------------------------------------------------------------------

/// A private directory under the system temp dir; there is no `tempfile` in
/// this workspace, and the license cache must be a real file so the test can
/// open a second handle to it and age rows.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("etun-polar-e2e-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
        limits: LimitsConfig {
            // Drive the live re-validation loop on a 1s cadence so the test can
            // observe the production trigger (a key re-validating on its own
            // schedule) instead of simulating it.
            token_revalidate_interval_secs: 1,
            ..Default::default()
        },
    })
}

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

/// A live daemon control session: real TLS + WebSocket upgrade + yamux, held
/// open until dropped.
struct Session {
    ctrl: tokio_util::compat::Compat<yamux::Stream>,
    cancel: CancellationToken,
    _driver: tokio::task::JoinHandle<()>,
}

impl Session {
    async fn open(addr: SocketAddr, cfg: Arc<ClientConfig>, token: &str) -> Self {
        let tcp = TcpStream::connect(addr).await.expect("tcp connect");
        tcp.set_nodelay(true).ok();
        let tls = TlsConnector::from(cfg)
            .connect(ServerName::try_from(CONNECT_HOST.to_owned()).unwrap(), tcp)
            .await
            .expect("tls handshake");
        let mux = mux_io_client(tls, &format!("wss://{CONNECT_HOST}/connect"))
            .await
            .expect("ws upgrade");
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

        let mut me = Self {
            ctrl: ctrl.compat(),
            cancel,
            _driver: driver,
        };
        codec::write_preamble(&mut me.ctrl).await.unwrap();
        me.send(ControlFrame::Hello {
            token: Secret::from(token),
            agent_version: "sandbox-e2e".into(),
            proto_min: 1,
            proto_max: ethertunnel_proto::PROTOCOL_VERSION,
        })
        .await;
        match me.recv().await {
            ControlFrame::Welcome { .. } => {}
            other => panic!("expected Welcome, got {other:?}"),
        }
        me
    }

    async fn send(&mut self, frame: ControlFrame) {
        codec::write_frame(&mut self.ctrl, &frame, MAX_CONTROL_FRAME)
            .await
            .unwrap();
    }

    async fn recv(&mut self) -> ControlFrame {
        tokio::time::timeout(
            Duration::from_secs(10),
            codec::read_frame::<_, ControlFrame>(&mut self.ctrl, MAX_CONTROL_FRAME),
        )
        .await
        .expect("control frame timed out")
        .unwrap()
    }

    /// Read past unsolicited relay→daemon traffic (prune notices, heartbeats)
    /// to the reply this call is actually waiting for.
    async fn recv_matching(&mut self, want: fn(&ControlFrame) -> bool) -> ControlFrame {
        for _ in 0..16 {
            let frame = self.recv().await;
            if want(&frame) {
                return frame;
            }
        }
        panic!("expected frame never arrived");
    }

    async fn claim(&mut self, host: &str) -> ControlFrame {
        self.send(ControlFrame::Claim {
            hostnames: vec![host.to_owned()],
            tcp_ports: vec![],
        })
        .await;
        self.recv_matching(|f| {
            matches!(
                f,
                ControlFrame::Granted { .. } | ControlFrame::Denied { .. }
            )
        })
        .await
    }

    async fn list_owned(&mut self) -> (Vec<String>, Option<i64>) {
        self.send(ControlFrame::ListOwned).await;
        match self
            .recv_matching(|f| matches!(f, ControlFrame::Owned { .. }))
            .await
        {
            ControlFrame::Owned {
                hostnames,
                max_tunnels,
                ..
            } => (hostnames, max_tunnels),
            other => unreachable!("{other:?}"),
        }
    }

    /// Round-trip a Ping. The session's re-validation tick and its control-frame
    /// read live in the same `select!`, so a Pong can only be produced after an
    /// in-flight tick (and the cap reconciliation inside it) has finished — this
    /// is the barrier that makes the assertions below race-free.
    async fn barrier(&mut self) {
        self.send(ControlFrame::Ping { nonce: 7 }).await;
        self.recv_matching(|f| matches!(f, ControlFrame::Pong { nonce: 7 }))
            .await;
    }
}

/// Rewrite a cached row's `validated_at` through a second handle on the same
/// database file. Equivalent to letting wall-clock time pass, but instant and
/// deterministic.
fn age_key(cache: &LicenseCache, key: &str, validated_at: i64) {
    let hash = Sha256::digest(key.as_bytes()).to_vec();
    let mut row = cache
        .get(&hash)
        .expect("cache read")
        .expect("key has a cached row");
    row.validated_at = validated_at;
    cache.upsert(&row).expect("cache write");
}

async fn await_validate(state: &MockState, key: &str, at_least: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while state.validate_count(key) < at_least {
        assert!(
            std::time::Instant::now() < deadline,
            "no validate round-trip for {key} within 20s"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn owned(registry: &Registry) -> Vec<String> {
    let uid = registry
        .lookup_user_id(CUSTOMER)
        .unwrap()
        .expect("account provisioned from the Polar customer id");
    registry.owned_hostnames(uid).unwrap()
}

// ---------------------------------------------------------------------------

/// One customer, two keys, two tunnels: the small key's scheduled
/// re-validation must not evict what the big key pays for, and the claim gate
/// must report the pooled cap. Then the negative control: once the big key's
/// row ages past the prune grace, the prune does fire and the pool collapses
/// to the small key's cap.
///
/// Pre-fix this fails twice over — the second claim is denied at `cap_for`,
/// and the CortexMind key's re-validation prunes the Team tunnel.
#[tokio::test]
async fn pooled_cap_survives_small_key_revalidation_then_prunes_on_real_downgrade() {
    let dir = TempDir::new();
    let mock = start_mock_polar(&[
        (TEAM_KEY, CUSTOMER, TEAM_BENEFIT),
        (CM_KEY, CUSTOMER, CM_BENEFIT),
    ])
    .await;

    let registry = Arc::new(Registry::open(dir.join("registry.db"), DOMAIN).unwrap());
    let router = Arc::new(Router::new());
    let cache_path = dir.join("polar-cache.db");
    let gate = Arc::new(PolarGate::new(
        LicenseCache::open(&cache_path).unwrap(),
        PolarPolicy {
            organization_id: ORG.to_owned(),
            cache_ttl_secs: CACHE_TTL_SECS,
            staleness_secs: STALENESS_SECS,
            cap_prune_grace_secs: CAP_PRUNE_GRACE_SECS,
            activate_on_claim: true,
            benefits: HashMap::from([
                (TEAM_BENEFIT.to_owned(), TEAM_CAP),
                (CM_BENEFIT.to_owned(), CM_CAP),
            ]),
            max_validate_per_sec: 10,
            validate_burst: 30,
        },
        Box::new(LoopbackPolarBackend::new(mock.base_url.clone())),
    ));
    gate.set_reconciler(Arc::new(Reconciler {
        registry: registry.clone(),
        router: router.clone(),
        domain: DOMAIN.to_owned(),
    }));
    let ctx = SessionCtx::new(router.clone(), registry.clone(), "sandbox-relay".into());
    ctx.set_polar(gate);

    let relay: RelayHandle = serve_with(relay_config("127.0.0.1:0".parse().unwrap()), ctx, None)
        .await
        .expect("relay starts");
    let addr = relay.local_addr;
    let tls_cfg = client_config(relay.cert_der.as_ref().expect("self-signed cert"));

    // A second handle on the same cache file, used to age rows.
    let cache = LicenseCache::open(&cache_path).unwrap();

    // -- 1. The CortexMind daemon (cap 1) connects and claims its one tunnel.
    let mut cm = Session::open(addr, tls_cfg.clone(), CM_KEY).await;
    assert!(matches!(
        cm.claim(HOST_FIRST).await,
        ControlFrame::Granted { .. }
    ));

    // -- 2. The Team daemon (cap 30), same customer, claims a second tunnel.
    //       Both keys resolve to ONE registry account and ONE pool.
    let mut team = Session::open(addr, tls_cfg.clone(), TEAM_KEY).await;
    assert!(matches!(
        team.claim(HOST_SECOND).await,
        ControlFrame::Granted { .. }
    ));
    assert_eq!(owned(&registry), vec![HOST_FIRST, HOST_SECOND]);
    assert!(router.lookup_http(HOST_FIRST).is_some());
    assert!(router.lookup_http(HOST_SECOND).is_some());

    // -- 3. The small key's cached validation expires, so its next scheduled
    //       re-validation is a real round-trip to Polar. This is the exact
    //       moment the pre-fix relay pruned the Team tunnel.
    age_key(&cache, CM_KEY, now_unix() - CACHE_TTL_SECS - 1);
    await_validate(&mock.state, CM_KEY, 2).await;
    cm.barrier().await;

    assert_eq!(
        owned(&registry),
        vec![HOST_FIRST, HOST_SECOND],
        "the small key's re-validation must not evict the big key's tunnel"
    );
    assert!(router.lookup_http(HOST_SECOND).is_some(), "route torn down");
    let (hosts, cap) = cm.list_owned().await;
    assert_eq!(hosts, vec![HOST_FIRST, HOST_SECOND]);
    assert_eq!(
        cap,
        Some(TEAM_CAP),
        "the claim gate must report the pooled cap, not the presenting key's"
    );

    // -- 4. And the pooled cap is enforced, not merely reported: the small key
    //       can claim a third tunnel because the pool allows 30.
    assert!(matches!(
        cm.claim(HOST_THIRD).await,
        ControlFrame::Granted { .. }
    ));
    assert_eq!(owned(&registry), vec![HOST_FIRST, HOST_SECOND, HOST_THIRD]);

    // -- 5. Negative control: a genuine downgrade. The Team daemon goes away
    //       and its key is never presented again, so nothing can re-validate
    //       it; once its row ages past the prune grace it stops backing the
    //       pool, and the next re-validation of the small key must prune.
    team.cancel.cancel();
    drop(team);
    let now = now_unix();
    age_key(&cache, TEAM_KEY, now - CAP_PRUNE_GRACE_SECS - 1);
    age_key(&cache, CM_KEY, now - CACHE_TTL_SECS - 1);
    await_validate(&mock.state, CM_KEY, 3).await;
    cm.barrier().await;

    assert_eq!(
        owned(&registry),
        vec![HOST_FIRST],
        "a real downgrade must still prune to the surviving key's cap, oldest kept"
    );
    assert!(
        router.lookup_http(HOST_THIRD).is_none(),
        "the pruned tunnel's live route must be torn down"
    );
    assert!(router.lookup_http(HOST_FIRST).is_some());
    let (hosts, cap) = cm.list_owned().await;
    assert_eq!(hosts, vec![HOST_FIRST]);
    assert_eq!(cap, Some(CM_CAP));

    assert_eq!(
        mock.state.activate_calls.load(Ordering::Relaxed),
        2,
        "each key activates once (device binding), and never again"
    );
    assert!(
        mock.state.violations.lock().unwrap().is_empty(),
        "malformed requests reached the mock Polar API: {:?}",
        mock.state.violations.lock().unwrap()
    );

    cm.cancel.cancel();
    relay.shutdown();
}
