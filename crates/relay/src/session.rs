//! Per-daemon session: drives one yamux connection and its control protocol.
//!
//! Topology (one daemon = one of these):
//!
//! * **Actor** (`run_session`) owns the yamux `Connection`. It must be polled
//!   continuously to drive *all* stream I/O, so it loops on `poll_next_inbound`.
//!   The daemon opens exactly one inbound stream (the control stream); a second
//!   inbound stream is a protocol violation. Outbound data streams (relay →
//!   daemon) arrive in M3.
//! * **Control task** owns the control stream. It performs the handshake
//!   (writing Welcome/Denied *directly*, so those are never lost to a teardown
//!   race), then hands the write half to a **writer task** and loops reading
//!   Claim/Ping/Goodbye, enforcing the heartbeat dead-man via a read timeout.
//! * **Writer task** owns the write half after the handshake and is the single
//!   writer for all asynchronously-pushed frames (Pong, Granted, Superseded),
//!   so writes never race.
//!
//! A [`CancellationToken`] ties their lifetimes together: when the control task
//! ends (dead-man, EOF, or error) it cancels, the actor stops driving, and the
//! connection drops.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ethertunnel_proto::codec::{self, CodecError};
use ethertunnel_proto::frames::{ControlFrame, DenyCode, StreamHeader};
use ethertunnel_proto::limits::{
    HELLO_TIMEOUT, MAX_CONTROL_FRAME, MAX_STREAM_HEADER, SESSION_DEAD_AFTER,
};
use ethertunnel_proto::transport::MuxIo;
use ethertunnel_proto::PROTOCOL_VERSION;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

use crate::auth::Authenticator;
use crate::router::{Router, SessionHandle};

/// A multiplexed byte stream to the daemon, tokio-flavored, with its preamble
/// already written. The proxy paths read/write opaque bytes on it.
pub type DataStream = Compat<yamux::Stream>;

/// Why opening a data stream to the daemon failed.
#[derive(Debug)]
pub enum OpenError {
    /// The session is gone (daemon disconnected, or shutting down).
    SessionClosed,
    /// The actor did not produce the stream in time.
    Timeout,
    /// The multiplexer refused (e.g. stream limit reached).
    Mux,
}

/// Commands the session actor services (it owns the yamux connection, so all
/// outbound-stream opens must go through it).
pub enum SessionCmd {
    OpenStream {
        header: StreamHeader,
        reply: oneshot::Sender<Result<DataStream, OpenError>>,
    },
}

/// Shared relay state handed to every session.
pub struct SessionCtx {
    pub router: Arc<Router>,
    pub auth: Arc<dyn Authenticator>,
    pub server_version: String,
    /// Raw-TCP port manager, installed by `serve` once the relay's listener and
    /// shutdown token exist. `None` means TCP tunnels are unavailable (tests,
    /// or before installation), and TCP claims are denied.
    pub tcp: arc_swap::ArcSwapOption<crate::tcp::TcpPortManager>,
    /// keygate entitlement gate, installed by `serve` when `[keygate]` is
    /// configured. `None` means no enforcement (self-host / pre-billing): every
    /// owned claim is allowed, exactly as before this integration.
    pub entitlements: arc_swap::ArcSwapOption<crate::entitlement::EntitlementGate>,
    /// keygate-authed provisioning control plane, installed by `run_serve` when
    /// `[provision]` is configured. `None` means the `/admin/*` provisioning
    /// endpoints are not mounted (the relay has no inbound control API).
    pub provision: arc_swap::ArcSwapOption<crate::admin_http::ProvisionState>,
    next_session_id: AtomicU64,
}

impl SessionCtx {
    pub fn new(
        router: Arc<Router>,
        auth: Arc<dyn Authenticator>,
        server_version: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            auth,
            server_version,
            tcp: arc_swap::ArcSwapOption::empty(),
            entitlements: arc_swap::ArcSwapOption::empty(),
            provision: arc_swap::ArcSwapOption::empty(),
            next_session_id: AtomicU64::new(1),
        })
    }

    /// Install the keygate provisioning control plane (called by `run_serve`
    /// when `[provision]` is configured).
    pub fn set_provision(&self, state: Arc<crate::admin_http::ProvisionState>) {
        self.provision.store(Some(state));
    }

    /// Install the raw-TCP port manager (called by `serve`).
    pub fn set_tcp(&self, manager: Arc<crate::tcp::TcpPortManager>) {
        self.tcp.store(Some(manager));
    }

    /// Install the keygate entitlement gate (called by `run_serve` when
    /// `[keygate]` is configured).
    pub fn set_entitlements(&self, gate: Arc<crate::entitlement::EntitlementGate>) {
        self.entitlements.store(Some(gate));
    }

    fn next_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// Pick the highest protocol version we and the peer both support, if any.
fn negotiate(peer_min: u16, peer_max: u16) -> Option<u16> {
    let v = peer_max.min(PROTOCOL_VERSION);
    (v >= peer_min && v >= 1).then_some(v)
}

/// Drive one daemon connection until it closes. Assigns the session id, waits
/// for the control stream, and cleans up the routing table on exit. `shutdown`
/// is the relay-wide token: when it fires (graceful shutdown / restart) the
/// session tears down, which the daemon sees as a disconnect and reconnects.
pub async fn run_session<T>(
    mut conn: yamux::Connection<MuxIo<T>>,
    ctx: Arc<SessionCtx>,
    shutdown: CancellationToken,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session_id = ctx.next_id();
    let cancel = shutdown.child_token();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<SessionCmd>(64);
    let mut control_started = false;
    // A command whose `poll_new_outbound` returned Pending; retried before we
    // accept any new command (so opens are served in order, one at a time).
    let mut pending_open: Option<SessionCmd> = None;

    // Pre-auth deadline: a peer that completes the WebSocket upgrade but never
    // opens the control stream would otherwise park this actor (and its yamux
    // connection) indefinitely, since `control_started` never flips. Tear the
    // session down if no control stream arrives within HELLO_TIMEOUT. Once the
    // stream is up, the handshake/heartbeat timeouts in `control_task` take over.
    let control_deadline = tokio::time::sleep(HELLO_TIMEOUT);
    tokio::pin!(control_deadline);

    tracing::debug!(session_id, "session started");
    loop {
        // The inbound/outbound/command sources all need `&mut conn`, so they
        // share one manual `poll_fn`; cancellation is a separate `select!`
        // branch so its waker is registered properly (a bare `is_cancelled()`
        // check inside the poll would never be re-polled on cancel).
        let event = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = &mut control_deadline, if !control_started => {
                tracing::debug!(session_id, "no control stream before deadline; closing");
                break;
            }
            ev = std::future::poll_fn(|cx| {
                // Finish a pending outbound open first.
                if pending_open.is_some() {
                    if let std::task::Poll::Ready(result) = conn.poll_new_outbound(cx) {
                        return std::task::Poll::Ready(Event::Opened(result));
                    }
                }
                // Drive inbound (control stream / protocol violations / close).
                if let std::task::Poll::Ready(inbound) = conn.poll_next_inbound(cx) {
                    return std::task::Poll::Ready(Event::Inbound(inbound));
                }
                // Accept a new open command only when not already busy with one.
                if pending_open.is_none() {
                    if let std::task::Poll::Ready(Some(cmd)) = cmd_rx.poll_recv(cx) {
                        return std::task::Poll::Ready(Event::Command(cmd));
                    }
                }
                std::task::Poll::Pending
            }) => ev,
        };

        match event {
            Event::Inbound(Some(Ok(stream))) if !control_started => {
                control_started = true;
                spawn_control(
                    stream,
                    ctx.clone(),
                    session_id,
                    cmd_tx.clone(),
                    cancel.clone(),
                );
            }
            Event::Inbound(Some(Ok(_extra))) => {
                tracing::warn!(session_id, "daemon opened a second stream; closing");
                break;
            }
            Event::Inbound(Some(Err(e))) => {
                tracing::debug!(session_id, error = %e, "connection error");
                break;
            }
            Event::Inbound(None) => {
                tracing::debug!(session_id, "connection closed");
                break;
            }
            Event::Command(cmd) => {
                pending_open = Some(cmd); // serviced on the next poll
            }
            Event::Opened(result) => {
                let Some(SessionCmd::OpenStream { header, reply }) = pending_open.take() else {
                    continue;
                };
                match result {
                    Ok(stream) => {
                        // Write the preamble off-thread so the actor keeps driving.
                        tokio::spawn(async move {
                            let mut io = stream.compat();
                            match codec::write_frame(&mut io, &header, MAX_STREAM_HEADER).await {
                                Ok(()) => {
                                    let _ = reply.send(Ok(io));
                                }
                                Err(_) => {
                                    let _ = reply.send(Err(OpenError::Mux));
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!(session_id, error = %e, "open_new_outbound failed");
                        let _ = reply.send(Err(OpenError::Mux));
                    }
                }
            }
        }
    }

    cancel.cancel();
    ctx.router.remove_session(session_id);
    tracing::debug!(session_id, "session ended");
}

/// Internal actor wake-up reasons.
enum Event {
    Inbound(Option<Result<yamux::Stream, yamux::ConnectionError>>),
    Command(SessionCmd),
    Opened(Result<yamux::Stream, yamux::ConnectionError>),
}

/// Spawn the control + writer tasks for a freshly accepted control stream.
fn spawn_control(
    stream: yamux::Stream,
    ctx: Arc<SessionCtx>,
    session_id: u64,
    cmd_tx: mpsc::Sender<SessionCmd>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let (mut rd, wr) = tokio::io::split(stream.compat());
        if let Err(e) = control_task(&mut rd, wr, &ctx, session_id, &cmd_tx, &cancel).await {
            if !e.is_eof() {
                tracing::debug!(session_id, error = %e, "control task error");
            }
        }
        cancel.cancel();
    });
}

/// Read the handshake, then run the steady-state control loop.
async fn control_task(
    rd: &mut ReadHalf<Compat<yamux::Stream>>,
    mut wr: WriteHalf<Compat<yamux::Stream>>,
    ctx: &Arc<SessionCtx>,
    session_id: u64,
    cmd_tx: &mpsc::Sender<SessionCmd>,
    cancel: &CancellationToken,
) -> Result<(), CodecError> {
    // --- Handshake (writes go directly to `wr`, so they can't be lost) ---
    // Preamble validates the magic and tells us the peer's protocol version.
    let _peer_proto = match tokio::time::timeout(HELLO_TIMEOUT, codec::read_preamble(rd)).await {
        Ok(r) => r?,
        Err(_) => return Ok(()), // handshake timeout: just drop
    };

    let hello = match tokio::time::timeout(
        HELLO_TIMEOUT,
        codec::read_frame::<_, ControlFrame>(rd, MAX_CONTROL_FRAME),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => return Ok(()),
    };

    let (token, proto_min, proto_max) = match hello {
        ControlFrame::Hello {
            token,
            proto_min,
            proto_max,
            ..
        } => (token, proto_min, proto_max),
        _ => {
            deny(rd, &mut wr, DenyCode::ProtocolError, "expected Hello").await?;
            return Ok(());
        }
    };

    let Some(proto) = negotiate(proto_min, proto_max) else {
        deny(
            rd,
            &mut wr,
            DenyCode::VersionUnsupported,
            &format!("relay speaks protocol {PROTOCOL_VERSION}"),
        )
        .await?;
        return Ok(());
    };

    let Some(user) = ctx.auth.authenticate(token.expose()) else {
        deny(rd, &mut wr, DenyCode::AuthFailed, "authentication failed").await?;
        return Ok(());
    };

    // Steady state: hand `wr` to a single writer task; push frames via channel.
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<ControlFrame>(64);
    spawn_writer(wr, ctrl_rx, cancel.clone());

    let handle = SessionHandle::new(session_id, user.user_id, ctrl_tx.clone(), cmd_tx.clone());
    let _ = ctrl_tx
        .send(ControlFrame::Welcome {
            proto,
            server_version: ctx.server_version.clone(),
            session_id,
        })
        .await;
    tracing::info!(session_id, user = %user.name, proto, "session authenticated");

    // --- Steady-state loop with heartbeat dead-man ---
    loop {
        let frame = match tokio::time::timeout(
            SESSION_DEAD_AFTER,
            codec::read_frame::<_, ControlFrame>(rd, MAX_CONTROL_FRAME),
        )
        .await
        {
            Err(_) => {
                tracing::debug!(session_id, "heartbeat dead-man fired");
                return Ok(());
            }
            Ok(Err(e)) if e.is_eof() => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Ok(Ok(f)) => f,
        };

        match frame {
            ControlFrame::Ping { nonce } => {
                let _ = ctrl_tx.send(ControlFrame::Pong { nonce }).await;
            }
            ControlFrame::Claim {
                hostnames,
                tcp_ports,
            } => {
                handle_claim(ctx, &handle, &user, hostnames, tcp_ports, &ctrl_tx).await;
            }
            ControlFrame::Goodbye => return Ok(()),
            ControlFrame::Hello { .. } => {
                let _ = ctrl_tx
                    .send(ControlFrame::Error {
                        code: ethertunnel_proto::frames::ErrorCode::MalformedClaim,
                        message: "duplicate Hello".into(),
                    })
                    .await;
            }
            // Relay→daemon frames must never arrive from the daemon; ignore.
            _ => {}
        }
    }
}

/// Validate and apply a claim (atomic, idempotent), then reply.
async fn handle_claim(
    ctx: &Arc<SessionCtx>,
    handle: &SessionHandle,
    user: &crate::auth::AuthedUser,
    hostnames: Vec<String>,
    tcp_ports: Vec<u16>,
    ctrl_tx: &mpsc::Sender<ControlFrame>,
) {
    // Bound per-claim work: a 64 KiB control frame can pack thousands of tiny
    // entries, each of which we lowercase and ownership-check. Reject oversized
    // claims outright; a daemon needing more sends additional claims.
    if hostnames.len() + tcp_ports.len() > ethertunnel_proto::limits::MAX_CLAIM_ENTRIES {
        let _ = ctrl_tx
            .send(ControlFrame::Denied {
                code: DenyCode::ProtocolError,
                message: format!(
                    "claim too large (max {} entries)",
                    ethertunnel_proto::limits::MAX_CLAIM_ENTRIES
                ),
            })
            .await;
        return;
    }

    let hostnames: Vec<String> = hostnames.iter().map(|h| h.to_ascii_lowercase()).collect();

    let tcp = ctx.tcp.load_full();
    for port in &tcp_ports {
        let Some(manager) = &tcp else {
            let _ = ctrl_tx
                .send(ControlFrame::Denied {
                    code: DenyCode::PortNotReserved,
                    message: "tcp tunnels are not enabled on this relay".into(),
                })
                .await;
            return;
        };
        if !manager.in_range(*port) || !ctx.auth.owns_port(user.user_id, *port) {
            let _ = ctrl_tx
                .send(ControlFrame::Denied {
                    code: DenyCode::PortNotReserved,
                    message: format!("port {port} not reserved"),
                })
                .await;
            return;
        }
        // Bind-before-grant: never route a port we couldn't actually serve.
        if let Err(e) = manager.ensure_bound(*port).await {
            let _ = ctrl_tx
                .send(ControlFrame::Denied {
                    code: DenyCode::PortUnavailable,
                    message: format!("port {port} unavailable: {e}"),
                })
                .await;
            return;
        }
    }

    // keygate entitlement enforcement runs BEFORE any hostname is registered, so
    // we never persist a label the cap would reject (no leaked rows). Fail-open:
    // when no gate is installed, or the customer has no fresh cached entitlement,
    // the claim proceeds. Only an active cap that this claim would exceed (or a
    // suspended account) is denied. The projected count includes the requested
    // hostnames/ports regardless of whether they're already registered, matching
    // the existing "concurrently active tunnels" semantics.
    if let Some(gate) = ctx.entitlements.load_full() {
        use crate::entitlement::{now_unix, CapDecision};
        match gate.cap_for(&user.name, now_unix()) {
            CapDecision::Allow => {}
            CapDecision::DenyAll => {
                let _ = ctrl_tx
                    .send(ControlFrame::Denied {
                        code: DenyCode::LimitExceeded,
                        message: "subscription does not permit new tunnels".into(),
                    })
                    .await;
                return;
            }
            CapDecision::Cap(max) => {
                let projected =
                    ctx.router
                        .projected_tunnel_count(user.user_id, &hostnames, &tcp_ports);
                if projected as i64 > max {
                    let _ = ctrl_tx
                        .send(ControlFrame::Denied {
                            code: DenyCode::LimitExceeded,
                            message: format!(
                                "tunnel limit reached ({max}); upgrade your plan for more"
                            ),
                        })
                        .await;
                    return;
                }
            }
        }
    }

    // Register-or-own each hostname from the global label pool. This runs only
    // after the cap check passed, so a rejected claim never leaves a registered
    // label behind. Self-registration is first-come-first-served: a free label
    // is claimed for this user; one the user already owns is a no-op; one owned
    // by someone else is refused. When no real registry backs the authenticator
    // (self-host without provisioning) the default trait impl keeps the legacy
    // "must already own it" behavior.
    //
    // All-or-nothing semantics are preserved relative to *routing*: we register
    // every label before touching the router, and on the first refusal we stop
    // and deny without claiming any route. (Labels registered earlier in this
    // same claim for free remain owned by the user — they are theirs now, just
    // not routed this round; a retry re-grants them idempotently.)
    use crate::auth::ClaimOutcome;
    for host in &hostnames {
        match ctx.auth.claim_hostname(user.user_id, host) {
            ClaimOutcome::Owned => {}
            ClaimOutcome::Taken => {
                let _ = ctrl_tx
                    .send(ControlFrame::Denied {
                        code: DenyCode::NotOwner,
                        message: format!("not authorized for {host}"),
                    })
                    .await;
                return;
            }
            ClaimOutcome::Invalid(why) => {
                let _ = ctrl_tx
                    .send(ControlFrame::Denied {
                        code: DenyCode::NotOwner,
                        message: format!("cannot claim {host}: {why}"),
                    })
                    .await;
                return;
            }
            ClaimOutcome::Error => {
                let _ = ctrl_tx
                    .send(ControlFrame::Denied {
                        code: DenyCode::NotOwner,
                        message: format!("could not register {host}"),
                    })
                    .await;
                return;
            }
        }
    }

    let superseded = ctx.router.claim(handle, &hostnames, &tcp_ports);
    for (old, resource) in superseded {
        old.send_ctrl(ControlFrame::Superseded { resource });
    }
    let _ = ctrl_tx
        .send(ControlFrame::Granted {
            hostnames,
            tcp_ports,
        })
        .await;
}

/// Write a terminal `Denied` frame, then keep the connection alive briefly so
/// the frame actually flushes to the wire and the peer can read it before we
/// tear down. yamux only transmits when the actor keeps polling the connection,
/// so an immediate teardown would drop the buffered frame; the bounded drain
/// read lets it go out while preventing a stuck peer from pinning us.
async fn deny(
    rd: &mut ReadHalf<Compat<yamux::Stream>>,
    wr: &mut WriteHalf<Compat<yamux::Stream>>,
    code: DenyCode,
    message: &str,
) -> Result<(), CodecError> {
    codec::write_frame(
        wr,
        &ControlFrame::Denied {
            code,
            message: message.to_owned(),
        },
        MAX_CONTROL_FRAME,
    )
    .await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 64];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    Ok(())
}

/// The single writer task: drains pushed control frames to the write half.
/// Exits when all senders drop (session over) or a write fails.
fn spawn_writer(
    mut wr: WriteHalf<Compat<yamux::Stream>>,
    mut ctrl_rx: mpsc::Receiver<ControlFrame>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        while let Some(frame) = ctrl_rx.recv().await {
            if codec::write_frame(&mut wr, &frame, MAX_CONTROL_FRAME)
                .await
                .is_err()
            {
                break;
            }
        }
        cancel.cancel();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::MemoryAuth;
    use ethertunnel_proto::frames::{Resource, Secret};
    use ethertunnel_proto::transport::{mux_connection, mux_io, Role};
    use futures::future::poll_fn;

    type Ctrl = Compat<yamux::Stream>;

    /// Stand up a relay session over an in-memory duplex and return the fake
    /// daemon's control stream (compat-wrapped for the tokio codec).
    async fn connect(ctx: Arc<SessionCtx>) -> Ctrl {
        let (a, b) = tokio::io::duplex(64 * 1024);

        // Relay side.
        let relay_io = mux_io(b, Role::Server).await;
        let relay_conn = mux_connection(relay_io, yamux::Mode::Server);
        tokio::spawn(run_session(relay_conn, ctx, CancellationToken::new()));

        // Daemon side: open the control stream, then drive the connection.
        let daemon_io = mux_io(a, Role::Client).await;
        let mut daemon_conn = mux_connection(daemon_io, yamux::Mode::Client);
        let ctrl = poll_fn(|cx| daemon_conn.poll_new_outbound(cx))
            .await
            .unwrap();
        tokio::spawn(async move {
            while let Some(Ok(_)) = poll_fn(|cx| daemon_conn.poll_next_inbound(cx)).await {}
        });
        ctrl.compat()
    }

    async fn send(ctrl: &mut Ctrl, frame: ControlFrame) {
        codec::write_frame(ctrl, &frame, MAX_CONTROL_FRAME)
            .await
            .unwrap();
    }

    async fn recv(ctrl: &mut Ctrl) -> ControlFrame {
        codec::read_frame(ctrl, MAX_CONTROL_FRAME).await.unwrap()
    }

    fn hello(token: &str) -> ControlFrame {
        ControlFrame::Hello {
            token: Secret::from(token),
            agent_version: "test".into(),
            proto_min: 1,
            proto_max: 1,
        }
    }

    /// Complete the preamble + Hello handshake, returning the session id.
    async fn handshake(ctrl: &mut Ctrl, token: &str) -> u64 {
        codec::write_preamble(ctrl).await.unwrap();
        send(ctrl, hello(token)).await;
        match recv(ctrl).await {
            ControlFrame::Welcome { session_id, .. } => session_id,
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    fn fixture() -> (Arc<SessionCtx>, Arc<Router>, Arc<MemoryAuth>, i64) {
        let auth = Arc::new(MemoryAuth::new());
        let uid = auth.add_user("mat", "etun_good");
        auth.grant_hostname(uid, "myapp.ethertunnel.com");
        auth.grant_port(uid, 20000);
        let router = Arc::new(Router::new());
        let ctx = SessionCtx::new(router.clone(), auth.clone(), "test-relay".into());
        (ctx, router, auth, uid)
    }

    #[tokio::test]
    async fn hello_welcome_claim_granted_ping_pong() {
        let (ctx, router, _auth, _uid) = fixture();
        let mut ctrl = connect(ctx).await;

        let _sid = handshake(&mut ctrl, "etun_good").await;

        // This duplex-based test has no TCP port manager (no listener stack), so
        // it claims only the hostname; raw-TCP claims are covered end-to-end in
        // the e2e suite where a real listener exists.
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["myapp.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        match recv(&mut ctrl).await {
            ControlFrame::Granted { hostnames, .. } => {
                assert_eq!(hostnames, vec!["myapp.ethertunnel.com".to_string()]);
            }
            other => panic!("expected Granted, got {other:?}"),
        }
        assert!(router.lookup_http("myapp.ethertunnel.com").is_some());

        send(&mut ctrl, ControlFrame::Ping { nonce: 99 }).await;
        match recv(&mut ctrl).await {
            ControlFrame::Pong { nonce } => assert_eq!(nonce, 99),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bad_token_is_denied() {
        let (ctx, _router, _auth, _uid) = fixture();
        let mut ctrl = connect(ctx).await;
        codec::write_preamble(&mut ctrl).await.unwrap();
        send(&mut ctrl, hello("etun_wrong")).await;
        match recv(&mut ctrl).await {
            ControlFrame::Denied { code, .. } => assert_eq!(code, DenyCode::AuthFailed),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn claim_label_owned_by_another_user_is_denied() {
        // A label already registered to a *different* user must be refused —
        // self-registration is first-come-first-served, not a takeover.
        let (ctx, router, auth, _uid) = fixture();
        let eve = auth.add_user("eve", "etun_eve");
        auth.grant_hostname(eve, "taken.ethertunnel.com");

        let mut ctrl = connect(ctx).await;
        handshake(&mut ctrl, "etun_good").await;
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["taken.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        match recv(&mut ctrl).await {
            ControlFrame::Denied { code, .. } => assert_eq!(code, DenyCode::NotOwner),
            other => panic!("expected Denied, got {other:?}"),
        }
        // The route is not stolen from eve.
        assert!(router.lookup_http("taken.ethertunnel.com").is_none());
    }

    #[tokio::test]
    async fn claim_free_label_auto_registers_and_is_granted() {
        // A label nobody owns is self-registered to the claimant and routed.
        let (ctx, router, auth, uid) = fixture();
        let mut ctrl = connect(ctx).await;
        handshake(&mut ctrl, "etun_good").await;
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["brandnew.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        match recv(&mut ctrl).await {
            ControlFrame::Granted { hostnames, .. } => {
                assert_eq!(hostnames, vec!["brandnew.ethertunnel.com".to_string()]);
            }
            other => panic!("expected Granted, got {other:?}"),
        }
        assert!(router.lookup_http("brandnew.ethertunnel.com").is_some());
        // And it is now owned by the claimant.
        assert!(auth.owns_hostname(uid, "brandnew.ethertunnel.com"));
    }

    #[tokio::test]
    async fn claim_exceeding_cap_is_denied_and_label_not_registered() {
        use crate::entitlement::{
            Entitlement, EntitlementCache, EntitlementGate, KeygatePolicy,
        };
        let (ctx, router, auth, _uid) = fixture();

        // Install a gate capping "mat" at 1 concurrent tunnel.
        let cache = EntitlementCache::open_in_memory().unwrap();
        cache
            .upsert(&Entitlement {
                external_ref: "mat".into(),
                customer_id: 1,
                max_tunnels: Some(1),
                status: "active".into(),
                issued_at: 0,
                expires_at: i64::MAX,
                updated_at: 0,
            })
            .unwrap();
        let gate = EntitlementGate::new(
            cache,
            KeygatePolicy {
                product: "ethertunnel".into(),
                public_key_b64: String::new(),
                key_id: "k1".into(),
                staleness_ceiling_secs: 0,
                require_entitlement: false,
            },
        );
        ctx.set_entitlements(Arc::new(gate));

        let mut ctrl = connect(ctx).await;
        handshake(&mut ctrl, "etun_good").await;
        // Two free labels in one claim → projected 2 > cap 1 → denied.
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["one.ethertunnel.com".into(), "two.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        match recv(&mut ctrl).await {
            ControlFrame::Denied { code, .. } => assert_eq!(code, DenyCode::LimitExceeded),
            other => panic!("expected Denied(LimitExceeded), got {other:?}"),
        }
        // Crucially, neither label leaked into the registry: the cap check runs
        // before self-registration.
        assert!(!auth.owns_hostname(_uid, "one.ethertunnel.com"));
        assert!(!auth.owns_hostname(_uid, "two.ethertunnel.com"));
        assert!(router.lookup_http("one.ethertunnel.com").is_none());
    }

    #[tokio::test]
    async fn oversized_claim_is_denied() {
        use ethertunnel_proto::limits::MAX_CLAIM_ENTRIES;
        let (ctx, router, _auth, _uid) = fixture();
        let mut ctrl = connect(ctx).await;
        handshake(&mut ctrl, "etun_good").await;
        // One past the cap; all bogus, but the cap check fires before ownership.
        let hostnames: Vec<String> = (0..=MAX_CLAIM_ENTRIES)
            .map(|i| format!("h{i}.ethertunnel.com"))
            .collect();
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames,
                tcp_ports: vec![],
            },
        )
        .await;
        match recv(&mut ctrl).await {
            ControlFrame::Denied { code, .. } => assert_eq!(code, DenyCode::ProtocolError),
            other => panic!("expected Denied(ProtocolError), got {other:?}"),
        }
        assert!(router.lookup_http("h0.ethertunnel.com").is_none());
    }

    #[tokio::test]
    async fn newest_session_supersedes_and_old_is_notified() {
        let (ctx, router, _auth, _uid) = fixture();

        let mut d1 = connect(ctx.clone()).await;
        let _s1 = handshake(&mut d1, "etun_good").await;
        send(
            &mut d1,
            ControlFrame::Claim {
                hostnames: vec!["myapp.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        assert!(matches!(recv(&mut d1).await, ControlFrame::Granted { .. }));

        let mut d2 = connect(ctx.clone()).await;
        let s2 = handshake(&mut d2, "etun_good").await;
        send(
            &mut d2,
            ControlFrame::Claim {
                hostnames: vec!["myapp.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        assert!(matches!(recv(&mut d2).await, ControlFrame::Granted { .. }));

        // d1 must be told it lost the hostname.
        match recv(&mut d1).await {
            ControlFrame::Superseded { resource } => {
                assert_eq!(resource, Resource::Host("myapp.ethertunnel.com".into()));
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
        // The route now points at the newer session.
        assert_eq!(
            router
                .lookup_http("myapp.ethertunnel.com")
                .unwrap()
                .session_id,
            s2
        );
    }

    /// With no heartbeat, the relay's dead-man closes the session after
    /// SESSION_DEAD_AFTER. Paused time auto-advances to fire it.
    #[tokio::test(start_paused = true)]
    async fn silent_session_hits_deadman() {
        let (ctx, router, _auth, _uid) = fixture();
        let mut ctrl = connect(ctx).await;
        handshake(&mut ctrl, "etun_good").await;
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["myapp.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        assert!(matches!(
            recv(&mut ctrl).await,
            ControlFrame::Granted { .. }
        ));

        // Go silent. The dead-man should close the control stream; our next read
        // returns an error (EOF/connection closed) once virtual time advances.
        let res = codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME).await;
        assert!(res.is_err(), "expected dead-man close, got {res:?}");
        // And the route is released.
        assert!(router.lookup_http("myapp.ethertunnel.com").is_none());
    }
}
