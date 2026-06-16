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
    TOKEN_REVALIDATE_INTERVAL,
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
    /// Caps concurrent *live* daemon control sessions (global + per-/64), held
    /// for each session's whole lifetime. Separate from the accept-time
    /// ConnLimiter (which the move-only ConnPermit can't reach inside the `Fn`
    /// service): the upgrade path acquires a permit here, before spawning
    /// `run_session`, and refuses with 503 when exhausted. `None` (the default,
    /// e.g. tests with no listener) means unlimited live sessions.
    pub session_limiter: arc_swap::ArcSwapOption<crate::ratelimit::ConnLimiter>,
    /// How often an established control session re-validates its bearer token so
    /// an admin revocation takes effect within one interval. `Duration::ZERO`
    /// disables re-validation (revocation then only takes effect at reconnect).
    /// Defaults to [`TOKEN_REVALIDATE_INTERVAL`]; `serve` overrides from config.
    pub token_revalidate_interval: std::sync::atomic::AtomicU64,
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
            session_limiter: arc_swap::ArcSwapOption::empty(),
            token_revalidate_interval: AtomicU64::new(TOKEN_REVALIDATE_INTERVAL.as_millis() as u64),
            next_session_id: AtomicU64::new(1),
        })
    }

    /// Install the live-session limiter (called by `serve` once the configured
    /// caps are known). Until installed, live sessions are unbounded.
    pub fn set_session_limiter(&self, limiter: Arc<crate::ratelimit::ConnLimiter>) {
        self.session_limiter.store(Some(limiter));
    }

    /// Set the token re-validation cadence (seconds; 0 disables). Called by
    /// `serve` from `token_revalidate_interval_secs`.
    pub fn set_token_revalidate_interval_secs(&self, secs: u64) {
        self.token_revalidate_interval
            .store(secs.saturating_mul(1000), Ordering::Relaxed);
    }

    fn token_revalidate_interval(&self) -> Duration {
        Duration::from_millis(self.token_revalidate_interval.load(Ordering::Relaxed))
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

    // --- Steady-state loop with heartbeat dead-man + token re-validation ---
    // The read future carries the 90s silence dead-man; a separate interval ticks
    // the bearer-token re-check so an admin `token revoke` (or user deletion)
    // takes effect within one interval instead of persisting until the daemon
    // voluntarily disconnects. The interval branch must NOT consume the read
    // future (it runs concurrently and the read resumes after each tick).
    let revalidate = ctx.token_revalidate_interval();
    let mut revalidate_tick = tokio::time::interval(if revalidate.is_zero() {
        // Disabled: a far-future cadence that effectively never fires.
        Duration::from_secs(60 * 60 * 24 * 365)
    } else {
        revalidate
    });
    revalidate_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first immediate tick is consumed up front so we don't re-auth instantly.
    revalidate_tick.tick().await;
    loop {
        let read = tokio::time::timeout(
            SESSION_DEAD_AFTER,
            codec::read_frame::<_, ControlFrame>(rd, MAX_CONTROL_FRAME),
        );
        tokio::pin!(read);
        let frame = loop {
            tokio::select! {
                biased;
                r = &mut read => break r,
                _ = revalidate_tick.tick(), if !revalidate.is_zero() => {
                    // Re-resolve the token. None (revoked/deleted) or a different
                    // user_id (token reissued to another user) => terminate.
                    match ctx.auth.authenticate(token.expose()) {
                        Some(u) if u.user_id == user.user_id => {}
                        _ => {
                            tracing::info!(session_id, "token revoked; closing session");
                            let _ = ctrl_tx
                                .send(ControlFrame::Denied {
                                    code: DenyCode::AuthFailed,
                                    message: "token revoked".into(),
                                })
                                .await;
                            // Best-effort: give the writer task a beat to flush the
                            // Denied to the wire while the actor is still driving
                            // the yamux connection (it only transmits while polled).
                            // Returning immediately would cancel before the flush.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            return Ok(());
                        }
                    }
                    // The token still resolves to this user, but the *entitlement*
                    // may have lapsed (cancelled/suspended) since the session came
                    // up. The claim-time gate only fires on NEW claims, so a
                    // cancelled customer keeps serving on already-routed tunnels
                    // until they disconnect. Consult the gate here on the same
                    // cadence so cancel/suspend stops LIVE traffic within one
                    // interval. This reads only the already-synced, signature-
                    // verified cache (no hot-path keygate call) and respects the
                    // policy's staleness ceiling / require_entitlement semantics:
                    // self-host (no gate installed) and unentitled-but-allowed
                    // users are unaffected (only CapDecision::DenyAll terminates).
                    if let Some(gate) = ctx.entitlements.load_full() {
                        use crate::entitlement::{now_unix, CapDecision};
                        if gate.cap_for(&user.name, now_unix()) == CapDecision::DenyAll {
                            tracing::info!(
                                session_id,
                                user = %user.name,
                                "entitlement lapsed; closing session"
                            );
                            let _ = ctrl_tx
                                .send(ControlFrame::Denied {
                                    code: DenyCode::LimitExceeded,
                                    message: "subscription lapsed or suspended".into(),
                                })
                                .await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            return Ok(());
                        }
                    }
                    continue;
                }
            }
        };
        let frame = match frame {
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
        // TCP ports are admin-granted only (there is no self-service port-claim
        // path), so they are not subject to the self-service `max_tunnels` claim
        // cap that hostnames go through — a user cannot self-inflate the port
        // count past an admin grant. This asymmetry with hostnames is intentional.
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
    // The authoritative cap, when one applies, is enforced against OWNED
    // registry rows inside `claim_hostname` (atomic with the insert). This
    // `cap` carries the active limit through to that call. The projected
    // routed-count check below is only a cheap pre-check that rejects obvious
    // over-claims early; it is NOT authoritative, because routed counts drop to
    // zero on disconnect while owned rows persist (the squatting hole).
    let mut cap: Option<i64> = None;
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
                cap = Some(max);
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
        match ctx.auth.claim_hostname(user.user_id, host, cap) {
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
            ClaimOutcome::CapExceeded => {
                // Authoritative owned-row cap hit: this free label would push the
                // account past its plan limit. Deny in the existing LimitExceeded
                // style; no label was registered (the cap check is inside the
                // insert path).
                let max = cap.unwrap_or_default();
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
        use crate::entitlement::{Entitlement, EntitlementCache, EntitlementGate, KeygatePolicy};
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
    async fn owned_cap_blocks_reclaim_after_disconnect() {
        // The squatting hole: with a cap of 1, claim a label, disconnect (routed
        // count drops to 0 but the owned row persists), then a NEW session tries
        // a DIFFERENT free label. The authoritative owned-row cap inside
        // claim_hostname must deny it even though the routed/projected count is 0.
        use crate::entitlement::{Entitlement, EntitlementCache, EntitlementGate, KeygatePolicy};
        let (ctx, _router, auth, uid) = fixture();

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

        // Simulate the user already owning one label from a prior, now-closed
        // session (MemoryAuth owned rows persist independently of routing).
        auth.grant_hostname(uid, "first.ethertunnel.com");

        // A fresh session claims a DIFFERENT free label. Routed count is 0, so the
        // projected pre-check passes — but the owned-row count is already 1 == cap,
        // so the authoritative check inside claim_hostname denies it.
        let mut ctrl = connect(ctx).await;
        handshake(&mut ctrl, "etun_good").await;
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["second.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        match recv(&mut ctrl).await {
            ControlFrame::Denied { code, .. } => assert_eq!(code, DenyCode::LimitExceeded),
            other => panic!("expected Denied(LimitExceeded), got {other:?}"),
        }
        // The second label never leaked into the owned set.
        assert!(!auth.owns_hostname(uid, "second.ethertunnel.com"));
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

    /// A token revoked AFTER a session is established must terminate that live
    /// session within one re-validation interval — *even while the daemon keeps
    /// heartbeating*. This is the load-bearing scenario: a continuously pinging
    /// daemon resets the 90s silence dead-man on every Ping, so the dead-man can
    /// NEVER fire. The ONLY thing that can end such a session is the token
    /// re-validation tick. We prove that by:
    ///   1. spawning a daemon that Pings every 5s forever (dead-man stays reset),
    ///   2. revoking the token out-of-band,
    ///   3. asserting the route is torn down within ~2x the 10s revalidate
    ///      interval, wrapped in a 40s timeout set WELL BELOW the 90s dead-man.
    ///
    /// On pre-fix code (no re-validation), the heartbeating daemon keeps the
    /// dead-man reset indefinitely, so the route would never drop and this
    /// 40s-bounded wait would time out and FAIL. (finding 13)
    #[tokio::test(start_paused = true)]
    async fn revoked_token_terminates_live_session() {
        let (ctx, router, auth, _uid) = fixture();
        // Tight re-validation cadence so the test fires quickly under paused time.
        const REVALIDATE_SECS: u64 = 10;
        ctx.set_token_revalidate_interval_secs(REVALIDATE_SECS);
        assert!(
            REVALIDATE_SECS * 4 < SESSION_DEAD_AFTER.as_secs(),
            "the bound must sit well below the dead-man or the test wouldn't \
             distinguish revalidation from the dead-man"
        );

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
        assert!(router.lookup_http("myapp.ethertunnel.com").is_some());

        // Spawn a daemon that heartbeats every 5s FOREVER. Each Ping is a read on
        // the relay side, which resets the 90s dead-man — so the dead-man cannot
        // be what ends this session. The task also drains inbound frames (the
        // relay's Pong / the Denied) so the relay writer never stalls. It runs
        // until the relay tears the stream down, at which point the writes/reads
        // error out and the loop exits.
        let heartbeat = tokio::spawn(async move {
            let mut nonce = 0u64;
            loop {
                tokio::select! {
                    biased;
                    // Surface relay->daemon frames (Pong, Denied) and detect close.
                    r = codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME) => {
                        if r.is_err() {
                            break; // stream closed -> session torn down
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        if codec::write_frame(
                            &mut ctrl,
                            &ControlFrame::Ping { nonce },
                            MAX_CONTROL_FRAME,
                        )
                        .await
                        .is_err()
                        {
                            break; // write failed -> stream gone
                        }
                        nonce += 1;
                    }
                }
            }
        });

        // Revoke out-of-band. The next re-validation tick (<=10s away) must kill
        // the session even though the daemon is healthy and heartbeating.
        assert!(auth.revoke("etun_good"));

        // The authoritative effect: the route is released via remove_session. We
        // poll for it, bounded to 40s of virtual time — comfortably more than two
        // revalidate intervals but far below the 90s dead-man. On pre-fix code
        // (no revalidation) this wait can only be satisfied by the dead-man, which
        // the live heartbeat keeps resetting, so it would hit the timeout.
        let torn_down = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if router.lookup_http("myapp.ethertunnel.com").is_none() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await;
        assert!(
            torn_down.is_ok(),
            "revoked session's route must be torn down within ~2x the revalidate \
             interval (well under the dead-man) — a heartbeating revoked session \
             must not survive"
        );

        // The daemon's side observes the stream close shortly after.
        let _ = tokio::time::timeout(Duration::from_secs(5), heartbeat).await;
    }

    /// P1-B: a LIVE session whose entitlement lapses (cancel/suspend) must be
    /// terminated by the in-session revalidation loop within one interval — even
    /// while the daemon keeps heartbeating (the dead-man can never fire on a
    /// pinging daemon). The token stays valid the whole time; only the
    /// entitlement gate flips to DenyAll. We start with an ACTIVE entitlement
    /// (claim succeeds), then swap in a SUSPENDED gate and assert the route is
    /// torn down well under the dead-man.
    #[tokio::test(start_paused = true)]
    async fn lapsed_entitlement_terminates_live_session() {
        use crate::entitlement::{Entitlement, EntitlementCache, EntitlementGate, KeygatePolicy};
        let (ctx, router, _auth, _uid) = fixture();
        const REVALIDATE_SECS: u64 = 10;
        ctx.set_token_revalidate_interval_secs(REVALIDATE_SECS);

        // Active entitlement so the initial claim is granted.
        let install_gate = |status: &str| {
            let cache = EntitlementCache::open_in_memory().unwrap();
            cache
                .upsert(&Entitlement {
                    external_ref: "mat".into(),
                    customer_id: 1,
                    max_tunnels: Some(5),
                    status: status.into(),
                    issued_at: 0,
                    expires_at: i64::MAX,
                    updated_at: 0,
                })
                .unwrap();
            Arc::new(EntitlementGate::new(
                cache,
                KeygatePolicy {
                    product: "ethertunnel".into(),
                    public_key_b64: String::new(),
                    key_id: "k1".into(),
                    staleness_ceiling_secs: 0,
                    require_entitlement: false,
                },
            ))
        };
        ctx.set_entitlements(install_gate("active"));

        let mut ctrl = connect(ctx.clone()).await;
        handshake(&mut ctrl, "etun_good").await;
        send(
            &mut ctrl,
            ControlFrame::Claim {
                hostnames: vec!["myapp.ethertunnel.com".into()],
                tcp_ports: vec![],
            },
        )
        .await;
        assert!(matches!(recv(&mut ctrl).await, ControlFrame::Granted { .. }));
        assert!(router.lookup_http("myapp.ethertunnel.com").is_some());

        // Heartbeat forever so the dead-man stays reset; only the entitlement gate
        // can end this session.
        let heartbeat = tokio::spawn(async move {
            let mut nonce = 0u64;
            loop {
                tokio::select! {
                    biased;
                    r = codec::read_frame::<_, ControlFrame>(&mut ctrl, MAX_CONTROL_FRAME) => {
                        if r.is_err() { break; }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        if codec::write_frame(&mut ctrl, &ControlFrame::Ping { nonce }, MAX_CONTROL_FRAME)
                            .await.is_err() { break; }
                        nonce += 1;
                    }
                }
            }
        });

        // The customer cancels: swap in a SUSPENDED gate (cap_for -> DenyAll).
        ctx.set_entitlements(install_gate("suspended"));

        // The next revalidation tick must tear the route down, bounded to 40s of
        // virtual time (>2 intervals, well below the 90s dead-man).
        let torn_down = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if router.lookup_http("myapp.ethertunnel.com").is_none() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await;
        assert!(
            torn_down.is_ok(),
            "a lapsed/suspended entitlement must terminate the live session within \
             ~2x the revalidate interval (well under the dead-man)"
        );
        let _ = tokio::time::timeout(Duration::from_secs(5), heartbeat).await;
    }

    /// Happy path: a session whose token is NOT revoked survives multiple
    /// re-validation ticks and keeps its route.
    #[tokio::test(start_paused = true)]
    async fn unrevoked_session_survives_revalidation_ticks() {
        let (ctx, router, _auth, _uid) = fixture();
        ctx.set_token_revalidate_interval_secs(10);
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

        // Heartbeat across several revalidation intervals; the session must stay
        // up and the route must remain. (Each Ping resets the dead-man too.)
        for nonce in 0..5u64 {
            tokio::time::sleep(Duration::from_secs(11)).await;
            send(&mut ctrl, ControlFrame::Ping { nonce }).await;
            match recv(&mut ctrl).await {
                ControlFrame::Pong { nonce: n } => assert_eq!(n, nonce),
                other => panic!("expected Pong, got {other:?}"),
            }
        }
        assert!(router.lookup_http("myapp.ethertunnel.com").is_some());
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
