//! The public `:443` listener.
//!
//! One socket serves both visitor traffic and daemon control connections. Per
//! accepted connection: bounded TLS handshake → HTTP/1.1 (the only ALPN we
//! offer) → route by `Host`:
//!
//! * `connect.<domain>` with a WebSocket upgrade → establish a daemon session.
//! * anything else → 404 for now (the apex page and the HTTP proxy land in M3).

use std::sync::Arc;
use std::time::Duration;

use async_tungstenite::tungstenite::handshake::derive_accept_key;
use ethertunnel_proto::transport::{mux_connection, mux_io, Role};
use hyper::header::{HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::proxy;
use crate::ratelimit::{ConnLimiter, ConnPermit, RateLimiter};
use crate::session::{run_session, SessionCtx};
use crate::tcp::TcpPortManager;
use crate::tls::{self, SniResolver};

/// A running relay. Dropping it (or calling [`RelayHandle::shutdown`]) stops the
/// accept loop; in-flight connections finish on their own.
pub struct RelayHandle {
    /// The actually-bound address (useful when the config requested port 0).
    pub local_addr: std::net::SocketAddr,
    /// In self-signed mode, the certificate DER — so tests/clients can trust it.
    pub cert_der: Option<Vec<u8>>,
    cancel: CancellationToken,
}

impl RelayHandle {
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Pre-built TLS material: the rustls signing key plus the certificate DER (so
/// callers can choose to trust it). Used for `manual` mode and tests; lets a
/// restarted relay reuse the same certificate.
pub type TlsMaterial = (Arc<rustls::sign::CertifiedKey>, Vec<u8>);

/// Bind the listener, build TLS, and spawn the accept loop. Returns once the
/// socket is bound (so callers/tests can read `local_addr`).
pub async fn serve(config: Arc<Config>, ctx: Arc<SessionCtx>) -> anyhow::Result<RelayHandle> {
    serve_with(config, ctx, None).await
}

/// Like [`serve`], but optionally use caller-supplied TLS material instead of
/// generating it from `config.tls.mode`.
pub async fn serve_with(
    config: Arc<Config>,
    ctx: Arc<SessionCtx>,
    injected: Option<TlsMaterial>,
) -> anyhow::Result<RelayHandle> {
    tls::ensure_crypto_provider();

    // The relay-wide shutdown token, created up front so the ACME renewal task
    // can be tied to it (and stop when the relay does).
    let cancel = CancellationToken::new();

    let resolver = Arc::new(SniResolver::new(&config.server.domain));
    let cert_der = match injected {
        Some((ck, der)) => {
            resolver.install(ck);
            Some(der)
        }
        None => match config.tls.mode {
            crate::config::TlsMode::SelfSigned => {
                let (ck, der) = tls::self_signed(&config.server.domain)?;
                resolver.install(ck);
                Some(der)
            }
            crate::config::TlsMode::Manual => {
                let manual =
                    config.tls.manual.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("tls.mode = manual requires [tls.manual]")
                    })?;
                let cert = std::fs::read(&manual.cert_file)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", manual.cert_file.display()))?;
                let key = std::fs::read(&manual.key_file)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", manual.key_file.display()))?;
                let ck = tls::certified_key_from_pem(&cert, &key)?;
                resolver.install(ck);
                tls::first_cert_der(&cert).ok()
            }
            crate::config::TlsMode::Acme => {
                let acme = config
                    .tls
                    .acme
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("tls.mode = acme requires [tls.acme]"))?;
                let token = acme.cloudflare.token()?;
                let manager = crate::acme::AcmeManager::new(
                    config.server.domain.clone(),
                    config.tls.state_dir.clone(),
                    acme.email.clone(),
                    acme.staging,
                    acme.cloudflare.zone_id.clone(),
                    token,
                );
                // Installs cached-or-self-signed immediately and issues/renews in
                // the background, so the listener never blocks on ACME.
                manager.boot(resolver.clone(), cancel.clone())?
            }
        },
    };

    let acceptor = TlsAcceptor::from(tls::server_config(resolver));
    let listener = TcpListener::bind(config.server.listen).await?;
    let local_addr = listener.local_addr()?;
    let domain = config.server.domain.clone();

    // Per-IP accept-*rate* limiter (pre-TLS), the concurrent-*connection* cap,
    // and the raw-TCP tunnel port manager.
    let rate = Arc::new(RateLimiter::new(20, 40));
    let conn_limiter = ConnLimiter::new(
        config.limits.max_connections,
        config.limits.max_connections_per_ip,
    );
    // The live-session cap: held for each control session's whole lifetime, so
    // the post-101 daemon population is actually bounded (the accept ConnPermit
    // can't reach inside the `Fn` service). Installed on the shared SessionCtx.
    let session_limiter = ConnLimiter::new(
        config.limits.max_sessions,
        config.limits.max_sessions_per_ip,
    );
    ctx.set_session_limiter(session_limiter);
    ctx.set_token_revalidate_interval_secs(config.limits.token_revalidate_interval_secs);
    let tcp_idle = (config.limits.proxy_idle_timeout_secs > 0)
        .then(|| Duration::from_secs(config.limits.proxy_idle_timeout_secs));
    let tcp_absolute = (config.limits.proxy_absolute_max_secs > 0)
        .then(|| Duration::from_secs(config.limits.proxy_absolute_max_secs));
    let tcp_manager = TcpPortManager::new(
        local_addr.ip(),
        config.tcp.port_range,
        ctx.router.clone(),
        rate.clone(),
        // SHARE the :443 ConnLimiter: one relay-wide global + per-/64 fd budget
        // spans both planes (they share the process fd table).
        conn_limiter.clone(),
        tcp_idle,
        tcp_absolute,
        cancel.clone(),
    );
    ctx.set_tcp(tcp_manager);

    // Periodically reclaim idle per-IP buckets off the hot accept path, so the
    // limiter map shrinks during quiet periods instead of only being pruned
    // reactively at its cap under load.
    {
        let sweep_rate = rate.clone();
        let sweep_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = sweep_cancel.cancelled() => break,
                    _ = tick.tick() => sweep_rate.sweep(),
                }
            }
        });
    }

    let accept_cancel = cancel.clone();
    let accept_rate = rate.clone();
    let accept_conns = conn_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = accept_cancel.cancelled() => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) if !accept_rate.check(peer.ip()) => {
                            tracing::debug!(%peer, "rate limited; dropping connection");
                            drop(stream);
                        }
                        Ok((stream, peer)) => {
                            // Hold a concurrency slot for the whole connection;
                            // None => global or per-source ceiling reached.
                            let Some(permit) = accept_conns.try_admit(peer.ip()) else {
                                tracing::debug!(%peer, "connection cap reached; dropping connection");
                                drop(stream);
                                continue;
                            };
                            let acceptor = acceptor.clone();
                            let ctx = ctx.clone();
                            let config = config.clone();
                            let conn_cancel = accept_cancel.clone();
                            tokio::spawn(async move {
                                handle_conn(stream, peer, acceptor, ctx, config, conn_cancel, permit)
                                    .await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                        }
                    }
                }
            }
        }
        tracing::debug!("accept loop stopped");
    });

    tracing::info!(%local_addr, %domain, "relay listening");
    Ok(RelayHandle {
        local_addr,
        cert_der,
        cancel,
    })
}

/// Enable TCP keepalive on a relay-side socket so a peer that vanishes without a
/// FIN/RST is detected and the socket (and its concurrency slot) reclaimed. This
/// is the data-plane counterpart to the control channel's app-level ping/pong:
/// the kernel probes the peer without touching the tunneled bytes, so a
/// live-but-idle connection is never harmed (a live peer answers the probes).
pub(crate) fn set_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use ethertunnel_proto::limits::{TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL};
    let ka = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    // Best-effort: a relay that cannot set keepalive still works, just without the
    // dead-peer reclaim.
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    ctx: Arc<SessionCtx>,
    config: Arc<Config>,
    cancel: CancellationToken,
    // The accept-time concurrency slot. For plain keep-alive HTTP it is released
    // when this connection's exchange ends. For an UPGRADE (visitor WS splice or
    // daemon control session) it is re-homed onto the longer-lived task so the
    // slot is held across the whole splice/session instead of being freed at the
    // 101 — closing the "every long-lived connection escapes max_connections"
    // hole. The permit is carried in a shared cell because the hyper service is an
    // `Fn` closure that cannot own a move-only `ConnPermit`; it is `.take()`-n
    // exactly once on the upgrade branch (a connection is never both keep-alive
    // HTTP and an upgrade, so taking once is sound). If never taken, the cell
    // drops here and releases the slot as before.
    permit: ConnPermit,
) {
    let _ = stream.set_nodelay(true);
    set_tcp_keepalive(&stream);
    let tls = match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "tls handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "tls handshake timed out");
            return;
        }
    };

    let header_read_timeout_secs = config.limits.header_read_timeout_secs;
    // Shared cell carrying the accept permit into the request router so it can be
    // re-homed onto an upgrade's long-lived task. See the `permit` doc above.
    let permit_cell: proxy::PermitCell = Arc::new(std::sync::Mutex::new(Some(permit)));
    let service = {
        let cancel = cancel.clone();
        service_fn(move |req| {
            let ctx = ctx.clone();
            let config = config.clone();
            let cancel = cancel.clone();
            let permit_cell = permit_cell.clone();
            async move { route(req, ctx, config, peer, cancel, permit_cell).await }
        })
    };

    let mut builder = hyper::server::conn::http1::Builder::new();
    // Bound slowloris: cap how long a client may take to send its request line +
    // headers after the TLS handshake. The route()/auth logic only runs once the
    // headers arrive, so without this an unauthenticated peer could stall forever.
    // hyper requires a Timer to be installed for header_read_timeout to work.
    if header_read_timeout_secs > 0 {
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(Duration::from_secs(header_read_timeout_secs));
    }
    let conn = builder
        .serve_connection(TokioIo::new(tls), service)
        .with_upgrades();

    // The pre-upgrade HTTP exchange stops on shutdown; the post-upgrade session
    // is independently tied to the same `cancel` via `run_session`.
    tokio::select! {
        _ = cancel.cancelled() => {}
        r = conn => {
            if let Err(e) = r {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        }
    }
}

/// Route one HTTP request: control upgrade on `connect.<domain>`, the apex page
/// on the bare domain, the HTTP proxy for tunnel hostnames, else 404.
async fn route(
    mut req: Request<hyper::body::Incoming>,
    ctx: Arc<SessionCtx>,
    config: Arc<Config>,
    peer: std::net::SocketAddr,
    cancel: CancellationToken,
    permit_cell: proxy::PermitCell,
) -> Result<proxy::Resp, std::convert::Infallible> {
    let host = host_of(&req);

    if host.as_deref() == Some(&config.connect_host()) {
        // The provisioning control plane shares this host with the WS control
        // upgrade; method+path discriminate them (admin = POST /admin/*, the
        // upgrade = GET + Upgrade headers). Only matches when `[provision]` is
        // configured (`is_admin_request` checks installation), so the relay has
        // no inbound control API otherwise.
        if crate::admin_http::is_admin_request(&ctx, &req) {
            return Ok(crate::admin_http::handle(ctx, req).await);
        }
        return Ok(handle_control_upgrade(&mut req, ctx, peer, cancel, permit_cell));
    }

    if host.as_deref() == Some(config.apex()) {
        return Ok(proxy::page(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            config.server.apex_response.clone(),
        ));
    }

    match host {
        Some(host) if config.is_tunnel_host(&host) => Ok(proxy::proxy_http(
            req,
            ctx,
            host,
            peer.ip(),
            peer.port(),
            config.limits.clone().into(),
            permit_cell,
        )
        .await),
        _ => Ok(proxy::page(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found",
        )),
    }
}

/// Validate a WebSocket upgrade on `connect.<domain>` and, if good, spawn the
/// session on the upgraded stream. Returns the 101 (or an error status).
fn handle_control_upgrade(
    req: &mut Request<hyper::body::Incoming>,
    ctx: Arc<SessionCtx>,
    peer: std::net::SocketAddr,
    cancel: CancellationToken,
    permit_cell: proxy::PermitCell,
) -> proxy::Resp {
    if req.method() != Method::GET || !is_websocket_upgrade(req) {
        return proxy::page(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            "expected websocket upgrade",
        );
    }
    let Some(accept) = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .map(|k| derive_accept_key(k.as_bytes()))
    else {
        return proxy::page(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            "missing Sec-WebSocket-Key",
        );
    };

    // Acquire a LIVE-SESSION permit before committing to the 101. Held for the
    // whole session lifetime (moved into the spawn below), it count-bounds the
    // post-upgrade daemon population that previously escaped max_connections.
    // When no limiter is installed (tests without a listener), sessions are
    // unbounded, preserving existing behavior.
    let session_permit = match ctx.session_limiter.load_full() {
        Some(limiter) => match limiter.try_admit(peer.ip()) {
            Some(p) => Some(p),
            None => {
                tracing::debug!(%peer, "session cap reached; refusing control upgrade");
                return proxy::page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "text/plain; charset=utf-8",
                    "relay at capacity",
                );
            }
        },
        None => None,
    };

    // The accept-time permit is no longer needed past the 101 on the control
    // path: the session is now count-bounded by `session_permit`. Take it from
    // the cell so it is released when this exchange ends (it is NOT carried into
    // the session — that would double-count one connection against both caps).
    let _ = permit_cell.lock().unwrap().take();

    let upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let _session_permit = session_permit; // held for the session's whole life
        match upgrade.await {
            Ok(upgraded) => {
                let io = mux_io(TokioIo::new(upgraded), Role::Server).await;
                let conn = mux_connection(io, yamux::Mode::Server);
                run_session(conn, ctx, cancel).await;
            }
            Err(e) => tracing::debug!(error = %e, "control upgrade failed"),
        }
    });

    let accept_value = HeaderValue::from_str(&accept).expect("accept key is valid ascii");
    proxy::switching_protocols(vec![
        (CONNECTION, HeaderValue::from_static("upgrade")),
        (UPGRADE, HeaderValue::from_static("websocket")),
        (SEC_WEBSOCKET_ACCEPT, accept_value),
    ])
}

/// The `Host` header, lowercased and port-stripped.
fn host_of(req: &Request<hyper::body::Incoming>) -> Option<String> {
    let raw = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
    let host = raw.split(':').next().unwrap_or(raw);
    Some(host.to_ascii_lowercase())
}

fn is_websocket_upgrade(req: &Request<hyper::body::Incoming>) -> bool {
    fn header_contains(
        req: &Request<hyper::body::Incoming>,
        name: hyper::header::HeaderName,
        needle: &str,
    ) -> bool {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains(needle))
            .unwrap_or(false)
    }
    header_contains(req, UPGRADE, "websocket") && header_contains(req, CONNECTION, "upgrade")
}
