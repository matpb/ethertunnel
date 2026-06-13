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
use crate::ratelimit::RateLimiter;
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
            other => anyhow::bail!("TLS mode {other:?} is not implemented until M6"),
        },
    };

    let acceptor = TlsAcceptor::from(tls::server_config(resolver));
    let listener = TcpListener::bind(config.server.listen).await?;
    let local_addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let domain = config.server.domain.clone();

    // Per-IP accept limiter (pre-TLS) and the raw-TCP tunnel port manager.
    let rate = Arc::new(RateLimiter::new(20, 40));
    let tcp_manager = TcpPortManager::new(
        local_addr.ip(),
        config.tcp.port_range,
        ctx.router.clone(),
        rate.clone(),
        cancel.clone(),
    );
    ctx.set_tcp(tcp_manager);

    let accept_cancel = cancel.clone();
    let accept_rate = rate.clone();
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
                            let acceptor = acceptor.clone();
                            let ctx = ctx.clone();
                            let config = config.clone();
                            let conn_cancel = accept_cancel.clone();
                            tokio::spawn(async move {
                                handle_conn(stream, peer, acceptor, ctx, config, conn_cancel).await;
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

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    ctx: Arc<SessionCtx>,
    config: Arc<Config>,
    cancel: CancellationToken,
) {
    let _ = stream.set_nodelay(true);
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

    let service = {
        let cancel = cancel.clone();
        service_fn(move |req| {
            let ctx = ctx.clone();
            let config = config.clone();
            let cancel = cancel.clone();
            async move { route(req, ctx, config, peer, cancel).await }
        })
    };

    let conn = hyper::server::conn::http1::Builder::new()
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
) -> Result<proxy::Resp, std::convert::Infallible> {
    let host = host_of(&req);

    if host.as_deref() == Some(&config.connect_host()) {
        return Ok(handle_control_upgrade(&mut req, ctx, cancel));
    }

    if host.as_deref() == Some(config.apex()) {
        return Ok(proxy::page(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            config.server.apex_response.clone(),
        ));
    }

    match host {
        Some(host) if config.is_tunnel_host(&host) => {
            Ok(proxy::proxy_http(req, ctx, host, peer.ip(), peer.port()).await)
        }
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
    cancel: CancellationToken,
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

    let upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
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
