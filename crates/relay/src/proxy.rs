//! The visitor-facing HTTP proxy.
//!
//! For a request to a tunnel hostname we open a fresh multiplexed stream to the
//! owning daemon (preamble already written by the session actor), speak HTTP/1.1
//! as a *client* over it, and stream the response back to the visitor. Bodies
//! flow end-to-end with backpressure provided by the yamux flow-control windows
//! — we never buffer a whole body. WebSocket upgrades are handled as a byte
//! splice after the 101; we never parse WS frames.

use std::net::IpAddr;

use bytes::Bytes;
use ethertunnel_proto::frames::StreamHeader;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue, CONNECTION, HOST, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;

use crate::session::SessionCtx;

/// The uniform response body type the listener serves: either a static page or
/// the streamed upstream response, both boxed to one type.
pub type Resp = Response<BoxBody<Bytes, hyper::Error>>;

/// Hop-by-hop headers stripped in both directions (RFC 7230 §6.1), minus
/// `Connection`/`Upgrade`, which are handled specially for WebSocket upgrades.
const HOP_BY_HOP: &[&str] = &[
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// Build a static response with the given status and plain-text-ish body.
pub fn page(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Resp {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(boxed(body.into()))
        .expect("static response builds")
}

/// A bare 101 response (no body) for the control upgrade.
pub fn switching_protocols(headers: Vec<(HeaderName, HeaderValue)>) -> Resp {
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder.body(boxed(Bytes::new())).expect("101 builds")
}

fn boxed(body: Bytes) -> BoxBody<Bytes, hyper::Error> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

fn relay_404() -> Resp {
    page(
        StatusCode::NOT_FOUND,
        "text/html; charset=utf-8",
        Bytes::from_static(ERR_404),
    )
}

fn relay_502() -> Resp {
    page(
        StatusCode::BAD_GATEWAY,
        "text/html; charset=utf-8",
        Bytes::from_static(ERR_502),
    )
}

fn relay_504() -> Resp {
    page(
        StatusCode::GATEWAY_TIMEOUT,
        "text/html; charset=utf-8",
        Bytes::from_static(ERR_504),
    )
}

const ERR_404: &[u8] = b"<!doctype html><meta charset=utf-8><title>404</title>\
<h1>404 - no such tunnel</h1><p>No tunnel is registered for this hostname.</p>";
const ERR_502: &[u8] = b"<!doctype html><meta charset=utf-8><title>502</title>\
<h1>502 - tunnel unavailable</h1><p>The tunnel is registered but its daemon is not reachable.</p>";
const ERR_504: &[u8] = b"<!doctype html><meta charset=utf-8><title>504</title>\
<h1>504 - upstream timeout</h1><p>The tunnel's local service did not respond in time.</p>";

/// Proxy one visitor request to the daemon serving `host`.
pub async fn proxy_http(
    mut req: Request<hyper::body::Incoming>,
    ctx: Arc<SessionCtx>,
    host: String,
    peer_ip: IpAddr,
    peer_port: u16,
) -> Resp {
    let Some(session) = ctx.router.lookup_http(&host) else {
        // Until the registry (M4) distinguishes registered-but-offline, an
        // unrouted host is simply unknown.
        return relay_404();
    };

    let stream = match session
        .open_stream(StreamHeader::Http {
            host: host.clone(),
            peer_ip,
            peer_port,
        })
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%host, error = ?e, "failed to open data stream");
            return relay_502();
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(%host, error = %e, "http handshake to daemon failed");
            return relay_502();
        }
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let upgrading = is_upgrade(&req);
    scrub_request(&mut req, peer_ip, &host, upgrading);
    let visitor_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));

    // Header timeout only; the body then streams untimed.
    let mut resp =
        match tokio::time::timeout(Duration::from_secs(30), sender.send_request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!(%host, error = %e, "upstream request failed");
                return relay_502();
            }
            Err(_) => return relay_504(),
        };

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let daemon_upgrade = hyper::upgrade::on(&mut resp);
        if let Some(visitor_upgrade) = visitor_upgrade {
            tokio::spawn(async move {
                match (visitor_upgrade.await, daemon_upgrade.await) {
                    (Ok(v), Ok(d)) => {
                        let _ = tokio::io::copy_bidirectional(
                            &mut TokioIo::new(v),
                            &mut TokioIo::new(d),
                        )
                        .await;
                    }
                    _ => tracing::debug!("websocket upgrade handoff failed"),
                }
            });
        }
    }

    scrub_response(&mut resp);
    resp.map(|b| b.boxed())
}

/// True if the request asks for a protocol upgrade (e.g. WebSocket).
fn is_upgrade(req: &Request<hyper::body::Incoming>) -> bool {
    req.headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false)
        && req.headers().contains_key(UPGRADE)
}

/// Strip hop-by-hop headers and (re)write the `X-Forwarded-*` set. Visitor-
/// supplied forwarding headers are dropped first so they can't be spoofed.
fn scrub_request(
    req: &mut Request<hyper::body::Incoming>,
    peer_ip: IpAddr,
    host: &str,
    upgrading: bool,
) {
    strip_hop_by_hop(req.headers_mut(), upgrading);
    let headers = req.headers_mut();
    for name in [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "forwarded",
    ] {
        headers.remove(name);
    }
    if let Ok(v) = HeaderValue::from_str(&peer_ip.to_string()) {
        headers.insert("x-forwarded-for", v);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert("x-forwarded-host", v);
    }
    // Preserve the original Host so the local app sees its public hostname.
    let _ = HOST; // Host is left intact intentionally.
}

fn scrub_response(resp: &mut Response<hyper::body::Incoming>) {
    strip_hop_by_hop(resp.headers_mut(), false);
    // Don't advertise the stack.
    resp.headers_mut().remove("server");
}

/// Remove hop-by-hop headers, including any named in the `Connection` header.
/// When `keep_upgrade` is set, `Connection` and `Upgrade` are preserved so a
/// WebSocket upgrade can reach the origin.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap, keep_upgrade: bool) {
    // Collect tokens listed in Connection (these are hop-by-hop too).
    let listed: Vec<String> = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();

    for token in &listed {
        if keep_upgrade && token == "upgrade" {
            continue;
        }
        headers.remove(token.as_str());
    }
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    if !keep_upgrade {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
}
