//! The visitor-facing HTTP proxy.
//!
//! For a request to a tunnel hostname we open a fresh multiplexed stream to the
//! owning daemon (preamble already written by the session actor), speak HTTP/1.1
//! as a *client* over it, and stream the response back to the visitor. Bodies
//! flow end-to-end with backpressure provided by the yamux flow-control windows
//! — we never buffer a whole body. WebSocket upgrades are handled as a byte
//! splice after the 101; we never parse WS frames.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use ethertunnel_proto::frames::StreamHeader;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue, CONNECTION, HOST, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::LimitsConfig;
use crate::ratelimit::ConnPermit;
use crate::session::SessionCtx;

/// Carries the accept-time [`ConnPermit`] from `handle_conn` into the request
/// router so it can be re-homed onto the visitor splice (the long-lived task)
/// when the connection upgrades. The hyper service is an `Fn` closure, so the
/// move-only permit cannot live in the closure directly; it is wrapped in a
/// shared cell and `.take()`-n exactly once on the upgrade branch. A connection
/// is never both keep-alive HTTP and an upgrade, so taking once is sound.
pub type PermitCell = Arc<std::sync::Mutex<Option<ConnPermit>>>;

/// Map a config "seconds, 0 = disabled" value to an `Option<Duration>`.
fn dur_or_off(secs: u64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs))
}

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

/// A shared "last activity" clock in whole milliseconds since a fixed epoch,
/// bumped whenever either direction of a splice makes progress. Idle is measured
/// against this so activity in EITHER direction resets the deadline (a download
/// with a silent client must not be killed).
#[derive(Clone)]
struct ActivityClock {
    epoch: Instant,
    last_ms: Arc<AtomicU64>,
}

impl ActivityClock {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_ms: Arc::new(AtomicU64::new(0)),
        }
    }
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
    fn bump(&self) {
        self.last_ms.store(self.now_ms(), Ordering::Relaxed);
    }
    fn idle_for(&self) -> Duration {
        Duration::from_millis(
            self.now_ms()
                .saturating_sub(self.last_ms.load(Ordering::Relaxed)),
        )
    }
}

/// Splice `a` <-> `b` until EOF, an error, the idle deadline, or the absolute
/// deadline. Unlike [`tokio::io::copy_bidirectional`], the idle clock is shared
/// across BOTH directions: any byte read on either side resets it, so a tunnel
/// that is busy in one direction and silent in the other is never torn down. A
/// `None` timeout disables that bound (config value 0 maps to `None`).
///
/// Returns `Ok((a_to_b, b_to_a))` byte counts on clean EOF, or an
/// `ErrorKind::TimedOut` error when a deadline fires.
pub async fn copy_bidirectional_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Option<Duration>,
    absolute: Option<Duration>,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let clock = ActivityClock::new();
    let copy = copy_both(a, b, &clock);
    tokio::pin!(copy);

    // No bounds at all: behave exactly like a plain bidirectional copy.
    if idle.is_none() && absolute.is_none() {
        return copy.await;
    }

    // The absolute cap is a single dedicated sleep (its own select branch so it
    // fires precisely, not only on a watchdog tick). The idle bound is checked on
    // a periodic watchdog tick against the shared cross-direction activity clock.
    let absolute_sleep = async {
        match absolute {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(absolute_sleep);

    // Sub-idle tick granularity so the idle bound fires promptly (and so short
    // idle windows in tests are observed). Capped at 1s for production cheapness.
    let tick_period = idle
        .map(|d| {
            (d / 4)
                .max(Duration::from_millis(10))
                .min(Duration::from_secs(1))
        })
        .unwrap_or(Duration::from_secs(1));
    let mut tick = tokio::time::interval(tick_period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            r = &mut copy => return r,
            _ = &mut absolute_sleep => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "splice absolute timeout",
                ));
            }
            _ = tick.tick() => {
                if let Some(idle) = idle {
                    if clock.idle_for() >= idle {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "splice idle timeout",
                        ));
                    }
                }
            }
        }
    }
}

/// Drive both copy directions concurrently, bumping `clock` on every read so the
/// shared idle deadline tracks activity in EITHER direction.
async fn copy_both<A, B>(a: &mut A, b: &mut B, clock: &ActivityClock) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let mut ar = ar;
    let mut aw = aw;
    let mut br = br;
    let mut bw = bw;
    let a2b = copy_one(&mut ar, &mut bw, clock);
    let b2a = copy_one(&mut br, &mut aw, clock);
    tokio::pin!(a2b);
    tokio::pin!(b2a);
    let (mut done_a, mut done_b) = (None, None);
    let mut n_ab = 0u64;
    let mut n_ba = 0u64;
    loop {
        tokio::select! {
            r = &mut a2b, if done_a.is_none() => {
                n_ab = r?;
                done_a = Some(());
            }
            r = &mut b2a, if done_b.is_none() => {
                n_ba = r?;
                done_b = Some(());
            }
            else => break,
        }
        if done_a.is_some() && done_b.is_some() {
            break;
        }
    }
    Ok((n_ab, n_ba))
}

/// Copy one direction, bumping the shared activity clock on every non-empty read
/// and shutting the writer down on EOF so the peer sees a clean half-close.
async fn copy_one<R, W>(r: &mut R, w: &mut W, clock: &ActivityClock) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(total);
        }
        clock.bump();
        w.write_all(&buf[..n]).await?;
        clock.bump();
        total += n as u64;
    }
}

/// An [`AsyncRead`]/[`AsyncWrite`] wrapper that fails a read or write with
/// `ErrorKind::TimedOut` once `idle` elapses with no progress in either
/// direction. Used to bound the relay->daemon body legs (request + response),
/// which flow through one yamux DataStream, so a stalled body tears the stream
/// down and frees the daemon's slot. A `None` idle disables the bound.
struct IdleTimeout<S> {
    inner: S,
    idle: Option<Duration>,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<S> IdleTimeout<S> {
    fn new(inner: S, idle: Option<Duration>) -> Self {
        // A far-future deadline when disabled; never rearmed in that case.
        let dur = idle.unwrap_or(Duration::from_secs(60 * 60 * 24 * 365));
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(dur)),
        }
    }
    fn rearm(&mut self) {
        if let Some(idle) = self.idle {
            self.deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + idle);
        }
    }
    /// Poll the idle deadline; `Ready` means we've been quiet too long.
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.idle.is_some() && self.deadline.as_mut().poll(cx).is_ready()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeout<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Any completed read (progress or a clean EOF) resets the clock.
                let _ = before;
                self.rearm();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if self.poll_expired(cx) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "body idle timeout",
                    )));
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                self.rearm();
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if self.poll_expired(cx) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "body idle timeout",
                    )));
                }
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Proxy one visitor request to the daemon serving `host`.
pub async fn proxy_http(
    mut req: Request<hyper::body::Incoming>,
    ctx: Arc<SessionCtx>,
    host: String,
    peer_ip: IpAddr,
    peer_port: u16,
    limits: Arc<LimitsConfig>,
    permit_cell: PermitCell,
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

    // Bound the relay->daemon body legs (request + response flow through this one
    // yamux DataStream): a stalled/dribbled body trips ErrorKind::TimedOut after
    // the idle window, tearing the stream down so the daemon's 128-stream slot is
    // freed. The handshake bytes flow through the same wrapper; that's fine — the
    // idle clock only fires on a *stall*, not on a slow-but-progressing peer.
    let body_idle = dur_or_off(limits.proxy_idle_timeout_secs);
    let stream = IdleTimeout::new(stream, body_idle);
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
            // This is the long-lived task: re-home the accept-time ConnPermit onto
            // it (taken exactly once from the shared cell) so the global + per-/64
            // accept slot is held for the splice's whole life, not released at the
            // 101. The daemon pump spawned above dies transitively when this
            // splice's yamux stream closes.
            let permit = permit_cell.lock().unwrap().take();
            let idle = dur_or_off(limits.proxy_idle_timeout_secs);
            let absolute = dur_or_off(limits.proxy_absolute_max_secs);
            tokio::spawn(async move {
                let _permit = permit; // held for the splice lifetime, released on drop
                match (visitor_upgrade.await, daemon_upgrade.await) {
                    (Ok(v), Ok(d)) => {
                        let _ = copy_bidirectional_timeout(
                            &mut TokioIo::new(v),
                            &mut TokioIo::new(d),
                            idle,
                            absolute,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Zero bytes for longer than the idle window -> the splice is reclaimed with
    /// ErrorKind::TimedOut. This is the f5/f14 zero-byte attack PoC.
    #[tokio::test(start_paused = true)]
    async fn idle_timeout_reclaims_silent_splice() {
        // Two independent duplex channels form the two sides of the splice. We
        // hold the far ends so neither side EOFs; the splice should die on idle.
        let (mut a, a_far) = tokio::io::duplex(1024);
        let (mut b, b_far) = tokio::io::duplex(1024);
        let splice = tokio::spawn(async move {
            copy_bidirectional_timeout(&mut a, &mut b, Some(Duration::from_millis(100)), None).await
        });
        // Advance virtual time past the idle window. The watchdog tick is
        // (idle/4).clamp(10ms, 1s); for the 100ms idle here that is ~25ms, so a
        // 2s sleep covers many ticks and the idle bound is observed promptly.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let res = splice.await.unwrap();
        assert!(
            matches!(&res, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "silent splice should time out, got {res:?}"
        );
        drop((a_far, b_far));
    }

    /// Activity in EITHER direction resets the idle clock. To isolate the
    /// cross-direction property we drive traffic in ONLY ONE direction
    /// (`b_far -> a_far`) and keep the other (`a_far -> b_far`) totally silent.
    /// The silent direction on its own would trip the 500ms idle bound long
    /// before the 2s active window ends; survival therefore proves the busy
    /// *opposite* direction is what keeps resetting the shared clock. Once the
    /// active direction stops and both ends close, the splice ends via clean EOF
    /// (Ok) — never a spurious mid-activity TimedOut.
    #[tokio::test(start_paused = true)]
    async fn idle_timeout_tracks_cross_direction_activity() {
        let (mut a, mut a_far) = tokio::io::duplex(64 * 1024);
        let (mut b, mut b_far) = tokio::io::duplex(64 * 1024);
        let splice = tokio::spawn(async move {
            copy_bidirectional_timeout(&mut a, &mut b, Some(Duration::from_millis(500)), None).await
        });
        // Only b_far -> a_far carries traffic; a_far -> b_far never sends a byte.
        // Keep a_far drained so the forwarded bytes don't stall the copy.
        let pump = tokio::spawn(async move {
            let mut sink = vec![0u8; 4096];
            for _ in 0..20 {
                b_far.write_all(b"ping").await.unwrap();
                b_far.flush().await.unwrap();
                // Drain the forwarded bytes on a_far so buffers don't back up.
                let _ =
                    tokio::time::timeout(Duration::from_millis(10), a_far.read(&mut sink)).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // Both ends drop here -> clean EOF in both directions. The splice must
            // end via EOF (Ok), proving it was never killed mid-activity.
            drop((a_far, b_far));
        });
        let res = tokio::time::timeout(Duration::from_secs(10), splice)
            .await
            .expect("splice must not hang")
            .unwrap();
        pump.await.unwrap();
        assert!(
            res.is_ok(),
            "active cross-direction transfer must not be killed by idle timeout, got {res:?}"
        );
    }

    /// With continuous activity, the ABSOLUTE cap still tears the splice down.
    #[tokio::test(start_paused = true)]
    async fn absolute_timeout_fires_on_active_splice() {
        let (mut a, mut a_far) = tokio::io::duplex(64 * 1024);
        let (mut b, mut b_far) = tokio::io::duplex(64 * 1024);
        let splice = tokio::spawn(async move {
            copy_bidirectional_timeout(
                &mut a,
                &mut b,
                Some(Duration::from_secs(60)), // idle never fires (always active)
                Some(Duration::from_millis(200)),
            )
            .await
        });
        let pump = tokio::spawn(async move {
            let mut sink = vec![0u8; 4096];
            for _ in 0..50 {
                if a_far.write_all(b"x").await.is_err() {
                    break;
                }
                let _ = tokio::time::timeout(Duration::from_millis(5), b_far.read(&mut sink)).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let res = tokio::time::timeout(Duration::from_secs(10), splice)
            .await
            .expect("splice must not hang")
            .unwrap();
        assert!(
            matches!(&res, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "absolute cap should fire even on an active splice, got {res:?}"
        );
        let _ = pump.await;
    }

    /// No bounds at all behaves like a plain copy: clean EOF returns Ok.
    #[tokio::test]
    async fn no_timeout_copies_to_eof() {
        let (mut a, mut a_far) = tokio::io::duplex(1024);
        let (mut b, mut b_far) = tokio::io::duplex(1024);
        let splice =
            tokio::spawn(
                async move { copy_bidirectional_timeout(&mut a, &mut b, None, None).await },
            );
        a_far.write_all(b"hello").await.unwrap();
        a_far.shutdown().await.unwrap();
        drop(a_far);
        // Read the forwarded bytes from b's far end, then close it.
        let mut got = vec![0u8; 5];
        b_far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        b_far.shutdown().await.unwrap();
        drop(b_far);
        let res = splice.await.unwrap();
        assert!(res.is_ok(), "clean EOF should be Ok, got {res:?}");
    }

    /// The IdleTimeout body wrapper trips a stalled read after the idle window.
    #[tokio::test(start_paused = true)]
    async fn idle_timeout_wrapper_trips_on_stalled_read() {
        let (one, _far) = tokio::io::duplex(1024);
        let mut wrapped = IdleTimeout::new(one, Some(Duration::from_millis(100)));
        let mut buf = [0u8; 16];
        // _far never writes -> the read stalls -> wrapper must time out.
        let r = tokio::time::timeout(Duration::from_secs(5), wrapped.read(&mut buf)).await;
        let inner = r.expect("wrapper should resolve, not hang");
        assert!(
            matches!(&inner, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "stalled body read should time out, got {inner:?}"
        );
    }

    /// The carried accept-permit cell yields its permit at most once: the upgrade
    /// branch `.take()`s it, and a second take (e.g. a stray keep-alive request on
    /// the same connection) gets None — so the permit is never double-released.
    #[tokio::test]
    async fn permit_cell_take_once() {
        use crate::ratelimit::ConnLimiter;
        let limiter = ConnLimiter::new(4, 4);
        let ip = "203.0.113.10".parse().unwrap();
        let permit = limiter.try_admit(ip).expect("admit");
        let cell: PermitCell = Arc::new(std::sync::Mutex::new(Some(permit)));
        assert!(
            cell.lock().unwrap().take().is_some(),
            "first take yields permit"
        );
        assert!(
            cell.lock().unwrap().take().is_none(),
            "second take yields None (take-once)"
        );
    }
}
