//! Local forwarding: relay → daemon → your service.
//!
//! The relay opens one multiplexed stream per visitor connection and writes a
//! [`StreamHeader`] preamble naming the tunnel. We read it, connect to the
//! mapped local address, and splice bytes in both directions — no HTTP parsing,
//! so plain HTTP, WebSocket, and (later) raw TCP all flow through the same
//! path. If the local service is down we synthesize a branded 502/504 for HTTP
//! tunnels so the visitor learns the tunnel is up but the app is not.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ethertunnel_proto::codec;
use ethertunnel_proto::frames::StreamHeader;
use ethertunnel_proto::limits::MAX_STREAM_HEADER;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

/// Where a tunnel forwards to locally.
#[derive(Clone, Debug)]
pub struct LocalTarget {
    pub host: String,
    pub port: u16,
}

/// Forwarding tables: HTTP tunnels keyed by hostname, TCP tunnels by public
/// port. Shared (read-only) across inbound streams.
#[derive(Default)]
pub struct RouteTable {
    pub http: HashMap<String, LocalTarget>,
    pub tcp: HashMap<u16, LocalTarget>,
}

/// Shared handle to the forwarding tables.
pub type Routes = Arc<RouteTable>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Handle one inbound stream from the relay: read its preamble and forward.
pub async fn handle_inbound(stream: yamux::Stream, routes: Routes) {
    let mut io = stream.compat();
    let header = match codec::read_frame::<_, StreamHeader>(&mut io, MAX_STREAM_HEADER).await {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(error = %e, "bad stream preamble");
            return;
        }
    };

    match header {
        StreamHeader::Http { host, .. } => match routes.http.get(&host) {
            Some(target) => forward_http(io, target).await,
            None => {
                // The relay routed a host we don't serve; shouldn't happen.
                write_502(&mut io, &host).await;
            }
        },
        StreamHeader::Tcp { port, .. } => match routes.tcp.get(&port) {
            Some(target) => forward_tcp(io, target).await,
            None => tracing::debug!(port, "tcp stream for unmapped port; dropping"),
        },
    }
}

/// Splice a raw-TCP stream to its local target. Unlike HTTP, there's no
/// protocol to synthesize an error into, so a failed connect just closes.
async fn forward_tcp(mut io: Compat<yamux::Stream>, target: &LocalTarget) {
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    {
        Ok(Ok(mut local)) => {
            let _ = local.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional(&mut io, &mut local).await;
        }
        _ => tracing::debug!(port = target.port, "tcp local connect failed"),
    }
}

async fn forward_http(mut io: Compat<yamux::Stream>, target: &LocalTarget) {
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    {
        Ok(Ok(mut local)) => {
            let _ = local.set_nodelay(true);
            // Pure byte splice: HTTP request → local, response → relay.
            let _ = tokio::io::copy_bidirectional(&mut io, &mut local).await;
        }
        Ok(Err(_)) => write_502(&mut io, &target.host).await,
        Err(_) => write_504(&mut io, &target.host).await,
    }
}

async fn write_502(io: &mut Compat<yamux::Stream>, host: &str) {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>502</title>\
<h1>502 - local service unavailable</h1>\
<p>The tunnel is connected, but nothing accepted the connection on the target \
for <code>{host}</code>. Check that your local service is running.</p>"
    );
    write_http(io, 502, "Bad Gateway", "local-connect-failed", &body).await;
}

async fn write_504(io: &mut Compat<yamux::Stream>, host: &str) {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>504</title>\
<h1>504 - local service timed out</h1>\
<p>The tunnel is connected, but the local target for <code>{host}</code> did \
not accept the connection in time.</p>"
    );
    write_http(io, 504, "Gateway Timeout", "local-connect-timeout", &body).await;
}

/// Write a minimal, self-contained HTTP/1.1 response and close. The relay's
/// HTTP client parses this and relays it to the visitor.
async fn write_http(
    io: &mut Compat<yamux::Stream>,
    status: u16,
    reason: &str,
    error_tag: &str,
    body: &str,
) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: {len}\r\n\
Cache-Control: no-store\r\n\
X-Etun-Error: {error_tag}\r\n\
Connection: close\r\n\
\r\n\
{body}",
        len = body.len()
    );
    let _ = io.write_all(response.as_bytes()).await;
    let _ = io.flush().await;
}
