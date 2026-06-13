//! Raw-TCP tunnel ports.
//!
//! When a daemon claims a public TCP port, the relay binds a listener for it
//! (bind-before-grant: a bind failure denies the claim) and, per inbound
//! connection, opens a multiplexed stream to whichever session currently owns
//! the port and splices bytes. Listeners persist for the relay's lifetime —
//! routing is by `router.lookup_tcp`, so supersede just repoints the owner —
//! and stop on relay shutdown.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ethertunnel_proto::frames::StreamHeader;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::ratelimit::RateLimiter;
use crate::router::Router;

/// Binds and serves raw-TCP tunnel ports.
pub struct TcpPortManager {
    bind_ip: IpAddr,
    port_range: [u16; 2],
    router: Arc<Router>,
    rate: Arc<RateLimiter>,
    cancel: CancellationToken,
    bound: Mutex<HashSet<u16>>,
}

impl TcpPortManager {
    pub fn new(
        bind_ip: IpAddr,
        port_range: [u16; 2],
        router: Arc<Router>,
        rate: Arc<RateLimiter>,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            bind_ip,
            port_range,
            router,
            rate,
            cancel,
            bound: Mutex::new(HashSet::new()),
        })
    }

    /// Whether `port` falls within the configured public-port range.
    pub fn in_range(&self, port: u16) -> bool {
        port >= self.port_range[0] && port <= self.port_range[1]
    }

    /// Ensure a listener exists for `port`, binding + spawning its accept loop
    /// on first use. Idempotent; a bind failure (e.g. port in use) is returned.
    pub async fn ensure_bound(self: &Arc<Self>, port: u16) -> std::io::Result<()> {
        if self.bound.lock().unwrap().contains(&port) {
            return Ok(());
        }
        let listener = TcpListener::bind((self.bind_ip, port)).await?;
        self.bound.lock().unwrap().insert(port);

        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = manager.cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((conn, peer)) = accepted else { continue };
                        if !manager.rate.check(peer.ip()) {
                            continue; // dropped: flooding source
                        }
                        let manager = manager.clone();
                        tokio::spawn(async move { manager.serve_conn(port, conn, peer).await });
                    }
                }
            }
            tracing::debug!(port, "tcp listener stopped");
        });
        tracing::info!(port, "tcp tunnel port bound");
        Ok(())
    }

    async fn serve_conn(
        &self,
        port: u16,
        mut conn: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
    ) {
        let _ = conn.set_nodelay(true);
        let Some(session) = self.router.lookup_tcp(port) else {
            return; // no current owner; drop
        };
        let stream = match session
            .open_stream(StreamHeader::Tcp {
                port,
                peer_ip: peer.ip(),
                peer_port: peer.port(),
            })
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(port, error = ?e, "failed to open tcp data stream");
                return;
            }
        };
        // `DataStream` is a compat-wrapped yamux stream — already a tokio
        // AsyncRead/AsyncWrite, so it splices directly.
        let mut data = stream;
        let _ = tokio::io::copy_bidirectional(&mut conn, &mut data).await;
    }
}
