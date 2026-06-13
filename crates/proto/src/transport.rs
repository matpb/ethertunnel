//! The transport seam: WebSocket ↔ byte stream ↔ yamux.
//!
//! Both halves of EtherTunnel speak yamux (a stream multiplexer) over a single
//! WebSocket connection. yamux wants a futures-io `AsyncRead + AsyncWrite`; a
//! WebSocket is a message stream. [`WsByteStream`] bridges the two by mapping
//! binary WS messages to and from a contiguous byte stream. We layer it
//! ourselves rather than depend on `ws_stream_tungstenite` so we don't couple
//! our build to a specific `tungstenite` patch release.
//!
//! The whole stack is generic over the underlying tokio IO `T`, so the relay
//! (a hyper `Upgraded`), the client (a TLS stream), and the tests (a
//! `tokio::io::duplex` half) all run the exact same code path. That is what
//! makes the protocol testable with zero network or TLS.

use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_tungstenite::tungstenite::Message;
use async_tungstenite::WebSocketStream;
use bytes::Bytes;
use futures::io::{AsyncRead, AsyncWrite};
use futures::{Sink, Stream};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use crate::limits;

/// Which side of the WebSocket this endpoint plays. The client masks frames,
/// the server does not — but neither performs an HTTP handshake here, because
/// by the time we reach this layer the connection is already an upgraded
/// WebSocket (the relay did the 101 over hyper; tests skip straight to framing).
pub use async_tungstenite::tungstenite::protocol::Role;

/// A byte stream layered over a tungstenite WebSocket.
///
/// On read, binary messages are surfaced as bytes; ping/pong/text frames are
/// transparently skipped; a close frame (or end of stream) reads as EOF. On
/// write, byte buffers are sent as binary messages, each capped at
/// [`limits::MAX_WS_MESSAGE`] so a fast writer can never emit an oversized
/// message.
pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    /// Leftover payload from the last binary message not yet handed to a reader.
    read_buf: Bytes,
    /// Set once we have seen a close frame or end-of-stream.
    closed: bool,
}

impl<S> WsByteStream<S> {
    fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: Bytes::new(),
            closed: false,
        }
    }
}

fn ws_err(e: async_tungstenite::tungstenite::Error) -> io::Error {
    use async_tungstenite::tungstenite::Error as WsError;
    match e {
        WsError::Io(io) => io,
        other => io::Error::other(other),
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let n = min(buf.len(), this.read_buf.len());
                buf[..n].copy_from_slice(&this.read_buf[..n]);
                let _ = this.read_buf.split_to(n);
                return Poll::Ready(Ok(n));
            }
            if this.closed {
                return Poll::Ready(Ok(0));
            }
            match Pin::new(&mut this.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    // `data` is `Bytes` on tungstenite >=0.24 and `Vec<u8>` on
                    // older releases; both deref to `[u8]`, so this is portable.
                    // Empty binary frames fall through to the skip arm and we
                    // fetch the next message.
                    Message::Binary(data) if !data.is_empty() => {
                        this.read_buf = Bytes::copy_from_slice(&data[..]);
                    }
                    Message::Close(_) => {
                        this.closed = true;
                        return Poll::Ready(Ok(0));
                    }
                    // ping/pong/text/frame: not part of our byte protocol, skip.
                    _ => {}
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(ws_err(e))),
                Poll::Ready(None) => {
                    this.closed = true;
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let n = min(buf.len(), limits::MAX_WS_MESSAGE);
                let msg = Message::binary(buf[..n].to_vec());
                match Pin::new(&mut this.ws).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(ws_err(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(ws_err(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.ws).poll_flush(cx).map_err(ws_err)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.ws).poll_close(cx).map_err(ws_err)
    }
}

/// The byte stream type that yamux runs on, for a given tokio IO `T`.
pub type MuxIo<T> = WsByteStream<Compat<T>>;

/// Wrap a tokio IO stream as a WebSocket and expose it as a yamux-ready byte
/// stream. The connection is assumed to be an already-upgraded WebSocket.
pub async fn mux_io<T>(io: T, role: Role) -> MuxIo<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ws = WebSocketStream::from_raw_socket(io.compat(), role, None).await;
    WsByteStream::new(ws)
}

/// Build a yamux connection with EtherTunnel's bounded receive windows.
///
/// The connection-level window caps total buffering for one daemon session;
/// combined with the per-stream window it makes worst-case memory a function of
/// session count, not traffic — see [`limits`].
pub fn mux_connection<T>(io: MuxIo<T>, mode: yamux::Mode) -> yamux::Connection<MuxIo<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(limits::MAX_STREAMS_PER_CONNECTION);
    cfg.set_max_connection_receive_window(Some(limits::CONNECTION_RECEIVE_WINDOW));
    yamux::Connection::new(io, cfg, mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;
    use yamux::{Connection, Mode};

    /// Spawn a task that drives a yamux connection forever, dropping any inbound
    /// streams. Used on the side that only opens outbound streams.
    fn spawn_driver<T>(mut conn: Connection<MuxIo<T>>)
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            while let Some(Ok(_stream)) =
                futures::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await
            {
                // inbound streams are not expected on this side; drop them
            }
        });
    }

    /// Build a connected client/server yamux pair over an in-memory duplex.
    async fn pair() -> (
        Connection<MuxIo<tokio::io::DuplexStream>>,
        Connection<MuxIo<tokio::io::DuplexStream>>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client_io = mux_io(a, Role::Client).await;
        let server_io = mux_io(b, Role::Server).await;
        (
            mux_connection(client_io, Mode::Client),
            mux_connection(server_io, Mode::Server),
        )
    }

    #[tokio::test]
    async fn echo_small() {
        let (mut client, server) = pair().await;

        // Server: accept one stream and echo it.
        tokio::spawn(async move {
            let mut server = server;
            if let Some(Ok(mut s)) =
                futures::future::poll_fn(|cx| server.poll_next_inbound(cx)).await
            {
                // keep driving the connection while echoing
                let drive = async {
                    loop {
                        if futures::future::poll_fn(|cx| server.poll_next_inbound(cx))
                            .await
                            .is_none()
                        {
                            break;
                        }
                    }
                };
                let echo = async {
                    let mut buf = [0u8; 64];
                    let n = s.read(&mut buf).await.unwrap();
                    s.write_all(&buf[..n]).await.unwrap();
                    s.flush().await.unwrap();
                };
                futures::future::join(drive, echo).await;
            }
        });

        let mut stream = futures::future::poll_fn(|cx| client.poll_new_outbound(cx))
            .await
            .unwrap();
        spawn_driver(client);

        stream.write_all(b"hello yamux").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello yamux");
    }

    #[tokio::test]
    async fn echo_large() {
        let (mut client, server) = pair().await;
        const N: usize = 1024 * 1024; // 1 MiB — exercises chunking + flow control

        tokio::spawn(async move {
            let mut server = server;
            if let Some(Ok(mut s)) =
                futures::future::poll_fn(|cx| server.poll_next_inbound(cx)).await
            {
                let drive = async {
                    loop {
                        if futures::future::poll_fn(|cx| server.poll_next_inbound(cx))
                            .await
                            .is_none()
                        {
                            break;
                        }
                    }
                };
                let echo = async {
                    let mut buf = vec![0u8; N];
                    s.read_exact(&mut buf).await.unwrap();
                    s.write_all(&buf).await.unwrap();
                    s.flush().await.unwrap();
                    s.close().await.unwrap();
                };
                futures::future::join(drive, echo).await;
            }
        });

        let mut stream = futures::future::poll_fn(|cx| client.poll_new_outbound(cx))
            .await
            .unwrap();
        spawn_driver(client);

        let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
        let writer_payload = payload.clone();
        let write_half = async {
            stream.write_all(&writer_payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut got = vec![0u8; N];
            stream.read_exact(&mut got).await.unwrap();
            got
        };
        let got = tokio::time::timeout(Duration::from_secs(20), write_half)
            .await
            .expect("1 MiB echo deadlocked — flow control bug");
        assert_eq!(got, payload);
    }

    /// Writing far more than the connection receive window to a stream nobody
    /// reads must block (backpressure), not buffer unboundedly. We assert the
    /// write does NOT complete within a deadline.
    #[tokio::test]
    async fn backpressure_blocks_without_reader() {
        let (mut client, server) = pair().await;

        // Server accepts the stream but never reads it; keep the connection
        // pumping so the window (not a stalled connection) is what blocks us.
        tokio::spawn(async move {
            let mut server = server;
            let mut parked: Vec<yamux::Stream> = Vec::new();
            while let Some(Ok(s)) =
                futures::future::poll_fn(|cx| server.poll_next_inbound(cx)).await
            {
                parked.push(s); // hold the stream open, never read it
            }
        });

        let mut stream = futures::future::poll_fn(|cx| client.poll_new_outbound(cx))
            .await
            .unwrap();
        spawn_driver(client);

        // 48 MiB > CONNECTION_RECEIVE_WINDOW (32 MiB): cannot all buffer, so
        // the write must block regardless of any per-stream window auto-tuning.
        let big = vec![7u8; 48 * 1024 * 1024];
        let result = tokio::time::timeout(Duration::from_millis(750), async {
            stream.write_all(&big).await
        })
        .await;
        assert!(
            result.is_err(),
            "write of 20 MiB to an unread stream completed — backpressure is broken"
        );
    }
}
