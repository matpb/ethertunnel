//! Length-prefixed postcard framing over any tokio byte stream.
//!
//! Wire shape: `u32` little-endian payload length, then that many bytes of
//! postcard-encoded value. We operate on tokio `AsyncRead`/`AsyncWrite` so the
//! same helpers work on a compat-wrapped yamux stream, a TLS stream, or a
//! `tokio::io::duplex` half in tests.
//!
//! The `max` parameter on reads is a hard anti-abuse ceiling: a peer cannot
//! make us allocate a huge buffer by sending a giant length prefix.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{CONTROL_MAGIC, PROTOCOL_VERSION};

/// Errors from framing or (de)serialization.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("frame of {len} bytes exceeds maximum {max}")]
    TooLarge { len: usize, max: usize },
    #[error("bad control-stream magic (not an EtherTunnel peer)")]
    BadMagic,
}

impl CodecError {
    /// True if the error is a clean end-of-stream (peer closed), as opposed to
    /// a protocol violation.
    pub fn is_eof(&self) -> bool {
        matches!(self, CodecError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    }
}

/// Write one length-prefixed postcard frame and flush.
pub async fn write_frame<W, T>(w: &mut W, frame: &T, max: usize) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = postcard::to_stdvec(frame)?;
    if bytes.len() > max {
        return Err(CodecError::TooLarge {
            len: bytes.len(),
            max,
        });
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed postcard frame, rejecting oversize lengths before
/// allocating.
pub async fn read_frame<R, T>(r: &mut R, max: usize) -> Result<T, CodecError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(CodecError::TooLarge { len, max });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

/// Write the control-stream preamble: magic bytes + this build's protocol
/// version. The first thing a daemon sends after opening the control stream.
pub async fn write_preamble<W>(w: &mut W) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&CONTROL_MAGIC).await?;
    w.write_all(&PROTOCOL_VERSION.to_le_bytes()).await?;
    w.flush().await?;
    Ok(())
}

/// Read and validate the control-stream preamble, returning the peer's highest
/// supported protocol version.
pub async fn read_preamble<R>(r: &mut R) -> Result<u16, CodecError>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).await?;
    if magic != CONTROL_MAGIC {
        return Err(CodecError::BadMagic);
    }
    let mut ver = [0u8; 2];
    r.read_exact(&mut ver).await?;
    Ok(u16::from_le_bytes(ver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{ControlFrame, DenyCode, Resource, Secret, StreamHeader};
    use crate::limits::{MAX_CONTROL_FRAME, MAX_STREAM_HEADER};
    use std::net::{IpAddr, Ipv4Addr};

    /// Round-trip a representative sample of every frame kind.
    #[tokio::test]
    async fn control_frames_roundtrip() {
        let frames = vec![
            ControlFrame::Hello {
                token: Secret::from("etun_abc"),
                agent_version: "0.1.0".into(),
                proto_min: 1,
                proto_max: 1,
            },
            ControlFrame::Welcome {
                proto: 1,
                server_version: "0.1.0".into(),
                session_id: 42,
            },
            ControlFrame::Denied {
                code: DenyCode::AuthFailed,
                message: "no".into(),
            },
            ControlFrame::Claim {
                hostnames: vec!["a.example.com".into()],
                tcp_ports: vec![20000],
            },
            ControlFrame::Granted {
                hostnames: vec!["a.example.com".into()],
                tcp_ports: vec![20000],
            },
            ControlFrame::Ping { nonce: 7 },
            ControlFrame::Pong { nonce: 7 },
            ControlFrame::Superseded {
                resource: Resource::Host("a.example.com".into()),
            },
            ControlFrame::Goodbye,
            ControlFrame::Shutdown {
                reason: "deploy".into(),
            },
        ];

        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        for f in &frames {
            write_frame(&mut a, f, MAX_CONTROL_FRAME).await.unwrap();
        }
        for expected in &frames {
            let got: ControlFrame = read_frame(&mut b, MAX_CONTROL_FRAME).await.unwrap();
            // Compare via Debug since ControlFrame isn't PartialEq (Secret).
            assert_eq!(format!("{got:?}"), format!("{expected:?}"));
        }
    }

    #[tokio::test]
    async fn stream_header_roundtrips() {
        let h = StreamHeader::Http {
            host: "x.example.com".into(),
            peer_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            peer_port: 51234,
        };
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, &h, MAX_STREAM_HEADER).await.unwrap();
        let got: StreamHeader = read_frame(&mut b, MAX_STREAM_HEADER).await.unwrap();
        assert_eq!(got, h);
    }

    #[tokio::test]
    async fn oversize_write_is_rejected() {
        let (mut a, _b) = tokio::io::duplex(64 * 1024);
        let big = ControlFrame::Shutdown {
            reason: "x".repeat(100),
        };
        let err = write_frame(&mut a, &big, 8).await.unwrap_err();
        assert!(matches!(err, CodecError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn oversize_read_is_rejected_before_alloc() {
        // Hand-craft a length prefix claiming 10 MiB; reader must reject on the
        // length alone without trying to allocate/read the body.
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            let _ = a.write_all(&(10u32 * 1024 * 1024).to_le_bytes()).await;
        });
        let err = read_frame::<_, ControlFrame>(&mut b, MAX_CONTROL_FRAME)
            .await
            .unwrap_err();
        assert!(matches!(err, CodecError::TooLarge { .. }));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn preamble_roundtrip_and_bad_magic() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_preamble(&mut a).await.unwrap();
        assert_eq!(read_preamble(&mut b).await.unwrap(), PROTOCOL_VERSION);

        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"XXXX\x01\x00").await.unwrap();
        let err = read_preamble(&mut b).await.unwrap_err();
        assert!(matches!(err, CodecError::BadMagic));
    }

    #[tokio::test]
    async fn truncated_frame_reads_as_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Valid length prefix (5) but only 2 body bytes, then close.
        a.write_all(&5u32.to_le_bytes()).await.unwrap();
        a.write_all(&[1, 2]).await.unwrap();
        drop(a);
        let err = read_frame::<_, ControlFrame>(&mut b, MAX_CONTROL_FRAME)
            .await
            .unwrap_err();
        assert!(err.is_eof(), "expected EOF, got {err:?}");
    }
}
