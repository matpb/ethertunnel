//! Property-based fuzzing: no byte sequence may panic a wire decoder.
//! panic=abort in release means a decoder panic on untrusted input kills the relay.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use async_tungstenite::tungstenite::Message;
use async_tungstenite::WebSocketStream;
use futures::io::AsyncReadExt as FuturesAsyncReadExt;
use proptest::prelude::*;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::compat::TokioAsyncReadCompatExt;

use ethertunnel_proto::codec::{read_frame, write_frame, CodecError};
use ethertunnel_proto::frames::{
    ControlFrame, DenyCode, ErrorCode, Resource, Secret, StreamHeader,
};
use ethertunnel_proto::limits::{
    MAX_CLAIM_ENTRIES, MAX_CONTROL_FRAME, MAX_STREAM_HEADER, MAX_WS_MESSAGE,
};
use ethertunnel_proto::transport::{mux_io, Role};

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

/// AsyncRead over a fixed byte buffer that panics if asked for more than
/// `cap` bytes total, proving `read_frame` never over-reads a declared limit.
struct CappedReader {
    data: std::io::Cursor<Vec<u8>>,
    served: usize,
    cap: usize,
}

impl CappedReader {
    fn new(data: Vec<u8>, cap: usize) -> Self {
        Self {
            data: std::io::Cursor::new(data),
            served: 0,
            cap,
        }
    }
}

impl AsyncRead for CappedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let n = std::io::Read::read(&mut this.data, buf.initialize_unfilled())?;
        buf.advance(n);
        this.served += n;
        assert!(
            this.served <= this.cap,
            "reader served {} bytes past declared cap {}",
            this.served,
            this.cap
        );
        Poll::Ready(Ok(()))
    }
}

fn arb_string() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => "[-.a-zA-Z0-9_]{0,32}",
        1 => "[-.a-zA-Z0-9_]{0,4096}",
        1 => proptest::collection::vec(any::<u8>(), 0..70_000usize)
            .prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
    ]
}

fn arb_len_biased_len() -> impl Strategy<Value = usize> {
    prop_oneof![
        60 => 0usize..=70_000usize,
        10 => Just(MAX_CONTROL_FRAME),
        10 => Just(MAX_CONTROL_FRAME + 1),
        5 => Just(MAX_CONTROL_FRAME.saturating_sub(1)),
        10 => Just(MAX_STREAM_HEADER),
        10 => Just(MAX_STREAM_HEADER + 1),
        5 => Just(MAX_STREAM_HEADER.saturating_sub(1)),
    ]
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    arb_len_biased_len().prop_flat_map(|len| proptest::collection::vec(any::<u8>(), len))
}

fn arb_deny_code() -> impl Strategy<Value = DenyCode> {
    prop_oneof![
        Just(DenyCode::AuthFailed),
        Just(DenyCode::VersionUnsupported),
        Just(DenyCode::NotOwner),
        Just(DenyCode::UnknownHostname),
        Just(DenyCode::PortNotReserved),
        Just(DenyCode::PortUnavailable),
        Just(DenyCode::LimitExceeded),
        Just(DenyCode::ProtocolError),
    ]
}

fn arb_error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![Just(ErrorCode::MalformedClaim), Just(ErrorCode::Internal)]
}

fn arb_resource() -> impl Strategy<Value = Resource> {
    prop_oneof![
        arb_string().prop_map(Resource::Host),
        any::<u16>().prop_map(Resource::Port),
    ]
}

fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| IpAddr::V4(Ipv4Addr::from(o))),
        any::<[u8; 16]>().prop_map(|o| IpAddr::V6(Ipv6Addr::from(o))),
    ]
}

fn arb_hostnames() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(arb_string(), 0..=(MAX_CLAIM_ENTRIES + 1))
}

fn arb_ports() -> impl Strategy<Value = Vec<u16>> {
    proptest::collection::vec(any::<u16>(), 0..=(MAX_CLAIM_ENTRIES + 1))
}

fn arb_control_frame() -> impl Strategy<Value = ControlFrame> {
    prop_oneof![
        (arb_string(), arb_string(), any::<u16>(), any::<u16>()).prop_map(
            |(token, agent_version, proto_min, proto_max)| ControlFrame::Hello {
                token: Secret::from(token),
                agent_version,
                proto_min,
                proto_max,
            }
        ),
        (any::<u16>(), arb_string(), any::<u64>()).prop_map(
            |(proto, server_version, session_id)| ControlFrame::Welcome {
                proto,
                server_version,
                session_id,
            }
        ),
        (arb_deny_code(), arb_string())
            .prop_map(|(code, message)| ControlFrame::Denied { code, message }),
        (arb_hostnames(), arb_ports()).prop_map(|(hostnames, tcp_ports)| ControlFrame::Claim {
            hostnames,
            tcp_ports
        }),
        (arb_hostnames(), arb_ports()).prop_map(|(hostnames, tcp_ports)| ControlFrame::Granted {
            hostnames,
            tcp_ports
        }),
        any::<u64>().prop_map(|nonce| ControlFrame::Ping { nonce }),
        any::<u64>().prop_map(|nonce| ControlFrame::Pong { nonce }),
        arb_resource().prop_map(|resource| ControlFrame::Superseded { resource }),
        Just(ControlFrame::Goodbye),
        arb_string().prop_map(|reason| ControlFrame::Shutdown { reason }),
        (arb_error_code(), arb_string())
            .prop_map(|(code, message)| ControlFrame::Error { code, message }),
        (arb_hostnames(), arb_ports()).prop_map(|(hostnames, tcp_ports)| ControlFrame::Release {
            hostnames,
            tcp_ports
        }),
        (arb_hostnames(), arb_ports()).prop_map(|(hostnames, tcp_ports)| ControlFrame::Released {
            hostnames,
            tcp_ports
        }),
        Just(ControlFrame::ListOwned),
        (
            arb_hostnames(),
            arb_ports(),
            proptest::option::of(any::<i64>())
        )
            .prop_map(|(hostnames, tcp_ports, max_tunnels)| ControlFrame::Owned {
                hostnames,
                tcp_ports,
                max_tunnels,
            }),
    ]
}

fn arb_stream_header() -> impl Strategy<Value = StreamHeader> {
    prop_oneof![
        (arb_string(), arb_ip(), any::<u16>()).prop_map(|(host, peer_ip, peer_port)| {
            StreamHeader::Http {
                host,
                peer_ip,
                peer_port,
            }
        }),
        (any::<u16>(), arb_ip(), any::<u16>()).prop_map(|(port, peer_ip, peer_port)| {
            StreamHeader::Tcp {
                port,
                peer_ip,
                peer_port,
            }
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 500, .. ProptestConfig::default() })]

    /// Arbitrary bytes fed as a control frame must never panic the reader, and an
    /// oversized length prefix must be rejected without reading the body.
    #[test]
    fn read_frame_never_panics_control(bytes in arb_bytes()) {
        rt().block_on(async move {
            let mut reader = CappedReader::new(bytes, MAX_CONTROL_FRAME + 4);
            let _ = read_frame::<_, ControlFrame>(&mut reader, MAX_CONTROL_FRAME).await;
        });
    }

    /// Same property against the stream-header limit.
    #[test]
    fn read_frame_never_panics_stream_header(bytes in arb_bytes()) {
        rt().block_on(async move {
            let mut reader = CappedReader::new(bytes, MAX_STREAM_HEADER + 4);
            let _ = read_frame::<_, StreamHeader>(&mut reader, MAX_STREAM_HEADER).await;
        });
    }

    /// postcard decoding of arbitrary bytes must never panic, whatever the shape.
    #[test]
    fn postcard_from_bytes_never_panics(bytes in arb_bytes()) {
        let _ = postcard::from_bytes::<ControlFrame>(&bytes);
        let _ = postcard::from_bytes::<StreamHeader>(&bytes);
    }

    /// An arbitrary ControlFrame either round-trips exactly through the codec, or
    /// is cleanly rejected as too large; it never panics either half.
    #[test]
    fn control_frame_roundtrips_or_rejects(frame in arb_control_frame()) {
        let result: Result<(), TestCaseError> = rt().block_on(async move {
            let (mut a, mut b) = tokio::io::duplex(128 * 1024);
            match write_frame(&mut a, &frame, MAX_CONTROL_FRAME).await {
                Ok(()) => {
                    let got: ControlFrame = read_frame(&mut b, MAX_CONTROL_FRAME)
                        .await
                        .expect("write succeeded but read failed");
                    prop_assert_eq!(format!("{got:?}"), format!("{frame:?}"));
                }
                Err(CodecError::TooLarge { .. }) => {}
                Err(e) => prop_assert!(false, "unexpected write error: {e:?}"),
            }
            Ok(())
        });
        result?;
    }

    /// Same round-trip-or-reject property for StreamHeader.
    #[test]
    fn stream_header_roundtrips_or_rejects(header in arb_stream_header()) {
        let result: Result<(), TestCaseError> = rt().block_on(async move {
            let (mut a, mut b) = tokio::io::duplex(16 * 1024);
            match write_frame(&mut a, &header, MAX_STREAM_HEADER).await {
                Ok(()) => {
                    let got: StreamHeader = read_frame(&mut b, MAX_STREAM_HEADER)
                        .await
                        .expect("write succeeded but read failed");
                    prop_assert_eq!(got, header);
                }
                Err(CodecError::TooLarge { .. }) => {}
                Err(e) => prop_assert!(false, "unexpected write error: {e:?}"),
            }
            Ok(())
        });
        result?;
    }
}

#[derive(Debug, Clone)]
enum ArbWsFrame {
    Binary(Vec<u8>),
    Text(String),
    Ping(Vec<u8>),
    Close,
}

/// Byte lengths biased around the MAX_WS_MESSAGE (1 MiB) clamp, up to 2 MiB.
fn arb_ws_payload_len() -> impl Strategy<Value = usize> {
    prop_oneof![
        70 => 0usize..=2000usize,
        20 => (MAX_WS_MESSAGE.saturating_sub(4))..=(MAX_WS_MESSAGE + 4),
        10 => 0usize..=(2 * 1024 * 1024usize),
    ]
}

fn arb_ws_bytes() -> impl Strategy<Value = Vec<u8>> {
    arb_ws_payload_len().prop_flat_map(|len| proptest::collection::vec(any::<u8>(), len))
}

fn arb_ws_frame() -> impl Strategy<Value = ArbWsFrame> {
    prop_oneof![
        5 => arb_ws_bytes().prop_map(ArbWsFrame::Binary),
        3 => arb_ws_bytes().prop_map(|b| ArbWsFrame::Text(String::from_utf8_lossy(&b).into_owned())),
        1 => proptest::collection::vec(any::<u8>(), 0..=125usize).prop_map(ArbWsFrame::Ping),
        1 => Just(ArbWsFrame::Close),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    /// WsByteStream::poll_read must never panic on any inbound frame kind/size; an
    /// oversized binary message (past the MAX_WS_MESSAGE clamp) must error cleanly.
    #[test]
    fn ws_byte_stream_never_panics(frame in arb_ws_frame()) {
        let result: Result<(), TestCaseError> = rt().block_on(async move {
            let (a, b) = tokio::io::duplex(4 * 1024 * 1024);
            let mut reader = mux_io(a, Role::Server).await;
            let mut writer = WebSocketStream::from_raw_socket(b.compat(), Role::Client, None).await;

            let oversized = matches!(&frame, ArbWsFrame::Binary(d) if d.len() > MAX_WS_MESSAGE);
            let expect_len = match &frame {
                ArbWsFrame::Binary(d) if !oversized => Some(d.len()),
                _ => None,
            };

            let msg = match &frame {
                ArbWsFrame::Binary(d) => Message::binary(d.clone()),
                ArbWsFrame::Text(s) => Message::text(s.clone()),
                ArbWsFrame::Ping(d) => Message::Ping(d.clone()),
                ArbWsFrame::Close => Message::Close(None),
            };

            let send_res = writer.send(msg).await;
            let _ = send_res;
            // Close right after sending so non-data frames (Text/Ping/Close) end the
            // stream promptly instead of leaving the read waiting on more input.
            let _ = writer.close(None).await;

            let mut buf = vec![0u8; expect_len.unwrap_or(4096).max(1)];
            let read_res = match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                reader.read(&mut buf),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };

            if oversized {
                prop_assert!(read_res.is_err(), "oversized WS message did not error: {read_res:?}");
            } else if let Some(len) = expect_len {
                if let Ok(n) = read_res {
                    prop_assert!(n <= len);
                }
            }
            Ok(())
        });
        result?;
    }
}
