//! EtherTunnel wire protocol crate.
//!
//! This crate is the *contract* between the relay and the client daemon. It is
//! deliberately runtime-light: no TLS, no hyper, no SQLite — just the frame
//! definitions, the length-prefixed codec, and the WebSocket↔yamux transport
//! seam that both halves build on. Keeping it minimal makes the protocol easy
//! to test over an in-memory duplex (see `transport` tests) and easy to reason
//! about when the wire format must stay stable across versions.

pub mod limits;
pub mod transport;

/// Highest wire-protocol version this build speaks.
///
/// The bootstrap frame set (Hello/Welcome/Denied) is frozen forever; within a
/// version, enum variants are append-only. Anything else bumps this number and
/// is negotiated in the Hello/Welcome exchange.
pub const PROTOCOL_VERSION: u16 = 1;

/// Magic bytes that prefix the control stream: ASCII `"ETUN"`.
pub const CONTROL_MAGIC: [u8; 4] = *b"ETUN";
