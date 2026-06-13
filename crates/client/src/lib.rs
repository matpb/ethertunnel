//! EtherTunnel client daemon.
//!
//! Opens a single outbound WebSocket to the relay (no inbound ports, no
//! firewall changes) and exposes local services as public HTTPS endpoints.
//!
//! Built incrementally — see the milestone plan. M0 establishes the workspace
//! and the proto transport seam; client internals land in M2+.
