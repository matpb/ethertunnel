//! EtherTunnel relay server.
//!
//! Terminates public TLS for `*.<domain>`, routes visitor traffic by `Host`
//! header to client daemons connected over multiplexed reverse tunnels.
//!
//! Built incrementally — see the milestone plan. M0 establishes the workspace
//! and the proto transport seam; relay internals land in M1+.
