# EtherTunnel

Self-hosted reverse tunnels in Rust. Expose a local service as a public HTTPS
endpoint on your own domain — no inbound ports, no firewall changes, no
third-party tunnel service. One static binary plays both roles:

- `etun serve` — the **relay**, on a small public VPS. Terminates TLS for
  `*.yourdomain.com` and routes visitor traffic by hostname to connected
  clients over a single multiplexed connection.
- `etun up` — the **client daemon**, on your machine. Opens one outbound
  WebSocket to the relay and forwards `myapp.yourdomain.com → localhost:8080`.

```
visitor ──HTTPS──▶ relay :443 ──┐
                                │  one outbound WSS + yamux multiplexing
your machine (etun up) ─────────┘
   └──▶ localhost:8080
```

It is, roughly, "ngrok you own": a token-gated hostname registry, wildcard
Let's Encrypt certificates issued automatically, and HTTP/WebSocket plus raw
TCP forwarding — all in a single cross-platform binary you host yourself.

> **Status: early development.** Built milestone by milestone; see the internal
> plan. The transport core (WebSocket ↔ yamux multiplexing with bounded
> backpressure) is implemented and tested.

## Workspace layout

| Crate | Purpose |
|-------|---------|
| `crates/proto` | Wire protocol: frames, codec, and the WebSocket↔yamux transport seam. The contract both halves share. |
| `crates/relay` | Relay server: TLS termination, hostname routing, session management, ACME. |
| `crates/client` | Client daemon: outbound connection, local proxying, service install. |
| `crates/cli` | The `etun` binary — clap dispatch into relay/client. |

## Building

```sh
cargo build --workspace
cargo test --workspace
```

## License

MIT — see [LICENSE](LICENSE). Not affiliated with Cloudflare or ngrok.
