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

## Quick start (client)

```sh
# 1. Log in with a token from your relay operator (verified before it's stored).
etun login --relay ethertunnel.com --token-stdin

# 2. Expose a local port.
etun add demo 8080          #  -> https://demo.ethertunnel.com
etun add ssh 22 --tcp 20022 #  -> tcp ethertunnel.com:20022

# 3. Run it (Ctrl-C to stop), or install it as a service.
etun up
etun service install        # survives reboot (systemd / launchd / Windows)

etun list           # configured tunnels
etun status         # live daemon state
etun logs -f        # follow logs
etun doctor         # diagnose config / credentials / relay TLS / auth
```

Tunnels are first-level hostnames: `demo.ethertunnel.com`. HTTP and WebSocket
are first-class; raw TCP maps a public relay port to a local one. When the local
app is down the relay serves a branded 502/504 so you know which side broke.

## Running a relay

A relay is one static binary on a small public VPS. See
[deploy/DEPLOY.md](deploy/DEPLOY.md) for the full walkthrough (DNS, systemd, the
Cloudflare DNS-01 token, staging → production certs). In short:

```sh
etun serve --config /etc/ethertunnel/relay.toml
etun admin --config <cfg> user add alice
etun admin --config <cfg> token create --user alice
etun admin --config <cfg> hostname add demo --user alice
etun admin --config <cfg> doctor
```

TLS is a single wildcard (`*.yourdomain.com` + apex) issued over the ACME
DNS-01 challenge with Cloudflare hosting the `_acme-challenge` records. The cert
is cached and hot-swapped on renewal; the relay never blocks on issuance (it
serves a self-signed stopgap while the first cert is minted).

## Workspace layout

| Crate | Purpose |
|-------|---------|
| `crates/proto` | Wire protocol: frames, codec, and the WebSocket↔yamux transport seam. The contract both halves share. |
| `crates/relay` | Relay server: TLS termination, hostname routing, session management, ACME. |
| `crates/client` | Client daemon: outbound connection, local proxying, config/credentials, service install. |
| `crates/cli` | The `etun` binary — clap dispatch into relay/client. |

## Building

```sh
cargo build --workspace
cargo test --workspace
```

A static, dependency-free Linux binary (for relay deployment) is built via
[deploy/Dockerfile](deploy/Dockerfile).

## License

MIT — see [LICENSE](LICENSE). Not affiliated with Cloudflare or ngrok.
