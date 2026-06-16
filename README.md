# EtherTunnel

> **ngrok you own** — a self-hostable reverse tunnel in Rust.

<div align="center">

[![CI](https://github.com/matpb/ethertunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/matpb/ethertunnel/actions/workflows/ci.yml)
![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-informational)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

</div>

Expose a local service as a public HTTPS endpoint on **your own domain** — no
inbound ports, no firewall changes, no third-party tunnel service in the middle.
One static binary plays both roles: run the relay on a small public VPS, run the
client daemon on your machine, and your `localhost:8080` is live at
`myapp.yourdomain.com` over TLS.

## Why

Hosted tunnel services are convenient until you care where your traffic goes,
what hostname you get, or what it costs at scale. EtherTunnel gives you the same
ergonomics on infrastructure you control:

- **No inbound ports.** The client dials *out* to the relay over a single WebSocket, so it works behind NAT and locked-down firewalls with nothing to open.
- **Your domain, your certs.** Tunnels live at `<label>.yourdomain.com` with wildcard Let's Encrypt TLS the relay issues and renews on its own.
- **One binary, both ends.** `etun serve` is the relay; `etun up` is the client. Same cross-platform binary, no separate packages.
- **Multi-tenant by design.** A token-gated SQLite registry of users, hostnames, and ports — hand out tokens, hand out hostnames, revoke either.

## Quickstart (60 seconds)

```sh
# 1. Install the `etun` binary.
#    Linux / macOS:
curl -fsSL https://ethertunnel.com/install.sh | sh
#    Windows (PowerShell):  irm https://ethertunnel.com/install.ps1 | iex

# 2. Log in with a token from your relay operator (verified before it's stored).
etun login --relay ethertunnel.com --token-stdin

# 3. Expose a local port and go live.
etun add web 3000          #  -> https://web.ethertunnel.com
etun up                    #  Ctrl-C to stop
```

That's it — `https://web.ethertunnel.com` now forwards to your local `:3000`.
Point `--relay` at your own domain instead to use a relay you host (see
[Self-host your own relay](#self-host-your-own-relay)).

Everyday client commands:

```sh
etun add ssh 22 --tcp 20022   # raw-TCP tunnel: tcp ethertunnel.com:20022 -> localhost:22
etun list                     # configured tunnels
etun status                   # live daemon state
etun logs -f                  # follow logs
etun doctor                   # diagnose config / credentials / relay TLS / auth
etun service install          # run as a background service (systemd / launchd / Windows)
etun remove web               # drop a tunnel (also releases it on the relay)
etun release web              # free a relay-owned label/port without editing config
```

Config lives at `~/.config/etun/config.toml` (no secrets — safe to commit/sync).
Bearer tokens are stored separately in `credentials.toml` at mode `0600`.

## Features

- **HTTP and WebSocket tunnels** at first-level hostnames (`demo.yourdomain.com`). WebSocket upgrades are spliced through transparently.
- **Raw-TCP tunnels** that map a public relay port to a local one (`etun add ssh 22 --tcp 20022`), from a configurable port range (default `20000–20999`).
- **Automatic wildcard TLS** — a single `*.yourdomain.com` + apex certificate issued over the ACME DNS-01 challenge (Cloudflare-hosted `_acme-challenge` records), cached and hot-swapped on renewal with zero downtime. The relay never blocks on issuance: it serves a self-signed stopgap while the first cert mints.
- **Single multiplexed connection.** All visitor traffic for a client rides one outbound WebSocket, yamux-multiplexed, with end-to-end flow-control backpressure — no whole-body buffering.
- **Token-gated multi-tenant registry** in SQLite: users, tokens, hostnames, and TCP ports. Bearer tokens are stored only as SHA-256 hashes — the relay never holds the plaintext.
- **Branded error pages.** When the local app is down, the relay distinguishes "no such tunnel" (404), "daemon unreachable" (502), and "upstream timeout" (504); the daemon serves its own branded 502/504 when the *local* service is the one that's down, so you always know which side broke.
- **Anti-DoS admission control** on the relay: per-IP accept-rate limiting (IPv6 keyed by /64), connection caps overall and per IP, and a slowloris-bounding header-read timeout.
- **Cross-platform background service.** `etun service install` survives reboots via systemd (user or hardened system unit), launchd, or Windows services.
- **Reconnect that just works.** The daemon reconnects with jittered exponential backoff and re-claims its hostnames/ports idempotently (newest-wins on the relay), so a relay restart or network blip self-heals.

## Drive it from your AI agent

EtherTunnel ships an **agent skill** at [`skills/tunnel-manager/SKILL.md`](skills/tunnel-manager/SKILL.md)
so an AI coding agent can set up and manage tunnels for you. Ask it to "expose
port 3000" and it runs `etun add` + `etun up`, hands back the public URL, and
can triage with `etun doctor` — no need to remember the commands yourself.

It's written for **[Claude Code](https://claude.com/claude-code)** — copy the
folder into your project's `.claude/skills/` (or load it via a plugin) and the
agent discovers it automatically:

```sh
mkdir -p .claude/skills && cp -r skills/tunnel-manager .claude/skills/
```

But it's just a Markdown file with a short YAML header — no lock-in. Any agentic
system that reads skill/tool descriptions (the Claude Agent SDK, or your own
harness) can use the same file or port it in minutes.

## Architecture

```
                          your VPS                          your machine
                ┌──────────────────────────┐         ┌──────────────────────┐
   visitor ───▶ │  relay  :443             │         │  etun up (daemon)    │
   (HTTPS /     │  ─ terminates public TLS │  one    │                      │
    raw TCP)    │  ─ routes by Host / port │◀ ─ WSS ─│  dials OUT, no       │
                │  ─ session + registry    │  + yamux│  inbound ports       │
                └──────────────────────────┘  mux    └──────────┬───────────┘
                                                                 │ splice
                                                                 ▼
                                                        127.0.0.1:3000
                                                        (your local app)
```

The client daemon opens exactly one **outbound** WebSocket to `connect.<domain>`
and runs a yamux stream multiplexer over it. The relay terminates public TLS for
`*.<domain>` on a single `:443` socket and routes each visitor by `Host` header
(HTTP) or by public port (raw TCP) to the owning client's session, opening a
fresh multiplexed stream per visitor connection. The daemon reads a small header
off each stream and byte-splices it to the local target. Because the only
connection that crosses the network boundary is the client's outbound one, no
ports ever need to be opened on the client side — that is the whole point.

The trust boundary is deliberate: the relay authenticates **clients** by an
opaque bearer token (stored only as a SHA-256 hash); **visitors** are untrusted
and never authenticated. The codebase is split into three crates — `proto` (the
frozen wire contract: frames, codec, and the WebSocket↔yamux transport seam),
`relay` (TLS/ACME, listener, sessions, router, registry, raw-TCP), and `client`
(config, supervisor, local forwarder) — plus the `etun` CLI.

| Crate | Purpose |
|-------|---------|
| `crates/proto` | Wire protocol: frames, codec, and the WebSocket↔yamux transport seam. The contract both halves share. |
| `crates/relay` | Relay server: TLS termination, hostname routing, session management, ACME. |
| `crates/client` | Client daemon: outbound connection, local proxying, config/credentials, service install. |
| `crates/cli` | The `etun` binary — clap dispatch into relay/client. |

## Self-host your own relay

A relay is one static binary on a small public VPS (a 512 MB instance is plenty;
it uses under 100 MB) behind a Cloudflare-hosted DNS zone for ACME wildcard
certs. The full walkthrough — DNS records, the static musl build, the hardened
systemd unit, the staging → production certificate flow, and creating users,
tokens, and hostnames — lives in **[deploy/DEPLOY.md](deploy/DEPLOY.md)**.

In short, on the relay host:

```sh
etun serve --config /etc/ethertunnel/relay.toml
etun admin --config <cfg> user add alice
etun admin --config <cfg> token create --user alice   # prints the token once
etun admin --config <cfg> hostname add demo --user alice
etun admin --config <cfg> doctor                       # DNS / registry / TLS / ACME pre-flight
```

Then hand the token to a client with
`etun login --relay your-domain.com --token-stdin`.

## Building from source

EtherTunnel is a standard Cargo workspace (Rust edition 2021, MSRV 1.85):

```sh
cargo build --workspace
cargo test --workspace
```

For the relay, a static, dependency-free Linux binary is produced by the
two-stage [deploy/Dockerfile](deploy/Dockerfile) (`x86_64-unknown-linux-musl` on
Alpine, copied into a `scratch` image with just the CA bundle). See
[CONTRIBUTING.md](CONTRIBUTING.md) for the formatting, lint, and test
expectations.

## Security

EtherTunnel terminates public TLS and brokers untrusted visitor traffic, so it
takes security seriously. It has been through **two adversarially-verified
security audits** (2026-06-13 and 2026-06-15) in which every finding had to
survive an adversarial refutation panel before being accepted; the first audit's
findings were remediated and the second re-stress-tested those fixes. This is
not a claim of being bug-free — the audits surfaced real issues (DoS-hardening
gaps and a secret-exposure race) that were then fixed.

Found something? Please report it **privately** — see
[SECURITY.md](SECURITY.md) for the disclosure process. Do not open a public
issue for security reports.

Abuse of the hosted relay at `ethertunnel.com` (phishing, malware,
command-and-control, etc.): email **abuse@ethertunnel.com**.

## Support

Questions, bug reports, and feature requests: open a
[GitHub issue](https://github.com/matpb/ethertunnel/issues). Please keep the
issue tracker for those — security vulnerabilities and abuse reports go to the
private addresses above.

## License

EtherTunnel is licensed under the **GNU Affero General Public License v3.0 or
later** ([AGPL-3.0-or-later](LICENSE)). It is free and open source: self-host it,
modify it, and run it for anything. The one obligation is reciprocity — if you
run a modified version as a network service, you must offer your users the
modified source under the same license.

A separate **commercial license** is available from the author for anyone who
wants to build on EtherTunnel without the AGPL's source-sharing terms — what it
covers, what stays free, and how to ask for a quote is in
[COMMERCIAL.md](COMMERCIAL.md). Short version: unmodified self-hosting needs no
license; the commercial license is for running a *modified* relay as a service
or embedding it in a closed product. Reach out at license@ethertunnel.com.

Not affiliated with Cloudflare or ngrok.
