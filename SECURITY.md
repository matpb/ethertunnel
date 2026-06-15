# Security Policy

EtherTunnel terminates public TLS and brokers traffic from untrusted visitors to
services on a private network. We take its security posture seriously, and we
welcome responsible disclosure from the community.

The project has been through two adversarially-verified security audits
(2026-06-13 and 2026-06-15), in which every candidate finding had to survive an
adversarial refutation panel before being accepted. Confirmed findings were
remediated and the fixes were re-stress-tested. We expect this file to be the
front door for anything those audits did not catch.

## Reporting a vulnerability

**Please report security issues privately. Do not open a public GitHub issue,
pull request, or discussion for a suspected vulnerability.**

Email **security@ethertunnel.com** with:

- a description of the issue and its impact,
- the affected component (relay, client daemon, or wire protocol) and version or commit,
- clear, minimal reproduction steps or a proof-of-concept, and
- any suggested remediation, if you have one.

If you want to encrypt your report or arrange a secure channel (PGP, Signal),
say so in an initial low-detail email and we'll set one up.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial **assessment and severity triage** within 7 business days.
- Coordinated disclosure: we'll agree on a timeline with you, aim to ship a fix
  before any public detail is published, and credit you in the advisory unless
  you'd rather stay anonymous.

Please give us a reasonable window to remediate before any public disclosure.

## Scope

**In scope** — the code in this repository:

- The relay (`etun serve`): TLS termination, the ACME/cert path, the listener and
  admission controls, session and stream handling, the router, the SQLite
  registry, and the optional admin/provisioning HTTP endpoints.
- The client daemon (`etun up`): the outbound connection, local forwarding,
  credential storage, and service-install paths.
- The wire protocol (`crates/proto`): the control-frame codec, transport seam,
  and limits.

Examples of issues we care about: authentication or authorization bypass on the
relay (token forgery, claiming hostnames/ports you don't own, cross-tenant
leakage), TLS or certificate-handling flaws, request-smuggling or header-spoofing
through the proxy, resource-exhaustion / DoS that a single client or visitor can
trigger, secret exposure (tokens, private keys, the Cloudflare API token), and
memory-safety issues in any `unsafe` code.

**Out of scope:**

- The hosted relay at `ethertunnel.com` as an operational service (rate limits,
  uptime, abuse handling) — report code issues here; report service issues to the
  operator, and abuse of the hosted service to **abuse@ethertunnel.com** (see
  below).
- Vulnerabilities in third-party dependencies that aren't reachable through
  EtherTunnel's use of them (please still tell us if a `cargo audit` advisory
  *is* reachable).
- Findings that require a misconfigured deployment that contradicts
  [deploy/DEPLOY.md](deploy/DEPLOY.md) (e.g. an inlined Cloudflare token, a
  world-readable credentials file, or running the relay as root without the
  documented hardening).
- Social engineering, physical attacks, and denial-of-service via raw volumetric
  flooding of the network link.

## Operator hardening notes

If you self-host a relay, a few deployment-side controls are part of your
security boundary and are documented in
[deploy/relay.toml.example](deploy/relay.toml.example) and
[deploy/DEPLOY.md](deploy/DEPLOY.md):

- Keep the Cloudflare API token in its own file at mode `0600`, owned by the
  relay user — **never inline it in `relay.toml`**.
- Run the relay under the provided hardened systemd unit (unprivileged user,
  `CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, etc.).
- Treat bearer tokens as secrets: they're stored only as SHA-256 hashes on the
  relay, but the plaintext is shown once at creation and lives in the client's
  `0600` credentials file.

## Reporting abuse

This is distinct from a security vulnerability. If a tunnel on the **hosted**
relay at `ethertunnel.com` is being used for phishing, malware distribution,
command-and-control, or other abuse, email **abuse@ethertunnel.com** with the
tunnel hostname (or URL) and what you observed. We act on hosted-service abuse
reports directly.

If you self-host your own relay, you are its operator — report abuse of it to
whoever runs that deployment.

Thank you for helping keep EtherTunnel and the people who run it safe.
