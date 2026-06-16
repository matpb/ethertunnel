---
name: tunnel-manager
description: >-
  Manage EtherTunnel reverse tunnels with the `etun` CLI — expose a local port
  as a public HTTPS URL, list/add/remove tunnels, run the daemon, check status,
  and diagnose connectivity. Use when the user wants to share a local service
  publicly, set up a tunnel, or troubleshoot one.
---

# Tunnel manager

EtherTunnel exposes a local service as `https://<name>.<relay-domain>` over a
single outbound connection — no inbound ports, no firewall changes. One binary,
`etun`, is both the relay (server) and the client daemon.

## First-time setup

1. Get a bearer token from the relay operator.
2. Log in (stores the token; verifies it with a real handshake):

       etun login --relay <relay-domain> --token-stdin   # paste the token

## Everyday commands

- Add an HTTP tunnel for a local port:

      etun add <name> <local-port> [--hostname <label>] [--local-host <host>]

- Add a raw-TCP tunnel (e.g. SSH) on a public relay port:

      etun add ssh 22 --tcp 20022

- List configured tunnels (also shows your plan usage and flags any
  relay-owned labels that are no longer in your config):

      etun list [--json]

- Remove a tunnel from the config; this also releases its hostname/port on the
  relay so it stops counting against your plan's tunnel limit:

      etun remove <name>

- Release a hostname/port on the relay directly — handy to free an orphaned
  label that isn't in your local config (takes a tunnel name or a bare label):

      etun release <name-or-label>

- Run the daemon in the foreground (prints the public URLs once connected):

      etun up

- Run it as a background service that survives reboot:

      etun service install            # per-user (systemd/launchd/Windows)
      etun service install --system   # system-wide (needs root)
      etun service status
      etun logs -f                    # follow the daemon's logs

- Check status / diagnose:

      etun status [--json]
      etun doctor                     # config, credentials, relay TLS, auth

## How to help

- To "expose port 3000": `etun add app 3000` then `etun up`; the URL is
  `https://app.<relay-domain>`.
- If a tunnel is up but the page errors: the relay returns a branded 502/504
  when the local app is down — check that something is actually listening on the
  local port.
- If `etun up` reports auth failure: re-run `etun login` with a fresh token.
- `etun doctor` is the fastest triage: it checks the config, the stored token,
  the relay's live TLS certificate, and performs a real authenticated handshake.

## Relay operators

Run and administer a relay (see `deploy/DEPLOY.md`):

    etun serve --config /etc/ethertunnel/relay.toml
    etun admin --config <cfg> user add <name>
    etun admin --config <cfg> token create --user <name>
    etun admin --config <cfg> hostname add <label> --user <name>
    etun admin --config <cfg> doctor
