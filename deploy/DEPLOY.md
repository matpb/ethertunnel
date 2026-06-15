# Deploying the EtherTunnel relay

A relay is one static binary on a small public VPS. These notes cover a fresh
deployment on Ubuntu using systemd (the binary + systemd path; the Docker image
in `Dockerfile` is an alternative).

## Prerequisites

- A domain whose DNS is on Cloudflare.
- A Cloudflare API token with **Zone:DNS:Edit** + **Zone:Zone:Read** on that zone.
- A VPS with a public IP (a 512 MB droplet is plenty; the relay uses <100 MB).

## 1. DNS

Point the apex, the wildcard, and the control endpoint at the VPS, **DNS-only**
(grey cloud — traffic must not transit Cloudflare):

    A   ethertunnel.com           -> <VPS_IP>   (DNS only)
    A   *.ethertunnel.com         -> <VPS_IP>   (DNS only)
    A   connect.ethertunnel.com   -> <VPS_IP>   (DNS only)

## 2. Binary + user

    # build a static musl binary (locally, via Docker) and copy it up:
    docker build -f deploy/Dockerfile --target build -t etun-build .
    id=$(docker create etun-build); docker cp $id:/src/target/release/etun ./etun; docker rm $id
    scp etun root@<VPS_IP>:/usr/local/bin/etun

    # on the VPS:
    useradd --system --no-create-home --shell /usr/sbin/nologin etun
    mkdir -p /etc/ethertunnel /var/lib/ethertunnel
    chown -R etun:etun /var/lib/ethertunnel

## 3. Config + token

    cp deploy/relay.toml.example /etc/ethertunnel/relay.toml   # edit domain/email/zone_id
    printf '%s' '<CLOUDFLARE_TOKEN>' > /etc/ethertunnel/cloudflare.token
    chmod 600 /etc/ethertunnel/cloudflare.token
    chown etun:etun /etc/ethertunnel/cloudflare.token

Keep `staging = true` in `[tls.acme]` for the first boot.

## 4. Service

    cp deploy/etun-relay.service /etc/systemd/system/etun-relay.service
    systemctl daemon-reload
    systemctl enable --now etun-relay
    etun admin --config /etc/ethertunnel/relay.toml doctor   # DNS, registry, Cloudflare, cert

## 5. Staging -> production cert

Watch the log for a staging certificate (`acme: new wildcard installed`), then:

    # set staging = false in /etc/ethertunnel/relay.toml
    rm -f /var/lib/ethertunnel/tls/cert.pem /var/lib/ethertunnel/tls/key.pem
    systemctl restart etun-relay

The relay issues a real Let's Encrypt wildcard and hot-swaps it on renewal.

## 6. Create a user + token

    etun admin --config /etc/ethertunnel/relay.toml user add <you>
    etun admin --config /etc/ethertunnel/relay.toml token create --user <you>
    etun admin --config /etc/ethertunnel/relay.toml hostname add demo --user <you>

Hand the token to the client: `etun login --relay ethertunnel.com --token-stdin`.

## Client (--system) install

The per-user install (`etun service install`, no flag) needs nothing beyond
`etun login` — it runs as your login user and reads `~/.config/etun`. The
`--system` install runs the client daemon under a hardened systemd unit with
`DynamicUser=yes` + `StateDirectory=etun`, so systemd allocates a locked-down
transient service user and creates `/var/lib/etun` owned by it — there is **no**
`useradd` and no stable uid. Two pieces of state cross into that sandbox:

- the **bearer token** (the secret) is bridged in via systemd `LoadCredential`
  from a root-owned file — it never touches the DynamicUser-owned disk;
- the **relay host** (not a secret) is seeded once into `config.toml` inside the
  StateDirectory.

`etun service install --system` writes the unit, creates `/etc/etun` and
`/var/lib/etun`, and **enables but does not start** the service — because the
hardened unit must be provisioned first (`LoadCredential` makes `/etc/etun/token`
mandatory: systemd refuses to start the unit without it). Provision the two
pieces, then start once. No crash-loop, no stop/seed/start dance.

**a. (as your user) Mint the token, exactly as for a per-user setup:**

    etun login --relay <relay-host> --token-stdin   # writes ~/.config/etun/{config.toml,credentials.toml}

**b. (as root) Install the service** (writes the unit + creates the dirs, enabled
but not started):

    sudo etun service install --system

**c. (as root) Place the bearer token outside the sandbox.** Copy the value
stored under `[tokens]."<relay-host>"` in `~/.config/etun/credentials.toml`:

    printf '%s' "<TOKEN>" | sudo install -D -m 0600 -o root -g root /dev/stdin /etc/etun/token

`/etc/etun/token` is **root:root 0600**. systemd reads it as root at start and
copies it into a private per-uid tmpfs (mode 0400) that only the transient
service user can read; the daemon picks it up via `ETUN_TOKEN_FILE`. The token
never lands in `/var/lib/etun`.

**d. (as root) Seed the non-secret config** (relay host + any tunnels) into the
StateDirectory at mode 0644 so the transient service user can read it:

    printf 'relay = "<relay-host>"\n' | sudo install -m 0644 /dev/stdin /var/lib/etun/config.toml

`config.toml` carries no secret (just `relay = "..."` and your tunnel
definitions); 0644 is fine and is readable whatever uid systemd assigns.

**e. (as root) Start and verify:**

    sudo systemctl start etun.service
    sudo systemctl status etun.service
    journalctl -u etun.service

**To rotate the token:** overwrite `/etc/etun/token`, then
`sudo systemctl restart etun.service` (the tmpfs credential is re-copied each
start).

**systemd version note:** `LoadCredential=` and the `%d`/`$CREDENTIALS_DIRECTORY`
expansion require **systemd 247+** (shipped by Ubuntu 22.04+, Debian 12+, and
RHEL/Alma 9). On systemd 235–246, skip step (c) and instead supply the token via
a drop-in — `sudo systemctl edit etun.service` and add:

    [Service]
    Environment=ETUN_TOKEN=<TOKEN>

The daemon's `ETUN_TOKEN_FILE` read is best-effort, so it falls through cleanly
to the `ETUN_TOKEN` env value.

## Backups

The registry is SQLite (WAL). Back it up live with:

    sqlite3 /var/lib/ethertunnel/registry.db ".backup '/var/backups/registry.db'"
