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

## Backups

The registry is SQLite (WAL). Back it up live with:

    sqlite3 /var/lib/ethertunnel/registry.db ".backup '/var/backups/registry.db'"
