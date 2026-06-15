# EtherTunnel relay image: static musl `etun`, shipped on scratch.
#
# Build the binary on Alpine (host target is x86_64-unknown-linux-musl, so the
# result is fully static), then copy just the binary and a CA bundle onto
# scratch. The CA bundle is needed because instant-acme's HTTP client verifies
# Let's Encrypt with the platform trust store.
#
#   docker build -f deploy/Dockerfile -t ethertunnel/relay .
#
# The container runs as a non-root user (uid:gid 65532:65532). Binding :443
# (privileged) therefore needs CAP_NET_BIND_SERVICE granted at runtime:
#
#   docker run --cap-drop ALL --cap-add NET_BIND_SERVICE -p 443:443 \
#       -v /etc/ethertunnel:/etc/ethertunnel ethertunnel/relay
#
# Omitting --cap-add NET_BIND_SERVICE yields EACCES on bind(:443). Any mounted
# volumes (Cloudflare token, cert/state dir) must be readable/owned by uid 65532.
FROM rust:alpine AS build
RUN apk add --no-cache build-base cmake perl ca-certificates
WORKDIR /src
COPY . .
RUN cargo build --release -p ethertunnel \
    && strip target/release/etun
# Synthesize a passwd/group entry for the non-root uid:gid the scratch image runs
# as (65532 = the distroless `nonroot` convention) so getpwuid/whoami resolve.
RUN printf 'nonroot:x:65532:65532:nonroot:/nonexistent:/sbin/nologin\n' > /etc/passwd.nonroot \
    && printf 'nonroot:x:65532:\n' > /etc/group.nonroot

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /etc/passwd.nonroot /etc/passwd
COPY --from=build /etc/group.nonroot /etc/group
COPY --from=build /src/target/release/etun /usr/local/bin/etun
EXPOSE 443
# Drop root inside the container. :443 stays internal; the runtime must grant
# CAP_NET_BIND_SERVICE (see header) or bind(:443) fails with EACCES.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/etun"]
CMD ["serve", "--config", "/etc/ethertunnel/relay.toml"]
