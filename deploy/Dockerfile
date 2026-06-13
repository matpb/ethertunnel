# EtherTunnel relay image: static musl `etun`, shipped on scratch.
#
# Build the binary on Alpine (host target is x86_64-unknown-linux-musl, so the
# result is fully static), then copy just the binary and a CA bundle onto
# scratch. The CA bundle is needed because instant-acme's HTTP client verifies
# Let's Encrypt with the platform trust store.
#
#   docker build -f deploy/Dockerfile -t ethertunnel/relay .
#   docker run -p 443:443 -v /etc/ethertunnel:/etc/ethertunnel ethertunnel/relay
FROM rust:alpine AS build
RUN apk add --no-cache build-base cmake perl ca-certificates
WORKDIR /src
COPY . .
RUN cargo build --release -p ethertunnel \
    && strip target/release/etun

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/etun /usr/local/bin/etun
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/etun"]
CMD ["serve", "--config", "/etc/ethertunnel/relay.toml"]
