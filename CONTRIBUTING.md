# Contributing to EtherTunnel

Thanks for your interest in improving EtherTunnel. This guide covers the local
dev loop, the checks CI enforces, and what we look for in a pull request.

> Found a **security issue**? Do not open a public issue or PR — follow
> [SECURITY.md](SECURITY.md) instead.

## Prerequisites

- A Rust toolchain. The pinned channel and components live in
  [`rust-toolchain.toml`](rust-toolchain.toml) (stable, with `rustfmt` and
  `clippy`); `rustup` will pick them up automatically. The workspace MSRV is
  **1.85**.

EtherTunnel is a standard Cargo workspace of four crates: `proto` (the wire
contract), `relay` (the server), `client` (the daemon), and `cli` (the `etun`
binary). See the [README](README.md#architecture) for how they fit together.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
```

The test suite includes end-to-end integration tests that spin up a relay and a
client in-process over an in-memory transport — running the whole workspace
exercises them.

## Before you open a PR

CI runs these and fails on any of them, so run them locally first:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- **Formatting:** `cargo fmt --all` — no manual style debates, `rustfmt` is the
  arbiter.
- **Lints:** clippy is run with `-D warnings`, so warnings are errors. Fix them
  rather than `#[allow(...)]`-ing, unless there's a clear, commented reason.
- **Tests:** add or update tests for any behavior change. New protocol behavior
  or relay/client logic should come with coverage.

CI also test-compiles on Linux, macOS, and Windows and builds the static
`x86_64-unknown-linux-musl` relay binary, so keep changes cross-platform.

## A note on the wire protocol

`crates/proto` is a **frozen contract** between the relay and the daemon. The
bootstrap handshake (preamble + `Hello`/`Welcome`/`Denied`) never changes, and
within a protocol version the frame enums are **append-only** — postcard is not
self-describing, so reordering or removing variants is a silent wire break that
will break every deployed client. If you need a new frame or field, add it at the
end, and bump `PROTOCOL_VERSION` only with a deliberate, documented reason.

## Pull request expectations

- Keep PRs focused — one logical change per PR is easier to review.
- Write a clear description: what changed, why, and how you verified it.
- Reference any related issue.
- Make sure `fmt`, `clippy`, and `test` are green before requesting review.
- Update docs (README, `deploy/DEPLOY.md`, inline docs) when behavior, flags, or
  config change.

## Reporting bugs and proposing features

Open a GitHub issue with enough detail to reproduce (for bugs: version/commit,
OS, exact commands, and what you expected vs. what happened). For larger
features, opening an issue to discuss the approach before writing code saves
everyone time.

By contributing, you agree your contributions are licensed under the project's
[LICENSE](LICENSE).
