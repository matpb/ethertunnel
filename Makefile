# EtherTunnel release Makefile
# ============================================================================
# Cuts a multi-platform release: builds the four `etun` binaries that install.sh
# expects, generates SHA256SUMS, and creates the GitHub release.
#
#   make release VERSION=v1.2.0    # build all 5 + checksums + GitHub release
#   make build-all                 # just build the 5 binaries into ./dist
#   make linux                     # linux x86_64 + aarch64 only (local Docker)
#   make darwin                    # macOS arm64 + x86_64 only (built on mat-air)
#   make windows                   # windows x86_64 (.exe) only (cargo-xwin)
#   make sums                      # (re)generate dist/SHA256SUMS
#   make clean
#
# HOW THE BINARIES ARE BUILT (no GitHub Actions — all from this desktop):
#   * linux x86_64 / aarch64 : static musl via `docker buildx`. aarch64 is built
#     under qemu emulation (slow, a few minutes). One-time host setup:
#         docker run --privileged --rm tonistiigi/binfmt --install arm64
#   * macOS arm64 / x86_64   : built NATIVELY on `mat-air` (the MacBook Air) over
#     Tailscale SSH — cross-compiling Apple targets from Linux is not worth it.
#     The committed HEAD is shipped with `git archive | ssh mat-air tar -x`, so
#     releases always build from committed source. One-time mat-air setup:
#         ssh mat-air 'rustup target add aarch64-apple-darwin x86_64-apple-darwin'
#     (Wake the Mac and `tailscale up` first if `make darwin` can't reach it.)
#   * windows x86_64 (msvc)  : cross-compiled from Linux with `cargo-xwin`
#     (clang + lld-link + the auto-downloaded MSVC CRT; no Windows host needed).
#     One-time host setup:
#         cargo install cargo-xwin && rustup target add x86_64-pc-windows-msvc
#         # plus clang + lld (e.g. via brew/llvm) on PATH
#
# PRECONDITIONS for `make release`:
#   * Bump the version first: workspace Cargo.toml [workspace.package] version
#     must equal VERSION without the leading `v` (checked by `make check-version`).
#   * The commit you are tagging must already be pushed to the GitHub default
#     branch — `gh release create` tags the remote head. (We keep the push a
#     deliberate, manual step; this Makefile never pushes for you.)
#   * `gh` authenticated for $(REPO).
#
# Asset names are the contract with ethertunnel-web/install.sh:
#   etun-linux-x86_64  etun-linux-aarch64  etun-darwin-x86_64  etun-darwin-arm64
#   etun-windows-x86_64.exe  plus SHA256SUMS.
# install.sh (POSIX sh) only auto-installs linux/macOS; Windows users grab the
# .exe from the release directly. Do not rename without updating install.sh.
# ============================================================================

REPO     ?= matpb/ethertunnel
MAC_HOST ?= mat-air
DIST     ?= dist
VERSION  ?=

# Apple binaries are built in this scratch dir on mat-air.
MAC_SRC  := ~/etun-src

WIN_TARGET := x86_64-pc-windows-msvc

.PHONY: help release build-all linux linux-x86_64 linux-aarch64 darwin windows sums clean check-version check-gh

help:
	@sed -n '2,40p' Makefile | sed 's/^# \{0,1\}//'

# --- full release -----------------------------------------------------------
release: check-version check-gh build-all sums
	@echo ">> Creating GitHub release $(VERSION) on $(REPO)"
	gh release create "$(VERSION)" \
	  "$(DIST)/etun-linux-x86_64" "$(DIST)/etun-linux-aarch64" \
	  "$(DIST)/etun-darwin-x86_64" "$(DIST)/etun-darwin-arm64" \
	  "$(DIST)/etun-windows-x86_64.exe" \
	  "$(DIST)/SHA256SUMS" \
	  --repo "$(REPO)" --title "EtherTunnel $(VERSION)" --generate-notes
	@echo ">> Done. Verify: curl -fsSL https://ethertunnel.com/install.sh | sh"

build-all: linux darwin windows
	@echo ">> Built all binaries into $(DIST)/"
	@ls -la $(DIST)/etun-* 2>/dev/null

# --- linux (static musl via Docker buildx) ----------------------------------
linux: linux-x86_64 linux-aarch64

linux-x86_64: | $(DIST)
	@echo ">> Building linux x86_64 (musl, docker)"
	docker buildx build -f deploy/Dockerfile --target export \
	  --platform linux/amd64 -o "type=local,dest=$(DIST)/.linux-amd64" .
	mv "$(DIST)/.linux-amd64/etun" "$(DIST)/etun-linux-x86_64"
	rm -rf "$(DIST)/.linux-amd64"

linux-aarch64: | $(DIST)
	@echo ">> Building linux aarch64 (musl, docker buildx + qemu — slow)"
	docker buildx build -f deploy/Dockerfile --target export \
	  --platform linux/arm64 -o "type=local,dest=$(DIST)/.linux-arm64" .
	mv "$(DIST)/.linux-arm64/etun" "$(DIST)/etun-linux-aarch64"
	rm -rf "$(DIST)/.linux-arm64"

# --- macOS (built on mat-air over Tailscale SSH) ----------------------------
darwin: | $(DIST)
	@echo ">> Building macOS arm64 + x86_64 on $(MAC_HOST)"
	@ssh -o ConnectTimeout=8 "$(MAC_HOST)" 'uname -sm' >/dev/null 2>&1 || \
	  { echo "ERROR: cannot reach $(MAC_HOST). Wake the Mac and run 'tailscale up'."; exit 1; }
	git archive HEAD | ssh "$(MAC_HOST)" 'rm -rf $(MAC_SRC) && mkdir -p $(MAC_SRC) && tar -x -C $(MAC_SRC)'
	ssh "$(MAC_HOST)" 'cd $(MAC_SRC) && \
	  ~/.cargo/bin/rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true; \
	  ~/.cargo/bin/cargo build --release -p ethertunnel \
	    --target aarch64-apple-darwin --target x86_64-apple-darwin && \
	  strip -x target/aarch64-apple-darwin/release/etun target/x86_64-apple-darwin/release/etun || true'
	scp "$(MAC_HOST):$(MAC_SRC)/target/aarch64-apple-darwin/release/etun" "$(DIST)/etun-darwin-arm64"
	scp "$(MAC_HOST):$(MAC_SRC)/target/x86_64-apple-darwin/release/etun" "$(DIST)/etun-darwin-x86_64"

# --- windows (cross-compiled from Linux via cargo-xwin) ---------------------
windows: | $(DIST)
	@echo ">> Building windows x86_64 (msvc, cargo-xwin)"
	@command -v cargo-xwin >/dev/null || { echo "ERROR: cargo-xwin not found (cargo install cargo-xwin)."; exit 1; }
	cargo xwin build --release --target $(WIN_TARGET) -p ethertunnel
	cp "target/$(WIN_TARGET)/release/etun.exe" "$(DIST)/etun-windows-x86_64.exe"

# --- checksums --------------------------------------------------------------
sums: | $(DIST)
	@echo ">> Generating SHA256SUMS"
	cd "$(DIST)" && sha256sum etun-linux-x86_64 etun-linux-aarch64 \
	  etun-darwin-x86_64 etun-darwin-arm64 etun-windows-x86_64.exe > SHA256SUMS
	@cat "$(DIST)/SHA256SUMS"

$(DIST):
	mkdir -p "$(DIST)"

clean:
	rm -rf "$(DIST)"

# --- guards -----------------------------------------------------------------
check-version:
	@test -n "$(VERSION)" || { echo "VERSION is required, e.g. make release VERSION=v1.2.0"; exit 1; }
	@v=$$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/'); \
	 want=$$(printf '%s' "$(VERSION)" | sed 's/^v//'); \
	 test "$$v" = "$$want" || { echo "Cargo.toml version ($$v) != $(VERSION) — bump [workspace.package] version first."; exit 1; }
	@git diff --quiet || { echo "WARNING: working tree is dirty; releases build from committed HEAD via git archive."; }

check-gh:
	@command -v gh >/dev/null || { echo "ERROR: gh CLI not found."; exit 1; }
	@gh auth status >/dev/null 2>&1 || { echo "ERROR: gh not authenticated (gh auth login)."; exit 1; }
