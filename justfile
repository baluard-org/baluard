set unstable

# ── IDtty build system ──────────────────────────────────────────────────────
# Usage: just <target>
# Help:  just            (lists all targets)
# ────────────────────────────────────────────────────────────────────────────

binary      := "idtty"
daemon      := "idtty-daemon"
build_dir   := "bin"
dist_dir    := "dist"
version     := trim(shell("grep -A1 '^\\[workspace.package\\]' Cargo.toml | grep '^version' | sed 's/.*= *\"\\(.*\\)\".*$/\\1/'"))

os          := if os_family() == "windows" { "windows" } else if os() == "macos" { "macos" } else { "linux" }
arch        := if arch() == "aarch64" { "arm64" } else if arch() == "x86_64" { "amd64" } else { arch() }
ext         := if os == "windows" { ".exe" } else { "" }

libgit2_pkg := absolute_path(join(home_directory(), ".linuxbrew/Cellar/libgit2/1.9.3/lib/pkgconfig"))
openssl_pkg := absolute_path(join(home_directory(), ".linuxbrew/Cellar/openssl@3/3.6.2/lib/pkgconfig"))
libgit2_lib := absolute_path(join(home_directory(), ".linuxbrew/Cellar/libgit2/1.9.3/lib"))
openssl_lib := absolute_path(join(home_directory(), ".linuxbrew/Cellar/openssl@3/3.6.2/lib"))
zlib_lib    := absolute_path(join(home_directory(), ".linuxbrew/opt/zlib-ng-compat/lib"))
linuxbrew_env := if os == "linux" && path_exists(libgit2_lib) { "PKG_CONFIG_PATH=" + libgit2_pkg + ":" + openssl_pkg + ":$PKG_CONFIG_PATH LD_LIBRARY_PATH=" + libgit2_lib + ":" + zlib_lib + ":" + openssl_lib + ":$LD_LIBRARY_PATH" } else { "" }

# ── Default ─────────────────────────────────────────────────────────────────

default:
	@just --list --unsorted

# ── Build ───────────────────────────────────────────────────────────────────

# Build all Rust crates (debug)
build:
	{{ linuxbrew_env }} cargo build

# Build optimized release binaries
build-release:
	{{ linuxbrew_env }} cargo build --release

# Build and install CLI + daemon to ~/.local/bin
install-local: build-release
	@mkdir -p ~/.local/bin
	@cp target/release/{{ binary }} ~/.local/bin/{{ binary }}
	@cp target/release/{{ daemon }} ~/.local/bin/{{ daemon }}
	@echo "Installed: ~/.local/bin/{{ binary }}, ~/.local/bin/{{ daemon }}"

# Build and install to /usr/local/bin (requires sudo)
install: build-release
	@sudo cp target/release/{{ binary }} /usr/local/bin/{{ binary }}
	@sudo cp target/release/{{ daemon }} /usr/local/bin/{{ daemon }}
	@echo "Installed: /usr/local/bin/{{ binary }}, /usr/local/bin/{{ daemon }}"

# Uninstall from ~/.local/bin
uninstall-local:
	@rm -f ~/.local/bin/{{ binary }} ~/.local/bin/{{ daemon }}
	@echo "Uninstalled from ~/.local/bin"

# Uninstall from /usr/local/bin
uninstall:
	@sudo rm -f /usr/local/bin/{{ binary }} /usr/local/bin/{{ daemon }}
	@echo "Uninstalled from /usr/local/bin"

# ── Test ────────────────────────────────────────────────────────────────────

# Run all tests
test:
	{{ linuxbrew_env }} cargo test

# Run tests in release mode
test-release:
	{{ linuxbrew_env }} cargo test --release

# Run core library tests only
test-core:
	{{ linuxbrew_env }} cargo test -p idtty-core

# Run tests with output
test-verbose:
	{{ linuxbrew_env }} cargo test -- --nocapture

# ── Lint & Format ───────────────────────────────────────────────────────────

# Check formatting
fmt-check:
	cargo fmt --check --all

# Apply formatting
fmt:
	cargo fmt --all

# Run clippy
lint:
	{{ linuxbrew_env }} cargo clippy --all-targets -- -D warnings

# Run clippy with --fix
lint-fix:
	{{ linuxbrew_env }} cargo clippy --fix --allow-dirty --all-targets

# ── Full Check ──────────────────────────────────────────────────────────────

# Run all checks: fmt + clippy + test + build
check: fmt-check lint test build
	@echo "All checks passed."

# ── Desktop (Tauri) ────────────────────────────────────────────────────────

# Kill any running idtty-daemon process (by socket or by name)
_kill_daemon:
	#!/usr/bin/env bash
	set +e
	# Method 1: find process by socket file
	SOCK="${XDG_RUNTIME_DIR:-/tmp}/idtty.sock"
	[[ "$OSTYPE" == "darwin"* ]] && SOCK="$HOME/.config/idtty/idtty.sock"
	if [ -S "$SOCK" ]; then
		PID=$(lsof -t -U "$SOCK" 2>/dev/null || true)
		if [ -n "$PID" ]; then
			kill $PID 2>/dev/null
			echo "Stopped daemon (pid=$PID) on socket $SOCK"
			sleep 0.3
		fi
		rm -f "$SOCK"
	fi
	# Method 2: find by process name (fallback)
	pkill -f 'idtty-daemon' 2>/dev/null && echo "Stopped idtty-daemon process" || true
	sleep 0.2

# Unconditionally rebuild sidecar binaries (no staleness check)
_sidecar-force:
	#!/usr/bin/env bash
	set -euo pipefail
	TRIPLE=$(rustc -vV | grep host | cut -d' ' -f2)
	mkdir -p desktop/src-tauri/binaries
	{{ linuxbrew_env }} cargo build --release -p idtty-daemon -p idtty-cli
	cp target/release/idtty-daemon "desktop/src-tauri/binaries/idtty-daemon-$TRIPLE"
	cp target/release/idtty "desktop/src-tauri/binaries/idtty-$TRIPLE"
	# Force-refresh sidecar in tauri target/debug
	mkdir -p desktop/src-tauri/target/debug
	cp "desktop/src-tauri/binaries/idtty-daemon-$TRIPLE" "desktop/src-tauri/target/debug/idtty-daemon"
	cp "desktop/src-tauri/binaries/idtty-$TRIPLE" "desktop/src-tauri/target/debug/idtty"
	echo "Sidecar rebuilt (forced): idtty-daemon-$TRIPLE"

# Build daemon sidecar for current platform (Tauri needs target-triple suffix)
_sidecar:
	#!/usr/bin/env bash
	set -euo pipefail
	TRIPLE=$(rustc -vV | grep host | cut -d' ' -f2)
	mkdir -p desktop/src-tauri/binaries

	# Staleness check: skip cargo+copy if sidecar is newer than all Rust sources
	SIDECAR="desktop/src-tauri/binaries/idtty-daemon-$TRIPLE"
	if [ -f "$SIDECAR" ]; then
	  # Find any .rs file newer than the sidecar binary
	  NEWEST_SRC=$(find crates -name '*.rs' -newer "$SIDECAR" -print -quit 2>/dev/null || true)
	  if [ -z "$NEWEST_SRC" ]; then
	    echo "Sidecar up-to-date (no Rust changes detected)"
	  else
	    {{ linuxbrew_env }} cargo build --release -p idtty-daemon -p idtty-cli
	    cp target/release/idtty-daemon "$SIDECAR"
	    cp target/release/idtty "desktop/src-tauri/binaries/idtty-$TRIPLE"
	    echo "Sidecar rebuilt: $SIDECAR"
	  fi
	else
	    {{ linuxbrew_env }} cargo build --release -p idtty-daemon -p idtty-cli
	    cp target/release/idtty-daemon "$SIDECAR"
	    cp target/release/idtty "desktop/src-tauri/binaries/idtty-$TRIPLE"
	    echo "Sidecar rebuilt: $SIDECAR"
	fi

	# Force-refresh sidecar in tauri target/debug (tauri-build copies from binaries/
	# to target/debug/ during compilation, but a stale cross-platform binary from
	# another host's cargo build can cause "cannot execute binary file" on exec).
	mkdir -p desktop/src-tauri/target/debug
	cp "desktop/src-tauri/binaries/idtty-daemon-$TRIPLE" "desktop/src-tauri/target/debug/idtty-daemon"
	cp "desktop/src-tauri/binaries/idtty-$TRIPLE" "desktop/src-tauri/target/debug/idtty"

# Install desktop npm dependencies
desktop-deps:
	cd desktop && npm install

# Run desktop app in dev mode
desktop-dev: _sidecar-force desktop-deps
	#!/usr/bin/env bash
	set -euo pipefail
	just _kill_daemon
	cd desktop && npm run tauri dev

# Run desktop app with full debug logging (IDTTY_DEBUG=1)
# Logs go to ./logs/ (daemon.log + desktop.log)
# Share: zip logs/ or paste the relevant file
desktop-debug: _sidecar-force desktop-deps
	#!/usr/bin/env bash
	set -euo pipefail
	just _kill_daemon
	LOG_DIR="$(pwd)/logs"
	mkdir -p "$LOG_DIR"
	# Clear previous logs for a clean session
	rm -f "$LOG_DIR/daemon.log" "$LOG_DIR/desktop.log"
	echo "Logs → $LOG_DIR/"
	echo "  daemon.log  — IPC routing, crypto, vault operations"
	echo "  desktop.log — Tauri bridge, daemon requests/responses"
	echo ""
	IDTTY_DEBUG=1 IDTTY_LOG_DIR="$LOG_DIR" cd desktop && npm run tauri dev

# Build desktop app (production bundle)
desktop-build: _sidecar desktop-deps
	cd desktop && npm run tauri build

# ── E2E Smoke Test ─────────────────────────────────────────────────────────

# End-to-end smoke test (requires release build)
e2e: build-release
	#!/usr/bin/env bash
	set -euo pipefail
	VAULT=$(mktemp -d)
	SOCK=$(mktemp -u /tmp/idtty-test-XXXXX)
	CLI="target/release/{{ binary }} --vault-path $VAULT --socket $SOCK"
	echo "Vault: $VAULT Socket: $SOCK"
	echo ""
	echo "=== INIT ===" && printf "testpass123\ntestpass123\n" | target/release/{{ binary }} init --vault-path "$VAULT"
	echo ""
	echo "=== DAEMON ===" && target/release/{{ daemon }} --vault-path "$VAULT" --socket "$SOCK" &>/tmp/idtty-daemon.log & DAEMON_PID=$!; sleep 1
	echo "=== PING ===" && $CLI ping
	echo ""
	echo "=== UNLOCK ===" && $CLI unlock <<< "testpass123"
	echo ""
	echo "=== ADD ===" && $CLI add --name "Test" --username "user@test.com" --password "secret123"
	UUID=$($CLI list 2>&1 | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
	echo "UUID: $UUID"
	echo ""
	echo "=== GET ===" && $CLI get "$UUID" 2>&1
	echo ""
	echo "=== DELETE ===" && $CLI delete "$UUID"
	echo ""
	echo "=== LIST (empty) ===" && $CLI list
	echo ""
	echo "=== LOCK ===" && $CLI lock
	echo ""
	kill $DAEMON_PID 2>/dev/null; wait $DAEMON_PID 2>/dev/null || true
	rm -f "$SOCK" "${SOCK%.sock}.tok"
	rm -rf "$VAULT"
	echo ""
	echo "E2E passed."

# ── Clean ───────────────────────────────────────────────────────────────────

# Clean build artifacts
clean:
	cargo clean
	rm -rf {{ build_dir }} {{ dist_dir }}

# ── Release ─────────────────────────────────────────────────────────────────

# Cross-compile for all targets
cross-compile:
	#!/usr/bin/env bash
	set -euo pipefail
	mkdir -p {{ dist_dir }}
	TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"
	for target in $TARGETS; do
	echo "Building for $target..."
	{{ linuxbrew_env }} cargo build --release --target "$target" || echo "SKIP: $target (add rustup target)"
	done
	echo "Done."

# Build release archives (tar.gz + checksums)
release: build-release
	#!/usr/bin/env bash
	set -euo pipefail
	mkdir -p {{ dist_dir }}
	for bin in target/release/{{ binary }} target/release/{{ daemon }}; do
	[ -f "$bin" ] || { echo "Missing: $bin"; exit 1; }
	done
	ARCHIVE="{{ binary }}-{{ version }}-{{ os }}-{{ arch }}.tar.gz"
	tar -czf "{{ dist_dir }}/$ARCHIVE" \
	-C target/release {{ binary }} {{ daemon }}
	cd {{ dist_dir }} && shasum -a 256 "$ARCHIVE" > checksums.txt
	echo "Release {{ version }}: {{ dist_dir }}/$ARCHIVE"
	cat {{ dist_dir }}/checksums.txt

# Build release + ad-hoc codesign (macOS; no-op on Linux)
build-signed: build-release
	#!/usr/bin/env bash
	set -euo pipefail
	if [ "{{ os }}" = "macos" ]; then
	codesign --force -s - target/release/{{ binary }}
	codesign --force -s - target/release/{{ daemon }}
	echo "Signed: target/release/{{ binary }}, target/release/{{ daemon }}"
	else
	echo "Codesign skipped (non-macOS)"
	fi
	mkdir -p {{ build_dir }}
	cp target/release/{{ binary }}{{ ext }} {{ build_dir }}/
	cp target/release/{{ daemon }}{{ ext }} {{ build_dir }}/
	echo "Built: {{ build_dir }}/"

# ── Version ─────────────────────────────────────────────────────────────────

# Show version
version:
	@echo "{{ binary }} {{ version }}"
