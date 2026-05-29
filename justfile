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

# Install desktop npm dependencies
desktop-deps:
	cd desktop && npm install

# Run desktop app in dev mode
desktop-dev: desktop-deps
	cd desktop && npm run tauri dev

# Build desktop app (production bundle)
desktop-build: desktop-deps
	cd desktop && npm run tauri build

# ── E2E Smoke Test ─────────────────────────────────────────────────────────

# End-to-end smoke test (requires release build)
e2e: build-release
	#!/usr/bin/env bash
	set -euo pipefail
	VAULT=$(mktemp -d)
	CLI="target/release/{{ binary }} --vault-path $VAULT"
	rm -f /tmp/idtty.sock /tmp/idtty.tok
	echo "Vault: $VAULT"
	echo ""
	echo "=== INIT ===" && printf "testpass123\ntestpass123\n" | target/release/{{ binary }} init --vault-path "$VAULT"
	echo ""
	echo "=== DAEMON ===" && target/release/{{ daemon }} --vault-path "$VAULT" &>/tmp/idtty-daemon.log & DAEMON_PID=$!; sleep 1
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
	rm -f /tmp/idtty.sock /tmp/idtty.tok
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
