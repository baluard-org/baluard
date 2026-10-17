set unstable
set lists

# ── Baluard build system ──────────────────────────────────────────────────────
# Usage: just <target>
# Help:  just            (lists all targets)
# ────────────────────────────────────────────────────────────────────────────

binary      := "baluard"
daemon      := "baluard-daemon"
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
# System pkg-config dirs must be explicit when linuxbrew exists: brew's
# pkg-config shadows the system one and never searches /usr/lib64/pkgconfig,
# which breaks gdk/webkit resolution for the desktop build.
linuxbrew_env := if os == "linux" && path_exists(libgit2_lib) { "PKG_CONFIG_PATH=" + libgit2_pkg + ":" + openssl_pkg + ":/usr/lib64/pkgconfig:/usr/share/pkgconfig:$PKG_CONFIG_PATH LD_LIBRARY_PATH=" + libgit2_lib + ":" + zlib_lib + ":" + openssl_lib + ":$LD_LIBRARY_PATH" } else { "" }

# ── Default ─────────────────────────────────────────────────────────────────

default:
	@just --list --unsorted

# ── System dependency preflight ─────────────────────────────────────────────

# Check Linux build dependencies (protoc for cargo builds, WebKitGTK/GTK for the
# desktop app) and print the install command for your distro when something is
# missing. Baluard never installs system packages itself.
# scope: core = protoc (cargo builds/tests) | desktop = adds WebKitGTK/GTK | all
sysdeps scope="all":
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ "$(uname -s)" != "Linux" ]]; then
		echo "Not Linux, skipping system dependency check."
		exit 0
	fi
	# Force system pkg-config dirs: linuxbrew's pkg-config shadows the system one
	# and never searches /usr/lib64/pkgconfig, which would cause false negatives.
	pc_libdirs="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig"
	if machine="$(gcc -dumpmachine 2>/dev/null)"; then
		pc_libdirs="$pc_libdirs:/usr/lib/$machine/pkgconfig"
	fi
	pc_libdirs="$pc_libdirs:/usr/lib64/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig"
	export PKG_CONFIG_LIBDIR="$pc_libdirs"
	want_desktop=1
	[[ "{{scope}}" == "core" ]] && want_desktop=0
	miss_protoc=0; miss_webkit=0; miss_gtk=0; miss_tray=0
	if [[ -z "${PROTOC:-}" ]] && ! command -v protoc >/dev/null 2>&1; then
		miss_protoc=1
	fi
	if (( want_desktop )); then
		if command -v pkg-config >/dev/null 2>&1; then
			pkg-config --exists webkit2gtk-4.1 2>/dev/null || miss_webkit=1
			pkg-config --exists gtk+-3.0 2>/dev/null || miss_gtk=1
			pkg-config --exists ayatana-appindicator3-0.1 2>/dev/null || miss_tray=1
		else
			miss_webkit=1; miss_gtk=1; miss_tray=1
		fi
	fi
	if (( miss_protoc == 0 && miss_webkit == 0 && miss_gtk == 0 && miss_tray == 0 )); then
		echo "System dependencies OK."
		exit 0
	fi
	missing=""
	(( miss_protoc )) && missing="protobuf-compiler (protoc)"
	(( miss_webkit )) && missing="${missing:+$missing }webkit2gtk"
	(( miss_gtk ))    && missing="${missing:+$missing }gtk3"
	(( miss_tray ))   && missing="${missing:+$missing }ayatana-appindicator"
	os_id="$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')"
	os_like="$(sed -n 's/^ID_LIKE=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')"
	distro="unknown"
	case "$os_id" in
		ubuntu|debian) distro="apt" ;;
		fedora|rhel|rocky|almalinux|nobara) distro="dnf" ;;
		arch|manjaro|endeavouros|garuda|cachyos) distro="pacman" ;;
		*) case "$os_like" in
			*debian*) distro="apt" ;;
			*fedora*|*rhel*) distro="dnf" ;;
			*arch*) distro="pacman" ;;
		esac ;;
	esac
	echo "ERROR: missing system libraries: $missing"
	echo "Baluard does not install system packages for you. Run the command below, then retry:"
	case "$distro:$want_desktop" in
		apt:0)    echo "  sudo apt install protobuf-compiler" ;;
		apt:1)    echo "  sudo apt install protobuf-compiler libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev libgtk-3-dev libayatana-appindicator3-dev pkg-config" ;;
		dnf:0)    echo "  sudo dnf install protobuf-compiler" ;;
		dnf:1)    echo "  sudo dnf install protobuf-compiler webkit2gtk4.1-devel gtk3-devel libayatana-appindicator-gtk3-devel pkgconf-pkg-config" ;;
		pacman:0) echo "  sudo pacman -S protobuf" ;;
		pacman:1) echo "  sudo pacman -S protobuf webkit2gtk-4.1 gtk3 libayatana-appindicator pkgconf" ;;
		*) echo "  Debian/Ubuntu: sudo apt install protobuf-compiler libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev libgtk-3-dev libayatana-appindicator3-dev pkg-config"
		   echo "  Fedora:        sudo dnf install protobuf-compiler webkit2gtk4.1-devel gtk3-devel libayatana-appindicator-gtk3-devel pkgconf-pkg-config"
		   echo "  Arch:          sudo pacman -S protobuf webkit2gtk-4.1 gtk3 libayatana-appindicator pkgconf" ;;
	esac
	(( miss_protoc )) && echo "(alternatively: brew install protobuf, or export PROTOC=/path/to/protoc)"
	exit 1

# Internal: core deps gate (protoc, needed by every cargo build/test)
_sysdeps-core:
	@just sysdeps core

# Internal: desktop deps gate (adds WebKitGTK + GTK for the Tauri app)
_sysdeps-desktop:
	@just sysdeps desktop

# ── Build ───────────────────────────────────────────────────────────────────

# Build all Rust crates (debug)
build: _sysdeps-core
	{{ linuxbrew_env }} cargo build

# Build optimized release binaries
build-release: _sysdeps-core
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
# BALUARD_DISABLE_KEYRING: hermetic tests. On hosts with a live Secret
# Service whose collection is locked, keyring reads inside vault open/unlock
# block forever on an unlock prompt no GUI answers (CI has no D-Bus and fails
# fast; dev boxes do not). The env var routes keyring-backed paths to their
# fail-closed fallbacks (crate::keyring_disabled).
test: _sysdeps-core
	BALUARD_DISABLE_KEYRING=1 {{ linuxbrew_env }} cargo test

# Run tests in release mode
# See the BALUARD_DISABLE_KEYRING note on `test`.
test-release:
	BALUARD_DISABLE_KEYRING=1 {{ linuxbrew_env }} cargo test --release

# Run core library tests only
test-core:
	{{ linuxbrew_env }} cargo test -p baluard-core

# Run CLI integration tests only (spawns the baluard binary against temp vaults)
test-cli:
	{{ linuxbrew_env }} cargo test -p baluard-cli

# E2E harness (docs/e2e-testing.md Phase 1): builds the cli + daemon binaries
# with the e2e-hooks transport relaxation, then runs the e2e integration
# target against the real daemon. Excluded from `just test` by design:
# `cargo test -p baluard-cli` alone leaves the daemon binary stale.
test-e2e:
	{{ linuxbrew_env }} cargo build -p baluard-cli -p baluard-daemon --features baluard-cli/e2e-hooks,baluard-daemon/e2e-hooks
	BALUARD_DISABLE_KEYRING=1 BALUARD_E2E=1 {{ linuxbrew_env }} cargo test -p baluard-cli --test e2e --features baluard-cli/e2e-hooks

# Desktop E2E (Phase 3): the real app headless via tauri-driver. Needs
# tauri-driver (cargo install tauri-driver --locked), Xvfb, and a fresh
# desktop build; see e2e/desktop/run-e2e-desktop.sh.
e2e-desktop *ARGS:
	bash e2e/desktop/run-e2e-desktop.sh {{ARGS}}

# Decode the committed golden backup vector with the reference decryptor
# (scripts/decrypt_backup.py). Needs: pip install argon2-cffi cryptography
# (Python's stdlib has neither Argon2id nor AES-GCM). Exits 0 only when the
# third-party implementation reads exactly what Baluard writes.
decrypt-vector:
	BALUARD_BACKUP_PASSPHRASE='correct horse battery staple' \
		python3 scripts/decrypt_backup.py crates/baluard-core/tests/golden/backup-v1.bldbak

# Run native messaging host tests (stdio<->daemon bridge)
test-nmh:
	{{ linuxbrew_env }} cargo test -p baluard-nmh

# Run browser extension tests (vitest + jsdom, mock chrome.* APIs)
test-browser:
	cd browser/shared && npm test

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

# L7 fix: Run cargo-audit to check for known security advisories in dependencies.
# Skipped silently if cargo-audit is not installed.
audit:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "cargo-audit not installed (run: cargo install cargo-audit --locked)"; \
	fi

# ── Full Check ──────────────────────────────────────────────────────────────

# Run all checks: fmt + clippy + audit + test + build
check: fmt-check lint audit test build
	@echo "All checks passed."

# ── Desktop (Tauri) ────────────────────────────────────────────────────────

# Kill any running baluard-daemon process (exact binary match only)
_kill_daemon:
	#!/usr/bin/env bash
	set +e
	SOCK="${XDG_RUNTIME_DIR:-$HOME/.local/share/baluard}/baluard.sock"
	[[ "$OSTYPE" == "darwin"* ]] && SOCK="$HOME/Library/Application Support/baluard/baluard.sock"

	# pgrep -x matches exact binary name only — no collateral damage
	pgrep -x 'baluard-daemon' 2>/dev/null | while IFS= read -r pid; do
		[ -z "$pid" ] && continue
		kill "$pid" 2>/dev/null
		echo "Stopped daemon (pid=$pid)"
	done

	# Clean up stale socket
	rm -f "$SOCK"
	sleep 0.2

# Kill ALL running Baluard processes: daemon, desktop app, NMH, CLI.
# Used by desktop-debug so every run starts from a clean stack (no stale
# daemons holding the socket, no orphan NMH workers from a prior browser
# session, no lingering desktop). Exact binary-name match only — no
# collateral damage to other processes.
_kill_procs:
	#!/usr/bin/env bash
	set +e
	SOCK="${XDG_RUNTIME_DIR:-$HOME/.local/share/baluard}/baluard.sock"
	[[ "$OSTYPE" == "darwin"* ]] && SOCK="$HOME/Library/Application Support/baluard/baluard.sock"

	for proc in baluard-daemon baluard-desktop baluard-nmh baluard; do
		pgrep -x "$proc" 2>/dev/null | while IFS= read -r pid; do
			[ -z "$pid" ] && continue
			kill "$pid" 2>/dev/null
			echo "Stopped $proc (pid=$pid)"
		done
	done

	# Clean up stale socket
	rm -f "$SOCK"
	sleep 0.3

# Unconditionally rebuild sidecar binaries (no staleness check)
_sidecar-force:
	#!/usr/bin/env bash
	set -euo pipefail
	TRIPLE=$(rustc -vV | grep host | cut -d' ' -f2)
	mkdir -p desktop/src-tauri/binaries
	{{ linuxbrew_env }} cargo build --release -p baluard-daemon -p baluard-cli -p baluard-nmh
	cp target/release/baluard-daemon "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE"
	cp target/release/baluard "desktop/src-tauri/binaries/baluard-$TRIPLE"
	# Force-refresh sidecar in tauri target/debug
	mkdir -p desktop/src-tauri/target/debug
	cp "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE" "desktop/src-tauri/target/debug/baluard-daemon"
	cp "desktop/src-tauri/binaries/baluard-$TRIPLE" "desktop/src-tauri/target/debug/baluard"
	echo "Sidecar rebuilt (forced): baluard-daemon-$TRIPLE"
	just _sign-sidecar

# Build daemon sidecar for current platform (Tauri needs target-triple suffix)
_sidecar:
	#!/usr/bin/env bash
	set -euo pipefail
	TRIPLE=$(rustc -vV | grep host | cut -d' ' -f2)
	mkdir -p desktop/src-tauri/binaries

	# Staleness check: skip cargo+copy if sidecars are newer than all Rust
	# sources. Reference mtime is the OLDER of (daemon sidecar, NMH binary) so
	# a change to EITHER crate triggers a rebuild (NMH sources can change
	# without touching daemon sources, and vice versa).
	SIDECAR="desktop/src-tauri/binaries/baluard-daemon-$TRIPLE"
	NMH_BIN="target/release/baluard-nmh"
	NEWEST_REFERENCE="$SIDECAR"
	if [ -f "$NMH_BIN" ] && [ "$NMH_BIN" -nt "$NEWEST_REFERENCE" ]; then
	  NEWEST_REFERENCE="$NMH_BIN"
	fi
	if [ -f "$SIDECAR" ] && [ -f "$NMH_BIN" ]; then
	  NEWEST_SRC=$(find crates -name '*.rs' -newer "$NEWEST_REFERENCE" -print -quit 2>/dev/null || true)
	  if [ -z "$NEWEST_SRC" ]; then
	    echo "Sidecars up-to-date (no Rust changes detected)"
	  else
	    {{ linuxbrew_env }} cargo build --release -p baluard-daemon -p baluard-cli -p baluard-nmh
	    cp target/release/baluard-daemon "$SIDECAR"
	    cp target/release/baluard "desktop/src-tauri/binaries/baluard-$TRIPLE"
	    echo "Sidecars rebuilt (stale): $SIDECAR, $NMH_BIN"
	  fi
	else
	    {{ linuxbrew_env }} cargo build --release -p baluard-daemon -p baluard-cli -p baluard-nmh
	    cp target/release/baluard-daemon "$SIDECAR"
	    cp target/release/baluard "desktop/src-tauri/binaries/baluard-$TRIPLE"
	    echo "Sidecars rebuilt (missing): $SIDECAR, $NMH_BIN"
	fi

	# Force-refresh sidecar in tauri target/debug (tauri-build copies from binaries/
	# to target/debug/ during compilation, but a stale cross-platform binary from
	# another host's cargo build can cause "cannot execute binary file" on exec).
	mkdir -p desktop/src-tauri/target/debug
	cp "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE" "desktop/src-tauri/target/debug/baluard-daemon"
	cp "desktop/src-tauri/binaries/baluard-$TRIPLE" "desktop/src-tauri/target/debug/baluard"
	just _sign-sidecar

# Sign daemon sidecar with a stable Apple Development identity.
# Without this, cargo ad-hoc-signs the binary with a random identifier and a
# cdhash-based designated requirement. Every rebuild changes the cdhash, so the
# macOS keychain ACL from "Always Allow" never matches and the daemon is
# re-prompted for the login password on every unlock (device privkey) and every
# sync-tab open (provider tokens). Signing with a real cert makes the DR bind to
# the certificate (stable across rebuilds) — prompt once, then it sticks.
# No-op on non-macOS or when no signing identity is present.
_sign-sidecar:
	#!/usr/bin/env bash
	set -euo pipefail
	[ "{{ os }}" = "macos" ] || { echo "Sign skipped (non-macOS)"; exit 0; }
	TRIPLE=$(rustc -vV | grep host | cut -d' ' -f2)
	SIDECAR="desktop/src-tauri/binaries/baluard-daemon-$TRIPLE"
	TARGET_DEBUG="desktop/src-tauri/target/debug/baluard-daemon"
	[ -f "$SIDECAR" ] || { echo "Not found: $SIDECAR"; exit 1; }
	IDENTITY=$(security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db 2>/dev/null \
		| grep "Apple Development" | head -1 | awk -F'"' '{print $2}' || true)
	if [ -z "$IDENTITY" ]; then
		echo "⚠ No 'Apple Development' signing identity — keychain will re-prompt each run."
		echo "  Fix: Xcode → Settings → Accounts → add Apple ID, then rerun."
		exit 0
	fi
	for BIN in "$SIDECAR" "$TARGET_DEBUG"; do
		[ -f "$BIN" ] || continue
		codesign --force --sign "$IDENTITY" --identifier xyz.actitud.baluard.daemon "$BIN"
		echo "Signed: $BIN"
	done

# Install desktop npm dependencies
desktop-deps:
	cd desktop && npm install

# Codesign the Tauri debug binary. Run after first desktop-debug or when Rust changes.
codesign:
	#!/usr/bin/env bash
	set -euo pipefail
	BINARY="desktop/src-tauri/target/debug/baluard-desktop"
	if [ ! -f "$BINARY" ]; then echo "Not found: $BINARY. Run desktop-debug first."; exit 1; fi
	ENTITLEMENTS="desktop/src-tauri/baluard.entitlements"
	IDENTITY=$(security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db 2>/dev/null \
		| grep "Apple Development" | head -1 | sed 's/.*"\(.*\)".*/\1/' || true)
	if [ -z "$IDENTITY" ]; then
		echo "⚠ No 'Apple Development' signing identity."
		echo "  Fix: Xcode → Settings → Accounts → add Apple ID"
		exit 1
	fi
	codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" --options runtime "$BINARY"
	echo "Signed: $BINARY ($IDENTITY)"

# Run desktop app in dev mode
desktop-dev: _sysdeps-desktop _sidecar-force desktop-deps
	#!/usr/bin/env bash
	set -euo pipefail
	# linuxbrew's pkg-config shadows the system one (brew-only default search
	# path); put system dirs on PKG_CONFIG_PATH so webkit/gtk/gdk resolve.
	if [[ "$(uname -s)" == "Linux" ]]; then
		export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
	fi
	just _kill_daemon
	cd desktop && npm run tauri dev

# Run desktop app with full debug logging (BALUARD_DEBUG=1)
# Logs go to ./logs/ (daemon.log + desktop.log)
# Share: zip logs/ or paste the relevant file
desktop-debug: _sysdeps-desktop _sidecar-force desktop-deps
	#!/usr/bin/env bash
	set -euo pipefail
	# Same pkg-config shadowing guard as desktop-dev.
	if [[ "$(uname -s)" == "Linux" ]]; then
		export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
	fi
	just _kill_procs
	LOG_DIR="$(pwd)/logs"
	mkdir -p "$LOG_DIR"
	# Clear previous logs for a clean session
	rm -f "$LOG_DIR/daemon.log" "$LOG_DIR/desktop.log"
	echo "Logs → $LOG_DIR/"
	echo "  daemon.log  — IPC routing, crypto, vault operations"
	echo "  desktop.log — Tauri bridge, daemon requests/responses"
	echo ""
	BALUARD_DEBUG=1 BALUARD_LOG_DIR="$LOG_DIR" cd desktop && npm run tauri dev

# Build desktop app (production bundle)
desktop-build: _sysdeps-desktop _sidecar desktop-deps
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ "$(uname -s)" == "Linux" ]]; then
		export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
		# linuxdeploy's bundled strip predates .relr.dyn sections (type 0x13)
		# in Fedora 44+ system libs and fails every AppImage bundle with
		# "failed to run linuxdeploy". NO_STRIP skips its strip pass; the
		# RPM/DEB bundles are unaffected.
		export NO_STRIP=true
	fi
	{{ linuxbrew_env }} cd desktop && npm run tauri build

# Install-and-launch smoke test for a built Linux package (deb or rpm).
# Usage: just smoke-pkg desktop/src-tauri/target/release/bundle/deb/*.deb
# Installs with the distro package manager (declared runtime deps must
# resolve — this catches soname drift), launches under Xvfb, asserts the
# daemon socket appears, saves a screenshot. See scripts/linux-smoke.sh.
smoke-pkg pkg:
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ "$(uname -s)" != "Linux" ]]; then
		echo "Linux only."
		exit 1
	fi
	bash scripts/linux-smoke.sh "{{pkg}}"

# ── App Icons ──────────────────────────────────────────────────────────────

# Generate app icons for ALL platforms (Windows/macOS/Linux desktop + Android/iOS mobile)
# from the brand SVGs and deploy them everywhere:
#   - desktop/src-tauri/icons/     (Tauri bundle icons)
#   - desktop/src/assets/logo.png  (browser-extension toolbar icon source)
#   - mobile/androidApp res/       (launcher mipmaps + ADAPTIVE icon layers, so the
#                                  launcher masks a full tile instead of shrink-
#                                  wrapping a legacy bitmap on white)
# Output bundle: assets/app-icons/{windows,macos,linux,tauri-desktop,android,ios}/
# No arguments; sources are fixed: assets/baluard-lock-l4.svg (tile)
# + assets/baluard-lock-only.svg (glyph). Tooling: rsvg-convert + magick + python3.
app-icons:
	./scripts/generate-all-icons.sh

# ── E2E Smoke Test ─────────────────────────────────────────────────────────

# Seed TWO demo vaults (personal + work) with realistic mixed test data.
# Used for multi-vault switch testing. Password for both: baluard99
# Each vault gets a mix: logins, cards, notes, identities, passkeys, banks,
# plus folders and tags. Removes existing demo vaults first (preserves others).
# Seeded data is committed to each vault's git history (baluard sync commit),
# so a manual push carries the entries — not just meta.
seed-demo: build-release
	#!/usr/bin/env bash
	set -euo pipefail
	export BALUARD_PASSWORD=baluard99

	# Detect platform data directory
	case "$(uname -s)" in
		Darwin) DATA_DIR="$HOME/Library/Application Support/baluard" ;;
		Linux)  DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/baluard" ;;
		MINGW*|MSYS*|CYGWIN*) DATA_DIR="$LOCALAPPDATA/baluard" ;;
		*)      DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/baluard" ;;
	esac
	VAULTS_DIR="$DATA_DIR/vaults"
	REGISTRY="$DATA_DIR/registry.json"

	PERSONAL_DIR="$VAULTS_DIR/baluard-personal"
	WORK_DIR="$VAULTS_DIR/baluard-work"

	# Scrub only the two demo slugs from the registry (preserves any other vaults).
	scrub_registry() {
		[ -f "$REGISTRY" ] || return 0
		jq 'del(.vaults["baluard-personal"]) | del(.vaults["baluard-work"])
		    | if (.active_vault == "baluard-personal" or .active_vault == "baluard-work")
		      then .active_vault = null else . end' \
			"$REGISTRY" > "$REGISTRY.tmp" && mv "$REGISTRY.tmp" "$REGISTRY"
	}

	if [ -d "$PERSONAL_DIR" ] || [ -d "$WORK_DIR" ]; then
		echo "Existing demo vault(s) found:"
		[ -d "$PERSONAL_DIR" ] && echo "  - $PERSONAL_DIR"
		[ -d "$WORK_DIR" ]     && echo "  - $WORK_DIR"
		echo ""
		read -r -p "Remove both and seed fresh? [y/N] " ANSWER
		case "$ANSWER" in
			y|Y)
				rm -rf "$PERSONAL_DIR" "$WORK_DIR"
				scrub_registry
				echo "Removed."
				echo ""
				;;
			*)
				echo "Aborted. Remove the demo vaults manually if needed:"
				echo "  rm -rf \"$PERSONAL_DIR\" \"$WORK_DIR\""
				exit 1
				;;
		esac
	fi

	# Per-vault baluard wrapper. Set VPATH before calling.
	VPATH=""
	baluard() { target/release/{{ binary }} --vault-path "$VPATH" --direct "$@"; }

	# Look up a folder id by name from the current vault's folder list.
	map_folder_id() {
		# awk must drain the pipe: an early `exit` closes it and the CLI
		# panics on EPIPE (Rust ignores SIGPIPE).
		baluard folders list | awk -v name="$1" '$0 ~ name && !found { print $1; found = 1 }'
	}

	# Inject a folder id into a passkey fixture and add it as JSON.
	add_passkey() {
		jq --arg fid "$1" '.folder_id = $fid' "scripts/$2" | baluard add json -
	}

	seed_personal() {
		VPATH="$PERSONAL_DIR"
		echo "=== Creating PERSONAL vault at $VPATH ==="
		baluard init --slug baluard-personal --name "Personal" --theme system --lang en --auto-lock 15

		echo ""
		echo "[personal] Creating folders ==="
		baluard folders create "Personal"
		baluard folders create "Finance"
		baluard folders create "Travel"
		baluard folders create "Subscriptions"
		PERSONAL=$(map_folder_id "Personal")
		FINANCE=$(map_folder_id "Finance")
		TRAVEL=$(map_folder_id "Travel")
		SUBS=$(map_folder_id "Subscriptions")
	baluard folders create "Health" >/dev/null
	baluard folders create "Government" >/dev/null
	baluard folders create "Dev" >/dev/null
	HEALTH=$(map_folder_id "Health")
	GOV=$(map_folder_id "Government")
	DEV=$(map_folder_id "Dev")

		echo ""
		echo "[personal] Creating tags ==="
		for tag in personal important mfa backup shared urgent; do
			baluard tags create "$tag"
		done

		echo ""
		echo "[personal] Seeding logins ==="
		baluard add login --name "Gmail" --username "esteban@gmail.com" --password "Gm@1lS3cur3!" --uri "https://mail.google.com" --tags personal,mfa --folder "$PERSONAL"
		baluard add login --name "Netflix" --username "esteban@gmail.com" --password 'N3tfl1x$tream' --uri "https://netflix.com" --tags personal --folder "$SUBS"
		baluard add login --name "Spotify" --username "esteban@gmail.com" --password "Sp0t1fyPl@y" --uri "https://spotify.com" --tags personal --folder "$SUBS"
		baluard add login --name "Amazon" --username "esteban@gmail.com" --password "Am@z0nSh0p!" --uri "https://amazon.com" --tags personal --folder "$PERSONAL"
		baluard add login --name "Instagram" --username "@estebanforge" --password "1nst@Gr@m!" --uri "https://instagram.com" --tags personal --folder "$PERSONAL"
		baluard add login --name "Apple ID" --username "esteban@gmail.com" --password "Appl3ID!2026" --uri "https://appleid.apple.com" --tags personal,mfa --folder "$PERSONAL"

		echo ""
		echo "[personal] Seeding login with passkey ==="
		# Google — passkey-only login (no password), iPhone 16 Pro
		add_passkey "$PERSONAL" demo-google-passkey.json

		echo ""
		echo "[personal] Seeding browser-extension test logins ==="
		# Public practice sites for safe extension autofill testing.
		baluard add login --name "VBSca Login Practice" --username "student" --password "Password123" --uri "http://vbsca.ca/login/login.asp" --notes "Classic ASP practice login form." --tags personal --folder "$PERSONAL"
		baluard add login --name "Practice Test Automation" --username "student" --password "Password123" --uri "https://practicetestautomation.com/practice-test-login/" --notes "Public login practice page." --tags personal --folder "$PERSONAL"
		baluard add login --name "scheb 2FA Demo" --username "user1" --password "test" --uri "https://2fa.scheb.de/login" --totp-uri "otpauth://totp/BaluardTest:scheb-2fa?secret=JBSWY3DPEHPK3PXP&issuer=scheb-2fa&digits=6&period=30" --notes "Two-factor practice site. TOTP secret is a sample (RFC test vector); re-register on the site to bind the real one." --tags personal,mfa --folder "$PERSONAL"

		echo ""
		echo "[personal] Seeding cards ==="
		baluard add card --name "Visa Platinum" --cardholder-name "Esteban Forge" --brand "Visa" --number "4532123456789012" --exp-month "09" --exp-year "2028" --code "123" --tags personal,important --folder "$FINANCE"
		baluard add card --name "Amex Gold" --cardholder-name "Esteban Forge" --brand "American Express" --number "378282246310005" --exp-month "12" --exp-year "2029" --code "7890" --notes "Travel rewards card" --tags personal --folder "$TRAVEL"

		echo ""
		echo "[personal] Seeding secure notes ==="
		baluard add note --name "WiFi Password - Home" --notes 'HomeNetwork$_2026!' --tags personal --folder "$PERSONAL"
		baluard add note --name "Garage Door Code" --notes "4521" --tags personal --folder "$PERSONAL"
		baluard add note --name "Safety Deposit Box" --notes $'Bank: Chase Downtown\nBox: #417\nKey: green tag in desk drawer' --tags personal,important --folder "$PERSONAL"
		baluard add note --name "Email Aliases" --notes $'personal: esteban@gmail.com\nwork: esteban@actitud.xyz\nbilling: billing@actitud.xyz' --tags shared --folder "$PERSONAL"

		echo ""
		echo "[personal] Seeding identity ==="
		baluard add identity --name "Esteban Forge" --title "Mr" --first-name "Esteban" --last-name "Forge" --username "estebanforge" --email "esteban@gmail.com" --phone "+1-555-0142" --address1 "742 Innovation Drive" --city "San Francisco" --state "CA" --postal-code "94105" --country "US" --tags personal,important --folder "$PERSONAL"

		echo ""
		echo "[personal] Seeding bank accounts ==="
		baluard add bank --name "Chase Checking" --bank-name "JPMorgan Chase" --name-on-account "Esteban Forge" --account-type "Checking" --account-number "123456789" --routing-number "021000021" --swift-code "CHASUS33" --tags personal --folder "$FINANCE"
		baluard add bank --name "Chase Savings" --bank-name "JPMorgan Chase" --name-on-account "Esteban Forge" --account-type "Savings" --account-number "987654321" --routing-number "021000021" --tags personal --folder "$FINANCE"

		echo ""
		echo "[personal] Seeding driver license ==="
		baluard add license --name "CA Driver License" --first-name "Esteban" --last-name "Forge" --date-of-birth "1990-06-15" --license-number "F1234567" --issuing-country "US" --issuing-state "CA" --issue-date "2018-03-20" --expiration-date "2028-03-20" --tags personal,important --folder "$PERSONAL"

		echo ""
		echo "[personal] Seeding passport ==="
		baluard add passport --name "US Passport" --surname "Forge" --given-name "Esteban" --date-of-birth "1990-06-15" --sex "M" --birth-place "San Francisco" --nationality "US" --passport-number "P12345678" --issuing-country "US" --issue-date "2022-01-15" --expiration-date "2032-01-14" --tags personal,important --folder "$TRAVEL"

		echo ""
		echo "[personal] Seeding national ID ==="
		baluard add note --name "Chile Carnet de Identidad" --notes $'RUN/RUT: 16.543.210-4\nTipo: Cédula de Identidad\nNombres: Esteban Andrés\nApellidos: Forge Muñoz\nSexo: M\nFecha de nacimiento: 1990-06-15\nNacionalidad: Chilena\nFecha de emisión: 2021-08-10\nFecha de vencimiento: 2031-08-10\nNúmero de documento: A12345678' --tags personal,important --folder "$PERSONAL"
	baluard add login --name "YouTube" --username "esteban@gmail.com" --password "Y0uTub3Pl@y!" --uri "https://youtube.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "GitHub" --username "estebanforge" --password "GhT0k3n#2026" --uri "https://github.com" --totp-uri "otpauth://totp/BaluardTest:github?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30" --tags personal,mfa --folder "$PERSONAL" >/dev/null
	baluard add login --name "GitLab" --username "estebanforge" --password "GlL@b#2026" --uri "https://gitlab.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "X (Twitter)" --username "@estebanforge" --password "XTw1tt3r!" --uri "https://x.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "LinkedIn" --username "esteban@gmail.com" --password "L1nk3dIn$" --uri "https://linkedin.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Reddit" --username "u/estebanforge" --password "R3dd1tP@ss" --uri "https://reddit.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Steam" --username "estebanforge" --password "St3@mG@ming" --uri "https://store.steampowered.com" --totp-uri "otpauth://totp/BaluardTest:steam?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Steam&digits=6&period=30" --tags personal,mfa --folder "$PERSONAL" >/dev/null
	baluard add login --name "Epic Games" --username "estebanforge" --password "Ep1cG@mes!" --uri "https://store.epicgames.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "HBO Max" --username "esteban@gmail.com" --password "HB0M@xStr3am" --uri "https://max.com" --tags personal --folder "$SUBS" >/dev/null
	baluard add login --name "Disney+" --username "esteban@gmail.com" --password "D1sn3y+Plus" --uri "https://disneyplus.com" --tags personal --folder "$SUBS" >/dev/null
	baluard add login --name "Mercado Libre" --username "esteban@gmail.com" --password "M3rc@d0L1br3" --uri "https://mercadolibre.cl" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Falabella" --username "esteban@gmail.com" --password "F@l@b3ll@CL" --uri "https://falabella.com" --tags personal --folder "$PERSONAL" >/dev/null
	cat <<'JSON' | baluard add json - >/dev/null
	{
	  "name": "Insurance Portal",
	  "folder_id": null,
	  "kind": { "type": "login", "data": {
	"username": "esteban@gmail.com",
	"password": "1nsur@nc3P0rtal",
	"uris": [{ "uri": "https://insurance.example.com", "match_strategy": "domain" }],
	"custom_fields": [
	  { "name": "Policy Number", "value": "POL-88431-CL", "field_type": "Text" },
	  { "name": "Agent Code", "value": "AG-2209", "field_type": "Hidden" },
	  { "name": "Auto Renew", "value": "true", "field_type": "Boolean" }
	]
	  } },
	  "notes": "Second custom-fields demo entry."
	}
	JSON
	cat <<'JSON' | baluard add json - >/dev/null
	{
	  "name": "Cloud Console",
	  "folder_id": null,
	  "kind": { "type": "login", "data": {
	"username": "esteban@actitud.xyz",
	"password": "Cl0udC0ns0l3!",
	"uris": [{ "uri": "https://console.example.cloud", "match_strategy": "domain" }],
	"custom_fields": [
	  { "name": "Project ID", "value": "actitud-prod-4411", "field_type": "Text" },
	  { "name": "Billing Alert", "value": "false", "field_type": "Boolean" },
	  { "name": "Root Token", "value": "tok_9f8e7d6c5b4a", "field_type": "Hidden" }
	]
	  } }
	}
	JSON
	baluard add card --name "Mastercard Travel" --cardholder-name "Esteban Forge" --brand "Mastercard" --number "5412751234567890" --exp-month "07" --exp-year "2029" --code "321" --tags personal --folder "$TRAVEL" >/dev/null
	baluard add card --name "Cencosud" --cardholder-name "Esteban Forge" --brand "Mastercard" --number "5287109988776655" --exp-month "03" --exp-year "2027" --code "654" --tags personal --folder "$FINANCE" >/dev/null
	baluard add note --name "Router Admin" --notes $'Admin: admin\nPass: R0ut3r$_2026!\nIP: 192.168.10.1' --tags personal --folder "$PERSONAL" >/dev/null
	baluard add note --name "NAS Recovery" --notes $'Model: Synology DS920+\nAdmin URL: https://nas.home.local:5001\nRecovery key envelope in safety deposit box' --tags personal,backup --folder "$PERSONAL" >/dev/null
	baluard add note --name "Car Documents" --notes $'Patente: FKXZ-4471\nSeguro: SURA full + asistencia\nVencimiento revisión técnica: 2027-03' --tags personal --folder "$PERSONAL" >/dev/null
	baluard add bank --name "Banco Estado CuentaRUT" --bank-name "BancoEstado" --name-on-account "Esteban Forge" --account-type "Checking" --account-number "99123456" --routing-number "0009" --tags personal --folder "$FINANCE" >/dev/null
	baluard add bank --name "Interactive Brokers" --bank-name "IBKR" --name-on-account "Esteban Forge" --account-type "Investment" --account-number "U7788123" --routing-number "021000021" --swift-code "IBKRUS33" --tags personal,important --folder "$FINANCE" >/dev/null
	baluard add ssh-key --name "Home Server Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeHomeServer2026" --fingerprint "SHA256:rT5wZ8xK2mN4pQ7vB1cL9dH3jF6gS0aY8uE2iO5pW4qX" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add license --name "CLP Boating License" --first-name "Esteban" --last-name "Forge" --date-of-birth "1990-06-15" --license-number "B9876543" --issuing-country "CL" --issue-date "2021-11-05" --expiration-date "2031-11-04" --tags personal --folder "$TRAVEL" >/dev/null
	baluard add login --name "ClaveÚnica" --username "estebanforge" --password "Cl@veUn1c@2026" --uri "https://claveunica.gob.cl" --totp-uri "otpauth://totp/BaluardTest:claveunica?secret=JBSWY3DPEHPK3PXP&issuer=ClaveUnica&digits=6&period=30" --tags personal,mfa --folder "$GOV" >/dev/null
	baluard add login --name "SII" --username "16654321-9" --password "S11@Contribuyente" --uri "https://www.sii.cl" --totp-uri "otpauth://totp/BaluardTest:sii?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=SII&digits=6&period=30" --tags personal,mfa --folder "$GOV" >/dev/null
	baluard add login --name "Registro Civil" --username "estebanforge" --password "R3g1str0C1v1l" --uri "https://www.registrocivil.cl" --tags personal --folder "$GOV" >/dev/null
	baluard add login --name "Fonasa" --username "estebanforge" --password "F0n@s@Salud" --uri "https://www.fonasa.cl" --tags personal --folder "$HEALTH" >/dev/null
	baluard add login --name "Salcobrand" --username "esteban@gmail.com" --password "S@lc0br@nd" --uri "https://www.salcobrand.cl" --tags personal,health --folder "$HEALTH" >/dev/null
	baluard add login --name "Medical Records Portal" --username "estebanforge" --password "M3d1c@lR3c0rds" --uri "https://health.example.com" --tags personal,health --folder "$HEALTH" >/dev/null
	baluard add login --name "Enel Distribución" --username "estebanforge" --password "3n3l3n3rg1a" --uri "https://www.eneldistribucion.cl" --totp-uri "otpauth://totp/BaluardTest:enel?secret=MFRGGZDFMZTWQ2LK&issuer=Enel&digits=6&period=30" --tags personal,mfa --folder "$PERSONAL" >/dev/null
	baluard add login --name "Aguas Andinas" --username "estebanforge" --password "@g0@nd1n@s" --uri "https://www.aguasandinas.cl" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "VTR" --username "esteban@gmail.com" --password "VTR1nt3rn3t" --uri "https://vtr.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Duolingo" --username "esteban@gmail.com" --password "Du0l1ng0+2026" --uri "https://duolingo.com" --totp-uri "otpauth://totp/BaluardTest:duolingo?secret=MZXW6YTBOI======&issuer=Duolingo&digits=6&period=30" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Coursera" --username "esteban@gmail.com" --password "C0urs3r@Learn" --uri "https://coursera.org" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Notion" --username "esteban@actitud.xyz" --password "N0t10nW0rks!" --uri "https://notion.so" --tags personal --folder "$DEV" >/dev/null
	baluard add login --name "Docker Hub" --username "estebanforge" --password "D0ck3rH0b#26" --uri "https://hub.docker.com" --totp-uri "otpauth://totp/BaluardTest:dockerhub?secret=MZXW633PNVWXKzM=&issuer=DockerHub&digits=6&period=30" --tags personal,mfa --folder "$DEV" >/dev/null
	baluard add login --name "npm" --username "estebanforge" --password "NPMt0k3n#26" --uri "https://npmjs.com" --totp-uri "otpauth://totp/BaluardTest:npm?secret=NBSWY3DP&issuer=npm&digits=6&period=30" --tags personal,mfa --folder "$DEV" >/dev/null
	baluard add login --name "Hetzner" --username "estebanforge" --password "H3tznerCl0ud" --uri "https://console.hetzner.cloud" --tags personal --folder "$DEV" >/dev/null
	baluard add login --name "Dropbox" --username "esteban@gmail.com" --password "Dr0pb0xB@ckup" --uri "https://dropbox.com" --tags personal,backup --folder "$DEV" >/dev/null
	baluard add login --name "Condominio Portal" --username "estebanforge" --password "C0nd0m1n10P0rtal" --uri "https://portal.condominio.cl" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Gimnasio SmartFit" --username "estebanforge" --password "Sm@rtF1tGym" --uri "https://smartfit.cl" --tags personal,health --folder "$HEALTH" >/dev/null
	baluard add login --name "Aerolíneas Punta Arenas" --username "estebanforge" --password "Punt@@r3n@s" --uri "https://example.com" --tags personal,travel --folder "$TRAVEL" >/dev/null
	baluard add login --name "Uber" --username "esteban@gmail.com" --password "Ub3rR1d3s!" --uri "https://uber.com" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add login --name "Spotify Family" --username "familia@gmail.com" --password "Sp0t1fyF@m" --uri "https://spotify.com" --tags personal,shared --folder "$SUBS" >/dev/null
	baluard add login --name "iCloud Mail Alias" --username "esteban@icloud.com" --password "1Cl0ud@l1@s" --uri "https://icloud.com" --tags personal --folder "$PERSONAL" >/dev/null
	cat <<'JSON' | baluard add json - >/dev/null
	{ "name": "Isapre Colmena", "folder_id": null, "kind": { "type": "login", "data": {
	  "username": "estebanforge", "password": "Is@pr3C0lm3n@",
	  "uris": [{ "uri": "https://colmena.cl", "match_strategy": "domain" }],
	  "custom_fields": [
	{ "name": "N° Contrato", "value": "COL-556677", "field_type": "Text" },
	{ "name": "Código Agente", "value": "AG-8899", "field_type": "Hidden" },
	{ "name": "Primas al Día", "value": "true", "field_type": "Boolean" } ] } } }
	JSON
	cat <<'JSON' | baluard add json - >/dev/null
	{ "name": "Portal de Impuestos", "folder_id": null, "kind": { "type": "login", "data": {
	  "username": "16654321-9", "password": "P0rt@l1mpu3st0s",
	  "uris": [{ "uri": "https://tax.example.com", "match_strategy": "domain" }],
	  "custom_fields": [
	{ "name": "Rol Avalúo", "value": "RO-4471-9", "field_type": "Text" },
	{ "name": "PIN Caja", "value": "778899", "field_type": "Hidden" },
	{ "name": "Declaración F22 Enviada", "value": "true", "field_type": "Boolean" } ] } } }
	JSON
	cat <<'JSON' | baluard add json - >/dev/null
	{ "name": "Enel Facturación", "folder_id": null, "kind": { "type": "login", "data": {
	  "username": "estebanforge", "password": "F@ctur@3n3l",
	  "uris": [{ "uri": "https://factura.enel.cl", "match_strategy": "domain" }],
	  "custom_fields": [
	{ "name": "N° Cliente", "value": "CLI-998877", "field_type": "Text" },
	{ "name": "NIS", "value": "NIS-331122", "field_type": "Text" },
	{ "name": "Boleta Digital", "value": "true", "field_type": "Boolean" } ] } } }
	JSON
	cat <<'JSON' | baluard add json - >/dev/null
	{ "name": "Gimnasio Membresía", "folder_id": null, "kind": { "type": "login", "data": {
	  "username": "estebanforge", "password": "M3mbr3s1@Gym",
	  "uris": [{ "uri": "https://gym.example.com", "match_strategy": "domain" }],
	  "custom_fields": [
	{ "name": "N° Socio", "value": "SOC-77123", "field_type": "Text" },
	{ "name": "Casillero", "value": "B-42", "field_type": "Text" },
	{ "name": "Congelada", "value": "false", "field_type": "Boolean" } ] } } }
	JSON
	cat <<'JSON' | baluard add json - >/dev/null
	{ "name": "Garantías Extendidas", "folder_id": null, "kind": { "type": "login", "data": {
	  "username": "esteban@gmail.com", "password": "G@r@nt1@sP0rtal",
	  "uris": [{ "uri": "https://warranty.example.com", "match_strategy": "domain" }],
	  "custom_fields": [
	{ "name": "TV LG Garantía", "value": "LG-2026-8871", "field_type": "Text" },
	{ "name": "Lavadora Garantía", "value": "SAM-2027-4412", "field_type": "Text" } ] } } }
	JSON
	cat <<'JSON' | baluard add json - >/dev/null
	{ "name": "Farmacia Salcobrand Club", "folder_id": null, "kind": { "type": "login", "data": {
	  "username": "esteban@gmail.com", "password": "ClubS@lc0",
	  "uris": [{ "uri": "https://club.salcobrand.cl", "match_strategy": "domain" }],
	  "custom_fields": [
	{ "name": "N° Socio Club", "value": "SB-338812", "field_type": "Text" },
	{ "name": "Puntos Acumulados", "value": "4820", "field_type": "Text" },
	{ "name": "Descuento Automático", "value": "true", "field_type": "Boolean" } ] } } }
	JSON
	baluard add card --name "Visa Débito BancoEstado" --cardholder-name "Esteban Forge" --brand "Visa" --number "4051888888881234" --exp-month "11" --exp-year "2028" --code "812" --tags personal --folder "$FINANCE" >/dev/null
	baluard add card --name "Amex CL" --cardholder-name "Esteban Forge" --brand "American Express" --number "374588899900111" --exp-month "09" --exp-year "2029" --code "1234" --tags personal --folder "$FINANCE" >/dev/null
	baluard add card --name "Virtual Card Dev" --cardholder-name "E. Forge" --brand "Visa" --number "4917661122334455" --exp-month "01" --exp-year "2027" --code "999" --notes "Single-use dev subscriptions card" --tags personal --folder "$FINANCE" >/dev/null
	baluard add card --name "Copec Card" --cardholder-name "Esteban Forge" --brand "Mastercard" --number "5512340987654321" --exp-month "05" --exp-year "2028" --code "445" --tags personal --folder "$TRAVEL" >/dev/null
	baluard add note --name "Office WiFi" --notes $'SSID: ACTITUD-WIFI\nPass: 0ff1c3W1F1$_2026' --tags personal,shared --folder "$PERSONAL" >/dev/null
	baluard add note --name "House Alarm Code" --notes "Alarm: 7788\nPanic: 9900\nCompany: Chile Alarmas +56 600 555 0101" --tags personal,important --folder "$PERSONAL" >/dev/null
	baluard add note --name "Software License Keys" --notes $'JetBrains: JB-2026-A1B2C3\nWindows 11 Pro: W11P-9988-X7Y6\nSublime: SL-5544-B3B4' --tags personal,backup --folder "$DEV" >/dev/null
	baluard add note --name "Warranty Records" --notes $'LG TV: vence 2026-12\nSamsung Lavadora: vence 2027-06\nMicroondas: sin garantía' --tags personal --folder "$PERSONAL" >/dev/null
	baluard add note --name "Subscriptions List" --notes $'Netflix 4K: $19.990/mes\nSpotify Family: $14.990/mes\nHBO Max: $11.990/mes\nDisney+: $11.990/mes\niCloud 2TB: $10.900/mes' --tags personal --folder "$SUBS" >/dev/null
	baluard add note --name "Emergency Contacts" --notes $'SURA Seguros: +56 600 400 2000\nAsistencia hogar: +56 600 300 1000\nBomberos: 132\nAmbulancia: 131' --tags personal,important --folder "$PERSONAL" >/dev/null
	baluard add note --name "Passport Renewal Checklist" --notes $'1. Certificado de nacimiento\n2. Foto fondo blanco\n3. Pago $86.800\n4. Agendar en registrocivil.cl' --tags personal,travel --folder "$TRAVEL" >/dev/null
	baluard add note --name "Seed Backup Locations" --notes $'Copia 1: caja de seguridad Chase\nCopia 2: sobre en casa (librería)\nCopia 3: Drive cifrado' --tags personal,backup,important --folder "$PERSONAL" >/dev/null
	baluard add note --name "Bike Info" --notes $'Trek Marlin 7\nN° serie: WTU-9912-K888\nCandado: Kryptonite code 4411' --tags personal --folder "$PERSONAL" >/dev/null
	baluard add note --name "Streaming PINs" --notes $'Netflix perfil E: 4471\nDisney+: 8899\nPrime Video: 2210' --tags personal,shared --folder "$SUBS" >/dev/null
	baluard add note --name "Red Médica Info" --notes $'Red: Clínica Las Condes\nMédico cabecera: Dra. Soto\nTel. hora: +56 600 500 3000' --tags personal,health --folder "$HEALTH" >/dev/null
	baluard add bank --name "Santander Cuenta Corriente" --bank-name "Santander" --name-on-account "Esteban Forge" --account-type "Checking" --account-number "77123999" --routing-number "018" --swift-code "BSCHCLRM" --tags personal --folder "$FINANCE" >/dev/null
	baluard add bank --name "BCI Cuenta Vista" --bank-name "BCI" --name-on-account "Esteban Forge" --account-type "Savings" --account-number "55011223" --routing-number "028" --tags personal --folder "$FINANCE" >/dev/null
	baluard add bank --name "Tenpo" --bank-name "Tenpo Labs" --name-on-account "Esteban Forge" --account-type "Prepaid" --account-number "TP-99881" --routing-number "0000" --tags personal --folder "$FINANCE" >/dev/null
	baluard add ssh-key --name "Git Server Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeGitServer2026" --fingerprint "SHA256:gH1jK2lM3nN4oO5pP6qQ7rR8sS9tT0uU1vV2wW3xX4" --tags personal --folder "$DEV" >/dev/null
	baluard add ssh-key --name "Raspberry Pi Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeRasPi2026" --fingerprint "SHA256:yY2zZ3aA4bB5cC6dD7eE8fF9gG0hH1iI2jJ3kK4lL5mM" --tags personal --folder "$DEV" >/dev/null
	baluard add ssh-key --name "Backup Server Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeBackup2026" --fingerprint "SHA256:nN6oO7pP8qQ9rR0sS1tT2uU3vV4wW5xX6yY7zZ8aA9" --tags personal,backup --folder "$DEV" >/dev/null
	baluard add identity --name "Esteban Forge (Work)" --title "Mr" --first-name "Esteban Andrés" --last-name "Forge Muñoz" --username "eforge" --email "e.forge@actitud.xyz" --phone "+56 9 5555 0180" --address1 "Av. Providencia 1234" --city "Santiago" --state "RM" --postal-code "7500000" --country "CL" --tags personal,shared --folder "$PERSONAL" >/dev/null
	baluard add license --name "CL Motorcycle License" --first-name "Esteban" --last-name "Forge" --date-of-birth "1990-06-15" --license-number "C5588991" --issuing-country "CL" --issue-date "2023-05-12" --expiration-date "2033-05-11" --tags personal --folder "$PERSONAL" >/dev/null
	baluard add passport --name "US Passport (Expired)" --surname "Forge" --given-name "Esteban" --date-of-birth "1990-06-15" --sex "M" --birth-place "San Francisco" --nationality "US" --passport-number "P09876543" --issuing-country "US" --issue-date "2013-02-10" --expiration-date "2023-02-09" --notes "Expired — kept for records" --tags personal,backup --folder "$TRAVEL" >/dev/null

		echo ""
		echo "[personal] Committing seeded data to git ==="
		baluard sync commit
	}

	seed_work() {
		VPATH="$WORK_DIR"
		echo ""
		echo "=== Creating WORK vault at $VPATH ==="
		baluard init --slug baluard-work --name "Work" --theme system --lang en --auto-lock 15

		echo ""
		echo "[work] Creating folders ==="
		baluard folders create "Work"
		baluard folders create "Infrastructure"
		baluard folders create "Finance"
		baluard folders create "Clients"
		WORK=$(map_folder_id "Work")
		INFRA=$(map_folder_id "Infrastructure")
		FINANCE=$(map_folder_id "Finance")
		CLIENTS=$(map_folder_id "Clients")

		echo ""
		echo "[work] Creating tags ==="
		for tag in work team api-key production staging important shared; do
			baluard tags create "$tag"
		done

		echo ""
		echo "[work] Seeding logins ==="
		baluard add login --name "GitLab" --username "esteban" --password "gl-pat-xxxxxxxxxxxx" --uri "https://gitlab.com" --tags api-key --folder "$WORK"
		baluard add login --name "Vercel" --username "esteban@actitud.xyz" --password "V3rc3lD3pl0y!" --uri "https://vercel.com" --tags work,api-key --folder "$WORK"
		baluard add login --name "Cloudflare" --username "admin@actitud.xyz" --password "CF_R@y_ID!2026" --uri "https://dash.cloudflare.com" --tags production --folder "$INFRA"
		baluard add login --name "Linear" --username "esteban@actitud.xyz" --password "L1n3@rPlan!" --uri "https://linear.app" --tags work --folder "$WORK"
		baluard add login --name "Slack" --username "esteban@actitud.xyz" --password "Sl@ckW0rk!" --uri "https://slack.com" --tags work,team --folder "$WORK"
		baluard add login --name "Acme Corp Staging" --username "admin@acme.test" --password "@cm3St@g1ng!" --uri "https://staging.acme.test" --notes "Client portal admin" --tags work,shared --folder "$CLIENTS"

		echo ""
		echo "[work] Seeding logins with passkeys ==="
		# GitHub — password + passkey (YubiKey 5C NFC)
		add_passkey "$WORK" demo-github-passkey.json
		# AWS — password + TOTP + 2 passkeys (YubiKey 5Ci + Touch ID)
		add_passkey "$INFRA" demo-aws-passkey.json
		# Figma — imported passkey (missing private key, Bitwarden import)
		add_passkey "$WORK" demo-figma-passkey.json

		echo ""
		echo "[work] Seeding browser-extension test logins ==="
		# Public practice sites for safe extension autofill testing.
		baluard add login --name "VBSca Login Practice" --username "student" --password "Password123" --uri "http://vbsca.ca/login/login.asp" --notes "Classic ASP practice login form." --tags work --folder "$WORK"
		baluard add login --name "Practice Test Automation" --username "student" --password "Password123" --uri "https://practicetestautomation.com/practice-test-login/" --notes "Public login practice page." --tags work --folder "$WORK"
		baluard add login --name "scheb 2FA Demo" --username "user1" --password "test" --uri "https://2fa.scheb.de/login" --totp-uri "otpauth://totp/BaluardTest:scheb-2fa?secret=JBSWY3DPEHPK3PXP&issuer=scheb-2fa&digits=6&period=30" --notes "Two-factor practice site. TOTP secret is a sample (RFC test vector); re-register on the site to bind the real one." --tags work,mfa --folder "$WORK"

		echo ""
		echo "[work] Seeding card ==="
		baluard add card --name "Mastercard Business" --cardholder-name "Esteban Forge" --brand "Mastercard" --number "5412345678901234" --exp-month "03" --exp-year "2027" --code "456" --tags work --folder "$FINANCE"

		echo ""
		echo "[work] Seeding secure notes ==="
		baluard add note --name "Server Recovery Codes" --notes $'BACKUP-1: A3F8-B7C2-D9E1\nBACKUP-2: K4M6-P8R2-T5W9\nBACKUP-3: X1Y3-Z5A7-B9C1' --tags important,backup --folder "$INFRA"
		baluard add note --name "Deploy Runbook" --notes $'1. ssh prod-app-01\n2. cd /srv/app\n3. ./deploy.sh staging\n4. watch logs: journalctl -u app -f' --tags production --folder "$INFRA"

		echo ""
		echo "[work] Seeding identity ==="
		baluard add identity --name "Business Contact" --title "Mr" --first-name "Esteban" --last-name "Forge" --company "Actitud Studio" --email "info@actitud.xyz" --phone "+1-555-0143" --address1 "742 Innovation Drive" --city "San Francisco" --state "CA" --postal-code "94105" --country "US" --tags work,shared --folder "$WORK"

		echo ""
		echo "[work] Seeding SSH keys ==="
		baluard add ssh-key --name "GitHub SSH Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeGitHub2026" --fingerprint "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8" --tags important,api-key --folder "$INFRA"
		baluard add ssh-key --name "Production Server" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeProd2026" --fingerprint "SHA256:pB9R3k7mWQ2vX4yN8tL6jK5hG0dF1sA3cE7uM9wR2iO" --tags production,important --folder "$INFRA"
		baluard add ssh-key --name "Staging Deploy Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeStaging2026" --fingerprint "SHA256:qR4tY7uW0vX2zN5bA8cD6eF3gH1iJ9kL0mO3pS6wU2xT" --notes "Read-only deploy key for staging" --tags staging --folder "$INFRA"

		echo ""
		echo "[work] Seeding bank accounts ==="
		baluard add bank --name "Business Account" --bank-name "Silicon Valley Bank" --name-on-account "Actitud Studio LLC" --account-type "Business Checking" --account-number "456789123" --routing-number "121000248" --swift-code "SVBKUS6S" --notes "Business operating account" --tags work --folder "$FINANCE"
		baluard add bank --name "Banco de Chile Cuenta Corriente" --bank-name "Banco de Chile" --name-on-account "Esteban Forge Muñoz" --account-type "Cuenta Corriente" --account-number "12345678" --routing-number "0001" --swift-code "BCHICLRM" --tags work --folder "$FINANCE"

		echo ""
		echo "[work] Seeding national ID (empresa) ==="
		baluard add note --name "Chile RUT (Empresa)" --notes $'RUT: 76.321.456-K\nRazón social: Actitud Studio SpA\nTipo entidad: Sociedad por Acciones\nActividad: Desarrollo de software\nFecha de inicio: 2023-03-15\nSII: Registro Vigente' --tags work,important --folder "$WORK"

		echo ""
		echo "[work] Committing seeded data to git ==="
		baluard sync commit
	}

	seed_personal
	seed_work

	echo ""
	echo "=== Demo vaults seeded ==="
	echo "  Personal: $PERSONAL_DIR"
	echo "  Work:     $WORK_DIR"
	echo "  Password (both): baluard99"
	echo ""
	echo "  Personal vault:"
	echo "    Logins:        10 (incl. 1 passkey login + 3 extension-test logins)"
	echo "    Cards:         2"
	echo "    Notes:         5  (incl. 1 Carnet)"
	echo "    Identities:    1"
	echo "    Bank Accounts: 2"
	echo "    Licenses:      1"
	echo "    Passports:     1"
	echo "    Folders: Personal, Finance, Travel, Subscriptions"
	echo "    Tags:    personal, important, mfa, backup, shared, urgent"
	echo ""
	echo "  Work vault:"
	echo "    Logins:        12 (incl. 3 passkey logins + 3 extension-test logins)"
	echo "    Cards:         1"
	echo "    Notes:         3"
	echo "    Identities:    1"
	echo "    SSH Keys:      3"
	echo "    Bank Accounts: 2  (incl. 1 Chilean)"
	echo "    Folders: Work, Infrastructure, Finance, Clients"
	echo "    Tags:    work, team, api-key, production, staging, important, shared"
	echo ""
	echo "  See both vaults: {{ binary }} vaults list"
	echo "  Switch between them: desktop (just desktop-debug) or daemon-backed CLI"
	echo "  Open in GUI:  just desktop-debug"

# End-to-end smoke test (requires release build)
e2e: build-release
	#!/usr/bin/env bash
	set -euo pipefail
	VAULT=$(mktemp -d)
	SOCK=$(mktemp -u /tmp/baluard-test-XXXXX)
	CLI="target/release/{{ binary }} --vault-path $VAULT --socket $SOCK"
	echo "Vault: $VAULT Socket: $SOCK"
	echo ""
	echo "=== INIT ===" && printf "testpass123\ntestpass123\n" | target/release/{{ binary }} init --vault-path "$VAULT"
	echo ""
	echo "=== DAEMON ===" && target/release/{{ daemon }} --vault-path "$VAULT" --socket "$SOCK" &>/tmp/baluard-daemon.log & DAEMON_PID=$!; sleep 1
	echo "=== PING ===" && $CLI ping
	echo ""
	echo "=== UNLOCK ===" && $CLI unlock <<< "testpass123"
	echo ""
	echo "=== ADD ===" && $CLI add login --name "Test" --username "user@test.com" --password "secret123"
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

# ── Mobile (Android) ────────────────────────────────────────────────────────
# Build the Android debug APK. Runs on a macOS host: builds the Rust cdylib for
# all 4 ABIs, writes local.properties, runs `./gradlew :androidApp:assembleDebug`.
# Prereqs + flags: see mobile/scripts/build-android-apk.sh and docs/mobile-dev-setup.md.
android-apk:
	cd mobile && ./scripts/build-android-apk.sh

# Build + install the debug APK on a connected device (adb). Extra args
# forward to the script, e.g. `just android-install --device 192.168.1.50:38507`

# Android E2E (docs/e2e-testing.md Phase 2): Maestro flows on a dedicated
# test device or emulator - NEVER a device holding real vaults (flow 01
# wipes app data). One-time Maestro install:
#   curl -Ls "https://get.maestro.mobile.dev" | bash
# Build + install the E2E APK first: mobile/scripts/build-android-apk.sh --e2e --install
e2e-android *ARGS:
	mobile/scripts/run-maestro.sh {{ARGS}}
# (needed when wireless debugging shows one phone twice: IP:port + mDNS entry).
android-install *ARGS:
	cd mobile && ./scripts/build-android-apk.sh --install {{ARGS}}

# Build the APK using the committed prebuilt .so (skip cargo-ndk).
android-apk-fast:
	cd mobile && ./scripts/build-android-apk.sh --skip-native

# Regenerate the committed UniFFI Kotlin bindings (run after baluard-uniffi API change).
android-bindings:
	cd mobile && ./scripts/regen-bindings.sh

# ── Version ─────────────────────────────────────────────────────────────────

# Show version
version:
	@echo "{{ binary }} {{ version }}"

# ── Browser extension + NMH (Phase 0) ───────────────────────────────────────

nmh := "baluard-nmh"

# Build the native messaging host binary (release).
build-nmh:
	cargo build --release -p {{ nmh }}

# Build both Chrome and Firefox extension bundles (Vite).
ext-build:
	cd browser/shared && npm install && npm run build

ext-build-chrome:
	cd browser/shared && npm run build:chrome

ext-build-firefox:
	cd browser/shared && npm run build:firefox

# Print the NMH binary path (for the host manifest `path` field).
nmh-path:
	@echo "{{ absolute_path('target/release/' + nmh) }}"

# Install the native messaging host manifest for the current OS + browser.
# Usage: just install-nmh-manifest chrome <EXT_ID>   # or firefox <ADDON_ID>
# Writes the host manifest JSON to the per-OS user-level NMH directory and
# points its `path` at the release NMH binary.
install-nmh-manifest browser ext_id:
	#!/usr/bin/env bash
	set -euo pipefail
	BIN="{{ absolute_path('target/release/' + nmh) }}"
	mkdir -p target/release
	cargo build --release -p {{ nmh }}
	case "{{ os }}:{{ browser }}" in
	  linux:chrome)   DIR="$HOME/.config/google-chrome/NativeMessagingHosts" ;;
	  linux:chromium) DIR="$HOME/.config/chromium/NativeMessagingHosts" ;;
	  linux:brave)    DIR="$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts" ;;
	  linux:edge)     DIR="$HOME/.config/microsoft-edge/NativeMessagingHosts" ;;
	  linux:firefox)  DIR="$HOME/.mozilla/native-messaging-hosts" ;;
	  macos:chrome)   DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" ;;
	  macos:chromium) DIR="$HOME/Library/Application Support/Chromium/NativeMessagingHosts" ;;
	  macos:brave)    DIR="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts" ;;
	  macos:brave-origin) DIR="$HOME/Library/Application Support/BraveSoftware/Brave-Origin/NativeMessagingHosts" ;;
	  macos:edge)     DIR="$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts" ;;
	  macos:firefox)  DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts" ;;
	  *) echo "Unsupported OS/browser combo: {{ os }}/{{ browser }}"; exit 1 ;;
	esac
	mkdir -p "$DIR"
	if [ "{{ browser }}" = "firefox" ]; then
	  cat > "$DIR/xyz.actitud.baluard.json" <<EOF
	{"name":"xyz.actitud.baluard","description":"Baluard bridge","path":"$BIN","type":"stdio","allowed_extensions":["{{ ext_id }}"]}
	EOF
	else
	  cat > "$DIR/xyz.actitud.baluard.json" <<EOF
	{"name":"xyz.actitud.baluard","description":"Baluard bridge","path":"$BIN","type":"stdio","allowed_origins":["chrome-extension://{{ ext_id }}/"]}
	EOF
	fi
	echo "Installed NMH manifest -> $DIR/xyz.actitud.baluard.json"
	echo "Pointed at: $BIN"
	echo "Next: load browser/chrome/dist or browser/firefox/dist as unpacked/temporary."

# Dev: build Chrome bundle + print load-unpacked instructions.
ext-dev-chrome: ext-build-chrome
	@echo "Load: chrome://extensions -> Developer mode -> Load unpacked -> {{ absolute_path('browser/chrome/dist') }}"

# Dev: build Firefox bundle + print about:debugging instructions.
ext-dev-firefox: ext-build-firefox
	@echo "Load: about:debugging -> This Firefox -> Load Temporary Add-on -> {{ absolute_path('browser/firefox/dist/manifest.json') }}"
