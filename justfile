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
	{{ linuxbrew_env }} cargo test -p baluard-core

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
desktop-dev: _sidecar-force desktop-deps
	#!/usr/bin/env bash
	set -euo pipefail
	just _kill_daemon
	cd desktop && npm run tauri dev

# Run desktop app with full debug logging (BALUARD_DEBUG=1)
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
	BALUARD_DEBUG=1 BALUARD_LOG_DIR="$LOG_DIR" cd desktop && npm run tauri dev

# Build desktop app (production bundle)
desktop-build: _sidecar desktop-deps
	cd desktop && npm run tauri build

# ── App Icons ──────────────────────────────────────────────────────────────

# Generate app icons for ALL platforms (Windows/macOS/Linux desktop + Android/iOS mobile)
# from the Baluard logo. Output: assets/app-icons/{windows,macos,linux,tauri-desktop,android,ios}/
#
# Default source is the gradient icon-TILE (baluard-logo-grad.png) because that is the
# proper app-icon form (dark bg + padlock). Override with `just app-icons assets/<file>`.
# Source is auto-squared (alpha-trim + center-pad) since the logo is portrait and icon-gen
# requires square input.
APP_ICON_SOURCE := "assets/baluard-logo-grad.png"
APP_ICON_OUT    := "assets/app-icons"

app-icons SOURCE=APP_ICON_SOURCE OUT=APP_ICON_OUT:
	#!/usr/bin/env bash
	set -euo pipefail
	SRC="{{SOURCE}}"; OUT="{{OUT}}"
	command -v icon-gen >/dev/null || { echo "icon-gen not installed. Run: cargo install --git https://github.com/Hkmu/icon-generator.git"; exit 1; }
	[[ -f "$SRC" ]] || { echo "Source not found: $SRC"; exit 1; }
	mkdir -p "$OUT"
	SQ="$OUT/_source-1024.png"
	# Auto-square: trim alpha, center-pad to square, resize to 1024. (ImageMagick, no Python deps)
	command -v magick >/dev/null || { echo "ImageMagick not installed. macOS: brew install imagemagick"; exit 1; }
	magick "$SRC" -trim +repage -background none -gravity center \
		-extent "%[fx:max(w,h)]x%[fx:max(w,h)]" -resize 1024x1024 "$SQ"
	icon-gen "$SQ" -o "$OUT"
	rm -f "$SQ"
	echo ""
	echo "Done. All platform icons in: $OUT/"
	echo "  windows/        icon.ico"
	echo "  macos/          icon.icns + Contents.json"
	echo "  linux/          32-512px PNGs"
	echo "  tauri-desktop/  -> copy to desktop/src-tauri/icons/"
	echo "  android/        -> copy mipmap-*/ to desktop/src-tauri/gen/android/app/src/main/res/"
	echo "  ios/            -> copy to desktop/src-tauri/gen/ios/Assets.xcassets/AppIcon.appiconset/"

# ── E2E Smoke Test ─────────────────────────────────────────────────────────

# Seed TWO demo vaults (personal + work) with realistic mixed test data.
# Used for multi-vault switch testing. Password for both: baluard99
# Each vault gets a mix: logins, cards, notes, identities, passkeys, banks,
# plus folders and tags. Removes existing demo vaults first (preserves others).
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
		baluard folders list | awk -v name="$1" '$0 ~ name { print $1; exit }'
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
	echo "    Logins:        7  (incl. 1 passkey login)"
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
	echo "    Logins:        9  (incl. 3 passkey logins)"
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
	echo "=== PING ===" && baluard ping
	echo ""
	echo "=== UNLOCK ===" && baluard unlock <<< "testpass123"
	echo ""
	echo "=== ADD ===" && baluard add --name "Test" --username "user@test.com" --password "secret123"
	UUID=$(baluard list 2>&1 | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
	echo "UUID: $UUID"
	echo ""
	echo "=== GET ===" && baluard get "$UUID" 2>&1
	echo ""
	echo "=== DELETE ===" && baluard delete "$UUID"
	echo ""
	echo "=== LIST (empty) ===" && baluard list
	echo ""
	echo "=== LOCK ===" && baluard lock
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
	  linux:firefox)  DIR="$HOME/.mozilla/native-messaging-hosts" ;;
	  macos:chrome)   DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" ;;
	  macos:chromium) DIR="$HOME/Library/Application Support/Chromium/NativeMessagingHosts" ;;
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
