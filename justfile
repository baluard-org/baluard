set unstable

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
	{{ linuxbrew_env }} cargo build --release -p baluard-daemon -p baluard-cli
	cp target/release/baluard-daemon "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE"
	cp target/release/baluard "desktop/src-tauri/binaries/baluard-$TRIPLE"
	# Force-refresh sidecar in tauri target/debug
	mkdir -p desktop/src-tauri/target/debug
	cp "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE" "desktop/src-tauri/target/debug/baluard-daemon"
	cp "desktop/src-tauri/binaries/baluard-$TRIPLE" "desktop/src-tauri/target/debug/baluard"
	echo "Sidecar rebuilt (forced): baluard-daemon-$TRIPLE"

# Build daemon sidecar for current platform (Tauri needs target-triple suffix)
_sidecar:
	#!/usr/bin/env bash
	set -euo pipefail
	TRIPLE=$(rustc -vV | grep host | cut -d' ' -f2)
	mkdir -p desktop/src-tauri/binaries

	# Staleness check: skip cargo+copy if sidecar is newer than all Rust sources
	SIDECAR="desktop/src-tauri/binaries/baluard-daemon-$TRIPLE"
	if [ -f "$SIDECAR" ]; then
	  # Find any .rs file newer than the sidecar binary
	  NEWEST_SRC=$(find crates -name '*.rs' -newer "$SIDECAR" -print -quit 2>/dev/null || true)
	  if [ -z "$NEWEST_SRC" ]; then
	    echo "Sidecar up-to-date (no Rust changes detected)"
	  else
	    {{ linuxbrew_env }} cargo build --release -p baluard-daemon -p baluard-cli
	    cp target/release/baluard-daemon "$SIDECAR"
	    cp target/release/baluard "desktop/src-tauri/binaries/baluard-$TRIPLE"
	    echo "Sidecar rebuilt: $SIDECAR"
	  fi
	else
	    {{ linuxbrew_env }} cargo build --release -p baluard-daemon -p baluard-cli
	    cp target/release/baluard-daemon "$SIDECAR"
	    cp target/release/baluard "desktop/src-tauri/binaries/baluard-$TRIPLE"
	    echo "Sidecar rebuilt: $SIDECAR"
	fi

	# Force-refresh sidecar in tauri target/debug (tauri-build copies from binaries/
	# to target/debug/ during compilation, but a stale cross-platform binary from
	# another host's cargo build can cause "cannot execute binary file" on exec).
	mkdir -p desktop/src-tauri/target/debug
	cp "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE" "desktop/src-tauri/target/debug/baluard-daemon"
	cp "desktop/src-tauri/binaries/baluard-$TRIPLE" "desktop/src-tauri/target/debug/baluard"

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

# ── E2E Smoke Test ─────────────────────────────────────────────────────────

# Seed a demo vault with realistic test data (31 entries, 5 folders, 11 tags)
# Creates vault at the platform-default location. Password: baluard99
# If an existing vault is found, offers to back it up before seeding.
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
	VAULT="$DATA_DIR/vaults/baluard-personal"

	if [ -d "$VAULT" ]; then
		echo "Existing vault directory found at: $VAULT"
		echo ""
		read -r -p "Remove and seed fresh? [y/N] " ANSWER
		case "$ANSWER" in
			y|Y)
				rm -rf "$VAULT"
				rm -f "$DATA_DIR/registry.json"
				echo "Removed."
				echo ""
				;;
			*)
				echo "Aborted. Remove the existing vault manually:"
				echo "  rm -rf \"$VAULT\""
				exit 1
				;;
		esac
	fi

		baluard() { target/release/{{ binary }} --vault-path "$VAULT" --direct "$@"; }

	echo "=== Creating vault at $VAULT ==="
	baluard init --slug baluard-personal --name "Esteban"

	echo ""
	echo "=== Creating folders ==="
	baluard folders create "Personal"
	baluard folders create "Work"
	baluard folders create "Finance"
	baluard folders create "Infrastructure"
	baluard folders create "Travel"

	# Capture folder IDs
	map_folder_id() {
		baluard folders list | awk -v name="$1" '$0 ~ name { print $1; exit }'
	}
	PERSONAL=$(map_folder_id "Personal")
	WORK=$(map_folder_id "Work")
	FINANCE=$(map_folder_id "Finance")
	INFRA=$(map_folder_id "Infrastructure")
	TRAVEL=$(map_folder_id "Travel")

	echo ""
	echo "=== Creating tags ==="
	for tag in important shared team personal urgent legacy backup mfa api-key staging production; do
		baluard tags create "$tag"
	done

	echo ""
	echo "=== Seeding login entries ==="

	baluard add login --name "GitHub" --username "esteban@actitud.xyz" --password "gh_s3cur3T0k3nH3r3!" --uri "https://github.com" --notes "Personal GitHub account" --tags important,mfa --folder "$WORK"
	baluard add login --name "GitLab" --username "esteban" --password "gl-pat-xxxxxxxxxxxx" --uri "https://gitlab.com" --tags api-key --folder "$WORK"
	baluard add login --name "AWS Console" --username "admin@actitud.xyz" --password "Aws#P@ssw0rd!2026" --uri "https://console.aws.amazon.com" --notes "Root account, enable MFA!" --tags important,production --folder "$INFRA"
	baluard add login --name "Gmail" --username "esteban@gmail.com" --password "Gm@1lS3cur3!" --uri "https://mail.google.com" --tags personal,mfa --folder "$PERSONAL"
	baluard add login --name "Netflix" --username "esteban@gmail.com" --password "N3tfl1x\$tream" --uri "https://netflix.com" --tags personal --folder "$PERSONAL"
	baluard add login --name "Figma" --username "esteban@actitud.xyz" --password "F1gm@D3sign!" --uri "https://figma.com" --tags work --folder "$WORK"
	baluard add login --name "Slack" --username "esteban@actitud.xyz" --password "Sl@ckW0rk!" --uri "https://slack.com" --tags work,team --folder "$WORK"
	baluard add login --name "Vercel" --username "esteban@actitud.xyz" --password "V3rc3lD3pl0y!" --uri "https://vercel.com" --tags work,api-key --folder "$WORK"
	baluard add login --name "Cloudflare" --username "admin@actitud.xyz" --password "CF_R@y_ID!2026" --uri "https://dash.cloudflare.com" --tags production --folder "$INFRA"
	baluard add login --name "Linear" --username "esteban@actitud.xyz" --password "L1n3@rPlan!" --uri "https://linear.app" --tags work --folder "$WORK"

	echo ""

	echo ""
	echo "=== Seeding login entries with passkeys ==="

	# GitHub — Login with password + passkey (YubiKey 5C NFC)
	jq --arg fid "$WORK" '.folder_id = $fid' scripts/demo-github-passkey.json | baluard add json -

	# Google — Passkey-only login (no password, iPhone 16 Pro)
	jq --arg fid "$PERSONAL" '.folder_id = $fid' scripts/demo-google-passkey.json | baluard add json -

	# AWS — Password + 2 passkeys (YubiKey 5Ci + MacBook Touch ID)
	jq --arg fid "$INFRA" '.folder_id = $fid' scripts/demo-aws-passkey.json | baluard add json -

	# Figma — Imported passkey (missing private key, Bitwarden import scenario)
	jq --arg fid "$WORK" '.folder_id = $fid' scripts/demo-figma-passkey.json | baluard add json -

	echo "=== Seeding card entries ==="

	baluard add card --name "Visa Platinum" --cardholder-name "Esteban Forge" --brand "Visa" --number "4532123456789012" --exp-month "09" --exp-year "2028" --code "123" --tags personal,important --folder "$FINANCE"
	baluard add card --name "Mastercard Business" --cardholder-name "Esteban Forge" --brand "Mastercard" --number "5412345678901234" --exp-month "03" --exp-year "2027" --code "456" --tags work --folder "$FINANCE"
	baluard add card --name "Amex Gold" --cardholder-name "Esteban Forge" --brand "American Express" --number "378282246310005" --exp-month "12" --exp-year "2029" --code "7890" --notes "Travel rewards card" --folder "$FINANCE"

	echo ""
	echo "=== Seeding secure notes ==="

	baluard add note --name "WiFi Password - Home" --notes 'HomeNetwork$_2026!' --tags personal --folder "$PERSONAL"
	baluard add note --name "Server Recovery Codes" --notes $'BACKUP-1: A3F8-B7C2-D9E1\nBACKUP-2: K4M6-P8R2-T5W9\nBACKUP-3: X1Y3-Z5A7-B9C1' --tags important,backup --folder "$INFRA"
	baluard add note --name "Garage Door Code" --notes "4521" --tags personal --folder "$PERSONAL"
	baluard add note --name "Safety Deposit Box" --notes $'Bank: Chase Downtown\nBox: #417\nKey: green tag in desk drawer' --tags personal,important --folder "$PERSONAL"
	baluard add note --name "Email Aliases" --notes $'personal: esteban@gmail.com\nwork: esteban@actitud.xyz\nbilling: billing@actitud.xyz\nspam: noreply+spam@actitud.xyz' --tags shared --folder "$PERSONAL"

	echo ""
	echo "=== Seeding identity entries ==="

	baluard add identity --name "Esteban Forge" --title "Mr" --first-name "Esteban" --last-name "Forge" --username "estebanforge" --company "Actitud Studio" --email "esteban@actitud.xyz" --phone "+1-555-0142" --address1 "742 Innovation Drive" --city "San Francisco" --state "CA" --postal-code "94105" --country "US" --tags personal,important --folder "$PERSONAL"
	baluard add identity --name "Business Contact" --title "Mr" --first-name "Esteban" --last-name "Forge" --company "Actitud Studio" --email "info@actitud.xyz" --phone "+1-555-0143" --address1 "742 Innovation Drive" --city "San Francisco" --state "CA" --postal-code "94105" --country "US" --tags work,shared --folder "$WORK"

	echo ""
	echo "=== Seeding SSH keys ==="

	baluard add ssh-key --name "GitHub SSH Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeGitHub2026" --fingerprint "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8" --tags important,api-key --folder "$INFRA"
	baluard add ssh-key --name "Production Server" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeProd2026" --fingerprint "SHA256:pB9R3k7mWQ2vX4yN8tL6jK5hG0dF1sA3cE7uM9wR2iO" --tags production,important --folder "$INFRA"
	baluard add ssh-key --name "Staging Deploy Key" --public-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEstebanForgeStaging2026" --fingerprint "SHA256:qR4tY7uW0vX2zN5bA8cD6eF3gH1iJ9kL0mO3pS6wU2xT" --notes "Read-only deploy key for staging" --tags staging --folder "$INFRA"

	echo ""
	echo "=== Seeding bank accounts ==="

	baluard add bank --name "Chase Checking" --bank-name "JPMorgan Chase" --name-on-account "Esteban Forge" --account-type "Checking" --account-number "123456789" --routing-number "021000021" --swift-code "CHASUS33" --tags personal --folder "$FINANCE"
	baluard add bank --name "Chase Savings" --bank-name "JPMorgan Chase" --name-on-account "Esteban Forge" --account-type "Savings" --account-number "987654321" --routing-number "021000021" --tags personal --folder "$FINANCE"
	baluard add bank --name "Business Account" --bank-name "Silicon Valley Bank" --name-on-account "Actitud Studio LLC" --account-type "Business Checking" --account-number "456789123" --routing-number "121000248" --swift-code "SVBKUS6S" --notes "Business operating account" --tags work --folder "$FINANCE"

	echo ""
	echo "=== Seeding driver licenses ==="

	baluard add license --name "CA Driver License" --first-name "Esteban" --last-name "Forge" --date-of-birth "1990-06-15" --license-number "F1234567" --issuing-country "US" --issuing-state "CA" --issue-date "2018-03-20" --expiration-date "2028-03-20" --tags personal,important --folder "$PERSONAL"

	echo ""
	echo "=== Seeding passports ==="

	baluard add passport --name "US Passport" --surname "Forge" --given-name "Esteban" --date-of-birth "1990-06-15" --sex "M" --birth-place "San Francisco" --nationality "US" --passport-number "P12345678" --issuing-country "US" --issue-date "2022-01-15" --expiration-date "2032-01-14" --tags personal,important --folder "$TRAVEL"

	echo ""
	echo "=== Seeding national IDs ==="

	baluard add note --name "Chile Carnet de Identidad" --notes $'RUN/RUT: 16.543.210-4\nTipo: Cédula de Identidad\nNombres: Esteban Andrés\nApellidos: Forge Muñoz\nSexo: M\nFecha de nacimiento: 1990-06-15\nNacionalidad: Chilena\nFecha de emisión: 2021-08-10\nFecha de vencimiento: 2031-08-10\nNúmero de documento: A12345678' --tags personal,important --folder "$PERSONAL"
	baluard add note --name "Chile RUT (Empresa)" --notes $'RUT: 76.321.456-K\nRazón social: Actitud Studio SpA\nTipo entidad: Sociedad por Acciones\nActividad: Desarrollo de software\nFecha de inicio: 2023-03-15\nSII: Registro Vigente' --tags work,important --folder "$WORK"
	baluard add bank --name "Banco de Chile Cuenta Corriente" --bank-name "Banco de Chile" --name-on-account "Esteban Forge Muñoz" --account-type "Cuenta Corriente" --account-number "12345678" --routing-number "0001" --swift-code "BCHICLRM" --tags personal --folder "$FINANCE"

	echo ""
	echo "=== Demo vault seeded ==="
	echo "  Location: $VAULT"
	echo "  Password: baluard99"
	echo ""
	echo "  Entries by type:"
	echo "    Logins:       14  (incl. 4 with passkeys)"
	echo "    Cards:         3"
	echo "    Notes:         7  (incl. 2 RUT/Carnet)"
	echo "    Identities:    2"
	echo "    SSH Keys:      3"
	echo "    Bank Accounts: 4  (incl. 1 Chilean)"
	echo "    Licenses:      1"
	echo "    Passports:     1"
	echo "    ────────────────"
	echo "    Total:        35"
	echo ""
	echo "  Passkeys:"
	echo "    GitHub (YubiKey 5C NFC)          — password + passkey"
	echo "    Google (iPhone 16 Pro)            — passkey-only, no password"
	echo "    AWS Console (YubiKey 5Ci + Touch ID) — password + TOTP + 2 passkeys"
	echo "    Figma (Imported)                  — password + passkey, private_key_missing"
	echo ""
	echo "  Folders: Personal, Work, Finance, Infrastructure, Travel"
	echo "  Tags:    important, shared, team, personal, urgent, legacy, backup, mfa, api-key, staging, production"
	echo ""
	echo "  List entries: {{ binary }} --direct list"
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
