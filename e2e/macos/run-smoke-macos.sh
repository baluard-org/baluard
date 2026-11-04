#!/usr/bin/env bash
# macOS desktop smoke (see docs/dev/release-smoke-testing.md).
#
# Drives the REAL release-mode app inside the quickemu Sequoia guest from
# this Linux box. The app is the SMOKE bundle (scripts/build-macos-app.sh
# --smoke), which embeds the WebDriver server (tauri-plugin-wdio-webdriver,
# port 4445) via the smoke cargo feature; the host attaches webdriverio over
# an SSH-forwarded WebDriver connection. The shipped artifact carries no
# embedded driver. The app launches through `open -a`, which lands it in the
# console (Aqua) session - the SSH session itself cannot show GUI windows.
#
# Requirements (one-time): Remote Login enabled in the guest with the smoke
# key authorized, the console session logged in (auto-login on), the SMOKE
# bundle installed, seed vault created with one login entry.
#
# Usage: run-smoke-macos.sh
# Env:
#   BALUARD_SMOKE_PW              required - the seed vault's master password
#   BALUARD_SMOKE_MAC_PORT        guest ssh port            (default 22221)
#   BALUARD_SMOKE_MAC_USER        guest ssh user           (default smoketests)
#   BALUARD_SMOKE_MAC_HOST        guest ssh host           (default 127.0.0.1)
#   BALUARD_SMOKE_MAC_SSH         ssh binary + extra args  (default "ssh")
#   BALUARD_SMOKE_MAC_APP         app path in the guest    (default /Applications/Baluard-smoke.app)
#   BALUARD_SMOKE_WEBDRIVER_PORT  embedded WebDriver port  (default 4445)
#   BALUARD_SMOKE_ARTIFACTS       screenshot dir           (default mktemp -d)
#   BALUARD_SMOKE_MAC_RESET=1     wipe the guest's baluard app data and exit
#                                 (destructive: removes the seeded vault too;
#                                 re-seed after; the .app install survives)
set -euo pipefail

PW="${BALUARD_SMOKE_PW:?set BALUARD_SMOKE_PW for the seed vault}"
PORT="${BALUARD_SMOKE_MAC_PORT:-22221}"
USER_NAME="${BALUARD_SMOKE_MAC_USER:-smoketests}"
HOST_NAME="${BALUARD_SMOKE_MAC_HOST:-127.0.0.1}"
APP="${BALUARD_SMOKE_MAC_APP:-/Applications/Baluard-smoke.app}"
WDP="${BALUARD_SMOKE_WEBDRIVER_PORT:-4445}"
ARTIFACTS="${BALUARD_SMOKE_ARTIFACTS:-$(mktemp -d)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ARTIFACTS"

KEY="$HOME/.local/share/baluard-smoke/mac-guest-key"
read -ra SSHBIN <<< "${BALUARD_SMOKE_MAC_SSH:-ssh}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
[[ -f "$KEY" ]] && SSH_OPTS+=(-i "$KEY" -o IdentitiesOnly=yes)
run_ssh() { "${SSHBIN[@]}" "${SSH_OPTS[@]}" -p "$PORT" "$USER_NAME@$HOST_NAME" "$1"; }

TUN_PID=""
cleanup() {
  [[ -n "$TUN_PID" ]] && kill "$TUN_PID" 2>/dev/null || true
  run_ssh "pkill -f Baluard-smoke >/dev/null 2>&1" >/dev/null 2>&1 || true
  run_ssh "pkill -x baluard-daemon >/dev/null 2>&1" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== SSH probe"
run_ssh "sw_vers -productVersion" >/dev/null || {
  echo "FAIL: no BatchMode SSH to $USER_NAME@$HOST_NAME:$PORT (Remote Login on? key authorized? VM running?)"
  exit 1
}

if [[ "${BALUARD_SMOKE_MAC_RESET:-0}" == "1" ]]; then
  echo "== Wiping guest app data (~/Library/Application Support/baluard)"
  run_ssh "rm -rf ~/Library/Application\\ Support/baluard"
  echo "OK: wiped. Re-seed the vault, then rerun without BALUARD_SMOKE_MAC_RESET."
  exit 0
fi

echo "== Locating app"
run_ssh "[ -d '$APP' ]" || {
  echo "FAIL: $APP missing in the guest. Install the SMOKE bundle:"
  echo "  tar cf - -C desktop/src-tauri/target/x86_64-apple-darwin/release/bundle/macos Baluard-smoke.app | tar xf - -C /tmp"
  echo "  sudo mv /tmp/Baluard-smoke.app /Applications/  (or set BALUARD_SMOKE_MAC_APP)"
  exit 1
}

echo "== Killing leftovers"
run_ssh "pkill -f Baluard-smoke >/dev/null 2>&1; pkill -x baluard-daemon >/dev/null 2>&1; true" >/dev/null

echo "== Launching via open -a (console session)"
run_ssh "open -a '$APP'" || { echo "FAIL: open -a did not accept the app"; exit 1; }

echo "== Forwarding WebDriver $WDP"
"${SSHBIN[@]}" "${SSH_OPTS[@]}" -N -L "$WDP:127.0.0.1:$WDP" -p "$PORT" "$USER_NAME@$HOST_NAME" &
TUN_PID=$!

echo "== Polling /status"
probe_ok=0
for i in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$WDP/status" >/dev/null 2>&1; then probe_ok=1; break; fi
  sleep 1
done
[[ "$probe_ok" == "1" ]] || {
  echo "FAIL: embedded WebDriver never answered on $WDP (is this the SMOKE bundle? console session logged in?)"
  exit 1
}

[[ -d node_modules ]] || npm install --no-audit --no-fund >/dev/null

cd "$HERE"
echo "== Running smoke flow"
BALUARD_SMOKE_PW="$PW" \
BALUARD_SMOKE_WEBDRIVER_PORT="$WDP" \
BALUARD_SMOKE_ARTIFACTS="$ARTIFACTS" \
node smoke.mjs

echo "OK: artifacts in $ARTIFACTS"
