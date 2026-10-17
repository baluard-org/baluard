#!/usr/bin/env bash
# Desktop E2E (docs/e2e-testing.md Phase 3): drives the REAL desktop
# app (WebKitGTK webview) headless under Xvfb through tauri-driver.
#
# Sandbox layout: one fresh BALUARD_DATA_DIR per run resets the unlock
# rate limiter and persisted UI state; HOME is isolated so libgit2
# never sees the developer's git config; LANG pins the i18n fallback
# to English. The debug app loads devUrl localhost:1420, so a vite dev
# server must serve CURRENT frontend source (started here from
# desktop/, never the repo root).
#
# Note: the app kills every baluard-daemon system-wide at startup and
# spawns its own sidecar; do not run this beside a daemon you care
# about. Requires: tauri-driver (cargo install tauri-driver --locked),
# Xvfb, WebKitWebDriver (webkit2gtk4.1 on Fedora).
#
# Usage: e2e/desktop/run-e2e-desktop.sh [flow.mjs]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d /tmp/baluard-e2e-desk.XXXXXX)"
FLOW="${1:-unlock.mjs}"
CLI="$ROOT/target/debug/baluard"
APP="$ROOT/desktop/src-tauri/target/debug/baluard-desktop"
DRIVER_PORT=4444
DISPLAY_NUM="${BALUARD_E2E_DISPLAY:-97}"

VITE_PID=""; DRIVER_PID=""; XVFB_PID=""
cleanup() {
  # pkill -f self-matches this script's own cmdline; enumerate by exact
  # comm and match the sandbox path instead.
  for p in $(pgrep -x baluard-daemon 2>/dev/null; pgrep -x baluard-desktop 2>/dev/null); do
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "baluard-e2e-desk"; then
      kill "$p" 2>/dev/null || true
    fi
  done
  [[ -n "$VITE_PID" ]] && kill "$VITE_PID" 2>/dev/null || true
  [[ -n "$DRIVER_PID" ]] && kill "$DRIVER_PID" 2>/dev/null || true
  [[ -n "$XVFB_PID" ]] && kill "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT

[[ -x "$CLI" ]] || { echo "missing $CLI (cargo build -p baluard-cli)"; exit 1; }
[[ -x "$APP" ]] || { echo "missing $APP (PKG_CONFIG_PATH=/usr/lib64/pkgconfig cargo build --manifest-path desktop/src-tauri/Cargo.toml)"; exit 1; }
command -v tauri-driver > /dev/null || { echo "missing tauri-driver (cargo install tauri-driver --locked)"; exit 1; }
command -v Xvfb > /dev/null || { echo "missing Xvfb"; exit 1; }

export BALUARD_E2E_PW="${BALUARD_E2E_PW:-e2e-desktop-pw1}"
export BALUARD_E2E_NAME="${BALUARD_E2E_NAME:-E2E Desk}"

# Fake display: WebKit needs software GL headless and the DMABUF
# renderer disabled or the window paints white (recorded recipe).
Xvfb ":$DISPLAY_NUM" -screen 0 1280x800x24 > /dev/null 2>&1 &
XVFB_PID=$!
sleep 1
export DISPLAY=":$DISPLAY_NUM"
export GDK_BACKEND=x11
export LIBGL_ALWAYS_SOFTWARE=1
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export LANG=C.UTF-8
# Hermetic app environment: own HOME (libgit2), own data dir, no
# keyring; children (WebKitWebDriver -> app -> sidecar daemon) inherit.
export HOME="$WORK/home"
mkdir -p "$HOME"
export BALUARD_DATA_DIR="$WORK/data"
export BALUARD_DISABLE_KEYRING=1
mkdir -p "$BALUARD_DATA_DIR"

# Seed one vault with a known password (CLI; registry + marker + theme).
BALUARD_PASSWORD="$BALUARD_E2E_PW" "$CLI" init --name "$BALUARD_E2E_NAME" --theme dark > /dev/null

# Frontend dev server for the debug binary's devUrl.
(cd "$ROOT/desktop" && exec npx vite --port 1420 --strictPort) > "$WORK/vite.log" 2>&1 &
VITE_PID=$!
for _ in $(seq 1 60); do
  curl -s -o /dev/null http://localhost:1420/ && break
  sleep 0.5
done
curl -sf -o /dev/null http://localhost:1420/ || { echo "vite did not serve"; exit 1; }

# tauri-driver proxies WebDriver to WebKitWebDriver and spawns the app
# from the capabilities' application path; the app inherits this env.
tauri-driver --port "$DRIVER_PORT" > "$WORK/driver.log" 2>&1 &
DRIVER_PID=$!
sleep 1

cd "$ROOT/e2e/desktop"
RC=0
node "$FLOW" "$APP" || RC=$?
exit "$RC"
