#!/usr/bin/env bash
# Desktop E2E (the E2E harness): drives the REAL desktop
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
  # pkill -f self-matches this script's own cmdline, and the APP's argv
  # carries no sandbox path (tauri-driver spawns it as the bare binary);
  # the sandbox only appears in its ENVIRONMENT. Match /proc/environ.
  for p in $(pgrep -x baluard-daemon 2>/dev/null; pgrep -x baluard-desktop 2>/dev/null); do
    if tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -q "baluard-e2e-desk"; then
      kill "$p" 2>/dev/null || true
    fi
  done
  [[ -n "$VITE_PID" ]] && kill "$VITE_PID" 2>/dev/null || true
  [[ -n "$DRIVER_PID" ]] && kill "$DRIVER_PID" 2>/dev/null || true
  [[ -n "$XVFB_PID" ]] && kill "$XVFB_PID" 2>/dev/null || true
  # The sandbox is synthetic and disposable; keep it only on demand.
  if [[ "${BALUARD_E2E_KEEP:-0}" != "1" ]]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

[[ -x "$CLI" ]] || { echo "missing $CLI (cargo build -p baluard-cli)"; exit 1; }
[[ -x "$APP" ]] || { echo "missing $APP (PKG_CONFIG_PATH=/usr/lib64/pkgconfig cargo build --manifest-path desktop/src-tauri/Cargo.toml)"; exit 1; }
# The app spawns its own sidecar daemon — and NOT from target/debug: it
# runs the STAGED COPY at desktop/src-tauri/binaries/baluard-daemon-<triple>
# (lib.rs's sidecar spawn). A stale copy serves old wire shapes (the
# health kind/n fields went dark exactly this way), so rebuild the daemon
# and CLI, then restage the copy the app actually runs.
# hw-seal rides along so the sidecar's security-chip probe works on
# hardware-capable machines (the desktop toggle needs it in the daemon;
# machines without a chip are unaffected - the probe reports honestly).
PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-/usr/lib64/pkgconfig}" cargo build -p baluard-daemon -p baluard-cli --features baluard-daemon/hw-seal > /dev/null 2>&1 || {
  echo "cargo build failed"; exit 1;
}
TRIPLE="$(rustc -Vv | sed -n 's/host: //p')"
cp target/debug/baluard-daemon "desktop/src-tauri/binaries/baluard-daemon-$TRIPLE"
# Dev sidecar resolution finds the daemon in the desktop crate's own
# target dir (the justfile's desktop recipes stage it the same way).
mkdir -p desktop/src-tauri/target/debug
cp target/debug/baluard-daemon desktop/src-tauri/target/debug/baluard-daemon
command -v tauri-driver > /dev/null || { echo "missing tauri-driver (cargo install tauri-driver --locked)"; exit 1; }
command -v Xvfb > /dev/null || { echo "missing Xvfb"; exit 1; }

export BALUARD_E2E_PW="${BALUARD_E2E_PW:-e2e-desktop-pw1}"
export BALUARD_E2E_NAME="${BALUARD_E2E_NAME:-E2E Desk}"

# The app kills every baluard-daemon system-wide at its own startup
# (E7's escape hatch is future work); warn loudly before that happens.
stray=$(pgrep -x baluard-daemon 2>/dev/null | grep -vc "^$$") || true
if [[ "${stray:-0}" -gt 0 ]]; then
  echo "WARNING: $stray baluard-daemon process(es) are running; the app will kill them at startup." >&2
fi

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

# Seed one vault with a known password (CLI; registry + marker + theme)
# plus one entry with a weak password for the health-check flow.
SEED_JSON=$(BALUARD_PASSWORD="$BALUARD_E2E_PW" "$CLI" init --json --name "$BALUARD_E2E_NAME" --theme dark)
SEED_PATH=$(printf '%s\n' "$SEED_JSON" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
[[ -n "$SEED_PATH" ]] || { echo "could not read seeded vault path"; exit 1; }
BALUARD_PASSWORD="$BALUARD_E2E_PW" "$CLI" add login --name "Weak Entry" --username u \
  --password 123 --direct --vault-path "$SEED_PATH" > /dev/null 2>&1

# Sharing-flow fixtures: a second LIVE member row (identity keys copied from
# the founder row - grants and group ops refuse rows without share keys) and
# a pending D61 ownership-claim record whose amber card the owner can cancel.
# Fixture recipe from the G26/G11 e2e waves; sandbox-local and disposable.
MEMBER_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
FOUNDER_ROW="$(ls "$SEED_PATH"/meta/members/*.json 2>/dev/null | head -1)"
if [[ -n "$FOUNDER_ROW" ]]; then
  python3 - "$FOUNDER_ROW" "$SEED_PATH" "$MEMBER_ID" << 'PYSEED'
import json, sys, time
from pathlib import Path
founder = json.loads(Path(sys.argv[1]).read_text())
seed_path, member_id = Path(sys.argv[2]), sys.argv[3]
now = int(time.time())
row = {
    "id": member_id,
    "display_name": "E2E Member",
    "email": "member@e2e.test",
    "role": "editor",
    "trust": "channel",
    "identity_signing_pubkey": founder.get("identity_signing_pubkey"),
    "identity_wrap_pubkey": founder.get("identity_wrap_pubkey"),
}
d = seed_path / "meta" / "members"
(d / f"{member_id}.json").write_text(json.dumps(row, indent=1))
cdir = seed_path / "meta" / "contests"
contest = {
    "format": "baluard.ownership-contest.v1",
    "old_owner_id": founder["id"],
    "new_owner_id": member_id,
    "confirmed_at": now,
    "window_until": now + 30 * 86400,
}
cdir.mkdir(parents=True, exist_ok=True)
(cdir / "ownership-claim.json").write_text(json.dumps(contest, indent=1))
PYSEED
fi

# Frontend dev server for the debug binary's devUrl. Invoke the binary
# directly: killing the npx wrapper can orphan the real vite process.
(cd "$ROOT/desktop" && exec ./node_modules/.bin/vite --port 1420 --strictPort) > "$WORK/vite.log" 2>&1 &
VITE_PID=$!
for _ in $(seq 1 60); do
  # A pre-existing server on 1420 answers this curl even though our
  # strictPort vite died - only trust the poll while OUR vite lives.
  if ! kill -0 "$VITE_PID" 2>/dev/null; then
    echo "vite died at startup (is port 1420 taken? see $WORK/vite.log)" >&2
    exit 1
  fi
  curl -s -o /dev/null http://localhost:1420/ && break
  sleep 0.5
done
if ! kill -0 "$VITE_PID" 2>/dev/null; then
  echo "vite died at startup (see $WORK/vite.log)" >&2
  exit 1
fi
curl -sf -o /dev/null http://localhost:1420/ || { echo "vite did not serve"; exit 1; }

# tauri-driver proxies WebDriver to WebKitWebDriver and spawns the app
# from the capabilities' application path; the app inherits this env.
tauri-driver --port "$DRIVER_PORT" > "$WORK/driver.log" 2>&1 &
DRIVER_PID=$!
for _ in $(seq 1 40); do
  curl -sf -o /dev/null "http://127.0.0.1:$DRIVER_PORT/status" && break
  sleep 0.25
done
curl -sf -o /dev/null "http://127.0.0.1:$DRIVER_PORT/status" || { echo "tauri-driver did not start (see $WORK/driver.log)"; exit 1; }

cd "$ROOT/e2e/desktop"
RC=0
node "$FLOW" "$APP" || RC=$?
exit "$RC"
