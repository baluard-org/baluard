#!/usr/bin/env bash
# Browser-extension e2e (the E2E harness), Firefox leg: real
# Firefox (geckodriver, temporary add-on) + real NMH + real daemon + the real
# bridge pairing ceremony over the daemon socket.
#
# Sandbox layout per run: a fresh BALUARD_DATA_DIR, an isolated HOME (the
# Firefox NMH manifest lives at $HOME/.mozilla/native-messaging-hosts), and a
# scratch socket. The Firefox extension id is fixed by the manifest's gecko
# id, so no key injection is needed. The popup page runs as a tab (see
# ff.mjs); the ring asserts pairing + an explicit-url matches probe.
set -euo pipefail
cd "$(dirname "$0")/../.."

REPO=$PWD
command -v node >/dev/null || { echo "node is required"; exit 1; }
[ -x "$REPO/e2e/extension/.tools/geckodriver" ] || {
  echo "geckodriver missing: fetch v0.36.0 into e2e/extension/.tools"; exit 1; }
command -v firefox >/dev/null || { echo "firefox is required"; exit 1; }

# ---- Build what the flow drives.
cargo build -q -p baluard-nmh -p baluard-cli -p baluard-daemon
just ext-build-firefox >/dev/null

WORK=$(mktemp -d /tmp/baluard-extff.XXXXXX)
DATA=$WORK/data
HOME_SBOX=$WORK/home
SOCK=$WORK/d.sock
FF_PROFILE=$WORK/ffprofile
mkdir -p "$DATA" "$HOME_SBOX/.mozilla/native-messaging-hosts" "$FF_PROFILE"

cleanup() {
  [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null || true
  # A wedged browser outlives the session delete; sweep by OUR profile path
  # (scoped: a concurrent run's Firefox uses its own directory).
  for CMD in /proc/[0-9]*/cmdline; do
    if grep -q -- "-profile $FF_PROFILE" "$CMD" 2>/dev/null; then
      PID="${CMD#/proc/}"
      kill "${PID%/cmdline}" 2>/dev/null || true
    fi
  done
  if [ "${BALUARD_E2E_KEEP:-0}" != "1" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ---- NMH manifest under the sandboxed HOME (Firefox user-level path); the
# allowed extension is the dist's fixed gecko id, no key injection needed.
NMH_BIN=$REPO/target/debug/baluard-nmh
cat > "$WORK/nmh-wrapper.sh" <<WRAPPER
#!/usr/bin/env bash
export BALUARD_SOCKET="$SOCK"
export BALUARD_DATA_DIR="$DATA"
export BALUARD_DISABLE_KEYRING=1
exec "$NMH_BIN"
WRAPPER
chmod +x "$WORK/nmh-wrapper.sh"
printf '{"name":"xyz.actitud.baluard","description":"Baluard bridge","path":"%s","type":"stdio","allowed_extensions":["baluard@actitud.xyz"]}' \
  "$WORK/nmh-wrapper.sh" > "$HOME_SBOX/.mozilla/native-messaging-hosts/xyz.actitud.baluard.json"

# ---- Scratch daemon + seeded, unlocked vault (the desktop side).
BALUARD_DATA_DIR="$DATA" BALUARD_DISABLE_KEYRING=1 BALUARD_AUTOSYNC=0 \
  "$REPO/target/debug/baluard-daemon" --socket "$SOCK" >"$WORK/daemon.log" 2>&1 &
DPID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
[ -S "$SOCK" ] || { echo "daemon socket never appeared"; tail "$WORK/daemon.log"; exit 1; }

export BALUARD_DATA_DIR="$DATA" BALUARD_DISABLE_KEYRING=1 BALUARD_NO_PROMPT=1
BALUARD_PASSWORD='ext-e2e-pw1' BALUARD_SOCKET="$SOCK" \
  "$REPO/target/debug/baluard" init --name 'Ext Vault' --slug ext-t --json >"$WORK/init.json" 2>"$WORK/init.err"
SITE_PORT=$(node -e 'console.log(20000 + Math.floor(Math.random() * 20000))')
SITE_URL="http://127.0.0.1:$SITE_PORT/"
BALUARD_PASSWORD='ext-e2e-pw1' BALUARD_SOCKET="$SOCK" \
  "$REPO/target/debug/baluard" add login --name 'Ext Bank' --username 'u@ext.test' \
  --password 'hunter2ext' --uri "$SITE_URL" >/dev/null
BALUARD_PASSWORD='ext-e2e-pw1' BALUARD_SOCKET="$SOCK" \
  "$REPO/target/debug/baluard" unlock >/dev/null
DESKTOP_TOKEN=$(cat "$WORK/d.tok")

# ---- Firefox runs under the sandboxed HOME so the NMH manifest resolves
# ($HOME/.mozilla/native-messaging-hosts); geckodriver creates its own temp
# profile and runs headless itself. The popup page runs as a tab (ff.mjs
# header documents the sender-classification chain that makes that work).
cd e2e/extension
export HOME="$HOME_SBOX"
export DESKTOP_TOKEN DAEMON_SOCKET="$SOCK" SITE_URL FF_DIST="$REPO/browser/firefox/dist" FF_PROFILE
node ff.mjs
