#!/usr/bin/env bash
# Browser-extension e2e (docs/e2e-testing.md Phase 4, Ring 1): real Chromium
# (Playwright bundle) + real NMH + real daemon + the real bridge pairing
# ceremony over the daemon socket.
#
# Sandbox layout per run: a fresh BALUARD_DATA_DIR (rate limiter + pairing
# state), an isolated HOME (the NMH manifest lives at $HOME/.config/chromium/
# NativeMessagingHosts and libgit2 hermeticity comes free), and a scratch
# socket. The extension dist is copied with an injected fixed "key" so the
# extension id — and therefore the NMH manifest's allowed_origins — is stable.
set -euo pipefail
cd "$(dirname "$0")/../.."

REPO=$PWD
EXT_KEY='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlqwKqiibJtMN9WPB8FNK9Gif/oYKvuVaRHzQnOKuuwRL1Sy9BVFaJOSYcCDJt9wsEJ7pzmefwn6clx2IfbzkZjUaPADyuoYylGlV1K/75/YlALy2OW7S6Eov+Bwga+stFXNcybVhHiQSxhQQMNeNECYwWQcqXUPbGPqa0bOByHzCeHUBKtGH3CPsoNMv/3ZicZVHGxMQZ8/TbEGXAbZgHjHOBfM5eFuWz02At6CXADtU3haNjWydTUBHWvtHKqKwmzfQrR6UDo7tNA3MqcyKlBkuNayiPuzUayCpTcA6J+p6DZvS8zQpjTd2R6kir7S9qqNus0msoPUCorRrQMm+awIDAQAB'   # test-only RSA public key (public material); pins the id

command -v node >/dev/null || { echo "node is required"; exit 1; }
[ -x e2e/extension/node_modules/.bin/playwright ] || {
  echo "run: (cd e2e/extension && npm install && npx playwright install chromium)"; exit 1; }

# ---- Build what the flow drives.
cargo build -q -p baluard-nmh -p baluard-cli -p baluard-daemon
just ext-build-chrome >/dev/null 2>&1

WORK=$(mktemp -d /tmp/baluard-ext.XXXXXX)
DATA=$WORK/data
HOME_SBOX=$WORK/home
PROFILE=$WORK/profile
SOCK=$WORK/d.sock
mkdir -p "$DATA" "$HOME_SBOX" "$PROFILE"
PW=$REPO/e2e/extension/node_modules/.bin

cleanup() {
  [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null || true
  [ -n "${XVFB_PID:-}" ] && kill "$XVFB_PID" 2>/dev/null || true
  if [ "${BALUARD_E2E_KEEP:-0}" != "1" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ---- Dist copy + injected key -> deterministic extension id.
EXT_DIR=$WORK/extdist
cp -r browser/chrome/dist "$EXT_DIR"
node -e '
  const fs = require("fs");
  const p = process.argv[1], key = process.argv[2];
  const m = JSON.parse(fs.readFileSync(p, "utf8"));
  m.key = key;
  fs.writeFileSync(p, JSON.stringify(m));
' "$EXT_DIR/manifest.json" "$EXT_KEY"
EXT_ID=$(node -e '
  const crypto = require("crypto");
  const der = Buffer.from(process.argv[1], "base64");
  const hex = crypto.createHash("sha256").update(der).digest("hex").slice(0, 32);
  console.log(hex.replace(/[0-9a-f]/g, (c) => String.fromCharCode(97 + parseInt(c, 16))));
' "$EXT_KEY")
echo "EXT_ID=$EXT_ID"

# ---- NMH manifest under the sandboxed HOME (Chromium brand paths).
NMH_BIN=$REPO/target/debug/baluard-nmh
cat > "$WORK/nmh-wrapper.sh" <<WRAPPER
#!/usr/bin/env bash
export BALUARD_SOCKET="$SOCK"
export BALUARD_DATA_DIR="$DATA"
export BALUARD_DISABLE_KEYRING=1
exec "$NMH_BIN"
WRAPPER
chmod +x "$WORK/nmh-wrapper.sh"
# Modern Chromium resolves user-level NMH manifests relative to the USER
# DATA DIR (observed via strace: it opens <profile>/NativeMessagingHosts);
# the HOME brand paths stay for older/branded builds.
for DIR in "$PROFILE/NativeMessagingHosts" \
  "$HOME_SBOX/.config/chromium/NativeMessagingHosts" \
  "$HOME_SBOX/.config/google-chrome/NativeMessagingHosts"; do
  mkdir -p "$DIR"
  printf '{"name":"xyz.actitud.baluard","description":"Baluard bridge","path":"%s","type":"stdio","allowed_origins":["chrome-extension://%s/"]}' \
    "$WORK/nmh-wrapper.sh" "$EXT_ID" > "$DIR/xyz.actitud.baluard.json"
done

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

# ---- Headed Chromium under Xvfb (extensions + real popup rendering).
# Always run on our own Xvfb: the inherited DISPLAY can point at a dead
# display (real browsers need a live X server for extension popups).
XVFB_PID=""
XVFB_DISP=$((20 + RANDOM % 40))
Xvfb ":$XVFB_DISP" -screen 0 1280x800x24 >/dev/null 2>&1 & XVFB_PID=$!
for _i in $(seq 1 30); do [ -S "/tmp/.X11-unix/X$XVFB_DISP" ] && break; sleep 0.2; done
[ -S "/tmp/.X11-unix/X$XVFB_DISP" ] || { echo "Xvfb never started"; exit 1; }
export DISPLAY=":$XVFB_DISP"
# The browser and node run under the sandboxed HOME (NMH brand paths; no
# caller state leaks through). Cargo deliberately stays on the real HOME so
# its caches keep working.
export HOME="$HOME_SBOX"

cd e2e/extension
CDP_PORT=$((25000 + RANDOM % 20000))
PLAYWRIGHT_BROWSERS_PATH="$REPO/e2e/extension/.browsers" \
EXT_ID="$EXT_ID" EXT_DIR="$EXT_DIR" DESKTOP_TOKEN="$DESKTOP_TOKEN" \
DAEMON_SOCKET="$SOCK" SITE_URL="$SITE_URL" PROFILE_DIR="$PROFILE" CDP_PORT="$CDP_PORT" \
  node pw.mjs
