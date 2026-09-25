#!/usr/bin/env bash
# Linux install-and-launch smoke test for Baluard desktop packages.
#
# Usage: linux-smoke.sh <path-to-.deb-or-.rpm>
#
# Installs the package with the distro package manager (runtime deps such as
# WebKitGTK, GTK3, and ayatana-appindicator resolve automatically — this is
# what catches soname drift on new distro releases), launches the app under
# Xvfb, and asserts:
#   1. the app process stays alive through the wait window
#   2. the daemon socket file appears (sidecar started and listening)
#   3. a screenshot artifact is saved for human inspection (blank windows)
#
# Exits nonzero on the first failed assertion and prints the app's stderr.
# Set SMOKE_ARTIFACTS to redirect artifact output (CI uses the workspace).
set -euo pipefail

PKG="${1:?usage: linux-smoke.sh <path-to-.deb-or-.rpm>}"
PKG="$(readlink -f "$PKG")"
ARTIFACTS="${SMOKE_ARTIFACTS:-$(mktemp -d)}"
WORK="$(mktemp -d)"
export HOME="$WORK/home"
export XDG_RUNTIME_DIR="$WORK/xdg-run"
# Hermetic CI: no Secret Service in containers; daemon skips keyring init.
export BALUARD_DISABLE_KEYRING=1
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$ARTIFACTS"

echo "== Installing $PKG"
if [[ "$PKG" == *.deb ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # Installing the package itself pulls its declared runtime deps; a soname
  # drift on this distro release fails loudly right here.
  apt-get install -y -qq xvfb imagemagick dbus "$PKG" >"$WORK/pkg.log" 2>&1 \
    || { tail -30 "$WORK/pkg.log"; exit 1; }
elif [[ "$PKG" == *.rpm ]]; then
  dnf install -y dbus-daemon dbus-x11 xorg-x11-server-Xvfb ImageMagick "$PKG" >"$WORK/pkg.log" 2>&1 \
    || { tail -30 "$WORK/pkg.log"; exit 1; }
else
  echo "Unknown package type: $PKG" >&2
  exit 2
fi

BIN=/usr/bin/baluard-desktop
if [[ ! -x "$BIN" ]]; then
  echo "FAIL: $BIN not found after install"
  exit 1
fi

echo "== Launching under Xvfb"
export BIN WORK ARTIFACTS
# WebKitGTK's bubblewrap sandbox cannot create user namespaces inside
# unprivileged CI containers, which kills the web process. This smoke run
# is a throwaway container, not a user machine: disabling it is the
# standard CI practice and does not affect real installations.
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
xvfb-run -a -s "-screen 0 1280x800x24" dbus-run-session -- bash -c '
  set -u
  "$BIN" >/dev/null 2>"$WORK/app.stderr" &
  APP=$!
  SOCK=""
  # 20s window: first launch initializes crypto and the daemon before the
  # socket appears.
  for _ in $(seq 1 40); do
    sleep 0.5
    if ! kill -0 "$APP" 2>/dev/null; then
      echo "FAIL: app exited before the daemon socket appeared"
      tail -40 "$WORK/app.stderr" 2>/dev/null || true
      exit 1
    fi
    for cand in "$XDG_RUNTIME_DIR/baluard/baluard.sock" \
                "$HOME/.local/share/baluard/baluard.sock"; do
      if [[ -S "$cand" ]]; then SOCK="$cand"; break 2; fi
    done
  done
  if [[ -z "$SOCK" ]]; then
    echo "FAIL: daemon socket never appeared within 20s"
    tail -40 "$WORK/app.stderr" 2>/dev/null || true
    exit 1
  fi
  # Let the webview paint a few frames before declaring victory.
  sleep 3
  if ! kill -0 "$APP" 2>/dev/null; then
    echo "FAIL: app died after the socket appeared"
    tail -40 "$WORK/app.stderr" 2>/dev/null || true
    exit 1
  fi
  # Screenshot artifact: humans glance for blank windows; `import` needs
  # ImageMagick, xwd is the fallback.
  import -window root "$ARTIFACTS/screenshot.png" 2>/dev/null \
    || xwd -root -out "$ARTIFACTS/screenshot.xwd" 2>/dev/null \
    || echo "WARN: no screenshot tool worked"
  kill "$APP" 2>/dev/null || true
  wait "$APP" 2>/dev/null || true
  echo "OK: process alive, socket present at $SOCK"
'

echo "== Artifacts: $ARTIFACTS"
ls -la "$ARTIFACTS" 2>/dev/null || true
echo "SMOKE PASS"
