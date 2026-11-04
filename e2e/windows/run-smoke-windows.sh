#!/usr/bin/env bash
# Windows desktop smoke (see docs/dev/release-smoke-testing.md).
#
# Drives the REAL release-mode app inside the quickemu Windows 11 guest from
# this Linux box. The app runs the SMOKE installer build (scripts/
# build-windows-installer.sh --smoke), whose tauri.smoke.conf.json bakes
# --remote-debugging-port=9222 into the webview; the host attaches Playwright
# over an SSH-forwarded CDP connection. The shipped artifact carries no such
# flag. The app launches through a scheduled task because it cannot run under
# the SSH session (Session 0: WebView2 refuses it).
#
# Requirements (one-time): sshd in the guest with your key authorized, the
# SMOKE installer installed, seed vault created with one login entry.
#
# Usage: run-smoke-windows.sh
# Env:
#   BALUARD_SMOKE_PW           required - the seed vault's master password
#   BALUARD_SMOKE_WIN_PORT     guest ssh port            (default 22220)
#   BALUARD_SMOKE_WIN_USER     guest ssh user           (default Quickemu)
#   BALUARD_SMOKE_WIN_HOST     guest ssh host           (default 127.0.0.1)
#   BALUARD_SMOKE_WIN_SSH      ssh binary + extra args  (default "ssh")
#   BALUARD_SMOKE_CDP          CDP port                 (default 9222)
#   BALUARD_SMOKE_ARTIFACTS    screenshot dir           (default mktemp -d)
#   BALUARD_SMOKE_WIN_RESET=1  wipe %LOCALAPPDATA%\baluard and exit
#                              (destructive: that dir holds BOTH the install
#                              and the app data; reinstall and re-seed after)
set -euo pipefail

PW="${BALUARD_SMOKE_PW:?set BALUARD_SMOKE_PW for the seed vault}"
PORT="${BALUARD_SMOKE_WIN_PORT:-22220}"
USER_NAME="${BALUARD_SMOKE_WIN_USER:-Quickemu}"
HOST_NAME="${BALUARD_SMOKE_WIN_HOST:-127.0.0.1}"
CDP="${BALUARD_SMOKE_CDP:-9222}"
ARTIFACTS="${BALUARD_SMOKE_ARTIFACTS:-$(mktemp -d)}"
EXE=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ARTIFACTS"

read -ra SSHBIN <<< "${BALUARD_SMOKE_WIN_SSH:-ssh}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5)
run_ssh() { "${SSHBIN[@]}" "${SSH_OPTS[@]}" -p "$PORT" "$USER_NAME@$HOST_NAME" "$1"; }

TUN_PID=""
cleanup() {
  [[ -n "$TUN_PID" ]] && kill "$TUN_PID" 2>/dev/null || true
  run_ssh 'schtasks /delete /f /tn BaluardSmoke >nul 2>&1' >/dev/null 2>&1 || true
  run_ssh 'schtasks /delete /f /tn BaluardSmokeDaemon >nul 2>&1' >/dev/null 2>&1 || true
  run_ssh 'taskkill /F /IM baluard-daemon.exe >nul 2>&1' >/dev/null 2>&1 || true
  local image="${EXE##*\\}"
  [[ -n "$image" ]] && run_ssh "taskkill /F /IM \"$image\" >nul 2>&1" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== SSH probe"
run_ssh ver >/dev/null || { echo "FAIL: no BatchMode SSH to $USER_NAME@$HOST_NAME:$PORT (key authorized? VM running?)"; exit 1; }

if [[ "${BALUARD_SMOKE_WIN_RESET:-0}" == "1" ]]; then
  echo "== Wiping guest install + app data (%LOCALAPPDATA%\baluard)"
  run_ssh 'rmdir /s /q "%LOCALAPPDATA%\baluard"'
  echo "OK: wiped. Reinstall the smoke build and re-seed the vault, then rerun without BALUARD_SMOKE_WIN_RESET."
  exit 0
fi

echo "== Locating the app"
EXE="$(run_ssh 'if exist "%LOCALAPPDATA%\baluard\baluard-desktop.exe" (echo %LOCALAPPDATA%\baluard\baluard-desktop.exe) else if exist "%LOCALAPPDATA%\Baluard\Baluard.exe" (echo %LOCALAPPDATA%\Baluard\Baluard.exe) else (echo NOTFOUND)' | tr -d '\r')"
[[ "$EXE" != "NOTFOUND" && -n "$EXE" ]] || { echo "FAIL: the app is not installed in the guest (install the SMOKE build: scripts/build-windows-installer.sh --smoke)"; exit 1; }
echo "   $EXE"

echo "== Opening CDP tunnel (127.0.0.1:$CDP -> guest)"
"${SSHBIN[@]}" "${SSH_OPTS[@]}" -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L "$CDP:127.0.0.1:$CDP" -p "$PORT" "$USER_NAME@$HOST_NAME" &
TUN_PID=$!

echo "== Launching daemon + app in the logged-on session"
# Orphaned WebView2 browser processes keep the user-data folder; a later
# launch would join them silently. Clear every leftover first.
run_ssh 'taskkill /F /IM baluard-daemon.exe >nul 2>&1 & taskkill /F /IM baluard-desktop.exe >nul 2>&1 & taskkill /F /IM Baluard.exe >nul 2>&1 & taskkill /F /IM msedgewebview2.exe >nul 2>&1' >/dev/null 2>&1 || true
# The app's sidecar spawn silently fails under a scheduled task (0.1.0 VM
# round), but a daemon started the same way runs fine, and on Windows the
# app has no kill sweep (that is #[cfg(unix)]) and adopts a healthy
# same-version daemon (D79). So: daemon first, then the app.
DAEMON_BAT='%LOCALAPPDATA%\baluard\smoke-daemon.bat'
run_ssh "(echo @echo off & echo set BALUARD_DISABLE_KEYRING=1 & echo start \"\" \"%LOCALAPPDATA%\\baluard\\baluard-daemon.exe\") > \"$DAEMON_BAT\""
run_ssh 'schtasks /create /f /tn BaluardSmokeDaemon /sc once /st 00:00 /tr "%LOCALAPPDATA%\baluard\smoke-daemon.bat" >nul' || { echo "FAIL: could not create the daemon task"; exit 1; }
run_ssh 'schtasks /run /tn BaluardSmokeDaemon >nul' || { echo "FAIL: could not run the daemon task"; exit 1; }
sleep 3
BAT='%LOCALAPPDATA%\baluard\smoke-launch.bat'
run_ssh "(echo @echo off & echo set BALUARD_DISABLE_KEYRING=1 & echo start \"\" \"$EXE\") > \"$BAT\""
run_ssh 'schtasks /create /f /tn BaluardSmoke /sc once /st 00:00 /tr "%LOCALAPPDATA%\baluard\smoke-launch.bat" >nul' || { echo "FAIL: could not create the launch task"; exit 1; }
run_ssh 'schtasks /run /tn BaluardSmoke >nul' || { echo "FAIL: could not run the launch task (is the guest logged on?)"; exit 1; }

echo "== Waiting for CDP"
READY=0
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$CDP/json/version" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == "1" ]] || { echo "FAIL: CDP never answered on $CDP (is this the SMOKE build? plain installs have no debug port)"; exit 1; }

echo "== Running the DOM smoke"
(cd "$HERE" && [[ -d node_modules/playwright ]] || { echo "== Installing playwright"; PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install; })
BALUARD_SMOKE_CDP="$CDP" BALUARD_SMOKE_PW="$PW" BALUARD_SMOKE_ARTIFACTS="$ARTIFACTS" \
  node "$HERE/smoke.mjs"

echo "== Artifacts: $ARTIFACTS"
ls -la "$ARTIFACTS"
echo "WINDOWS SMOKE PASS"
