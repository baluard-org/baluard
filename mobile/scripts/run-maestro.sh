#!/usr/bin/env bash
#
# run-maestro.sh — Android E2E flows (docs/e2e-testing.md Phase 2).
#
# Usage:
#   ./scripts/run-maestro.sh [--pin-locale] [--flow <name.yaml>] [device-serial]
#
# Env:
#   BALUARD_E2E_MASTER_PW   required — the synthetic vault password
#   ANDROID_SERIAL          device serial (or pass as the first arg)
#
# The build is an E2E build (FLAG_SECURE skipped so Maestro can
# screenshot): mobile/scripts/build-android-apk.sh --e2e --install
#
# Emulator (CI): build with x86_64 too, the default alpha APK carries
# arm64-v8a only — build-android-apk.sh needs -Pbaluard.abis support or
# a direct gradle run with -Pbaluard.abis=arm64-v8a,x86_64 -Pbaluard.e2e=true.
# NEVER aim this at a device holding real vaults: flow 01 wipes all
# app data (Maestro clearState). Use a dedicated device or emulator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FLOW_DIR="$REPO_ROOT/e2e/mobile"

PIN_LOCALE=0
SERIAL="${ANDROID_SERIAL:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pin-locale) PIN_LOCALE=1; shift ;;
    --flow) ONLY_FLOW="$2"; shift 2 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) SERIAL="$1"; shift ;;
  esac
done

# Opt out of Maestro's anonymous analytics (mobile.dev telemetry).
export MAESTRO_CLI_NO_ANALYTICS=1
command -v maestro >/dev/null 2>&1 || {
  echo "ERROR: Maestro CLI missing. Install it (one-time):" >&2
  echo '  curl -Ls "https://get.maestro.mobile.dev" | bash' >&2
  exit 1
}
ADB="$(command -v adb || true)"
[[ -n "$ADB" ]] || { echo "ERROR: adb missing (android-platform-tools)" >&2; exit 1; }

# The arg parser above may already have lifted a positional serial into
# SERIAL (and shifted it away), so fall through to it before $1.
SERIAL="${ANDROID_SERIAL:-${SERIAL:-${1:-}}}"
if [[ -n "$SERIAL" ]]; then
  ADBS=("$ADB" -s "$SERIAL")
else
  mapfile -t DEVS < <("$ADB" devices | awk '$2=="device"{print $1}')
  if [[ ${#DEVS[@]} -ne 1 ]]; then
    printf 'attached: %s\n' "${DEVS[*]:-none}" >&2
    echo "ERROR: pass the device serial or attach exactly one device" >&2
    exit 1
  fi
  SERIAL="${DEVS[0]}"
  ADBS=("$ADB" -s "$SERIAL")
fi
# Maestro does not honor ANDROID_SERIAL: hand it the resolved serial via
# --udid so a multi-device host runs against the chosen one.
export ANDROID_SERIAL="$SERIAL"
MAESTRO_DEVICE="--udid=$SERIAL"
echo "==> device: ${ADBS[*]}"

# A device mid-boot refuses installs and launches; wait it out.
BOOTED="$("${ADBS[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
WAITED=0
while [[ "$BOOTED" != "1" ]]; do
  WAITED=$((WAITED + 5))
  [[ $WAITED -ge 120 ]] && { echo "ERROR: device not booted after 120s" >&2; exit 1; }
  sleep 5
  BOOTED="$("${ADBS[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
done

# Text selectors track the device locale; the flows pin en-US when asked.
if [[ $PIN_LOCALE -eq 1 ]]; then
  echo "==> pinning locale en-US"
  "${ADBS[@]}" shell settings put system system_locales en-US
fi

: "${BALUARD_E2E_MASTER_PW:?set BALUARD_E2E_MASTER_PW for the synthetic vault}"

# Only the named flow runs when --flow is given (the two-phone harness
# drives its own flow); otherwise every flow runs in name order.
rc=0
for f in "$FLOW_DIR"/*.yaml; do
  if [[ -n "$ONLY_FLOW" && "$(basename "$f")" != "$ONLY_FLOW" ]]; then
    continue
  fi
  echo
  echo "==> maestro test $(basename "$f")"
  # MASTER_PW keeps its short name for the original flows; every
  # BALUARD_E2E_* variable is also forwarded UNSTRIPPED so newer flows
  # can reference the full names (the two-phone journey passes invite
  # code, PAT, and repo name through).
  args=(test -e MASTER_PW="$BALUARD_E2E_MASTER_PW" -e BALUARD_E2E_MASTER_PW="$BALUARD_E2E_MASTER_PW")
  while read -r k; do
    args+=(-e "${k}=${!k}")
  done < <(compgen -e | grep '^BALUARD_E2E_' | grep -v 'BALUARD_E2E_MASTER_PW$')
  # Maestro's DADB opens the USB device nodes directly; a running adb
  # server holds those interfaces and the driver dies at its first RPC
  # (DeviceServerDied at deviceInfo). Drop the server for the duration —
  # maestro needs no server, and the next plain adb client restarts it.
  adb kill-server > /dev/null 2>&1 || true
  # An orphaned maestro from a killed run holds the same USB interface;
  # a new driver start then dies identically. Clear stale launchers first.
  for p in $(pgrep -f "bin/maestro" 2>/dev/null); do
    [ "$p" != "$$" ] && kill "$p" 2>/dev/null
  done
  sleep 1
  adb kill-server > /dev/null 2>&1 || true
  maestro "${args[@]}" "$MAESTRO_DEVICE" "$f" || rc=1
done
exit "$rc"
