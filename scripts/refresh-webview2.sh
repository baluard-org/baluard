#!/usr/bin/env bash
# Refresh the portable build's WebView2 Fixed Version pin
# (scripts/windows-portable/webview2.sha256). The build leg hard-fails when
# the downloaded cab is not the pinned file, so the pin must be updated
# deliberately: this script downloads the newest stable fixed runtime,
# prints its sha256 for review, and rewrites the pin. The hash itself is
# the trust anchor - review the version bump before committing it.
#
# usage: refresh-webview2.sh [--check]
#   --check: print pinned vs newest available, exit 0 either way.
# BALUARD_WV2_PAGE overrides the downloads-page fetch (test seam).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIN="$ROOT/scripts/windows-portable/webview2.sha256"
WV2_CACHE="$ROOT/target/wv2-fixed"
mkdir -p "$WV2_CACHE"
PAGE_FILE="$WV2_CACHE/page.html"

CHECK_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=true ;;
    *) echo "unknown flag $arg" >&2; exit 1 ;;
  esac
done

if [[ -n "${BALUARD_WV2_PAGE:-}" ]]; then
  cp "$BALUARD_WV2_PAGE" "$PAGE_FILE"
else
  curl -fsSL --max-time 60 https://developer.microsoft.com/en-us/microsoft-edge/webview2/ -o "$PAGE_FILE"
fi

CAB_URL="$(python3 "$ROOT/scripts/lib/wv2_cab_url.py" "$PAGE_FILE")"
[[ -n "$CAB_URL" ]] || { echo "no WebView2 Fixed Version x64 cab URL found on the downloads page" >&2; exit 1; }
CAB_NAME="$(basename "${CAB_URL%%\?*}")"
NEW_VERSION="$(sed -E 's/.*FixedVersionRuntime\.([0-9.]+)\.x64\.cab/\1/' <<<"$CAB_NAME")"
PINNED_VERSION="$(sed -E 's/.*FixedVersionRuntime\.([0-9.]+)\.x64\.cab/\1/' "$PIN" 2>/dev/null | tr -d '\r' || true)"
PINNED_HASH="$(awk '{print $1}' "$PIN" 2>/dev/null || true)"

echo "pinned: $PINNED_VERSION"
echo "available: $NEW_VERSION"

if $CHECK_ONLY; then
  if [[ "$PINNED_VERSION" == "$NEW_VERSION" ]]; then
    echo "verdict: current"
  else
    echo "verdict: refresh available (run $0 without --check)"
  fi
  exit 0
fi

if [[ "$PINNED_VERSION" == "$NEW_VERSION" ]]; then
  CAB="$WV2_CACHE/$CAB_NAME"
  if [[ -f "$CAB" ]] && [[ "$(sha256sum "$CAB" | awk '{print $1}')" == "$PINNED_HASH" ]]; then
    echo "pin is already current ($PINNED_VERSION); cached cab verifies"
    exit 0
  fi
  echo "pin says $PINNED_VERSION but the cached cab is missing or does not verify; re-downloading"
  # The corrupt cache would otherwise be hashed as-is below and its hash
  # written into the pin -- the trust anchor must only ever hold a hash of
  # freshly downloaded bytes.
  rm -f "$CAB" "$CAB.part"
fi

CAB="$WV2_CACHE/$CAB_NAME"
[[ -f "$CAB" ]] || {
  echo "Downloading $CAB_NAME..."
  curl -fsSL --max-time 900 -o "$CAB.part" "$CAB_URL" && mv "$CAB.part" "$CAB"
}
[[ -s "$CAB" ]] || { echo "downloaded cab is empty" >&2; exit 1; }

HASH="$(sha256sum "$CAB" | awk '{print $1}')"
if [[ "$NEW_VERSION" == "$PINNED_VERSION" ]]; then
  if [[ "$HASH" == "$PINNED_HASH" ]]; then
    echo "pin is current ($NEW_VERSION); freshly downloaded cab verifies"
    exit 0
  fi
  echo "refusing to rewrite the pin: version $NEW_VERSION matches the pin but the bytes differ; review the page manually" >&2
  exit 1
fi
if [[ "$HASH" == "$PINNED_HASH" ]]; then
  echo "downloaded cab matches the current pin's hash but the version moved; refusing to guess" >&2
  exit 1
fi

PIN_TMP="$(mktemp "$PIN.tmp.XXXXXX")"
printf '%s  %s\n' "$HASH" "$CAB_NAME" > "$PIN_TMP"
mv "$PIN_TMP" "$PIN"

echo "pin updated:"
cat "$PIN"
echo "review the version bump and hash, then commit $PIN and rerun the portable build."
