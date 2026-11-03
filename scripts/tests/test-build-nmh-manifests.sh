#!/usr/bin/env bash
# Hermetic test for scripts/build-nmh-manifests.sh. No cargo, no npm, no
# browser, no root: the script only writes JSON derived from env vars, so the
# test drives it in a temp dir and asserts the manifest contents.
set -euo pipefail

# Host env must not leak into the cases below.
unset BALUARD_CHROME_EXTENSION_ID BALUARD_FIREFOX_EXTENSION_ID || true

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SCRIPT="$TMP/repo/scripts/build-nmh-manifests.sh"
mkdir -p "$TMP/repo/scripts"
cp "$ROOT/scripts/build-nmh-manifests.sh" "$SCRIPT"
# The script resolves its output dir relative to its own location.
chmod +x "$SCRIPT"

MAN="$TMP/repo/desktop/src-tauri/nmh-manifests"
CHROME_ID="abcdefghijklmnopabcdefghijklmnop"
FF_ID="baluard@actitud.xyz"

# ── Happy path: chrome id from env, firefox default ──────────────────────────
BALUARD_CHROME_EXTENSION_ID="$CHROME_ID" "$SCRIPT" > "$TMP/happy.out" 2> "$TMP/happy.err"

for f in firefox chrome chromium edge; do
  [[ -f "$MAN/$f.json" ]] || { echo "missing manifest: $f.json" >&2; exit 1; }
  [[ -f "$MAN/$f-legacy.json" ]] || { echo "missing legacy manifest: $f-legacy.json" >&2; exit 1; }
done

# New-name manifests pair with future bundles; legacy ones keep the
# pre-rename name so in-review 0.1.0 store bundles still connect.
for f in firefox chrome chromium edge; do
  jq -er '.path == "/usr/bin/baluard-nmh" and .type == "stdio" and .name == "app.baluard.browser"' \
    "$MAN/$f.json" > /dev/null || { echo "$f.json: bad path/type/name" >&2; exit 1; }
  jq -er '.path == "/usr/bin/baluard-nmh" and .type == "stdio" and .name == "xyz.actitud.baluard"' \
    "$MAN/$f-legacy.json" > /dev/null || { echo "$f-legacy.json: bad path/type/name" >&2; exit 1; }
done

# Firefox authorizes the AMO id; chrome-family authorizes the store id.
jq -er --arg id "$FF_ID" '.allowed_extensions == [$id]' "$MAN/firefox.json" > /dev/null \
  || { echo "firefox.json: wrong allowed_extensions" >&2; exit 1; }
jq -er --arg id "$FF_ID" '.allowed_extensions == [$id]' "$MAN/firefox-legacy.json" > /dev/null \
  || { echo "firefox-legacy.json: wrong allowed_extensions" >&2; exit 1; }
for f in chrome chromium edge; do
  jq -er --arg origin "chrome-extension://$CHROME_ID/" '.allowed_origins == [$origin]' \
    "$MAN/$f.json" > /dev/null || { echo "$f.json: wrong allowed_origins" >&2; exit 1; }
done

# ── Unset chrome id: placeholder origin + loud warning, firefox still right ──
rm -rf "$MAN"
"$SCRIPT" > "$TMP/unset.out" 2> "$TMP/unset.err" || { echo "unset-id run failed" >&2; exit 1; }
if ! grep -qi "chrome" "$TMP/unset.err"; then
  echo "unset chrome id must warn on stderr" >&2
  exit 1
fi
jq -er --arg id "$FF_ID" '.allowed_extensions == [$id]' "$MAN/firefox.json" > /dev/null \
  || { echo "firefox.json: wrong allowed_extensions (unset run)" >&2; exit 1; }
jq -er '.allowed_origins[0] | test("chrome-extension://")' "$MAN/chrome.json" > /dev/null \
  || { echo "chrome.json: placeholder origin missing" >&2; exit 1; }

# ── Invalid chrome id fails loudly ────────────────────────────────────────────
rm -rf "$MAN"
if BALUARD_CHROME_EXTENSION_ID="UPPERCASE-not-an-id" "$SCRIPT" > "$TMP/bad.out" 2> "$TMP/bad.err"; then
  echo "invalid chrome id must fail the run" >&2
  exit 1
fi
if ! grep -qi "chrome" "$TMP/bad.err"; then
  echo "invalid chrome id must explain on stderr" >&2
  exit 1
fi
[[ ! -e "$MAN/chrome.json" ]] || { echo "invalid id wrote a manifest" >&2; exit 1; }

# ── Firefox id override ───────────────────────────────────────────────────────
rm -rf "$MAN"
BALUARD_CHROME_EXTENSION_ID="$CHROME_ID" BALUARD_FIREFOX_EXTENSION_ID="custom@example.org" \
  "$SCRIPT" > "$TMP/override.out" 2> "$TMP/override.err"
jq -er '.allowed_extensions == ["custom@example.org"]' "$MAN/firefox.json" > /dev/null \
  || { echo "firefox.json: id override ignored" >&2; exit 1; }

echo "PASS: build-nmh-manifests.sh"
