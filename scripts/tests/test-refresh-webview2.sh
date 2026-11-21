#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic webview2-refresh checks: the downloads-page fetch is replaced by
# a fixture (BALUARD_WV2_PAGE), the cab download by a fake curl, and the
# sandbox copy of the script operates on a fixture pin file.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts/lib" "$SANDBOX/scripts/windows-portable" \
  "$SANDBOX/target/wv2-fixed" "$TMP/bin"
cp "$ROOT/scripts/refresh-webview2.sh" "$SANDBOX/scripts/"
cp "$ROOT/scripts/lib/wv2_cab_url.py" "$SANDBOX/scripts/lib/"

CURL_LOG="$TMP/curl.log"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${WV2_TEST_CURL_LOG:?}"
target=""
args=("$@")
for i in "${!args[@]}"; do
  [[ "${args[$i]}" == "-o" ]] && target="${args[$((i + 1))]}"
done
if [[ "$target" == *\.cab* ]]; then
  if [[ "${WV2_TEST_CAB_FAIL:-0}" == 1 ]]; then exit 22; fi
  cat "${WV2_TEST_CAB_FILE:?}" > "$target"
  exit 0
fi
if [[ "${WV2_TEST_PAGE_FAIL:-0}" == 1 ]]; then exit 22; fi
exit 0
EOF
chmod +x "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH" WV2_TEST_CURL_LOG="$CURL_LOG"
export WV2_TEST_CAB_FILE="$TMP/new.cab"

# Fixture page: three fixed-version cabs, the newest NOT first, with one
# \u002F-escaped URL like the real page embeds.
PAGE="$TMP/page.html"
cat > "$PAGE" <<'EOF'
{"data":[{"files":["https:\/\/msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/aaa/Microsoft.WebView2.FixedVersionRuntime.158.0.4370.33.x64.cab",
"https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/bbb/Microsoft.WebView2.FixedVersionRuntime.157.0.4100.11.x64.cab",
"https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/ccc/Microsoft.WebView2.FixedVersionRuntime.159.0.4501.9.x64.cab"]}]}
EOF

# Fixture cab with a known hash (content does not matter, only stability).
CAB_BODY="fake-cab-bytes"
printf '%s' "$CAB_BODY" > "$TMP/new.cab"
NEW_HASH="$(sha256sum "$TMP/new.cab" | awk '{print $1}')"
OLD_HASH="$(printf 'old-158-cab-bytes' | sha256sum | awk '{print $1}')"
printf '%s  Microsoft.WebView2.FixedVersionRuntime.158.0.4370.33.x64.cab\n' "$OLD_HASH" \
  > "$SANDBOX/scripts/windows-portable/webview2.sha256"

export BALUARD_WV2_PAGE="$PAGE"

# ── --check reports a refresh as available without touching the pin ────────
out="$("$SANDBOX/scripts/refresh-webview2.sh" --check)"
grep -q 'pinned: 158.0.4370.33' <<<"$out"
grep -q 'available: 159.0.4501.9' <<<"$out"
grep -q 'refresh available' <<<"$out"

# ── Default mode downloads the NEWEST cab and rewrites the pin ─────────────
"$SANDBOX/scripts/refresh-webview2.sh" > "$TMP/apply.out"
grep -q 'available: 159.0.4501.9' "$TMP/apply.out"
grep -q "pin updated" "$TMP/apply.out"
grep -q "$NEW_HASH  Microsoft.WebView2.FixedVersionRuntime.159.0.4501.9.x64.cab" \
  "$SANDBOX/scripts/windows-portable/webview2.sha256"
test "$(wc -l < "$SANDBOX/scripts/windows-portable/webview2.sha256")" -eq 1
grep -q 'files/ccc/' "$CURL_LOG"   # the newest GUID was fetched, not the first listed

# ── Already-current pin: --check verdict current, apply is a no-op ─────────
out="$("$SANDBOX/scripts/refresh-webview2.sh" --check)"
grep -q 'verdict: current' <<<"$out"
out="$("$SANDBOX/scripts/refresh-webview2.sh")"
grep -q 'pin is already current' <<<"$out"

# ── Same hash under a new name is refused (hostile page repointing) ────────
sed 's/159\.0\.4501\.9/160.0.4501.9/g' "$PAGE" > "$TMP/page2.html"
export BALUARD_WV2_PAGE="$TMP/page2.html"
sed -i 's/FixedVersionRuntime\.159\.0\.4501\.9\.x64\.cab/FixedVersionRuntime.160.0.4501.9.x64.cab/' \
  "$SANDBOX/scripts/windows-portable/webview2.sha256"
if "$SANDBOX/scripts/refresh-webview2.sh" > "$TMP/evil.out" 2>&1; then
  echo 'expected refusal when the new version carries the old hash' >&2
  exit 1
fi
grep -q 'refusing to guess' "$TMP/evil.out" || { echo "--- evil.out was:"; cat "$TMP/evil.out"; exit 1; }

# ── Missing cab URL in the page fails loudly ───────────────────────────────
printf '{"data":[]}' > "$TMP/empty.html"
BALUARD_WV2_PAGE="$TMP/empty.html" "$SANDBOX/scripts/refresh-webview2.sh" > "$TMP/none.out" 2>&1 \
  && { echo 'expected a failure with no cab URL on the page' >&2; exit 1; }
grep -q 'no WebView2 Fixed Version x64 cab URL' "$TMP/none.out"

echo "test-refresh-webview2: ok"
