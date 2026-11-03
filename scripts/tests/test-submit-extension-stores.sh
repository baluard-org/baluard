#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Run the submit script against a sandbox copy of the repository so the real
# worktree, its zips, and the network are never touched.
SANDBOX="$TMP/repo"
ART="$TMP/staging"
mkdir -p "$SANDBOX/scripts" "$ART" "$TMP/bin"
cp "$ROOT/scripts/submit-extension-stores.sh" "$SANDBOX/scripts/"

write_dist() {
  local store="$1" version="$2"
  local dir="$SANDBOX/browser/$store/dist"
  mkdir -p "$dir"
  printf 'background\n' > "$dir/background.js"
  printf '{"manifest_version": 3, "name": "Baluard", "version": "%s"}\n' "$version" > "$dir/manifest.json"
}

make_zip() {
  local store="$1" version="$2"
  (cd "$SANDBOX/browser/$store/dist" && zip -q -r "$ART/baluard-extension-$version-$store.zip" .)
}

write_dist chrome 0.1.0
write_dist firefox 0.1.0
make_zip chrome 0.1.0
make_zip firefox 0.1.0

# Fake curl: records argv, answers the three Chrome Web Store API calls the
# script makes, and never sees real secrets (they ride 0600 files).
CURL_LOG="$TMP/curl.log"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SUB_TEST_CURL_LOG:?}"
for arg in "$@"; do
  case "$arg" in
    *oauth2.googleapis.com/token*)
      printf '{"access_token": "test-token", "expires_in": 3600}\n'
      exit 0 ;;
    *:upload)
      if [[ -n "${SUB_TEST_UPLOAD_STATE:-}" ]]; then
        printf '{"uploadState": "%s"}\n' "$SUB_TEST_UPLOAD_STATE"
        exit "${SUB_TEST_UPLOAD_CODE:-0}"
      fi
      printf '{"uploadState": "SUCCESS"}\n'
      exit 0 ;;
    *:publish)
      printf '{"status": ["OK"]}\n'
      exit 0 ;;
  esac
done
echo "unexpected curl invocation: $*" >&2
exit 64
EOF

# Fake npx: records argv for the pinned web-ext sign call. The test body
# asserts the flags; the shim only records and honors the failure knob.
NPX_LOG="$TMP/npx.log"
cat > "$TMP/bin/npx" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SUB_TEST_NPX_LOG:?}"
[[ "${SUB_TEST_AMO_FAIL:-0}" == 1 ]] && exit 1
exit 0
EOF
chmod +x "$TMP/bin/curl" "$TMP/bin/npx"
export PATH="$TMP/bin:$PATH"
export SUB_TEST_CURL_LOG="$CURL_LOG" SUB_TEST_NPX_LOG="$NPX_LOG"

AMO_ENV=(AMO_JWT_KEY=user:123 AMO_JWT_SECRET=amo-secret)
CHROME_ENV=(CHROME_CLIENT_ID=cid CHROME_CLIENT_SECRET=chrome-secret
  CHROME_REFRESH_TOKEN=chrome-refresh CHROME_EXTENSION_ID=extid
  CHROME_PUBLISHER_ID=pubid)

# Always invoke the sandbox script by path: env is an external command and
# cannot run a bash function.

# ── Happy path: both stores submit ───────────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/happy.out"
grep -q 'firefox/AMO: submitted' "$TMP/happy.out"
grep -q 'chrome/store: uploaded and submitted' "$TMP/happy.out"

grep -q 'web-ext@10.8.0' "$NPX_LOG"
for flag in sign '--channel listed' '--approval-timeout 0' '--no-input' \
  "$SANDBOX/browser/firefox/dist" '--artifacts-dir'; do
  grep -q -- "$flag" "$NPX_LOG"
done
if grep -q -- '--amo-metadata' "$NPX_LOG"; then echo 'metadata flag leaked into default run' >&2; exit 1; fi
if grep -q -- '--upload-source-code' "$NPX_LOG"; then echo 'source flag leaked into default run' >&2; exit 1; fi

test "$(wc -l < "$CURL_LOG")" = 3
grep -q 'oauth2.googleapis.com/token' "$CURL_LOG"
grep -q 'publishers/pubid/items/extid:upload' "$CURL_LOG"
grep -q -- "-T $ART/baluard-extension-0.1.0-chrome.zip" "$CURL_LOG"
grep -q -- "--data-urlencode" "$CURL_LOG"
grep -q 'publishers/pubid/items/extid:publish' "$CURL_LOG"
# Secrets and the access token ride 0600 files, never argv.
if grep -q 'amo-secret' "$NPX_LOG"; then echo 'AMO secret hit argv' >&2; exit 1; fi
if grep -q 'chrome-secret' "$CURL_LOG"; then echo 'chrome secret hit argv' >&2; exit 1; fi
if grep -q 'chrome-refresh' "$CURL_LOG"; then echo 'refresh token hit argv' >&2; exit 1; fi
if grep -q 'test-token' "$CURL_LOG"; then echo 'access token hit argv' >&2; exit 1; fi

# ── Optional AMO knobs ride through ──────────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  AMO_METADATA="$TMP/meta.json" AMO_UPLOAD_SOURCE="$TMP/source.zip" \
  "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > /dev/null
grep -q -- "--amo-metadata $TMP/meta.json" "$NPX_LOG"
grep -q -- "--upload-source-code $TMP/source.zip" "$NPX_LOG"

# ── Firefox only: chrome skipped cleanly ─────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${AMO_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/ff-only.out"
grep -q 'firefox/AMO: submitted' "$TMP/ff-only.out"
grep -q 'chrome/store: skipped' "$TMP/ff-only.out"
if [[ -s "$CURL_LOG" ]]; then echo "curl shim was invoked unexpectedly" >&2; exit 1; fi

# ── Partial store credentials are an error, not a skip ─────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
if env AMO_JWT_KEY=only-one "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/partial.out" 2> "$TMP/partial.err"; then
  echo 'expected partial AMO credentials to fail the run' >&2
  exit 1
fi
grep -q 'AMO_JWT_KEY and AMO_JWT_SECRET must be set together' "$TMP/partial.err"
grep -q 'chrome/store: uploaded and submitted' "$TMP/partial.out"
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── Chrome only: firefox skipped cleanly ─────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${CHROME_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/ch-only.out"
grep -q 'chrome/store: uploaded and submitted' "$TMP/ch-only.out"
grep -q 'firefox/AMO: skipped' "$TMP/ch-only.out"
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── AMO submission failure fails the run; chrome still submits ─────────────
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  SUB_TEST_AMO_FAIL=1 "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" \
  > "$TMP/amofail.out" 2> "$TMP/amofail.err"; then
  echo 'expected failed AMO submission to fail the run' >&2
  exit 1
fi
# The chrome store is independent and still submits; only the run must fail.
grep -q 'chrome/store: uploaded and submitted' "$TMP/amofail.out"
grep -q ':upload' "$CURL_LOG"

# ── Nothing configured: loud guidance, no submissions ────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
if "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > /dev/null 2> "$TMP/none.err"; then
  echo 'expected unconfigured stores to fail the run' >&2
  exit 1
fi
grep -qi 'AMO_JWT_KEY' "$TMP/none.err"
grep -qi 'CHROME_CLIENT_ID' "$TMP/none.err"
if [[ -s "$CURL_LOG" ]]; then echo "curl shim was invoked unexpectedly" >&2; exit 1; fi
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── Version guard: dist moved past the newest packaged zip ───────────────────
make_zip chrome 0.1.1
rm -f "$CURL_LOG" "$NPX_LOG"
env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" 2> "$TMP/mismatch.err" \
  && { echo 'expected stale dist to refuse submission' >&2; exit 1; }
grep -qi 'ext-package' "$TMP/mismatch.err"
if [[ -s "$CURL_LOG" ]]; then echo "curl shim was invoked unexpectedly" >&2; exit 1; fi
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── Chrome upload failure fails the run, firefox still submits ──────────────
rm -f "$ART/baluard-extension-0.1.1-chrome.zip"
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  SUB_TEST_UPLOAD_STATE=FAILURE SUB_TEST_UPLOAD_CODE=22 "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" \
  > "$TMP/upfail.out" 2> "$TMP/upfail.err"; then
  echo 'expected failed chrome upload to fail the run' >&2
  exit 1
fi
grep -q 'chrome/store: upload failed' "$TMP/upfail.err"
grep -q 'firefox/AMO: submitted' "$TMP/upfail.out"

# ── Chrome branch accepts the v2 alternate success state ────────────────────
# The API can spell the good upload state as SUCCEEDED instead of SUCCESS;
# only its absence must fail the run.
rm -f "$CURL_LOG" "$NPX_LOG"
env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  SUB_TEST_UPLOAD_STATE=SUCCEEDED "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > /dev/null

# ── Chrome branch honors uploadState rejection (HTTP 200, FAILURE body) ─────
# The knob rewires the shim's :upload response to a success exit with a
# FAILURE uploadState, the other way a store can silently reject a package.
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  SUB_TEST_UPLOAD_STATE=FAILURE "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" \
  > "$TMP/state.out" 2> "$TMP/state.err"; then
  echo 'expected FAILURE uploadState to fail the run' >&2
  exit 1
fi
grep -qi 'upload rejected' "$TMP/state.err"
grep -q 'firefox/AMO: submitted' "$TMP/state.out"

printf 'PASS: submit-extension-stores.sh\n'
