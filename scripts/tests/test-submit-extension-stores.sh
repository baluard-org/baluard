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

# CRX signing shim: honors the real crx3 flag surface (-p key, -o out, zip
# bytes on stdin) so assertions check the script's actual argv usage.
CRX_LOG="$TMP/crx3.log"
cat > "$TMP/bin/crx3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SUB_TEST_CRX_LOG:?}"
key=""; out=""
while (($#)); do
  case "$1" in
    -p) key="$2"; shift 2 ;;
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -z "$key" || -z "$out" ]]; then echo "crx3 shim: missing -p/-o" >&2; exit 64; fi
cat > /dev/null
printf 'Cr24FAKE\n' > "$out"
if [[ "${SUB_TEST_CRX_FAIL:-0}" == 1 ]]; then exit 1; fi
exit 0
EOF
chmod +x "$TMP/bin/crx3"
export SUB_TEST_CRX_LOG="$CRX_LOG"
# The machine may carry a real signing key at the script's default path; the
# default runs must never see it. CRX cases override per invocation.
export BALUARD_CHROME_CRX_KEY="$TMP/absent-signing-key"

# The invoking shell may carry real store credentials (they live in the
# interactive environment since the real keys were set up); every invocation
# must start from a scrubbed slate or the skip cases silently submit instead.
UNSET=(BALUARD_AMO_JWT_KEY BALUARD_AMO_JWT_SECRET AMO_METADATA AMO_UPLOAD_SOURCE
  BALUARD_CHROME_CLIENT_ID BALUARD_CHROME_CLIENT_SECRET BALUARD_CHROME_REFRESH_TOKEN
  BALUARD_CHROME_EXTENSION_ID BALUARD_CHROME_PUBLISHER_ID)

AMO_ENV=(BALUARD_AMO_JWT_KEY=user:123 BALUARD_AMO_JWT_SECRET=amo-secret)
CHROME_ENV=(BALUARD_CHROME_CLIENT_ID=cid BALUARD_CHROME_CLIENT_SECRET=chrome-secret
  BALUARD_CHROME_REFRESH_TOKEN=chrome-refresh BALUARD_CHROME_EXTENSION_ID=extid
  BALUARD_CHROME_PUBLISHER_ID=pubid)

# Always invoke the sandbox script by path: env is an external command and
# cannot run a bash function.

# ── Happy path: both stores submit ───────────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/happy.out"
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
env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  AMO_METADATA="$TMP/meta.json" AMO_UPLOAD_SOURCE="$TMP/source.zip" \
  "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > /dev/null
grep -q -- "--amo-metadata $TMP/meta.json" "$NPX_LOG"
grep -q -- "--upload-source-code $TMP/source.zip" "$NPX_LOG"

# ── Firefox only: chrome skipped cleanly ─────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/ff-only.out"
grep -q 'firefox/AMO: submitted' "$TMP/ff-only.out"
grep -q 'chrome/store: skipped' "$TMP/ff-only.out"
if [[ -s "$CURL_LOG" ]]; then echo "curl shim was invoked unexpectedly" >&2; exit 1; fi

# ── Partial store credentials are an error, not a skip ─────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${UNSET[@]/#/-u}" BALUARD_AMO_JWT_KEY=only-one "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/partial.out" 2> "$TMP/partial.err"; then
  echo 'expected partial AMO credentials to fail the run' >&2
  exit 1
fi
grep -q 'BALUARD_AMO_JWT_KEY and BALUARD_AMO_JWT_SECRET must be set together' "$TMP/partial.err"
grep -q 'chrome/store: uploaded and submitted' "$TMP/partial.out"
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── Chrome only: firefox skipped cleanly ─────────────────────────────────────
rm -f "$CURL_LOG" "$NPX_LOG"
env "${UNSET[@]/#/-u}" "${CHROME_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/ch-only.out"
grep -q 'chrome/store: uploaded and submitted' "$TMP/ch-only.out"
grep -q 'firefox/AMO: skipped' "$TMP/ch-only.out"
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── AMO submission failure fails the run; chrome still submits ─────────────
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
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
if env "${UNSET[@]/#/-u}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > /dev/null 2> "$TMP/none.err"; then
  echo 'expected unconfigured stores to fail the run' >&2
  exit 1
fi
grep -qi 'BALUARD_AMO_JWT_KEY' "$TMP/none.err"
grep -qi 'BALUARD_CHROME_CLIENT_ID' "$TMP/none.err"
if [[ -s "$CURL_LOG" ]]; then echo "curl shim was invoked unexpectedly" >&2; exit 1; fi
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── Version guard: dist moved past the newest packaged zip ───────────────────
make_zip chrome 0.1.1
rm -f "$CURL_LOG" "$NPX_LOG"
env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" 2> "$TMP/mismatch.err" \
  && { echo 'expected stale dist to refuse submission' >&2; exit 1; }
grep -qi 'ext-package' "$TMP/mismatch.err"
if [[ -s "$CURL_LOG" ]]; then echo "curl shim was invoked unexpectedly" >&2; exit 1; fi
if [[ -s "$NPX_LOG" ]]; then echo "npx shim was invoked unexpectedly" >&2; exit 1; fi

# ── Chrome upload failure fails the run, firefox still submits ──────────────
rm -f "$ART/baluard-extension-0.1.1-chrome.zip"
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
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
env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  SUB_TEST_UPLOAD_STATE=SUCCEEDED "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > /dev/null

# ── Chrome branch honors uploadState rejection (HTTP 200, FAILURE body) ─────
# The knob rewires the shim's :upload response to a success exit with a
# FAILURE uploadState, the other way a store can silently reject a package.
rm -f "$CURL_LOG" "$NPX_LOG"
if env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  SUB_TEST_UPLOAD_STATE=FAILURE "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" \
  > "$TMP/state.out" 2> "$TMP/state.err"; then
  echo 'expected FAILURE uploadState to fail the run' >&2
  exit 1
fi
grep -qi 'upload rejected' "$TMP/state.err"
grep -q 'firefox/AMO: submitted' "$TMP/state.out"

# ── CRX signing: key present packages and uploads the signed CRX ──────────────
printf 'test-key-material\n' > "$TMP/crx.key"
rm -f "$CURL_LOG" "$CRX_LOG"
env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  BALUARD_CHROME_CRX_KEY="$TMP/crx.key" \
  "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" > "$TMP/crx.out"
grep -q -- "-p $TMP/crx.key" "$CRX_LOG"
grep -qE -- '-o [^ ]+baluard-extension-0.1.0-chrome\.crx' "$CRX_LOG"
grep -qE -- '-T [^ ]+baluard-extension-0.1.0-chrome\.crx' "$CURL_LOG"
if grep -q -- "-T $ART/baluard-extension-0.1.0-chrome.zip" "$CURL_LOG"; then
  echo 'unsigned zip was uploaded despite the signing key' >&2
  exit 1
fi
grep -q 'chrome/store: uploaded and submitted' "$TMP/crx.out"

# ── CRX tool failure fails the run before any store contact ──────────────────
rm -f "$CURL_LOG" "$CRX_LOG"
if env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  BALUARD_CHROME_CRX_KEY="$TMP/crx.key" SUB_TEST_CRX_FAIL=1 \
  "$SANDBOX/scripts/submit-extension-stores.sh" "$ART" \
  > /dev/null 2> "$TMP/crxfail.err"; then
  echo 'expected CRX packaging failure to fail the run' >&2
  exit 1
fi
grep -q 'CRX packaging failed' "$TMP/crxfail.err"
if [[ -s "$CURL_LOG" ]]; then echo "store contacted despite CRX failure" >&2; exit 1; fi

printf 'PASS: submit-extension-stores.sh\n'
