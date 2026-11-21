#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic verdict checks: a fake curl answers the AMO versions API and the
# Chrome token + v2 fetchStatus endpoints from fixtures shaped like the real
# APIs (AMO file.status enum: public/unreviewed/disabled/rejected; Chrome
# ItemState enum: PENDING_REVIEW/STAGED/PUBLISHED/...), so the real stores
# and credentials are never touched.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$TMP/bin"
cp "$ROOT/scripts/extension-verdicts.sh" "$SANDBOX/scripts/"

CURL_LOG="$TMP/curl.log"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SUB_TEST_CURL_LOG:?}"
for arg in "$@"; do
  case "$arg" in
    *addons.mozilla.org*)
      if [[ "${SUB_TEST_AMO_STATUS:-public}" == "unreachable" ]]; then exit 7; fi
      # Two results, oldest id first: the verdict must pick the newest by id.
      printf '{"results":[{"id":10,"version":"0.7.9","file":{"status":"public"}},{"id":11,"version":"0.8.0","file":{"status":"%s"}}]}' "${SUB_TEST_AMO_STATUS:-public}"
      exit 0 ;;
    *oauth2.googleapis.com/token*)
      printf '{"access_token": "test-token", "expires_in": 3600}\n'
      exit 0 ;;
    *chromewebstore.googleapis.com*v2*publishers*fetchStatus*)
      if [[ "${SUB_TEST_CHROME_STATUS:-PUBLISHED}" == "unreachable" ]]; then exit 7; fi
      printf '{"submittedItemRevisionStatus": {"state": "%s"}}\n' "${SUB_TEST_CHROME_STATUS:-PUBLISHED}"
      exit 0 ;;
  esac
done
echo "unexpected curl invocation: $*" >&2
exit 64
EOF
chmod +x "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH" SUB_TEST_CURL_LOG="$CURL_LOG"

UNSET=(BALUARD_AMO_JWT_KEY BALUARD_AMO_JWT_SECRET BALUARD_AMO_ADDON_ID
  BALUARD_CHROME_CLIENT_ID BALUARD_CHROME_CLIENT_SECRET
  BALUARD_CHROME_REFRESH_TOKEN BALUARD_CHROME_EXTENSION_ID
  BALUARD_CHROME_PUBLISHER_ID)
AMO_ENV=(BALUARD_AMO_JWT_KEY=user:123 BALUARD_AMO_JWT_SECRET=amo-secret)
CHROME_ENV=(BALUARD_CHROME_CLIENT_ID=cid BALUARD_CHROME_CLIENT_SECRET=chr-secret
  BALUARD_CHROME_REFRESH_TOKEN=chr-refresh BALUARD_CHROME_EXTENSION_ID=extid
  BALUARD_CHROME_PUBLISHER_ID=pub-83ac1e)

# ── Nothing configured: both stores report as unconfigured, exit 0 ──────────
out="$(env "${UNSET[@]/#/-u}" "$SANDBOX/scripts/extension-verdicts.sh")"
grep -q 'amo: not configured' <<<"$out"
grep -q 'chrome: not configured' <<<"$out"

# ── Chrome partially configured: the set must be complete ───────────────────
if env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" BALUARD_CHROME_CLIENT_ID=cid \
  "$SANDBOX/scripts/extension-verdicts.sh" > "$TMP/part.out" 2>&1; then
  echo 'expected partially configured chrome to fail' >&2
  exit 1
fi
grep -q 'set all of' "$TMP/part.out"

# ── AMO report mode: newest-by-id version and status surface ───────────────
rm -f "$CURL_LOG"
out="$(env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "$SANDBOX/scripts/extension-verdicts.sh")"
grep -q 'amo: 0.8.0 public' <<<"$out"
if grep -q 'amo-secret' "$CURL_LOG"; then echo 'amo secret hit argv' >&2; exit 1; fi
if grep -qE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$CURL_LOG"; then
  echo 'signed JWT hit argv' >&2
  exit 1
fi

# ── Guard passes when the store matches or is approved ─────────────────────
SUB_TEST_AMO_STATUS=public env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 >/dev/null

# ── Guard refuses a different in-review version (real enum: unreviewed) ────
if SUB_TEST_AMO_STATUS=unreviewed env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.9.0 > "$TMP/guard.out" 2>&1; then
  echo 'expected the guard to refuse stacking on an open review' >&2
  exit 1
fi
grep -q 'stack on an open review' "$TMP/guard.out"
# Same version in review = resubmitting the same entry; guard passes.
SUB_TEST_AMO_STATUS=unreviewed env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 >/dev/null

# ── Guard warns and passes through an AMO probe failure ────────────────────
SUB_TEST_AMO_STATUS=unreachable env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/net.out" 2>&1
grep -q 'probe failed' "$TMP/net.out"

# ── Chrome guard refuses a pending review (v2 ItemState) ───────────────────
if SUB_TEST_CHROME_STATUS=PENDING_REVIEW env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/cr.out" 2>&1; then
  echo 'expected the chrome guard to refuse a pending review' >&2
  exit 1
fi
grep -q 'chrome: the item is PENDING_REVIEW' "$TMP/cr.out"
SUB_TEST_CHROME_STATUS=PUBLISHED env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/cr-ok.out"
grep -q 'chrome: item PUBLISHED' "$TMP/cr-ok.out"
# STAGED is approved-awaiting-publish, not an open review; pass.
SUB_TEST_CHROME_STATUS=STAGED env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 >/dev/null

# ── Chrome probe failure warns through ─────────────────────────────────────
SUB_TEST_CHROME_STATUS=unreachable env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/cr-net.out" 2>&1
grep -q 'chrome: probe failed' "$TMP/cr-net.out"

echo "test-extension-verdicts: ok"
