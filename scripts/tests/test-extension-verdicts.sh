#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic verdict checks: a fake curl answers the AMO versions API and the
# Chrome token + item-status endpoints from fixtures, so the real stores
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
      printf '{"results":[{"version":"0.7.9","file":{"status":"%s"}}]}' "${SUB_TEST_AMO_STATUS:-public}"
      exit 0 ;;
    *oauth2.googleapis.com/token*)
      printf '{"access_token": "test-token", "expires_in": 3600}\n'
      exit 0 ;;
    *chromewebstore.googleapis.com*)
      printf '{"itemStatus": "%s"}\n' "${SUB_TEST_CHROME_STATUS:-APPROVED}"
      exit 0 ;;
    *www.googleapis.com*)
      printf '{"itemStatus": "%s"}\n' "${SUB_TEST_CHROME_STATUS:-APPROVED}"
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
  BALUARD_CHROME_REFRESH_TOKEN BALUARD_CHROME_EXTENSION_ID)
AMO_ENV=(BALUARD_AMO_JWT_KEY=user:123 BALUARD_AMO_JWT_SECRET=amo-secret)
CHROME_ENV=(BALUARD_CHROME_CLIENT_ID=cid BALUARD_CHROME_CLIENT_SECRET=chrome-secret
  BALUARD_CHROME_REFRESH_TOKEN=chrome-refresh BALUARD_CHROME_EXTENSION_ID=extid)

# ── Nothing configured: both stores report as unconfigured, exit 0 ──────────
out="$(env "${UNSET[@]/#/-u}" "$SANDBOX/scripts/extension-verdicts.sh")"
grep -q 'amo: not configured' <<<"$out"
grep -q 'chrome: not configured' <<<"$out"

# ── AMO report mode: newest version and status surface ─────────────────────
rm -f "$CURL_LOG"
out="$(env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "$SANDBOX/scripts/extension-verdicts.sh")"
grep -q 'amo: 0.7.9 public' <<<"$out"
# The HMAC secret must never ride argv (ps-visible): openssl/python read env.
if grep -q 'amo-secret' "$CURL_LOG"; then echo 'amo secret hit argv' >&2; exit 1; fi

# ── Guard passes when the store matches or is approved ─────────────────────
SUB_TEST_AMO_STATUS=public env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 >/dev/null

# ── Guard refuses a different in-review version ────────────────────────────
if SUB_TEST_AMO_STATUS=awaiting_review env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/guard.out" 2>&1; then
  echo 'expected the guard to refuse stacking on an open review' >&2
  exit 1
fi
grep -q 'stack on an open review' "$TMP/guard.out"
# Same version awaiting review = resubmitting the same entry; guard passes.
SUB_TEST_AMO_STATUS=awaiting_review env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.7.9 >/dev/null

# ── Guard warns and passes through an AMO probe failure ────────────────────
SUB_TEST_AMO_STATUS=unreachable env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/net.out" 2>&1
grep -q 'probe failed' "$TMP/net.out"

# ── Chrome guard refuses an in-review item ─────────────────────────────────
if SUB_TEST_CHROME_STATUS=IN_REVIEW env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/cr.out" 2>&1; then
  echo 'expected the chrome guard to refuse an in-review item' >&2
  exit 1
fi
grep -q 'chrome: the item is IN_REVIEW' "$TMP/cr.out"
SUB_TEST_CHROME_STATUS=APPROVED env "${UNSET[@]/#/-u}" "${AMO_ENV[@]}" "${CHROME_ENV[@]}" \
  "$SANDBOX/scripts/extension-verdicts.sh" --guard 0.8.0 > "$TMP/cr-ok.out"
grep -q 'chrome: item APPROVED' "$TMP/cr-ok.out"

echo "test-extension-verdicts: ok"
