#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --deep trust-chain checks: a real throwaway rsign keypair signs a fixture
# SHA256SUMS; a fake gh and curl serve the release; the suite proves the
# signature verification and the per-asset checksums both bite.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$TMP/bin"
cp "$ROOT/scripts/verify-release-live.sh" "$ROOT/scripts/release-common.sh" "$SANDBOX/scripts/"

ASSET="Baluard-amd64.deb"
printf 'asset-body-v1' > "$TMP/$ASSET"
ASSET_HASH="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
make_sums() { printf '%s  %s\n' "$ASSET_HASH" "$ASSET" > "$TMP/SHA256SUMS"; }
make_sums
rsign generate -W -p "$TMP/pub.key" -s "$TMP/sec.key" -c test < /dev/null > /dev/null 2>&1
rsign sign -W -s "$TMP/sec.key" -x "$TMP/sums.minisign.sig" "$TMP/SHA256SUMS" > /dev/null 2>&1
base64 -w0 "$TMP/sums.minisign.sig" > "$TMP/SHA256SUMS.sig"
# The script verifies against ROOT/updater.pub, so the sandbox gets its own
# fake ROOT whose trust anchor is the throwaway key.
FAKE_ROOT="$TMP/fakeroot"
mkdir -p "$FAKE_ROOT/scripts"
cp "$SANDBOX/scripts/verify-release-live.sh" "$FAKE_ROOT/scripts/"
cp "$SANDBOX/scripts/release-common.sh" "$FAKE_ROOT/scripts/"
cp "$TMP/pub.key" "$FAKE_ROOT/updater.pub"

cat > "$TMP/bin/gh" <<'SHIMEOF'
#!/usr/bin/env bash
# The real gh applies -q itself; the shim answers with the jq RESULT.
case "$*" in
  *releases/latest*) printf '0.9.9\n'; exit 0 ;;
  *repo*) printf 'baluard-org/baluard\n'; exit 0 ;;
esac
exit 0
SHIMEOF
cat > "$TMP/bin/curl" <<'SHIMEOF'
#!/usr/bin/env bash
target=""
url=""
args=("$@")
for i in "${!args[@]}"; do
  if [[ "${args[$i]}" == "-o" || "${args[$i]}" == "--output" ]]; then
    target="${args[$((i + 1))]}"
  elif [[ "${args[$i]}" != -* ]]; then
    url="${args[$i]}"
  fi
done
# http_code probes write to /dev/null and expect a status on stdout.
if [[ "$target" == "/dev/null" ]]; then
  printf '206\n'
  exit 0
fi
case "$url" in
  *SHA256SUMS.sig*) cat "$VRP_TEST_SUMS_SIG" > "$target" ;;
  *SHA256SUMS*) cat "$VRP_TEST_SUMS" > "$target" ;;
  */$VRP_TEST_ASSET) cat "$VRP_TEST_ASSET_BODY" > "$target" ;;
  *) printf 'not found\n'; exit 22 ;;
esac
SHIMEOF

chmod +x "$TMP/bin/gh" "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH"
export VRP_TEST_SUMS="$TMP/SHA256SUMS" VRP_TEST_SUMS_SIG="$TMP/SHA256SUMS.sig" \
  VRP_TEST_ASSET="$ASSET" VRP_TEST_ASSET_BODY="$TMP/$ASSET"
export BALUARD_PACKAGES_SITE="$TMP/empty-packages" BALUARD_VERIFY_TRIES=1
mkdir -p "$TMP/empty-packages"

run_verify() { (cd "$FAKE_ROOT" && ./scripts/verify-release-live.sh 0.9.9 "$@" 2>&1) || true; }
die() { echo "test-verify-release-live: $*" >&2; exit 1; }

# -- Good chain: signature ok, asset checksum ok -----------------------------
out="$(run_verify --deep --only --checksum "$ASSET")"
grep -q 'PASS sha256sums-signature' <<<"$out" || die "good chain: $out"
grep -q "PASS checksum/$ASSET" <<<"$out" || die "good chain checksum: $out"

# -- Tampered SHA256SUMS: signature fails, checksums refused -----------------
printf 'tampered  %s\n' "$ASSET" > "$TMP/SHA256SUMS"
out="$(run_verify --deep --only --checksum "$ASSET")"
grep -q 'FAIL sha256sums-signature' <<<"$out" || die "tampered sums: $out"
grep -q 'untrusted sums' <<<"$out" || die "untrusted-sums refusal: $out"

# -- Tampered asset: signature ok, checksum fails ----------------------------
make_sums
printf 'asset-body-V2' > "$TMP/$ASSET"
out="$(run_verify --deep --only --checksum "$ASSET")"
grep -q 'PASS sha256sums-signature' <<<"$out" || die "tampered asset: sig broke instead: $out"
grep -q "FAIL checksum/$ASSET" <<<"$out" || die "tampered asset: $out"

# -- Asset missing from the sums refuses -------------------------------------
make_sums
printf 'asset-body-v1' > "$TMP/$ASSET"
printf 'no entries here\n' > "$TMP/SHA256SUMS"
out="$(run_verify --deep --only --checksum "$ASSET")"
grep -q "FAIL checksum/$ASSET" <<<"$out" || die "missing entry: $out"

# -- A .sig that is not valid base64 fails the signature ---------------------
make_sums
printf 'not base64 at all !!!' > "$TMP/SHA256SUMS.sig"
out="$(run_verify --deep --only --checksum "$ASSET")"
grep -q 'FAIL sha256sums-signature' <<<"$out" || die "non-base64 sig: $out"
grep -q 'untrusted sums' <<<"$out" || die "non-base64 sums refusal: $out"

echo "test-verify-release-live: ok"
