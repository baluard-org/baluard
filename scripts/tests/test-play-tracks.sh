#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --tracks mode: read both pre-release tracks and fail on divergence.
# Fixture SA signs a real JWT (openssl), the fake curl answers the
# androidpublisher edit/track reads.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$TMP/bin"
cp "$ROOT/scripts/upload-play-release.sh" "$SANDBOX/scripts/"
printf '[workspace.package]\nversion = "0.9.9"\n' > "$SANDBOX/Cargo.toml"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/sa.pem" 2>/dev/null
python3 - "$TMP/sa.pem" "$TMP/sa.json" <<'PY'
import json, sys
json.dump({"client_email": "pub@baluard-play.iam.gserviceaccount.com",
           "private_key": open(sys.argv[1]).read()}, open(sys.argv[2], "w"))
PY
chmod 600 "$TMP/sa.json"

TRACK_JSON="$TMP/tracks.json"
set_tracks() {
  printf '{"internal":{"releases":[{"versionCodes":[%s]}]},"alpha":{"releases":[{"versionCodes":[%s]}]}}' \
    "${1:-}" "${2:-}" > "$TRACK_JSON"
}
set_tracks 9000 9000

cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=""
args=("$@")
for i in "${!args[@]}"; do
  [[ "${args[$i]}" == "-o" ]] && out="${args[$((i + 1))]}"
done
if [[ -n "$out" ]]; then
  printf '{"access_token": "test-token", "expires_in": 3600}\n' > "$out"
  exit 0
fi
case "$*" in
  */edits)
    printf '{"id": "edit-1"}\n'; exit 0 ;;
  */tracks/internal*|*/tracks/alpha*)
    track="alpha"
    [[ "$*" == *tracks/internal* ]] && track="internal"
    PLAY_TEST_TRACK="$track" python3 -c 'import json, os, sys
d = json.load(open(os.environ["PLAY_TEST_TRACK_JSON"]))
releases = d.get(os.environ["PLAY_TEST_TRACK"], {}).get("releases", [])
print(json.dumps({"releases": releases}))'
    exit 0 ;;
  */edits/edit-1*)
    exit 0 ;;
esac
echo "unexpected curl: $*" >&2
exit 64
EOF
chmod +x "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH" PLAY_TEST_TRACK_JSON="$TRACK_JSON" PLAY_TEST_TRACK=internal \
  BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json"

out="$( (cd "$SANDBOX" && "$SANDBOX/scripts/upload-play-release.sh" --tracks) 2>&1 )"
grep -q 'play/internal: 9000' <<<"$out"
grep -q 'play/alpha:    9000' <<<"$out"
grep -q 'tracks agree' <<<"$out"

set_tracks 9000 9001
if (cd "$SANDBOX" && "$SANDBOX/scripts/upload-play-release.sh" --tracks) > "$TMP/div.out" 2>&1; then
  echo "expected divergence to fail" >&2
  exit 1
fi
grep -q 'track divergence' "$TMP/div.out"

echo "test-play-tracks: ok"
