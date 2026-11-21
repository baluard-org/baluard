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

# Workspace 0.9.9 maps to versionCode 9009 (0-major formula); tracks must carry exactly that.
CODE=9009
TRACK_JSON="$TMP/tracks.json"
set_tracks() {
  printf '{"internal":{"releases":[{"versionCodes":[%s]}]},"alpha":{"releases":[{"versionCodes":[%s]}]}}' \
    "${1:-}" "${2:-}" > "$TRACK_JSON"
}
set_tracks "$CODE" "$CODE"

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

# The run must leave no secrets in the temp dir (the SA key, JWT, auth header).
SCRATCH="$TMP/tmpdir"; mkdir -p "$SCRATCH"
out="$( (cd "$SANDBOX" && TMPDIR="$SCRATCH" "$SANDBOX/scripts/upload-play-release.sh" --tracks) 2>&1 )"
if find "$SCRATCH" -name 'privkey.pem' -o -name 'auth-header' -o -name 'assertion' | grep -q .; then
  echo "secrets survived the run:" >&2
  find "$SCRATCH" -name 'privkey.pem' -o -name 'auth-header' -o -name 'assertion' >&2
  exit 1
fi
grep -q "play/internal: $CODE" <<<"$out"
grep -q "play/alpha:    $CODE" <<<"$out"
grep -q "tracks agree on $CODE" <<<"$out"

# Divergence refuses.
set_tracks "$CODE" $((CODE + 1))
if (cd "$SANDBOX" && "$SANDBOX/scripts/upload-play-release.sh" --tracks) > "$TMP/div.out" 2>&1; then
  echo "expected divergence to fail" >&2
  exit 1
fi
grep -q 'track divergence' "$TMP/div.out"

# Agreement on an OLD version refuses (the workspace code is the expectation).
set_tracks 8000 8000
if (cd "$SANDBOX" && "$SANDBOX/scripts/upload-play-release.sh" --tracks) > "$TMP/old.out" 2>&1; then
  echo "expected stale agreement to fail" >&2
  exit 1
fi
grep -q 'upload the current bundle first' "$TMP/old.out"

# A missing track reads as none; one populated + one missing diverges.
set_tracks "$CODE" ""
if (cd "$SANDBOX" && "$SANDBOX/scripts/upload-play-release.sh" --tracks) > "$TMP/missing.out" 2>&1; then
  echo "expected missing-track divergence to fail" >&2
  exit 1
fi
grep -q 'track divergence' "$TMP/missing.out"

# An API failure dies instead of reading as none/none agreement.
set_tracks "$CODE" "$CODE"
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
for arg in "$@"; do
  case "$arg" in
    */edits)
      printf '{"id": "edit-1"}\n'; exit 0 ;;
    *tracks/internal*)
      echo "curl: (22) The requested URL returned error: 503" >&2; exit 22 ;;
  esac
done
echo "unexpected curl: $*" >&2
exit 64
EOF
chmod +x "$TMP/bin/curl"
if (cd "$SANDBOX" && "$SANDBOX/scripts/upload-play-release.sh" --tracks) > "$TMP/err.out" 2>&1; then
  echo "expected an API failure to die" >&2
  exit 1
fi
grep -q 'reading track internal failed' "$TMP/err.out"

echo "test-play-tracks: ok"
