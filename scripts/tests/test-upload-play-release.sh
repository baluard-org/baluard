#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Run the upload script against a sandbox copy of the repository so the real
# worktree, its AABs, and the network are never touched.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$TMP/bin"
cp "$ROOT/scripts/upload-play-release.sh" "$SANDBOX/scripts/" 2>/dev/null || {
  echo "scripts/upload-play-release.sh missing" >&2
  exit 127
}

# Sandbox repo: workspace version drives versionName/versionCode.
mkdir -p "$SANDBOX/mobile/androidApp/build/outputs/bundle/playRelease"
mkdir -p "$SANDBOX/mobile/androidApp/build/outputs/apk/fdroid/release"
printf '[workspace.package]\nversion = "0.1.11"\n' > "$SANDBOX/Cargo.toml"
printf 'AAB-PAYLOAD\n' > "$SANDBOX/mobile/androidApp/build/outputs/bundle/playRelease/androidApp-play-release.aab"

# Throwaway service-account material: a real RSA key (the script signs a JWT
# with openssl) wrapped in the Google JSON shape.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/sa-key.pem" 2>/dev/null
python3 - "$TMP/sa-key.pem" "$TMP/sa.json" <<'PY'
import json, sys
key = open(sys.argv[1]).read()
json.dump({"client_email": "baluard-upload@baluard-play.iam.gserviceaccount.com",
           "private_key": key}, open(sys.argv[2], "w"))
PY
chmod 600 "$TMP/sa.json"

# Fake aapt2: emits one badging line with a knob-controlled targetSdkVersion.
cat > "$TMP/bin/aapt2" <<'EOF'
#!/usr/bin/env bash
printf "sdkVersion:'35'\ntargetSdkVersion:'${SUB_PLAY_TARGET_SDK:-36}'\n"
exit 0
EOF
chmod +x "$TMP/bin/aapt2"

# Fake curl: records argv, answers the token exchange and the five
# androidpublisher calls, and honors failure knobs.
CURL_LOG="$TMP/curl.log"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SUB_PLAY_CURL_LOG:?}"
out=""
args=()
while (($#)); do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
emit() { [[ -n "$out" ]] && printf '%s\n' "$1" > "$out" || printf '%s\n' "$1"; }
for arg in "${args[@]}"; do
  case "$arg" in
    *oauth2.googleapis.com/token*)
      emit '{"access_token": "test-token", "expires_in": 3600}'
      exit 0 ;;
    *bundles?uploadType=media*)
      if [[ "${SUB_PLAY_UPLOAD_FAIL:-0}" == 1 ]]; then
        emit '{"error": {"message": "upload rejected"}}'
        exit 22
      fi
      emit "{\"versionCode\": ${SUB_PLAY_UPLOAD_VC:-1011}}"
      exit 0 ;;
    *:commit*)
      emit '{"id": "edit-1"}'
      exit 0 ;;
    */tracks/*)
      if [[ "${SUB_PLAY_TRACK_FAIL:-0}" == 1 ]]; then
        emit '{"error": {"message": "track rejected"}}'
        exit 22
      fi
      emit '{}'
      exit 0 ;;
    */edits)
      emit '{"id": "edit-1"}'
      exit 0 ;;
    */bundles)
      if [[ "${SUB_PLAY_BURNED:-0}" == 1 ]]; then
        emit '{"bundles": [{"versionCode": 1011}]}'
      else
        emit '{"bundles": []}'
      fi
      exit 0 ;;
  esac
done
echo "unexpected curl invocation: ${args[*]}" >&2
exit 64
EOF
chmod +x "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH"
export SUB_PLAY_CURL_LOG="$CURL_LOG"

# ── Happy path: full edit flow releases the AAB to internal ─────────────────
AAB="$SANDBOX/mobile/androidApp/build/outputs/bundle/playRelease/androidApp-play-release.aab"
APK="$SANDBOX/mobile/androidApp/build/outputs/apk/fdroid/release/androidApp-fdroid-release.apk"
printf 'APK\n' > "$APK"
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/happy.out"
grep -q 'play/internal: released 0.1.11 (1011)' "$TMP/happy.out"

test "$(wc -l < "$CURL_LOG")" = 6
grep -q 'oauth2.googleapis.com/token' "$CURL_LOG"
grep -q 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' "$CURL_LOG"
# The JWT rides a --data-urlencode @file, never raw argv.
if grep -q 'assertion=ey' "$CURL_LOG"; then echo 'JWT leaked onto argv' >&2; exit 1; fi
grep -q 'applications/app.baluard.mobile/edits' "$CURL_LOG"
grep -q 'bundles?uploadType=media' "$CURL_LOG"
grep -q -- "--data-binary @$AAB" "$CURL_LOG"
grep -q 'application/octet-stream' "$CURL_LOG"
grep -q '/tracks/internal' "$CURL_LOG"
grep -q '"versionCodes":\[1011\]' "$CURL_LOG"
grep -q '"name":"0.1.11 (1011)"' "$CURL_LOG"
grep -q '"status":"completed"' "$CURL_LOG"
grep -q ':commit' "$CURL_LOG"
# The service-account private key and the bearer token never appear on argv.
if grep -q 'PRIVATE KEY' "$CURL_LOG"; then echo 'key material on argv' >&2; exit 1; fi
if grep -q 'Bearer test-token' "$CURL_LOG"; then echo 'bearer token on argv' >&2; exit 1; fi

# ── Burned versionCode refuses before any upload ────────────────────────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" SUB_PLAY_BURNED=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/burned.out" 2> "$TMP/burned.err" \
  && { echo 'burned version accepted' >&2; exit 1; }
grep -qi 'already used' "$TMP/burned.out" "$TMP/burned.err"
grep -q 'bump' "$TMP/burned.err" "$TMP/burned.out"
if grep -q 'uploadType=media' "$CURL_LOG"; then echo 'upload ran past burn guard' >&2; exit 1; fi

# ── Upload failure stops before track assignment ────────────────────────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" SUB_PLAY_UPLOAD_FAIL=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/upfail.out" 2>&1 \
  && { echo 'upload failure accepted' >&2; exit 1; }
if grep -q '/tracks/' "$CURL_LOG"; then echo 'track ran past upload failure' >&2; exit 1; fi
if grep -q ':commit' "$CURL_LOG"; then echo 'commit ran past upload failure' >&2; exit 1; fi

# ── Upload response versionCode mismatch refuses the track step ─────────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" SUB_PLAY_UPLOAD_VC=999 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/mismatch.out" 2>&1 \
  && { echo 'mismatched bundle accepted' >&2; exit 1; }
if grep -q '/tracks/internal' "$CURL_LOG"; then echo 'track ran past mismatch' >&2; exit 1; fi

# ── Track failure stops before commit ────────────────────────────────────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" SUB_PLAY_TRACK_FAIL=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/trkfail.out" 2>&1 \
  && { echo 'track failure accepted' >&2; exit 1; }
if grep -q ':commit' "$CURL_LOG"; then echo 'commit ran past track failure' >&2; exit 1; fi

# ── Missing credentials print guidance and never touch the network ──────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/absent-key.json" \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/nocreds.out" 2> "$TMP/nocreds.err" \
  && { echo 'missing creds accepted' >&2; exit 1; } || true
grep -q 'BALUARD_PLAY_SERVICE_ACCOUNT_JSON' "$TMP/nocreds.err"
test ! -s "$CURL_LOG" || { echo 'network touched without creds' >&2; exit 1; }

# ── Production track is refused without the explicit allow flag ─────────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" BALUARD_PLAY_TRACK=production \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/prod.err" \
  && { echo 'production accepted without allow flag' >&2; exit 1; } || true
grep -q 'BALUARD_PLAY_ALLOW_PRODUCTION' "$TMP/prod.err"
test ! -s "$CURL_LOG" || { echo 'network touched for refused production' >&2; exit 1; }

# ── targetSdk below the floor refuses with guidance ─────────────────────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json" SUB_PLAY_TARGET_SDK=34 \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/tsdk.err" \
  && { echo 'stale targetSdk accepted' >&2; exit 1; } || true
grep -qi 'targetSdk' "$TMP/tsdk.err"

echo "PASS: upload-play-release.sh"
