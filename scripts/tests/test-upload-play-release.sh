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
python3 -I - "$TMP/sa-key.pem" "$TMP/sa.json" <<'PY'
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

# Fake curl: parses -o and -H @file like the real CLI (header file contents
# go to a separate log), records argv, answers the token exchange and the
# five androidpublisher calls, and honors failure knobs. HTTP failures only
# exit 22 when the script actually passes --fail-with-body; without it the
# body is emitted and the exit is 0, matching real curl.
CURL_LOG="$TMP/curl.log"
HDR_LOG="$TMP/hdr.log"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SUB_PLAY_CURL_LOG:?}"
out=""
args=()
while (($#)); do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -H)
      if [[ "${2:-}" == @* ]]; then
        printf '%s\n' "HEADER $(cat "${2#@}")" >> "${SUB_PLAY_HDR_LOG:?}"
        shift 2
      else
        args+=("-H" "$2"); shift 2
      fi ;;
    *) args+=("$1"); shift ;;
  esac
done
fail() {
  emit "$1"
  [[ " ${args[*]} " == *' --fail-with-body '* ]] && exit 22
  exit 0
}
emit() { if [[ -n "$out" ]]; then printf '%s\n' "$1" > "$out"; else printf '%s\n' "$1"; fi; }
for arg in "${args[@]}"; do
  case "$arg" in
    *oauth2.googleapis.com/token*)
      emit '{"access_token": "test-token", "expires_in": 3600}'
      exit 0 ;;
    */upload/*bundles*)
      if [[ "${SUB_PLAY_UPLOAD_FAIL:-0}" == 1 ]]; then
        fail '{"error": {"message": "upload rejected"}}'
      fi
      emit "{\"versionCode\": ${SUB_PLAY_UPLOAD_VC:-1011}}"
      exit 0 ;;
    *:commit*)
      emit '{"id": "edit-1"}'
      exit 0 ;;
    */tracks/*)
      if [[ "${SUB_PLAY_TRACK_FAIL:-0}" == 1 ]]; then
        fail '{"error": {"message": "track rejected"}}'
      fi
      emit '{}'
      exit 0 ;;
    */edits)
      emit '{"id": "edit-1"}'
      exit 0 ;;
    */bundles)
      if [[ "${SUB_PLAY_BURNED:-0}" == 1 ]]; then
        emit '{"bundles": [{"versionCode": 1011}]}'
      elif [[ -n "${SUB_PLAY_EXISTING_SHA:-}" ]]; then
        emit "{\"bundles\": [{\"versionCode\": 1011, \"sha256\": \"${SUB_PLAY_EXISTING_SHA}\"}]}"
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
export SUB_PLAY_CURL_LOG="$CURL_LOG" SUB_PLAY_HDR_LOG="$HDR_LOG"

# Pin every BALUARD_PLAY_* knob so machine-level exports cannot leak in.
BASE_ENV=(BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/sa.json"
  BALUARD_PLAY_PACKAGE_NAME=app.baluard.mobile
  BALUARD_PLAY_TRACK=internal
  BALUARD_PLAY_RELEASE_STATUS=completed
  BALUARD_PLAY_MIN_TARGET_SDK=35)

AAB="$SANDBOX/mobile/androidApp/build/outputs/bundle/playRelease/androidApp-play-release.aab"
APK="$SANDBOX/mobile/androidApp/build/outputs/apk/fdroid/release/androidApp-fdroid-release.apk"
printf 'APK\n' > "$APK"

# ── Happy path: full edit flow releases the AAB to internal ─────────────────
rm -f "$CURL_LOG" "$HDR_LOG"
env -u BALUARD_PLAY_AAB -u BALUARD_PLAY_ALLOW_PRODUCTION "${BASE_ENV[@]}" \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/happy.out"
grep -q 'play/internal: released 0.1.11 (1011)' "$TMP/happy.out"

test "$(wc -l < "$CURL_LOG")" = 6
grep -q 'oauth2.googleapis.com/token' "$CURL_LOG"
grep -q 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' "$CURL_LOG"
# The JWT rides a --data-urlencode @file, never raw argv.
if grep -q 'assertion=ey' "$CURL_LOG"; then echo 'JWT leaked onto argv' >&2; exit 1; fi
# The bearer token reaches curl only through the header file.
grep -q 'HEADER Authorization: Bearer test-token' "$HDR_LOG"
if grep -q 'Bearer test-token' "$CURL_LOG"; then echo 'bearer token on argv' >&2; exit 1; fi
# The service-account private key never appears on argv or headers.
if grep -q 'PRIVATE KEY' "$CURL_LOG" "$HDR_LOG"; then echo 'key material leaked' >&2; exit 1; fi
# Edit flow: POST creates the edit, the id propagates into every later URL.
grep -q -- '-X POST' "$CURL_LOG"
grep -q 'applications/app.baluard.mobile/edits' "$CURL_LOG"
grep -q 'edits/edit-1/bundles' "$CURL_LOG"
# Upload goes to the /upload/ media URI with the right verb, content type,
# and body file.
grep 'upload/androidpublisher' "$CURL_LOG" | grep -q -- '-X POST'
grep 'upload/androidpublisher' "$CURL_LOG" | grep -q -- "--data-binary @$AAB"
grep 'upload/androidpublisher' "$CURL_LOG" | grep -q 'application/octet-stream'
# Track assignment carries the computed code, the release name, and the verb.
grep '/tracks/internal' "$CURL_LOG" | grep -q -- '-X PUT'
grep -q '"versionCodes":\[1011\]' "$CURL_LOG"
grep -q '"name":"0.1.11 (1011)"' "$CURL_LOG"
grep -q '"status":"completed"' "$CURL_LOG"
grep -q ':commit' "$CURL_LOG"

# ── Burned versionCode refuses before any upload ────────────────────────────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" SUB_PLAY_BURNED=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/burned.out" 2> "$TMP/burned.err" \
  && { echo 'burned version accepted' >&2; exit 1; }
grep -qi 'different bytes' "$TMP/burned.err"
grep -q 'bump' "$TMP/burned.err"
if grep -q '/upload/' "$CURL_LOG"; then echo 'upload ran past burn guard' >&2; exit 1; fi

# ── Same bundle on a second track skips the upload and assigns ──────────────
# While Baluard is in pre-release, internal and closed testing must carry
# the SAME version: the second play-submit run sees the committed bundle
# with identical bytes and goes straight to track assignment.
rm -f "$CURL_LOG"
AAB_SHA="$(sha256sum "$AAB" | awk '{print $1}')"
env "${BASE_ENV[@]}" BALUARD_PLAY_TRACK=alpha SUB_PLAY_EXISTING_SHA="$AAB_SHA" \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/same.out"
grep -q 'already on the app with identical bytes' "$TMP/same.out"
grep -q 'play/alpha: released 0.1.11 (1011)' "$TMP/same.out"
if grep -q '/upload/' "$CURL_LOG"; then echo 'identical bundle re-uploaded' >&2; exit 1; fi
grep '/tracks/alpha' "$CURL_LOG" | grep -q -- '-X PUT'
grep -q '"versionCodes":\[1011\]' "$CURL_LOG"
grep -q ':commit' "$CURL_LOG"

# ── Same versionCode with different bytes still refuses ─────────────────────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" SUB_PLAY_EXISTING_SHA=deadbeef \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/samebad.out" 2> "$TMP/samebad.err" \
  && { echo 'different bytes accepted' >&2; exit 1; }
grep -qi 'different bytes' "$TMP/samebad.err"
if grep -q '/upload/' "$CURL_LOG"; then echo 'upload ran past byte guard' >&2; exit 1; fi

# ── Upload failure stops before track assignment, with the store's error ────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" SUB_PLAY_UPLOAD_FAIL=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/upfail.out" 2> "$TMP/upfail.err" \
  && { echo 'upload failure accepted' >&2; exit 1; }
grep -q 'AAB upload failed' "$TMP/upfail.err"
grep -q 'upload rejected' "$TMP/upfail.err"
if grep -q '/tracks/' "$CURL_LOG"; then echo 'track ran past upload failure' >&2; exit 1; fi
if grep -q ':commit' "$CURL_LOG"; then echo 'commit ran past upload failure' >&2; exit 1; fi

# ── Upload response versionCode mismatch refuses the track step ─────────────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" SUB_PLAY_UPLOAD_VC=999 \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/mismatch.err" \
  && { echo 'mismatched bundle accepted' >&2; exit 1; }
grep -q 'drifted' "$TMP/mismatch.err"
if grep -q '/tracks/' "$CURL_LOG"; then echo 'track ran past mismatch' >&2; exit 1; fi

# ── Track failure stops before commit ────────────────────────────────────────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" SUB_PLAY_TRACK_FAIL=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/trkfail.err" \
  && { echo 'track failure accepted' >&2; exit 1; }
grep -q 'track assignment failed' "$TMP/trkfail.err"
grep -q 'track rejected' "$TMP/trkfail.err"
if grep -q ':commit' "$CURL_LOG"; then echo 'commit ran past track failure' >&2; exit 1; fi

# ── Missing credentials print guidance and never touch the network ──────────
rm -f "$CURL_LOG"
env BALUARD_PLAY_SERVICE_ACCOUNT_JSON="$TMP/absent-key.json" \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/nocreds.err" \
  && { echo 'missing creds accepted' >&2; exit 1; } || true
grep -q 'BALUARD_PLAY_SERVICE_ACCOUNT_JSON' "$TMP/nocreds.err"
if [[ -s "$CURL_LOG" ]]; then echo 'network touched without creds' >&2; exit 1; fi

# ── Production track is refused without the explicit allow flag ─────────────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" BALUARD_PLAY_TRACK=production \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/prod.err" \
  && { echo 'production accepted without allow flag' >&2; exit 1; } || true
grep -q 'BALUARD_PLAY_ALLOW_PRODUCTION' "$TMP/prod.err"
if [[ -s "$CURL_LOG" ]]; then echo 'network touched for refused production' >&2; exit 1; fi

# ── Unsupported track names are refused ──────────────────────────────────────
env "${BASE_ENV[@]}" BALUARD_PLAY_TRACK=beta \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/beta.err" \
  && { echo 'unsupported track accepted' >&2; exit 1; } || true
grep -q 'is not supported' "$TMP/beta.err"

# ── targetSdk below the floor refuses with guidance ─────────────────────────
env "${BASE_ENV[@]}" SUB_PLAY_TARGET_SDK=34 \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/tsdk.err" \
  && { echo 'stale targetSdk accepted' >&2; exit 1; } || true
grep -qi 'targetSdk' "$TMP/tsdk.err"

# ── Independent apps can override workspace-derived version metadata ───────
rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" BALUARD_PLAY_VERSION_NAME=1.0.0 BALUARD_PLAY_VERSION_CODE=1 SUB_PLAY_UPLOAD_VC=1 \
  "$SANDBOX/scripts/upload-play-release.sh" > "$TMP/override.out"
grep -q 'play/internal: released 1.0.0 (1)' "$TMP/override.out"
grep -q '"versionCodes":\[1\]' "$CURL_LOG"
grep -q '"name":"1.0.0 (1)"' "$CURL_LOG"

rm -f "$CURL_LOG"
env "${BASE_ENV[@]}" BALUARD_PLAY_VERSION_CODE=not-a-number \
  "$SANDBOX/scripts/upload-play-release.sh" > /dev/null 2> "$TMP/bad-version.err" \
  && { echo 'invalid version code accepted' >&2; exit 1; } || true
grep -qi 'version code' "$TMP/bad-version.err"
if [[ -s "$CURL_LOG" ]]; then echo 'network touched for invalid version code' >&2; exit 1; fi

echo "PASS: upload-play-release.sh"
