#!/usr/bin/env bash
set -euo pipefail

# Upload the Play-flavor AAB to a Google Play testing track through the
# androidpublisher v3 edits API, mirroring ext-submit's conventions:
# credentials gated on the environment with loud guidance when absent, and
# secrets kept off argv in 0600 temp files.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="${BALUARD_PLAY_PACKAGE_NAME:-app.baluard.mobile}"
TRACK="${BALUARD_PLAY_TRACK:-internal}"
STATUS="${BALUARD_PLAY_RELEASE_STATUS:-completed}"
MIN_TARGET_SDK="${BALUARD_PLAY_MIN_TARGET_SDK:-35}"
SA_JSON="${BALUARD_PLAY_SERVICE_ACCOUNT_JSON:-$HOME/.baluard/play-service-account.json}"
API_BASE="https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$PKG"
# Media uploads live under the /upload/ host prefix; the plain URI accepts
# metadata only (edits.bundles.upload reference).
UPLOAD_BASE="https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/$PKG"

die() { echo "play: $*" >&2; exit 1; }

for tool in curl jq python3 openssl; do
  command -v "$tool" >/dev/null || die "$tool is required but not installed"
done

case "$TRACK" in
  internal | alpha) ;;
  production)
    [[ "${BALUARD_PLAY_ALLOW_PRODUCTION:-0}" == 1 ]] \
      || die "refusing track=production without BALUARD_PLAY_ALLOW_PRODUCTION=1; roll out production from the console where staged rollouts are configurable"
    ;;
  *) die "BALUARD_PLAY_TRACK '$TRACK' is not supported; use internal (default), alpha (closed testing), or production with the allow flag" ;;
esac
case "$STATUS" in
  completed | draft) ;;
  *) die "invalid BALUARD_PLAY_RELEASE_STATUS '$STATUS' (completed or draft)" ;;
esac

if [[ ! -r "$SA_JSON" ]]; then
  {
    echo "play: skipped - no service account"
    echo "play: set BALUARD_PLAY_SERVICE_ACCOUNT_JSON or place the key at ~/.baluard/play-service-account.json"
    echo "play: console setup: Play Console > Setup > API access, link a Cloud project, enable the Android Developer API, create a service account with the Release Manager role"
  } >&2
  exit 1
fi

# AAB resolution: argument, then env, then the build script's playRelease output.
AAB="${1:-${BALUARD_PLAY_AAB:-$ROOT/mobile/androidApp/build/outputs/bundle/playRelease/androidApp-play-release.aab}}"
[[ -f "$AAB" ]] || die "AAB not found: $AAB (build it with just android-apk-release)"

# Version metadata defaults to the workspace formula. Independent apps can
# override both values; the upload response and existing-bundle pool are checked.
VER="${BALUARD_PLAY_VERSION_NAME:-$(awk '/\[workspace\.package\]/{f=1} f && /^version = /{gsub(/"/, "", $3); print $3; exit}' "$ROOT/Cargo.toml")}"
[[ "$VER" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || die "version name '$VER' is not plain semver"
if [[ -n "${BALUARD_PLAY_VERSION_CODE:-}" ]]; then
  CODE="$BALUARD_PLAY_VERSION_CODE"
else
  MAJOR=${VER%%.*}; REST=${VER#*.}; MINOR=${REST%%.*}; PATCH=${REST#*.}
  CODE=$((10#$MAJOR * 1000000 + 10#$MINOR * 1000 + 10#$PATCH))
fi
[[ "$CODE" =~ ^[1-9][0-9]*$ ]] || die "version code '$CODE' must be a positive integer"

# Play gates rollout on targetSdkVersion. The fdroid APK shares defaultConfig
# with the play AAB, so its badging is a faithful pre-upload check when both
# aapt2 and the APK happen to be present; otherwise Play rejects later.
if command -v aapt2 >/dev/null; then
  AAPT2=(aapt2)
else
  AAPT2=()
  if [[ -n "${ANDROID_HOME:-}" ]]; then
    bt="$(find "$ANDROID_HOME/build-tools" -mindepth 2 -maxdepth 2 -name aapt2 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$bt" ]] && AAPT2=("$bt")
  fi
fi
FDROID_APK="$ROOT/mobile/androidApp/build/outputs/apk/fdroid/release/androidApp-fdroid-release.apk"
if ((${#AAPT2[@]})) && [[ -f "$FDROID_APK" ]]; then
  TSDK="$("${AAPT2[@]}" dump badging "$FDROID_APK" | grep -oE "targetSdkVersion:'[0-9]+'" | grep -oE '[0-9]+' || true)"
  if [[ -z "$TSDK" ]]; then
    echo "play: warning - could not read targetSdkVersion; letting Play verify it" >&2
  elif ((10#$TSDK < 10#$MIN_TARGET_SDK)); then
    die "fdroid APK targetSdkVersion $TSDK is below the required floor $MIN_TARGET_SDK; raise targetSdkVersion, rebuild, and verify with aapt2 before uploading (version codes burn on processed uploads)"
  fi
fi

SEC="$(mktemp -d)"
trap 'rm -rf "$SEC"' EXIT
umask 077

CLIENT_EMAIL="$(jq -r '.client_email // empty' "$SA_JSON")"
[[ -n "$CLIENT_EMAIL" ]] || die "service account JSON has no client_email"
python3 -I -c 'import json, sys; sys.stdout.write(json.load(open(sys.argv[1]))["private_key"])' "$SA_JSON" > "$SEC/privkey.pem" \
  || die "service account JSON has no usable private_key"
chmod 600 "$SEC/privkey.pem"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
NOW="$(date +%s)"
HEADER="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
PAYLOAD="$(printf '{"iss":"%s","scope":"https://www.googleapis.com/auth/androidpublisher","aud":"https://oauth2.googleapis.com/token","iat":%s,"exp":%s}' \
  "$CLIENT_EMAIL" "$NOW" "$((NOW + 1200))" | b64url)"
printf '%s.%s' "$HEADER" "$PAYLOAD" | openssl dgst -sha256 -binary -sign "$SEC/privkey.pem" | b64url > "$SEC/sig"
printf '%s.%s.%s' "$HEADER" "$PAYLOAD" "$(cat "$SEC/sig")" > "$SEC/assertion"
chmod 600 "$SEC/assertion"
TOKEN="$(curl -sS --fail-with-body -o "$SEC/token.json" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "assertion@$SEC/assertion" \
  https://oauth2.googleapis.com/token \
  && jq -r '.access_token // empty' "$SEC/token.json")" \
  || die "token exchange failed: $(cat "$SEC/token.json" 2>/dev/null || echo 'no response')"
[[ -n "$TOKEN" ]] || die "token exchange returned no access_token"

# curl reads -H values from a file with the @path form, so the bearer token
# never rides argv. Content-Type headers are not secret and stay on argv.
printf 'Authorization: Bearer %s\n' "$TOKEN" > "$SEC/auth-header"
chmod 600 "$SEC/auth-header"

api() { curl -sS --fail-with-body -H @"$SEC/auth-header" "$@"; }

EDIT="$(api -X POST -d '' "$API_BASE/edits" > "$SEC/resp" && jq -r '.id // empty' "$SEC/resp")" \
  || die "creating the edit failed: $(head -c 300 "$SEC/resp" 2>/dev/null || echo 'no response')"
[[ -n "$EDIT" ]] || die "edit creation returned no id"

EXISTING="$(api "$API_BASE/edits/$EDIT/bundles" > "$SEC/resp" \
  && jq '[.bundles[]?.versionCode] | index('"$CODE"') != null' "$SEC/resp")" \
  || die "listing existing bundles failed: $(head -c 300 "$SEC/resp" 2>/dev/null || echo 'no response')"
if [[ "$EXISTING" == "true" ]]; then
  die "version code $CODE was already used on this app; bump the workspace version and rebuild before uploading"
fi

api -X POST "$UPLOAD_BASE/edits/$EDIT/bundles" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$AAB" > "$SEC/bundle.json" \
  || die "AAB upload failed: $(head -c 300 "$SEC/bundle.json" 2>/dev/null || echo 'no response')"
UPLOADED="$(jq -r '.versionCode // empty' "$SEC/bundle.json")"
[[ "$UPLOADED" == "$CODE" ]] \
  || die "uploaded bundle reports versionCode '$UPLOADED', expected $CODE; workspace and AAB have drifted"

api -X PUT "$API_BASE/edits/$EDIT/tracks/$TRACK" -H 'Content-Type: application/json' \
  -d "{\"track\":\"$TRACK\",\"releases\":[{\"name\":\"$VER ($CODE)\",\"versionCodes\":[$CODE],\"status\":\"$STATUS\"}]}" \
  > "$SEC/track.json" || die "track assignment failed: $(head -c 300 "$SEC/track.json")"

api -X POST -d '' "$API_BASE/edits/$EDIT:commit" > "$SEC/resp" \
  || die "committing the edit failed; the discarded edit takes the uploaded bundle with it: $(head -c 300 "$SEC/resp" 2>/dev/null || echo 'no response')"

echo "play/$TRACK: released $VER ($CODE)"
