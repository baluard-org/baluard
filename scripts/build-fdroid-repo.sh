#!/usr/bin/env bash
set -euo pipefail

APK="${1:?usage: build-fdroid-repo.sh <signed-release.apk> <repo-out-dir>}"
OUT="${2:?usage: build-fdroid-repo.sh <repo-out-dir>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${BALUARD_FDROID_HOME:-$HOME/.baluard/fdroid}"
EXPECTED_KEY_FILE="${BALUARD_FDROID_EXPECTED_SIGNING_KEY:-$ROOT/fdroid/allowed-signing-key.sha256}"
PACKAGE="app.baluard.mobile"
RETENTION="${BALUARD_FDROID_APK_RETENTION:-3}"

fail() { echo "ERROR: $*" >&2; exit 1; }
[[ -s "$APK" ]] || fail "signed release APK not found: $APK"
[[ "$RETENTION" =~ ^[1-9][0-9]*$ ]] || fail "BALUARD_FDROID_APK_RETENTION must be a positive integer"
command -v rsync >/dev/null || fail "rsync is required"

FDROID="${FDROID:-$(command -v fdroid || true)}"
if [[ -z "$FDROID" && -x "$HOME/.baluard/fdroidserver-venv/bin/fdroid" ]]; then
  FDROID="$HOME/.baluard/fdroidserver-venv/bin/fdroid"
fi
[[ -n "$FDROID" && -x "$FDROID" ]] || fail "fdroidserver 2.4.5 not found; see docs/dev/fdroid-repository.md"

ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
export ANDROID_HOME
[[ -d "$ANDROID_HOME" ]] || fail "Android SDK not found; set ANDROID_HOME"

latest_build_tool() {
  local name="$1" candidate
  local -a candidates=()
  for candidate in "$ANDROID_HOME"/build-tools/*/"$name"; do
    [[ -x "$candidate" ]] && candidates+=("$candidate")
  done
  ((${#candidates[@]} > 0)) || return 1
  printf '%s\n' "${candidates[@]}" | sort -V | tail -1
}

APKSIGNER="${APKSIGNER:-$(command -v apksigner || true)}"
[[ -n "$APKSIGNER" ]] || APKSIGNER="$(latest_build_tool apksigner || true)"
[[ -n "$APKSIGNER" && -x "$APKSIGNER" ]] || fail "apksigner not found in the Android SDK build-tools"
AAPT="${AAPT:-$(command -v aapt || true)}"
[[ -n "$AAPT" ]] || AAPT="$(latest_build_tool aapt || true)"
[[ -n "$AAPT" && -x "$AAPT" ]] || fail "aapt not found in the Android SDK build-tools"

if ! BADGING="$("$AAPT" dump badging "$APK")"; then
  fail "aapt could not read the APK"
fi
BADGING="${BADGING%%$'\n'*}"
[[ "$BADGING" == package:\ name=\'$PACKAGE\'* ]] || fail "APK application ID is not $PACKAGE"
VERSION_CODE="$(sed -n "s/.*versionCode='\([0-9][0-9]*\)'.*/\1/p" <<< "$BADGING")"
VERSION_NAME="$(sed -n "s/.*versionName='\([^']*\)'.*/\1/p" <<< "$BADGING")"
[[ -n "$VERSION_CODE" ]] || fail "could not read the APK versionCode"
WORKSPACE_VERSION="$(awk -F'"' '/^\[workspace.package\]/{section=1; next} section && /^version =/{print $2; exit}' "$ROOT/Cargo.toml")"
[[ -n "$VERSION_NAME" && "$VERSION_NAME" == "$WORKSPACE_VERSION" ]] || fail "APK versionName ($VERSION_NAME) does not match workspace version ($WORKSPACE_VERSION)"

if ! SIGNER_OUTPUT="$("$APKSIGNER" verify --print-certs "$APK")"; then
  fail "apksigner could not verify the APK"
fi
FINGERPRINT="$(sed -n '0,/^Signer #1 certificate SHA-256 digest: /s///p' <<< "$SIGNER_OUTPUT")"
[[ "$FINGERPRINT" =~ ^[[:xdigit:]]{64}$ ]] || fail "could not verify the APK signing certificate"
FINGERPRINT="${FINGERPRINT,,}"
[[ -s "$EXPECTED_KEY_FILE" ]] || fail "expected APK signing certificate not configured: $EXPECTED_KEY_FILE"
EXPECTED="$(<"$EXPECTED_KEY_FILE")"
[[ "$FINGERPRINT" == "$EXPECTED" ]] || fail "APK signing certificate changed; refusing to publish an incompatible update"

REPO_KEY_DN='CN=Baluard, O=Baluard Org, C=CL'
REPO_KEY_ALIAS=baluard
mkdir -p "$WORK"
if [[ ! -e "$WORK/config.yml" && ! -e "$WORK/keystore.p12" ]]; then
  (
    umask 077
    cd "$WORK"
    "$FDROID" init --no-prompt -d "$REPO_KEY_DN" --repo-keyalias "$REPO_KEY_ALIAS"
  )
  # fdroidserver 2.4.5 ignores init --dname and generates CN=<alias>, OU=F-Droid.
  if [[ "$(awk -F': ' '$1 == "keydname" {print $2; exit}' "$WORK/config.yml")" != "$REPO_KEY_DN" ]]; then
    KEYTOOL_BIN="${KEYTOOL:-$(command -v keytool || true)}"
    [[ -n "$KEYTOOL_BIN" ]] || fail "keytool not found; cannot set the repo key identity"
    repo_pw="$(awk -F': ' '$1 == "keypass" {print $2; exit}' "$WORK/config.yml")"
    [[ -n "$repo_pw" ]] || fail "keypass missing from config.yml"
    "$KEYTOOL_BIN" -delete -keystore "$WORK/keystore.p12" -storetype PKCS12 -alias "$REPO_KEY_ALIAS" -storepass "$repo_pw"
    "$KEYTOOL_BIN" -genkeypair -keystore "$WORK/keystore.p12" -storetype PKCS12 -alias "$REPO_KEY_ALIAS" \
      -keyalg RSA -keysize 3072 -validity 10000 -dname "$REPO_KEY_DN" \
      -storepass "$repo_pw" -keypass "$repo_pw"
    sed -i "s|^keydname:.*|keydname: $REPO_KEY_DN|" "$WORK/config.yml"
  fi
elif [[ ! -s "$WORK/config.yml" || ! -s "$WORK/keystore.p12" ]]; then
  fail "incomplete F-Droid initialization; restore config.yml and keystore.p12 from backup"
fi
[[ "$(awk -F': ' '$1 == "keydname" {print $2; exit}' "$WORK/config.yml")" == "$REPO_KEY_DN" ]] \
  || fail "repo key identity is not $REPO_KEY_DN; regenerate the repo signing key"
chmod 600 "$WORK/config.yml" "$WORK/keystore.p12"

FDROID_PYTHON="${FDROID_PYTHON:-$(dirname "$FDROID")/python}"
[[ -x "$FDROID_PYTHON" ]] || FDROID_PYTHON="python3"
WORK="$WORK" "$FDROID_PYTHON" - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["WORK"]) / "config.yml"
updates = {
    "repo_url": "https://packages.baluard.app/fdroid/repo",
    "repo_name": "Baluard",
    "repo_icon": "fdroid-icon.png",
    "repo_description": "Official Baluard Android releases.",
}
lines = path.read_text().splitlines(keepends=True)
seen = set()
output = []
for line in lines:
    key = line.split(":", 1)[0]
    if key in updates:
        output.append(f"{key}: {updates[key]}\n")
        seen.add(key)
    else:
        output.append(line)
for key, value in updates.items():
    if key not in seen:
        output.append(f"{key}: {value}\n")
content = "".join(output)
if content != path.read_text():
    backup = path.with_suffix(".yml.backup")
    backup.write_text(path.read_text())
    backup.chmod(0o600)
    temporary = path.with_suffix(".yml.tmp")
    temporary.write_text(content)
    temporary.chmod(0o600)
    os.replace(temporary, path)
PY

mkdir -p "$WORK/metadata" "$WORK/repo/$PACKAGE/en-US"
cp "$ROOT/fdroid/metadata/$PACKAGE.yml" "$WORK/metadata/$PACKAGE.yml"
printf "\nAllowedAPKSigningKeys: '%s'\n" "$FINGERPRINT" >> "$WORK/metadata/$PACKAGE.yml"
cp "$ROOT/assets/baluard-lock-only-512.png" "$WORK/fdroid-icon.png"
cp "$ROOT/assets/baluard-lock-only-512.png" "$WORK/repo/$PACKAGE/en-US/icon.png"
# The index advertises icon="fdroid-icon.png" relative to the repo base, but
# fdroidserver never copies the repo icon into the served tree itself.
cp "$WORK/fdroid-icon.png" "$WORK/repo/fdroid-icon.png"
TARGET="$WORK/repo/${PACKAGE}_${VERSION_CODE}.apk"
if [[ -f "$TARGET" ]] && ! cmp -s "$APK" "$TARGET"; then
  echo "WARNING: replacing an APK with the same versionCode ($VERSION_CODE); installed clients will not update" >&2
fi
cp "$APK" "$TARGET"

mapfile -t APKS < <(find "$WORK/repo" -maxdepth 1 -type f -name "${PACKAGE}_*.apk" -printf '%f\n' | sort -t_ -k2,2n)
while ((${#APKS[@]} > RETENTION)); do
  rm -f -- "$WORK/repo/${APKS[0]}"
  APKS=("${APKS[@]:1}")
done

INPUT_STAMP="$({ sha256sum "$APK" "$WORK/config.yml" "$WORK/metadata/$PACKAGE.yml" "$WORK/fdroid-icon.png" "$WORK/repo/$PACKAGE/en-US/icon.png"; printf '%s\n' "${APKS[@]}"; } | sha256sum | awk '{print $1}')"
if [[ ! -f "$WORK/repo/index-v2.json" || ! -f "$WORK/.last-inputs.sha256" ]] || [[ "$(<"$WORK/.last-inputs.sha256")" != "$INPUT_STAMP" ]]; then
  (
    cd "$WORK"
    "$FDROID" update
  )
  printf '%s\n' "$INPUT_STAMP" > "$WORK/.last-inputs.sha256"
fi
printf '%s\n' "$FINGERPRINT" > "$WORK/allowed-apk-signing-key"
chmod 600 "$WORK/allowed-apk-signing-key"

mkdir -p "$OUT"
rsync -a --delete --delete-excluded --exclude=/status/ "$WORK/repo/" "$OUT/"
echo "F-Droid repository staged at $OUT"
