#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/home" "$TMP/out"
printf 'apk\n' > "$TMP/androidApp-release.apk"
printf '9cdf3df5ef4a228d51cc5bfabaa303d65bd534c306c12aa0a8857cea223130ff\n' > "$TMP/expected-key"

cat > "$TMP/bin/fdroid" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FDROID_TEST_LOG"
if [[ "$1" == init ]]; then
  printf 'keystorepass: secret\nkeypass: secret\nkeydname: CN=baluard, OU=F-Droid\nrepo_url: old\n' > config.yml
  printf 'key\n' > keystore.p12
elif [[ "$1" == update ]]; then
  mkdir -p repo/status repo/diff
  printf 'index\n' > repo/index-v2.json
  printf 'entry\n' > repo/entry.jar
  printf 'private paths\n' > repo/status/update.json
  printf 'diff\n' > "repo/diff/$(date +%s%N).json"
fi
EOF
cat > "$TMP/bin/keytool" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KEYTOOL_TEST_LOG"
if [[ "$1" == -genkeypair ]]; then
  printf 'regenerated\n' > "$KEYTOOL_FAKE_STORE"
fi
EOF
cat > "$TMP/bin/apksigner" <<'EOF'
#!/usr/bin/env bash
printf 'Signer #1 certificate SHA-256 digest: 9CDF3DF5EF4A228D51CC5BFABAA303D65BD534C306C12AA0A8857CEA223130FF\n'
EOF
cat > "$TMP/bin/aapt" <<'EOF'
#!/usr/bin/env bash
printf "package: name='%s' versionCode='%s' versionName='0.1.0'\n" "${FAKE_PACKAGE:-app.baluard.mobile}" "${FAKE_VERSION_CODE:-1}"
EOF
chmod +x "$TMP/bin/fdroid" "$TMP/bin/apksigner" "$TMP/bin/aapt" "$TMP/bin/keytool"

export HOME="$TMP/home"
export PATH="$TMP/bin:$PATH"
export FDROID_TEST_LOG="$TMP/fdroid.log"
export KEYTOOL_TEST_LOG="$TMP/keytool.log"
export KEYTOOL_FAKE_STORE="$TMP/work/keystore.p12"
export BALUARD_FDROID_HOME="$TMP/work"
export BALUARD_FDROID_EXPECTED_SIGNING_KEY="$TMP/expected-key"
export ANDROID_HOME="$TMP/sdk"
export APKSIGNER="$TMP/bin/apksigner"
export AAPT="$TMP/bin/aapt"
export FDROID_PYTHON=python3
mkdir -p "$ANDROID_HOME"

"$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out"

grep -q "AllowedAPKSigningKeys: '9cdf3df5ef4a228d51cc5bfabaa303d65bd534c306c12aa0a8857cea223130ff'" "$TMP/work/metadata/app.baluard.mobile.yml"
grep -q 'https://baluard.app/fdroid/repo' "$TMP/work/config.yml"
grep -q 'keystorepass: secret' "$TMP/work/config.yml"
grep -q 'repo_url: old' "$TMP/work/config.yml.backup"
grep -q 'keydname: CN=Baluard, O=Baluard Org, C=CL' "$TMP/work/config.yml"
grep -q -- '-dname CN=Baluard, O=Baluard Org, C=CL' "$TMP/keytool.log"
grep -q -- '-alias baluard' "$TMP/keytool.log"
grep -q 'regenerated' "$TMP/work/keystore.p12"
test "$(stat -c %a "$TMP/work/config.yml")" = 600
test "$(stat -c %a "$TMP/work/config.yml.backup")" = 600
test "$(stat -c %a "$TMP/work/keystore.p12")" = 600
test "$(stat -c %a "$TMP/work/allowed-apk-signing-key")" = 600
test -f "$TMP/work/repo/app.baluard.mobile_1.apk"
test -f "$TMP/work/repo/app.baluard.mobile/en-US/icon.png"
test -f "$TMP/work/repo/fdroid-icon.png"
test ! -e "$TMP/work/repo/androidApp-release.apk"
test -f "$TMP/out/index-v2.json"
test ! -e "$TMP/out/config.yml"
test ! -e "$TMP/out/keystore.p12"
test ! -e "$TMP/out/status"
printf 'stale\n' > "$TMP/out/stale"

updates_before="$(grep -c '^update$' "$FDROID_TEST_LOG")"
"$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out"
test "$(grep -c '^update$' "$FDROID_TEST_LOG")" = "$updates_before"
test ! -e "$TMP/out/stale"

printf 'replacement\n' > "$TMP/androidApp-release.apk"
"$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out" 2> "$TMP/replacement.err"
grep -q 'same versionCode' "$TMP/replacement.err"
test "$(find "$TMP/work/repo" -maxdepth 1 -name '*.apk' | wc -l)" = 1
test "$(cat "$TMP/work/repo/app.baluard.mobile_1.apk")" = replacement

for version in 2 3 4; do
  printf 'version-%s\n' "$version" > "$TMP/androidApp-release.apk"
  FAKE_VERSION_CODE="$version" "$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out"
done
test "$(find "$TMP/work/repo" -maxdepth 1 -name '*.apk' | wc -l)" = 3
test ! -e "$TMP/work/repo/app.baluard.mobile_1.apk"
test -f "$TMP/work/repo/app.baluard.mobile_4.apk"

printf 'different\n' > "$TMP/expected-key"
if "$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out" 2> "$TMP/mismatch.err"; then
  echo 'expected an APK signing-certificate mismatch to fail' >&2
  exit 1
fi
grep -q 'certificate changed' "$TMP/mismatch.err"
cp "$ROOT/fdroid/allowed-signing-key.sha256" "$TMP/expected-key"

if FAKE_PACKAGE=wrong.package "$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out" 2> "$TMP/package.err"; then
  echo 'expected a wrong application ID to fail' >&2
  exit 1
fi
grep -q 'application ID' "$TMP/package.err"

rm "$TMP/work/keystore.p12"
if "$ROOT/scripts/build-fdroid-repo.sh" "$TMP/androidApp-release.apk" "$TMP/out" 2>/dev/null; then
  echo 'expected incomplete repository initialization to fail' >&2
  exit 1
fi

printf 'PASS: build-fdroid-repo.sh\n'
