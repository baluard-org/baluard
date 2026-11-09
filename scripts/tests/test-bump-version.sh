#!/usr/bin/env bash
# Hermetic test for scripts/bump-version.sh. Sandbox repo copy with every
# version source plus a browser/shared dir and a fake npm that records the
# dist rebuild the bump triggers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$SANDBOX/browser/shared" "$SANDBOX/desktop/src-tauri" \
  "$SANDBOX/mobile/androidApp" "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n" \
  "$TMP/bin"
cp "$ROOT/scripts/bump-version.sh" "$SANDBOX/scripts/"
chmod +x "$SANDBOX/scripts/bump-version.sh"
cp "$ROOT/Cargo.toml" "$SANDBOX/Cargo.toml"
cp "$ROOT/desktop/src-tauri/Cargo.toml" "$SANDBOX/desktop/src-tauri/Cargo.toml"
cp "$ROOT/desktop/package.json" "$SANDBOX/desktop/package.json"
cp "$ROOT/mobile/androidApp/build.gradle.kts" "$SANDBOX/mobile/androidApp/"
cp "$ROOT/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsEn.kt" \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/"
cp "$ROOT/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsEs.kt" \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/"
cp "$ROOT/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsFr.kt" \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/"
cp "$ROOT/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsPt.kt" \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/"
# Simulate the drift that shipped: Fr stale at an old version, Pt a bare
# label. The bump must key on the settings.version key, not on any version
# literal, so both shapes land on the new version.
sed -i 's|Baluard Mobile v[0-9.]*|Baluard Mobile v0.1.0|' \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsFr.kt"
sed -i 's|"settings.version" to "[^"]*"|"settings.version" to "Versao"|' \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsPt.kt"
cp "$ROOT/browser/shared/package.json" "$SANDBOX/browser/shared/package.json"
cp "$ROOT/browser/shared/manifest.base.json" "$SANDBOX/browser/shared/"

cat > "$TMP/bin/npm" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo "\$*" >> "$TMP/npm.log"
EOF
chmod +x "$TMP/bin/npm"

export PATH="$TMP/bin:$PATH"
export SANDBOX

run_bump() {
  (cd "$SANDBOX" && ./scripts/bump-version.sh "$@")
}

expect_new() {
  if ! grep -q "$2" "$SANDBOX/$1"; then
    echo "$1: $2" >&2
    exit 1
  fi
}

# The fixture copies the real root Cargo.toml, so the bump target must be
# derived from the workspace version; a hardcoded one silently becomes a
# downgrade the next time the workspace moves past it.
CUR="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)"
IFS=. read -r B_MA B_MI B_PA <<< "$CUR"
BUMP="$B_MA.$B_MI.$((10#$B_PA + 1))"
VCODE=$((10#$B_MA * 1000000 + 10#$B_MI * 1000 + 10#$B_PA + 1))

# ── Happy path: every source moves together ──────────────────────────────────
run_bump "$BUMP" > "$TMP/happy.out" 2> "$TMP/happy.err"

expect_new Cargo.toml "^version = \"$BUMP\"$"
expect_new desktop/src-tauri/Cargo.toml "^version = \"$BUMP\"$"
expect_new desktop/package.json "\"version\": \"$BUMP\""
expect_new browser/shared/package.json "\"version\": \"$BUMP\""
expect_new browser/shared/manifest.base.json "\"version\": \"$BUMP\""
expect_new mobile/androidApp/build.gradle.kts "versionName = \"$BUMP\""
# versionCode derives from the bumped semver, 3 digits per component.
expect_new mobile/androidApp/build.gradle.kts "versionCode = $VCODE"
expect_new mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsEn.kt "Baluard Mobile v$BUMP"
expect_new mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsEs.kt "Baluard Mobile v$BUMP"
expect_new mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsFr.kt "Baluard Mobile v$BUMP"
expect_new mobile/shared/src/commonMain/kotlin/app/baluard/mobile/i18n/StringsPt.kt "Baluard Mobile v$BUMP"

# The bump rebuilds the committed extension dists (B11).
if [[ ! -s "$TMP/npm.log" ]]; then
  echo "dist rebuild (npm) did not run" >&2
  exit 1
fi
grep -q '^run build$' "$TMP/npm.log" \
  || { echo "npm run build missing from dist rebuild" >&2; exit 1; }

# ── Refuses a non-semver version without mutating anything ────────────────────
: > "$TMP/npm.log"
if run_bump 1.0 2> "$TMP/bad.err"; then
  echo "non-semver version must fail" >&2
  exit 1
fi
grep -qi "semver" "$TMP/bad.err" || { echo "non-semver error unexplained" >&2; exit 1; }
if [[ -s "$TMP/npm.log" ]]; then
  echo "dist rebuild ran despite bad version" >&2
  exit 1
fi

# ── Refuses a leading-zero component (semver clause 2, bash octal trap) ──────
if run_bump 0.08.0 2> "$TMP/zero.err"; then
  echo "leading-zero version must fail" >&2
  exit 1
fi

# ── Refuses a downgrade ───────────────────────────────────────────────────────
if run_bump 0.0.1 2> "$TMP/down.err"; then
  echo "downgrade must fail" >&2
  exit 1
fi
grep -qi "higher" "$TMP/down.err" || { echo "downgrade error unexplained" >&2; exit 1; }
expect_new Cargo.toml "^version = \"$BUMP\"$"

# ── Same-version rerun is also refused ────────────────────────────────────────
if run_bump "$CUR" 2> "$TMP/same.err"; then
  echo "same-version rerun must fail" >&2
  exit 1
fi

echo "PASS: bump-version.sh"
