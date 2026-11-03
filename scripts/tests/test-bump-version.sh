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
  "$SANDBOX/mobile/androidApp" "$SANDBOX/mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n" \
  "$TMP/bin"
cp "$ROOT/scripts/bump-version.sh" "$SANDBOX/scripts/"
chmod +x "$SANDBOX/scripts/bump-version.sh"
cp "$ROOT/Cargo.toml" "$SANDBOX/Cargo.toml"
cp "$ROOT/desktop/src-tauri/Cargo.toml" "$SANDBOX/desktop/src-tauri/Cargo.toml"
cp "$ROOT/desktop/package.json" "$SANDBOX/desktop/package.json"
cp "$ROOT/mobile/androidApp/build.gradle.kts" "$SANDBOX/mobile/androidApp/"
cp "$ROOT/mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEn.kt" \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/"
cp "$ROOT/mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEs.kt" \
  "$SANDBOX/mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/"
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

# ── Happy path: every source moves together ──────────────────────────────────
run_bump 0.2.0 > "$TMP/happy.out" 2> "$TMP/happy.err"

expect_new Cargo.toml '^version = "0.2.0"$'
expect_new desktop/src-tauri/Cargo.toml '^version = "0.2.0"$'
expect_new desktop/package.json '"version": "0.2.0"'
expect_new browser/shared/package.json '"version": "0.2.0"'
expect_new browser/shared/manifest.base.json '"version": "0.2.0"'
expect_new mobile/androidApp/build.gradle.kts 'versionName = "0.2.0"'
# versionCode derives from semver, 3 digits per component: 0.2.0 -> 2000.
expect_new mobile/androidApp/build.gradle.kts 'versionCode = 2000'
expect_new mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEn.kt 'Baluard Mobile v0.2.0'
expect_new mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEs.kt 'Baluard Mobile v0.2.0'

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
if run_bump 0.1.0 2> "$TMP/down.err"; then
  echo "downgrade must fail" >&2
  exit 1
fi
grep -qi "higher" "$TMP/down.err" || { echo "downgrade error unexplained" >&2; exit 1; }
expect_new Cargo.toml '^version = "0.2.0"$'

# ── Same-version rerun is also refused ────────────────────────────────────────
if run_bump 0.2.0 2> "$TMP/same.err"; then
  echo "same-version rerun must fail" >&2
  exit 1
fi

echo "PASS: bump-version.sh"
