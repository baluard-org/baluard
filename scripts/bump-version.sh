#!/usr/bin/env bash
# Bump the product version across every source that carries it, then rebuild
# the committed browser extension dists so they stay in sync (B11).
#
# Sources:
#   Cargo.toml                          [workspace.package] version (all crates
#                                       inherit via version.workspace = true)
#   desktop/src-tauri/Cargo.toml        desktop package version (drives the
#                                       deb/rpm/dmg filenames; its own workspace)
#   desktop/package.json                desktop UI package version
#   browser/shared/package.json         extension build package version
#   browser/shared/manifest.base.json   extension manifest version
#   mobile/androidApp/build.gradle.kts  versionName + versionCode
#   mobile/.../i18n/Strings{En,Es}.kt   mobile about-screen version string
#
# Cargo.lock refreshes on the next cargo build; it is never sed-edited.
#
# Usage: ./scripts/bump-version.sh 0.2.0
# Strict SemVer, no leading zeroes. The version must be higher than the
# current one; Chrome and the stores reject non-monotonic versions, so a
# downgrade fails here instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NEW="${1:-}"
if [[ ! "$NEW" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "usage: bump-version.sh <semver X.Y.Z (no leading zeroes)>, got: ${NEW:-<empty>}" >&2
  exit 1
fi

CARGO_TOML="Cargo.toml"
DESKTOP_CARGO_TOML="desktop/src-tauri/Cargo.toml"
DESKTOP_PKG="desktop/package.json"
EXT_PKG="browser/shared/package.json"
MANIFEST="browser/shared/manifest.base.json"
GRADLE="mobile/androidApp/build.gradle.kts"
STRINGS_EN="mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEn.kt"
STRINGS_ES="mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/i18n/StringsEs.kt"

CURRENT=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$CARGO_TOML" | head -1)
if [[ -z "$CURRENT" ]]; then
  echo "could not read current version from $CARGO_TOML" >&2
  exit 1
fi
if [[ "$(printf '%s\n%s\n' "$CURRENT" "$NEW" | sort -V | head -1)" != "$CURRENT" || "$CURRENT" == "$NEW" ]]; then
  echo "refusing to bump: $NEW is not higher than current $CURRENT" >&2
  exit 1
fi

command -v npm >/dev/null 2>&1 || { echo "missing tool: npm" >&2; exit 1; }

IFS=. read -r MAJOR MINOR PATCH <<< "$NEW"
VERSION_CODE=$((10#$MAJOR * 1000000 + 10#$MINOR * 1000 + 10#$PATCH))

# Rust: exactly one line-start `version = ` per Cargo.toml (verified).
sed -i "s/^version = \"[^\"]*\"\$/version = \"$NEW\"/" "$CARGO_TOML" "$DESKTOP_CARGO_TOML"

# JSON: line-start "version" only exists for the package itself; dependency
# versions are nested values.
for f in "$DESKTOP_PKG" "$EXT_PKG" "$MANIFEST"; do
  sed -i "s/^\(\s*\)\"version\": \"[^\"]*\"/\1\"version\": \"$NEW\"/" "$f"
done

# Android: versionName + derived versionCode (3 digits per component).
sed -i "s/versionName = \"[^\"]*\"/versionName = \"$NEW\"/; s/versionCode = [0-9]*/versionCode = $VERSION_CODE/" "$GRADLE"

# Mobile about-screen string.
sed -i "s/Baluard Mobile v[0-9][0-9.]*/Baluard Mobile v$NEW/" "$STRINGS_EN" "$STRINGS_ES"

# Verify every source actually moved; a miss means that file drifted.
check() {
  if ! grep -q "$2" "$1"; then
    echo "bump did not land in $1 (expected: $2)" >&2
    exit 1
  fi
}
check "$CARGO_TOML" "^version = \"$NEW\"\$"
check "$DESKTOP_CARGO_TOML" "^version = \"$NEW\"\$"
for f in "$DESKTOP_PKG" "$EXT_PKG" "$MANIFEST"; do
  check "$f" "\"version\": \"$NEW\""
done
check "$GRADLE" "versionName = \"$NEW\""
check "$GRADLE" "versionCode = $VERSION_CODE"
check "$STRINGS_EN" "Baluard Mobile v$NEW"
check "$STRINGS_ES" "Baluard Mobile v$NEW"

# B11: the committed store dists are reviewable artifacts; rebuild them now so
# the bump commit can carry fresh dists instead of drifting.
echo "Rebuilding extension dists (commit them with the version bump)..."
(cd browser/shared && npm install && npm run build)

echo "bumped $CURRENT -> $NEW (android versionCode $VERSION_CODE)"
echo "next: review and commit, then just ext-package if a store zip is due"
