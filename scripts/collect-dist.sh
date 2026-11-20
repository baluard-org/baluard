#!/usr/bin/env bash
# Collect this release's desktop bundles into the dist staging dir and
# remove the previous release's loose files. The build legs never write
# dist/ themselves (only the macOS deliverable, ext-package, and the CLI
# archive do), so without this step release-sign signs stale-version
# strays and repo-stage packages them into every Linux tree. Refuses
# before deleting anything when a bundle is missing, so a partial build
# cannot destroy the staged set of the last run.
#
# usage: collect-dist.sh [dist-dir]   (default: <repo>/dist)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${1:-$ROOT/dist}"
VERSION="$(awk -F'"' '/^\[workspace.package\]/{section=1; next} section && /^version =/{print $2; exit}' "$ROOT/Cargo.toml")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || { echo "cannot read workspace version from $ROOT/Cargo.toml" >&2; exit 1; }
VERSION_CORE="${VERSION%%-*}"

BUNDLES=(
  "desktop/src-tauri/target/release/bundle/deb/Baluard_${VERSION}_amd64.deb"
  "desktop/src-tauri/target/release/bundle/rpm/Baluard-${VERSION}-1.x86_64.rpm"
  "desktop/src-tauri/target/release/bundle/appimage/Baluard_${VERSION}_amd64.AppImage"
  "desktop/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/Baluard_${VERSION}_x64-setup.exe"
)

missing=()
for b in "${BUNDLES[@]}"; do
  [[ -f "$ROOT/$b" ]] || missing+=("$b")
done
# The portable zip is a first-class download (site card links
# releases/latest/download/...), so a release without it must fail loudly:
# unlike the bundles it is written straight into dist/ by its own leg.
if [[ ! -f "$DIST/Baluard_${VERSION}_x64-portable.zip" ]]; then
  missing+=("$DIST/Baluard_${VERSION}_x64-portable.zip (run scripts/build-windows-portable.sh)")
fi
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "refusing to touch $DIST: missing bundles (run the build legs first):" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

mkdir -p "$DIST"
# Loose files of another release only: archive-*/ subtrees are recovery
# storage and versionless files (SHA256SUMS, checksums.txt) are refreshed
# downstream, so both stay.
stale=()
while IFS= read -r f; do
  v="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<<"${f##*/}" | head -n1 || true)"
  [[ -z "$v" || "$v" == "$VERSION_CORE" ]] || stale+=("$f")
done < <(find "$DIST" -maxdepth 1 -type f)
for f in "${stale[@]}"; do
  echo "removing stale $f"
  rm "$f"
done

for b in "${BUNDLES[@]}"; do
  cp -p "$ROOT/$b" "$DIST/"
  echo "collected $(basename "$b")"
done

echo "dist/ holds $VERSION: ${#stale[@]} stale files removed, 4 bundles collected"
