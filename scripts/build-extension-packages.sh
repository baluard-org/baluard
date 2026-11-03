#!/usr/bin/env bash
# Package the browser extension store uploads. Rebuilds both dists from
# browser/shared, refuses to package when the rebuilt dists differ from the
# committed ones (the same drift gate extension.yml enforces in CI), then
# zips each store dist into the artifacts staging dir as
# baluard-extension-<version>-<store>.zip.
set -euo pipefail

ART="${1:?usage: build-extension-packages.sh <artifacts-dir>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for tool in npm jq zip git; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

mkdir -p "$ART"
ART=$(cd "$ART" && pwd)

cd "$ROOT/browser/shared"
npm install
npm run build

cd "$ROOT"
drift="$(git status --porcelain -- browser/chrome/dist browser/firefox/dist)"
if [[ -n "$drift" ]]; then
  echo "extension dists drifted from browser/shared after rebuild:" >&2
  printf '%s\n' "$drift" >&2
  echo "commit the rebuilt dists (or fix the source) before packaging" >&2
  exit 1
fi

version=""
for store in chrome firefox; do
  manifest="browser/$store/dist/manifest.json"
  [[ -f "$manifest" ]] || { echo "missing $manifest; the build failed silently" >&2; exit 1; }
  store_version="$(jq -er '.version | select(type == "string" and length > 0)' "$manifest")" \
    || { echo "$manifest has no version" >&2; exit 1; }
  if [[ -n "$version" && "$version" != "$store_version" ]]; then
    echo "store versions disagree: chrome=$version firefox=$store_version" >&2
    exit 1
  fi
  version="$store_version"
done

for store in chrome firefox; do
  zip="$ART/baluard-extension-$version-$store.zip"
  (cd "browser/$store/dist" && zip -q -r "$zip" .)
  echo "packaged $zip"
done
