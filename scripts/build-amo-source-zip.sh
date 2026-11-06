#!/usr/bin/env bash
# Build the AMO source-code submission zip for Baluard's Firefox extension.
# Usage: build-amo-source-zip.sh <repo-root> <out-dir>
# Produces baluard-extension-<version>-source.zip containing exactly what a
# Mozilla reviewer needs: the browser/shared sources, the firefox manifest
# extra, the brand lock SVG the build derives icons from, LICENSE, a README
# with the pinned commit, and an executable build.sh reproducing the store
# zip from the source tree.
set -euo pipefail

ROOT="${1:?repo root required}"
OUT="${2:?out dir required}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/source"
git -C "$ROOT" archive "$COMMIT" browser/shared browser/firefox/manifest.extra.json assets/baluard-lock-only.svg LICENSE | tar -x -C "$STAGE/source"

cat > "$STAGE/source/README.md" <<EOF
# Baluard browser extension — source package

Source for the Firefox extension submitted to addons.mozilla.org,
version ${VERSION}, built from commit ${COMMIT} of
https://github.com/baluard-org/baluard.

## Build requirements

- Node.js 22 or newer and npm (any recent version).

## Build

\`\`\`bash
./build.sh
\`\`\`

The script runs \`npm ci\` inside \`browser/shared\` and then
\`npm run build:firefox\`, which produces \`browser/firefox/dist/\` with
\`manifest.json\` at its root, and zips it as
\`baluard-extension-${VERSION}-firefox.zip\`.

## Layout

- browser/shared — extension sources shared by all stores (manifest base,
  vite config, popup, background service worker, content and inline
  scripts, tests).
- browser/firefox/manifest.extra.json — Firefox-specific manifest keys
  (gecko id and data-collection declaration).
- assets/baluard-lock-only.svg — the brand mark the build derives all
  toolbar icons from at build time.
EOF

cat > "$STAGE/source/build.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/browser/shared"
command -v npm >/dev/null || { echo "npm is required" >&2; exit 1; }
npm ci
npm run build:firefox
cd ../firefox/dist
test -f manifest.json
OUT="baluard-extension-$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' manifest.json)-firefox.zip"
rm -f "$OUT"
zip -q -r "$OUT" .
mv "$OUT" "$SCRIPT_DIR/.."
echo "built $SCRIPT_DIR/../$OUT"
INNER
chmod +x "$STAGE/source/build.sh"

mkdir -p "$OUT"
ZIP="$OUT/baluard-extension-${VERSION}-source.zip"
rm -f "$ZIP"
(cd "$STAGE" && zip -q -r "$ZIP" source)
echo "$ZIP"
