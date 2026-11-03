#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Run the packaging script against a sandbox copy of the repository so the
# real worktree, its committed dists, and its npm are never touched.
SANDBOX="$TMP/repo"
ART="$TMP/staging"
mkdir -p "$SANDBOX/scripts" "$ART" "$TMP/bin"
cp "$ROOT/scripts/build-extension-packages.sh" "$SANDBOX/scripts/"

git init -q "$SANDBOX"
mkdir -p "$SANDBOX/browser/shared"

# Fake npm: `install` is a no-op, `run build` writes deterministic dist
# content for both stores. Knobs drive the failure cases.
cat > "$TMP/bin/npm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == install ]] && exit 0
[[ "$1 $2" == "run build" ]] || { echo "unexpected npm invocation: $*" >&2; exit 64; }
[[ "${EXT_TEST_NO_BUILD:-0}" == 1 ]] && exit 0
write() {
  local dir="$1" version="$2"
  mkdir -p "$dir/icons"
  printf 'background\n' > "$dir/background.js"
  printf 'popup\n' > "$dir/popup.html"
  printf 'icon\n' > "$dir/icons/icon-16.png"
  printf '{"manifest_version": 3, "name": "Baluard", "version": "%s"}\n' "$version" > "$dir/manifest.json"
}
write "${EXT_TEST_SANDBOX}/browser/chrome/dist" "${EXT_TEST_VERSION:-0.1.0}"
write "${EXT_TEST_SANDBOX}/browser/firefox/dist" "${EXT_TEST_FF_VERSION:-${EXT_TEST_VERSION:-0.1.0}}"
EOF
chmod +x "$TMP/bin/npm"
export PATH="$TMP/bin:$PATH"
export EXT_TEST_SANDBOX="$SANDBOX"

# Build the dists with the same writer the npm shim uses, then commit them,
# mirroring the B11 flow: committed dists always match a shared-source build.
commit_dists() {
  local version="$1" ff="${2:-$1}"
  EXT_TEST_VERSION="$version" EXT_TEST_FF_VERSION="$ff" "$TMP/bin/npm" run build
  git -C "$SANDBOX" add browser
  git -C "$SANDBOX" diff --cached --quiet || \
    git -C "$SANDBOX" -c user.email=test@test -c user.name=test commit -qm "dists $version"
}

run_pkg() {
  "$SANDBOX/scripts/build-extension-packages.sh" "$ART"
}

# ── Missing dists: build produced nothing ────────────────────────────────────
# Nothing committed and the shim build writes nothing, so the drift gate is
# quiet and the script must catch the absent manifest itself.
if EXT_TEST_NO_BUILD=1 run_pkg 2> "$TMP/missing.err"; then
  echo 'expected missing dists to fail packaging' >&2
  exit 1
fi
grep -qi 'manifest.json' "$TMP/missing.err"

# ── Happy path ───────────────────────────────────────────────────────────────
commit_dists 0.1.0
run_pkg > "$TMP/happy.out"
test -f "$ART/baluard-extension-0.1.0-chrome.zip"
test -f "$ART/baluard-extension-0.1.0-firefox.zip"

for store in chrome firefox; do
  zip="$ART/baluard-extension-0.1.0-$store.zip"
  unzip -l "$zip" | grep -q 'manifest.json'
  test "$(unzip -p "$zip" manifest.json | jq -r .version)" = 0.1.0
  test "$(unzip -p "$zip" background.js)" = background
done
grep -q 'baluard-extension-0.1.0-chrome.zip' "$TMP/happy.out"

# ── Drift: rebuilt dists differ from the committed ones ─────────────────────
rm -f "$ART"/*.zip
# Shim writes 0.1.1 while the committed dists say 0.1.0: a source edit whose
# rebuilt dists were never committed (the CI B11 gate, locally).
# Drift and mismatch cases invoke the sandbox script directly: an env-prefix
# on a bash function call persists afterward, which would leak the knob into
# every later case.
if EXT_TEST_VERSION=0.1.1 "$SANDBOX/scripts/build-extension-packages.sh" "$ART" 2> "$TMP/drift.err"; then
  echo 'expected dist drift to fail packaging' >&2
  exit 1
fi
grep -qi 'drift' "$TMP/drift.err"
test -z "$(find "$ART" -name '*.zip')"

# ── Store version mismatch ───────────────────────────────────────────────────
# Commit divergent store versions, then let the script's own build reproduce
# them exactly (the knob rides into the script's npm through the environment)
# so the drift gate stays quiet and the version gate fires.
commit_dists 0.1.0 9.9.9
if EXT_TEST_FF_VERSION=9.9.9 "$SANDBOX/scripts/build-extension-packages.sh" "$ART" 2> "$TMP/mismatch.err"; then
  echo 'expected a store version mismatch to fail packaging' >&2
  exit 1
fi
grep -qi 'version' "$TMP/mismatch.err"

# ── Re-run is safe; a new version adds zips without removing old ones ───────
commit_dists 0.1.0
run_pkg > /dev/null
run_pkg > /dev/null
test "$(find "$ART" -name '*.zip' | wc -l)" = 2
commit_dists 0.1.1
# The knob mirrors bumping manifest.base.json: source and committed dists move together.
EXT_TEST_VERSION=0.1.1 "$SANDBOX/scripts/build-extension-packages.sh" "$ART" > /dev/null
test -f "$ART/baluard-extension-0.1.1-chrome.zip"
test -f "$ART/baluard-extension-0.1.1-firefox.zip"
test "$(find "$ART" -name '*.zip' | wc -l)" = 4

printf 'PASS: build-extension-packages.sh\n'
