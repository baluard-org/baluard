#!/usr/bin/env bash
# Hermetic test for scripts/generate-updates-manifest.mjs. Fake updater
# artifacts with base64 minisign signatures: the happy matrix, the
# version-substitution refusal, missing-signature refusal, duplicate-artifact
# refusal, stray-artifact refusal, and the v-prefix tolerance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SCRIPT="$ROOT/scripts/generate-updates-manifest.mjs"

# Emit a .sig whose base64 payload carries a minisign-shaped body with the
# given version in the trusted comment (the generator decodes base64 first).
make_sig() { # file version
  local file="$1" version="$2"
  printf 'untrusted comment: fake\ntrusted comment: version:%s\nB64SIG\n' "$version" \
    | base64 -w0 > "${file}.sig"
}

run() { # ...args ; captures exit code into RC, output into OUT
  set +e
  OUT=$(node "$SCRIPT" "$@" 2>&1)
  RC=$?
  set -e
}

check_fails() { # name
  if [[ $RC -eq 0 ]]; then
    echo "FAIL: $1 (expected nonzero exit), output: $OUT" >&2
    exit 1
  fi
}

check_passes() { # name
  if [[ $RC -ne 0 ]]; then
    echo "FAIL: $1 (expected success), output: $OUT" >&2
    exit 1
  fi
}

json_field() { # file -> jq-less field grab via node
  node -e "const m=require('$1'); console.log($2)"
}

# --- Happy matrix: one AppImage + one app.tar.gz, both signed for 0.2.0.
ART="$TMP/artifacts"
mkdir -p "$ART"
printf 'fake appimage' > "$ART/Baluard_0.2.0_amd64.AppImage"
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.2.0
printf 'fake mac bundle' > "$ART/baluard_0.2.0_aarch64.app.tar.gz"
make_sig "$ART/baluard_0.2.0_aarch64.app.tar.gz" 0.2.0
printf 'release notes' > "$TMP/notes.md"

run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/latest.json" --notes-file "$TMP/notes.md" --pub-date 2026-11-03T00:00:00Z
check_passes "happy matrix"

[[ $(json_field "$TMP/latest.json" "m.version") == "0.2.0" ]] || { echo "FAIL: version"; exit 1; }
[[ $(json_field "$TMP/latest.json" "m.pub_date") == "2026-11-03T00:00:00Z" ]] || { echo "FAIL: pub_date"; exit 1; }
[[ $(json_field "$TMP/latest.json" "m.notes") == "release notes" ]] || { echo "FAIL: notes"; exit 1; }
[[ $(json_field "$TMP/latest.json" "Object.keys(m.platforms).sort().join(',')") == "darwin-aarch64,linux-x86_64-appimage" ]] \
  || { echo "FAIL: platform keys must be installer-suffixed linux + bare darwin, got: $(json_field "$TMP/latest.json" "Object.keys(m.platforms)")"; exit 1; }
[[ $(json_field "$TMP/latest.json" "m.platforms['linux-x86_64-appimage'].url") \
   == "https://github.com/baluard-org/baluard/releases/download/0.2.0/Baluard_0.2.0_amd64.AppImage" ]] \
  || { echo "FAIL: artifact url"; exit 1; }

# --- v-prefix tolerated: same manifest, version without the v.
run --tag v0.2.0 --artifacts-dir "$ART" --out "$TMP/latest-v.json"
check_passes "v-prefix tag"
[[ $(json_field "$TMP/latest-v.json" "m.version") == "0.2.0" ]] || { echo "FAIL: v-prefix strip"; exit 1; }

# --- Version substitution: a signature signed for another version refuses.
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.1.0
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "version substitution must refuse"
[[ "$OUT" == *"signed for version 0.1.0, expected 0.2.0"* ]] || { echo "FAIL: substitution message"; exit 1; }
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.2.0

# --- Missing signature refuses.
rm "$ART/baluard_0.2.0_aarch64.app.tar.gz.sig"
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "missing signature must refuse"
make_sig "$ART/baluard_0.2.0_aarch64.app.tar.gz" 0.2.0

# --- Duplicate artifact (two AppImages) refuses.
printf 'second appimage' > "$ART/Baluard_other_amd64.AppImage"
make_sig "$ART/Baluard_other_amd64.AppImage" 0.2.0
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "duplicate AppImage must refuse"
rm "$ART/Baluard_other_amd64.AppImage" "$ART/Baluard_other_amd64.AppImage.sig"

# --- Stray updater-shaped artifact refuses (matrix drift guard).
printf 'windows build' > "$ART/Baluard_0.2.0_x64-setup.exe"
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "stray exe must refuse"
rm "$ART/Baluard_0.2.0_x64-setup.exe"

# --- Unknown flag refuses (typo guard).
run --tag 0.2.0 --artifact-dir "$ART" --out "$TMP/x.json"
check_fails "unknown flag must refuse"

# --- Happy path still green after the gauntlet.
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/final.json"
check_passes "final happy re-run"

echo "test-generate-updates-manifest: OK"
