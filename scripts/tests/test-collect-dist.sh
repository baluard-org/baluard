#!/usr/bin/env bash
# Hermetic tests for scripts/collect-dist.sh (dist staging collection).
# Pattern: temp sandbox, the script under test copied into the sandbox's
# scripts/ dir, a fake repo layout (Cargo.toml plus the four bundle paths),
# assertions on the collected set, then a PASS line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

setup_repo() {
  rm -rf "$TMP/scripts" "$TMP/dist"
  mkdir -p "$TMP/scripts" "$TMP/dist"
  cp "$SCRIPT_DIR/../collect-dist.sh" "$TMP/scripts/"
  cat > "$TMP/Cargo.toml" <<'EOF'
[workspace.package]
version = "0.7.3"
edition = "2024"
EOF
  local base="$TMP/desktop/src-tauri/target"
  mkdir -p "$base/release/bundle/deb" "$base/release/bundle/rpm" \
    "$base/release/bundle/appimage" \
    "$base/x86_64-pc-windows-msvc/release/bundle/nsis"
  echo deb-body > "$base/release/bundle/deb/Baluard_0.7.3_amd64.deb"
  echo rpm-body > "$base/release/bundle/rpm/Baluard-0.7.3-1.x86_64.rpm"
  echo appimage-body > "$base/release/bundle/appimage/Baluard_0.7.3_amd64.AppImage"
  echo exe-body > "$base/x86_64-pc-windows-msvc/release/bundle/nsis/Baluard_0.7.3_x64-setup.exe"
}

seed_stale_dist() {
  : > "$TMP/dist/Baluard_0.7.2_amd64.deb"
  : > "$TMP/dist/Baluard_0.7.2_amd64.deb.sig"
  : > "$TMP/dist/Baluard-0.7.2-1.x86_64.rpm"
  : > "$TMP/dist/Baluard_0.7.2_amd64.AppImage"
  : > "$TMP/dist/Baluard_0.7.2_x64-setup.exe"
  : > "$TMP/dist/baluard-0.7.2-linux-amd64.tar.gz"
  mkdir -p "$TMP/dist/archive-0.7.2"
  : > "$TMP/dist/archive-0.7.2/Baluard_0.7.2_amd64.deb"
  echo old-sums > "$TMP/dist/SHA256SUMS"
  echo old-checksums > "$TMP/dist/checksums.txt"
}

# 1. Copies the four bundles, purges stale loose files, keeps archives
#    and versionless files.
setup_repo
seed_stale_dist
"$TMP/scripts/collect-dist.sh" > /dev/null 2>&1 || fail "collect failed on the happy path"
cmp -s "$TMP/dist/Baluard_0.7.3_amd64.deb" <(echo deb-body) || fail "deb not copied"
cmp -s "$TMP/dist/Baluard-0.7.3-1.x86_64.rpm" <(echo rpm-body) || fail "rpm not copied"
cmp -s "$TMP/dist/Baluard_0.7.3_amd64.AppImage" <(echo appimage-body) || fail "AppImage not copied"
cmp -s "$TMP/dist/Baluard_0.7.3_x64-setup.exe" <(echo exe-body) || fail "setup exe not copied"
[[ ! -e "$TMP/dist/Baluard_0.7.2_amd64.deb" ]] || fail "stale deb survived"
[[ ! -e "$TMP/dist/Baluard_0.7.2_amd64.deb.sig" ]] || fail "stale sig survived"
[[ ! -e "$TMP/dist/baluard-0.7.2-linux-amd64.tar.gz" ]] || fail "stale cli tar survived"
[[ -f "$TMP/dist/archive-0.7.2/Baluard_0.7.2_amd64.deb" ]] || fail "archive-* must be preserved"
grep -q old-sums "$TMP/dist/SHA256SUMS" || fail "versionless SHA256SUMS must be kept for release-sign to refresh"
grep -q old-checksums "$TMP/dist/checksums.txt" || fail "versionless checksums.txt must be kept"
echo "ok 1: copies four bundles, purges stale, keeps archive and versionless files"

# 2. A missing bundle refuses BEFORE deleting anything: the stale set
#    survives for the next attempt.
setup_repo
seed_stale_dist
rm "$TMP/desktop/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/Baluard_0.7.3_x64-setup.exe"
rc=0
out="$(TMPDIR="$TMP" "$TMP/scripts/collect-dist.sh" 2>&1)" || rc=$?
[[ $rc -ne 0 ]] || fail "missing bundle must fail the run"
grep -q "Baluard_0.7.3_x64-setup.exe" <<<"$out" || fail "refusal must name the missing bundle"
[[ -f "$TMP/dist/Baluard_0.7.2_amd64.deb" ]] || fail "stale set must survive a failed collect"
[[ ! -e "$TMP/dist/Baluard_0.7.3_amd64.deb" ]] || fail "nothing may be copied on a failed collect"
echo "ok 2: missing bundle refuses before deleting"

# 3. A fresh dist gets a pure copy, no stale handling needed.
setup_repo
"$TMP/scripts/collect-dist.sh" > /dev/null 2>&1 || fail "collect failed on a fresh dist"
[[ -f "$TMP/dist/Baluard_0.7.3_amd64.deb" ]] || fail "deb missing after fresh collect"
[[ -f "$TMP/dist/Baluard_0.7.3_x64-setup.exe" ]] || fail "exe missing after fresh collect"
echo "ok 3: fresh dist collects cleanly"

# 4. No sources at all refuses naming every missing bundle.
setup_repo
rm -rf "$TMP/desktop"
rc=0
out="$(TMPDIR="$TMP" "$TMP/scripts/collect-dist.sh" 2>&1)" || rc=$?
[[ $rc -ne 0 ]] || fail "all-sources-missing must fail"
for f in Baluard_0.7.3_amd64.deb Baluard-0.7.3-1.x86_64.rpm \
  Baluard_0.7.3_amd64.AppImage Baluard_0.7.3_x64-setup.exe; do
  grep -q "$f" <<<"$out" || fail "refusal must name $f"
done
echo "ok 4: missing sources all named"

# 5. An explicit dist argument is honored (the justfile passes one).
setup_repo
mkdir -p "$TMP/other-dist"
"$TMP/scripts/collect-dist.sh" "$TMP/other-dist" > /dev/null 2>&1 \
  || fail "collect failed with an explicit dist"
[[ -f "$TMP/other-dist/Baluard_0.7.3_amd64.deb" ]] || fail "explicit dist argument ignored"
echo "ok 5: explicit dist argument honored"

echo "PASS test-collect-dist"
