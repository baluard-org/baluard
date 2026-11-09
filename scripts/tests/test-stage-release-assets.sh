#!/usr/bin/env bash
# Hermetic tests for scripts/stage-release-assets.sh (stable-name release staging).
# Pattern: temp sandbox, the script under test copied to scripts/, fake npx shim
# first on PATH, assertions on the staged set, then a PASS line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="$SCRIPT_DIR/../stage-release-assets.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BIN="$TMP/bin"
mkdir -p "$BIN"
cat > "$BIN/npx" <<'EOF'
#!/usr/bin/env bash
echo "npx $*" >> "$SHIM_LOG"
# `npx --yes @tauri-apps/cli@X signer sign FILE` -> write FILE.sig
if [[ "${4:-}" == "sign" && -n "${5:-}" ]]; then
  printf -- "--- FAKE SIG: %s\n" "$5" > "$5.sig"
fi
exit 0
EOF
chmod +x "$BIN/npx"

# Hermetic key: never touch the real ~/.tauri key, and never let an inherited
# TAURI_SIGNING_PRIVATE_KEY (checked first by the script) leak into the run
: > "$TMP/fake-updater-key"
export BALUARD_UPDATER_KEY="$TMP/fake-updater-key"
export BALUARD_TAURI_BIN="npx --yes @tauri-apps/cli@fake-signer"
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD

ART="$TMP/artifacts"
OUT="$TMP/release-upload"
VER=0.1.0

make_artifacts() {
  mkdir -p "$ART"
  : > "$ART/Baluard_${VER}_amd64.AppImage"
  : > "$ART/Baluard_${VER}_amd64.AppImage.sig"
  : > "$ART/Baluard_${VER}_amd64.deb"
  : > "$ART/Baluard_${VER}_amd64.deb.sig"
  : > "$ART/Baluard-${VER}-1.x86_64.rpm"
  : > "$ART/Baluard-${VER}-1.x86_64.rpm.sig"
  : > "$ART/baluard-${VER}-linux-amd64.tar.gz"
  : > "$ART/baluard-${VER}-linux-amd64.tar.gz.sig"
  : > "$ART/Baluard_${VER}_x64-setup.exe"
  : > "$ART/Baluard_${VER}_x64-setup.exe.sig"
  : > "$ART/baluard-extension-${VER}-chrome.zip"
  : > "$ART/baluard-extension-${VER}-firefox.zip"
  : > "$ART/baluard-extension-${VER}-chrome.zip.sig"
  : > "$ART/baluard-${VER}-macos-aarch64-non-notarized.zip"
  : > "$ART/SHA256SUMS"
  : > "$ART/SHA256SUMS.sig"
  : > "$ART/checksums.txt"
}

EXPECT=(
  Baluard-amd64.AppImage Baluard-amd64.AppImage.sig
  Baluard-amd64.deb Baluard-amd64.rpm
  Baluard-cli-amd64.tar.gz
  Baluard-amd64-setup.exe Baluard-amd64-setup.exe.sig
  Baluard-android.apk
  Baluard-macos-aarch64-non-notarized.zip
  Baluard-extension-chrome.zip Baluard-extension-firefox.zip
  updater.pub SHA256SUMS SHA256SUMS.sig
)

check_set() {
  local expected_count=$#
  local actual_count
  actual_count="$(find "$OUT" -maxdepth 1 -type f | wc -l)"
  if [[ "$actual_count" -ne "$expected_count" ]]; then
    echo "FAIL: expected $expected_count files in output, got $actual_count:" >&2
    find "$OUT" -maxdepth 1 -type f >&2
    exit 1
  fi
  local f
  for f in "$@"; do
    if [[ ! -f "$OUT/$f" ]]; then
      echo "FAIL: missing staged file $f" >&2
      exit 1
    fi
  done
}

# --- Case 1: happy path (local dist layout + --apk) ---
make_artifacts
: > "$TMP/fake.apk"
SHIM_LOG="$TMP/npx.log"
export SHIM_LOG
PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --apk "$TMP/fake.apk" --output "$OUT" "$ART" > "$TMP/out1.log" 2>&1

check_set "${EXPECT[@]}"

# Copy semantics: the staged file must be an independent inode (a later
# in-place rewrite of dist/ must not mutate the staged copy)
src_inode="$(stat -c %i "$ART/Baluard_${VER}_amd64.AppImage")"
dst_inode="$(stat -c %i "$OUT/Baluard-amd64.AppImage")"
if [[ "$src_inode" == "$dst_inode" ]]; then
  echo "FAIL: staged AppImage aliases the source artifact (hardlink)" >&2
  exit 1
fi

# SHA256SUMS must list stable names only
if grep -q "$VER" "$OUT/SHA256SUMS"; then
  echo "FAIL: SHA256SUMS carries versioned names" >&2
  grep "$VER" "$OUT/SHA256SUMS" >&2
  exit 1
fi
if ! grep -q "Baluard-amd64.AppImage" "$OUT/SHA256SUMS"; then
  echo "FAIL: SHA256SUMS misses the AppImage entry" >&2
  exit 1
fi
if ! grep -q "updater.pub" "$OUT/SHA256SUMS"; then
  echo "FAIL: SHA256SUMS misses the updater.pub entry" >&2
  exit 1
fi

# SHA256SUMS got signed through the tauri CLI shim
if ! grep -q "signer sign .*SHA256SUMS" "$SHIM_LOG"; then
  echo "FAIL: SHA256SUMS was not signed" >&2
  cat "$SHIM_LOG" >&2
  exit 1
fi

# Per-asset sigs of non-updater artifacts must be dropped, updater sigs kept
if [[ -f "$OUT/Baluard-amd64.deb.sig" || -f "$OUT/Baluard-extension-chrome.zip.sig" ]]; then
  echo "FAIL: non-updater per-asset sigs leaked into the release set" >&2
  exit 1
fi

# --- Case 2: idempotent re-run ---
PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --apk "$TMP/fake.apk" --output "$OUT" "$ART" > "$TMP/out2.log" 2>&1
check_set "${EXPECT[@]}"

# --- Case 3: CI layout (windows CLI archive name, macos dmg) collision-free ---
rm -rf "$ART" "$OUT"
mkdir -p "$ART"
: > "$ART/baluard-cli-linux-x86_64.tar.gz"
: > "$ART/baluard-cli-macos-aarch64.tar.gz"
: > "$ART/Baluard_${VER}_aarch64.dmg"
: > "$ART/Baluard_${VER}_aarch64.app.tar.gz"
: > "$ART/Baluard_${VER}_aarch64.app.tar.gz.sig"
: > "$ART/baluard-cli-windows-x86_64.tar.gz"
PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --output "$OUT" "$ART" > "$TMP/out3.log" 2>&1
# The Windows CLI tarball is a release artifact since CLI self-update ships;
# it must be renamed in, not dropped or passed through unmapped.
check_set Baluard-cli-amd64.tar.gz Baluard-cli-darwin-arm64.tar.gz Baluard-arm64.dmg \
  Baluard-arm64.app.tar.gz Baluard-arm64.app.tar.gz.sig Baluard-cli-windows-x86_64.tar.gz \
  updater.pub SHA256SUMS SHA256SUMS.sig
if [[ ! -f "$OUT/Baluard-cli-windows-x86_64.tar.gz" ]]; then
  echo "FAIL: windows CLI tarball missing from the release set" >&2
  exit 1
fi
if [[ -f "$OUT/baluard-cli-windows-x86_64.tar.gz" ]]; then
  echo "FAIL: windows CLI tarball staged under its unmapped name" >&2
  exit 1
fi

# --- Case 4: target collision is a loud failure ---
rm -rf "$ART" "$OUT"
mkdir -p "$ART"
: > "$ART/baluard-${VER}-linux-amd64.tar.gz"
: > "$ART/baluard-cli-linux-x86_64.tar.gz"
if PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --output "$OUT" "$ART" > "$TMP/out4.log" 2>&1; then
  echo "FAIL: collision case must exit nonzero" >&2
  exit 1
fi
if ! grep -qi "collision" "$TMP/out4.log"; then
  echo "FAIL: collision error must name the problem" >&2
  cat "$TMP/out4.log" >&2
  exit 1
fi

# --- Case 5: unmapped artifact is a loud failure ---
rm -rf "$ART" "$OUT"
make_artifacts
: > "$ART/Baluard_0.0.9_amd64.deb"
if PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --apk "$TMP/fake.apk" --output "$OUT" "$ART" > "$TMP/out5.log" 2>&1; then
  echo "FAIL: unmapped artifact case must exit nonzero" >&2
  exit 1
fi
if ! grep -q "Baluard_0.0.9_amd64.deb" "$TMP/out5.log"; then
  echo "FAIL: unmapped error must name the stray file" >&2
  cat "$TMP/out5.log" >&2
  exit 1
fi
if [[ -d "$OUT" ]]; then
  echo "FAIL: a failed staging must leave no partial output dir" >&2
  exit 1
fi

# --- Case 5b: wrong arch or stale version must NOT pass the pinned rows ---
rm -rf "$ART" "$OUT"
mkdir -p "$ART"
: > "$ART/baluard-cli-linux-x86_64.tar.gz"
: > "$ART/Baluard_${VER}-1.aarch64.rpm"
: > "$ART/Baluard_0.0.9_aarch64.app.tar.gz"
: > "$ART/Baluard_${VER}_x64.dmg"
if PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --output "$OUT" "$ART" > "$TMP/out5b.log" 2>&1; then
  echo "FAIL: wrong-arch/stale-version artifacts must exit nonzero" >&2
  exit 1
fi
for stray in "aarch64.rpm" "0.0.9_aarch64.app.tar.gz" "x64.dmg"; do
  if ! grep -q "$stray" "$TMP/out5b.log"; then
    echo "FAIL: unmapped error must name the $stray stray" >&2
    cat "$TMP/out5b.log" >&2
    exit 1
  fi
done

# --- Case 5c: --require refuses an incomplete staged set ---
rm -rf "$ART" "$OUT"
mkdir -p "$ART"
: > "$ART/baluard-cli-linux-x86_64.tar.gz"
if PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --require "Baluard-amd64.deb,Baluard-amd64.AppImage" \
  --output "$OUT" "$ART" > "$TMP/out5c.log" 2>&1; then
  echo "FAIL: --require must fail when a required artifact is missing" >&2
  exit 1
fi
if ! grep -q "required artifacts missing" "$TMP/out5c.log"; then
  echo "FAIL: --require error must name the missing set" >&2
  cat "$TMP/out5c.log" >&2
  exit 1
fi

# --- Case 5d: an empty artifacts dir must stay a loud failure (the
# always-present updater.pub staging must not satisfy the mapped-set guard) ---
rm -rf "$ART" "$OUT"
mkdir -p "$ART"
if PATH="$BIN:$PATH" "$STAGE" \
  --version "$VER" --output "$OUT" "$ART" > "$TMP/out5d.log" 2>&1; then
  echo "FAIL: empty artifacts dir must exit nonzero" >&2
  exit 1
fi
if ! grep -q "no artifacts mapped" "$TMP/out5d.log"; then
  echo "FAIL: empty-dir error must name the guard" >&2
  cat "$TMP/out5d.log" >&2
  exit 1
fi
if [[ -d "$OUT" ]]; then
  echo "FAIL: a failed staging must leave no partial output dir" >&2
  exit 1
fi

# --- Case 6: missing updater key fails fast before staging ---
rm -rf "$ART" "$OUT"
make_artifacts
if PATH="$BIN:$PATH" BALUARD_UPDATER_KEY="$TMP/no-such-key" \
  "$STAGE" \
  --version "$VER" --output "$OUT" "$ART" > "$TMP/out6.log" 2>&1; then
  echo "FAIL: missing updater key must exit nonzero" >&2
  exit 1
fi
if [[ -d "$OUT" ]]; then
  echo "FAIL: staging must not run when the updater key is missing" >&2
  exit 1
fi

echo "PASS: test-stage-release-assets.sh"
