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
  Baluard-extension-chrome.zip Baluard-extension-firefox.zip
  SHA256SUMS SHA256SUMS.sig
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

# Hardlink, not copy: inode must match the source artifact
src_inode="$(stat -c %i "$ART/Baluard_${VER}_amd64.AppImage")"
dst_inode="$(stat -c %i "$OUT/Baluard-amd64.AppImage")"
if [[ "$src_inode" != "$dst_inode" ]]; then
  echo "FAIL: staged AppImage is not a hardlink of the source" >&2
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
check_set Baluard-cli-amd64.tar.gz Baluard-cli-darwin-arm64.tar.gz Baluard-arm64.dmg \
  Baluard-arm64.app.tar.gz Baluard-arm64.app.tar.gz.sig SHA256SUMS SHA256SUMS.sig
if [[ -f "$OUT/baluard-cli-windows-x86_64.tar.gz" ]]; then
  echo "FAIL: windows CLI tarball must stay out of the release set" >&2
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
