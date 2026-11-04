#!/usr/bin/env bash
# Stage the stable-name release set: hardlink versioned build artifacts into
# their unversioned download names, then sign SHA256SUMS with the updater key.
#
# GitHub's releases/latest/download/<file> resolves by exact filename, so the
# published release must carry one stable-named copy of each artifact. Build
# outputs keep their versioned names (the apt/dnf pools and the extension
# submit flow depend on them); only this staged set is uploaded to the release.
#
# usage: stage-release-assets.sh --version <X.Y.Z> [--apk <path>] \
#          [--output <dir>] <artifacts-dir>
set -euo pipefail

die() { echo "stage-release-assets: $*" >&2; exit 1; }

VER=""
APK=""
OUT=""
SRC=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VER="${2:?}"; shift 2 ;;
    --apk) APK="${2:?}"; shift 2 ;;
    --output) OUT="${2:?}"; shift 2 ;;
    -*) die "unknown option $1" ;;
    *) SRC="$1"; shift ;;
  esac
done
[[ -n "$VER" ]] || die "usage: $0 --version <X.Y.Z> [--apk <path>] [--output <dir>] <artifacts-dir>"
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must be X.Y.Z, got '$VER'"
[[ -n "$SRC" && -d "$SRC" ]] || die "artifacts dir missing: ${SRC:-<none>}"

KEY="${BALUARD_UPDATER_KEY:-$HOME/.tauri/baluard-updater.key}"
if [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  : # secret arrives as env (CI); the -k path form cannot decode the wrapped format
elif [[ -f "$KEY" ]]; then
  export TAURI_SIGNING_PRIVATE_KEY
  TAURI_SIGNING_PRIVATE_KEY="$(cat "$KEY")"
else
  die "updater key not found: set TAURI_SIGNING_PRIVATE_KEY or BALUARD_UPDATER_KEY"
fi

if [[ -z "$OUT" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  OUT="$ROOT/release-upload"
fi
rm -rf "$OUT"
mkdir -p "$OUT"

# target -> first source claiming it; a second claim is a mapping-table bug
declare -A MAP
claim() {
  local target="$1" source="$2"
  if [[ -n "${MAP[$target]:-}" ]]; then
    die "collision on $target: '${MAP[$target]}' and '$source' both map to it"
  fi
  MAP[$target]="$source"
}

shopt -s nullglob
unmapped=()
while IFS= read -r f; do
  b="$(basename "$f")"
  target=""
  case "$b" in
    "Baluard_${VER}_amd64.AppImage")          target="Baluard-amd64.AppImage" ;;
    "Baluard_${VER}_amd64.AppImage.sig")      target="Baluard-amd64.AppImage.sig" ;;
    "Baluard_${VER}_amd64.deb")               target="Baluard-amd64.deb" ;;
    "Baluard-${VER}"-*.rpm)                   target="Baluard-amd64.rpm" ;;
    "baluard-${VER}-linux-amd64.tar.gz" | "baluard-cli-linux-x86_64.tar.gz")
                                              target="Baluard-cli-amd64.tar.gz" ;;
    "baluard-cli-macos-aarch64.tar.gz")       target="Baluard-cli-darwin-arm64.tar.gz" ;;
    *.app.tar.gz.sig)                         target="Baluard-arm64.app.tar.gz.sig" ;;
    *.app.tar.gz)                             target="Baluard-arm64.app.tar.gz" ;;
    "Baluard_${VER}_x64-setup.exe")           target="Baluard-amd64-setup.exe" ;;
    "Baluard_${VER}_x64-setup.exe.sig")       target="Baluard-amd64-setup.exe.sig" ;;
    "baluard-extension-${VER}-chrome.zip")    target="Baluard-extension-chrome.zip" ;;
    "baluard-extension-${VER}-firefox.zip")   target="Baluard-extension-firefox.zip" ;;
    *.dmg)                                    target="Baluard-arm64.dmg" ;;
    # produced and consumed inside the repo trees; never uploaded
    *.deb.sig | *.rpm.sig | *.tar.gz.sig | *.zip.sig) ;;
    # Windows CLI tarball stays out of the release set: the NSIS installer
    # bundles the CLI and daemon; revisit when CI builds the installer
    baluard-cli-windows-*.tar.gz) ;;
    SHA256SUMS | SHA256SUMS.sig | checksums.txt) ;;
    *) unmapped+=("$b") ;;
  esac
  if [[ -n "$target" ]]; then
    claim "$target" "$b"
    ln "$f" "$OUT/$target" 2>/dev/null || cp -p "$f" "$OUT/$target"
  fi
done < <(find "$SRC" -type f)

if [[ -n "$APK" ]]; then
  [[ -f "$APK" ]] || die "--apk path not found: $APK"
  claim "Baluard-android.apk" "$(basename "$APK")"
  ln "$APK" "$OUT/Baluard-android.apk" 2>/dev/null || cp -p "$APK" "$OUT/Baluard-android.apk"
fi

if [[ ${#unmapped[@]} -gt 0 ]]; then
  die "unmapped artifacts in $SRC (extend the mapping table or remove them): ${unmapped[*]}"
fi
[[ ${#MAP[@]} -gt 0 ]] || die "no artifacts mapped from $SRC"

# Sorted for stable diffs; names only, no version strings survive
(cd "$OUT" && sha256sum ./* | sed 's| \./| |' | sort -k2 > SHA256SUMS)

echo "signing SHA256SUMS"
export TAURI_SIGNING_PRIVATE_KEY
npx --yes "@tauri-apps/cli@2.12.4" signer sign "$OUT/SHA256SUMS"

echo
echo "staged $((${#MAP[@]} + 2)) files in $OUT:"
ls -1 "$OUT"
