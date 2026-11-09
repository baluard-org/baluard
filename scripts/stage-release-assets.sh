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
#          [--output <dir>] [--require name1,name2,...] <artifacts-dir>
set -euo pipefail

die() { echo "stage-release-assets: $*" >&2; exit 1; }

VER=""
APK=""
OUT=""
SRC=""
REQUIRE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VER="${2:?}"; shift 2 ;;
    --apk) APK="${2:?}"; shift 2 ;;
    --output) OUT="${2:?}"; shift 2 ;;
    --require) REQUIRE="${2:?}"; shift 2 ;;
    -*) die "unknown option $1" ;;
    *) SRC="$1"; shift ;;
  esac
done
[[ -n "$VER" ]] || die "usage: $0 --version <X.Y.Z> [--apk <path>] [--output <dir>] [--require names] <artifacts-dir>"
# prerelease suffixes (-beta.1) are legal; the tag policy is no v prefix
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version must be X.Y.Z[-suffix], got '$VER'"
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
# default to the empty password (the release key is unencrypted) so the signer
# never prompts; ${VAR-} leaves a caller-provided password untouched
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -z "$OUT" ]]; then
  OUT="$ROOT/release-upload"
fi
# rm -rf guard: the output must not eat the sources (or the world)
SRC_ABS="$(realpath "$SRC")"
OUT_ABS="$(realpath -m "$OUT")"
if [[ "$OUT_ABS" == "$SRC_ABS" || "$OUT_ABS/" == "$SRC_ABS"/* || "$SRC_ABS/" == "$OUT_ABS"/* \
  || "$OUT_ABS" == "/" || "$OUT_ABS" == "$HOME" ]]; then
  die "refusing --output '$OUT': it overlaps the artifacts dir, /, or \$HOME"
fi
# a failed staging leaves nothing behind: EXIT trap checks the final status
# (an ERR trap would miss die()'s explicit exit)
cleanup() { local rc=$?; if (( rc != 0 )); then rm -rf "$OUT_ABS"; fi; }
trap cleanup EXIT
rm -rf "$OUT_ABS"
mkdir -p "$OUT_ABS"

# target -> first source claiming it; a second claim is a mapping-table bug
declare -A MAP=()
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
    "Baluard-${VER}"-*.x86_64.rpm)            target="Baluard-amd64.rpm" ;;
    "baluard-${VER}-linux-amd64.tar.gz" | "baluard-cli-linux-x86_64.tar.gz")
                                              target="Baluard-cli-amd64.tar.gz" ;;
    "baluard-cli-macos-aarch64.tar.gz")       target="Baluard-cli-darwin-arm64.tar.gz" ;;
    *"${VER}"*aarch64.app.tar.gz.sig)         target="Baluard-arm64.app.tar.gz.sig" ;;
    *"${VER}"*aarch64.app.tar.gz)             target="Baluard-arm64.app.tar.gz" ;;
    "Baluard_${VER}_x64-setup.exe")           target="Baluard-amd64-setup.exe" ;;
    "Baluard_${VER}_x64-setup.exe.sig")       target="Baluard-amd64-setup.exe.sig" ;;
    "baluard-extension-${VER}-chrome.zip")    target="Baluard-extension-chrome.zip" ;;
    "baluard-extension-${VER}-firefox.zip")   target="Baluard-extension-firefox.zip" ;;
    # dev-smoke macOS build: ad-hoc signed, never notarized; published so
    # Mac users have something installable while release-grade signing
    # stays a known gap
    "baluard-${VER}-macos-aarch64-non-notarized.zip")
                                              target="Baluard-macos-aarch64-non-notarized.zip" ;;
    *"${VER}"*aarch64.dmg)                    target="Baluard-arm64.dmg" ;;
    # produced and consumed inside the repo trees; never uploaded
    *.deb.sig | *.rpm.sig | *.tar.gz.sig | *.zip.sig) ;;
    # CLI/daemon archive consumed by `baluard self-update` and the mise
    # github backend; named with os+arch tokens so both matchers resolve it
    "baluard-cli-windows-x86_64.tar.gz")          target="Baluard-cli-windows-x86_64.tar.gz" ;;
    SHA256SUMS | SHA256SUMS.sig | checksums.txt) ;;
    *) unmapped+=("$b") ;;
  esac
  if [[ -n "$target" ]]; then
    claim "$target" "$b"
    # copy, never hardlink: a later in-place rewrite of dist/ would silently
    # mutate the staged copy and stale its recorded hash
    cp -p "$f" "$OUT_ABS/$target"
  fi
done < <(find "$SRC" \( -type f -o -type l \))

if [[ -n "$APK" ]]; then
  [[ -f "$APK" ]] || die "--apk path not found: $APK"
  claim "Baluard-android.apk" "$(basename "$APK")"
  cp -p "$APK" "$OUT_ABS/Baluard-android.apk"
fi

# The empty-dist guard must fire before the always-present key staging, or
# every bare call would silently stage a release set of checksums plus key.
[[ ${#MAP[@]} -gt 0 ]] || die "no artifacts mapped from $SRC"

# The README's manual-verify flow downloads the minisign public key from the
# same release page (minisign -V -p updater.pub); it is committed repo
# content, not a build artifact, so it stages from ROOT rather than dist/.
[[ -f "$ROOT/updater.pub" ]] || die "updater public key missing: $ROOT/updater.pub"
claim "updater.pub" "updater.pub"
cp -p "$ROOT/updater.pub" "$OUT_ABS/updater.pub"

if [[ -n "$REQUIRE" ]]; then
  IFS=',' read -r -a NEED <<< "$REQUIRE"
  missing=()
  for name in "${NEED[@]}"; do
    [[ -n "${MAP[$name]:-}" ]] || missing+=("$name")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "required artifacts missing from the staged set: ${missing[*]}"
fi
if [[ ${#unmapped[@]} -gt 0 ]]; then
  die "unmapped artifacts in $SRC (extend the mapping table or remove them): ${unmapped[*]}"
fi

# Sorted for stable diffs and locale-independent order; names only, no version strings survive
(cd "$OUT_ABS" && sha256sum ./* | sed 's| \./| |' | LC_ALL=C sort -k2 > SHA256SUMS)

echo "signing SHA256SUMS"
export TAURI_SIGNING_PRIVATE_KEY
# BALUARD_TAURI_BIN overrides the resolution entirely (tests pin a fake shim);
# otherwise prefer the lockfile-backed CLI: an npx fetch resolves the whole
# dependency tree at run time, and this call holds the updater private key.
TAURI_BIN="${BALUARD_TAURI_BIN:-}"
if [[ -z "$TAURI_BIN" ]]; then
  if [[ -x "$ROOT/desktop/node_modules/.bin/tauri" ]]; then
    TAURI_BIN="$ROOT/desktop/node_modules/.bin/tauri"
  else
    TAURI_BIN="npx --yes @tauri-apps/cli@2.12.4"
  fi
fi
# </dev/null: an encrypted key with a missing password fails fast, never prompts
$TAURI_BIN signer sign "$OUT_ABS/SHA256SUMS" </dev/null
[[ -s "$OUT_ABS/SHA256SUMS.sig" ]] || die "SHA256SUMS.sig missing after signing"

echo
echo "staged $(find "$OUT_ABS" -maxdepth 1 -type f | wc -l) files in $OUT_ABS:"
ls -1 "$OUT_ABS"
