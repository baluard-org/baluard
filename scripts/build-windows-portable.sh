#!/usr/bin/env bash
# Build the Baluard Windows portable zip (run-from-USB, no installer, no
# admin). Cross-compiles with cargo-xwin like build-windows-installer.sh,
# skips NSIS, and bundles the Microsoft WebView2 Fixed Version runtime;
# the launcher points WEBVIEW2_BROWSER_EXECUTABLE_FOLDER at it, so the
# zip is fully self-contained on any Windows 10/11 x64 machine.
#
# Portable builds never register the browser-bridge manifests and never
# self-update (BALUARD_PORTABLE gates both in the code). Output:
#   dist/Baluard_<version>_x64-portable.zip
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-pc-windows-msvc"
TRIPLE="$TARGET"
DIST="$ROOT/dist"
STAGE="$DIST/portable-staging"

cd "$ROOT"

for tool in cargo-xwin cargo npm curl 7z zip python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing tool: $tool" >&2
    case "$tool" in
      cargo-xwin) echo "  cargo install --locked cargo-xwin" >&2 ;;
      7z)         echo "  Fedora: sudo dnf install p7zip p7zip-plugins" >&2 ;;
      zip)        echo "  Fedora: sudo dnf install zip" >&2 ;;
    esac
    exit 1
  fi
done

if ! rustc --target "$TARGET" --print cfg >/dev/null 2>&1; then
  echo "missing Rust target: $TARGET (rustup target add $TARGET)" >&2
  exit 1
fi

VERSION="$(awk -F'"' '/^\[workspace.package\]/{section=1; next} section && /^version =/{print $2; exit}' "$ROOT/Cargo.toml")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || { echo "cannot read workspace version from $ROOT/Cargo.toml" >&2; exit 1; }

# Release-parity environment: provider OAuth client IDs bake into the
# daemon binary at compile time (same as the installer leg). No updater
# signing key here: --no-bundle produces no updater artifacts, and the
# zip itself is signed afterwards by scripts/sign-release-artifacts.sh.
sec() { grep -m1 "^\(export \)\?$1=" ~/.secrets | cut -d= -f2- | sed -E "s/^\"(.*)\"\$/\1/; s/^'(.*)'\$/\1/"; }
export BALUARD_GITLAB_CLIENT_ID="$(sec BALUARD_GITLAB_CLIENT_ID)"
export BALUARD_CODEBERG_CLIENT_ID="$(sec BALUARD_CODEBERG_CLIENT_ID)"
[[ -n "$BALUARD_GITLAB_CLIENT_ID" && -n "$BALUARD_CODEBERG_CLIENT_ID" ]] \
  || { echo "provider client ids missing or empty in ~/.secrets" >&2; exit 1; }

echo "Cross-compiling Windows sidecars ($TRIPLE)..."
cargo xwin build --release --target "$TARGET" \
  -p baluard-daemon -p baluard-cli -p baluard-nmh -p baluard-portable-launcher \
  --features baluard-daemon/fido2

# The tauri build resolves externalBin from this directory; keep it in sync
# with the freshly built sidecars (the installer leg does the same).
BIN_DIR="desktop/src-tauri/binaries"
mkdir -p "$BIN_DIR"
cp "target/$TARGET/release/baluard-daemon.exe" "$BIN_DIR/baluard-daemon-$TRIPLE.exe"
cp "target/$TARGET/release/baluard.exe" "$BIN_DIR/baluard-$TRIPLE.exe"
cp "target/$TARGET/release/baluard-nmh.exe" "$BIN_DIR/baluard-nmh-$TRIPLE.exe"

echo "Building desktop app (no bundle)..."
(cd desktop && npm run tauri build -- --no-bundle --runner cargo-xwin --target "$TARGET")

REL="src-tauri/target/$TARGET/release"
DESKTOP_EXE="$ROOT/desktop/$REL/baluard-desktop.exe"
[[ -f "$DESKTOP_EXE" ]] || { echo "desktop exe missing: $DESKTOP_EXE" >&2; exit 1; }

# WebView2 Fixed Version runtime: the downloads page embeds the current
# cab URLs in its payload; the newest x64 entry is the first match.
WV2_CACHE="$ROOT/target/wv2-fixed"
mkdir -p "$WV2_CACHE"
PAGE_FILE="$WV2_CACHE/page.html"
curl -fsSL --max-time 60 https://developer.microsoft.com/en-us/microsoft-edge/webview2/ -o "$PAGE_FILE"
CAB_URL="$(python3 - "$PAGE_FILE" <<'PY'
import re, sys
page = open(sys.argv[1]).read().replace("\\u002F", "/")
m = re.findall(r'https://[^"\']*FixedVersionRuntime\.([0-9.]+)\.x64\.cab', page)
if not m:
    print("")
else:
    newest = max(m, key=lambda v: tuple(int(p) for p in v.split('.')))
    print(re.search(r'https://[^"\']*FixedVersionRuntime\.' + re.escape(newest) + r'\.x64\.cab', page).group(0))
PY
)"
[[ -n "$CAB_URL" ]] || { echo "no WebView2 Fixed Version x64 cab URL found on the downloads page" >&2; exit 1; }
WV2_VERSION="$(sed -E 's/.*FixedVersionRuntime\.([0-9.]+)\.x64\.cab/\1/' <<<"$CAB_URL")"
CAB="$WV2_CACHE/Microsoft.WebView2.FixedVersionRuntime.$WV2_VERSION.x64.cab"
if [[ ! -f "$CAB" ]]; then
  echo "Downloading WebView2 Fixed Version $WV2_VERSION..."
  curl -fsSL --max-time 600 -o "$CAB.part" "$CAB_URL" && mv "$CAB.part" "$CAB"
fi
( cd "$WV2_CACHE" && grep -F "$(basename "$CAB")" "$ROOT/scripts/windows-portable/webview2.sha256" | sed 's/\r$//' | sha256sum -c - ) \
  || { echo "cab hash not pinned or mismatched; update scripts/windows-portable/webview2.sha256 only after review:" >&2; sha256sum "$CAB" >&2; exit 1; }

EXTRACT="$WV2_CACHE/extract-$WV2_VERSION"
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"
7z x -y -o"$EXTRACT" "$CAB" >/dev/null
RUNTIME_DIR="$(find "$EXTRACT" -maxdepth 2 -type d -name 'Microsoft.WebView2.FixedVersionRuntime.*' | head -1)"
[[ -n "$RUNTIME_DIR" && -f "$RUNTIME_DIR/msedgewebview2.exe" ]] \
  || { echo "runtime folder or msedgewebview2.exe missing after cab extraction" >&2; exit 1; }

echo "Assembling portable staging..."
rm -rf "$STAGE"
mkdir -p "$STAGE/Baluard/WebView2"
APP="$STAGE/Baluard"
cp "$DESKTOP_EXE" "$APP/"
for side in baluard-daemon baluard baluard-nmh baluard-portable; do
  cp "$ROOT/target/$TARGET/release/$side.exe" "$APP/"
done
cp "$ROOT/scripts/windows-portable/README.txt" "$APP/"
cp -a "$RUNTIME_DIR/." "$APP/WebView2/"

ZIP="$DIST/Baluard_${VERSION}_x64-portable.zip"
mkdir -p "$DIST"
rm -f "$ZIP"
(cd "$STAGE" && zip -qr "$ZIP" Baluard/)

echo "portable zip: $ZIP (WebView2 $WV2_VERSION)"
ls -lh "$ZIP"
