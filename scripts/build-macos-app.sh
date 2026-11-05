#!/usr/bin/env bash
# Build the Baluard macOS desktop app bundle on a Linux host. Dev-smoke use
# only: releases still come off a macOS host (see docs/dev/release-protocol.md
# build matrix). Cross-compiles the sidecars with cargo-zigbuild against a
# locally staged macOS SDK, then drives `tauri build` with the app bundle.
#
# Pass --smoke to embed the WebDriver server (tauri-plugin-wdio-webdriver)
# via the smoke cargo feature + desktop/src-tauri/tauri.smoke.conf.json (see
# docs/dev/release-smoke-testing.md). The output copies to Baluard-smoke.app
# so the two artifacts do not overwrite each other.
#
# x86_64 needs no tapi tbd shims (those exist for the SDK's arm64e-only v5
# tbds that break aarch64 builds).
set -euo pipefail

SMOKE=0
for arg in "$@"; do
  case "$arg" in
    --smoke) SMOKE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-apple-darwin"
TRIPLE="$TARGET"
# No SDKROOT-free path: zig's darwin linker needs an SDK for libSystem and
# framework stubs. zig prefixes every -L/-F path with the sysroot, so the SDK
# carries root-relative symlinks (home/, tmp/) that make the prefixed paths
# resolve. cargo-zigbuild passes SDKROOT through to zig cc.
MAC_SDK="$HOME/.local/opt/macos-sdk/MacOSX.sdk"
export SDKROOT="$MAC_SDK"
# Guest floor is macOS 15 (repo minimum).
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
# objc2/wry do not declare ColorSync; the WKWebView link needs it from the SDK.
# The SDK 27 tbds list arm64e targets, which zig's tbd parser rejects as
# MalformedYaml; shim them to v4 x86_64-only stubs (some SDK tbds are
# arm64e-only and get an empty-symbols stub instead).
MAC_SDK="$HOME/.local/opt/macos-sdk/MacOSX.sdk"
SHIM_DIR="$HOME/.local/opt/macos-sdk/framework-shims"
# Shim every framework the SDK ships: AppKit alone re-exports the whole
# ApplicationServices graph, so a fixed list always misses one.
for f in "$MAC_SDK"/System/Library/Frameworks/*.framework/*.tbd; do
  fw=$(basename "${f%.tbd}")
  mkdir -p "$SHIM_DIR/$fw.framework"
  python3 "$(dirname "$0")/shim-tbd.py" "$f" "$SHIM_DIR/$fw.framework/$fw.tbd" "$fw"
done
export CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS="-C link-arg=-F$SHIM_DIR -C link-arg=-F$MAC_SDK/System/Library/Frameworks -C link-arg=-framework -C link-arg=ColorSync"
# libgit2's SecureTransport stream needs SDK framework headers at compile
# time. Include-only (no sysroot arg): a sysroot reaches zig's linker and
# gets prefixed onto every -L path.
export CFLAGS_x86_64_apple_darwin="-isysroot $MAC_SDK -F$MAC_SDK/System/Library/Frameworks"
# Cross-built OpenSSL 3.6.3 (zig cc, no-asm): the repo's OPENSSL_DIR=/usr pins
# Linux headers into the C graph and breaks libssh2-sys on darwin targets.
export OPENSSL_DIR="${OPENSSL_DIR:-$HOME/.local/opt/macos-openssl/ossl-x86}"  # rescue copy + rebuild recipe live beside it (README.md)

cd "$ROOT"

for tool in cargo-zigbuild npm zig; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing tool: $tool" >&2
    case "$tool" in
      cargo-zigbuild) echo "  cargo install --locked cargo-zigbuild" >&2 ;;
      zig) echo "  see ziglang.org; expect it on PATH" >&2 ;;
    esac
    exit 1
  fi
done

if [[ ! -d "$OPENSSL_DIR/include/openssl" ]]; then
  echo "missing cross-built OpenSSL: $OPENSSL_DIR (Configure darwin64-x86_64-cc no-tests no-asm no-shared with zig cc, stage include/ + lib/)" >&2
  exit 1
fi

if ! rustc --target "$TARGET" --print cfg >/dev/null 2>&1; then
  echo "missing Rust target: $TARGET" >&2
  echo "  rustup target add $TARGET" >&2
  exit 1
fi

# Tauri sidecars are named <binary>-<target-triple> (no suffix on macOS).
BIN_DIR="desktop/src-tauri/binaries"
mkdir -p "$BIN_DIR"

echo "Cross-compiling macOS sidecars ($TRIPLE)..."
if ! cargo zigbuild --release --target "$TARGET" \
  -p baluard-daemon -p baluard-cli -p baluard-nmh --features baluard-daemon/fido2; then
  echo "cargo-zigbuild cross-compile failed for $TARGET" >&2
  exit 1
fi
cp "target/$TARGET/release/baluard-daemon" "$BIN_DIR/baluard-daemon-$TRIPLE"
cp "target/$TARGET/release/baluard" "$BIN_DIR/baluard-$TRIPLE"
cp "target/$TARGET/release/baluard-nmh" "$BIN_DIR/baluard-nmh-$TRIPLE"

echo "Building app binary..."
cd desktop
FEAT_ARGS=()
if [[ "$SMOKE" == "1" ]]; then
  FEAT_ARGS=(--features smoke)
fi
# --no-bundle: tauri-cli compiles the macOS bundler only for macOS hosts.
# The .app is assembled below (sidecars + Info.plist + icons), which also
# keeps the smoke bundle independent of bundler renames.
npm run tauri build -- --no-bundle --target "$TARGET" --runner cargo-zigbuild --config src-tauri/tauri.smoke.conf.json "${FEAT_ARGS[@]}"

BIN_DIR_SRC="src-tauri/target/$TARGET/release"
APP_NAME="Baluard-smoke.app"
if [[ "$SMOKE" != "1" ]]; then
  APP_NAME="Baluard.app"
fi
VERSION=$(grep -m1 '^version' src-tauri/Cargo.toml | sed 's/.*"\(.*\)"/\1/')
APP_ROOT="$PWD/src-tauri/target/$TARGET/release/bundle/macos/$APP_NAME"
rm -rf "$APP_ROOT"
mkdir -p "$APP_ROOT/Contents/MacOS" "$APP_ROOT/Contents/Resources"

main_bin=$(ls "$BIN_DIR_SRC/baluard-desktop" 2>/dev/null || ls "$BIN_DIR_SRC/Baluard")
cp "$main_bin" "$APP_ROOT/Contents/MacOS/baluard-desktop"
cp "$ROOT/desktop/src-tauri/binaries/baluard-daemon-$TRIPLE" "$APP_ROOT/Contents/MacOS/baluard-daemon"
cp "$ROOT/desktop/src-tauri/binaries/baluard-$TRIPLE" "$APP_ROOT/Contents/MacOS/baluard"
cp "$ROOT/desktop/src-tauri/binaries/baluard-nmh-$TRIPLE" "$APP_ROOT/Contents/MacOS/baluard-nmh"
cp "$ROOT/desktop/src-tauri/icons/icon.icns" "$APP_ROOT/Contents/Resources/icon.icns"

cat > "$APP_ROOT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>English</string>
	<key>CFBundleDisplayName</key><string>Baluard</string>
	<key>CFBundleExecutable</key><string>baluard-desktop</string>
	<key>CFBundleIconFile</key><string>icon.icns</string>
	<key>CFBundleIdentifier</key><string>app.baluard.desktop</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>Baluard</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$VERSION</string>
	<key>CFBundleVersion</key><string>$VERSION</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLName</key><string>app.baluard.desktop</string>
			<key>CFBundleURLSchemes</key>
			<array><string>baluard</string></array>
		</dict>
	</array>
	<key>LSMinimumSystemVersion</key><string>15.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Not codesigned: zig-linked binaries reserve no signature room, and the
# tar-over-ssh deploy path never sets the quarantine attribute, so Gatekeeper
# never sees the bundle.
echo "macOS app: $APP_ROOT"
