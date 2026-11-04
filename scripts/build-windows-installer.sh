#!/usr/bin/env bash
# Build the Baluard Windows desktop installer (NSIS setup.exe) on a Linux or
# macOS host. Cross-compiles the daemon and CLI sidecars for the Windows MSVC
# target with cargo-xwin, then drives `tauri build` with the NSIS bundle.
# MSI stays a Windows-only build: WiX cannot run on this host.
#
# Pass --smoke to bake --remote-debugging-port=9222 into the webview via
# desktop/src-tauri/tauri.smoke.conf.json (see docs/dev/release-smoke-testing.md).
# The smoke build exists only for UI smoke tests; the shipped artifact is the
# build WITHOUT the flag. The output is copied to *_smoke-setup.exe so the
# two artifacts do not overwrite each other.
set -euo pipefail

SMOKE=0
for arg in "$@"; do
  case "$arg" in
    --smoke) SMOKE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="x86_64-pc-windows-msvc"
TRIPLE="$TARGET"

cd "$ROOT"

for tool in cargo-xwin cargo npm clang lld llvm-rc makensis; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing tool: $tool" >&2
    case "$tool" in
      makensis)
        echo "  Fedora: sudo dnf install mingw64-nsis, then copy Stubs/ and Plugins/ from the NSIS release (see Tauri Windows installer docs)" >&2
        echo "  Debian/Ubuntu: sudo apt install nsis" >&2
        echo "  macOS: brew install makensis" >&2 ;;
      cargo-xwin)
        echo "  cargo install --locked cargo-xwin" >&2 ;;
      clang|lld|llvm-rc)
        echo "  Fedora: sudo dnf install clang lld llvm" >&2
        echo "  Debian/Ubuntu: sudo apt install clang lld llvm" >&2
        echo "  macOS: brew install llvm" >&2 ;;
    esac
    exit 1
  fi
done

# cargo-xwin needs the Windows MSVC target in the rustc sysroot.
if ! rustc --target "$TARGET" --print cfg >/dev/null 2>&1; then
  echo "missing Rust target: $TARGET" >&2
  echo "  rustup target add $TARGET" >&2
  exit 1
fi

# Tauri sidecars are named <binary>-<target-triple>[.exe]; NSIS is the only
# Windows bundle that builds off-Windows, so the sidecar carries a .exe suffix.
BIN_DIR="desktop/src-tauri/binaries"
mkdir -p "$BIN_DIR"

echo "Cross-compiling Windows sidecars ($TRIPLE)..."
if ! cargo xwin build --release --target "$TARGET" \
  -p baluard-daemon -p baluard-cli -p baluard-nmh --features baluard-daemon/fido2; then
  echo "cargo-xwin cross-compile failed for $TARGET" >&2
  exit 1
fi
cp "target/$TARGET/release/baluard-daemon.exe" "$BIN_DIR/baluard-daemon-$TRIPLE.exe"
cp "target/$TARGET/release/baluard.exe" "$BIN_DIR/baluard-$TRIPLE.exe"
cp "target/$TARGET/release/baluard-nmh.exe" "$BIN_DIR/baluard-nmh-$TRIPLE.exe"

echo "Building NSIS installer..."
cd desktop
CONFIG_ARGS=()
if [[ "$SMOKE" == "1" ]]; then
  CONFIG_ARGS=(--config src-tauri/tauri.smoke.conf.json)
fi
npm run tauri build -- --bundles nsis --target "$TARGET" --runner cargo-xwin "${CONFIG_ARGS[@]}"

BUNDLE_DIR="src-tauri/target/$TARGET/release/bundle/nsis"
if [[ "$SMOKE" == "1" ]]; then
  SETUP="$(ls "$BUNDLE_DIR"/*-setup.exe 2>/dev/null | head -1)"
  [[ -n "$SETUP" ]] && cp "$SETUP" "${SETUP/%-setup.exe/-smoke-setup.exe}"
  echo "windows SMOKE installer: $BUNDLE_DIR/*-smoke-setup.exe"
else
  echo "windows installer: $BUNDLE_DIR/"
fi
