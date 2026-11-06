#!/usr/bin/env bash
# Build the aarch64 macOS release deliverable from Linux: cross-compiled
# sidecars and desktop binary (cargo-zigbuild against the local SDK), an
# ad-hoc signed Baluard.app, the non-notarized release zip, the sha-named
# ~/Downloads copy, and the .app.tar.gz updater payload with its signature.
#
# Machine inputs outside the repo (checked up front):
#   ~/.local/opt/macos-sdk/MacOSX.sdk        full macOS SDK (non-redistributable)
#   ~/.local/opt/macos-openssl/ossl-arm      cross-built static arm64 OpenSSL
#   zig, rcodesign, ruby on PATH             (~/.local/bin, ~/.cargo/bin)
#   desktop/node_modules                     (just desktop-deps)
#   TAURI_SIGNING_PRIVATE_KEY, or BALUARD_UPDATER_KEY (default
#   ~/.tauri/baluard-updater.key), for the updater-payload signature
#
# The zip lands in dist/ for release-stage, the sha-named copy in
# ~/Downloads for hand-off (maintainer-ordered location), and superseded
# macos-aarch64 deliverables in ~/Downloads are removed per the
# exactly-one-deliverable rule.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(awk -F'"' '/^version = /{print $2; exit}' "$ROOT/Cargo.toml")"
SDK="${MACOS_SDK:-$HOME/.local/opt/macos-sdk/MacOSX.sdk}"
OSSSL="${MACOS_OPENSSL_DIR:-$HOME/.local/opt/macos-openssl/ossl-arm}"
SHIM_ROOT="$HOME/.local/opt/macos-sdk/aarch64-shims"
DL="$HOME/Downloads"
WORK="$(mktemp -d)"
LOGDIR="$ROOT/logs"
mkdir -p "$LOGDIR"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in zig rcodesign ruby node npm file python3 npx; do
  command -v "$tool" >/dev/null || fail "$tool not on PATH"
done
[[ -d "$SDK/usr/lib" ]] || fail "macOS SDK missing at $SDK"
[[ -f "$OSSSL/lib/libcrypto.a" ]] || fail "cross-built OpenSSL missing at $OSSSL (see ~/.local/opt/macos-openssl rebuild README)"
[[ -d "$ROOT/desktop/node_modules" ]] || fail "desktop/node_modules missing; run just desktop-deps"
if [[ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  key_file="${BALUARD_UPDATER_KEY:-$HOME/.tauri/baluard-updater.key}"
  [[ -f "$key_file" ]] || fail "no updater key: set TAURI_SIGNING_PRIVATE_KEY or BALUARD_UPDATER_KEY"
  export TAURI_SIGNING_PRIVATE_KEY
  TAURI_SIGNING_PRIVATE_KEY="$(cat "$key_file")"
fi
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD-}"

# SDK .tbd stubs need conversion to the tapi-tbd v4 arm64 shape zig accepts.
FW_SHIMS="$SHIM_ROOT/frameworks"
LIB_SHIMS="$SHIM_ROOT/usr-lib"
if [[ ! -d "$FW_SHIMS" ]] || [[ -z "$(find "$FW_SHIMS" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  mkdir -p "$FW_SHIMS"
  ruby "$ROOT/scripts/macos-aarch64-tbd-convert.rb" "$SDK" "$FW_SHIMS" fw
fi
if [[ ! -d "$LIB_SHIMS" ]] || [[ -z "$(find "$LIB_SHIMS" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  mkdir -p "$LIB_SHIMS"
  ruby "$ROOT/scripts/macos-aarch64-tbd-convert.rb" "$SDK" "$LIB_SHIMS" lib
fi
[[ -f "$LIB_SHIMS/libiconv.tbd" ]] || fail "lib shims incomplete (no libiconv.tbd)"

# zig cc rejects -Wl,-exported_symbols_list (cdylib-only artifacts, never
# shipped) and needs the sysroot spelled out; filter and retarget here.
cat > "$WORK/zigcc" <<'WRAP'
#!/usr/bin/env bash
args=()
skip=0
for a in "$@"; do
  if [[ $skip == 1 ]]; then skip=0; continue; fi
  if [[ $a == "-Wl,-exported_symbols_list" ]]; then skip=1; continue; fi
  args+=("$a")
done
exec "${ZIGMAC_ZIG}" cc -target aarch64-macos.15.0-none -isysroot "${ZIGMAC_SDK}" "${args[@]}"
WRAP
chmod +x "$WORK/zigcc"
export ZIGMAC_SDK="$SDK"
ZIGMAC_ZIG="$(command -v zig)"
export ZIGMAC_ZIG
export SDKROOT="$SDK"
export OPENSSL_DIR="$OSSSL"
export MACOSX_DEPLOYMENT_TARGET=15.0
export RUSTFLAGS="--cfg aes_armv8 -C linker=$WORK/zigcc -C link-arg=-F$FW_SHIMS -C link-arg=-F$SDK/System/Library/Frameworks -C link-arg=-L$LIB_SHIMS"
export PATH="$HOME/.cargo/bin:$PATH"

echo "== frontend =="
(cd "$ROOT/desktop" && npm run build) > "$LOGDIR/macos-aarch64-frontend.log" 2>&1 || fail "frontend build (see $LOGDIR/macos-aarch64-frontend.log)"
FRONT_HASH="$(find "$ROOT/desktop/dist/assets" -maxdepth 1 -name 'index-*.js' -printf '%f\n' | head -n1)"
echo "FRONT_HASH=$FRONT_HASH"

echo "== sidecars =="
(cd "$ROOT" && cargo zigbuild --release --target aarch64-apple-darwin \
  -p baluard-daemon -p baluard-cli -p baluard-nmh \
  --features baluard-daemon/fido2) > "$LOGDIR/macos-aarch64-sidecars.log" 2>&1 || fail "sidecar zigbuild (see $LOGDIR/macos-aarch64-sidecars.log)"
TW="$ROOT/target/aarch64-apple-darwin/release"
for b in baluard baluard-daemon baluard-nmh; do
  file "$TW/$b" | grep -q "Mach-O 64-bit arm64" || fail "$b is not arm64 Mach-O"
  cp -p "$TW/$b" "$ROOT/desktop/src-tauri/binaries/$b-aarch64-apple-darwin"
done

echo "== desktop =="
(cd "$ROOT/desktop/src-tauri" && cargo zigbuild --release --target aarch64-apple-darwin \
  --features tauri/custom-protocol) > "$LOGDIR/macos-aarch64-desktop.log" 2>&1 || fail "desktop zigbuild (see $LOGDIR/macos-aarch64-desktop.log)"
DT="$ROOT/desktop/src-tauri"
DW="$DT/target/aarch64-apple-darwin/release"
file "$DW/baluard-desktop" | grep -q "Mach-O 64-bit arm64" || fail "baluard-desktop is not arm64 Mach-O"
strings -a "$DW/baluard-desktop" | grep -c "$VERSION" | grep -qv '^0' || fail "baluard-desktop lacks $VERSION strings"

echo "== bundle =="
STAGE="$WORK/stage"
APP="$STAGE/Baluard.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -p "$DW/baluard-desktop" "$APP/Contents/MacOS/baluard-desktop"
cp -p "$TW/baluard"        "$APP/Contents/MacOS/baluard"
cp -p "$TW/baluard-daemon" "$APP/Contents/MacOS/baluard-daemon"
cp -p "$TW/baluard-nmh"    "$APP/Contents/MacOS/baluard-nmh"
chmod 755 "$APP"/Contents/MacOS/*
cp -p "$DT/icons/icon.icns" "$APP/Contents/Resources/baluard.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>app.baluard.desktop</string>
<key>CFBundleName</key><string>Baluard</string>
<key>CFBundleExecutable</key><string>baluard-desktop</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleIconFile</key><string>baluard</string>
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key><string>app.baluard.desktop</string>
    <key>CFBundleURLSchemes</key>
    <array><string>baluard</string></array>
  </dict>
</array>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
printf 'APPL????' > "$APP/Contents/PkgInfo"

rcodesign sign "$APP" > "$LOGDIR/macos-aarch64-sign.log" 2>&1 || fail "rcodesign (see $LOGDIR/macos-aarch64-sign.log)"

echo "== battery =="
MAIN="$APP/Contents/MacOS/baluard-desktop"
EMBED_COUNT="$(strings -a "$MAIN" | grep -cF "$FRONT_HASH" || true)"
[[ "$EMBED_COUNT" -eq 1 ]] || fail "frontend hash embedded $EMBED_COUNT times"
if [[ "$(strings -a "$MAIN" | grep -c "Git-native password manager" || true)" -ne 0 ]]; then
  fail "CLI strings in the main executable"
fi
[[ "$(strings -a "$APP/Contents/MacOS/baluard" | grep -c "Usage:" || true)" -gt 0 ]] || fail "clap marker missing in the CLI sidecar"
DUPS="$(find "$APP" -depth | sort -f | uniq -di | wc -l)"
[[ "$DUPS" -eq 0 ]] || fail "$DUPS case-fold duplicate paths in the bundle"
for b in baluard-desktop baluard baluard-daemon baluard-nmh; do
  file "$APP/Contents/MacOS/$b" | grep -q "Mach-O 64-bit arm64" || fail "arch check failed: $b"
done
python3 -c "import plistlib; plistlib.load(open('$APP/Contents/Info.plist','rb'))" || fail "Info.plist does not parse"
rcodesign print-signature-info "$MAIN" | grep -q "ADHOC" || fail "main executable is not ad-hoc signed"
echo "BATTERY_OK"

echo "== zips =="
python3 - "$STAGE" "$ROOT/dist" "$DL" "$VERSION" <<'PYEOF'
import hashlib, os, shutil, sys, zipfile
stage, dist, downloads, version = sys.argv[1:5]
app = os.path.join(stage, "Baluard.app")

def make_zip(path):
    # writestr(ZipInfo) defaults to ZIP_STORED per entry; set DEFLATED here.
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(app):
            for f in sorted(files):
                full = os.path.join(root, f)
                rel = os.path.relpath(full, stage)
                zi = zipfile.ZipInfo(rel, (1980, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = (0o755 << 16) | 0o100644
                with open(full, "rb") as fh:
                    z.writestr(zi, fh.read())
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

dist_zip = os.path.join(dist, f"baluard-{version}-macos-aarch64-non-notarized.zip")
sha = make_zip(dist_zip)
dl = os.path.join(downloads, f"Baluard-{version}-macos-aarch64-{sha[:8]}.zip")
sha2 = make_zip(dl)
assert sha == sha2, "dist and Downloads zips differ"
with open(os.path.join(downloads, f"MANIFEST-macos-{sha[:8]}.sha256"), "w") as m:
    m.write(f"{sha}  Baluard-{version}-macos-aarch64-{sha[:8]}.zip\n")
# exactly-one-deliverable: retire superseded macos-aarch64 hand-offs.
for name in os.listdir(downloads):
    keep = (os.path.basename(dl), f"MANIFEST-macos-{sha[:8]}.sha256")
    if ("macos-aarch64" in name or name.startswith("MANIFEST-macos-")) \
       and name.endswith((".zip", ".sha256")) and name not in keep:
        os.remove(os.path.join(downloads, name))
        print(f"removed superseded {name}")
print(f"ZIP_SHA={sha}")
print(f"ZIP_BYTES={os.path.getsize(dl)}")
PYEOF

echo "== updater payload =="
DIST="$ROOT/dist"
TAR_NAME="Baluard_${VERSION}_aarch64.app.tar.gz"
tar -C "$STAGE" -czf "$DIST/$TAR_NAME" Baluard.app
(cd "$DIST" && npx --yes @tauri-apps/cli@2.12.4 signer sign "$DIST/$TAR_NAME") > "$LOGDIR/macos-aarch64-tarsig.log" 2>&1 \
  || fail "updater signature (see $LOGDIR/macos-aarch64-tarsig.log)"
[[ -f "$DIST/$TAR_NAME.sig" ]] || fail "updater .sig missing after signing"

ls -la "$DIST/$TAR_NAME" "$DIST/$TAR_NAME.sig" "$DIST/baluard-$VERSION-macos-aarch64-non-notarized.zip"
echo "ALL_OK ($VERSION)"
