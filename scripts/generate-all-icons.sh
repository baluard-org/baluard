#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-assets/baluard-lock-l4-svg-1024.png}"
OUT_DIR="assets/app-icons"

echo "Generating icons from $SRC..."
mkdir -p "$OUT_DIR"/{windows,macos,linux,tauri-desktop,android,ios}
mkdir -p "$OUT_DIR"/android/{mipmap-mdpi,mipmap-hdpi,mipmap-xhdpi,mipmap-xxhdpi,mipmap-xxxhdpi}

# 1. Linux PNGs
magick "$SRC" -resize 32x32 "$OUT_DIR/linux/32x32.png"
magick "$SRC" -resize 64x64 "$OUT_DIR/linux/64x64.png"
magick "$SRC" -resize 128x128 "$OUT_DIR/linux/128x128.png"
magick "$SRC" -resize 256x256 "$OUT_DIR/linux/256x256.png"
magick "$SRC" -resize 512x512 "$OUT_DIR/linux/icon.png"

# 2. Windows ICO (multi-layer 16, 24, 32, 48, 64, 256)
magick "$SRC" -define icon:auto-resize=256,64,48,32,24,16 "$OUT_DIR/windows/icon.ico"

# 3. macOS ICNS (via iconutil)
ICONSET_TMP=$(mktemp -d)/Baluard.iconset
mkdir -p "$ICONSET_TMP"
sips -z 16 16     "$SRC" --out "$ICONSET_TMP/icon_16x16.png" >/dev/null
sips -z 32 32     "$SRC" --out "$ICONSET_TMP/icon_16x16@2x.png" >/dev/null
sips -z 32 32     "$SRC" --out "$ICONSET_TMP/icon_32x32.png" >/dev/null
sips -z 64 64     "$SRC" --out "$ICONSET_TMP/icon_32x32@2x.png" >/dev/null
sips -z 128 128   "$SRC" --out "$ICONSET_TMP/icon_128x128.png" >/dev/null
sips -z 256 256   "$SRC" --out "$ICONSET_TMP/icon_128x128@2x.png" >/dev/null
sips -z 256 256   "$SRC" --out "$ICONSET_TMP/icon_256x256.png" >/dev/null
sips -z 512 512   "$SRC" --out "$ICONSET_TMP/icon_256x256@2x.png" >/dev/null
sips -z 512 512   "$SRC" --out "$ICONSET_TMP/icon_512x512.png" >/dev/null
sips -z 1024 1024 "$SRC" --out "$ICONSET_TMP/icon_512x512@2x.png" >/dev/null
iconutil -c icns "$ICONSET_TMP" -o "$OUT_DIR/macos/icon.icns"
rm -rf "$(dirname "$ICONSET_TMP")"

# 4. Tauri Desktop Bundle Icons
cp "$OUT_DIR/linux/32x32.png" "$OUT_DIR/tauri-desktop/32x32.png"
cp "$OUT_DIR/linux/128x128.png" "$OUT_DIR/tauri-desktop/128x128.png"
cp "$OUT_DIR/linux/256x256.png" "$OUT_DIR/tauri-desktop/128x128@2x.png"
cp "$OUT_DIR/macos/icon.icns" "$OUT_DIR/tauri-desktop/icon.icns"
cp "$OUT_DIR/windows/icon.ico" "$OUT_DIR/tauri-desktop/icon.ico"

# 5. Android Icons (mipmap)
magick "$SRC" -resize 48x48 "$OUT_DIR/android/mipmap-mdpi/ic_launcher.png"
magick "$SRC" -resize 72x72 "$OUT_DIR/android/mipmap-hdpi/ic_launcher.png"
magick "$SRC" -resize 96x96 "$OUT_DIR/android/mipmap-xhdpi/ic_launcher.png"
magick "$SRC" -resize 144x144 "$OUT_DIR/android/mipmap-xxhdpi/ic_launcher.png"
magick "$SRC" -resize 192x192 "$OUT_DIR/android/mipmap-xxxhdpi/ic_launcher.png"

# 6. iOS Icons
magick "$SRC" -resize 40x40 "$OUT_DIR/ios/AppIcon-20x20@2x.png"
magick "$SRC" -resize 60x60 "$OUT_DIR/ios/AppIcon-20x20@3x.png"
magick "$SRC" -resize 29x29 "$OUT_DIR/ios/AppIcon-29x29@1x.png"
magick "$SRC" -resize 58x58 "$OUT_DIR/ios/AppIcon-29x29@2x.png"
magick "$SRC" -resize 87x87 "$OUT_DIR/ios/AppIcon-29x29@3x.png"
magick "$SRC" -resize 40x40 "$OUT_DIR/ios/AppIcon-40x40@1x.png"
magick "$SRC" -resize 80x80 "$OUT_DIR/ios/AppIcon-40x40@2x.png"
magick "$SRC" -resize 120x120 "$OUT_DIR/ios/AppIcon-40x40@3x.png"
magick "$SRC" -resize 120x120 "$OUT_DIR/ios/AppIcon-60x60@2x.png"
magick "$SRC" -resize 180x180 "$OUT_DIR/ios/AppIcon-60x60@3x.png"
magick "$SRC" -resize 76x76 "$OUT_DIR/ios/AppIcon-76x76@1x.png"
magick "$SRC" -resize 152x152 "$OUT_DIR/ios/AppIcon-76x76@2x.png"
magick "$SRC" -resize 167x167 "$OUT_DIR/ios/AppIcon-83x83@2x.png"
magick "$SRC" -resize 1024x1024 "$OUT_DIR/ios/AppIcon-1024x1024.png"

echo "Deploying to desktop (Tauri)..."
cp "$OUT_DIR"/tauri-desktop/* desktop/src-tauri/icons/
cp "$OUT_DIR"/linux/icon.png desktop/src-tauri/icons/icon.png
cp "$OUT_DIR"/linux/64x64.png desktop/src-tauri/icons/64x64.png

echo "Deploying to mobile (Android app)..."
cp "$OUT_DIR"/android/mipmap-mdpi/ic_launcher.png mobile/androidApp/src/main/res/mipmap-mdpi/ic_launcher.png
cp "$OUT_DIR"/android/mipmap-hdpi/ic_launcher.png mobile/androidApp/src/main/res/mipmap-hdpi/ic_launcher.png
cp "$OUT_DIR"/android/mipmap-xhdpi/ic_launcher.png mobile/androidApp/src/main/res/mipmap-xhdpi/ic_launcher.png
cp "$OUT_DIR"/android/mipmap-xxhdpi/ic_launcher.png mobile/androidApp/src/main/res/mipmap-xxhdpi/ic_launcher.png
cp "$OUT_DIR"/android/mipmap-xxxhdpi/ic_launcher.png mobile/androidApp/src/main/res/mipmap-xxxhdpi/ic_launcher.png

echo "All platform icons generated and deployed successfully."
