#!/usr/bin/env bash
set -euo pipefail

# Generate app icons for ALL platforms (Windows/macOS/Linux desktop + Android/iOS)
# from the two brand SVGs:
#   - TILE  (assets/baluard-lock-l4.svg):   full-bleed dark squircle + padlock
#   - GLYPH (assets/baluard-lock-only.svg): padlock only, transparent background
#
# Produces: assets/app-icons/{windows,macos,linux,tauri-desktop,android,ios}/
# and deploys to:
#   - desktop/src-tauri/icons/        (Tauri bundle icons)
#   - desktop/src/assets/logo.png     (browser-extension toolbar icon source,
#                                      consumed by browser/shared/vite.config.js)
#   - mobile/androidApp/.../res/      (launcher mipmaps + adaptive-icon layers)
#
# Android adaptive icons: full-bleed background color + glyph-only foreground,
# so the launcher mask shapes the icon (full tile, like Bitwarden) instead of
# shrink-wrapping a legacy bitmap on white.
#
# Tooling: rsvg-convert + magick + python3 (all portable; no sips/iconutil).

TILE_SVG="assets/baluard-lock-l4.svg"
GLYPH_SVG="assets/baluard-lock-only.svg"
OUT_DIR="assets/app-icons"
RES_DIR="mobile/androidApp/src/main/res"

# Adaptive foreground: glyph height in px on a 1024 canvas.
# Reduced ~15% from 625 to 531 so the lock stays well inside the squircle mask
# forced by Android launchers (matching Bitwarden proportions without touching edges).
FG_H=531
# Mobile tile lock glyph height in px on a 1024 canvas (iOS + Android legacy).
# Original lock in baluard-lock-l4.svg was 744px (72.65%); reduced ~15% to 632px.
MOBILE_GLYPH_H=632

command -v rsvg-convert >/dev/null || { echo "ERROR: rsvg-convert not found"; exit 1; }
command -v magick >/dev/null || { echo "ERROR: magick not found"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Rendering sources from SVGs..."
TILE="$TMP/tile-1024.png"
FG="$TMP/foreground-1024.png"
rsvg-convert -w 1024 -h 1024 "$TILE_SVG" -o "$TILE"
rsvg-convert -w 1024 -h 1024 "$GLYPH_SVG" -o "$TMP/glyph-1024.png"
# Trim to the padlock bbox, scale glyph to FG_H, center on transparent canvas for Android adaptive foreground.
magick "$TMP/glyph-1024.png" -trim +repage -resize x${FG_H} -gravity center -background none -extent 1024x1024 "$FG"

# Render mobile base backgrounds (full-bleed for iOS, squircle for Android legacy).
cat > "$TMP/bg-full-1024.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <defs>
    <linearGradient id="bg-grad-l4" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0e1b1e" />
      <stop offset="100%" stop-color="#091315" />
    </linearGradient>
  </defs>
  <rect width="1024" height="1024" fill="url(#bg-grad-l4)" />
</svg>
SVG
cat > "$TMP/bg-squircle-1024.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <defs>
    <linearGradient id="bg-grad-l4" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0e1b1e" />
      <stop offset="100%" stop-color="#091315" />
    </linearGradient>
  </defs>
  <rect width="1024" height="1024" rx="200" fill="url(#bg-grad-l4)" />
</svg>
SVG
rsvg-convert -w 1024 -h 1024 "$TMP/bg-full-1024.svg" -o "$TMP/bg-full-1024.png"
rsvg-convert -w 1024 -h 1024 "$TMP/bg-squircle-1024.svg" -o "$TMP/bg-squircle-1024.png"

# Trimmed glyph sized for mobile tiles
magick "$TMP/glyph-1024.png" -trim +repage -resize x${MOBILE_GLYPH_H} "$TMP/mobile-glyph-trimmed.png"

# iOS tile: full-bleed square with 15% smaller centered lock (no transparent corners, HIG compliant)
IOS_TILE="$TMP/ios-tile-1024.png"
magick "$TMP/bg-full-1024.png" "$TMP/mobile-glyph-trimmed.png" -gravity center -composite "$IOS_TILE"

# Android legacy tile: squircle with 15% smaller centered lock
ANDROID_LEGACY_TILE="$TMP/android-legacy-tile-1024.png"
magick "$TMP/bg-squircle-1024.png" "$TMP/mobile-glyph-trimmed.png" -gravity center -composite "$ANDROID_LEGACY_TILE"

mkdir -p "$OUT_DIR"/{windows,macos,linux,tauri-desktop,android,ios}
mkdir -p "$OUT_DIR"/android/mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}

echo "1/6 Linux PNGs..."
for s in 32 64 128 256 512; do
  magick "$TILE" -resize ${s}x${s} "$OUT_DIR/linux/${s}x${s}.png"
done
cp "$OUT_DIR/linux/512x512.png" "$OUT_DIR/linux/icon.png"

echo "2/6 Windows ICO..."
magick "$TILE" -define icon:auto-resize=256,64,48,32,24,16 "$OUT_DIR/windows/icon.ico"

echo "3/6 macOS ICNS..."
for s in 16 32 64 128 256 512 1024; do
  magick "$TILE" -resize ${s}x${s} "$TMP/icns-${s}.png"
done
# Assemble the ICNS container (magick writes single-size icns only; the format
# itself is just a header + typed PNG entries, so assemble it directly).
python3 - "$OUT_DIR/macos/icon.icns" "$TMP" <<'PY'
import struct, sys, os
out, tmp = sys.argv[1], sys.argv[2]
entries = [("icp4", 16), ("ic11", 32), ("ic12", 64), ("ic08", 128),
           ("ic09", 256), ("ic14", 512), ("ic10", 1024)]
blobs = []
for typ, s in entries:
    with open(os.path.join(tmp, f"icns-{s}.png"), "rb") as f:
        data = f.read()
    blobs.append(typ.encode() + struct.pack(">I", len(data) + 8) + data)
with open(out, "wb") as f:
    f.write(b"icns" + struct.pack(">I", 8 + sum(len(b) for b in blobs)))
    for b in blobs:
        f.write(b)
PY

echo "4/6 Tauri desktop set..."
cp "$OUT_DIR/linux/32x32.png"  "$OUT_DIR/tauri-desktop/32x32.png"
cp "$OUT_DIR/linux/128x128.png" "$OUT_DIR/tauri-desktop/128x128.png"
cp "$OUT_DIR/linux/256x256.png" "$OUT_DIR/tauri-desktop/128x128@2x.png"
cp "$OUT_DIR/macos/icon.icns"  "$OUT_DIR/tauri-desktop/icon.icns"
cp "$OUT_DIR/windows/icon.ico" "$OUT_DIR/tauri-desktop/icon.ico"

echo "5/6 Android launcher icons..."
# Legacy full-tile rasters (system-UI fallbacks; launchers use the adaptive XML).
for pair in mdpi:48 hdpi:72 xhdpi:96 xxhdpi:144 xxxhdpi:192; do
  d=${pair%%:*}; s=${pair##*:}
  magick "$ANDROID_LEGACY_TILE" -resize ${s}x${s} "$OUT_DIR/android/mipmap-$d/ic_launcher.png"
done
# Adaptive foreground layers (108dp base x density).
for pair in mdpi:108 hdpi:162 xhdpi:216 xxhdpi:324 xxxhdpi:432; do
  d=${pair%%:*}; s=${pair##*:}
  magick "$FG" -resize ${s}x${s} "$OUT_DIR/android/mipmap-$d/ic_launcher_foreground.png"
done
mkdir -p "$OUT_DIR/android/mipmap-anydpi-v26" "$OUT_DIR/android/values"
cat > "$OUT_DIR/android/mipmap-anydpi-v26/ic_launcher.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<!-- Adaptive launcher icon: full-bleed dark background layer + padlock
     foreground (glyph-only PNG, sized for the 66dp safe zone). The launcher
     applies its own mask (squircle/circle/etc), so the icon fills the whole
     tile like Bitwarden instead of being shrink-wrapped on white. -->
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
    <monochrome android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
XML
cat > "$OUT_DIR/android/values/ic_launcher_background.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<!-- Midpoint of the brand tile gradient (#0e1b1e -> #091315). -->
<resources>
    <color name="ic_launcher_background">#0B1719</color>
</resources>
XML

echo "6/6 iOS icons..."
for pair in 40:AppIcon-20x20@2x 60:AppIcon-20x20@3x 29:AppIcon-29x29@1x 58:AppIcon-29x29@2x 87:AppIcon-29x29@3x 40:AppIcon-40x40@1x 80:AppIcon-40x40@2x 120:AppIcon-40x40@3x 120:AppIcon-60x60@2x 180:AppIcon-60x60@3x 76:AppIcon-76x76@1x 152:AppIcon-76x76@2x 167:AppIcon-83x83@2x 1024:AppIcon-1024x1024; do
  s=${pair%%:*}; n=${pair##*:}
  magick "$IOS_TILE" -resize ${s}x${s} "$OUT_DIR/ios/${n}.png"
done

echo "Deploying to desktop (Tauri)..."
cp "$OUT_DIR"/tauri-desktop/* desktop/src-tauri/icons/
cp "$OUT_DIR/linux/icon.png" desktop/src-tauri/icons/icon.png
cp "$OUT_DIR/linux/64x64.png" desktop/src-tauri/icons/64x64.png
# Browser-extension toolbar icon source (vite resizes 48/128 from this at build).
magick "$TILE" -resize 512x512 desktop/src/assets/logo.png

echo "Deploying to Android app res..."
for d in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
  cp "$OUT_DIR/android/mipmap-$d/ic_launcher.png" "$RES_DIR/mipmap-$d/ic_launcher.png"
  cp "$OUT_DIR/android/mipmap-$d/ic_launcher_foreground.png" "$RES_DIR/mipmap-$d/ic_launcher_foreground.png"
done
mkdir -p "$RES_DIR/mipmap-anydpi-v26" "$RES_DIR/values"
cp "$OUT_DIR/android/mipmap-anydpi-v26/ic_launcher.xml" "$RES_DIR/mipmap-anydpi-v26/ic_launcher.xml"
cp "$OUT_DIR/android/values/ic_launcher_background.xml" "$RES_DIR/values/ic_launcher_background.xml"

echo "All platform icons generated and deployed successfully."
