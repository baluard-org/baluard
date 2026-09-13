# App Icons

> How Baluard generates platform icons (macOS `.icns`, Windows `.ico`, Linux PNG, Android, iOS) from a single source image.

**Recipe:** `just app-icons` (defined in `justfile`)
**Tool:** [`icon-gen`](https://github.com/Hkmu/icon-generator) (Rust CLI, MIT)
**Source:** `assets/baluard-logo-grad.png` (the icon *tile*, dark gradient + padlock + "B")

---

## Why not commit the generated icons?

`assets/app-icons/` is gitignored. It is **33 derived files** across 6 platform groups, all reproducible from one source image in under a second. Committing them would bloat diffs every time the logo changes. The single source of truth is the PNG/SVG master in `assets/`.

Only the **deployed** desktop icons in `desktop/src-tauri/icons/` are committed (they are built into the bundle).

---

## Source image choice

Baluard ships two logo variants in `assets/`:

| File | Form | Use as app icon? |
|---|---|---|
| `baluard-logo-grad.png` | Icon **tile**: dark gradient background + neon-green padlock + "B", fills the frame | **Yes (default)** |
| `baluard-logo-grad-lock.png` | Padlock on **white** background, centered with margin | No, produces white-square icons that look broken on dark docks/taskbars |

The recipe defaults to the tile. The logo is portrait (1888×2254); `icon-gen` requires square input, so the recipe auto-squares it (see [Squaring step](#squaring-step)).

Override the source at invocation time:

```bash
just app-icons assets/baluard-logo-grad-lock.png   # if you really want the white-bg lock
just app-icons assets/new-logo.png assets/custom-out  # custom source + output dir
```

---

## Install (one-time)

The recipe needs two tools: [`icon-gen`](https://github.com/Hkmu/icon-generator) and ImageMagick.

### macOS

```bash
brew install imagemagick
brew install rustup-init && rustup-init -y
cargo install --git https://github.com/Hkmu/icon-generator.git
source ~/.zshrc   # pick up ~/.cargo/bin
```

### Linux

```bash
# ImageMagick (varies by distro; Homebrew works too)
sudo apt install imagemagick        # Debian/Ubuntu
sudo dnf install ImageMagick        # Fedora

# Rust + icon-gen
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install --git https://github.com/Hkmu/icon-generator.git
```

### Verify

```bash
magick --version
icon-gen --version
```

---

## Generate

```bash
just app-icons
```

Output (`assets/app-icons/`):

```
windows/        icon.ico                          (6 layers: 16/24/32/48/64/256)
macos/          icon.icns + Contents.json         (macOS 15 compliant: 16→1024 incl. @2x)
linux/          32/64/128/256 PNGs + icon.png (512)
tauri-desktop/  32x32, 128x128, 128x128@2x, icon.ico, icon.icns
android/        mipmap-{mdpi..xxxhdpi}/ic_launcher.png
ios/            AppIcon-* @1x/@2x/@3x + Contents.json
```

---

## Squaring step

`icon-gen` requires square input. The recipe uses ImageMagick to auto-square:

1. **Trim** transparent margins (`-trim`).
2. **Center-pad** to square on transparent background (`-extent %[fx:max(w,h)]x%[fx:max(w,h)]`).
3. **Resize** to 1024×1024 (the master size `icon-gen` expects).

The squaring command (run by `just app-icons`):

```bash
magick "$SRC" -trim +repage -background none -gravity center \
    -extent "%[fx:max(w,h)]x%[fx:max(w,h)]" -resize 1024x1024 "$SQ"
```

---

## Deploy

### Desktop (Tauri)

`tauri.conf.json` references 5 files. Copy the whole `tauri-desktop/` set (the `.icns` inside is byte-identical to `macos/icon.icns`):

```bash
cp assets/app-icons/tauri-desktop/* desktop/src-tauri/icons/
```

Then rebuild to see it in the app:

```bash
just desktop-debug
```

> **Icon cache:** macOS aggressively caches app icons. If the dock still shows the old one after rebuild:
> ```bash
> sudo rm -rfv /Library/Caches/com.apple.iconservices.store
> killall Dock Finder
> ```

### Mobile (Android / iOS)

The mobile target dirs (`desktop/src-tauri/gen/android`, `gen/ios`) are populated by `tauri android init` / `taura ios init`. Until those run, the `android/` and `ios/` outputs from `icon-gen` wait in `assets/app-icons/`. After init:

```bash
# Android
cp -r assets/app-icons/android/mipmap-* desktop/src-tauri/gen/android/app/src/main/res/

# iOS
cp assets/app-icons/ios/AppIcon-*.png assets/app-icons/ios/Contents.json \
   desktop/src-tauri/gen/ios/Assets.xcassets/AppIcon.appiconset/
```

---

## Platform coverage reference

| Platform | Format | Sizes | Verified |
|---|---|---|---|
| macOS | `.icns` | 16, 32, 128, 256, 512, 1024 (@1x + @2x retina) | OSTypes `ic07`–`ic14`, `is32/il32` ✅ |
| Windows | `.ico` | 16, 24, 32, 48, 64, 256 (PNG-compressed 256) | 6 layers ✅ |
| Linux | PNG | 32, 64, 128, 256, 512 | - |
| Android | PNG | mdpi 48 → xxxhdpi 192 | - |
| iOS | PNG | 20→1024px, @1x/@2x/@3x | `Contents.json` ✅ |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `icon-gen: command not found` | `cargo install --git https://github.com/Hkmu/icon-generator.git` |
| `magick: command not found` | `brew install imagemagick` (macOS) / `apt install imagemagick` (Linux) |
| White square on dark dock | You passed the `*-lock.png` source. Use `baluard-logo-grad.png` (the tile). |
| Icon off-center / cropped | The squaring step failed to trim. Check the source has an alpha channel. |
| Old icon still showing after swap | Clear the icon cache (see Desktop deploy above). |
