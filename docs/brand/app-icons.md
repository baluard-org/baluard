# App icons

The single source is `assets/baluard-appicon.svg`, a 1024 px master carrying the grey tile and the lock shadow. The brand lock SVGs (`baluard-lock-l4.svg`, `baluard-lock-only.svg`) are separate marks: the browser extension build and the store art derive from them and deliberately keep the older dark tile.

Regenerate the whole platform set from the repo root:

```sh
cd desktop
npx @tauri-apps/cli icon ../assets/baluard-appicon.svg
```

The CLI writes everything under `desktop/src-tauri/icons/`: the Tauri bundle icons (icon.icns, icon.ico, the PNG sizes, Square and StoreLogo tiles), the Android launcher mipmaps in `android/mipmap-*`, and the iOS AppIcons in `ios/` — about 52 files. Commit everything it changes; the icons ship with the next release build.

Before committing, render the source with rsvg-convert at 32 px and 58 px and check the tile and shadow stay legible on a dark background. There is no separate icon pipeline: the old magick-based generator was removed; this command is the only path.
