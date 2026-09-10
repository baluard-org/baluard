// Vite config: builds both Chrome and Firefox targets from the shared source.
// TARGET env var selects which manifest extra to merge.
//
// Output layout per target:
//   browser/<target>/dist/
//     manifest.json   (base + target extra merged)
//     background.js   (copied, not bundled — it's a service worker, no imports)
//     popup.html + assets/   (SolidJS popup, bundled)

import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";
import { build as esbuild } from "esbuild";

const __dirname = dirname(fileURLToPath(import.meta.url));
const target = process.env.TARGET || "chrome";

function mergeManifest() {
  const base = JSON.parse(
    readFileSync(resolve(__dirname, "manifest.base.json"), "utf8")
  );
  let merged = base;
  const extraPath = resolve(__dirname, `../${target}/manifest.extra.json`);
  try {
    const extra = JSON.parse(readFileSync(extraPath, "utf8"));
    merged = { ...base, ...extra };
  } catch {
    // No extra for this target — chrome has none.
  }
  // Firefox MV3: `background.service_worker` is only supported on FF 121+,
  // and our strict_min is 115. Use the event-page `scripts` form for broad
  // compat. background.js has no ES imports, so a plain
  // script tag loads cleanly. Chrome keeps service_worker.
  if (target === "firefox") {
    merged.background = { scripts: ["background.js"] };
    // B8: `offscreen` is Chrome-only. Subtract base-only permissions during
    // the merge so they never reach the Firefox dist (unknown-permission
    // warning at AMO review). Firefox falls back to popup-context
    // navigator.clipboard (see background.js clipboardCopy).
    merged.permissions = (merged.permissions || []).filter(
      (p) => p !== "offscreen"
    );
  }
  return JSON.stringify(merged, null, 2);
}

// Minimal plugin: copies background.js, writes the merged manifest, after bundle.
function extensionPackPlugin() {
  return {
    name: "baluard-extension-pack",
    async closeBundle() {
      const outDir = resolve(__dirname, "..", target, "dist");
      mkdirSync(outDir, { recursive: true });
      // background.js bundles as an IIFE: it uses ES `export` for unit
      // tests (which import the SOURCE file), but Firefox loads the built
      // file as a classic event-page script (background.scripts) where
      // `export` is a syntax error. IIFE bundling strips the exports;
      // Chrome's service_worker (type: module) also accepts a plain IIFE.
      // content.js (popup-driven fill executor) + inline.js (in-field
      // dropdown, dynamically registered by the SW while the setting is on)
      // share autofill.js via ES imports, so they bundle the same way.
      await esbuild({
        entryPoints: [
          resolve(__dirname, "src/background.js"),
          resolve(__dirname, "src/content.js"),
          resolve(__dirname, "src/inline.js"),
        ],
        outdir: outDir,
        bundle: true,
        format: "iife",
        target: "es2022",
        minify: true,
        legalComments: "none",
        logLevel: "warning",
      });
      copyFileSync(
        resolve(__dirname, "offscreen.html"),
        resolve(outDir, "offscreen.html")
      );
      copyFileSync(
        resolve(__dirname, "src/offscreen.js"),
        resolve(outDir, "offscreen.js")
      );
      writeFileSync(resolve(outDir, "manifest.json"), mergeManifest());
      // Copy popup.html into outDir (vite emits assets/ for JS).
      copyFileSync(
        resolve(__dirname, "popup.html"),
        resolve(outDir, "popup.html")
      );
      // icons: the lock GLYPH only (assets/baluard-lock-only.svg), sized
      // like competitors' toolbar icons (glyph fills ~88% of the canvas).
      // The desktop app logo's dark tile is designed for in-app use; on the
      // 16dp Chromium toolbar the tile reads as a dark blob and the lock
      // inside it looks undersized next to other extensions' glyphs. The
      // SVG is rasterized once, trimmed to its painted bounds, then placed
      // centered on a transparent canvas per size (crisp at 16/32 HiDPI).
      const iconsDir = resolve(outDir, "icons");
      mkdirSync(iconsDir, { recursive: true });
      const lockSvgPath = resolve(__dirname, "../../assets/baluard-lock-only.svg");
      if (!existsSync(lockSvgPath)) {
        throw new Error(`[baluard-extension-pack] icon source not found: ${lockSvgPath}`);
      }
      // viewBox is 512; default 72dpi density renders it at 512px — enough
      // resolution for the 128px store icon.
      const glyphPainted = await sharp(readFileSync(lockSvgPath), { density: 72 })
        .trim({ threshold: 20 })
        .png()
        .toBuffer({ resolveWithObject: true });
      const GLYPH_FILL = 0.88; // painted height per canvas edge
      const makeIcon = async (size) => {
        const glyph = await sharp(glyphPainted.data)
          .resize({ height: Math.round(size * GLYPH_FILL) })
          .png()
          .toBuffer();
        await sharp({
          create: {
            width: size,
            height: size,
            channels: 4,
            background: { r: 0, g: 0, b: 0, alpha: 0 },
          },
        })
          .composite([{ input: glyph, gravity: "centre" }])
          .png()
          .toFile(resolve(iconsDir, `icon-${size}.png`));
      };
      await Promise.all([16, 32, 48, 128].map(makeIcon));
    },
  };
}

export default defineConfig({
  plugins: [solid(), extensionPackPlugin()],
  build: {
    target: "es2022",
    outDir: resolve(__dirname, "..", target, "dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(__dirname, "src/popup.jsx"),
      output: {
        entryFileNames: "assets/popup.js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
});
