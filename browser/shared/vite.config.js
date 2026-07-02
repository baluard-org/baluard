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
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

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
  // compat (review agy Nit). background.js has no ES imports, so a plain
  // script tag loads cleanly. Chrome keeps service_worker.
  if (target === "firefox") {
    merged.background = { scripts: ["background.js"] };
  }
  return JSON.stringify(merged, null, 2);
}

// Minimal plugin: copies background.js, writes the merged manifest, after bundle.
function extensionPackPlugin() {
  return {
    name: "baluard-extension-pack",
    closeBundle() {
      const outDir = resolve(__dirname, "..", target, "dist");
      mkdirSync(outDir, { recursive: true });
      copyFileSync(
        resolve(__dirname, "src/background.js"),
        resolve(outDir, "background.js")
      );
      // Phase 1: content script (fill executor) + offscreen clipboard doc.
      copyFileSync(
        resolve(__dirname, "src/content.js"),
        resolve(outDir, "content.js")
      );
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
      // icons placeholder dir
      try {
        mkdirSync(resolve(outDir, "icons"), { recursive: true });
      } catch {}
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
