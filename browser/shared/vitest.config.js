import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

// Vitest config for the browser extension. Defaults to jsdom for DOM-heavy
// tests (content.js form fill, popup settings toggles) but lets individual
// files opt into the node environment via `// @vitest-environment node` for
// pure-logic tests (background.js semver compare, offscreen.js routing).
export default defineConfig({
  plugins: [solid()],
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.{js,jsx}"],
    globals: false,
    setupFiles: ["./tests/setup.js"],
  },
});