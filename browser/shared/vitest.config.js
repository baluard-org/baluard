import { defineConfig } from "vitest/config";

// Vitest config for the browser extension. Defaults to jsdom for DOM-heavy
// tests (content.js form fill) but lets individual files opt into the node
// environment via `// @vitest-environment node` for pure-logic tests
// (background.js semver compare, offscreen.js message routing).
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.{js,jsx}"],
    globals: false,
    setupFiles: ["./tests/setup.js"],
  },
});