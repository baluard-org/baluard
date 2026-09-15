// Shared URL helpers for the two bundles that resolve imports (background.js
// is esbuild-bundled, popup.jsx is vite-bundled). The content scripts compare
// location.origin directly and do not need this module.

// B1: fill-time origin (scheme + host + port). A credential saved on
// https://example.com must NOT fill on http://example.com — a network
// attacker can serve the plain-HTTP page and read the typed password.
// Content scripts compare this against location.origin (same definition).
export function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}
