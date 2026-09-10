// Build-artifact canary (dists are committed per B11).
//
// Solid entity-escapes STATIC JSX children, which silently turned every
// "&" nesting selector in the popup's <style> block into "&amp;" — real
// Chrome then dropped the rules (`.toggle.on`, `:hover`, `:active`,
// `.danger`), making the settings toggles flip state with zero visual
// feedback. The CSS now ships as an ?inline string rendered as a DYNAMIC
// child (text-node insertion, never escaped). This canary fails if the
// escaping ever sneaks back into the shipped popup bundle.
// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const distPopup = (target) =>
  readFileSync(
    resolve(process.cwd(), `../${target}/dist/assets/popup.js`),
    "utf8"
  );

describe("popup css canary (no html-escaped selectors)", () => {
  for (const target of ["chrome", "firefox"]) {
    it(`${target}: dist popup.js carries raw "&" selectors, not "&amp;"`, () => {
      const js = distPopup(target);
      expect(js.includes("&amp;")).toBe(false);
      // The state-painting selectors must exist raw; .toggle.on is the one
      // whose absence made the settings toggles look dead.
      expect(js.includes("&.on")).toBe(true);
    });
  }
});
