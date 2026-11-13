import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

// The tag input is a bare borderless box inside the rounded wrapper, so the
// global keyboard-nav outline rendered as a sharp rectangle inside it instead
// of following the wrapper's radius like every other field. The wrapper owns
// the focus indicator (focus-within border) and the input's outline is
// suppressed — same contract as the vault search field. These static guards
// pin both halves; a form-markup regression or a global-outline change to
// bare inputs inside wrappers reintroduces the double box.
describe("tag input focus contract", () => {
  const css = fs.readFileSync(path.resolve(process.cwd(), "src/app.css"), "utf8");
  const form = fs.readFileSync(
    path.resolve(process.cwd(), "src/components/AddEditCipherForm.jsx"),
    "utf8",
  );

  it("the tags wrapper carries the focus-within border", () => {
    expect(form).toMatch(/vault-tags [^"]*focus-within:border-\[var\(--color-primary\)\]/);
  });

  it("the tag input's outline is suppressed like the search input's", () => {
    expect(css).toMatch(/\.vault-search input:focus-visible,\s*\.vault-tags input:focus-visible\s*{\s*outline: none !important;/);
  });
});
