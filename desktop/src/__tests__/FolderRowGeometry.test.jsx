import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

// Folder rows carry inline geometry rather than utility classes, so these
// contracts are pinned statically against FolderTree.jsx and VaultView.jsx.
describe("folder row geometry contract", () => {
  const tree = fs.readFileSync(
    path.resolve(process.cwd(), "src/components/FolderTree.jsx"),
    "utf8",
  );
  const view = fs.readFileSync(
    path.resolve(process.cwd(), "src/components/VaultView.jsx"),
    "utf8",
  );

  it("folder counts share the category badge column", () => {
    // Category rows inset their badge 14px (px-3.5) from the sidebar edge;
    // the folder row's inline right padding must match or the number columns
    // drift apart.
    expect(view).toMatch(/px-3\.5 py-2\.5 rounded-xl/);
    expect(tree).toContain('"padding-right": "14px"');
  });

  it("the count badge is exactly as tall as the hover toolbar buttons", () => {
    // Hover swaps the badge for toolbar buttons; if the two differ in height
    // the hovered row reflows and every row below it jumps a couple of
    // pixels. Both must be fixed-height 18px (icon 12 + p-0.5 + borders).
    const badge = tree.match(/class="ml-auto [^"]*"[^>]*>\s*\{folderCount\(\)\}/)?.[0] ?? "";
    expect(badge).toContain("h-[18px]");
    expect(badge).not.toContain("py-0.5");
    const confirm = tree.match(/confirmDelete"[\s\S]*?class="([^"]*)"/)?.[1] ?? "";
    expect(confirm).toContain("h-[18px]");
    expect(confirm).not.toContain("py-0.5");
  });
});
