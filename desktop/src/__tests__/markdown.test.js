// Tests for desktop/src/lib/markdown.js — markdown detection heuristic and
// the sanitized renderer used by entry notes. Detection must be conservative:
// ordinary prose never renders as markdown; markdown input must come out
// sanitized (no script/img/iframe, links restricted to safe schemes).

import { describe, it, expect } from "vitest";
import { looksLikeMarkdown, renderMarkdown } from "../lib/markdown.js";

describe("looksLikeMarkdown", () => {
  const mdCases = [
    "# Heading",
    "## Sub heading",
    "line one\n\n# A title\n\nline two",
    "**bold text**",
    "__bold text__",
    "*italic text*",
    "some `inline code` here",
    "- list item",
    "* list item",
    "1. first item",
    "1) first item",
    "> a quote",
    "```\ncode block\n```",
    "[a link](https://example.com)",
    "| a | b |\n| --- | --- |\n| 1 | 2 |",
    "---",
  ];

  it.each(mdCases)("detects markdown: %j", (text) => {
    expect(looksLikeMarkdown(text)).toBe(true);
  });

  const plainCases = [
    "",
    null,
    "ab",
    "router admin / see sticker on bottom",
    "3 * 4 * 5",
    "2*3*4 multiplication",
    "snake_case_name",
    "file_v2_final.txt",
    "hello world, nothing special",
    "e-mail me at user@example.com",
    "10 * 20 = 200",
  ];

  it.each(plainCases)("treats as plain text: %j", (text) => {
    expect(looksLikeMarkdown(text)).toBe(false);
  });
});

describe("renderMarkdown", () => {
  it("renders headings, emphasis and lists to HTML", () => {
    const html = renderMarkdown("# Title\n\n**bold** and *soft*\n\n- one\n- two");
    expect(html).toContain("<h1");
    expect(html).toContain("Title");
    expect(html).toContain("<strong>bold</strong>");
    expect(html).toContain("<em>soft</em>");
    expect(html).toContain("<li>one</li>");
  });

  it("keeps single newlines as line breaks (breaks: true)", () => {
    const html = renderMarkdown("line one\nline two");
    expect(html).toContain("<br");
  });

  it("renders raw HTML as inert escaped text (no script execution)", () => {
    const html = renderMarkdown("hello <script>window.evil = 1</script> world");
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("window.evil = 1");
  });

  it("renders raw tags with handlers as escaped text (handlers inert)", () => {
    const html = renderMarkdown('<a href="https://example.com" onclick="evil()">x</a>');
    expect(html).not.toContain("<a href");
    expect(html).toContain("&lt;a href=");
    expect(html).toContain("x&lt;/a&gt;");
  });

  it("drops img and iframe tags (no remote fetches from vault content)", () => {
    const html = renderMarkdown('<img src="https://beacon.example/pixel.png">t\n<iframe src="https://beacon.example"></iframe>');
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<iframe");
  });

  it("strips javascript: link targets", () => {
    const html = renderMarkdown("[click](javascript:alert(1))");
    expect(html).not.toContain("javascript:");
  });

  it("strips data: and vbscript: link targets", () => {
    const html = renderMarkdown("[a](data:text/html,hi) [b](vbscript:x)");
    expect(html).not.toContain("data:");
    expect(html).not.toContain("vbscript:");
  });

  it("keeps raw pseudo-tag text visible instead of swallowing it", () => {
    const html = renderMarkdown("ask the <admin> or check <your-password>");
    expect(html).toContain("&lt;admin&gt;");
    expect(html).toContain("&lt;your-password&gt;");
  });

  it("exposes link destinations via title attr (anti-phishing)", () => {
    const html = renderMarkdown("[mybank](https://evil.test)");
    expect(html).toContain('title="https://evil.test"');
  });

  it("keeps safe links with their href", () => {
    const html = renderMarkdown("[site](https://example.com)");
    expect(html).toContain('href="https://example.com"');
  });
});
