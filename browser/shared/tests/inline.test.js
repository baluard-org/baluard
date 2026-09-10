// Import smoke + fill-origin gating for inline.js.
//
// The IIFE registers page listeners at import time against the jsdom
// document and the chrome mock (setup.js) — importing it must not throw and
// must not mount the shadow host before any qualifying focus happens
// (zero page surface until a login field is focused).

import { describe, it, expect } from "vitest";
import "../src/inline.js";
import { statusKeyFor } from "../src/inline.js";

describe("statusKeyFor (inline dropdown status mapping)", () => {
  it("maps daemon/lock states to actionable status keys", () => {
    // Same codes the popup state machine maps (popup.jsx refresh catch).
    expect(statusKeyFor("no-daemon")).toBe("appRequired");
    expect(statusKeyFor("locked")).toBe("locked");
    expect(statusKeyFor("version-skew")).toBe("updateApp");
    expect(statusKeyFor("not-paired")).toBe("notPaired");
  });

  it("falls back to noMatches for unknown codes", () => {
    expect(statusKeyFor(undefined)).toBe("noMatches");
    expect(statusKeyFor("no-match")).toBe("noMatches");
    expect(statusKeyFor("proto")).toBe("noMatches");
  });
});

describe("inline.js import", () => {
  it("registers without throwing and mounts nothing until focus", () => {
    expect(window.__baluardInline).toBe(true);
    const hosts = document.querySelectorAll("[data-baluard-inline]");
    expect(hosts.length).toBe(0);
  });

  it("double injection is guarded (second import is a no-op)", async () => {
    // Dynamic re-import: module cache makes this the same module, so the
    // guard flag is what actually protects production double-injection.
    await import("../src/inline.js");
    expect(window.__baluardInline).toBe(true);
  });
});
