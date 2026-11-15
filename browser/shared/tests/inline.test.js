// Import smoke + fill-origin gating for inline.js.
//
// The IIFE registers page listeners at import time against the jsdom
// document and the chrome mock (setup.js) — importing it must not throw and
// must not mount the shadow host before any qualifying focus happens
// (zero page surface until a login field is focused).

import { describe, it, expect } from "vitest";
import "../src/inline.js";
import { statusKeyFor, otpRingState } from "../src/inline.js";

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

describe("otpRingState (inline TOTP ring math)", () => {
  it("returns a full window at a period boundary", () => {
    expect(otpRingState(30, 1800)).toEqual({ seconds: 30, expiring: false, period: 30 });
  });

  it("counts down and flags the expiring window at 7s and under", () => {
    expect(otpRingState(30, 1805)).toEqual({ seconds: 25, expiring: false, period: 30 });
    expect(otpRingState(30, 1823)).toEqual({ seconds: 7, expiring: true, period: 30 });
    expect(otpRingState(30, 1829)).toEqual({ seconds: 1, expiring: true, period: 30 });
  });

  it("supports non-30 periods", () => {
    expect(otpRingState(60, 1835)).toEqual({ seconds: 25, expiring: false, period: 60 });
    expect(otpRingState(60, 1859)).toEqual({ seconds: 1, expiring: true, period: 60 });
  });

  it("falls back to a 30s window when the period is unusable", () => {
    expect(otpRingState(0, 1805)).toEqual({ seconds: 25, expiring: false, period: 30 });
    expect(otpRingState(undefined, 1823)).toEqual({ seconds: 7, expiring: true, period: 30 });
    expect(otpRingState(-5, 1805)).toEqual({ seconds: 25, expiring: false, period: 30 });
  });

  it("floors fractional seconds so the ring never looks fresher than the code", () => {
    // The daemon rotates on floor(now/period); rounding here would show a
    // full fresh window for the last half second of the old one.
    expect(otpRingState(30, 1822.6)).toEqual({ seconds: 8, expiring: false, period: 30 });
    expect(otpRingState(30, 1822.4)).toEqual({ seconds: 8, expiring: false, period: 30 });
    expect(otpRingState(30, 1829.9)).toEqual({ seconds: 1, expiring: true, period: 30 });
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
