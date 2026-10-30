// Pure-logic tests for desktop/src/lib/update.js — the opt-out store, the
// startup jitter, the background-check schedule, and progress formatting.

import { describe, it, expect } from "vitest";
import {
  STARTUP_JITTER_MS,
  CHECK_INTERVAL_MS,
  autoChecksEnabled,
  setAutoChecksEnabled,
  startupDelayMs,
  lastCheckAt,
  noteCheckNow,
  backgroundCheckDue,
  formatProgress,
} from "../lib/update.js";

function fakeStore(initial = {}) {
  const data = { ...initial };
  return {
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = String(v);
    },
    removeItem: (k) => {
      delete data[k];
    },
    _data: data,
  };
}

describe("update auto-check opt-out", () => {
  it("defaults to enabled", () => {
    expect(autoChecksEnabled(fakeStore())).toBe(true);
  });

  it("persists the opt-out and clears it on re-enable", () => {
    const store = fakeStore();
    setAutoChecksEnabled(false, store);
    expect(store._data["baluard.updateChecks"]).toBe("off");
    expect(autoChecksEnabled(store)).toBe(false);
    setAutoChecksEnabled(true, store);
    expect(store._data["baluard.updateChecks"]).toBeUndefined();
    expect(autoChecksEnabled(store)).toBe(true);
  });
});

describe("startup jitter", () => {
  it("stays within [0, STARTUP_JITTER_MS]", () => {
    for (const r of [0, 0.5, 0.9999]) {
      const d = startupDelayMs(() => r);
      expect(d).toBeGreaterThanOrEqual(0);
      expect(d).toBeLessThanOrEqual(STARTUP_JITTER_MS);
    }
  });
});

describe("background check schedule", () => {
  it("is disabled entirely when the user opted out", () => {
    const store = fakeStore({ "baluard.updateChecks": "off" });
    expect(backgroundCheckDue(1000, store)).toBe(false);
  });

  it("is due when never checked", () => {
    expect(backgroundCheckDue(1000, fakeStore())).toBe(true);
  });

  it("is not due right after a check", () => {
    const store = fakeStore();
    noteCheckNow(1000, store);
    expect(backgroundCheckDue(1000 + CHECK_INTERVAL_MS - 1, store)).toBe(false);
  });

  it("is due once the interval has elapsed", () => {
    const store = fakeStore();
    noteCheckNow(1000, store);
    expect(backgroundCheckDue(1000 + CHECK_INTERVAL_MS, store)).toBe(true);
  });

  it("lastCheckAt tolerates garbage", () => {
    expect(lastCheckAt(fakeStore({ "baluard.updateLastCheck": "abc" }))).toBeNull();
    expect(lastCheckAt(fakeStore({ "baluard.updateLastCheck": "0" }))).toBeNull();
  });
});

describe("formatProgress", () => {
  it("returns null without a usable total", () => {
    expect(formatProgress(10, 0)).toBeNull();
    expect(formatProgress(10, undefined)).toBeNull();
  });

  it("computes a bounded percentage", () => {
    expect(formatProgress(50, 200)).toBe(25);
    expect(formatProgress(500, 200)).toBe(100);
  });
});
