// Unit tests for settings.js (chrome.storage.local wrapper).
//
// The global chrome mock (setup.js) returns {} for every storage read, so
// these tests install a Map-backed fake storage.local to exercise defaults,
// merge semantics, and write-through.

import { describe, it, expect, beforeEach } from "vitest";
import { getSettings, updateSettings, DEFAULT_SETTINGS, normalizeClearSeconds, CLEAR_SECONDS_CHOICES } from "../src/settings.js";

function installFakeStorage() {
  const store = new Map();
  globalThis.chrome.storage.local = {
    get: (keys, cb) => {
      const out = {};
      for (const k of keys) if (store.has(k)) out[k] = store.get(k);
      cb(out);
    },
    set: (obj, cb) => {
      for (const [k, v] of Object.entries(obj)) store.set(k, v);
      cb && cb();
    },
    _store: store,
  };
  return store;
}

describe("getSettings", () => {
  beforeEach(() => installFakeStorage());

  it("returns defaults when nothing is stored", async () => {
    expect(await getSettings()).toEqual(DEFAULT_SETTINGS);
  });

  it("inline autofill defaults to ON (1Password/Bitwarden parity)", async () => {
    const s = await getSettings();
    expect(s.inlineAutofill).toBe(true);
  });

  it("returns stored values over defaults", async () => {
    const store = installFakeStorage();
    store.set("settings", { inlineAutofill: false });
    expect(await getSettings()).toEqual({
      inlineAutofill: false,
      copyTotp: true,
      clipboardClearSeconds: 60,
    });
  });

  it("copyTotp defaults to ON (1Password/Bitwarden parity)", async () => {
    const s = await getSettings();
    expect(s.copyTotp).toBe(true);
  });

  it("clipboard auto-clear defaults to 60 seconds", async () => {
    const s = await getSettings();
    expect(s.clipboardClearSeconds).toBe(60);
  });
});

describe("updateSettings", () => {
  beforeEach(() => installFakeStorage());

  it("merges the patch into current settings and persists", async () => {
    const next = await updateSettings({ inlineAutofill: false });
    expect(next.inlineAutofill).toBe(false);
    const store = globalThis.chrome.storage.local._store;
    expect(store.get("settings")).toEqual({
      inlineAutofill: false,
      copyTotp: true,
      clipboardClearSeconds: 60,
    });
  });

  it("keeps unrelated future keys when merging", async () => {
    const store = installFakeStorage();
    store.set("settings", { inlineAutofill: false, futureKey: 42 });
    const next = await updateSettings({ inlineAutofill: true });
    expect(next).toEqual({
      inlineAutofill: true,
      copyTotp: true,
      clipboardClearSeconds: 60,
      futureKey: 42,
    });
  });
});

describe("normalizeClearSeconds", () => {
  it("passes through every UI choice (0 = never)", () => {
    for (const c of CLEAR_SECONDS_CHOICES) expect(normalizeClearSeconds(c)).toBe(c);
  });

  it("coerces numeric strings from storage round-trips", () => {
    expect(normalizeClearSeconds("30")).toBe(30);
    expect(normalizeClearSeconds("0")).toBe(0);
  });

  it("falls back to 60 on junk", () => {
    expect(normalizeClearSeconds(undefined)).toBe(60);
    expect(normalizeClearSeconds(null)).toBe(60);
    expect(normalizeClearSeconds("banana")).toBe(60);
    expect(normalizeClearSeconds(45)).toBe(60);
    expect(normalizeClearSeconds(-10)).toBe(60);
  });
});
