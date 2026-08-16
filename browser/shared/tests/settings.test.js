// Unit tests for settings.js (chrome.storage.local wrapper).
//
// The global chrome mock (setup.js) returns {} for every storage read, so
// these tests install a Map-backed fake storage.local to exercise defaults,
// merge semantics, and write-through.

import { describe, it, expect, beforeEach } from "vitest";
import { getSettings, updateSettings, DEFAULT_SETTINGS } from "../src/settings.js";

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
    expect(await getSettings()).toEqual({ inlineAutofill: false });
  });
});

describe("updateSettings", () => {
  beforeEach(() => installFakeStorage());

  it("merges the patch into current settings and persists", async () => {
    const next = await updateSettings({ inlineAutofill: false });
    expect(next.inlineAutofill).toBe(false);
    const store = globalThis.chrome.storage.local._store;
    expect(store.get("settings")).toEqual({ inlineAutofill: false });
  });

  it("keeps unrelated future keys when merging", async () => {
    const store = installFakeStorage();
    store.set("settings", { inlineAutofill: false, futureKey: 42 });
    const next = await updateSettings({ inlineAutofill: true });
    expect(next).toEqual({ inlineAutofill: true, futureKey: 42 });
  });
});
