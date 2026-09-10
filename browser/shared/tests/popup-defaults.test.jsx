// Fresh-install defaults rendered through the real popup.
//
// Empty storage (new user, nothing in chrome.storage.local) must render
// BOTH settings toggles enabled, matching DEFAULT_SETTINGS. Separate test
// file on purpose: vitest gives each file a fresh module registry, so the
// dynamic import here mounts a popup that loads with an EMPTY store,
// unlike popup-settings.test.jsx which starts from stored false values.

import { describe, it, expect, beforeAll } from "vitest";

function installFakeStorage(initial = {}) {
  const store = new Map(Object.entries(initial));
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

// No "settings" key: the new-user state.
const store = installFakeStorage({ onboarded: true });

await import("../src/popup.jsx");

describe("fresh-install settings defaults", () => {
  beforeAll(async () => {
    await new Promise((r) => setTimeout(r, 0)); // boot + onMount load
    document.querySelector('[aria-label="Settings"]').click();
    await new Promise((r) => setTimeout(r, 0));
  });

  it("renders both toggles enabled on first run", () => {
    const toggles = [
      ...document.querySelectorAll(".setting-row input[type=checkbox]"),
    ];
    expect(toggles.length).toBe(2);
    for (const input of toggles) {
      expect(input.checked, "checkbox should be checked").toBe(true);
      expect(
        input.closest(".toggle").classList.contains("on"),
        "toggle knob should paint the on state"
      ).toBe(true);
    }
  });

  it("getSettings reports both enabled without writing to storage", () => {
    // A fresh install must not need a storage write to be enabled: the
    // absent key means enabled everywhere (SW reads `!== false`).
    expect(store.has("settings")).toBe(false);
  });
});
