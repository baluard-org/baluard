// Fresh-install defaults rendered through the real popup.
//
// Empty storage (new user, nothing in chrome.storage.local) must render
// ALL settings toggles enabled, matching DEFAULT_SETTINGS. Separate test
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
      // MV3: promise result when no callback is passed.
      if (typeof cb !== "function") return Promise.resolve(out);
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

  it("renders the settings toggles with correct fresh-install defaults", () => {
    const toggles = [
      ...document.querySelectorAll(".setting-row input[type=checkbox]"),
    ];
    expect(toggles.length).toBe(4);
    // inlineAutofill + copyTotp default ON (1Password/Bitwarden parity).
    for (const input of toggles.slice(0, 2)) {
      expect(input.checked, "checkbox should be checked").toBe(true);
      expect(
        input.closest(".toggle").classList.contains("on"),
        "toggle knob should paint the on state"
      ).toBe(true);
    }
    // enablePasskeys defaults ON (1Password/Bitwarden parity): a fresh
    // install offers passkeys from the vault, and the badge + PK overlay
    // make interception visible. Users can turn it off.
    const passkeys = toggles[2];
    expect(passkeys.checked, "passkeys toggle should start on").toBe(true);
    expect(passkeys.closest(".toggle").classList.contains("on")).toBe(true);
    // defaultPasswordManager defaults ON (1Password General-toggle parity):
    // a fresh install claims the manager role; the browser's offer-to-save
    // prompt is turned off by the service worker via chrome.privacy.
    const defaultManager = toggles[3];
    expect(defaultManager.checked, "default-manager toggle should start on").toBe(true);
    expect(defaultManager.closest(".toggle").classList.contains("on")).toBe(true);
  });

  it("getSettings reports both enabled without writing to storage", () => {
    // A fresh install must not need a storage write to be enabled: the
    // absent key means enabled everywhere (SW reads `!== false`).
    expect(store.has("settings")).toBe(false);
  });
});
