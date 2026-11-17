// Unit tests for the default-password-manager control (background.js).
//
// "Make Baluard the default password manager" (1Password General-toggle
// parity) flips chrome.privacy.services.passwordSavingEnabled: ON turns
// the browser's offer-to-save prompt off; OFF clears the override so the
// browser keeps whatever the user configured themselves (we never force
// the built-in manager back on). The property name is pinned against the
// real privacy.services key list — PasswordManagerEnabled is the enterprise
// policy name and not part of this API; a wrong name would make the whole
// feature a silent no-op while every mock-based test stays green.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";

function makeChrome({ settings = {} } = {}) {
  const state = {
    settings,
    privacyCalls: [],
    storageListeners: [],
  };
  const api = {
    __state: state,
    runtime: {
      connectNative: undefined,
      lastError: null,
      onMessage: { addListener: () => {} },
      onConnect: { addListener: () => {} },
    },
    storage: {
      local: {
        get: async (keys) => {
          const out = {};
          for (const k of keys || []) if (k in state.settings) out[k] = state.settings[k];
          return out;
        },
        set: async (obj) => {
          for (const [k, v] of Object.entries(obj)) state.settings[k] = v;
        },
        remove: async (k) => {
          delete state.settings[k];
        },
      },
      onChanged: { addListener: (fn) => state.storageListeners.push(fn) },
      session: {
        get: async () => ({}),
        set: async () => {},
        remove: async () => {},
      },
    },
    scripting: {
      registerContentScripts: vi.fn(async () => {}),
      unregisterContentScripts: vi.fn(async () => {}),
      getRegisteredContentScripts: vi.fn(async () => []),
      executeScript: vi.fn(async () => {}),
    },
    tabs: {
      query: vi.fn(async () => []),
      sendMessage: vi.fn(async () => {}),
      onActivated: { addListener: () => {} },
      onUpdated: { addListener: () => {} },
      onRemoved: { addListener: () => {} },
    },
    windows: { onRemoved: { addListener: () => {} } },
  };
  api.privacy = {
    services: {
      passwordSavingEnabled: {
        set: vi.fn(async ({ value }) => state.privacyCalls.push(["set", value])),
        clear: vi.fn(async () => state.privacyCalls.push(["clear"])),
      },
    },
  };
  return api;
}

async function loadBackground(chromeApi) {
  globalThis.chrome = chromeApi;
  await import("../src/background.js");
  // Startup application is fire-and-forget; let it settle.
  await new Promise((r) => setTimeout(r, 0));
  return chromeApi.__state;
}

const SETTINGS_KEY = "settings";

function fireSettingsChange(state, oldValue, newValue) {
  state.settings[SETTINGS_KEY] = newValue;
  for (const fn of state.storageListeners) {
    fn({ [SETTINGS_KEY]: { oldValue, newValue } }, "local");
  }
}

describe("default password manager control", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("targets a real privacy.services property, not the policy name", () => {
    // Mocks that copy the code's assumptions prove nothing: this pins the
    // referenced property against the keys Chrome and Firefox actually ship
    // (passwordSavingEnabled). PasswordManagerEnabled is the enterprise
    // policy name and MUST NOT appear.
    const src = readFileSync("src/background.js", "utf8");
    const popupSrc = readFileSync("src/popup.jsx", "utf8");
    // privacy.services keys only (Chrome reference + MDN): network/websites
    // names would mask a typo landing on the wrong namespace.
    const realKeys = [
      "alternateErrorPagesEnabled",
      "autofillAddressEnabled",
      "autofillCreditCardEnabled",
      "autofillEnabled",
      "passwordSavingEnabled",
      "safeBrowsingEnabled",
      "safeBrowsingExtendedReportingEnabled",
      "searchSuggestEnabled",
      "spellingServiceEnabled",
      "translationServiceEnabled",
    ];
    const used = src.match(/chrome\.privacy\?\.services\?\.(\w+)/)?.[1];
    expect(used, "applyDefaultPasswordManager must reference one property").toBeTruthy();
    expect(realKeys).toContain(used);
    // The policy name may never appear as a property access; comments
    // cannot match this pattern, a real use always does.
    const policyAccess = /\.\s*passwordManagerEnabled\b/;
    expect(policyAccess.test(src)).toBe(false);
    expect(policyAccess.test(popupSrc)).toBe(false);
  });

  it("turns the browser prompt off at startup (default-on install)", async () => {
    const state = await loadBackground(makeChrome({ settings: {} }));
    expect(state.privacyCalls).toEqual([["set", false]]);
  });

  it("does not touch the browser at startup when the user opted out", async () => {
    const state = await loadBackground(
      makeChrome({ settings: { [SETTINGS_KEY]: { defaultPasswordManager: false } } })
    );
    expect(state.privacyCalls).toEqual([]);
  });

  it("applies the control when the setting flips on", async () => {
    const chromeApi = makeChrome({
      settings: { [SETTINGS_KEY]: { defaultPasswordManager: false } },
    });
    const state = await loadBackground(chromeApi);
    state.privacyCalls = [];
    fireSettingsChange(
      state,
      { defaultPasswordManager: false },
      { defaultPasswordManager: true }
    );
    expect(state.privacyCalls).toEqual([["set", false]]);
  });

  it("clears the override when the setting flips back off", async () => {
    const chromeApi = makeChrome({ settings: {} });
    const state = await loadBackground(chromeApi);
    state.privacyCalls = [];
    fireSettingsChange(
      state,
      { defaultPasswordManager: true },
      { defaultPasswordManager: false }
    );
    expect(state.privacyCalls).toEqual([["clear"]]);
  });

  it("ignores unrelated settings changes", async () => {
    const chromeApi = makeChrome({ settings: {} });
    const state = await loadBackground(chromeApi);
    state.privacyCalls = [];
    fireSettingsChange(state, undefined, { enablePasskeys: false });
    expect(state.privacyCalls).toEqual([]);
  });

  it("does nothing harmful when the privacy API is missing", async () => {
    const chromeApi = makeChrome({
      settings: { [SETTINGS_KEY]: { defaultPasswordManager: true } },
    });
    delete chromeApi.privacy;
    const state = await loadBackground(chromeApi);
    expect(state.privacyCalls).toEqual([]);
  });
});
