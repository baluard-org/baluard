// Unit tests for the passkey content-script registration lifecycle
// (syncPasskeyScripts in background.js).
//
// Covers the review majors:
//   - serialization: overlapping sync calls must not race
//     registerContentScripts into a duplicate-id error;
//   - scoped revert: only a world-support error may flip the user's opt-in
//     off — a transient registration failure leaves the setting alone;
//   - transition-only injection: live-tab injection runs once per browser
//     session, not on every unrelated settings change.
//
// The fake chrome mirrors the storage/scripting/tabs surfaces the sync
// touches; each test gets a fresh module registry (vitest isolates files),
// so chrome is installed before the background import.

import { describe, it, expect, vi, beforeEach } from "vitest";

function makeChrome({ worldError = false } = {}) {
  const state = {
    registered: [],
    registerCalls: 0,
    injectedTabs: [],
    settings: {},
    session: {},
    settingWrites: [],
    errors: [],
  };
  const api = {
    __state: state,
    runtime: {
      // NMH connect must fail fast and harmlessly at import time.
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
      session: {
        get: async (k) => ({ [k]: state.session[k] }),
        set: async (obj) => {
          for (const [k, v] of Object.entries(obj)) state.session[k] = v;
        },
        remove: async (k) => {
          delete state.session[k];
        },
      },
    },
    scripting: {
      registerContentScripts: vi.fn(async (scripts) => {
        state.registerCalls += 1;
        if (worldError && scripts.some((s) => s.world === "MAIN")) {
          throw new Error("Invalid value for world: MAIN");
        }
        for (const s of scripts) state.registered.push(s.id);
      }),
      unregisterContentScripts: vi.fn(async ({ ids }) => {
        state.registered = state.registered.filter((id) => !ids.includes(id));
      }),
      getRegisteredContentScripts: vi.fn(async () =>
        state.registered.map((id) => ({ id }))
      ),
      executeScript: vi.fn(async ({ target, files }) => {
        // Two scripts ride one tab injection pass (page + bridge).
        state.injectedTabs.push(`${target.tabId}:${files[0]}`);
      }),
    },
    tabs: {
      query: vi.fn(async () => [{ id: 11 }, { id: 12 }]),
      sendMessage: vi.fn(async () => {}),
      onActivated: { addListener: () => {} },
      onUpdated: { addListener: () => {} },
      onRemoved: { addListener: () => {} },
    },
    windows: { onRemoved: { addListener: () => {} } },
  };
  api.storage.onChanged = { addListener: () => {} };
  return api;
}

async function loadSync(chromeApi) {
  globalThis.chrome = chromeApi;
  const mod = await import("../src/background.js");
  return mod.syncPasskeyScripts;
}

const SETTINGS_KEY = "settings";

describe("syncPasskeyScripts", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("registers page+bridge scripts when enabled", async () => {
    const chromeApi = makeChrome();
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    const sync = await loadSync(chromeApi);
    await sync();
    const s = chromeApi.__state;
    expect(s.registered).toContain("baluard-passkey-page");
    expect(s.registered).toContain("baluard-passkey-bridge");
    expect(s.injectedTabs).toEqual([
      "11:passkey-page.js",
      "11:passkey-bridge.js",
      "12:passkey-page.js",
      "12:passkey-bridge.js",
    ]);
    expect(s.session.passkeysInjected).toBe(true);
  });

  it("registers scripts for a fresh install with no stored settings", async () => {
    // Default ON (1Password/Bitwarden parity): an install that never wrote
    // a settings object still gets interception, through the same defaults
    // the popup reads.
    const chromeApi = makeChrome();
    chromeApi.__state.settings = {};
    const sync = await loadSync(chromeApi);
    await sync();
    const s = chromeApi.__state;
    expect(s.registered).toContain("baluard-passkey-page");
    expect(s.registered).toContain("baluard-passkey-bridge");
  });

  it("unregisters and restores natives when disabled", async () => {
    const chromeApi = makeChrome();
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: false } };
    chromeApi.__state.registered = ["baluard-passkey-page", "baluard-passkey-bridge"];
    const sync = await loadSync(chromeApi);
    await sync();
    const s = chromeApi.__state;
    const passkeyIds = s.registered.filter((id) => id.startsWith("baluard-passkey"));
    expect(passkeyIds).toEqual([]);
    expect(s.injectedTabs).toEqual([]);
    expect(chromeApi.tabs.sendMessage).toHaveBeenCalledTimes(2);
  });

  it("serializes overlapping calls into one registration each", async () => {
    const chromeApi = makeChrome();
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    const sync = await loadSync(chromeApi);
    await Promise.all([sync(), sync(), sync()]);
    const s = chromeApi.__state;
    // Exactly one page + one bridge registration despite three syncs
    // (baluard-inline is the separate, always-on autofill registration).
    const passkeyIds = s.registered.filter((id) => id.startsWith("baluard-passkey"));
    expect(passkeyIds).toEqual(["baluard-passkey-page", "baluard-passkey-bridge"]);
    // Injection runs once per browser session: one page + one bridge per tab.
    expect(s.injectedTabs).toEqual([
      "11:passkey-page.js",
      "11:passkey-bridge.js",
      "12:passkey-page.js",
      "12:passkey-bridge.js",
    ]);
  });

  it("skips re-injection on unrelated settings changes in the same session", async () => {
    const chromeApi = makeChrome();
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    const sync = await loadSync(chromeApi);
    await sync();
    // An unrelated settings write (copyTotp) fires sync again.
    chromeApi.__state.settings[SETTINGS_KEY].copyTotp = true;
    await sync();
    expect(chromeApi.__state.injectedTabs).toEqual([
      "11:passkey-page.js",
      "11:passkey-bridge.js",
      "12:passkey-page.js",
      "12:passkey-bridge.js",
    ]);
  });

  it("reverts the opt-in ONLY on a world-support error", async () => {
    const chromeApi = makeChrome({ worldError: true });
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    const sync = await loadSync(chromeApi);
    await sync();
    const s = chromeApi.__state;
    expect(s.settings[SETTINGS_KEY].enablePasskeys).toBe(false);
    expect(s.settings.passkeysWorldUnsupported).toBe(true);
  });

  it("leaves the opt-in alone on a transient registration failure", async () => {
    const chromeApi = makeChrome();
    const sync = await loadSync(chromeApi);
    // Break registerContentScripts AFTER import (transient, non-world).
    chromeApi.scripting.registerContentScripts.mockRejectedValueOnce(
      new Error("duplicate content script id")
    );
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    await sync();
    const s = chromeApi.__state;
    expect(s.settings[SETTINGS_KEY].enablePasskeys).toBe(true);
    expect(s.settings.passkeysWorldUnsupported).toBeUndefined();
  });
});
