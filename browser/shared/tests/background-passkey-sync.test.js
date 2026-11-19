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
        for (const s of scripts) {
          // Store the full registration object: the real API echoes back
          // every field, which is what drift comparison reads.
          state.registered = state.registered.filter((r) => r.id !== s.id);
          state.registered.push({ ...s });
        }
      }),
      unregisterContentScripts: vi.fn(async ({ ids }) => {
        state.registered = state.registered.filter((r) => !ids.includes(r.id));
      }),
      getRegisteredContentScripts: vi.fn(async () =>
        state.registered.map((r) => ({ ...r }))
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

async function loadMod(chromeApi) {
  globalThis.chrome = chromeApi;
  return import("../src/background.js");
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
    const ids = s.registered.map((r) => r.id);
    expect(ids).toContain("baluard-passkey-page");
    expect(ids).toContain("baluard-passkey-bridge");
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
    const ids = s.registered.map((r) => r.id);
    expect(ids).toContain("baluard-passkey-page");
    expect(ids).toContain("baluard-passkey-bridge");
  });

  it("unregisters and restores natives when disabled", async () => {
    const chromeApi = makeChrome();
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: false } };
    chromeApi.__state.registered = [
      { id: "baluard-passkey-page" },
      { id: "baluard-passkey-bridge" },
    ];
    const sync = await loadSync(chromeApi);
    await sync();
    const s = chromeApi.__state;
    const passkeyIds = s.registered.map((r) => r.id).filter((id) => id.startsWith("baluard-passkey"));
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
    const passkeyIds = s.registered.map((r) => r.id).filter((id) => id.startsWith("baluard-passkey"));
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

  it("repairs a stale registration that predates world MAIN", async () => {
    const chromeApi = makeChrome();
    const s = chromeApi.__state;
    s.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    // What a pre-MAIN release persisted: right id, wrong params.
    s.registered = [
      {
        id: "baluard-passkey-page",
        js: ["passkey-page.js"],
        matches: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
        runAt: "document_start",
        allFrames: false,
        persistAcrossSessions: true,
      },
    ];
    const sync = await loadSync(chromeApi);
    await sync();
    const pages = s.registered.filter((r) => r.id === "baluard-passkey-page");
    expect(pages).toHaveLength(1);
    expect(pages[0].world).toBe("MAIN");
    expect(s.registered.some((r) => r.id === "baluard-passkey-bridge")).toBe(true);
  });

  it("leaves matching registrations alone across syncs", async () => {
    const chromeApi = makeChrome();
    const s = chromeApi.__state;
    s.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    const sync = await loadSync(chromeApi);
    await sync();
    const callsAfterFirst = s.registerCalls;
    await sync();
    expect(s.registerCalls).toBe(callsAfterFirst);
  });

  it("repairs a bridge entry pinned with world MAIN (drift outside spec keys)", async () => {
    const chromeApi = makeChrome();
    const s = chromeApi.__state;
    s.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    // The bridge spec omits world; a persisted entry carrying MAIN is
    // still drift and must be repaired even though the id matches.
    s.registered = [
      {
        id: "baluard-passkey-bridge",
        js: ["passkey-bridge.js"],
        matches: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
        runAt: "document_start",
        world: "MAIN",
        allFrames: false,
        persistAcrossSessions: true,
      },
    ];
    const sync = await loadSync(chromeApi);
    await sync();
    const bridge = s.registered.find((r) => r.id === "baluard-passkey-bridge");
    expect(bridge).toBeTruthy();
    expect(bridge.world ?? "ISOLATED").toBe("ISOLATED");
  });

  it("does not churn when the engine omits default-valued echo fields", async () => {
    const chromeApi = makeChrome();
    const s = chromeApi.__state;
    s.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    // Both entries in omitted-echo form: no allFrames / persistAcrossSessions,
    // bridge without world. Matches the spec once defaults are applied.
    s.registered = [
      {
        id: "baluard-passkey-page",
        js: ["passkey-page.js"],
        matches: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
        runAt: "document_start",
        world: "MAIN",
      },
      {
        id: "baluard-passkey-bridge",
        js: ["passkey-bridge.js"],
        matches: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
        runAt: "document_start",
      },
    ];
    const sync = await loadSync(chromeApi);
    await sync();
    // The only permitted register call is the separate always-on inline
    // autofill script; zero calls may target the passkey scripts across
    // BOTH the import-time boot sync and this one.
    const passkeyRegisters = chromeApi.scripting.registerContentScripts.mock.calls.filter(
      (args) => args[0].some((x) => String(x.id).startsWith("baluard-passkey"))
    );
    expect(passkeyRegisters).toHaveLength(0);
    const passkeyEntries = s.registered.filter((r) => r.id.startsWith("baluard-passkey"));
    expect(passkeyEntries).toHaveLength(2);
  });

  it("reports the registration as unverified while a repair fails", async () => {
    const chromeApi = makeChrome();
    // Reject every register attempt: the import-time boot sync races this
    // test's own sync through the shared chain, so a once-rejection could
    // land on either. Both fail -> flag stays false, deterministically.
    chromeApi.scripting.registerContentScripts.mockRejectedValue(
      new Error("duplicate content script id")
    );
    const mod = await loadMod(chromeApi);
    chromeApi.__state.settings = { [SETTINGS_KEY]: { enablePasskeys: true } };
    await mod.syncPasskeyScripts();
    expect(mod.passkeyRegistrationVerified()).toBe(false);
  });
});
