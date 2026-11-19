// Unit tests for the popup passkey diagnostics route
// (background.js handlePasskeyDiagnostics): registration params, the
// session-keyed pkTrail, world-unsupported flag, and the version stack.

import { describe, it, expect } from "vitest";

function installFakeChrome({ registered = [], trail = null, worldUnsupported = false, settings = {} } = {}) {
  const localStore = new Map(
    Object.entries({
      ...(worldUnsupported ? { passkeysWorldUnsupported: true } : {}),
      settings,
    })
  );
  const sessionStore = new Map(Object.entries(trail === null ? {} : { pkTrail: trail }));
  globalThis.chrome = {
    runtime: {
      id: "test-ext-id",
      getURL: (p) => `chrome-extension://test-ext-id/${p}`,
      getManifest: () => ({ version: "0.7.4" }),
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: {
        get: async (keys) => {
          const out = {};
          for (const k of [].concat(keys)) if (localStore.has(k)) out[k] = localStore.get(k);
          return out;
        },
        remove: async (keys) => {
          for (const k of [].concat(keys)) localStore.delete(k);
        },
      },
      session: {
        get: async (keys) => {
          const out = {};
          for (const k of [].concat(keys)) if (sessionStore.has(k)) out[k] = sessionStore.get(k);
          return out;
        },
      },
    },
    scripting: {
      getRegisteredContentScripts: async () => registered,
    },
  };
  return { localStore, sessionStore };
}

describe("handlePasskeyDiagnostics", () => {
  it("reports registered passkey scripts with their full params", async () => {
    installFakeChrome({
      registered: [
        {
          id: "baluard-passkey-page",
          js: ["passkey-page.js"],
          matches: ["https://*/*"],
          runAt: "document_start",
          world: "MAIN",
          allFrames: false,
          persistAcrossSessions: true,
        },
        { id: "baluard-inline", js: ["inline.js"], matches: ["https://*/*"] },
      ],
    });
    const { handlePasskeyDiagnostics } = await import("../src/background.js");
    const d = await handlePasskeyDiagnostics();
    expect(d.registered).toHaveLength(1);
    expect(d.registered[0]).toMatchObject({
      id: "baluard-passkey-page",
      world: "MAIN",
      runAt: "document_start",
    });
  });

  it("surfaces the pkTrail, world-unsupported flag, and versions", async () => {
    installFakeChrome({
      trail: ["12:00:01 wrap installed", "12:00:02 GET npmjs.com"],
      worldUnsupported: true,
    });
    const { handlePasskeyDiagnostics } = await import("../src/background.js");
    const d = await handlePasskeyDiagnostics();
    expect(d.pkTrail).toEqual(["12:00:01 wrap installed", "12:00:02 GET npmjs.com"]);
    expect(d.worldUnsupported).toBe(true);
    expect(d.versions.extension).toBe("0.7.4");
    expect(d.versions.nmh).toBe("0.0.0"); // no ping ran in this test
  });

  it("degrades every probe to a safe default when the API is missing", async () => {
    installFakeChrome({ settings: { enablePasskeys: false } });
    delete globalThis.chrome.scripting;
    delete globalThis.chrome.storage.session;
    const { handlePasskeyDiagnostics } = await import("../src/background.js");
    const d = await handlePasskeyDiagnostics();
    expect(d.registered).toEqual([]);
    expect(d.pkTrail).toEqual([]);
    expect(d.enabled).toBe(false);
  });
});
