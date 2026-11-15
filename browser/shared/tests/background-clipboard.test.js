// Unit tests for the SW clipboard path (clipboardCopy + ensureOffscreen).
//
// Regression guard for the Chromium copy-TOTP fix: ensureOffscreen must
// serialize concurrent creations (createDocument rejects with "Only a
// single offscreen document may be created" on the second call), tolerate
// a stale document probe by re-checking after a failed create, and
// clipboardCopy must fail loudly when the offscreen document refuses the
// write instead of reporting a copy that never happened.

import { describe, it, expect, beforeEach, vi } from "vitest";

// Deferred probe: tests decide when each getContexts answer settles, which
// is what makes the stale-probe race reproducible (a probe issued before
// another caller's createDocument finished but resolving after it).
function deferredContexts() {
  const pending = [];
  const mock = vi.fn(() => new Promise((resolve) => pending.push(resolve)));
  mock.resolveAll = (contexts) => {
    while (pending.length) pending.shift()(contexts);
  };
  return mock;
}

async function freshBackground() {
  vi.resetModules();
  // setup.js's chrome mock predates runtime.getURL; hasOffscreenDocument
  // needs it for the documentUrls filter.
  globalThis.chrome.runtime.getURL = (p) => `chrome-extension://test-extension-id/${p}`;
  return import("../src/background.js");
}

describe("ensureOffscreen (offscreen document lifecycle)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("creates the document once for concurrent callers", async () => {
    const createDocument = vi.fn(async () => undefined);
    const contexts = deferredContexts();
    globalThis.chrome.runtime.getContexts = contexts;
    globalThis.chrome.offscreen.createDocument = createDocument;
    const bg = await freshBackground();

    const a = bg.ensureOffscreen();
    const b = bg.ensureOffscreen();
    contexts.resolveAll([]);
    await Promise.all([a, b]);

    expect(createDocument).toHaveBeenCalledTimes(1);
  });

  it("recovers when a stale probe races a finished creation", async () => {
    // Caller B probes AFTER caller A's createDocument settled, but its
    // answer is stale ("no document"). B's create then rejects with the
    // single-document error; the re-check must notice the document and
    // swallow the rejection instead of losing the copy.
    let documentExists = false;
    let staleProbes = 0;
    const createDocument = vi.fn(async () => {
      if (documentExists) throw new Error("Only a single offscreen document may be created");
      documentExists = true;
    });
    globalThis.chrome.runtime.getContexts = async () => {
      if (staleProbes > 0) {
        staleProbes -= 1;
        return [];
      }
      return documentExists ? [{ url: "offscreen.html" }] : [];
    };
    globalThis.chrome.offscreen.createDocument = createDocument;
    const bg = await freshBackground();

    await bg.ensureOffscreen();
    staleProbes = 1; // the next probe lies: document exists but reports none
    await expect(bg.ensureOffscreen()).resolves.toBeUndefined();
    expect(createDocument).toHaveBeenCalledTimes(2);
  });
});

describe("clipboardCopy (SW-owned clipboard write)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Document already exists: no creation involved in these tests.
    globalThis.chrome.runtime.getContexts = async () => [
      { url: "offscreen.html" },
    ];
  });

  it("throws when the offscreen document refuses the write", async () => {
    globalThis.chrome.runtime.sendMessage = async () => ({ ok: false, error: "no" });
    const bg = await freshBackground();
    await expect(bg.clipboardCopy("123456")).rejects.toThrow(/refused/);
  });

  it("resolves without a fallback flag on a successful offscreen copy", async () => {
    globalThis.chrome.runtime.sendMessage = async () => ({ ok: true });
    const bg = await freshBackground();
    await expect(bg.clipboardCopy("123456")).resolves.toBeUndefined();
  });

  it("signals the Firefox fallback instead of throwing when offscreen is absent", async () => {
    const bg = await freshBackground();
    const originalOffscreen = globalThis.chrome.offscreen;
    globalThis.chrome.offscreen = undefined;
    await expect(bg.clipboardCopy("123456")).resolves.toBe("fallback");
    globalThis.chrome.offscreen = originalOffscreen;
  });
});

describe("handleInlineFill copy failure surfacing", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps the fill and sets copyFailed when the clipboard write is refused", async () => {
    // NMH port with the version handshake, matching g24-merged.test.js.
    let swListener = null;
    globalThis.chrome.runtime.connectNative = () => ({
      postMessage: (msg) => {
        if (msg.action === "ping") {
          swListener({ id: msg.id, ok: true, payload: JSON.stringify({ nmh_version: "9.9.9" }) });
        } else if (msg.action === "cipher.totp_code") {
          swListener({ id: msg.id, ok: true, payload: JSON.stringify({ code: "123456" }) });
        } else if (msg.action === "vault.get") {
          swListener({
            id: msg.id,
            ok: true,
            payload: JSON.stringify({ username: "u", password: "p", totp: true }),
          });
        } else {
          swListener({ id: msg.id, ok: true, payload: "{}" });
        }
      },
      onMessage: { addListener: (fn) => (swListener = fn) },
      onDisconnect: { addListener: () => {} },
    });
    // Offscreen document exists; the write is refused. Capture the fill push.
    globalThis.chrome.runtime.getContexts = async () => [{ url: "offscreen.html" }];
    globalThis.chrome.runtime.getURL = (p) => `chrome-extension://test-extension-id/${p}`;
    globalThis.chrome.runtime.sendMessage = async () => ({ ok: false, error: "refused" });
    let fillPush = null;
    globalThis.chrome.tabs.sendMessage = (_tabId, msg) => {
      fillPush = msg;
    };

    const bg = await freshBackground();
    const sender = { tab: { id: 1, url: "https://site.test/login" } };
    await bg.handleInlineFill(sender, "c1", "login", false, "");
    expect(fillPush.copied).toBe(false);
    expect(fillPush.copyFailed).toBe(true);
    expect(fillPush.credential.password).toBe("p");
  });
});
