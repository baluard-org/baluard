// Render tests for the popup passkey diagnostics block (settings view).
// popup.jsx auto-mounts on import; fake chrome APIs are installed first.
// The diagnostics block must reflect three probe outcomes (shadowed, healthy,
// no-tab) plus the SW-side payload (registered count, versions, pkTrail).

import { describe, it, expect, beforeAll } from "vitest";

const store = new Map(
  Object.entries({
    settings: { enablePasskeys: true, inlineAutofill: true, copyTotp: true },
    onboarded: true,
  })
);

const diagPayload = {
  enabled: true,
  worldUnsupported: false,
  registered: [{ id: "baluard-passkey-page", world: "MAIN" }],
  pkTrail: ["12:00:01 wrap installed", "12:00:02 GET npmjs.com"],
  versions: { extension: "0.7.4-test", nmh: "0.7.4", proto: 2 },
};

let probeResult = { wrap: true, shadow: true, supported: true };

globalThis.chrome = {
  runtime: {
    getURL: (p) => `chrome-extension://test/${p}`,
    getManifest: () => ({ version: "0.7.4-test" }),
    sendMessage: (msg, cb) => {
      if (msg && msg.action === "passkey.diagnostics") {
        cb({ ok: true, payload: diagPayload });
        return;
      }
      cb({ ok: false, error: "not under test" });
    },
    onMessage: { addListener: () => {} },
  },
  storage: {
    local: {
      get: (keys, cb) => {
        const out = {};
        for (const k of [].concat(keys)) if (store.has(k)) out[k] = store.get(k);
        if (typeof cb !== "function") return Promise.resolve(out);
        cb(out);
      },
      set: (obj, cb) => {
        for (const [k, v] of Object.entries(obj)) store.set(k, v);
        cb && cb();
      },
    },
    session: { get: async () => ({}) },
  },
  tabs: {
    query: async () => [{ id: 1, url: "https://npmjs.com/login" }],
  },
  scripting: {
    // The popup gates passkey support on this function existing.
    registerContentScripts: async () => {},
    executeScript: async () => [{ result: probeResult }],
  },
};

await import("../src/popup.jsx");

async function flush(ms = 0) {
  await new Promise((r) => setTimeout(r, ms));
}

function openSettings() {
  document.querySelector('[aria-label="Settings"]').click();
}

function closeSettings() {
  const backBtn = [...document.querySelectorAll(".btn-secondary")].find((b) =>
    b.textContent.trim() === "Back"
  );
  backBtn?.click();
}

function diagBlock() {
  return document.querySelector(".pk-diag");
}

describe("popup passkey diagnostics", () => {
  beforeAll(async () => {
    await flush(20); // boot + onMount settings load (passkeysEnabled flip)
    openSettings();
    await flush(20);
  });

  it("warns when another manager shadows the wrap on the active tab", () => {
    const block = diagBlock();
    expect(block).toBeTruthy();
    expect(block.querySelector(".pk-diag-status").textContent).toContain(
      "Another password manager"
    );
    expect(block.querySelector(".pk-diag-warn")).toBeTruthy();
  });

  it("shows the registered-script count and version stack", () => {
    const meta = diagBlock().querySelector(".pk-diag-meta").textContent;
    expect(meta).toContain("1/2");
    expect(meta).toContain("0.7.4-test");
    expect(meta).toContain("NMH 0.7.4");
    expect(meta).toContain("proto 2");
  });

  it("lists the pkTrail entries when expanded", async () => {
    const details = diagBlock().querySelector(".pk-diag-trail");
    expect(details).toBeTruthy();
    details.open = true;
    await flush();
    const rows = [...details.querySelectorAll(".pk-diag-trail-row")].map((r) =>
      r.textContent
    );
    expect(rows).toContain("12:00:01 wrap installed");
    expect(rows).toContain("12:00:02 GET npmjs.com");
  });

  it("reports a healthy wrap without the warning class", async () => {
    probeResult = { wrap: true, shadow: false, supported: true };
    closeSettings();
    await flush(20);
    openSettings();
    await flush(20);
    const status = diagBlock().querySelector(".pk-diag-status");
    expect(status.textContent).toContain("Intercepting passkeys");
    expect(status.classList.contains("pk-diag-warn")).toBe(false);
    expect(status.classList.contains("pk-diag-ok")).toBe(true);
  });

  it("falls back to the no-tab hint when the probe cannot run", async () => {
    globalThis.chrome.tabs.query = async () => [{ id: 1, url: "chrome://newtab" }];
    probeResult = { wrap: true, shadow: false, supported: true };
    closeSettings();
    await flush(20);
    openSettings();
    await flush(20);
    expect(diagBlock().querySelector(".pk-diag-status").textContent).toContain(
      "Open a website tab"
    );
  });
});
