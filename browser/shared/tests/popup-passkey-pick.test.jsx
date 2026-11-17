// The assertion picker must send exactly one decision per pick. Rapid
// double-Enter (or double-click) on a match card must not push two
// passkey.ui.decide messages — the service worker would run the
// assertion ceremony twice against the daemon.

import { describe, it, expect } from "vitest";

const decideCalls = [];

globalThis.chrome = globalThis.chrome || {};
globalThis.chrome.storage = globalThis.chrome.storage || {};
globalThis.chrome.storage.local = {
  get: (keys, cb) => {
    const out = {};
    if (typeof cb === "function") cb(out);
    return Promise.resolve(out);
  },
  set: (obj, cb) => {
    if (typeof cb === "function") cb();
    return Promise.resolve();
  },
};
globalThis.chrome.runtime = {
  sendMessage: async (msg) => {
    if (msg.action === "passkey.ui.state") {
      return {
        ok: true,
        payload: {
          id: "sw-1",
          kind: "pickAssertion",
          rpId: "rp.example",
          rpName: "Totally Not PayPal",
          userName: "u@rp.example",
          requiresUv: false,
          rows: [
            { credential_id: "cred-1", name: "Existing Login", username: "u", vault_slug: "main" },
          ],
          siteRows: [],
        },
      };
    }
    if (msg.action === "passkey.ui.decide") decideCalls.push(msg);
    return { ok: true, payload: {} };
  },
};

window.location.hash = "#/passkey/sw-1";
await import("../src/popup.jsx");

describe("passkey popout picker", () => {
  it("sends one pick decision under a rapid double Enter", async () => {
    await new Promise((r) => setTimeout(r, 20));
    const card = document.querySelector(".match-card");
    expect(card, "assertion match card").toBeTruthy();

    card.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    card.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));

    expect(decideCalls.length).toBe(1);
    expect(decideCalls[0].decision).toEqual({ kind: "pickAssertion", credential_id: "cred-1" });
  });
});
