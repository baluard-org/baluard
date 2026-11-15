// The ceremony popout must present the daemon-validated rpId as the site
// identity. The page-supplied rp.name is attacker-controlled ("Totally Not
// PayPal") and is never rendered — it only feeds the new-entry default name.
//
// popup.jsx auto-mounts on import; setting the passkey hash route BEFORE
// the import renders PasskeyPopout instead of the settings App.

import { describe, it, expect, beforeAll } from "vitest";

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
          kind: "confirmRegister",
          rpId: "rp.example",
          rpName: "Totally Not PayPal",
          userName: "u@rp.example",
          rows: [],
          siteRows: [{ cipher_id: "c1", name: "Existing Login", username: "u", vault_slug: "main" }],
        },
      };
    }
    return { ok: true, payload: {} };
  },
};

window.location.hash = "#/passkey/sw-1";
await import("../src/popup.jsx");

describe("passkey popout site identity", () => {
  beforeAll(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

  it("shows the trusted rpId and never the page-supplied rp.name", () => {
    const text = document.body.textContent;
    expect(text).toContain("rp.example");
    expect(text).not.toContain("Totally Not PayPal");
    expect(text).toContain("u@rp.example");
  });

  it("keeps the save-target list working", () => {
    const text = document.body.textContent;
    expect(text).toContain("Existing Login");
    expect(document.querySelectorAll(".match-card").length).toBe(1);
  });
});
