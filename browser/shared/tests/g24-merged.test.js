// G24 step-5 tests: service-worker boundary rules for the merged surfaces.
//
//   - handleInlineMatches projection (B4): the page principal gets match
//     fields + vault_slug + a multiVault flag. The `vaults` array and vault
//     display names NEVER cross to inline (they render in the popup only).
//   - handleInlineFill pass-through: both daemon sends (vault.get,
//     cipher.totp_code) carry the page URL and the entry's vault_slug so the
//     daemon's slug-scoped read enforces the URI match server-side.
//
// Drives the real send() path through a scripted NMH port so the version
// handshake gate (B7) is satisfied before the actions fire.

import { describe, it, expect, beforeAll } from "vitest";

let swListener = null;
const nmhMessages = [];

const fakePort = {
  postMessage: (msg) => {
    nmhMessages.push(msg);
    // Version handshake first (id 1), then respond per action.
    if (msg.action === "ping") {
      swListener({ id: msg.id, ok: true, payload: JSON.stringify({ nmh_version: "9.9.9" }) });
      return;
    }
    if (msg.action === "bridge.match") {
      swListener({
        id: msg.id,
        ok: true,
        payload: JSON.stringify({
          matches: [
            { id: "u1", name: "Bank", username: "me", favorite: true, vault_slug: "personal", vault_name: "Personal vault" },
            { id: "f1", name: "Wifi", username: "home", favorite: false, vault_slug: "family", vault_name: "Family space" },
          ],
          // The raw route payload carries the chips array - it must be
          // projected OUT before anything reaches the page principal.
          vaults: [
            { slug: "personal", display_name: "Personal vault", unlocked: true },
            { slug: "family", display_name: "Family space", unlocked: false, removed: false },
          ],
          active_vault: "Personal vault",
        }),
      });
      return;
    }
    if (msg.action === "vault.get") {
      swListener({
        id: msg.id,
        ok: true,
        payload: JSON.stringify({ username: "me", password: "pw", totp: true }),
      });
      return;
    }
    if (msg.action === "cipher.totp_code") {
      swListener({ id: msg.id, ok: true, payload: JSON.stringify({ code: "123456" }) });
      return;
    }
    swListener({ id: msg.id, ok: true, payload: "{}" });
  },
  onMessage: {
    addListener: (fn) => {
      swListener = fn;
    },
  },
  onDisconnect: { addListener: () => {} },
};

beforeAll(async () => {
  globalThis.chrome.runtime.connectNative = () => fakePort;
  await import("../src/background.js");
});

function lastPayloadFor(action) {
  const msg = [...nmhMessages].reverse().find((m) => m.action === action);
  return msg ? JSON.parse(msg.payload) : null;
}

describe("handleInlineMatches projection (B4, G24 step 5)", () => {
  it("projects match fields + vault_slug, drops the vaults array and vault names", async () => {
    const bg = await import("../src/background.js");
    const sender = { tab: { id: 7, url: "https://site.test/login" } };
    const raw = await bg.handleInlineMatches(sender);
    const data = JSON.parse(raw);

    expect(data.multiVault).toBe(true);
    expect(data.matches).toHaveLength(2);
    for (const m of data.matches) {
      expect(Object.keys(m).sort()).toEqual([
        "favorite",
        "id",
        "name",
        "username",
        "vault_slug",
      ]);
      expect(m.vault_name).toBeUndefined();
    }
    expect(data.vaults).toBeUndefined();
    expect(raw).not.toContain("Family space");
    expect(raw).not.toContain("Personal vault");
  });

  it("reports multiVault false for a single-vault match set", async () => {
    const bg = await import("../src/background.js");
    // Swap the bridge.match responder for a single-slug set.
    const realPost = fakePort.postMessage;
    fakePort.postMessage = (msg) => {
      if (msg.action === "bridge.match") {
        nmhMessages.push(msg);
        swListener({
          id: msg.id,
          ok: true,
          payload: JSON.stringify({
            matches: [
              { id: "u1", name: "Bank", username: "me", vault_slug: "personal", vault_name: "Personal" },
            ],
            vaults: [{ slug: "personal", display_name: "Personal", unlocked: true }],
          }),
        });
        return;
      }
      realPost(msg);
    };
    try {
      const raw = await bg.handleInlineMatches({ tab: { id: 7, url: "https://site.test/login" } });
      const data = JSON.parse(raw);
      expect(data.multiVault).toBe(false);
      expect(data.vaults).toBeUndefined();
    } finally {
      fakePort.postMessage = realPost;
    }
  });
});

describe("handleInlineFill slug/url pass-through (G24 step 5)", () => {
  it("carries url + vault_slug on both daemon sends", async () => {
    const bg = await import("../src/background.js");
    await bg.handleInlineFill(
      { tab: { id: 7, url: "https://site.test/login" }, frameId: 0 },
      "f1",
      "login",
      true,
      "family"
    );
    const getPayload = lastPayloadFor("vault.get");
    expect(getPayload).toEqual({ id: "f1", url: "https://site.test/login", vault_slug: "family" });
    const totpPayload = lastPayloadFor("cipher.totp_code");
    expect(totpPayload).toEqual({ id: "f1", url: "https://site.test/login", vault_slug: "family" });
  });

  it("defaults to the active vault (empty slug) when the entry has none", async () => {
    const bg = await import("../src/background.js");
    await bg.handleInlineFill(
      { tab: { id: 7, url: "https://site.test/login" }, frameId: 0 },
      "u1",
      "login",
      false,
      ""
    );
    const getPayload = lastPayloadFor("vault.get");
    expect(getPayload.vault_slug).toBe("");
    expect(getPayload.url).toBe("https://site.test/login");
  });
});
