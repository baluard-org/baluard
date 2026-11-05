// G24 step-5 popup tests: the merged surfaces on the extension-owned page.
//
//   - Locked-space chips render from the bridge.match `vaults` array, with
//     removal wording when the D73 flag rides along.
//   - Per-match vault labels render only when two or more vaults contribute.
//   - Slug/url pass-through: fill and copy reads carry the tab URL and the
//     entry's vault_slug (slug-scoped reads enforce the URI match server-side).

import { describe, it, expect, beforeAll } from "vitest";

function installFakeStorage(initial = {}) {
  const store = new Map(Object.entries(initial));
  globalThis.chrome.storage.local = {
    get: (keys, cb) => {
      const out = {};
      for (const k of keys) if (store.has(k)) out[k] = store.get(k);
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

const store = installFakeStorage({ onboarded: true });

const sentMessages = [];
const TAB_URL = "https://site.test/login";

globalThis.chrome.runtime.sendMessage = (msg, cb) => {
  sentMessages.push(msg);
  if (msg.action === "bridge.match") {
    cb({
      ok: true,
      payload: JSON.stringify({
        matches: [
          { id: "u1", name: "Bank", username: "me", favorite: true, vault_slug: "personal", vault_name: "Personal" },
          { id: "f1", name: "Wifi", username: "home", favorite: false, vault_slug: "family", vault_name: "Family" },
        ],
        vaults: [
          { slug: "personal", display_name: "Personal", unlocked: true, removed: false },
          { slug: "family", display_name: "Family", unlocked: false, removed: false },
          { slug: "oldspace", display_name: "Old space", unlocked: false, removed: true },
        ],
        active_vault: "Personal",
      }),
    });
    return;
  }
  if (msg.action === "vault.get") {
    cb({ ok: true, payload: JSON.stringify({ username: "me", password: "pw", totp: false }) });
    return;
  }
  if (msg.action === "clipboard-copy") {
    cb({ ok: true });
    return;
  }
  cb({ ok: true });
};

globalThis.chrome.tabs.query = (_opts, cb) => cb([{ id: 1, url: TAB_URL }]);

const createdTabs = [];
globalThis.chrome.tabs.create = (opts) => { createdTabs.push(opts); };

// Must exist before popup.jsx's import-time mount probes the daemon.
await import("../src/popup.jsx");

async function flush(rounds = 6) {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}

function sendsFor(action) {
  return sentMessages.filter((m) => m.action === action);
}

describe("popup merged surfaces (G24 step 5)", () => {
  beforeAll(async () => {
    await flush();
  });

  it("renders locked and removed space chips from the vaults array", () => {
    const chips = [...document.querySelectorAll(".vault-chip")];
    expect(chips).toHaveLength(2);
    const texts = chips.map((c) => c.textContent);
    expect(texts[0]).toContain("Family");
    expect(texts[0]).toContain("is locked");
    expect(texts[1]).toContain("no longer have access");
    expect(chips[1].className).toContain("danger");
  });

  it("labels match cards with their vault when two vaults contribute", () => {
    const labels = [...document.querySelectorAll(".match-vault")];
    expect(labels).toHaveLength(2);
    expect(labels.map((l) => l.textContent)).toEqual(["Personal", "Family"]);
  });

  it("fill read carries the tab URL and the entry's vault_slug", async () => {
    const fillBtn = document.querySelector(".match-card .btn-primary-mini");
    expect(fillBtn).toBeTruthy();
    fillBtn.click();
    await flush(2);
    const gets = sendsFor("vault.get");
    const last = gets[gets.length - 1].payload;
    expect(last).toEqual({ id: "u1", url: TAB_URL, vault_slug: "personal" });
  });

  it("copy read carries the tab URL and the entry's vault_slug", async () => {
    const card = [...document.querySelectorAll(".match-card")][1];
    const copyBtn = card.querySelector(".match-secondary-actions .btn-icon");
    expect(copyBtn).toBeTruthy();
    copyBtn.click();
    await flush(2);
    const gets = sendsFor("vault.get");
    const last = gets[gets.length - 1].payload;
    expect(last).toEqual({ id: "f1", url: TAB_URL, vault_slug: "family" });
  });

  it("clicking a locked chip asks the desktop to unlock it once", async () => {
    const chips = [...document.querySelectorAll(".vault-chip.clickable")];
    expect(chips).toHaveLength(1);
    chips[0].click();
    await flush(2);
    const asks = sentMessages.filter((m) => m.action === "bridge.request_unlock");
    expect(asks).toHaveLength(1);
    expect(asks[0].payload).toEqual({ slug: "family" });
    // Second click is a no-op (already requested).
    chips[0].click();
    await flush(2);
    expect(sentMessages.filter((m) => m.action === "bridge.request_unlock")).toHaveLength(1);
    expect(chips[0].textContent).toContain("Unlock requested");
  });

  it("totp read carries the tab URL and the entry's vault_slug", async () => {
    const card = [...document.querySelectorAll(".match-card")][1];
    const btns = card.querySelectorAll(".match-secondary-actions .btn-icon");
    const totpBtn = btns[btns.length - 2]; // last button is view-in-app
    totpBtn.click();
    await flush(2);
    const codes = sendsFor("cipher.totp_code");
    const last = codes[codes.length - 1].payload;
    expect(last).toEqual({ id: "f1", url: TAB_URL, vault_slug: "family" });
  });

  it("the view button opens the entry deep link for its vault", async () => {
    createdTabs.length = 0;
    const card = [...document.querySelectorAll(".match-card")][0];
    const btns = card.querySelectorAll(".match-secondary-actions .btn-icon");
    btns[btns.length - 1].click();
    await flush(2);
    expect(createdTabs).toHaveLength(1);
    expect(createdTabs[0].url).toBe("baluard://entry/personal/u1");
  });
});
