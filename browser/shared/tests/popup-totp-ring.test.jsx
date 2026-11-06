// TOTP live window ring on the popup copy button: the remaining code
// lifetime renders as a red border draining clockwise into the regular
// border color. The window is epoch-aligned, so the popup needs only the
// entry's period from the match row — no code is ever fetched for display.

import { describe, it, expect, beforeAll, vi } from "vitest";

// A whole multiple of 60s, so the ring starts exactly at a rollover.
const BASE = 1794000000000;
vi.useFakeTimers({ now: BASE });

function installFakeStorage(initial = {}) {
  const store = new Map(Object.entries(initial));
  globalThis.chrome.storage.local = {
    get: (keys, cb) => {
      const out = {};
      for (const k of keys) if (store.has(k)) out[k] = store.get(k);
      cb(out);
    },
    set: (obj, cb) => {
      for (const k of Object.keys(obj)) store.set(k, obj[k]);
      cb && cb();
    },
    _store: store,
  };
  return store;
}

installFakeStorage({ onboarded: true });

const sentMessages = [];
const TAB_URL = "https://site.test/login";

globalThis.chrome.runtime.sendMessage = (msg, cb) => {
  sentMessages.push(msg);
  if (msg.action === "bridge.match") {
    cb({
      ok: true,
      payload: JSON.stringify({
        matches: [
          { id: "t1", name: "Site", username: "me", favorite: true, totp: true, totp_period: 60, vault_slug: "personal", vault_name: "Personal" },
          { id: "t2", name: "Broken seed", username: "me2", favorite: false, totp: true, totp_period: 0, vault_slug: "personal", vault_name: "Personal" },
          { id: "n1", name: "No totp", username: "me3", favorite: false, totp: false, vault_slug: "personal", vault_name: "Personal" },
        ],
        vaults: [
          { slug: "personal", display_name: "Personal", unlocked: true, removed: false },
        ],
        active_vault: "Personal",
      }),
    });
    return;
  }
  if (msg.action === "cipher.totp_code") {
    cb({
      ok: true,
      payload: JSON.stringify({ code: "123456", period_seconds: 60, expires_at: BASE / 1000 + 60 }),
    });
    return;
  }
  if (msg.action === "clipboard-copy") {
    cb({ ok: true });
    return;
  }
  cb({ ok: true });
};

globalThis.chrome.tabs.query = (_opts, cb) => cb([{ id: 1, url: TAB_URL }]);
globalThis.chrome.tabs.create = () => {};

await import("../src/popup.jsx");

async function flush(rounds = 8) {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}

function totpBtn(cardIdx) {
  const card = [...document.querySelectorAll(".match-card")][cardIdx];
  const btns = card.querySelectorAll(".match-secondary-actions .btn-icon");
  return btns[btns.length - 2]; // last button is view-in-app
}

describe("popup TOTP window ring", () => {
  beforeAll(async () => {
    await flush();
  });

  it("never fetches a code to render the ring", () => {
    expect(sentMessages.filter((m) => m.action === "cipher.totp_code")).toHaveLength(0);
  });

  it("starts as a full red border on a fresh window", () => {
    const btn = totpBtn(0);
    expect(btn.classList.contains("totp-ring")).toBe(true);
    expect(btn.style.getPropertyValue("--totp-sweep")).toBe("0.00deg");
  });

  it("no ring without a period or without TOTP", () => {
    expect(totpBtn(1).classList.contains("totp-ring")).toBe(false);
    expect(totpBtn(2).classList.contains("totp-ring")).toBe(false);
  });

  it("drains clockwise: a quarter of the period is a quarter spent", async () => {
    await vi.advanceTimersByTimeAsync(15000);
    expect(totpBtn(0).style.getPropertyValue("--totp-sweep")).toBe("90.00deg");
  });

  it("snaps back to a full border when the window rolls over", async () => {
    await vi.advanceTimersByTimeAsync(44500); // 59.5s of 60s elapsed
    expect(totpBtn(0).style.getPropertyValue("--totp-sweep")).toBe("357.00deg");
    await vi.advanceTimersByTimeAsync(1500); // 61s total = 1s into the next window
    expect(totpBtn(0).style.getPropertyValue("--totp-sweep")).toBe("6.00deg");
  });

  it("still fetches the code on copy click, not before", async () => {
    sentMessages.length = 0;
    totpBtn(0).click();
    await flush(2);
    const codes = sentMessages.filter((m) => m.action === "cipher.totp_code");
    expect(codes).toHaveLength(1);
    expect(codes[0].payload).toEqual({ id: "t1", url: TAB_URL, vault_slug: "personal" });
  });
});
