// Interaction tests for the popup settings view (real rendered Solid).
// popup.jsx auto-mounts App on import; the import happens AFTER fake
// storage is installed so the onMount load sees stored OFF values — the
// exact state from the reported bug (toggles off, clicks do nothing).
// Guards the regression class: toggles going visually dead.

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

// Must exist before popup.jsx's import-time mount reads settings.
const store = installFakeStorage({
  settings: { inlineAutofill: false, copyTotp: false },
  onboarded: true,
});

const { DEFAULT_SETTINGS } = await import("../src/settings.js");
await import("../src/popup.jsx");

async function flush() {
  await new Promise((r) => setTimeout(r, 0));
}

function toggleRows() {
  return [...document.querySelectorAll(".setting-row")].filter((row) =>
    row.querySelector('input[type="checkbox"]')
  );
}

function storedSettings() {
  return store.get("settings");
}

describe("popup settings toggles", () => {
  beforeAll(async () => {
    await flush(); // boot + onMount settings load
    document.querySelector('[aria-label="Settings"]').click();
    await flush();
  });

  it("renders both toggles OFF from stored false values (bug state)", () => {
    const rows = toggleRows();
    expect(rows.length).toBe(2);
    expect(rows[0].querySelector(".toggle").classList.contains("on")).toBe(false);
    expect(rows[1].querySelector(".toggle").classList.contains("on")).toBe(false);
  });

  it("first toggle flips on click and persists", async () => {
    const rows = toggleRows();
    rows[0].querySelector('input[type="checkbox"]').click();
    await flush();

    expect(rows[0].querySelector(".toggle").classList.contains("on")).toBe(true);
    expect(storedSettings().inlineAutofill).toBe(true);
  });

  it("second toggle flips on click and persists", async () => {
    const rows = toggleRows();
    rows[1].querySelector('input[type="checkbox"]').click();
    await flush();

    expect(rows[1].querySelector(".toggle").classList.contains("on")).toBe(true);
    expect(storedSettings().copyTotp).toBe(true);
  });

  it("clicking the row text also flips via label forwarding", async () => {
    // Toggle 1 is on from the earlier test; clicking the row text must
    // forward to the checkbox and flip it back off, persisting false.
    const rows = toggleRows();
    rows[0].querySelector(".setting-name").click();
    await flush();

    expect(rows[0].querySelector(".toggle").classList.contains("on")).toBe(false);
    expect(storedSettings().inlineAutofill).toBe(false);
  });
});
