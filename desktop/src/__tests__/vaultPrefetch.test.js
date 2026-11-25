// Tests for desktop/src/lib/vaultPrefetch.js + biometry.js — the prefetch
// helper + Tauri biometry plugin wrapper. Both are tiny; both need a mock
// for the underlying Tauri / daemon call.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── vaultPrefetch.js ───────────────────────────────────────────

// The prefetch helper imports daemon from ./daemon.js, which itself
// imports invoke from @tauri-apps/api/core. We can't easily run that
// in node, so we mock the daemon module before importing the helper.
vi.mock("../lib/daemon.js", () => ({
  daemon: vi.fn(),
}));

import { daemon } from "../lib/daemon.js";
import {
  fetchVaultFull,
  startVaultPrefetch,
  consumeVaultPrefetch,
} from "../lib/vaultPrefetch.js";

describe("vaultPrefetch", () => {
  beforeEach(() => {
    vi.mocked(daemon).mockReset();
  });

  it("start fires vault.list_ids and consume returns the parsed promise", async () => {
    const parsed = { ids: [], folders: [], total: 0 };
    vi.mocked(daemon).mockResolvedValue(JSON.stringify(parsed));

    startVaultPrefetch();
    const promise = consumeVaultPrefetch();
    expect(promise).not.toBeNull();
    const result = await promise;
    expect(result).toEqual({ folders: [], total: 0, ciphers: [] });
    expect(daemon).toHaveBeenCalledWith("vault.list_ids");
  });

  it("fetchVaultFull fetches envelope chunks over the id snapshot", async () => {
    const ids = Array.from({ length: 511 }, (_, i) => `id-${i}`);
    vi.mocked(daemon).mockImplementation(async (action, payload) => {
      if (action === "vault.list_ids") {
        return JSON.stringify({
          ids,
          folders: [{ id: "f1" }],
          trash: [{ id: "t1" }],
          archived: [{ id: "a1" }],
          tags: ["work"],
          unreadable: 2,
          total: ids.length,
        });
      }
      const { ids: want } = JSON.parse(payload);
      return JSON.stringify({ ciphers: want.map((id) => ({ id })) });
    });

    const result = await fetchVaultFull();
    expect(result.ciphers).toHaveLength(511);
    expect(result.ciphers[0].id).toBe("id-0");
    expect(result.ciphers[510].id).toBe("id-510");
    expect(result.folders).toEqual([{ id: "f1" }]);
    expect(result.trash).toEqual([{ id: "t1" }]);
    expect(result.archived).toEqual([{ id: "a1" }]);
    expect(result.tags).toEqual(["work"]);
    expect(result.unreadable).toBe(2);
    expect(result.ids).toBeUndefined();
    expect(daemon).toHaveBeenNthCalledWith(
      2,
      "vault.list_full_batch",
      JSON.stringify({ ids: ids.slice(0, 200) })
    );
    expect(daemon).toHaveBeenNthCalledWith(
      3,
      "vault.list_full_batch",
      JSON.stringify({ ids: ids.slice(200, 400) })
    );
  });

  it("consume with no prefetch started returns null", () => {
    // After the previous test, the module-level _promise was set to null.
    // No new prefetch -> consume returns null.
    // (We can't reliably reset the module-level state, so this is
    // best-effort — it works as long as the previous test cleared it.)
    const p = consumeVaultPrefetch();
    expect(p).toBeNull();
  });

  it("consume clears the prefetched promise", async () => {
    vi.mocked(daemon).mockResolvedValue("{}");
    startVaultPrefetch();
    const first = consumeVaultPrefetch();
    expect(first).not.toBeNull();
    const second = consumeVaultPrefetch();
    expect(second).toBeNull();
    // Resolve the first so we don't leak the promise.
    await first;
  });

  it("errors during prefetch are swallowed and consume yields null", async () => {
    vi.mocked(daemon).mockRejectedValue(new Error("network down"));
    startVaultPrefetch();
    const p = consumeVaultPrefetch();
    expect(p).not.toBeNull();
    // The promise resolves to null (catch handler swallows the error).
    const result = await p;
    expect(result).toBeNull();
  });

  it("a batch that fails to reconcile the requested ids rejects the walk", async () => {
    // Two ids requested, one served, no missing count: a silent skip.
    // The walk must reject (surfacing as a null prefetch and the normal
    // load path) instead of resolving a stable undercount.
    vi.mocked(daemon).mockImplementation(async (action, payload) => {
      if (action === "vault.list_ids") {
        return JSON.stringify({ ids: ["a", "b"], folders: [], total: 2 });
      }
      if (action === "vault.list_full_batch") {
        return JSON.stringify({ ciphers: [{ id: "a" }] });
      }
      return "{}";
    });
    startVaultPrefetch();
    const p = consumeVaultPrefetch();
    await expect(p).resolves.toBeNull();
  });

  it("a counted missing id reconciles the batch and the walk resolves", async () => {
    // A pull deleted the second cipher mid-walk: served 1 + missing 1
    // accounts for both requested ids, so the walk must NOT throw.
    vi.mocked(daemon).mockImplementation(async (action, payload) => {
      if (action === "vault.list_ids") {
        return JSON.stringify({ ids: ["a", "b"], folders: [], total: 2 });
      }
      if (action === "vault.list_full_batch") {
        return JSON.stringify({ ciphers: [{ id: "a" }], missing: 1 });
      }
      return "{}";
    });
    startVaultPrefetch();
    const result = await consumeVaultPrefetch();
    expect(result.ciphers).toHaveLength(1);
    expect(result.total).toBe(2);
  });
});

// ── biometry.js ───────────────────────────────────────────────

// Mock the Tauri biometry plugin to avoid the real native binding.
vi.mock("@choochmeque/tauri-plugin-biometry-api", () => ({
  checkStatus: vi.fn(),
  authenticate: vi.fn(),
}));

import { checkStatus, authenticate } from "@choochmeque/tauri-plugin-biometry-api";
import { biometryAvailable, biometryPrompt } from "../lib/biometry.js";

describe("biometryAvailable", () => {
  beforeEach(() => {
    vi.mocked(checkStatus).mockReset();
  });

  it("returns true when plugin reports available", async () => {
    vi.mocked(checkStatus).mockResolvedValue({ isAvailable: true });
    expect(await biometryAvailable()).toBe(true);
  });

  it("returns false when plugin reports unavailable", async () => {
    vi.mocked(checkStatus).mockResolvedValue({ isAvailable: false });
    expect(await biometryAvailable()).toBe(false);
  });

  it("returns false when the plugin throws (e.g. unsupported platform)", async () => {
    vi.mocked(checkStatus).mockRejectedValue(new Error("not supported"));
    expect(await biometryAvailable()).toBe(false);
  });
});

describe("biometryPrompt", () => {
  beforeEach(() => {
    vi.mocked(authenticate).mockReset();
  });

  it("returns true on successful authenticate()", async () => {
    vi.mocked(authenticate).mockResolvedValue(undefined);
    expect(await biometryPrompt("Unlock Baluard")).toBe(true);
  });

  it("uses default reason when none provided", async () => {
    vi.mocked(authenticate).mockResolvedValue(undefined);
    await biometryPrompt();
    expect(authenticate).toHaveBeenCalledWith(
      "Unlock Baluard",
      expect.objectContaining({ allowDeviceCredential: true })
    );
  });

  it("propagates authenticate failure (user cancel / lockout)", async () => {
    vi.mocked(authenticate).mockRejectedValue(new Error("canceled"));
    await expect(biometryPrompt("test")).rejects.toThrow("canceled");
  });
});