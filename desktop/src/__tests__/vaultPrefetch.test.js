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
import { startVaultPrefetch, consumeVaultPrefetch } from "../lib/vaultPrefetch.js";

describe("vaultPrefetch", () => {
  beforeEach(() => {
    vi.mocked(daemon).mockReset();
  });

  it("start fires vault.list_full and consume returns the parsed promise", async () => {
    const parsed = { ciphers: [], folders: [] };
    vi.mocked(daemon).mockResolvedValue(JSON.stringify(parsed));

    startVaultPrefetch();
    const promise = consumeVaultPrefetch();
    expect(promise).not.toBeNull();
    const result = await promise;
    expect(result).toEqual(parsed);
    expect(daemon).toHaveBeenCalledWith("vault.list_full");
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