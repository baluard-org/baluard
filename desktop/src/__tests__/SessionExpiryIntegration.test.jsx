import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, waitFor, cleanup } from "@solidjs/testing-library";

// Integration: real daemon.js (only the Tauri invoke is mocked) driving the
// real AuthContext, so the event -> listener -> lock chain is covered.
const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a) => invokeMock(...a) }));
vi.mock("../lib/heldPhrase.js", () => ({ clearHeldPhrase: vi.fn() }));
vi.mock("../lib/vaultPrefetch.js", () => ({ startVaultPrefetch: vi.fn() }));
vi.mock("../context/toastSignal.js", () => ({ toastError: vi.fn(), toastWarning: vi.fn() }));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (k) => k, locale: () => "en" }) }));

import { daemon } from "../lib/daemon.js";
import { AuthProvider, useAuth } from "../context/AuthContext.jsx";

let auth;
function Capture() {
  auth = useAuth();
  return null;
}

describe("session expiry end to end", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    cleanup();
    auth = null;
  });

  it("a real daemon rejection locks the vault exactly once", async () => {
    invokeMock.mockImplementation((cmd, args) => {
      const action = args?.action;
      const ok = (payload) => Promise.resolve({ success: true, payload });
      if (action === "vault.active") return ok(JSON.stringify({ slug: "s" }));
      if (action === "vault.open") return ok("");
      if (action === "vault.unlock") return ok(JSON.stringify({ name: "Vault" }));
      // Even the lock call rejects: the in-flight guard must stop recursion.
      if (action === "agents.list" || action === "vault.lock") {
        return Promise.resolve({ success: false, error: "Invalid session token. Re-unlock the vault." });
      }
      return ok("{}");
    });

    render(() => <AuthProvider><Capture /></AuthProvider>);
    auth.setLoginPasswordRef({ value: "pw" });
    const okUnlock = await auth.unlock((k) => k);
    expect(okUnlock).toBe(true);
    expect(auth.status()).toBe("unlocked");

    await expect(daemon("agents.list")).rejects.toThrow(/Invalid session token/);
    await waitFor(() => expect(auth.status()).toBe("locked"), { timeout: 3000 });

    const lockCalls = invokeMock.mock.calls.filter((c) => c[1]?.action === "vault.lock");
    expect(lockCalls).toHaveLength(1);
    expect(auth.lastUnlockError()).toMatch(/Invalid session token/);
  });
});
