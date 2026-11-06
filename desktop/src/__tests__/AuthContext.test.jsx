import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, waitFor, cleanup } from "@solidjs/testing-library";

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...a) => daemonMock(...a) }));
vi.mock("../lib/heldPhrase.js", () => ({ clearHeldPhrase: vi.fn() }));
vi.mock("../lib/vaultPrefetch.js", () => ({ startVaultPrefetch: vi.fn() }));
vi.mock("../context/toastSignal.js", () => ({ toastError: vi.fn(), toastWarning: vi.fn() }));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (k) => k, locale: () => "en" }) }));

import { AuthProvider, useAuth } from "../context/AuthContext.jsx";

let auth;
function Capture() {
  auth = useAuth();
  return null;
}

function mockDaemon() {
  daemonMock.mockImplementation((action) => {
    if (action === "vault.active") return Promise.resolve(JSON.stringify({ slug: "s" }));
    if (action === "vault.open") return Promise.resolve("");
    if (action === "vault.unlock") return Promise.resolve(JSON.stringify({ name: "Vault" }));
    // The daemon rejects even the lock call once the session is dead.
    if (action === "vault.lock") return Promise.reject(new Error("Invalid session token. Re-unlock the vault."));
    return Promise.resolve("{}");
  });
}

describe("session expiry forces the lock screen", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    mockDaemon();
    cleanup();
    auth = null;
  });

  it("locks locally even when the daemon lock call also fails", async () => {
    render(() => <AuthProvider><Capture /></AuthProvider>);
    auth.setLoginPasswordRef({ value: "pw" });
    const ok = await auth.unlock((k) => k);
    expect(ok).toBe(true);
    expect(auth.status()).toBe("unlocked");

    window.dispatchEvent(new CustomEvent("baluard:session-expired"));
    await waitFor(() => expect(auth.status()).toBe("locked"), { timeout: 3000 });
    expect(auth.lastUnlockError()).toMatch(/Invalid session token/);
  });

  it("does not call the daemon lock when already locked", async () => {
    render(() => <AuthProvider><Capture /></AuthProvider>);
    expect(auth.status()).toBe("locked");
    window.dispatchEvent(new CustomEvent("baluard:session-expired"));
    await new Promise((r) => setTimeout(r, 100));
    expect(daemonMock).not.toHaveBeenCalledWith("vault.lock");
  });

  it("ignores an expiry from a secondary vault session", async () => {
    render(() => <AuthProvider><Capture /></AuthProvider>);
    auth.setLoginPasswordRef({ value: "pw" });
    await auth.unlock((k) => k);
    expect(auth.status()).toBe("unlocked");
    window.dispatchEvent(new CustomEvent("baluard:session-expired", { detail: { slug: "other-vault" } }));
    await new Promise((r) => setTimeout(r, 100));
    expect(auth.status()).toBe("unlocked");
    expect(daemonMock).not.toHaveBeenCalledWith("vault.lock");
  });

  it("locks for the active vault slug", async () => {
    render(() => <AuthProvider><Capture /></AuthProvider>);
    auth.setLoginPasswordRef({ value: "pw" });
    await auth.unlock((k) => k);
    window.dispatchEvent(new CustomEvent("baluard:session-expired", { detail: { slug: "s" } }));
    await waitFor(() => expect(auth.status()).toBe("locked"), { timeout: 3000 });
  });

  it("collapses concurrent expiries into one lock call", async () => {
    let resolveLock;
    daemonMock.mockImplementation((action) => {
      if (action === "vault.active") return Promise.resolve(JSON.stringify({ slug: "s" }));
      if (action === "vault.open") return Promise.resolve("");
      if (action === "vault.unlock") return Promise.resolve(JSON.stringify({ name: "Vault" }));
      if (action === "vault.lock") return new Promise((res) => { resolveLock = res; });
      return Promise.resolve("{}");
    });
    render(() => <AuthProvider><Capture /></AuthProvider>);
    auth.setLoginPasswordRef({ value: "pw" });
    await auth.unlock((k) => k);
    window.dispatchEvent(new CustomEvent("baluard:session-expired"));
    window.dispatchEvent(new CustomEvent("baluard:session-expired"));
    window.dispatchEvent(new CustomEvent("baluard:session-expired"));
    await new Promise((r) => setTimeout(r, 100));
    expect(daemonMock.mock.calls.filter((c) => c[0] === "vault.lock")).toHaveLength(1);
    resolveLock("");
  });

  it("does not re-lock when the user re-unlocks during the lock call", async () => {
    let resolveLock;
    daemonMock.mockImplementation((action) => {
      if (action === "vault.active") return Promise.resolve(JSON.stringify({ slug: "s" }));
      if (action === "vault.open") return Promise.resolve("");
      if (action === "vault.unlock") return Promise.resolve(JSON.stringify({ name: "Vault" }));
      if (action === "vault.lock") return new Promise((res) => { resolveLock = res; });
      return Promise.resolve("{}");
    });
    render(() => <AuthProvider><Capture /></AuthProvider>);
    auth.setLoginPasswordRef({ value: "pw" });
    await auth.unlock((k) => k);
    window.dispatchEvent(new CustomEvent("baluard:session-expired"));
    await new Promise((r) => setTimeout(r, 50));
    // unlock() clears the ref on success, so the re-unlock needs it again.
    auth.setLoginPasswordRef({ value: "pw" });
    await auth.unlock((k) => k);
    resolveLock("");
    await new Promise((r) => setTimeout(r, 100));
    expect(auth.status()).toBe("unlocked");
  });
});
