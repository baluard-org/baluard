import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, waitFor, cleanup } from "@solidjs/testing-library";
import { createSignal } from "solid-js";

const { listeners, daemonMock, clearHeldPhraseMock } = vi.hoisted(() => ({
  listeners: new Map(),
  daemonMock: vi.fn(),
  clearHeldPhraseMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((event, handler) => {
    listeners.set(event, handler);
    return Promise.resolve(() => listeners.delete(event));
  }),
}));

vi.mock("../lib/daemon.js", () => ({
  daemon: (...args) => daemonMock(...args),
}));

vi.mock("../lib/heldPhrase.js", () => ({
  clearHeldPhrase: (...args) => clearHeldPhraseMock(...args),
}));

import { AuthContext } from "../context/AuthContext.jsx";
import { VaultSwitcherProvider, useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";

describe("VaultSwitcherContext", () => {
  beforeEach(() => {
    listeners.clear();
    daemonMock.mockReset();
    clearHeldPhraseMock.mockReset();
    cleanup();
  });

  afterEach(() => {
    cleanup();
  });

  it("clears held phrase and locks when blur-locked hits the active unlocked vault", async () => {
    const [status, setStatus] = createSignal("unlocked");
    const setVaultInfo = vi.fn();
    daemonMock.mockImplementation(async (action) => {
      if (action === "vaults.list") {
        return JSON.stringify({
          vaults: [{ slug: "vault-a", display_name: "Vault A", active: true, presence: "unlocked" }],
        });
      }
      return "{}";
    });

    let switcher;
    function Probe() {
      switcher = useVaultSwitcher();
      return null;
    }

    render(() => (
      <AuthContext value={{ status, setStatus, setVaultInfo }}>
        <VaultSwitcherProvider>
          <Probe />
        </VaultSwitcherProvider>
      </AuthContext>
    ));

    await waitFor(() => expect(switcher.activeSlug()).toBe("vault-a"));
    await waitFor(() => expect(listeners.has("baluard://blur-locked")).toBe(true));

    listeners.get("baluard://blur-locked")({ payload: ["vault-a"] });

    await waitFor(() => expect(status()).toBe("locked"));
    expect(clearHeldPhraseMock).toHaveBeenCalledTimes(1);
    expect(setVaultInfo).toHaveBeenCalledWith(null);
  });

  it("refreshes activeSlug when auth status transitions to unlocked", async () => {
    const [status, setStatus] = createSignal("locked");
    let unlocked = false;
    daemonMock.mockImplementation(async (action) => {
      if (action === "vaults.list") {
        return JSON.stringify({
          vaults: unlocked
            ? [{ slug: "vault-b", display_name: "Vault B", active: true, presence: "unlocked" }]
            : [],
        });
      }
      return "{}";
    });

    let switcher;
    function Probe() {
      switcher = useVaultSwitcher();
      return null;
    }

    render(() => (
      <AuthContext value={{ status, setStatus, setVaultInfo: vi.fn() }}>
        <VaultSwitcherProvider>
          <Probe />
        </VaultSwitcherProvider>
      </AuthContext>
    ));

    await waitFor(() => expect(switcher.vaultsLoaded()).toBe(true));
    expect(switcher.activeSlug()).toBeNull();

    unlocked = true;
    setStatus("unlocked");

    await waitFor(() => expect(switcher.activeSlug()).toBe("vault-b"));
  });

  it("refreshes once on mount when auth status starts unlocked", async () => {
    const [status, setStatus] = createSignal("unlocked");
    let listCalls = 0;
    daemonMock.mockImplementation(async (action) => {
      if (action === "vaults.list") {
        listCalls += 1;
        return JSON.stringify({
          vaults: [{ slug: "vault-a", display_name: "Vault A", active: true, presence: "unlocked" }],
        });
      }
      return "{}";
    });

    let switcher;
    function Probe() {
      switcher = useVaultSwitcher();
      return null;
    }

    render(() => (
      <AuthContext value={{ status, setStatus, setVaultInfo: vi.fn() }}>
        <VaultSwitcherProvider>
          <Probe />
        </VaultSwitcherProvider>
      </AuthContext>
    ));

    await waitFor(() => expect(switcher.activeSlug()).toBe("vault-a"));
    await new Promise((r) => setTimeout(r, 30));
    expect(listCalls).toBe(1);
  });
});
