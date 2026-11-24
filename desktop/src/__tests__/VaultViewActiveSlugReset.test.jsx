import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, fireEvent, screen, waitFor, cleanup } from "@solidjs/testing-library";

const { daemonMock, setActiveSlug, activeSlugSignal, refreshMock } = await vi.hoisted(async () => {
  const solid = await import("solid-js");
  const [activeSlug, setActiveSlug] = solid.createSignal(null);
  return {
    daemonMock: vi.fn(),
    setActiveSlug,
    activeSlugSignal: activeSlug,
    refreshMock: vi.fn(),
  };
});

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k, locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (p) => p.children,
}));

vi.mock("../lib/daemon.js", () => ({ daemon: (...a) => daemonMock(...a) }));

vi.mock("../context/toastSignal.js", () => ({
  toast: vi.fn(),
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
  toastWarning: vi.fn(),
  toasts: [],
}));

vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => ({
    activeSlug: () => activeSlugSignal(),
    unlockRequest: () => null,
    vaults: () => [],
    refresh: (...a) => refreshMock(...a),
    switchTo: vi.fn().mockResolvedValue(undefined),
  }),
}));

vi.mock("../context/AuthContext.jsx", () => ({
  useAuth: () => ({ lock: vi.fn(), signOut: vi.fn() }),
  AuthContext: { Provider: (p) => p.children },
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

vi.mock("../components/CipherRow.jsx", () => ({
  default: (props) => <div data-testid="row" data-name={props.cipher.name} />,
}));
vi.mock("../components/AskAccessModal.jsx", () => ({ default: () => null }));
vi.mock("../components/OpenSharedModal.jsx", () => ({ default: () => null }));
vi.mock("../components/ConflictBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/LegacyBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/RemovalBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/VaultSwitcher.jsx", () => ({
  default: (props) => (
    <button
      type="button"
      data-testid="pick-locked-vault"
      onClick={() => props.onLockedTarget?.({ slug: "vault-b", display_name: "Vault B" })}
    />
  ),
}));
vi.mock("../components/SwitchUnlockModal.jsx", async () => {
  const { Show } = await import("solid-js");
  return {
    default: (props) => (
      <Show when={props.target}>
        <button
          type="button"
          data-testid="confirm-switch-unlock"
          onClick={async () => {
            await props.onUnlocked?.();
            props.onClose?.();
          }}
        />
      </Show>
    ),
  };
});

import VaultView from "../components/VaultView.jsx";
import { VaultProvider } from "../context/VaultContext.jsx";

const C = (id, name) => ({ id, type: "login", name, username: "u" });

function rowNames() {
  return screen.queryAllByTestId("row").map((r) => r.getAttribute("data-name"));
}

describe("VaultView activeSlug reset regressions", () => {
  beforeEach(() => {
    setActiveSlug(null);
    refreshMock.mockReset().mockResolvedValue(undefined);
    daemonMock.mockReset();
    cleanup();
  });

  afterEach(() => {
    cleanup();
  });

  it("keeps entries when activeSlug hydrates from null to the unlocked slug after mount", async () => {
    daemonMock.mockImplementation(async (action) => {
      if (action === "vault.list_full") {
        return JSON.stringify({
          ciphers: [C("1", "Alpha"), C("2", "Beta")],
          folders: [],
          tags: [],
          trash: [],
          archived: [],
          unreadable: 0,
          has_more: false,
        });
      }
      return "{}";
    });

    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(rowNames()).toEqual(["Alpha", "Beta"]));

    // Simulates focus regain or initial switcher refresh completing after mount.
    setActiveSlug("vault-a");
    await new Promise((r) => setTimeout(r, 30));

    expect(rowNames()).toEqual(["Alpha", "Beta"]);
  });

  it("reloads entries if a stale non-null activeSlug updates after mount", async () => {
    setActiveSlug("vault-a");
    let useVaultB = false;
    let listCalls = 0;
    daemonMock.mockImplementation(async (action) => {
      if (action === "vault.list_full") {
        listCalls += 1;
        return JSON.stringify({
          ciphers: useVaultB ? [C("b1", "Vault B Entry")] : [C("a1", "Stale Vault A Entry")],
          folders: [],
          tags: [],
          trash: [],
          archived: [],
          unreadable: 0,
          has_more: false,
        });
      }
      return "{}";
    });

    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(rowNames()).toEqual(["Stale Vault A Entry"]));

    // Simulates switcher.refresh() catching up from stale vault-a to vault-b.
    useVaultB = true;
    setActiveSlug("vault-b");

    await waitFor(() => expect(rowNames()).toEqual(["Vault B Entry"]));
    expect(listCalls).toBeGreaterThanOrEqual(2);
  });

  it("resets and reloads when activeSlug dips to null before changing to another slug", async () => {
    setActiveSlug("vault-a");
    let useVaultB = false;
    daemonMock.mockImplementation(async (action) => {
      if (action === "vault.list_full") {
        return JSON.stringify({
          ciphers: useVaultB ? [C("b1", "Vault B Entry")] : [C("a1", "Vault A Entry")],
          folders: [],
          tags: [],
          trash: [],
          archived: [],
          unreadable: 0,
          has_more: false,
        });
      }
      return "{}";
    });

    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(rowNames()).toEqual(["Vault A Entry"]));

    setActiveSlug(null);
    await new Promise((r) => setTimeout(r, 20));
    expect(rowNames()).toEqual(["Vault A Entry"]);

    useVaultB = true;
    setActiveSlug("vault-b");

    await waitFor(() => expect(rowNames()).toEqual(["Vault B Entry"]));
  });

  it("preserves entries without reloading when activeSlug dips to null and returns to the same slug", async () => {
    setActiveSlug("vault-a");
    let listCalls = 0;
    daemonMock.mockImplementation(async (action) => {
      if (action === "vault.list_full") {
        listCalls += 1;
        return JSON.stringify({
          ciphers: [C("a1", "Vault A Entry")],
          folders: [],
          tags: [],
          trash: [],
          archived: [],
          unreadable: 0,
          has_more: false,
        });
      }
      return "{}";
    });

    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(rowNames()).toEqual(["Vault A Entry"]));
    expect(listCalls).toBe(1);

    setActiveSlug(null);
    await new Promise((r) => setTimeout(r, 20));
    setActiveSlug("vault-a");
    await new Promise((r) => setTimeout(r, 20));

    expect(rowNames()).toEqual(["Vault A Entry"]);
    expect(listCalls).toBe(1);
  });

  it("ignores a slower earlier list_full response after activeSlug switches", async () => {
    setActiveSlug("vault-a");
    let resolveSlowVaultA;
    let callIndex = 0;
    daemonMock.mockImplementation((action) => {
      if (action === "vault.list_full") {
        callIndex += 1;
        if (callIndex === 1) {
          return new Promise((resolve) => {
            resolveSlowVaultA = resolve;
          });
        }
        return Promise.resolve(
          JSON.stringify({
            ciphers: [C("b1", "Vault B Entry")],
            folders: [],
            tags: [],
            trash: [],
            archived: [],
            unreadable: 0,
            has_more: false,
          }),
        );
      }
      return Promise.resolve("{}");
    });

    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(callIndex).toBe(1));

    setActiveSlug("vault-b");
    await waitFor(() => expect(rowNames()).toEqual(["Vault B Entry"]));

    resolveSlowVaultA(
      JSON.stringify({
        ciphers: [C("a1", "Stale Vault A Entry")],
        folders: [],
        tags: [],
        trash: [],
        archived: [],
        unreadable: 0,
        has_more: false,
      }),
    );
    await new Promise((r) => setTimeout(r, 30));

    expect(rowNames()).toEqual(["Vault B Entry"]);
  });

  it("keeps newly unlocked vault entries after SwitchUnlockModal unlocks", async () => {
    setActiveSlug("vault-a");
    let switched = false;
    daemonMock.mockImplementation(async (action) => {
      if (action === "vault.list_full") {
        return JSON.stringify({
          ciphers: switched ? [C("b1", "Vault B Secret")] : [C("a1", "Vault A Secret")],
          folders: [],
          tags: [],
          trash: [],
          archived: [],
          unreadable: 0,
          has_more: false,
        });
      }
      return "{}";
    });
    refreshMock.mockImplementation(async () => {
      setActiveSlug("vault-b");
    });

    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(rowNames()).toEqual(["Vault A Secret"]));

    fireEvent.click(screen.getByTestId("pick-locked-vault"));
    await waitFor(() => expect(screen.getByTestId("confirm-switch-unlock")).toBeTruthy());

    switched = true;
    fireEvent.click(screen.getByTestId("confirm-switch-unlock"));

    await waitFor(() => expect(rowNames()).toEqual(["Vault B Secret"]));
    await new Promise((r) => setTimeout(r, 30));
    expect(rowNames()).toEqual(["Vault B Secret"]);
  });
});
