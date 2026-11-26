// VaultView selection vs detail pane: closing the detail pane must clear the
// list-row highlight. Regression for the stale-selection bug where the X in
// the detail header only reset the pane, leaving the row rendered selected
// while the third column showed "select an entry".

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, screen, waitFor } from "@solidjs/testing-library";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k, locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (p) => p.children,
}));

const daemonMock = vi.fn();
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
    activeSlug: () => "vault-a",
    unlockRequest: vi.fn(),
    vaults: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
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

// jsdom fires no CSS transitions, so the real out-in Transition never swaps
// panes (the new Match waits for a transitionend that never comes). Render
// the active pane directly; pane swapping is not under test here.
vi.mock("../lib/transition", () => ({
  Transition: (props) => props.children,
}));

// Rows stubbed to expose the active prop VaultView derives from viewCipher.
vi.mock("../components/CipherRow.jsx", () => ({
  default: (props) => (
    <div
      data-testid="row"
      data-name={props.cipher.name}
      data-active={props.active ? "true" : "false"}
      onClick={() => props.onSelect(props.cipher)}
    />
  ),
}));
// Detail stubbed to a close button wired to the prop under test.
vi.mock("../components/CipherDetail.jsx", () => ({
  default: (props) => (
    <div data-testid="detail">
      <button data-testid="detail-close" onClick={props.onClose}>close</button>
    </div>
  ),
}));
vi.mock("../components/AskAccessModal.jsx", () => ({ default: () => null }));
vi.mock("../components/VaultSwitcher.jsx", () => ({ default: (p) => p.children || null }));
vi.mock("../components/OpenSharedModal.jsx", () => ({ default: () => null }));
vi.mock("../components/ConflictBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/LegacyBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/RemovalBanner.jsx", () => ({ default: () => null }));

import VaultView from "../components/VaultView.jsx";
import { VaultProvider } from "../context/VaultContext.jsx";

const FIXTURES = [
  { id: "a", type: "login", name: "Alpha", username: "u" },
  { id: "b", type: "login", name: "Beta", username: "u" },
];

function row(name) {
  return screen.getAllByTestId("row").find((r) => r.getAttribute("data-name") === name);
}

describe("VaultView detail close clears selection (regression)", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    daemonMock.mockImplementation(async (action, payload) => {
      if (action === "vault.list_ids") {
        return JSON.stringify({
          ids: FIXTURES.map((f) => f.id),
          folders: [],
          tags: [],
          trash: [],
          archived: [],
          unreadable: 0,
          total: FIXTURES.length,
        });
      }
      if (action === "vault.list_full_batch") {
        const { ids: want } = JSON.parse(payload);
        return JSON.stringify({ ciphers: FIXTURES.filter((f) => want.includes(f.id)) });
      }
      return "{}";
    });
  });

  it("selecting a row opens the detail, closing it clears the row highlight", async () => {
    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    await waitFor(() => expect(row("Alpha")).toBeTruthy());

    fireEvent.click(row("Alpha"));
    await waitFor(() => expect(screen.getByTestId("detail")).toBeTruthy());
    expect(row("Alpha").getAttribute("data-active")).toBe("true");
    expect(row("Beta").getAttribute("data-active")).toBe("false");

    fireEvent.click(screen.getByTestId("detail-close"));
    await waitFor(() => expect(screen.getByText("entry.selectPrompt")).toBeTruthy());

    // The bug: the pane went back to the prompt but the row stayed active.
    expect(row("Alpha").getAttribute("data-active")).toBe("false");
    expect(row("Beta").getAttribute("data-active")).toBe("false");
  });
});
