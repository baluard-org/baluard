// VaultView against the real VaultProvider with a mocked daemon: proves
// the "No folder" row selects only folder-less entries and its highlight
// stays exclusive with All items. Regression for the null-vs-sentinel bug
// where both rows rendered selected at startup and No folder was a no-op.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, screen, waitFor, cleanup } from "@solidjs/testing-library";

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

// Rows stubbed to expose cipher identity + folder so the test can assert
// the filtered set.
vi.mock("../components/CipherRow.jsx", () => ({
  default: (props) => (
    <div
      data-testid="row"
      data-name={props.cipher.name}
      data-folder={props.cipher.folder_id || "none"}
    />
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

const C = (id, name, folder) => ({ id, type: "login", name, username: "u", folder_id: folder });
// Epsilon keeps its folder in the _meta list-row shape: it counts as
// filed under f1 and must stay out of the No-folder result.
const FIXTURES = [
  C("a", "Alpha", "f1"),
  C("b", "Beta", "f1"),
  C("c", "Gamma", null),
  C("d", "Delta", null),
  { id: "e", type: "login", name: "Epsilon", username: "u", _meta: { folder_id: "f1" } },
];
const FOLDERS = [{ id: "f1", parent_id: null }];
// A folder-less entry from another open vault: visible in All items,
// never under No folder (folder filters never surface foreign rows).
const OTHER_VAULTS = {
  vaults: [
    {
      slug: "vault-b",
      display_name: "Vault B",
      presence: "unlocked",
      ciphers: [C("x", "Foreign", null)],
    },
  ],
};

function rows() {
  return screen.getAllByTestId("row").map((r) => r.getAttribute("data-name"));
}

function isSelected(el) {
  return el?.closest("button")?.className.includes("bg-[var(--color-card)]") ?? false;
}

describe("VaultView No folder filter (regression)", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    daemonMock.mockImplementation(async (action, payload) => {
      if (action === "vault.list_ids") {
        return JSON.stringify({
          ids: FIXTURES.map((f) => f.id),
          folders: FOLDERS,
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
      if (action === "vaults.list_full_all") {
        return JSON.stringify(OTHER_VAULTS);
      }
      return "{}";
    });
  });

  it("startup selects All items only, No folder filters to active-vault folder-less entries, All items restores", async () => {
    render(() => (
      <VaultProvider>
        <VaultView />
      </VaultProvider>
    ));

    // VaultView loads on mount (onSettled); wait for the rendered rows.
    await waitFor(() =>
      expect(rows()).toEqual(["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Foreign"]),
    );
    const allItems = document.querySelector('[data-testid="category-allItems"] span');
    const noFolder = screen.getByText("entry.noFolder");
    expect(isSelected(allItems)).toBe(true);
    expect(isSelected(noFolder)).toBe(false);

    // Click No folder: only active-vault folder-less entries remain, the
    // row highlights. Foreign rows never surface (no folder filter ever
    // shows them) and _meta-filed Epsilon stays filed. All items stays
    // lit: the category does not change when a folder filter activates.
    fireEvent.click(noFolder);
    await waitFor(() => expect(rows()).toEqual(["Gamma", "Delta"]));
    expect(isSelected(noFolder)).toBe(true);
    expect(isSelected(allItems)).toBe(true);

    // Back to All items: everything returns, No folder un-highlights.
    fireEvent.click(allItems);
    await waitFor(() =>
      expect(rows()).toEqual(["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Foreign"]),
    );
    expect(isSelected(allItems)).toBe(true);
    expect(isSelected(noFolder)).toBe(false);
  });
});
