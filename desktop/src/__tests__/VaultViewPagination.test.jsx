// VaultView list pagination: the entry list renders a bounded window
// (500 on first paint) and grows by 100 rows when the scroll position
// reaches 85% of the way to the bottom, until the filtered list is
// exhausted. Keeps a vault with thousands of entries from paying the
// full DOM cost at startup.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
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

vi.mock("../components/CipherRow.jsx", () => ({
  default: (props) => (
    <div data-testid="row" data-name={props.cipher.name} />
  ),
}));
vi.mock("../components/AskAccessModal.jsx", () => ({ default: () => null }));
vi.mock("../components/VaultSwitcher.jsx", () => ({ default: (p) => p.children || null }));
vi.mock("../components/OpenSharedModal.jsx", () => ({ default: () => null }));
vi.mock("../components/ConflictBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/LegacyBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/RemovalBanner.jsx", () => ({ default: () => null }));

import VaultView from "../components/VaultView.jsx";
import { VaultProvider, useVault } from "../context/VaultContext.jsx";

// Grabs the live context so tests can drive provider mutations directly.
let vaultApi;
function ContextProbe() {
  vaultApi = useVault();
  return null;
}

const C = (id, name) => ({ id, type: "login", name, username: "u" });

function serveCiphers(count) {
  daemonMock.mockReset();
  const ciphers = Array.from({ length: count }, (_, i) => C(`c${i}`, `Entry ${i}`));
  daemonMock.mockImplementation(async (action, payload) => {
    if (action === "vault.list_ids") {
      return JSON.stringify({
        ids: ciphers.map((c) => c.id),
        folders: [],
        tags: [],
        trash: [],
        archived: [],
        unreadable: 0,
        total: ciphers.length,
      });
    }
    if (action === "vault.list_full_batch") {
      const { ids: want } = JSON.parse(payload);
      return JSON.stringify({ ciphers: ciphers.filter((c) => want.includes(c.id)) });
    }
    if (action === "vaults.list_full_all") {
      return JSON.stringify({ vaults: [] });
    }
    return "{}";
  });
}

function rows() {
  return screen.getAllByTestId("row");
}

// Geometry models the real DOM: scrollHeight grows with the rendered
// rows (16px each) inside a 200px viewport, so one page-load pushes the
// scroll position back under the threshold until the user scrolls deeper.
const ROW_H = 16;
const VIEW_H = 200;
function stubScroll(el) {
  const geo = { top: 0, scrollHeight: VIEW_H };
  Object.defineProperty(el, "scrollTop", {
    configurable: true,
    get: () => geo.top,
    set: (v) => {
      geo.top = v;
    },
  });
  Object.defineProperty(el, "clientHeight", { value: VIEW_H, configurable: true });
  Object.defineProperty(el, "scrollHeight", {
    configurable: true,
    get: () => geo.scrollHeight,
  });
  el.__geo = geo;
}

function scrollToFrac(el, frac) {
  el.__geo.scrollHeight = VIEW_H + rows().length * ROW_H;
  el.__geo.top = Math.floor(el.__geo.scrollHeight * frac - VIEW_H);
  fireEvent.scroll(el);
}

async function renderList(count) {
  serveCiphers(count);
  render(() => (
    <VaultProvider>
      <ContextProbe />
      <VaultView />
    </VaultProvider>
  ));
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
  const el = document.querySelector('[data-testid="cipher-list-scroll"]');
  expect(el, "list scroll container").toBeTruthy();
  stubScroll(el);
  return el;
}

describe("VaultView list pagination", () => {
  beforeEach(() => {
    daemonMock.mockReset();
  });
  afterEach(cleanup);

  it("renders at most 500 entries on first paint", async () => {
    await renderList(1200);
    expect(rows().length).toBe(500);
  });

  it("renders a list that fits under the window whole", async () => {
    await renderList(120);
    expect(rows().length).toBe(120);
  });

  it("adds 100 rows at 85% scroll depth and no earlier", async () => {
    const el = await renderList(1200);
    expect(rows().length).toBe(500);

    scrollToFrac(el, 0.84); // just under the threshold: no page yet
    await waitFor(() => expect(rows().length).toBe(500));

    scrollToFrac(el, 0.85); // at the threshold: next page
    await waitFor(() => expect(rows().length).toBe(600));

    scrollToFrac(el, 0.85); // scrolling deeper earns the next page
    await waitFor(() => expect(rows().length).toBe(700));
  });

  it("shows rows added after the window reached the list length, no scroll needed", async () => {
    const el = await renderList(120);
    scrollToFrac(el, 0.9); // bottom of a short list
    expect(rows().length).toBe(120);

    // A later sync adds an entry. The window must keep covering the list:
    // clamping the window down at exhaustion would hide the new row with
    // no scroll event to earn it back.
    serveCiphers(121);
    await vaultApi.refreshCiphers();
    await waitFor(() => expect(rows().length).toBe(121));
  });

  it("keeps serving pages on repeated deep scrolls until exhausted", async () => {
    const el = await renderList(1200);
    for (let i = 1; i <= 7; i++) {
      scrollToFrac(el, 0.9);
      await waitFor(() => expect(rows().length).toBe(Math.min(500 + i * 100, 1200)));
    }
    expect(rows().length).toBe(1200);

    scrollToFrac(el, 0.95); // exhausted: extra triggers are no-ops
    expect(rows().length).toBe(1200);
  });

  it("resets the window when the search query reshapes the list", async () => {
    const el = await renderList(1200);
    scrollToFrac(el, 0.9);
    await waitFor(() => expect(rows().length).toBe(600));

    const input = document.querySelector('[data-testid="vault-search"] input');
    fireEvent.input(input, { target: { value: "Entry" } });
    await waitFor(() => expect(rows().length).toBe(500));
    expect(el.__geo.top).toBe(0); // scroll returns to the top with the window
  });

  it("resets the window when the category changes", async () => {
    const el = await renderList(1200);
    scrollToFrac(el, 0.9);
    await waitFor(() => expect(rows().length).toBe(600));

    fireEvent.click(screen.getByTestId("category-favorites"));
    await waitFor(() => expect(screen.queryAllByTestId("row")).toEqual([]));

    fireEvent.click(screen.getByTestId("category-allItems"));
    await waitFor(() => expect(rows().length).toBe(500));
  });
});
