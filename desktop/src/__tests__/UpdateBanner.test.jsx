// Tests for desktop/src/components/UpdateBanner.jsx — the D79 install
// surface. The updater context is mocked so the test drives the states
// directly; lib/update.js is mocked to isolate the banner from Tauri.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k) }),
}));

vi.mock("../lib/update.js", () => ({
  formatProgress: (received, total) =>
    !total || total <= 0 ? null : Math.min(100, Math.floor((received / total) * 100)),
}));

const openUrlMock = vi.fn().mockResolvedValue(undefined);
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: (...a) => openUrlMock(...a) }));

const store = {
  status: () => ({ configured: true, channel: "stable", version: "0.1.0" }),
  checking: () => false,
  available: () => null,
  upToDate: () => false,
  error: () => null,
  installing: () => false,
  progress: () => null,
  dismissedVersion: () => null,
  check: vi.fn(),
  install: vi.fn(),
  dismiss: vi.fn(),
  clearError: vi.fn(),
};
vi.mock("../context/UpdateContext.jsx", () => ({
  useUpdater: () => store,
}));

import UpdateBanner from "../components/UpdateBanner.jsx";

beforeEach(() => {
  vi.clearAllMocks();
  openUrlMock.mockResolvedValue(undefined);
  store.available = () => null;
  store.error = () => null;
  store.installing = () => false;
  store.progress = () => null;
  store.dismissedVersion = () => null;
  cleanup();
});

describe("UpdateBanner", () => {
  it("renders nothing when idle", () => {
    const { container } = render(() => <UpdateBanner />);
    expect(container.querySelector("[data-testid=update-banner]")).toBeNull();
  });

  it("offers install for an available version and dismisses", async () => {
    store.available = () => ({ version: "0.2.0", notes: "Fixes", date: null, current_version: "0.1.0" });
    const { container, getByTestId } = render(() => <UpdateBanner />);
    const banner = container.querySelector("[data-testid=update-banner]");
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain("0.2.0");
    fireEvent.click(getByTestId("update-install"));
    expect(store.install).toHaveBeenCalledTimes(1);
    fireEvent.click(getByTestId("update-dismiss"));
    expect(store.dismiss).toHaveBeenCalledTimes(1);
  });

  it("opens the GitHub changelog entry for the offered version", async () => {
    store.available = () => ({ version: "0.3.0", notes: "Notes", date: null, current_version: "0.2.0" });
    const { getByTestId } = render(() => <UpdateBanner />);
    fireEvent.click(getByTestId("update-changelog"));
    await Promise.resolve();
    expect(openUrlMock).toHaveBeenCalledWith("https://github.com/baluard-org/baluard/releases/tag/0.3.0");
  });

  it("clamps the notes to six lines and offers not-now beside install", () => {
    store.available = () => ({
      version: "0.3.0",
      notes: "line1\nline2\nline3\nline4\nline5\nline6\nline7",
      date: null,
      current_version: "0.2.0",
    });
    const { getByTestId, container } = render(() => <UpdateBanner />);
    const notes = container.querySelector(".line-clamp-6");
    expect(notes).not.toBeNull();
    expect(notes.textContent).toContain("line7");
    const row = getByTestId("update-install").closest("div").parentElement;
    expect(row.firstElementChild).toBe(getByTestId("update-changelog"));
    const right = getByTestId("update-install").closest("div");
    expect(right.firstElementChild).toBe(getByTestId("update-dismiss"));
    expect(right.lastElementChild).toBe(getByTestId("update-install"));
  });

  it("hides the banner for a dismissed version", () => {
    store.available = () => ({ version: "0.2.0", notes: null, date: null, current_version: "0.1.0" });
    store.dismissedVersion = () => "0.2.0";
    const { container } = render(() => <UpdateBanner />);
    expect(container.querySelector("[data-testid=update-banner]")).toBeNull();
  });

  it("shows progress while installing and no dismiss control", () => {
    store.available = () => ({ version: "0.2.0", notes: null, date: null, current_version: "0.1.0" });
    store.installing = () => true;
    store.progress = () => ({ received: 50, total: 200 });
    const { container, queryByTestId } = render(() => <UpdateBanner />);
    expect(container.querySelector("[data-testid=update-banner]").textContent).toContain("0.2.0");
    expect(queryByTestId("update-install")).toBeNull();
    expect(queryByTestId("update-dismiss")).toBeNull();
  });

  it("surfaces a manual-check failure and clears it", async () => {
    store.error = () => "Download failed: boom";
    const { getByTestId } = render(() => <UpdateBanner />);
    expect(getByTestId("update-banner").textContent).toContain("Download failed: boom");
    fireEvent.click(getByTestId("update-error-dismiss"));
    expect(store.clearError).toHaveBeenCalledTimes(1);
  });
});
