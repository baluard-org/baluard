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
