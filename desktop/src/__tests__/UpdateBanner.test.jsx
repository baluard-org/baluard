// Tests for desktop/src/components/UpdateBanner.jsx — the D79 install
// surface. The updater context is mocked so the test drives the states
// directly; lib/update.js is mocked to isolate the banner from Tauri.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { createSignal } from "solid-js";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({
    t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k),
    locale: () => "en-US",
  }),
}));

vi.mock("../lib/update.js", async (importOriginal) => ({
  ...(await importOriginal()),
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

  it("opens the changelog page anchored at the offered version", async () => {
    store.available = () => ({ version: "0.3.0", notes: "Notes", date: null, current_version: "0.2.0" });
    const { getByTestId } = render(() => <UpdateBanner />);
    fireEvent.click(getByTestId("update-changelog"));
    await Promise.resolve();
    expect(openUrlMock).toHaveBeenCalledWith("https://baluard.app/changelog/#v-0-3-0");
  });

  it("shows the release date and the first five changelog entries", () => {
    store.available = () => ({
      version: "0.3.0",
      notes: "- First change\n- Second change\n- Third change\n- Fourth change\n- Fifth change\n- Sixth change",
      date: "2026-11-17T14:22:54Z",
      current_version: "0.2.0",
    });
    const { getByTestId, container } = render(() => <UpdateBanner />);
    const entries = container.querySelectorAll("[data-testid=update-changelog-entry]");
    expect(entries).toHaveLength(5);
    expect(entries[0].textContent).toContain("First change");
    expect(entries[4].textContent).toContain("Fifth change");
    expect(container.textContent).not.toContain("Sixth change");
    expect(container.textContent).toContain("Nov 17, 2026");
    const row = getByTestId("update-install").closest("div").parentElement;
    expect(row.firstElementChild).toBe(getByTestId("update-changelog"));
    const right = getByTestId("update-install").closest("div");
    expect(right.firstElementChild).toBe(getByTestId("update-dismiss"));
    expect(right.lastElementChild).toBe(getByTestId("update-install"));
  });

  it("shows release-note paragraphs as changelog entries", () => {
    store.available = () => ({
      version: "0.3.0",
      notes: "Baluard 0.3.0 is out.\n\nFirst change.\n\nSecond change.\n\nDesktop, mobile, the browser extension, and all package channels carry 0.3.0.\n\nAs always, thanks for trying Baluard :)",
      date: null,
      current_version: "0.2.0",
    });
    const { container } = render(() => <UpdateBanner />);
    const entries = container.querySelectorAll("[data-testid=update-changelog-entry]");
    expect(entries).toHaveLength(2);
    expect(entries[0].textContent).toContain("First change.");
    expect(entries[1].textContent).toContain("Second change.");
    expect(container.textContent).not.toContain("As always");
    expect(container.textContent).not.toContain("package channels carry");
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

  it("animates the modal when it opens for a new version", async () => {
    const [avail, setAvail] = createSignal(null);
    store.available = avail;
    const { container } = render(() => <UpdateBanner />);
    expect(container.querySelector("[data-testid=update-banner]")).toBeNull();

    setAvail({ version: "0.2.0", notes: "Fixes", date: null, current_version: "0.1.0" });
    await Promise.resolve();
    const banner = container.querySelector("[data-testid=update-banner]");
    expect(banner).not.toBeNull();
    expect(banner.classList.contains("update-banner-enter")).toBe(true);
    expect(banner.classList.contains("update-banner-enter-active")).toBe(true);
  });

  it("transitions between the offer and installing views when install is clicked", async () => {
    const [installing, setInstalling] = createSignal(false);
    store.available = () => ({ version: "0.2.0", notes: "Fixes", date: null, current_version: "0.1.0" });
    store.installing = installing;
    store.install = vi.fn(() => setInstalling(true));

    const { container, getByTestId } = render(() => <UpdateBanner />);
    const banner = container.querySelector("[data-testid=update-banner]");
    const offerEl = getByTestId("update-install").closest(".flex.items-start");

    fireEvent.click(getByTestId("update-install"));
    expect(store.install).toHaveBeenCalledTimes(1);
    await Promise.resolve();

    // out-in mode exits the offer view first before mounting the installing view
    expect(offerEl.classList.contains("fade-exit-active")).toBe(true);
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    fireEvent(offerEl, new Event("transitionend"));
    await Promise.resolve();

    expect(banner.textContent).toContain("update.installing");
    const installingEl = banner.querySelector(".flex.items-center");
    expect(installingEl.classList.contains("fade-enter-active")).toBe(true);
  });
});
