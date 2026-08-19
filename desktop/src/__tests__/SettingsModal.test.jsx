// Tests for desktop/src/components/SettingsModal.jsx — the big settings
// modal (765 lines). We test the user-facing behavior of the General +
// Data tabs without trying to cover every child panel.
//
// Heavy child components (DeviceFleetPanel, SyncTab, BridgeTab,
// FocusTrap) are stubbed to a div so the modal mounts without dragging
// in their entire context trees.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";

// ── Mocks (hoisted) ───────────────────────────────────────────

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k), locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (props) => props.children,
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

vi.mock("../lib/biometry.js", () => ({ biometryAvailable: vi.fn().mockResolvedValue(false) }));

const themeMock = { value: "system", set: vi.fn() };
vi.mock("../context/themeSignal.js", () => ({
  theme: () => "system",
  setTheme: (t) => themeMock.set(t),
}));

const vaultMock = {
  showSettingsModal: vi.fn(() => true),
  setShowSettingsModal: vi.fn(),
  refreshProfile: vi.fn().mockResolvedValue(undefined),
};
const authMock = { signOut: vi.fn() };

import { useVault as realUseVault } from "../context/VaultContext.jsx";
import { useAuth as realUseAuth } from "../context/AuthContext.jsx";
import { createSignal as realCreateSignal, flush } from "solid-js";

vi.mock("../context/VaultContext.jsx", () => ({
  useVault: () => vaultMock,
  VaultContext: { Provider: (p) => p.children },
}));
vi.mock("../context/AuthContext.jsx", () => ({
  useAuth: () => authMock,
  AuthContext: { Provider: (p) => p.children },
}));

vi.mock("../context/toastSignal.js", () => ({
  toast: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toasts: { length: 0 },
}));

// Heavy child panels: stub them.
vi.mock("../components/DeviceFleetPanel.jsx", () => ({ default: () => <div data-testid="device-fleet" /> }));
vi.mock("../components/SyncTab.jsx", () => ({ default: () => <div data-testid="sync-tab" /> }));
vi.mock("../components/BridgeTab.jsx", () => ({ default: () => <div data-testid="bridge-tab" /> }));
vi.mock("../components/FocusTrap.jsx", () => ({ default: () => null }));

import SettingsModal from "../components/SettingsModal.jsx";

describe("SettingsModal", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    vaultMock.showSettingsModal.mockReturnValue(true);
    themeMock.set.mockClear();
    authMock.signOut.mockClear();
    vaultMock.refreshProfile.mockClear();
    // Default settings payload
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") {
        return Promise.resolve(JSON.stringify({
          vault_timeout: "15m",
          fetch_favicons: false,
          display_name: "Alice",
          avatar_ext: "png",
        }));
      }
      if (action === "vault.avatar.get") return Promise.resolve("");
      if (action === "vault.pin_status") return Promise.resolve(JSON.stringify({ enabled: false }));
      if (action === "vault.biometric_status") return Promise.resolve(JSON.stringify({ enabled: false }));
      return Promise.resolve("");
    });
  });

  it("does not render when showSettingsModal=false", () => {
    vaultMock.showSettingsModal.mockReturnValue(false);
    const { queryByRole } = render(() => <SettingsModal />);
    expect(queryByRole("dialog")).toBeNull();
  });

  it("renders the dialog when open", async () => {
    const { getByRole } = render(() => <SettingsModal />);
    await waitFor(() => expect(getByRole("dialog")).toBeTruthy());
  });

  it("renders General + Data tabs", async () => {
    const { getByText } = render(() => <SettingsModal />);
    await waitFor(() => {
      expect(getByText("settings.tabGeneral", { exact: false })).toBeTruthy();
    });
    expect(getByText("settings.tabData", { exact: false })).toBeTruthy();
  });

  it("renders Devices tab", async () => {
    const { getByText } = render(() => <SettingsModal />);
    await waitFor(() => {
      expect(getByText("settings.tabDevices", { exact: false })).toBeTruthy();
    });
  });

  it("loads settings on open and pre-fills the auto-lock select", async () => {
    daemonMock.mockImplementationOnce((action) => {
      if (action === "settings.get") {
        return Promise.resolve(JSON.stringify({ vault_timeout: "1h", fetch_favicons: false, display_name: "Alice", avatar_ext: "png" }));
      }
      return daemonMock.getMockImplementation()(action);
    });
    const { container } = render(() => <SettingsModal />);
    // The select element for the auto-lock preset reflects the loaded value.
    await waitFor(() => {
      const sel = container.querySelector("select");
      expect(sel).toBeTruthy();
      expect(sel.value).toBe("1h");
    });
  });

  it("changing the auto-lock select calls daemon settings.set with the new token", async () => {
    const { container } = render(() => <SettingsModal />);
    await waitFor(() => expect(container.querySelector("select")).toBeTruthy());
    const sel = container.querySelector("select");
    // Set the value to "30m" and dispatch a change event.
    sel.value = "30m";
    fireEvent.change(sel);
    flush();
    await waitFor(() =>
      expect(daemonMock).toHaveBeenCalledWith(
        "settings.set",
        JSON.stringify({ vault_timeout: "30m" }),
      )
    );
  });

  it("clicking the Light theme button calls setTheme + daemon settings.set", async () => {
    const { getByText } = render(() => <SettingsModal />);
    await waitFor(() => expect(getByText("settings.lightMode", { exact: false })).toBeTruthy());
    fireEvent.click(getByText("settings.lightMode", { exact: false }));
    flush();
    expect(themeMock.set).toHaveBeenCalledWith("light");
    await waitFor(() =>
      expect(daemonMock).toHaveBeenCalledWith(
        "settings.set",
        JSON.stringify({ theme: "light" }),
      )
    );
  });

  it("clicking the Data tab shows the import/export panel", async () => {
    const { getByText } = render(() => <SettingsModal />);
    await waitFor(() => expect(getByText("settings.tabData", { exact: false })).toBeTruthy());
    fireEvent.click(getByText("settings.tabData", { exact: false }));
    flush();
    // The data tab reveals the import/export headings.
    expect(getByText("settings.importTitle", { exact: false })).toBeTruthy();
  });
});