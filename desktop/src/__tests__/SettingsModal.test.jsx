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
  toastWarning: vi.fn(),
  toasts: { length: 0 },
}));

// Heavy child panels: stub them.
vi.mock("../components/DeviceFleetPanel.jsx", () => ({ default: () => <div data-testid="device-fleet" /> }));
vi.mock("../components/SyncTab.jsx", () => ({ default: () => <div data-testid="sync-tab" /> }));
vi.mock("../components/BridgeTab.jsx", () => ({ default: () => <div data-testid="bridge-tab" /> }));
vi.mock("../components/FocusTrap.jsx", () => ({ default: () => null }));

import { toastSuccess as toastSuccessMock, toastError as toastErrorMock, toastWarning as toastWarningMock } from "../context/toastSignal.js";

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

describe("SettingsModal security-key guard flow", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    toastSuccessMock.mockClear();
    toastErrorMock.mockClear();
    toastWarningMock.mockClear();
  });

  // The runtime hw_status shape for a machine whose only usable backend
  // is a FIDO security key (tap on every use, no consent support).
  const fidoStatus = (over = {}) =>
    JSON.stringify({
      capable: true,
      backend: "fido2",
      backends: [
        { backend: "fido2", capable: true, reason: null, interaction: "per-use" },
      ],
      seal: "v1",
      enabled: false,
      consent_supported: false,
      consent: false,
      attestation: null,
      ...over,
    });

  function mockBase(statusPayload, enableResponse) {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") {
        return Promise.resolve(
          JSON.stringify({ vault_timeout: "15m", fetch_favicons: false, display_name: "Alice", avatar_ext: "png" }),
        );
      }
      if (action === "vault.avatar.get") return Promise.resolve("");
      if (action === "vault.pin_status") return Promise.resolve(JSON.stringify({ enabled: false }));
      if (action === "vault.biometric_status") return Promise.resolve(JSON.stringify({ enabled: false }));
      if (action === "vault.hw_status") return Promise.resolve(statusPayload);
      if (action === "vault.hw_enable") return enableResponse();
      return Promise.resolve("");
    });
  }

  async function openDataTab(rendered) {
    await waitFor(() => expect(rendered.getByText("settings.tabData", { exact: false })).toBeTruthy());
    fireEvent.click(rendered.getByText("settings.tabData", { exact: false }));
    await waitFor(() => expect(rendered.getByTestId("hw-guard-card")).toBeTruthy());
  }

  it("enabling on a tap key shows the touch panel naming the vault, cancel hides it, and the finish still toasts", async () => {
    let resolveEnable;
    mockBase(fidoStatus(), () => new Promise((res) => { resolveEnable = res; }));
    const rendered = render(() => <SettingsModal />);
    await openDataTab(rendered);

    fireEvent.click(rendered.getByTestId("hw-toggle"));
    await waitFor(() => expect(rendered.getByTestId("confirm-accept")).toBeTruthy());
    fireEvent.click(rendered.getByTestId("confirm-accept"));

    // The request is pending on the physical touch: the panel names the
    // vault (the i18n mock inlines vars as JSON).
    await waitFor(() => expect(rendered.getByTestId("hw-touch-wait")).toBeTruthy());
    expect(rendered.getByText(/hwTouchBodyName/).textContent).toContain("Alice");

    fireEvent.click(rendered.getByTestId("hw-touch-cancel"));
    flush();
    expect(rendered.queryByTestId("hw-touch-wait")).toBeNull();

    resolveEnable(JSON.stringify({ enabled: true, backend: "fido2", attestation: "verified" }));
    await waitFor(() => expect(toastSuccessMock).toHaveBeenCalledWith("settings.hwEnabledToast"));
  });

  it("an unknown-vendor key still enables but warns instead of celebrating", async () => {
    mockBase(
      fidoStatus(),
      () => Promise.resolve(JSON.stringify({ enabled: true, backend: "fido2", attestation: "unknown-vendor" })),
    );
    const rendered = render(() => <SettingsModal />);
    await openDataTab(rendered);
    fireEvent.click(rendered.getByTestId("hw-toggle"));
    await waitFor(() => expect(rendered.getByTestId("confirm-accept")).toBeTruthy());
    fireEvent.click(rendered.getByTestId("confirm-accept"));

    await waitFor(() => expect(toastWarningMock).toHaveBeenCalledWith("settings.hwAttestUnknownToast"));
    expect(toastSuccessMock).not.toHaveBeenCalled();
  });

  it("an enabled tap seal reports the recorded attestation verdict", async () => {
    mockBase(
      fidoStatus({ seal: "v2-hw", enabled: true, attestation: "unknown-vendor" }),
      () => Promise.resolve(""),
    );
    const rendered = render(() => <SettingsModal />);
    await openDataTab(rendered);
    expect(rendered.getByText("settings.hwAttestUnknownShort")).toBeTruthy();
  });

  it("disabling demands the master password and sends it with the request", async () => {
    const repromptShow = vi.fn((cb) => cb("retype-my-pass"));
    window.__baluardReprompt = { show: repromptShow };
    try {
      const calls = [];
      daemonMock.mockImplementation((action, payload) => {
        calls.push([action, payload]);
        if (action === "settings.get") {
          return Promise.resolve(
            JSON.stringify({ vault_timeout: "15m", fetch_favicons: false, display_name: "Alice", avatar_ext: "png" }),
          );
        }
        if (action === "vault.avatar.get") return Promise.resolve("");
        if (action === "vault.pin_status" || action === "vault.biometric_status") {
          return Promise.resolve(JSON.stringify({ enabled: false }));
        }
        if (action === "vault.hw_status") {
          return Promise.resolve(fidoStatus({ seal: "v2-hw", enabled: true }));
        }
        if (action === "vault.hw_disable") return Promise.resolve(JSON.stringify({ enabled: false }));
        return Promise.resolve("");
      });
      const rendered = render(() => <SettingsModal />);
      await openDataTab(rendered);

      fireEvent.click(rendered.getByTestId("hw-toggle"));
      await waitFor(() => expect(rendered.getByTestId("confirm-accept")).toBeTruthy());
      fireEvent.click(rendered.getByTestId("confirm-accept"));
      flush();

      // The password collector gates the downgrade and its verified
      // password rides the disable request.
      expect(repromptShow).toHaveBeenCalled();
      const disable = calls.find(([a]) => a === "vault.hw_disable");
      expect(disable).toBeTruthy();
      expect(disable[1]).toBe("retype-my-pass");
      await waitFor(() => expect(toastSuccessMock).toHaveBeenCalledWith("settings.hwDisabledToast"));
    } finally {
      delete window.__baluardReprompt;
    }
  });

  it("enabling never consults the password collector", async () => {
    const repromptShow = vi.fn();
    window.__baluardReprompt = { show: repromptShow };
    try {
      mockBase(fidoStatus(), () => Promise.resolve(JSON.stringify({ enabled: true, backend: "fido2", attestation: "verified" })));
      const rendered = render(() => <SettingsModal />);
      await openDataTab(rendered);
      fireEvent.click(rendered.getByTestId("hw-toggle"));
      await waitFor(() => expect(rendered.getByTestId("confirm-accept")).toBeTruthy());
      fireEvent.click(rendered.getByTestId("confirm-accept"));
      flush();
      await waitFor(() => expect(toastSuccessMock).toHaveBeenCalledWith("settings.hwEnabledToast"));
      expect(repromptShow).not.toHaveBeenCalled();
    } finally {
      delete window.__baluardReprompt;
    }
  });

  it("does not accumulate hw-status polls across open/close cycles", async () => {
    vi.useFakeTimers();
    try {
      const [settingsOpen, setSettingsOpen] = realCreateSignal(true);
      vaultMock.showSettingsModal.mockImplementation(() => settingsOpen());
      let hwStatusCalls = 0;
      daemonMock.mockImplementation((action) => {
        if (action === "settings.get") {
          return Promise.resolve(JSON.stringify({ vault_timeout: "15m", fetch_favicons: false, display_name: "Alice", avatar_ext: "png" }));
        }
        if (action === "vault.avatar.get") return Promise.resolve("");
        if (action === "vault.pin_status") return Promise.resolve(JSON.stringify({ enabled: false }));
        if (action === "vault.biometric_status") return Promise.resolve(JSON.stringify({ enabled: false }));
        if (action === "vault.hw_status") {
          hwStatusCalls += 1;
          return Promise.resolve(fidoStatus());
        }
        return Promise.resolve("");
      });
      render(() => <SettingsModal />);
      // Two full open/close cycles: each open used to start another
      // 4-second poll, so a leaked interval probes the token on every
      // tick of every past session.
      await vi.advanceTimersByTimeAsync(50);
      setSettingsOpen(false);
      await vi.advanceTimersByTimeAsync(50);
      setSettingsOpen(true);
      await vi.advanceTimersByTimeAsync(50);
      setSettingsOpen(false);
      await vi.advanceTimersByTimeAsync(50);
      setSettingsOpen(true);
      await vi.advanceTimersByTimeAsync(50);

      const before = hwStatusCalls;
      await vi.advanceTimersByTimeAsync(8100);
      expect(hwStatusCalls - before).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("re-probes the security key on an interval so a plugged key appears without a reopen", async () => {
    vi.useFakeTimers();
    try {
      let plugged = false;
      daemonMock.mockImplementation((action) => {
        if (action === "settings.get") {
          return Promise.resolve(
            JSON.stringify({ vault_timeout: "15m", fetch_favicons: false, display_name: "Alice", avatar_ext: "png" }),
          );
        }
        if (action === "vault.avatar.get") return Promise.resolve("");
        if (action === "vault.pin_status") return Promise.resolve(JSON.stringify({ enabled: false }));
        if (action === "vault.biometric_status") return Promise.resolve(JSON.stringify({ enabled: false }));
        if (action === "vault.hw_status") {
          return Promise.resolve(
            plugged
              ? fidoStatus()
              : JSON.stringify({ capable: false, reason: "no-token", backends: [{ backend: "fido2", capable: false, reason: "no-token", interaction: "per-use" }], seal: "v1", enabled: false, consent_supported: false, consent: false, attestation: null }),
          );
        }
        return Promise.resolve("");
      });
      const rendered = render(() => <SettingsModal />);
      await waitFor(() => expect(rendered.getByText("settings.tabData", { exact: false })).toBeTruthy());
      fireEvent.click(rendered.getByText("settings.tabData", { exact: false }));
      await vi.advanceTimersByTimeAsync(100);
      expect(rendered.queryByTestId("hw-guard-card")).toBeNull();

      plugged = true;
      await vi.advanceTimersByTimeAsync(4500);
      expect(rendered.getByTestId("hw-guard-card")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });
});