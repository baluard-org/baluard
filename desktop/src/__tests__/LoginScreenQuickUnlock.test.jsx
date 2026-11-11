// LoginScreen Quick Unlock auto-prompt behavior.
//
// 1Password/Bitwarden parity: when the login screen mounts and Quick Unlock
// is available for the targeted vault, the platform biometric prompt fires
// immediately. Cancel falls back to the password form (no toast, no loop);
// the button remains for manual retry. Rejections arrive as Tauri's plain
// strings, which is the shape the cancel check must survive.
import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@solidjs/testing-library";
import { createSignal } from "solid-js";

// A REAL Solid signal: the auto-prompt effect tracks auth.biometricAvailable,
// so a cold-start flip (false -> true after mount) must be observable
// reactivity, not a plain object property.
const [biometricAvailable, setBiometricAvailable] = createSignal(false);

const authState = {
  status: "locked",
  switchTarget: null, // null = the switcher's activeSlug is the real target
};

const authMock = {
  status: () => authState.status,
  activeVault: () => null,
  lastUnlockError: () => null,
  switchTarget: () => authState.switchTarget,
  setSwitchTarget: vi.fn(),
  biometricAvailable,
  pinAvailable: () => false,
  keyringHint: () => null,
  refreshBiometric: vi.fn(),
  refreshPin: vi.fn(),
  refreshActiveVault: vi.fn(),
  setLoginPasswordRef: vi.fn(),
  setStatus: vi.fn(),
  unlock: vi.fn(),
  finishQuickUnlock: vi.fn(),
};

const switcherState = {
  vaultsLoaded: true,
  vaults: [{ slug: "baluard-x", display_name: "X" }],
};

const switcherMock = {
  activeSlug: () => "baluard-x",
  switchTo: vi.fn(),
  vaultsLoaded: () => switcherState.vaultsLoaded,
  vaults: () => switcherState.vaults,
};

vi.mock("../context/AuthContext.jsx", () => ({
  useAuth: () => authMock,
}));
vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => switcherMock,
}));
vi.mock("../lib/biometry.js", () => ({
  biometryAvailable: vi.fn(() => Promise.resolve(true)),
  biometryPrompt: vi.fn(),
}));
vi.mock("../lib/daemon.js", () => ({
  daemon: vi.fn(),
  getRenderState: vi.fn(() => Promise.resolve({ linux: false, recovery: false })),
}));
vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k, locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (props) => props.children,
}));
vi.mock("../context/toastSignal.js", () => ({
  toast: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toastWarning: vi.fn(),
  dismiss: vi.fn(),
  toasts: { length: 0 },
}));
// Children with their own provider/daemon needs stay out of this suite.
vi.mock("../components/VaultSwitcher.jsx", () => ({ default: () => null }));
vi.mock("../components/BridgeUnlockBanner.jsx", () => ({ default: () => null }));
vi.mock("../components/ThemeToggleFloating.jsx", () => ({ default: () => null }));
vi.mock("../components/CopyButton.jsx", () => ({ default: () => null }));
vi.mock("../components/OpenSharedModal.jsx", () => ({ default: () => null }));
vi.mock("../components/LegacyContactOpen.jsx", () => ({ default: () => null }));

import { biometryAvailable, biometryPrompt } from "../lib/biometry.js";
import { daemon } from "../lib/daemon.js";
import { toastError } from "../context/toastSignal.js";
import LoginScreen from "../components/LoginScreen.jsx";

// Without this, each test's LoginScreen stays mounted and its effect keeps
// sharing the module-scope availability signal with the next test's mount.
afterEach(() => {
  cleanup();
});

beforeEach(() => {
  vi.clearAllMocks();
  authState.status = "locked";
  authState.switchTarget = null;
  setBiometricAvailable(false);
  biometryAvailable.mockResolvedValue(true);
});

describe("LoginScreen Quick Unlock auto-prompt", () => {
  test("fires the biometric prompt once as soon as Quick Unlock is available", async () => {
    setBiometricAvailable(true);
    biometryPrompt.mockResolvedValue(true);
    daemon.mockImplementation(async (action) => {
      if (action === "vault.open") return JSON.stringify({ info: "x" });
      return "{}";
    });

    render(() => <LoginScreen />);

    await waitFor(() => expect(biometryPrompt).toHaveBeenCalledTimes(1));
    // Assert on the terminal step so the whole unlock chain has landed.
    await waitFor(() => expect(authMock.finishQuickUnlock).toHaveBeenCalled());
    // The slug comes from the switcher's activeSlug when no explicit target
    // is set — the daemon-active vault on a cold start.
    expect(daemon).toHaveBeenCalledWith("vault.open", "", "baluard-x");
    expect(daemon).toHaveBeenCalledWith("vault.biometric_unlock", "", "baluard-x");
    // The prompt must not loop while the unlock completes.
    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).toHaveBeenCalledTimes(1);
  });

  test("a plain-string cancel (the real Tauri rejection shape) stays silent", async () => {
    setBiometricAvailable(true);
    biometryPrompt.mockRejectedValue(
      "[userCancel] - Authentication was canceled by the user",
    );

    render(() => <LoginScreen />);

    await waitFor(() => expect(biometryPrompt).toHaveBeenCalledTimes(1));
    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).toHaveBeenCalledTimes(1);
    expect(toastError).not.toHaveBeenCalled();
    expect(daemon).not.toHaveBeenCalled();
    // The password form stays rendered (the login screen carries more than
    // one unlock submit across its sections; presence is what matters).
    expect(screen.getAllByTestId("login-unlock").length).toBeGreaterThan(0);
  });

  test("a plain-string non-cancel rejection surfaces a toast", async () => {
    setBiometricAvailable(true);
    biometryPrompt.mockRejectedValue(
      "[biometryUnavailable] - No biometric hardware",
    );

    render(() => <LoginScreen />);

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(daemon).not.toHaveBeenCalled();
  });

  test("no prompt when the daemon reports Quick Unlock unavailable", async () => {
    setBiometricAvailable(false);

    render(() => <LoginScreen />);

    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).not.toHaveBeenCalled();
  });

  test("no prompt when the platform biometry plugin cannot prompt (Linux)", async () => {
    setBiometricAvailable(true);
    biometryAvailable.mockResolvedValue(false);

    render(() => <LoginScreen />);

    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).not.toHaveBeenCalled();
  });

  test("no prompt while a password unlock is in flight", async () => {
    setBiometricAvailable(true);
    authState.status = "unlocking";

    render(() => <LoginScreen />);

    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).not.toHaveBeenCalled();
  });

  test("prompts once availability flips true after mount (cold start)", async () => {
    render(() => <LoginScreen />);
    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).not.toHaveBeenCalled();

    setBiometricAvailable(true);
    await waitFor(() => expect(biometryPrompt).toHaveBeenCalledTimes(1));
    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).toHaveBeenCalledTimes(1);
  });
  test("empty registry shows the decision state, never the unlock form", async () => {
    switcherState.vaultsLoaded = true;
    switcherState.vaults = [];
    const { container, getByText, queryByText } = render(() => (
      <LoginScreen />
    ));
    await waitFor(() =>
      expect(getByText("login.noVaultsTitle")).toBeTruthy(),
    );
    // No unlock form to fail against a phantom vault.
    expect(queryByText("login.unlock")).toBeNull();
    // The action button hands the user to the welcome decision screen.
    const btn = container.querySelector("button");
    expect(btn && btn.textContent.includes("login.noVaultsAction")).toBe(true);
    btn.click();
    await Promise.resolve();
    expect(authMock.setStatus).toHaveBeenCalledWith("welcome");
    // restore for sibling tests
    switcherState.vaults = [{ slug: "baluard-x", display_name: "X" }];
  });
});