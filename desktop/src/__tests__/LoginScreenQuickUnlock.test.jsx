// LoginScreen Quick Unlock auto-prompt behavior.
//
// 1Password/Bitwarden parity: when the login screen mounts and Quick Unlock
// is available for the targeted vault, the platform biometric prompt fires
// immediately. Cancel falls back to the password form (no toast, no loop);
// the button remains for manual retry.
import { describe, test, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@solidjs/testing-library";

const authMock = {
  status: () => "locked",
  activeVault: () => null,
  lastUnlockError: () => null,
  switchTarget: () => "baluard-x",
  setSwitchTarget: vi.fn(),
  biometricAvailable: () => biometricState.available,
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

const switcherMock = {
  activeSlug: () => "baluard-x",
  switchTo: vi.fn(),
  vaults: () => [],
};

const biometricState = { available: false };

vi.mock("../context/AuthContext.jsx", () => ({
  useAuth: () => authMock,
}));
vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => switcherMock,
}));
vi.mock("../lib/biometry.js", () => ({
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

import { biometryPrompt } from "../lib/biometry.js";
import { daemon } from "../lib/daemon.js";
import { toastError } from "../context/toastSignal.js";
import LoginScreen from "../components/LoginScreen.jsx";

beforeEach(() => {
  vi.clearAllMocks();
  biometricState.available = false;
});

describe("LoginScreen Quick Unlock auto-prompt", () => {
  test("fires the biometric prompt once as soon as Quick Unlock is available", async () => {
    biometricState.available = true;
    biometryPrompt.mockResolvedValue(true);
    daemon.mockImplementation(async (action) => {
      if (action === "vault.open") return JSON.stringify({ info: "x" });
      return "{}";
    });

    render(() => <LoginScreen />);

    await waitFor(() => expect(biometryPrompt).toHaveBeenCalledTimes(1));
    // Assert on the terminal step so the whole unlock chain has landed.
    await waitFor(() => expect(authMock.finishQuickUnlock).toHaveBeenCalled());
    expect(daemon).toHaveBeenCalledWith("vault.open", "", "baluard-x");
    expect(daemon).toHaveBeenCalledWith("vault.biometric_unlock", "", "baluard-x");
    // The prompt must not loop while the unlock completes.
    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).toHaveBeenCalledTimes(1);
  });

  test("cancel leaves the password form usable with no toast and no loop", async () => {
    biometricState.available = true;
    biometryPrompt.mockRejectedValue(new Error("User canceled the prompt"));

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

  test("no prompt when Quick Unlock is not available", async () => {
    biometricState.available = false;

    render(() => <LoginScreen />);

    await new Promise(r => setTimeout(r, 20));
    expect(biometryPrompt).not.toHaveBeenCalled();
  });
});
