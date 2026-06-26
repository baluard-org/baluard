import { onMount, Show } from "solid-js";
import { useI18n } from "./i18n/index.jsx";
import { daemon, showWindow } from "./lib/daemon.js";
import { disableAutofill } from "./lib/disableAutofill.js";
import { useAuth } from "./context/AuthContext.jsx";
import { VaultProvider } from "./context/VaultContext.jsx";
import { VaultSwitcherProvider } from "./context/VaultSwitcherContext.jsx";
import { AutoSyncProvider } from "./context/AutoSyncContext.jsx";

import LoginScreen from "./components/LoginScreen.jsx";
import RecoveryScreen from "./components/RecoveryScreen.jsx";
import CreateVaultScreen from "./components/CreateVaultScreen.jsx";
import SetupScreen from "./components/SetupScreen.jsx";
import WelcomeScreen from "./components/WelcomeScreen.jsx";
import VaultView from "./components/VaultView.jsx";
import ToastContainer from "./components/ToastContainer.jsx";

export default function App() {
  const auth = useAuth();
  const { t } = useI18n();

  onMount(async () => {
    try {
      // Detect macOS to apply titlebar adjustments
      if (navigator.userAgent.includes("Mac")) {
        document.documentElement.classList.add("platform-mac");
      }

      // Autofill is off app-wide by default; inputs opt in with data-autofill="on".
      disableAutofill();

      // Try to open + probe the active vault. Best-effort: if the daemon is
      // reachable and a vault is already unlocked (e.g. resumed session),
      // jump straight in. Failures here are NOT proof that no vault exists.
      let daemonUp = true;
      try {
        await daemon("vault.open");
        const info = JSON.parse(await daemon("vault.info"));
        if (info.unlocked) {
          auth.setStatus("unlocked");
          auth.setVaultInfo(info);
          return;
        }
      } catch (e) {
        if (/Cannot connect/i.test(e.message)) daemonUp = false;
        // Any other error (e.g. "Vault not opened", stale active) just means
        // the user must pick/unlock a vault — handled by the login screen.
      }

      if (!daemonUp) return; // daemon down: stay on default (locked) screen

      // Decide create-vs-login by whether ANY vault is registered. The create
      // screen is only for a genuinely empty install.
      try {
        const data = JSON.parse(await daemon("vaults.list"));
        const count = Array.isArray(data.vaults) ? data.vaults.length : 0;
        if (count === 0) auth.setStatus("init");
      } catch {
        // Could not read the registry — stay on the login screen rather than
        // risk clobbering an existing install with the create flow.
      }
    } finally {
      // Show window once initialization and initial state checks finish.
      await showWindow();
    }
  });

  return (
    <VaultSwitcherProvider>
      <div class="app relative w-full h-full overflow-hidden">
        {/* macOS window drag region */}
        <Show when={navigator.userAgent.includes("Mac")}>
          <div data-tauri-drag-region class="absolute top-0 left-0 right-0 h-7 z-50 cursor-default" />
        </Show>
        {/* Toast overlay — always rendered */}
        <ToastContainer />
        {/* Auth screens — covered by vault when unlocked */}
        <Show when={auth.status() !== "unlocked"}>
          <div class="app__auth absolute inset-0">
            <Show when={auth.status() === "welcome"} fallback={
              <Show when={auth.status() === "setup"} fallback={
                <Show when={auth.status() === "recovery"} fallback={
                  <Show when={auth.status() === "init" || auth.status() === "creating"}
                    fallback={<LoginScreen />}>
                    <CreateVaultScreen />
                  </Show>
                }>
                  <RecoveryScreen />
                </Show>
              }>
                <SetupScreen />
              </Show>
            }>
              <WelcomeScreen />
            </Show>
          </div>
        </Show>

        {/* Vault — mounts instantly, animates its own entrance */}
        <Show when={auth.status() === "unlocked"}>
          <div class="app__vault absolute inset-0 vault-enter">
            <VaultProvider>
              <AutoSyncProvider>
                <VaultView />
              </AutoSyncProvider>
            </VaultProvider>
          </div>
        </Show>
      </div>
    </VaultSwitcherProvider>
  );
}
