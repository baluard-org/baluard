import { onMount, Show } from "solid-js";
import { useI18n } from "./i18n/index.jsx";
import { daemon } from "./lib/daemon.js";
import { useAuth } from "./context/AuthContext.jsx";
import { VaultProvider } from "./context/VaultContext.jsx";

import LoginScreen from "./components/LoginScreen.jsx";
import RecoveryScreen from "./components/RecoveryScreen.jsx";
import CreateVaultScreen from "./components/CreateVaultScreen.jsx";
import SetupScreen from "./components/SetupScreen.jsx";
import VaultView from "./components/VaultView.jsx";
import ToastContainer from "./components/ToastContainer.jsx";

export default function App() {
  const auth = useAuth();
  const { t } = useI18n();

  onMount(async () => {
    try {
      await daemon("vault.open");
    } catch (e) {
      if (/Cannot connect/i.test(e.message)) {
    // no error signal to clear
      } else {
        auth.setStatus("init");
      }
      return;
    }
    try {
      const info = JSON.parse(await daemon("vault.info"));
      if (info.unlocked) {
        auth.setStatus("unlocked");
        auth.setVaultInfo(info);
      }
    } catch {}
  });

  return (
    <div class="app relative w-full h-full overflow-hidden">
      {/* Toast overlay — always rendered */}
      <ToastContainer />
      {/* Auth screens — covered by vault when unlocked */}
      <Show when={auth.status() !== "unlocked"}>
        <div class="app__auth absolute inset-0">
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
        </div>
      </Show>

      {/* Vault — mounts instantly, animates its own entrance */}
      <Show when={auth.status() === "unlocked"}>
        <div class="app__vault absolute inset-0 vault-enter">
          <VaultProvider>
            <VaultView />
          </VaultProvider>
        </div>
      </Show>
    </div>
  );
}
