import { onMount, Show } from "solid-js";
import { useI18n } from "./i18n/index.jsx";
import { ERROR_PATTERNS } from "./lib/utils.js";
import { daemon } from "./lib/daemon.js";
import { AppProvider, useApp } from "./context/AppContext.jsx";
import { useActions } from "./hooks/useActions.js";

import LoginScreen from "./components/LoginScreen.jsx";
import RecoveryScreen from "./components/RecoveryScreen.jsx";
import CreateVaultScreen from "./components/CreateVaultScreen.jsx";
import VaultView from "./components/VaultView.jsx";

export default function App() {
  return (
    <AppProvider>
      <AppInner />
    </AppProvider>
  );
}

function AppInner() {
  const { setStatus, setError, setVaultInfo, status } = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();

  onMount(async () => {
    try {
      await daemon("vault.open");
    } catch (e) {
      if (ERROR_PATTERNS.some(({ pattern }) => pattern.test(e.message))) {
        if (/Cannot connect/i.test(e.message)) {
          setError("");
          return;
        }
      }
      setStatus("init");
      return;
    }
    try {
      const info = JSON.parse(await daemon("vault.info"));
      if (info.unlocked) {
        setStatus("unlocked");
        setVaultInfo(info);
        await refreshCiphers();
      }
    } catch {}
  });

  return (
    <Show when={status() === "unlocked"} fallback={
      <Show when={status() === "init" || status() === "creating"} fallback={
        <Show when={status() === "recovery"} fallback={<LoginScreen />}>
          <RecoveryScreen />
        </Show>
      }>
        <CreateVaultScreen />
      </Show>
    }>
      <VaultView />
    </Show>
  );
}
