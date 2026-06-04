import { onMount, Switch, Match } from "solid-js";
import { Transition } from "solid-transition-group";
import { useI18n } from "./i18n/index.jsx";
import { daemon } from "./lib/daemon.js";
import { useAuth } from "./context/AuthContext.jsx";
import { setError } from "./context/errorSignal.js";
import { VaultProvider } from "./context/VaultContext.jsx";

import LoginScreen from "./components/LoginScreen.jsx";
import RecoveryScreen from "./components/RecoveryScreen.jsx";
import CreateVaultScreen from "./components/CreateVaultScreen.jsx";
import VaultView from "./components/VaultView.jsx";

export default function App() {
  const auth = useAuth();
  const { t } = useI18n();

  onMount(async () => {
    try {
      await daemon("vault.open");
    } catch (e) {
      if (/Cannot connect/i.test(e.message)) {
        setError("");
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
    <Transition name="fade" mode="out-in">
      <Switch>
        <Match when={auth.status() === "unlocked"}>
          <VaultProvider>
            <VaultView />
          </VaultProvider>
        </Match>
        <Match when={auth.status() === "init" || auth.status() === "creating"}>
          <CreateVaultScreen />
        </Match>
        <Match when={auth.status() === "recovery"}>
          <RecoveryScreen />
        </Match>
        <Match when={true}>
          <LoginScreen />
        </Match>
      </Switch>
    </Transition>
  );
}

