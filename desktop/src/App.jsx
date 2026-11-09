import { onSettled, Show, createSignal, createEffect } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { initDeepLink, flushPendingEntry } from "./lib/deepLink.js";
import { useI18n } from "./i18n/index.jsx";
import { daemon, showWindow } from "./lib/daemon.js";
import { toastInfo } from "./context/toastSignal.js";
import { disableAutofill } from "./lib/disableAutofill.js";
import { useAuth } from "./context/AuthContext.jsx";
import { VaultProvider } from "./context/VaultContext.jsx";
import { VaultSwitcherProvider } from "./context/VaultSwitcherContext.jsx";
import { AutoSyncProvider } from "./context/AutoSyncContext.jsx";
import { ConflictResolutionProvider } from "./context/ConflictResolutionContext.jsx";
import { UpdateProvider } from "./context/UpdateContext.jsx";
import { AgentApprovalProvider } from "./context/AgentApprovalContext.jsx";

import LoginScreen from "./components/LoginScreen.jsx";
import RecoveryScreen from "./components/RecoveryScreen.jsx";
import CreateVaultScreen from "./components/CreateVaultScreen.jsx";
import SetupScreen from "./components/SetupScreen.jsx";
import WelcomeScreen from "./components/WelcomeScreen.jsx";
import VaultView from "./components/VaultView.jsx";
import AutoSyncIndicator from "./components/AutoSyncIndicator.jsx";
import ConflictResolutionPanel from "./components/ConflictResolutionPanel.jsx";
import ToastContainer from "./components/ToastContainer.jsx";
import UpdateBanner from "./components/UpdateBanner.jsx";

// D79 version gate: after an update, a stale daemon (the bundled sidecar
// did not get replaced) must be impossible to talk to, not quietly wrong.
// This blocks the whole app until the versions agree again.
function VersionGate(props) {
  const { t } = useI18n();
  return (
    <div class="absolute inset-0 z-[100] bg-[var(--color-bg, #101014)] flex items-center justify-center p-8">
      <div class="max-w-sm text-center space-y-3">
        <div class="text-sm font-bold text-[var(--color-text)]">{t("update.versionMismatchTitle")}</div>
        <p class="text-xs text-[var(--color-muted)] whitespace-pre-line">{t("update.versionMismatchBody")}</p>
        <p class="text-[10px] text-[var(--color-muted)] font-mono">{props.detail}</p>
      </div>
    </div>
  );
}

export default function App() {
  const auth = useAuth();
  const { t } = useI18n();
  const [versionMismatch, setVersionMismatch] = createSignal(null);

  // Audit C8/D9: the dev conflict trigger is dynamically imported and only
  // in dev builds. Vite drops `if (import.meta.env.DEV)` blocks statically
  // in `vite build`, so the import() (and the whole trigger + mock chunk,
  // Math.random included) never lands in a production bundle.
  const [ConflictDevTrigger, setConflictDevTrigger] = createSignal(null);
  function DevTriggerSlot() {
    const Comp = ConflictDevTrigger();
    return Comp ? <Comp /> : null;
  }

  onSettled(() => {
    if (import.meta.env.DEV) {
      import("./lib/conflictDevTriggers.jsx").then((m) =>
        setConflictDevTrigger(() => m.default),
      );
    }
  });
  // baluard:// deep links (extension eye icon). Validated in Rust, routed
  // to VaultView through a window event; stashed here while locked and
  // flushed the moment auth reaches unlocked, so nothing is revealed first.
  onSettled(() => {
    void initDeepLink(
      (entry) => window.dispatchEvent(new CustomEvent("baluard:open-entry", { detail: entry })),
      () => auth.status() === "unlocked",
    );
  });
  createEffect(
    () => auth.status(),
    (status) => {
      if (status !== "unlocked") return;
      flushPendingEntry((entry) =>
        window.dispatchEvent(new CustomEvent("baluard:open-entry", { detail: entry })),
      );
    },
  );
  onSettled(() => {
    (async () => {
      try {
        const isMac = navigator.userAgent.includes("Mac");
        // Detect macOS to apply titlebar adjustments
        if (isMac) {
          document.documentElement.classList.add("platform-mac");
        } else {
          // Linux and Windows have no native menu, so the tray menu was the
          // only exit path until the keyboard shortcut below. e.code keys on
          // the physical key, so it survives non-Latin keyboard layouts.
          window.addEventListener("keydown", (e) => {
            if (e.ctrlKey && e.code === "KeyQ") {
              e.preventDefault();
              invoke("exit_app").catch(() => {});
            }
          });
        }

        // Version gate FIRST: a stale daemon answers old protocol shapes and
        // every later probe would misread it as vault state.
        try {
          const v = await invoke("daemon_version");
          if (v && v.matches === false) {
            setVersionMismatch(`${v.version || "?"} / expected ${v.expected}`);
            await showWindow();
            return;
          }
        } catch {
          // Pre-handshake desktops have no command; dev/browser tests skip.
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
        // One-time hint, non-Mac only: closing the window hides to the tray
        // rather than quitting, which reads as a dead app on Linux/Windows
        // otherwise (macOS users expect the dock + Cmd+Q convention).
        try {
          const isMac = navigator.userAgent.includes("Mac");
          if (
            !isMac &&
            !localStorage.getItem("baluard.trayHint.v1")
          ) {
            localStorage.setItem("baluard.trayHint.v1", "1");
            toastInfo(t("app.trayHint"));
          }
        } catch {
          // Storage unavailable (tests, private mode): skip the hint.
        }
      }
    })();
  });

  return (
    <UpdateProvider>
      <VaultSwitcherProvider>
      <div class="app relative w-full h-full overflow-hidden">
        {/* D79: updates ride above everything; a stale daemon blocks all */}
        <Show when={versionMismatch()}>
          <VersionGate detail={versionMismatch()} />
        </Show>
        <UpdateBanner />
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
              <AgentApprovalProvider>
              <ConflictResolutionProvider>
                <AutoSyncProvider>
                  <AutoSyncIndicator />
                  <VaultView />
                  <ConflictResolutionPanel />
                  <DevTriggerSlot />
                </AutoSyncProvider>
              </ConflictResolutionProvider>
              </AgentApprovalProvider>
            </VaultProvider>
          </div>
        </Show>
      </div>
      </VaultSwitcherProvider>
    </UpdateProvider>
  );
}
