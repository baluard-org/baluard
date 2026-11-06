// Desktop update state (D79). App-root provider: the banner renders above
// both auth screens and the vault, and Settings reads the same state.
//
// Background checks are quiet: failures resolve silently and only manual
// checks surface errors. Installs never run in the background — an
// available update waits for the user's click.

import { createContext, useContext, createSignal, onSettled } from "solid-js";
import {
  updaterStatus,
  updaterCheck,
  updaterInstall,
  listenUpdateProgress,
  noteCheckNow,
  backgroundCheckDue,
  startupDelayMs,
  CHECK_INTERVAL_MS,
} from "../lib/update.js";

// Explicit null default: without it, solid 2.0's getContext THROWS when a
// consumer mounts without a provider (UpdateSettingsRow outside the App
// tree, e.g. isolated SettingsModal tests).
const UpdateContext = createContext(null);

export function useUpdater() {
  return useContext(UpdateContext);
}

export function UpdateProvider(props) {
  const [status, setStatus] = createSignal(null);
  const [checking, setChecking] = createSignal(false);
  const [available, setAvailable] = createSignal(null);
  const [upToDate, setUpToDate] = createSignal(false);
  const [error, setError] = createSignal(null);
  const [installing, setInstalling] = createSignal(false);
  const [progress, setProgress] = createSignal(null);
  const [dismissedVersion, setDismissedVersion] = createSignal(null);

  async function check({ manual = false } = {}) {
    if (checking() || installing()) return;
    // No checks until the status probe has confirmed the updater; this also
    // keeps the jittered startup timer harmless in unconfigured builds.
    if (!status()?.configured) return;
    setChecking(true);
    if (manual) setError(null);
    try {
      const info = await updaterCheck();
      noteCheckNow();
      if (info) {
        setAvailable(info);
        setUpToDate(false);
      } else {
        setAvailable(null);
        setUpToDate(true);
        if (!manual) setDismissedVersion(null);
      }
      if (manual && !info) setError(null);
    } catch (e) {
      setAvailable(null);
      // Background failures stay quiet; only a manual check reports.
      if (manual) setError(e?.message || String(e));
    } finally {
      setChecking(false);
    }
  }

  async function install() {
    if (installing()) return;
    setInstalling(true);
    setError(null);
    // Resolve comes only from the failure paths: success replaces the
    // binary and restarts the app from the new version.
    try {
      await updaterInstall();
    } catch (e) {
      setInstalling(false);
      setProgress(null);
      setError(e?.message || String(e));
    }
  }

  function dismiss() {
    if (available()) setDismissedVersion(available().version);
  }

  function clearError() {
    setError(null);
  }

  onSettled(() => {
    let disposed = false;
    let unlisten;
    listenUpdateProgress((p) => {
      if (p && typeof p.downloaded === "number") {
        setProgress({ received: p.downloaded, total: p.total ?? 0 });
      }
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });

    const handleMenuCheck = () => {
      void check({ manual: true });
    };
    window.addEventListener("baluard:check-updates", handleMenuCheck);

    const first = setTimeout(() => {
      if (backgroundCheckDue()) check({ manual: false });
    }, startupDelayMs());
    const timer = setInterval(() => {
      if (backgroundCheckDue()) check({ manual: false });
    }, CHECK_INTERVAL_MS);

    (async () => {
      try {
        setStatus(await updaterStatus());
      } catch {
        setStatus({ configured: false, channel: "", version: "" });
      }
    })();

    return () => {
      disposed = true;
      unlisten?.();
      window.removeEventListener("baluard:check-updates", handleMenuCheck);
      clearTimeout(first);
      clearInterval(timer);
    };
  });

  const store = {
    status,
    checking,
    available,
    upToDate,
    error,
    installing,
    progress,
    dismissedVersion,
    check,
    install,
    dismiss,
    clearError,
  };
  // solid-js 2.0 rc: contexts render directly; the classic .Provider is gone.
  return <UpdateContext value={store}>{props.children}</UpdateContext>;
}
