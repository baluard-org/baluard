// Phase 6: vault switcher state.
//
// Holds the list of registered vaults (with in-daemon state), the active
// slug, and the actions the switcher UI calls. Polls `vaults.list` on mount
// and on a 30s heartbeat so the UI reflects auto-locks / closes. The
// daemon is the source of truth; this context is a thin cache.
//
// Per the keep-unlocked model:
//   - clicking an UNLOCKED vault = instant switch (no re-prompt)
//   - clicking a LOCKED vault = caller runs `vault.unlock` for that slug
//     (AuthContext re-uses the existing unlock screen)
//   - clicking a CLOSED vault = same as locked (unlock opens + inserts)

import { createSignal, createContext, useContext, onSettled } from "solid-js";
import { daemon } from "../lib/daemon.js";

const VaultSwitcherContext = createContext(null);

function VaultSwitcherProvider(props) {
  const [vaults, setVaults] = createSignal([]);
  const [activeSlug, setActiveSlug] = createSignal(null);
  // G24 §4.7 v2: a pending browser unlock request, resolved to a vault row
  // for the banner. Null = no pending ask.
  const [unlockRequest, setUnlockRequest] = createSignal(null);

  async function refresh() {
    try {
      const data = JSON.parse(await daemon("vaults.list"));
      const rows = Array.isArray(data.vaults) ? data.vaults : [];
      setVaults(rows);
      const active = rows.find((r) => r.active);
      setActiveSlug(active ? active.slug : null);
      try {
        const req = JSON.parse((await daemon("bridge.unlock_request")) || "{}");
        const row = req.slug ? rows.find((r) => r.slug === req.slug) : null;
        setUnlockRequest(row ? { slug: row.slug, display_name: row.display_name } : null);
      } catch {
        setUnlockRequest(null);
      }
    } catch {
      // Daemon unreachable / no vaults — leave the list as-is.
    }
  }

  // Consume the pending request when the desktop acts on it or dismisses
  // it. Returns the row (or null).
  async function takeUnlockRequest() {
    const cur = unlockRequest();
    try {
      await daemon("bridge.unlock_request_take");
    } catch {
      // Already gone (TTL) — still clear locally.
    }
    setUnlockRequest(null);
    return cur;
  }

  // 30s heartbeat: catches auto-locks and closes that happen while the
  // app is open. The token-rejection path in lib.rs is the correctness
  // backstop; this heartbeat is the primary refresh.
  //
  // Also refresh on window focus regain: the Tauri backend fires lock_all
  // on window blur (Phase 6 / T15), so when the user comes back the vault
  // states will have changed. Refreshing here picks up the locked states.
  let heartbeat;
  function onFocusRegain() { refresh(); }
  onSettled(() => {
    refresh();
    heartbeat = setInterval(refresh, 30_000);
    window.addEventListener("focus", onFocusRegain);
    document.addEventListener("visibilitychange", onFocusRegain);
    return () => {
      clearInterval(heartbeat);
      window.removeEventListener("focus", onFocusRegain);
      document.removeEventListener("visibilitychange", onFocusRegain);
    };
  });

  // Switch the live focus to a slug. Returns the outcome so the caller
  // can branch on `presence`:
  //   "unlocked" -> re-fetch vault.list_full, update signals
  //   "locked"/"closed" -> caller runs unlock for this slug
  async function switchTo(slug) {
    const payload = JSON.stringify({ slug });
    const result = JSON.parse(await daemon("vaults.switch", payload));
    await refresh();
    return result; // { active, presence }
  }

  // Close a vault (remove from daemon map). Keys zeroize once in-flight
  // requests drain.
  async function close(slug) {
    await daemon("vaults.close", JSON.stringify({ slug }));
    await refresh();
  }

  // Detach a vault: drop the registry entry so it stops appearing in the
  // app. Works pre-unlock (the vault does not need to be open in the
  // daemon). The safe, reversible arm only — the vault directory is left
  // untouched on disk and can be re-attached later via Open Vault.
  //
  // The destructive arm (delete-from-disk) is intentionally not exposed
  // here; it lives in the CLI (`baluard vaults detach --delete-from-disk`)
  // as a power-user escape hatch. See DetachVaultModal.jsx for the
  // rationale.
  //
  // `refresh()` lives in `finally` so the dropdown re-syncs even if the
  // daemon reports an error.
  async function detach(slug) {
    const payload = JSON.stringify({ slug });
    try {
      await daemon("vaults.detach", payload);
    } finally {
      await refresh();
    }
  }

  const store = {
    vaults,
    activeSlug,
    refresh,
    switchTo,
    close,
    detach,
    unlockRequest,
    takeUnlockRequest,
  };

  return (
    <VaultSwitcherContext value={store}>
      {props.children}
    </VaultSwitcherContext>
  );
}

function useVaultSwitcher() {
  const ctx = useContext(VaultSwitcherContext);
  if (!ctx) throw new Error("useVaultSwitcher must be used within VaultSwitcherProvider");
  return ctx;
}

export { VaultSwitcherContext, VaultSwitcherProvider, useVaultSwitcher };
