import { invoke } from "@tauri-apps/api/core";

// ── Daemon proxy ──
// Single entry point for all Tauri → daemon IPC.
// Mock this file to test all action logic without Tauri.
//
// Phase 6: vault-level actions take an optional `slug` so the daemon can
// route to the right vault in its map and verify the per-vault session
// token. When `slug` is omitted the daemon targets the active vault.
async function daemon(action, payload = "", slug = null) {
  const args = { action, payload };
  if (slug) args.slug = slug;
  const res = await invoke("daemon_request", args);
  if (!res.success) {
    throw new Error(res.error);
  }
  return res.payload;
}

// Phase 6 / T15: lock every currently-unlocked vault. Used by the
// window-blur hook (handled in the Tauri backend) and available to the
// frontend for a manual "lock all" action. Returns true on success.
async function lockAllVaults() {
  return invoke("lock_all_vaults");
}

export { daemon, lockAllVaults };
