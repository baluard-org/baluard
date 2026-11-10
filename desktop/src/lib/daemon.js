import { invoke } from "@tauri-apps/api/core";

// ── Daemon proxy ──
// Single entry point for all Tauri → daemon IPC.
// Mock this file to test all action logic without Tauri.
//
// Phase 6: vault-level actions take an optional `slug` so the daemon can
// route to the right vault in its map and verify the per-vault session
// token. When `slug` is omitted the daemon targets the active vault.

// Actions that mutate the vault and therefore arm auto-sync. Mirrors the
// daemon's COVER_MUTATION_ACTIONS (handler.rs). On success we dispatch a
// window event so the sync indicator can light up immediately instead of
// waiting for the next 10s status poll (which would miss the 5s dirty window).
const MUTATION_ACTIONS = new Set([
  "vault.add", "vault.update", "vault.delete", "vault.archive", "vault.unarchive",
  "cipher.clone", "vault.import", "vault.trash.restore", "vault.trash.purge",
  "folder.create", "folder.rename", "folder.delete",
  "tag.create", "tag.rename", "tag.delete", "tag.rebuild_index",
  "settings.set", "vault.avatar.set", "device.revoke",
  "passkey.finish_register", "passkey.delete", "passkey.rename", "passkey.finish_assert",
  "cipher.set_collection", "collections.create", "collections.rename", "collections.delete",
  "collections.grant", "collections.revoke", "collections.catalog_set",
  "groups.create", "groups.rename", "groups.delete", "groups.member_add", "groups.member_remove",
  "policies.set",
  "packages.import",
  "vault.rotate_recovery", "vault.attach_upload", "vault.attach_delete", "vault.change_password",
  "members.invite", "members.remove", "members.reset", "members.transfer", "members.claim",
  "members.set_email", "members.set_minor", "members.set_role", "members.leave",
  "members.leave_approve", "members.contest_cancel", "members.replace_device",
  "requests.stage", "requests.approve", "requests.deny",
  "space.set_purpose", "space.flip", "space.migrate", "locale.save",
  "templates.create", "templates.delete", "collections.sweep",
  "legacy.arm", "legacy.close",
]);

async function daemon(action, payload = "", slug = null) {
  const payloadStr = typeof payload === "string" ? payload : JSON.stringify(payload ?? "");
  const args = { action, payload: payloadStr };
  if (slug) args.slug = slug;
  const res = await invoke("daemon_request", args);
  if (!res.success) {
    // A dead session must not sit behind a stale but normal-looking UI:
    // tell the app to drop to the lock screen (listener in AuthContext).
    // The daemon has three rejection shapes: a wrong/missing token, the 4h
    // TTL expiry, and a generation bump after a lock + re-unlock cycle.
    if (/Invalid session token|Session token expired|Re-unlock required/i.test(res.error || "")) {
      window.dispatchEvent(new CustomEvent("baluard:session-expired", { detail: { slug: slug || null } }));
    }
    throw new Error(res.error);
  }
  // Notify the UI immediately that a local mutation succeeded so the sync
  // indicator can show "waiting" without waiting for the next status poll.
  if (MUTATION_ACTIONS.has(action)) {
    window.dispatchEvent(new CustomEvent("baluard:local-mutation"));
  }
  return res.payload;
}

// Instruct the Tauri backend to reveal the main window once frontend has mounted/loaded.
async function showWindow() {
  return invoke("show_window");
}

// Read app-global desktop preferences (background behavior, etc.). Handled in
// the Tauri layer, not the daemon — these are client-level, pre-unlock prefs.
async function getDesktopPrefs() {
  return invoke("get_desktop_prefs");
}

// Toggle run-in-background (keep running in the tray when the window closes).
// Persists; takes effect on the next close.
async function setRunInBackground(enabled) {
  return invoke("set_run_in_background", { enabled });
}

// Linux compatible-rendering state: drives the login recovery notice and the
// Settings toggle. Safe to call on every platform; linux=false elsewhere.
async function getRenderState() {
  return invoke("get_render_state");
}

// Set the compatible-rendering preference. `null` = automatic (GPU detection
// + crash recovery). Applies after the next app restart.
async function setCompatibleRendering(value) {
  return invoke("set_compatible_rendering", { value });
}

export { daemon, showWindow, getDesktopPrefs, setRunInBackground, getRenderState, setCompatibleRendering };
