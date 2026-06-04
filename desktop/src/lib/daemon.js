import { invoke } from "@tauri-apps/api/core";

// ── Daemon proxy ──
// Single entry point for all Tauri → daemon IPC.
// Mock this file to test all action logic without Tauri.
async function daemon(action, payload = "") {
  const res = await invoke("daemon_request", { action, payload });
  if (!res.success) {
    throw new Error(res.error);
  }
  return res.payload;
}

export { daemon };
