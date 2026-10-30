// Desktop self-update (D79). Thin Tauri wrappers plus the pure pieces the
// tests pin: the opt-out store, the startup jitter, and the background
// schedule. The updater binary logic lives in src-tauri/src/updater.rs.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const OPT_OUT_KEY = "baluard.updateChecks";
const LAST_CHECK_KEY = "baluard.updateLastCheck";

// Privacy (D79): a check tells GitHub the user's IP and app version, so the
// cadence is a jittered startup probe plus a slow periodic one, and it is
// opt-out-able in Settings.
export const STARTUP_JITTER_MS = 10 * 60 * 1000;
export const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

export function updaterStatus() {
  return invoke("updater_status");
}

export function updaterCheck() {
  return invoke("updater_check");
}

export function updaterInstall() {
  return invoke("updater_install");
}

// Progress events ride the plugin's download callback; the caller gets an
// unlisten function it MUST clean up.
export function listenUpdateProgress(cb) {
  return listen("updater://progress", (e) => cb(e.payload));
}

export function autoChecksEnabled(store = window.localStorage) {
  return store.getItem(OPT_OUT_KEY) !== "off";
}

export function setAutoChecksEnabled(enabled, store = window.localStorage) {
  if (enabled) {
    store.removeItem(OPT_OUT_KEY);
  } else {
    store.setItem(OPT_OUT_KEY, "off");
  }
}

// Random 0..STARTUP_JITTER_MS so a fleet of users does not ping GitHub in
// the same second after launch.
export function startupDelayMs(rand = Math.random) {
  return Math.floor(rand() * STARTUP_JITTER_MS);
}

export function lastCheckAt(store = window.localStorage) {
  const raw = Number(store.getItem(LAST_CHECK_KEY));
  return Number.isFinite(raw) && raw > 0 ? raw : null;
}

export function noteCheckNow(now = Date.now(), store = window.localStorage) {
  store.setItem(LAST_CHECK_KEY, String(now));
}

// A background check is due when the last one is older than the interval
// (or never happened). Manual checks ignore this entirely.
export function backgroundCheckDue(now = Date.now(), store = window.localStorage) {
  if (!autoChecksEnabled(store)) return false;
  const last = lastCheckAt(store);
  return last === null || now - last >= CHECK_INTERVAL_MS;
}

export function formatProgress(received, total) {
  if (!total || total <= 0) return null;
  return Math.min(100, Math.floor((received / total) * 100));
}
