// baluard:// deep links. The Rust layer validates the URL shape and emits
// "deep-link://entry" with {slug, id}; this module routes it to the vault UI.
// While the app is locked the target is stashed and flushed on unlock, so
// navigation can never reveal an entry before authentication.

import { listen } from "@tauri-apps/api/event";

let pending = null;
let unlisten = null;

export function pendingEntry() {
  return pending;
}

export function consumePendingEntry() {
  const entry = pending;
  pending = null;
  return entry;
}

// onEntry receives {slug, id}; isUnlocked gates stash-vs-navigate.
export async function initDeepLink(onEntry, isUnlocked) {
  if (unlisten) return;
  unlisten = await listen("deep-link://entry", (event) => {
    const entry = normalizeEntry(event?.payload);
    if (!entry) return;
    if (isUnlocked()) onEntry(entry);
    else pending = entry;
  });
}

export function disposeDeepLink() {
  unlisten?.();
  unlisten = null;
  pending = null;
}

export function flushPendingEntry(onEntry) {
  const entry = consumePendingEntry();
  if (entry) onEntry(entry);
}

export function normalizeEntry(payload) {
  if (!payload || typeof payload !== "object") return null;
  const slug = typeof payload.slug === "string" ? payload.slug.trim() : "";
  const id = typeof payload.id === "string" ? payload.id.trim().toLowerCase() : "";
  if (!slug.startsWith("baluard-") || !/^[a-z0-9-]+$/.test(slug.slice(8))) return null;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) return null;
  return { slug, id };
}
