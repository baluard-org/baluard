import { daemon } from "./daemon.js";

// Phase 2b-4: real IPC wiring for the conflict resolution panel.
//
// The daemon's `sync.conflict` route decrypts the head pending conflict, runs
// merge_ciphers, and either auto-merges (no UI prompt) or surfaces a masked
// conflict for a user verdict. `sync.conflict.resolve` applies the verdict.
//
// Both routes are slug/token-gated on the daemon side. This module is a thin
// helper layer mirroring cloneFlow.js — maps the daemon's wire shape to the
// frontend `PendingConflict` contract (docs/adr/0093-conflict-resolution-panel.md).
//
// SECURITY: the daemon never sends secret values. `fields[].sensitive` marks
// which fields are masked server-side; the panel renders labels only.

/**
 * Fetch the head pending conflict from the daemon. Returns:
 *   - { pending: false } when nothing is awaiting a decision.
 *   - { pending: true, auto_merged: true } when merge_ciphers auto-resolved
 *     (no UI prompt; the caller just refreshes the sync badge).
 *   - { pending: true, cross_epoch: true, ... } when a side is at an
 *     unreachable epoch — only keep_local/keep_remote are safe.
 *   - { pending: true, cipher_id, name, cipher_type, fields } when a real
 *     same-field conflict needs a user verdict.
 */
export async function fetchPendingConflict() {
  const raw = await daemon("sync.conflict");
  return JSON.parse(raw);
}

/**
 * Map a daemon `sync.conflict` body to the frontend `PendingConflict` shape
 * consumed by ConflictResolutionContext. Returns null when there is nothing to
 * queue (not pending, or auto-merged with no user action needed).
 */
export function toPendingConflict(body) {
  if (!body || !body.pending || body.auto_merged) return null;
  return {
    cipherId: body.cipher_id ?? "unknown",
    name: body.name ?? "This item",
    cipherType: body.cipher_type ?? "login",
    // The daemon does not currently report a type-change; default false.
    typeChanged: false,
    fields: Array.isArray(body.fields)
      ? body.fields.map((f) => ({
          key: f.key ?? f.label ?? "field",
          label: f.label ?? f.key ?? "field",
          sensitive: !!f.sensitive,
        }))
      : [],
    // Device names are not in the sync.conflict response today; the panel
    // falls back to i18n "this device" / "the other device" when null.
    localDevice: null,
    remoteDevice: null,
    // Epochs drifted too far apart to merge: only keep_local and
    // keep_remote are safe (keep_both is refused daemon-side).
    crossEpoch: !!body.cross_epoch,
  };
}

/**
 * Apply the user's verdict to the head conflict. Returns the daemon's JSON
 * response ({ resolved, remaining, ... } or a cross_epoch error body).
 * Throws on IPC failure (the panel surfaces a toast via decide()'s try/catch).
 *
 * verdict: "keep_local" | "keep_remote" | "keep_both"
 */
export async function resolveConflict(verdict) {
  const payload = JSON.stringify({ verdict });
  const raw = await daemon("sync.conflict.resolve", payload);
  return JSON.parse(raw);
}
