import { daemon } from "./daemon.js";

// Envelope chunks ride the same IPC frame budget the old offset pages used.
const BATCH_SIZE = 200;

let _promise = null;

/**
 * Snapshot walk: vault.list_ids returns the sorted cipher id list plus the
 * meta lists in one atomic call, then explicit id chunks fetch the cipher
 * envelopes. The old offset pagination re-read the live list on every page,
 * so the unlock-time sync pull could reorder entries between calls and the
 * windows would silently skip entries until restart.
 */
export async function fetchVaultFull() {
  const base = JSON.parse(await daemon("vault.list_ids"));
  if (!Array.isArray(base.ids)) throw new Error("vault.list_ids returned no id list");
  const ids = base.ids;
  const ciphers = [];
  for (let i = 0; i < ids.length; i += BATCH_SIZE) {
    const want = ids.slice(i, i + BATCH_SIZE);
    const raw = await daemon("vault.list_full_batch", JSON.stringify({ ids: want }));
    const page = JSON.parse(raw);
    if (!page || !Array.isArray(page.ciphers)) throw new Error("vault.list_full_batch returned no ciphers");
    if (page.ciphers.length + (page.missing ?? 0) !== want.length)
      throw new Error("vault.list_full_batch did not reconcile the requested ids");
    ciphers.push(...page.ciphers);
  }
  const { ids: _snapshot, ...rest } = base;
  return { ...rest, ciphers };
}

/**
 * Fire the snapshot walk immediately after unlock responds.
 * By the time VaultView.onMount fires (~5-15ms later), the
 * response is usually already in-flight or resolved.
 */
export function startVaultPrefetch() {
  _promise = fetchVaultFull().catch(() => null);
}

/**
 * Consume and clear the prefetched promise.
 * Returns null if no prefetch was started.
 */
export function consumeVaultPrefetch() {
  const p = _promise;
  _promise = null;
  return p;
}
