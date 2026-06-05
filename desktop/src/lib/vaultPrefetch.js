import { daemon } from "./daemon.js";

let _promise = null;

/**
 * Fire vault.list_full immediately after unlock responds.
 * By the time VaultView.onMount fires (~5-15ms later), the
 * response is usually already in-flight or resolved.
 */
export function startVaultPrefetch() {
  _promise = daemon("vault.list_full")
    .then(s => JSON.parse(s))
    .catch(() => null);
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
