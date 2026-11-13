import { daemon } from "./daemon.js";

const DEFAULT_PAGE_SIZE = 200;

let _promise = null;

/**
 * Fetch the full unlocked vault in bounded IPC pages so large vaults
 * never exceed the socket frame limit.
 */
export async function fetchVaultFull(pageSize = DEFAULT_PAGE_SIZE) {
  let offset = 0;
  let merged = null;

  for (;;) {
    const raw = await daemon(
      "vault.list_full",
      JSON.stringify({ offset, limit: pageSize })
    );
    const page = JSON.parse(raw);
    if (!page) return null;

    if (!merged) {
      merged = {
        ...page,
        ciphers: Array.isArray(page.ciphers) ? [...page.ciphers] : [],
      };
    } else if (Array.isArray(page.ciphers) && page.ciphers.length > 0) {
      const seen = new Set(merged.ciphers.map((c) => c.id || c._meta?.id));
      for (const c of page.ciphers) {
        const id = c.id || c._meta?.id;
        if (!id || !seen.has(id)) {
          if (id) seen.add(id);
          merged.ciphers.push(c);
        }
      }
    }

    if (!page.has_more) break;
    const next = typeof page.next_offset === "number"
      ? page.next_offset
      : offset + pageSize;
    if (next <= offset) break;
    offset = next;
  }

  return merged;
}

/**
 * Fire paginated vault.list_full immediately after unlock responds.
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
