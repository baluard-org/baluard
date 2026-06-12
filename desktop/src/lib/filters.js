/**
 * Pure filter functions for the cipher list.
 * All functions are stateless, testable, and composable.
 */

/** Maps UI category names to daemon cipher type strings. */
export const CATEGORY_TYPE_MAP = {
  "Login": "login",
  "Card": "card",
  "Identity": "identity",
  "Secure note": "secureNote",
  "SSH key": "sshKey",
  "Bank account": "bankAccount",
  "Driver license": "driversLicense",
  "Passport & ID": "passport",
};

/** Special categories that don't map 1:1 to a type */
const SPECIAL_CATEGORIES = new Set(["All items", "Favorites", "Passkeys", "Trash", "Archive"]);

/**
 * Select source list based on category.
 */
export function selectSource(category, ciphers, trashCiphers, archivedCiphers) {
  if (category === "Trash") return trashCiphers || [];
  if (category === "Archive") return archivedCiphers || [];
  return ciphers || [];
}

/**
 * Filter ciphers by category.
 * "All items" and "Trash"/"Archive" pass through (source selection handles them).
 */
export function filterByCategory(ciphers, category) {
  if (!category || category === "All items" || category === "Trash" || category === "Archive") {
    return ciphers;
  }
  if (category === "Favorites") {
    return ciphers.filter(c => c.favorite || c._meta?.favorite);
  }
  if (category === "Passkeys") {
    return ciphers.filter(c => {
      const fido2 = c.fido2_credentials || c.kind?.data?.fido2_credentials;
      return Array.isArray(fido2) && fido2.length > 0;
    });
  }
  const typeStr = CATEGORY_TYPE_MAP[category];
  if (typeStr) {
    return ciphers.filter(c => (c.type || c._meta?.type) === typeStr);
  }
  return ciphers;
}

/**
 * Filter ciphers by folder, including all descendant folders (BFS).
 */
export function filterByFolder(ciphers, folders, folderId) {
  if (!folderId) return ciphers;
  const allFolders = folders || [];
  const descendantIds = new Set();
  const queue = [folderId];
  while (queue.length > 0) {
    const current = queue.shift();
    descendantIds.add(current);
    allFolders.forEach(f => {
      if (f.parent_id === current) queue.push(f.id);
    });
  }
  return ciphers.filter(c => descendantIds.has(c.folder_id || c._meta?.folder_id));
}

/**
 * Filter ciphers by tag (case-insensitive match).
 */
export function filterByTag(ciphers, tag) {
  if (!tag) return ciphers;
  const lower = tag.toLowerCase();
  return ciphers.filter(c =>
    (c.tags || []).some(t => t.toLowerCase() === lower)
  );
}

/**
 * Search ciphers by text query. Matches name, username, URIs, and notes.
 */
export function searchCiphers(ciphers, query) {
  if (!query) return ciphers;
  const q = query.toLowerCase();
  return ciphers.filter(c =>
    c.name?.toLowerCase().includes(q) ||
    c.username?.toLowerCase().includes(q) ||
    (c.uris && c.uris.some(u => (typeof u === "string" ? u : u.uri || "").toLowerCase().includes(q))) ||
    c.notes?.toLowerCase().includes(q)
  );
}
