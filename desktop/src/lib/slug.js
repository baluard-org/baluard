/**
 * Vault slug generation and validation.
 *
 * Mirrors crates/baluard-core/src/vault/slug.rs so the desktop can show a
 * live slug preview that matches what the daemon would accept. Keep these in
 * sync with the Rust implementation.
 *
 * Rules:
 * - Lowercase a-z0-9 and hyphens only
 * - Must start and end with alphanumeric
 * - 4-63 characters
 * - "baluard-" prefix suggested but not enforced
 */

/**
 * Normalize a user-provided name into a suggested slug.
 * Lowercases, collapses non-alphanumerics to single hyphens, strips
 * leading/trailing hyphens, prepends "baluard-" if needed, enforces length.
 */
export function suggestSlug(name) {
  const lowered = (name || "").toLowerCase();

  const chars = [];
  let prevHyphen = false;
  for (const ch of lowered) {
    if (/[a-z0-9]/.test(ch)) {
      chars.push(ch);
      prevHyphen = false;
    } else if (!prevHyphen) {
      chars.push("-");
      prevHyphen = true;
    }
  }

  // Strip leading/trailing hyphens
  while (chars[0] === "-") chars.shift();
  while (chars[chars.length - 1] === "-") chars.pop();

  let base = chars.join("");
  if (!base) return "baluard-vault";

  const withPrefix = base.startsWith("baluard-") ? base : `baluard-${base}`;
  return enforceLength(withPrefix);
}

/**
 * Validate a slug. Returns null if valid, or an error message string.
 */
export function validateSlug(slug) {
  if (!slug) return "Slug cannot be empty";
  if (slug.length < 4) return `Slug is ${slug.length} chars, minimum is 4`;
  if (slug.length > 63) return `Slug is ${slug.length} chars, maximum is 63`;
  if (slug.startsWith("-") || slug.endsWith("-"))
    return "Slug cannot start or end with a hyphen";
  if (!/^[a-z0-9-]+$/.test(slug))
    return "Slug can only contain lowercase letters, digits, and hyphens";
  if (slug.includes("--")) return "Slug cannot contain consecutive hyphens";
  return null;
}

/**
 * Minimal cleanup for a user-edited slug: lowercase, replace invalid chars
 * with hyphens, collapse consecutive hyphens, strip leading/trailing.
 * Returns the cleaned slug.
 */
export function cleanSlug(input) {
  const lowered = (input || "").toLowerCase();

  const chars = [];
  let prevHyphen = false;
  for (const ch of lowered) {
    if (/[a-z0-9]/.test(ch)) {
      chars.push(ch);
      prevHyphen = false;
    } else if (!prevHyphen) {
      chars.push("-");
      prevHyphen = true;
    }
  }
  while (chars[0] === "-") chars.shift();
  while (chars[chars.length - 1] === "-") chars.pop();
  return chars.join("");
}

function enforceLength(slug) {
  if (slug.length <= 63) return slug;
  const truncated = slug.slice(0, 63).replace(/-+$/, "");
  return truncated.length < 4 ? "baluard-vault" : truncated;
}
