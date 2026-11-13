import { getSchema } from "./cipherSchema.js";

// ── Payload builders for daemon IPC ──
//
// Rule: NEVER send null for fields the Rust backend expects as enum/struct.
// Send undefined (omitted from JSON) instead. Rust serde(default) handles missing keys.
// null ≠ missing and causes "expected value" errors.

/**
 * Build URIs array for login kind. Omit match_strategy when absent
 * so Rust serde(default) kicks in (UriMatchStrategy::Domain).
 */
export function buildUris(uris) {
  if (!uris || uris.length === 0) return [];
  return uris.map(u => {
    const obj = { uri: u.uri || u };
    if (u.match_strategy) obj.match_strategy = u.match_strategy;
    return obj;
  });
}

/**
 * Build the structured kind object from a flat cipher buffer.
 * Uses cipherSchema.toKind for each type.
 */
export function buildKind(c) {
  const cipherType = c.cipherType || "login";
  const schema = getSchema(cipherType);
  const kind = schema.toKind(c);
  // Ensure login URIs use the buildUris helper for proper format
  if (cipherType === "login" && kind.data.uris?.length) {
    kind.data.uris = buildUris(kind.data.uris);
  }
  return kind;
}

/**
 * Build the full vault.add payload.
 */
export function buildAddPayload(c) {
  return {
    name: c.name,
    kind: buildKind(c),
    favorite: c.favorite || false,
    reprompt: c.reprompt || false,
    notes: c.notes || null,
    folder_id: c.folder_id || null,
    collection_id: c.collection_id || null,
    custom_fields: c.custom_fields || [],
    tags: c.tags || [],
  };
}

/**
 * Build the full vault.update payload.
 */
export function buildUpdatePayload(id, c) {
  return { id, ...buildAddPayload(c) };
}

/**
 * Build vault.get payload.
 */
export function buildGetPayload(id) {
  return { id, decrypt: true };
}


/**
 * Build vault.create payload.
 * @param {string} password
 * @param {object} [options]
 * @param {string} [options.profile="desktop_std"]
 * @param {string} [options.slug] - filesystem-safe vault identifier
 * @param {string} [options.name] - user-facing vault display name
 */
export function buildCreatePayload(password, { profile = "desktop_std", slug, name, family } = {}) {
  const payload = { password, profile };
  if (slug) payload.slug = slug;
  if (name) payload.name = name;
  if (family) payload.family = true;
  return payload;
}

/**
 * Build vault.import payload.
 */
export function buildImportPayload(format, data) {
  return { format, data };
}

/**
 * Build vault.attach_download payload.
 */
export function buildAttachDownloadPayload(cipherId, attachmentId) {
  return { cipher_id: cipherId, attachment_id: attachmentId };
}

/**
 * Build vault.attach_upload payload.
 */
export function buildAttachUploadPayload(cipherId, filename, dataBase64) {
  return { cipher_id: cipherId, filename, data_base64: dataBase64 };
}

/**
 * Build vault.attach_delete payload.
 */
export function buildAttachDeletePayload(cipherId, attachmentId) {
  return { cipher_id: cipherId, attachment_id: attachmentId };
}

/**
 * Build folder.create payload.
 */
export function buildFolderCreatePayload(name, parentId) {
  const p = { name };
  if (parentId) p.parent_id = parentId;
  return p;
}

