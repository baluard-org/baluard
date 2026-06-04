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
 * Build the CipherKind tagged union object from form state.
 * { type: "login", data: { ... } }
 */
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
    notes: c.notes || null,
    folder_id: c.folder_id || null,
    custom_fields: c.custom_fields || [],
  };
}

/**
 * Build the full vault.update payload.
 */
export function buildUpdatePayload(id, c) {
  return {
    id,
    name: c.name,
    kind: buildKind(c),
    favorite: c.favorite || false,
    notes: c.notes || null,
    folder_id: c.folder_id || null,
    custom_fields: c.custom_fields || [],
  };
}

/**
 * Build vault.get payload.
 */
export function buildGetPayload(id) {
  return { id, decrypt: true };
}

/**
 * Build settings.set payload.
 */
export function buildSettingsPayload(key, value) {
  return { [key]: value };
}

/**
 * Build vault.create payload.
 */
export function buildCreatePayload(password, profile = "desktop_std") {
  return { password, profile };
}

/**
 * Build vault.import payload.
 */
export function buildImportPayload(format, data) {
  return { format, data };
}

/**
 * Build vault.export payload.
 */
export function buildExportPayload(format) {
  return { format };
}

/**
 * Build vault.attach_download payload.
 */
export function buildAttachDownloadPayload(cipherId, attachmentId) {
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

/**
 * Build vault.biometric_enable payload.
 */
export function buildBiometricEnablePayload(password) {
  return { password };
}
