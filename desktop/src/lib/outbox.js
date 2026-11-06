export function recipientOutboxPath(basePath, contact) {
  const base = basePath.trim().replace(/\\/g, "/").replace(/\/+$/, "");
  const name = (contact.display_name || "recipient")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "recipient";
  const identity = contact.identity_signing_pubkey.slice(0, 12);
  return `${base}/${name}-${identity}`;
}
