# ADR 0053. The Outbox Is a Folder, Not a Route (S2-4 owner and recipient surfaces)

> Status: Accepted (2026-09-26)

## Context

The core exposed ten outbox routes without a user interface. The outbox's transport must let a recipient carry a folder and resynchronize its items without a streaming route.

Revocation cannot recall bytes that a recipient has already carried away. The recipient surface must not imply otherwise, and it must not offer write-back.

## Decision

Represent the outbox as a plain folder carried by the recipient. Mirror items through digest-driven resynchronization. Revocation stops future mirroring but does not recall previously carried bytes; confirmation text states this limit.

The recipient view is read-only, masks passwords, and uses the shared auto-clear clipboard utility. Export strips attachments, password history, and passkeys. Resynchronization applies globally to all mirrors rather than per outbox.

Locale tooling must verify the resolved translation lookup key, not only the existence of a key with the same suffix.

## Consequences

Folders are local paths and do not cross machines by themselves. The viewer exposes core fields for login items. Custom fields and non-login cipher types show names and notes without typed editors. Outbox management UI for publishing and revoking mirrors remains unowned.

## References

- Original record D50.
- Address book: ADR 0052.
