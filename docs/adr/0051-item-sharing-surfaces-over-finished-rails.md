# ADR 0051. Item-Sharing Surfaces over Finished Rails (S2 UI)

> Status: Accepted (2026-09-26)

## Context

The S2 core and daemon sharing operations existed without a user interface. Shared files have multiple cryptographic formats, and the interface should identify a format without requiring users to understand or classify it.

## Decision

The client detects a shared-file type by trying supported operations in order and using the daemon's plain-language refusals. The receive chain is package import, contact reveal, then passphrase-guest open. These formats are cryptographically domain-separated, so an input for one format cannot succeed as another. New shared-file flavors must remain mutually exclusive at the cryptographic layer; client detection does not use a magic-number header.

Clipboard secrets use the shared auto-clear utility. A multi-stage file flow resets its stage when the selected file changes.

## Consequences

Users can open supported shared files without classifying their formats. The shared auto-clear utility provides one clipboard path for audit. Contact-key reveals and package sending remain deferred until an address-book surface exists; `contacts_list` has no routes. Outbox publish and revoke UI remains unowned. The reveal view is transient and does not show a TOTP countdown.

The shared-file flavor list remains open. New flavors join the detection chain in daemon refusal order.

## References

- Original record D48.
- Address book: ADR 0052.
- Outbox surfaces: ADR 0053.

---
