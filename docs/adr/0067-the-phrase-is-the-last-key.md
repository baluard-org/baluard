# ADR 0067. The Phrase Is the Last Key

> Status: Accepted (2026-09-29)

## Context

A Space must remain recoverable if every admin device is lost. In that case no admin quorum can approve recovery. The personal-vault phrase recovery resets its device registry, but a Space roster is required for peers to verify signatures.

## Decision

Escrow the Space Root Key under an offline BIP-39 phrase in plaintext, git-tracked `meta/recovery-kit.json` on the `meta/**` Admin row. Possession of the phrase is approval. The kit has no status machinery, request flow, or expiry, and bypasses quorum. An admin disables it by removing the file.

Space recovery binds a new device into the live Owner member row's subtree and never resets the roster. Rotation updates the kit in both rotation paths: an absent kit is a no-op, while a damaged kit fails rotation rather than leaving an unusable phrase. The recovery ceremony is specified in `docs/security/emergency-org-identity.md`.

## Consequences

Anyone holding the phrase holds the Space while the file exists. Losing the phrase and every admin device loses the Space. A hostile admin who rewrites the kit gains no additional power because the kit is useful only when no admin device survives. The file format is validated when loaded, and vault-ID mismatch is reported as a file mismatch before parsing the phrase.

## References

- `docs/security/emergency-org-identity.md`
- S1b per-device activity log
- P4 rotation semantics
