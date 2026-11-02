# ADR 0044. Member Collection Access (S3-7c)

> Status: Accepted (2026-09-25)

## Context

The team-shape flip restricts which keys a member holds. Collection ciphers therefore need collection-scoped keys, and every operation that moves, deletes, restores, rotates, or synchronizes those ciphers must respect the same key domain.

## Decision

Collection ciphers use item keys derived from the collection's random content key (CK) with the existing `baluard-item-v1` HKDF info. The derivation discipline remains the same as the SGK path; only the input key material differs.

A path-domain resolver is the single source of truth for cipher key selection: collection paths use CK, flat paths use SGK, and trash paths preserve their source domain. Administrators unwrap CK from the collection file; members open their per-member grant wrap. Trash retains the origin subdirectory so restore is a byte-identical move within the same domain. Assigning a cipher to a collection re-encrypts it because the path defines its key domain.

Root rotation re-keys collection ciphers as `ck@new_epoch`. The CK value does not change, so member grant wraps remain valid across rotation. The rotation inventory includes collection ciphers as well as flat paths.

Sync treats known collection directories as structurally open to Owner/Admin writes. It checks `trash/<dir>/**` against the source collection's scope. Personal flat paths are Admin-only after the shape marker enters the commit tree; before the flip, members may still hold SGK and author flat content. The integrity check retains an unconditional sequence floor: the checkpoint sequence is the envelope `update_seq`, which rises on each edit, including cross-device handoffs.

## Consequences

Collection membership determines the encryption domain, and moving a cipher across domains requires re-encryption. Attachments follow the item key automatically. Flat and personal ciphers remain administrator-only, while member-facing collection UI is handled by the §4.8 work.

S4 groups and dual control are outside this decision.

## References

- Original record D41.
- Team-shape flip: ADR 0043.
