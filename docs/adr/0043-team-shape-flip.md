# ADR 0043. Team-Shape Flip (S3-7b)

> Status: Accepted (2026-09-25)

## Context

Team-vault members who need access to one collection must not receive the vault Root Key. Before this change, member devices held the Root Key and the Space Group Key, even when their access was limited to a collection.

The change must also prevent offline key distribution through every sync and approval path. A member device can open any committed key wrap addressed to its device, regardless of the unlock path enforced by the application.

## Decision

An administrator can flip the vault to team shape. From the flip commit onward, member devices hold neither the Root Key nor the Space Group Key. Their unlock path is identity seed → `space.wrap` → SMK.

The seven member-visible metadata derivations (index, folders, tags, profile, settings, contacts, and events) use HKDF(SMK) in place of Root Key bytes. Their per-file info constants remain unchanged so administrators and members derive identical keys. Administrator-only derivations (activity, generator history, templates, outbox, and avatar) remain Root-Key-bound and return errors on member devices. A refused derivation must not return dummy key material that could be used to encrypt unreadable data.

The plaintext `meta/space-shape.json` marker, governed by the admin-row policy, is written before files are converted. It marks the point of no return. A crash before the marker has no effect. After the marker, the next administrator unlock reads any old-keyed file with the live Root Key derivation and saves it under the SMK derivation. Flip readiness treats a missing wrap public key as unusable, even if a stale wrap file exists.

Root-Key distribution is gated by the shape marker in the rotation staging filter, quorum transaction builder, transaction adoption, and join approval. No path may distribute the Root Key to a member device after the flip.

## Consequences

The flip is recoverable after interruption because administrator unlock converges files to the new derivation. A member pulling during convergence may fail to read metadata until the administrator's convergence commit lands. This is bounded to the flip window and self-heals on that commit.

Members do not read or write ciphers in this decision. Collection ciphers remain encrypted under SGK-derived item keys; member cipher access requires S3-7c to re-key them under collection keys and provide member CRUD through grant wraps. Flat and personal ciphers remain administrator-only.

## References

- Original record D40.
- S3-7c member collection access: ADR 0044.
