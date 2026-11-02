# ADR 0060. The Avatar Follows Its Profile (member-visible metadata and write-gate sweep)

> Status: Accepted (2026-09-27)

## Context

After the team-shape flip, member devices could not read `meta/avatar.enc` because it used an epoch-bound SGK derivation. The avatar must use the same member-visible metadata key material as the profile it decorates.

Member-reachable operations that write git-tracked metadata can create commits that peers refuse, preventing the Space from syncing. The issue applies to metadata mutations generally, not only the avatar.

## Decision

Derive the avatar key from the member-visible metadata IKM. Reads try the metadata key and then the legacy SGK derivation. Rewrites re-key the avatar. The flip convergence pass re-encrypts it when present (`files_reencrypted` is 6 when an avatar exists). Pre-flip rotation migrates it; post-flip rotation skips it because SMK is rotation-invariant.

Require managing-device authority for writes to settings, avatar, locale, contacts, and generator history. Apply the locale restriction in every state, including pre-unlock writes. Refuse with one plain-language message. The flip crash-recovery pass reads the avatar in the same dropped-SMK window as other metadata because interrupted-flip bytes use the Root-Key domain.

## Consequences

Members can read the avatar after the flip once convergence completes. Member language and theme preferences remain a future local-store item; current synchronized administrator preferences apply, and member changes are refused. A member can read legacy plaintext avatar bytes but does not migrate them; an administrator migrates on the next read. Pre-wave encrypted avatars in vaults that are never rotated or re-saved remain administrator-readable only.

## References

- Original record D57.
- Team-shape flip and convergence: ADR 0043.
