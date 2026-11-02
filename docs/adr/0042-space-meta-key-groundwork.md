# ADR 0042. Space Meta Key Groundwork (S3-7a)

> Status: Accepted (2026-09-24)

## Context

The Team-shape promise is that a Viewer or single-collection Editor never receives the Root Key. Today every member's device keywrap carries it, so grants are cosmetic at the crypto layer. Closing that gap needs one missing primitive: a member-readable meta key that is not the Root Key. This slice ships it additively. The work is slice S3-7a and was recorded as D39.

## Decision

**Space Meta Key (SMK).** A random 32-byte key with two distribution paths: a sealed admin store (`meta/space.enc`, Root-Key HKDF) and per-member identity wraps (`meta/members/<m>/space.wrap`, HPKE context-bound to the member like the collection wraps). Nothing derives from the SMK yet. No unlock path changes, and an untouched vault behaves identically until an admin runs `space.prepare`. The S3-7b flip, in the next wave, re-homes the member-visible meta derivations to the SMK, stops putting the Root Key in non-admin keywraps, and gates the flip on `space.status` readiness (every live member wrapped, none missing a wrap pubkey).

**Convergence over wedging.** `prepare` is idempotent on a healthy store and re-mints on a missing or damaged one. A crash between a rotation commit and its store re-seal orphans the store, and re-running prepare heals it with a fresh SMK and a full re-wrap in one pass. For the same reason, rotation treats a pre-swap store-open failure as "no SMK rides this rotation" and skips the re-seal instead of propagating, so a hostile or torn meta file never blocks the offboarding rotation. The review challenged this as a P4 violation. The asymmetry resolves it: post-swap re-seal failures propagate, because a healthy store must not be silently dropped mid-rotation, while pre-swap open failures skip, because the store is already dead or absent and prepare converges either way.

**Pre-existing blocker fixed.** `rotate_identity`'s refusal (identity lost from memory while wraps exist) fired after the sealed seed, escrow, and member-unlock material had already been overwritten with the new identity. The refusal meant to protect the wraps still destroyed the only copy of the old identity they were wrapped to. The self-heal and the refusal now run before any identity byte is written, which is what the P1 review comment always claimed.

**Other hardening.** Malformed wrap pubkeys no longer abort `prepare`. Invalid keys count as missing, so one hostile member row cannot block readiness. Member removal rotates the SMK, so a removed member's knowledge of the old key retires with them. This is best-effort in this slice and authoritative in 7b.

## Consequences

Because nothing derives from the SMK yet, grants remain cosmetic at the crypto layer until the 7b flip.

Slice 7b owns the flip itself: meta derivation re-homing, keywrap shape changes, shape-aware rotation staging, and the flip ceremony. Sync-engine validation of `identity_wrap_pubkey` lands when the field becomes load-bearing at verification. The desktop surface for prepare and status rides the §4.8 wave.
