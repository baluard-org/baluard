# ADR 0038. Per-Member Identity Wraps (P1 Space Parts groundwork)

> Status: Accepted (2026-09-23)

## Context

In the Team shape, non-admins hold only their collection wraps and never the Space key K (ADR 0085). Reaching that shape needs per-member wraps of each collection key. The work is groundwork inside slice S3 and was recorded as D35. An external review round accepted 8 findings and partially accepted 1.

## Decision

**Member wrap key.** `MemberFile.identity_wrap_pubkey` (hex X25519, serde default) is recorded at approval from the intro card's v2 signed payload. The card signature is verified and the wrap key hex and length are validated, because a malformed key would brick every later re-key. The owner's genesis row carries their wrap pubkey.

**Per-member CK wraps.** Collections mint per-member CK wraps at `meta/collections/<c>/<m>.wrap`. The collection key is HPKE-wrapped to the member's wrap pubkey with the context binding `collection-grant-v1/<collection_id>/<member_id>`, so a wrap transplanted to another collection or member name fails the AEAD tag (the outbox-entry AAD discipline).

**Lifecycle.** Wraps are minted at grant, removed at revoke, and killed with the collection. Every rotation path re-wraps them under the new CK: Root Key rotation, removal rekey, and the S3-3 expiry sweep. They self-heal across identity rotation by the member's own client. The client unwraps all with the old secret first and then writes, in two phases, and this runs before any identity byte is written, so an abort leaves zero state change.

**Wrap survival is grant-gated.** `rewrap_grant_wraps` re-writes a wrap only when the member id is in the collection's live grant list (not expired), the member row is live (no removed or reset tombstone), and the row carries a wrap pubkey. Anything else loses its wrap file. Without this, a revoked-before-rotation member whose tombstone kept a wrap identity would receive the new collection key from the very rotation meant to lock them out. Both tombstone writers (reset and remove) now also clear `identity_wrap_pubkey`.

**Mint gate.** `upsert_grant` refuses a past-dated `expires_at`, because a grant expires by time passing and not by being minted expired. It keeps save-before-wrap ordering, so a failed wrap write fails toward no access and never toward a key without a grant.

**Accepted review findings.** Blockers: the tombstoned-member wrap surviving rotation, and the disk-driven rewrap ignoring the grants list. Majors: the static HPKE context (cross-collection transplant), the identity-rotation partial-failure window (reordered and made two-phase), and the malformed-wrap-pubkey rotation brick. Minors: the owner genesis wrap pubkey, the no-old-identity rotation refusal, expired-at-mint refusal, and removal errors being inspected (NotFound tolerated).

## Consequences

Wraps are additive groundwork. Every member still holds SGK, so consumption through per-member wraps lands with the later Team-shape flip, where non-admins stop receiving SGK and the wraps become their only path to granted collections. This slice builds and maintains the wrap set so that the flip is an unlock-path change only.

Expired-but-unrotated grants keep their wraps until a rotation path runs, which is the unchanged eventual-revocation boundary. No background timer maintains wraps. The Team-shape SGK flip is the next P1 slice.

Partially accepted: save and wrap ordering in `upsert_grant`. The suggested wrap-first order was rejected, because a failed save would then leave a working wrap for an ungranted state.

## References

- `docs/adr/0085-sharing.md`, Team-shape key separation
