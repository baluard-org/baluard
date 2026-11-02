# ADR 0033. Per-Recipient Outboxes with Live Mirror (IS-4b, row C)

> Status: Accepted (2026-09-22)

## Context

Sharing a live, view-only mirror of selected entries with a recipient needs a transport and trust design that does not wrap any vault key. The work is slice S2-4 and was recorded as D30. It went through two external review rounds on the design and on the shipped commit.

## Decision

**Layout.** An outbox is a small standalone git repo, one per recipient (`crates/baluard-core/src/vault/outbox.rs`).

- `outbox.json` is a plaintext marker with the outbox id, owner vault id, and owner signed contact card.
- `share/keywrap.json` holds the HPKE wrap of the content key to the recipient's identity wrap pubkey, plus an Ed25519 signature binding the recipient pubkey and outbox id.
- `entries/<cipher_id>.enc` holds sealed blobs with AAD purpose `outbox-entry-v1/<outbox_id>/<cipher_id>`. Entries carry the sender card, the item, and a signature binding outbox id, entry id, timestamp, and item bytes.
- The content key is a fresh random AES-256-GCM key per outbox. No vault key ever wraps into it (Level 1 channel trust).
- The owner registry `meta/outbox-owner.enc` and the recipient links `meta/outbox-links.enc` are sealed under the new RootKey-derived `derive_outbox_key`. Both are re-encrypted in `rotate_root_key` and `revoke_device_and_rekey`.

**Live mirror.** `publish_entry` seals from the current cipher state. A SHA-256 digest over the sealed doc makes republish idempotent: unchanged content means no write and no commit. The daemon's post-CRUD `COVER_MUTATION` hook runs `outbox_resync()` best-effort between two autosync nudges. The registry file is git-tracked, and the second nudge guarantees a cycle commits it. Trashed and purged sources unpublish on the next resync. A purged cipher's `CipherNotFound` is handled and not propagated, because a purge would otherwise wedge every later resync.

**Routes.** There are nine routes: publish, unpublish, revoke, list, link, links, forget, read, and entries. All are token-gated, and the five that write the registry are in `COVER_MUTATION_ACTIONS`. Resync normally rides the hook, and review round 2 additionally exposed and pinned the `outbox.resync` route.

**Recipient side.** `outbox.link` verifies the marker card, unwraps the content key with the recipient's own identity, and stores the link with the owner's signing pubkey as seen at link time. Every open re-checks the marker id and owner pubkey against the link. A repo writer who swaps in a complete impostor set (own card, own key, keywrap re-addressed to the victim, which needs no secret for HPKE Base wraps) cannot hijack an existing link. Entry attribution must equal the marker owner's identity, so a repo writer cannot inject entries labeled as someone else. Reads are view-only and nothing is imported.

**Review round 1 (10 findings: 7 accepted, 3 of them blockers; 2 declined)**

- Registry writes ran under the runtime read guard, which allowed a lost-update race. All mutating wrappers now take the write guard and the handle methods are `&mut self`.
- `git2::Repository::discover` walks parents, so an outbox folder inside the vault would commit mirror files into the vault repo. The code uses `open` with an init fallback.
- A purged source permanently aborted `outbox_resync_all`. `CipherNotFound` now unpublishes.
- `update_all` stages deletions into the outbox git tree, so unpublish and revoke reach clones.
- Link and owner-attribution binding, as described above.
- Content keys are stripped from the IPC surface (`outbox.list`, `links`, and `link` responses).
- Recipient-keyed reuse is based on the stable signing pubkey, with wrap-rotation re-wrapping.
- Registry paths are canonicalized.

**Review round 2 (13 findings: 10 accepted, 3 declined)**

- Blocker: the unchanged-skip digest was computed over the payload including the live `updated_at` clock, so every resync rewrote, committed, and pushed every entry in every outbox. The digest is now a canonical mirror doc: outbox id, entry id, and item bytes, with no clock.
- The keywrap signature binds `sha256(ephemeral|ciphertext|tag)`, so a repo writer cannot swap the ciphertext under a still-valid signature.
- Unpublishing the last entry keeps the registry record. The on-disk marker still carries the outbox id, and dropping the record wedged republishing to that folder.
- Embedded passkey material is stripped from mirrored items (`strip_fido2`), so view-only mirrors never carry passkey keys.
- The resync loop continues past per-outbox publish failures.
- Entry listing skips unreadable files.
- `open_entry` size-bounds the file before reading it.
- `revoke_outbox` must find an owned record first, so a mistyped path can never strip an unrelated folder's `entries/`.
- Publishing refuses outbox paths at or inside the vault, in either direction, because either would commit the other's files. This hardens the git-attachment fix into an invariant.
- The `outbox.resync` route is exposed and pinned.

## Consequences

Durable rule: a digest used as a change-detection key must be computed over canonical content, never over a document containing a live clock or nonce.

Declined in round 1: a forge-seat strike on revoke (this wave grants no seats, and the future transport wiring pairs grant and strike), and Zeroizing hex key fields (the key rests inside a sealed blob and the decode path already zeroizes). Declined in round 2: re-reading the marker per entry in listing (N is trivial), git error-string detail (repo-tolerated format strings), and typed response DTOs in place of the dynamic key-strip (the existing pattern).

Only a local-folder transport exists in this wave. Origin push is best-effort, and provider seat grant and strike for outboxes belong to the P8c-facade wave. The UI share sheet belongs to the §4.8 wave. Revoke keeps old-key copies readable, which is the plan's eventual-revocation boundary, stated at share time.

## References

- `docs/adr/0085-sharing.md` §4.6 (row C) and the S2 tracking row for the wave context
