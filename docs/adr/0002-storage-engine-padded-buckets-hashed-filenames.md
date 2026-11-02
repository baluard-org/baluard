# ADR 0002. Storage Engine: Padded Buckets and Hashed Filenames

> Status: Accepted

## Context

Storage must reduce metadata exposure, including website names, usernames, and approximate file sizes, and prevent Git merge conflicts between entries. The vault lives in a Git repository that the remote host can read in full, so every filename, size, and plaintext header field is visible to that host.

## Decision

**One file per entry.** Each entry is a separate encrypted file named by a random UUID, never by a value derived from its content or title. Personal entries live at `ciphers/<uuid>.enc`; deleted entries move to `trash/`. Entries assigned to a shared collection live under a salted directory, `ciphers/<salted-hash-of-collection-id>/<uuid>.enc` (ADR 0085). Attachments live at `entries/<cipher_id>/attachments/<id>.enc` and are encrypted under the owning cipher's item key. One file per entry means two devices conflict only when they edit the same entry, which is the unit the conflict resolver handles (ADR 0004).

**Uniform size tiers.** The storage engine pads each plaintext payload to one of five exact sizes before AES-256-GCM encryption: Xs (5 KB) for standard logins, S (30 KB) for extended logins and TOTPs, M (100 KB) for extended secure notes, L (250 KB) for small attachments and scanned IDs, and XL (2 MB) for larger documents or media. `Tier::fit` selects the smallest tier that holds the content plus a 4-byte little-endian length prefix, which rides inside the tier. Content that does not fit the largest tier is rejected. Padding is zero fill inside the plaintext. It is not random fill, because the ciphertext is already indistinguishable and the length prefix is what lets `unpad` recover the content. A declared length larger than the available data fails closed.

**Context binding.** The AAD is a SHA-256 hash over a domain prefix (`baluard-aad-v2`) and length-prefixed fields: vault id, object type (cipher, meta, keywrap, or attachment), object id, tier, algorithm id, key epoch, and update sequence. Length prefixes prevent collisions between different field splits. The binding prevents cut-and-paste of a ciphertext between objects or vaults and rollback to an older sequence. The serialized envelope keeps a 28-byte plaintext header (version, algorithm, key epoch, nonce counter, update sequence, tier) so the reader can select a key before decryption.

**Encrypted index.** `meta/index.enc` maps human-readable metadata, including URLs and titles, to entry ids. `baluard-core` decrypts it on demand. The index is padded like every other object, is sharded (each shard binds its position and the total shard count, so a missing shard, a stale extra shard, or two swapped shard files is detected), and is encrypted under a key derived from the Root Key (`derive_index_key`; Spaces use the member-visible metadata key, ADR 0085). The index is local-only: it is gitignored and rebuilt from the entry files, so it never rides a commit and never conflicts between devices. A read failure degrades silently to a full scan and a rebuild. Entries that cannot be decrypted at rebuild time (foreign epoch or corruption) are recorded in the index as skipped so staleness checks compare like with like.

**Residual leakage.** The design hides content and sizes inside a tier. It does not hide the number of entries, the tier of each entry, the key epoch, the per-entry update sequence, or commit timing. Those remain visible to the Git host.

## Consequences

Entry sizes fall into a small set of public tiers and filenames do not reveal entry identities. This reduces metadata leakage at the cost of additional storage: a small login occupies a full 5 KB tier, and every rewrite of an entry is retained in Git history at that size. Because the index is a rebuildable local cache, losing it costs time, not data.

## References

- `crates/baluard-core/src/vault/padding.rs`
- `crates/baluard-core/src/vault/envelope.rs`
- `crates/baluard-core/src/vault/index.rs`
- `crates/baluard-core/src/crypto/aead.rs` (`build_aad`)
- `crates/baluard-core/src/types.rs` (`Tier`)
- ADR 0004 for index rebuild after sync writes
