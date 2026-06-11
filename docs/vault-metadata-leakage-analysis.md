# Vault Metadata Leakage Analysis

**Status:** Accepted design tradeoff (documented 2026-06-11)
**Audit reference:** Security Audit 2026-06, finding **M2**

## Summary

Baluard's current on-disk layout stores each encrypted cipher as a separate
file under `ciphers/<uuid>.enc`, plus a `trash/<uuid>.enc` directory for
tombstones. This layout leaks structural metadata to anyone with read access
to the git repository. The leaks are inherent to the one-file-per-cipher
design and to git's commit-graph model.

This document describes exactly what is leaked, what is not, and the
mitigations and design tradeoffs.

## What is leaked

An attacker with read access to the vault git repository can observe:

| Signal | Source | Granularity |
|---|---|---|
| Exact entry count | `ls ciphers/` | per-snapshot |
| Entry UUIDs | filenames | per-snapshot |
| Entry sizes | file sizes | per-snapshot (bucket only, not exact, due to padding tiers) |
| Padding tier (Xs/S/M/L/XL) | plaintext byte in envelope header | per-entry |
| Per-entry creation/edit timestamps | git log | per-commit |
| Per-entry update history | git log | per-commit |
| Tombstone existence and timing | `trash/` + git log | per-delete |
| Vault activity patterns | git commit frequency | aggregate |
| Folder/tag structure | `index.json` | per-snapshot |
| Device additions/revocations | `meta/devices.json` + `meta/epoch.json` | per-event |
| Emergency access config (signed) | `meta/emergency.json` | per-event |

## What is NOT leaked

| Signal | Why |
|---|---|
| Cipher plaintext (passwords, notes, URIs, card numbers, SSH keys) | AES-256-GCM with item key derived from device-bound key |
| Master password | never stored; KEK derived via Argon2id |
| TOTP secrets (in detail view) | seed stays in cipher; only derived code sent to UI |
| Per-entry update_seq changes | visible as git commits, but the value itself is in the encrypted envelope |
| Field-level diffs | D10 structured-merge only runs after decryption; git sees only ciphertext blobs |

## Mitigations in place

1. **Padded bucket sizes** (5 tiers: Xs 5KB, S 30KB, M 100KB, L 250KB, XL 2MB).
   An attacker measuring file size learns only the tier, not the exact size.
2. **Envelope header tier byte** is bound into the AAD, preventing tier
   rewriting without re-encryption.
3. **Profile-aware display in UI** (entries shown by name, not UUID) keeps
   UUIDs out of human-facing surfaces.
4. **Index rebuild on every read** keeps `index.json` accurate but does not
   hide the existence of entries from the directory listing.

## Design tradeoffs

The one-file-per-cipher layout was chosen for:

- **Efficient partial sync.** Git can fetch only the changed ciphers
  without downloading the entire vault.
- **Simple conflict resolution.** Per-file granularity maps naturally to
  git's three-way merge.
- **Trivial incremental backup.** `rsync` / `git pull` gets you the delta.
- **Cheap encryption.** No need to re-encrypt the whole vault on a single
  entry change.

A packed single-blob layout (all ciphers in one encrypted file) would
hide entry count and per-entry timing, but at the cost of:

- O(n) re-encryption on every write (or a complex Merkle-tree structure).
- O(total vault size) sync on first clone and on any conflict.
- More complex conflict resolution (no per-file three-way merge).
- Harder partial restore from backup.

## Accepted residual

For Baluard's threat model (untrusted git remote, trusted local device),
the metadata leaks are accepted. The rationale:

1. **Remote trust model already assumes passive read.** The remote sees
   ciphertext blobs; the structural metadata is no more sensitive than the
   fact that a vault exists at all.
2. **Mitigation has high cost.** Packed format would degrade sync
   performance and conflict resolution significantly.
3. **Sensitive data is still encrypted.** The plaintext contents remain
   protected by the device-bound key hierarchy.

## Future work (not committed)

If the threat model shifts to require metadata privacy:

1. **Packed blob format** with per-entry Merkle tree. Tradeoffs above.
2. **Steganographic transport** (embed ciphertext in cover traffic).
   Out of scope.
3. **Local-only mode** (never sync). Possible with current code by
   disabling git-sync, but loses the multi-device benefit.

## References

- Audit finding: `docs/security-audit-2026-06.md` M2
- Padding tiers: `crates/baluard-core/src/vault/padding.rs`
- Envelope header: `crates/baluard-core/src/vault/envelope.rs`
- Index rebuild: `crates/baluard-core/src/vault/index.rs`
- D10 (structured merge): `docs/architecture-decisions.md`
