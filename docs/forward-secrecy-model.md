# Forward Secrecy and Post-Compromise Model

**Status:** Accepted design constraint (documented 2026-06-11)
**Audit reference:** Security Audit 2026-06, finding **L8**

## Summary

Baluard's git-native storage means that historical ciphertext blobs persist
in the repository's history forever. A device that held the Root Key at any
point can decrypt every `.enc` blob that was written during that epoch,
even after the device is revoked. This is inherent to the design and is
not a bug, it is a tradeoff between forward secrecy (which git cannot
provide) and the other properties Baluard guarantees (multi-device sync,
no central server, user control).

## What revocation does guarantee

- **New writes after revocation** are encrypted with the new Root Key.
  The revoked device cannot decrypt them.
- **The revoked device cannot write new entries**: its signing key is
  removed from the device registry, and other devices reject its commits.
- **The revoked device cannot trigger further key rotations**: quorum
  (single-admin) authorization requires the remaining device(s).

## What revocation does NOT guarantee

- **Old-epoch ciphertexts in git history remain decryptable** by a
  compromised device that held the old Root Key. The attacker can:
  - Pull the full git history from the remote.
  - Use the old Root Key to derive the SGK and item keys for past epochs.
  - Decrypt every `.enc` blob written before revocation.
- **The recovery phrase** (if it was compromised before revocation) can
  still unwrap the old Root Key from `meta/recovery.json` history.
- **The emergency access config** (if it was approved before revocation)
  can still unwrap the old Root Key from `meta/emergency.json` history.

## What to do after a device compromise

1. **Immediately rotate the Root Key** (`vault.rotate_root_key` or
   `vault.revoke_device`). This protects all FUTURE writes.
2. **Re-issue credentials** that were accessible to the compromised
   device. The old device can still decrypt them from git history.
3. **If the master password was also compromised**: change it
   (`vault.change_password`). Note: this is cosmetic against a device-key
   holder; the device's X25519 key independently controls Root Key
   access. The real defense is the device revocation above.
4. **Audit git history** for any ciphertext the attacker may have exfiltrated
   from the remote between initial compromise and revocation.

## Why git-native storage makes this inherent

Git's content-addressable storage means every committed blob is permanent.
`git gc` and `git filter-branch` can remove blobs, but:

- Forks, clones, and remotes retain the original history.
- A compromised device that pulled the history retains it forever.
- Even after a filter-branch cleanup, any party who pulled the history
  before cleanup has an unaltered copy.

Baluard cannot retroactively re-encrypt history without breaking the
multi-device sync model (which depends on every device seeing the same
history). A user who needs retroactive secrecy would have to:

1. Create a new vault.
2. Manually re-issue every credential.
3. Re-share the new vault with all devices.

This is the same situation as any git-based secret store (git-crypt,
blackbox, etc.) and is consistent with the threat model stated in the
audit: the git remote is untrusted for **forward** secrecy, and the
local device is trusted for **current** secrecy.

## Threat model recap

| Threat | Defense | Residual risk |
|---|---|---|
| Compromised device (live) | Rate limit + biometric + token gating | Argon2id cost |
| Compromised device (post-revocation, new writes) | Root Key rotation | None |
| Compromised device (post-revocation, old writes) | None (inherent) | Full history readable |
| Compromised git remote | Encryption at rest | Metadata only (see M2) |
| Compromised recovery phrase | Re-wrap on rotation | Old history readable |
| Compromised emergency grant | Owner-signed approval | Old history readable |
| Malicious same-UID process | Session token + peer cred | Token must be obtained first |
| Brute-force master password | Argon2id + rate limit | Argon2id cost |

## References

- Audit finding: `docs/security-audit-2026-06.md` L8
- Root Key rotation: `crates/baluard-core/src/keys/rotation.rs`
- Recovery re-wrap: `crates/baluard-core/src/vault/handle.rs::rewrap_recovery_key`
- Emergency access: `crates/baluard-core/src/emergency.rs`
- Change password: `crates/baluard-core/src/vault/handle.rs::change_master_password`
- M2 metadata leakage: `docs/vault-metadata-leakage-analysis.md`
