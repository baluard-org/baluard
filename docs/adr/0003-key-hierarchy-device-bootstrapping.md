# ADR 0003. Key Hierarchy and Device Bootstrapping

> Status: Accepted

## Context

Vault access must support encrypted storage, device identity, new-device setup through Git providers, and secure storage of credentials used for background synchronization. The original record described a device key escrowed in the repository and a Space Group Key wrapped in `meta/access_list.json`. The implementation moved on from both, and this record states the model as built.

## Decision

**Hierarchy.** The master password derives a 256-bit KEK with Argon2id. Argon2id is the only password-stretching step: HKDF is applied only to the already-stretched KEK, to derive purpose-scoped subkeys (session key, sync-only key, device-key seal key). The device private key opens a per-device HPKE wrap of the Root Key, a 512-bit random key generated per epoch. Item keys derive from the Root Key through the Space Group Key:

```
Master Password
    |  Argon2id
    v
KEK  --HKDF--> session key, sync-only key, device-key seal key
    |  unlocks
    v
Device Private Key (X25519)
    |  HPKE unwrap of meta/keywrap/<device_id>.json
    v
Root Key (512-bit, per epoch)
    |  HKDF("baluard-sgk-v1" || epoch)
    v
Space Group Key (256-bit)
    |  HKDF("baluard-item-v1" || epoch || cipher_id)
    v
Item Key (256-bit) -> entry files
```

For a single-user vault the Space Group Key is derived deterministically from the Root Key. For a shared Space, members never receive the Root Key or the Space Group Key; the key model for Spaces, collection keys, and per-member wraps is in ADR 0085, and `meta/access_list.json` does not exist in the implementation. Item keys are epoch-bound: a key held at one epoch cannot derive item keys for another (`try_derive_item_key` returns `None` instead of deriving), which is why conflict resolution across a rotation needs special handling (ADR 0004).

**Device identity.** Each device has its own asymmetric keypair: X25519 for HPKE wrapping and Ed25519 for commit signatures. The vault has one master password and one KDF salt shared by all devices, and a single KEK canary (`meta/kek-canary.enc`) verifies it.

**Device key storage.** The device private key is never committed. When the platform provides a keystore, the key lives there. When it does not, the key lives in `meta/device-privkey.json`, an AES-256-GCM envelope sealed under the device-key seal subkey derived from the KEK. The file is gitignored together with `meta/device-id` and the local Git credentials, and the commit staging filter refuses to admit them, so a Git host never holds the key even in encrypted form. The unlocked handle retains only the seal subkey, not the KEK. Where a chip is available, the seal can additionally require the hardware key (ADR 0097). Older plaintext files are still readable and are re-sealed on the next successful unlock.

**New-device bootstrap.** Cloning the repository through the provider yields ciphertext only. A new device needs its own wrap of the Root Key before it can open anything, and it obtains it in one of two ways: approval by an already enrolled device, with physical presence and master-password confirmation, or the recovery phrase (BIP-39, 24 words, wrapping the Root Key in `meta/recovery.json`). Both paths, the enrollment policy, and the rotation protocol are in ADR 0101. Recovery on a fresh clone is ADR 0068, and propagation of a phrase-enrolled device's first signed commit is ADR 0081. The master password alone cannot enroll a device. The earlier design in which a new device decrypted a synced escrow file with only the master password is retired.

**Provider credentials.** The OAuth token or Personal Access Token used by `git2-rs` for background synchronization is stored in the host OS keyring (Apple Keychain, Windows Credential Manager, Secret Service) and is never committed to Git. Other device-local credentials, such as a custom-remote SSH deploy key, are likewise gitignored.

## Consequences

Disk theft of an enrolled device yields a sealed device key and ciphertext, so offline guessing of the master password is the remaining attack, which the optional hardware seal addresses. Because the Root Key is wrapped per device, revoking a device means rotating the Root Key and deleting that device's wrap (ADR 0101), and there is no shared secret to chase across machines. The cost is that a lost device with no other enrolled device and no recovery phrase is unrecoverable by design. Sharing, role, and collection key handling belongs to ADR 0085, not to this hierarchy.

## References

- `crates/baluard-core/src/keys/hierarchy.rs`
- `crates/baluard-core/src/crypto/hkdf_derive.rs`
- `crates/baluard-core/src/vault/device_privkey.rs`
- `crates/baluard-core/src/vault/keywrap.rs`
- `docs/security/threat-model.md`
- ADR 0068, ADR 0081, ADR 0085, ADR 0097, ADR 0101
