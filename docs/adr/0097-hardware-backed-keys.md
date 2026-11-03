# ADR 0097. Hardware-Backed Device Key Seals

> Status: Accepted (2026-10-21). The plan was drafted on 2026-10-18. Landed by 2026-10-21: the trait, probe, kill-switch, `vault.hw_status`, the v2-hw seal, the desktop toggle, the macOS Secure Enclave, Windows PCP, and Linux TPM backends, and per-use consent on the Secure Enclave. The macOS backend still needs on-device verification, the keychain-access-groups entitlement, and a provisioning profile. The Linux backend was verified against a real TPM (Intel PTT). The chip backends compile only under the non-default `hw-seal` feature, which no repository build recipe enables yet, so default and release builds currently install no chip backend. The FIDO2 security key backend (ADR 0096) extended this framework. Mobile platform keystores are not implemented.

## Context

The vault's entire key hierarchy bottoms out at one local file, `meta/device-privkey.json`. It holds the device X25519 key, and that key opens the Root Key keywrap at `meta/keywrap/<device>.json`, whose HPKE purpose is `root-key-keywrap`. Protecting the device key protects the Root Key, and losing it makes everything above it unreachable.

The existing `baluard-devkey-seal-v1` envelope is AES-256-GCM under a purpose-scoped HKDF subkey of the Argon2id-derived KEK. That improves on the plaintext era, but the seal inherits the KEK's weakness: everything needed to attack it is on disk. An adversary with a disk image (stolen laptop, cloned drive, pulled backup, exfiltrated synced clone) can run an offline Argon2id brute force against the master password for as long as the ciphertext is worth attacking. Argon2id raises the cost per guess and does not remove the attack. The same image carries the keywrap file, so a recovered password yields the Root Key with no further hardware in the way. Two earlier audit notes pointed at the same gap: the threat model lists offline brute force or cache recovery as the remaining path for local disk access (adversary D), and the biometric module records that on Linux and Windows the keyring backends have no per-read gate, naming a TPM-backed key or Windows Hello key credential as the deferred fix.

Applications in the Secretive class close this by generating keys inside a security chip whose private half cannot leave. Baluard's model differs on purpose, since keys must be exportable, syncable, and recoverable. The goal is therefore not to copy that model but to buy the same offline resistance for the one file that guards everything, without giving up recoverability.

The protection is limited to the local device-key seal. Device identities remain X25519, Root Key keywraps remain HPKE, canaries remain unlock verifiers, and recovery-phrase enrollment remains the recovery path. Hardware never receives vault key material, and git synchronization, sharing, backup format, and every wire-visible artifact remain byte-identical before and after. The protection is for data at rest. Root Key, SGK, item keys, and the seal subkey remain in daemon memory (locked and zeroized on drop) during an unlocked session. This design does not prevent memory scraping by a same-user attacker while the vault is open, does not stop active malware that rides an authorized session token (token gating, rate limits, re-prompt, and auto-lock remain those controls), and does not address firmware or DMA attacks. It makes no remote-attestation or anti-tamper claim. The detail view of the settings copy must say plainly that the chip guards the vault at rest and not while it is open.

## Decision

### Product rule

One plain-language toggle in Security settings: "Guard this vault with this device's security chip". Its promise to a non-technical user is that a stolen disk or backup alone cannot open the vault, even with the password, because the machine's chip is part of the lock. The failure it must disclose in the same dialog is that if the chip or the machine dies, the device needs the recovery phrase to rejoin, like any new device. Disclosing only one half would be a dark pattern, so both halves appear in one dialog before the toggle takes effect. No git, crypto, TPM, or Secure Enclave jargon reaches the user. The toggle is per vault and mirrors quick unlock, and a global enable-on-all-vaults convenience row was not adopted for the first version. The vault stays fully syncable.

### Seal construction

Introduce the `HardwareKeyStore` abstraction in `crates/baluard-core/src/hwkey/` and the seal type `baluard-devkey-seal-v2-hw` alongside v1. A binding is associated with the deterministic `vault_id`, in the same naming discipline as quick unlock, so each vault has an independent binding and multi-vault never crosses bindings. The daemon performs all hardware operations, and desktop, CLI, native messaging host, and mobile never touch a keystore directly, so IPC and FFI surfaces are unchanged.

For each write, the hardware key performs ECDH between its non-exportable private key and a fresh ephemeral public key. Derive the content key as `ck = HKDF-SHA256(ikm = hw_secret || kek_subkey, info = "baluard-devkey-seal-v2-hw")`. Encrypt the inner private-key JSON with AES-256-GCM using the v1 envelope and the v1 AAD discipline (the purpose string is AAD, so the blob cannot be replayed as another meta file). Store the envelope, the ephemeral public key (the handshake), the hardware binding ID, and the device ID, plus the consent mode where applicable. Store neither key material nor a KDF salt.

Opening requires both inputs: the hardware ECDH, which is impossible off-device and without the chip's private half, and the KEK subkey from the master password. The composition is AND: the password alone fails offline and the hardware alone fails without the password. The master password stays the single user-facing credential while the chip becomes a silent second factor of the at-rest seal. The primitive chosen on all three platforms does not demand per-use consent, so unlock friction is unchanged by default.

### Platform matrix

| Platform | Primitive | Constraints |
|---|---|---|
| macOS 15+ | Secure Enclave P-256 key agreement, keychain-persisted reference with an application-scoped ACL | Every qualifying Mac (T2 or Apple silicon) has one. Key material is generated inside the Secure Enclave and is non-exportable by construction. The keychain reference binds to the daemon's stable signing identifier `app.baluard.mobile.daemon`; ad-hoc re-signs re-prompt and can strand the reference. Persistent keys require the keychain-access-groups entitlement and a provisioning profile. |
| Windows 11 | TPM 2.0 through the CNG Platform Crypto Provider | Keys are per-vault named TPM-resident keys, so there is no slot scarcity and deleting really deletes. Software-minted ephemerals are imported as the agreement peer (secrecy lives in the chip key). The raw CNG secret (`BCRYPT_KDF_RAW_SECRET`) is reversed from little-endian. |
| Linux (Ubuntu 26.04, Fedora 43) | TPM 2.0 through TSS 2.0 ESAPI (`tss-esapi`) | One shared persistent chip key per TPM, because slot-constrained parts such as Intel PTT expose only a handful of persistent slots; vault separation rides the password-derived seal subkey. The key is identified by TPM name, since outside information never appears in the public area. A per-command session matrix is required because ESYS refuses sessionless hierarchy commands but misbehaves with sessions on TR open and key generation. Builds need `tpm2-tss-devel`, and the process needs TSS access (`tss` group membership where configured); `tabrmd` is a possible runtime service and `just sysdeps` needs a matching line. |

Hardware presence varies (virtual machines, older machines, Windows virtual TPMs), so probe-or-hide is mandatory, and the probe must distinguish "no TPM" from "TPM without PCP" for honest status copy. Mobile keystores (Android Keystore, iOS Secure Enclave through UniFFI) are parked, and the trait is shaped so such implementations can be added without core changes. A FIDO2 security key backend, which also works on phones over NFC and USB, is specified in ADR 0096. That work extended the original four-method trait into a multi-backend registry keyed by backend ID, with an opaque length-bounded handshake blob in place of a fixed public key and an interaction capability.

### Availability and lifecycle

Hardware availability is probed and unavailable hardware is not offered. `BALUARD_DISABLE_HWKEY=1` disables the feature for hermetic operation, mirroring `BALUARD_DISABLE_KEYRING`. The pre-unlock host-level route `vault.hw_status` (like `pin_status` and `biometric_status`) reports capability and current seal kind without touching vault material. File-type detection recognizes `v2-hw`, which opens only when both inputs are available, and a v1 seal keeps opening under its existing path. A v2-hw seal fails closed with a typed error pointing at the toggle if the hardware is unavailable (driver gone, TPM disabled in firmware); it never silently falls back to ignoring the hardware half, because a silent fallback would turn the feature into a no-op without telling the user.

Enabling the feature re-seals v1 to v2-hw through `rotate_seal_key` with staged temporary output, an atomic rename, and `RotationGuard` crash safety. Disabling re-seals v2-hw to v1 and requires working hardware, so a dead chip cannot downgrade, by design. A master-password change derives the new KEK input and performs a fresh ECDH while retaining the binding. Device revocation and Root Key rotation do not change the seal, since the keywrap chain changes and the seal does not care. Deleting a vault from disk deletes its binding, while a plain detach preserves it because detach is reversible. A clone on the same machine has a new path, a new `vault_id`, and so a new binding; a clone on a machine whose chip holds no binding takes the normal enrollment flow, after which the hardware seal is offered again.

### Failure model

If the chip or machine is lost, the keychain is restored from backup to new hardware, or a PCP key is lost in a Windows reset, the local v2-hw seal cannot be opened on that device, permanently. The rescue is the existing phrase path: phrase enrollment derives a new device identity and overwrites the local device key, so the same physical device rejoins without any external reset, and no new recovery machinery is introduced. The test requirement is "phrase rescue after simulated hardware death".

### Per-use consent

Per-use consent is an optional seal mode, implemented on Secure Enclave only. On supported devices it uses a separate per-vault binding tagged `baluard-hwc:` and an ACL carrying `BIOMETRY_CURRENT_SET`. Consent capability is determined by a real throwaway ACL key-generation probe cached per process, so Apple silicon without a Touch ID sensor never claims consent. Secure Enclave failures are typed as `HardwareAuthFailed` (declined or invalidated, so retryable or phrase rescue) distinct from `HardwareUnavailable`. The consent mode byte is part of the seal AAD, so tampering with the flag in either direction fails the open; early files without the byte fail the AEAD check by design. Windows and Linux report consent as unsupported and fail closed. The Windows Hello key credential signs but cannot perform ECDH agreement, so composing a Hello gate with PCP agreement is the recorded future path, while a TPM authorization value would be a second password, which the product rule forbids.

### Threat coverage

Closed: offline adversary D on hardware-sealed vaults. A disk image plus unlimited time plus a correct password guess is insufficient, because the hardware ECDH input does not exist off-device, which shrinks the brute-force window from forever at Argon2id speed to nothing. Strictly harder: same-user silent reads of the device-key file on Linux and Windows, because the content key now requires chip participation and not merely a keyring read. The quick-unlock password entry is a separate, unchanged surface, and per-use consent is where that story completes.

### Non-goals

No remote attestation, no server-side chip verification, no anti-tamper claim. No change to the keywrap HPKE wire format, the canary, sharing, the encrypted backup, or phrase recovery. No hardware binding of stored SSH keys beyond what protecting the device key already gives them transitively, since they are item-key ciphers. No operating-system versions below the minimum platform table.

### Testing

Hermetic unit tests, always run, use a mock `HardwareKeyStore` for seal and open round trips, the AND property (either input missing fails), v1 to v2-hw migrations in both directions, master-password-change re-keying, AAD purpose binding, the probe-unavailable hide path, and fail-closed on missing hardware at unwrap, with property tests over random keys and ephemeral pairs. Hardware-gated integration tests run under `BALUARD_HW_KEY_TEST=1` against a real Secure Enclave on a Mac, a real TPM on Linux, and `swtpm` in Linux CI. The end-to-end harness is extended with a manual per-platform checklist (enable, unlock, lock, password change, phrase rescue after simulated hardware death, disable). `BALUARD_DISABLE_HWKEY=1` is set in `just test` from the start so that no test ever requires a chip.

### Phases and status

| Phase | Scope | Status |
|---|---|---|
| 0 | Trait, probe, `vault.hw_status`, kill-switch, v2-hw seal with mock tests, desktop toggle | Landed 2026-10-20 |
| 1 | macOS Secure Enclave backend | Committed behind `hw-seal`; needs on-device verification, entitlement, and provisioning profile |
| 2 | Windows PCP backend | Landed 2026-10-21; real-hardware acceptance is not recorded |
| 3 | Linux `tss-esapi` backend with `swtpm` CI | Landed 2026-10-21; verified on a real TPM |
| 4 | Surface polish: Security settings detail view, status in device-info surfaces, binding lifecycle strings in en, es, pt | No completion recorded |
| 5 | Per-use consent (Secure Enclave only) | Landed 2026-10-21 after a whole-feature review |

The phases are independently shippable, and Phase 1 alone covers every macOS user, the largest hardware-capable share of the desktop fleet.

### Open questions

Whether the daemon's stable signing identity survives local install rebuilds without stranding Secure Enclave references, or whether local installs must always keep the stable identifier. The `tss-esapi` build dependencies and minimum Rust version on Fedora 43 and Ubuntu 26.04.

## Consequences

A disk image plus a correct password guess is insufficient to open a hardware-sealed vault without the bound chip. The master password remains the user-facing credential, and no new recovery mechanism is required.

Loss of the chip requires recovery-phrase enrollment on that device, and disabling the feature requires a working chip. Users must understand both outcomes before enabling it, so the enable dialog states both together. Per-use consent is currently available only on the supported Secure Enclave path.

The macOS implementation depends on stable code signing and provisioning. Linux builds require `tpm2-tss-devel` and appropriate TSS access. Real-hardware integration tests are gated by `BALUARD_HW_KEY_TEST=1`, and Linux CI can use `swtpm`. Because the chip backends are behind a non-default feature that no build recipe enables, the feature is not yet reachable in shipped builds until that wiring is done. Mobile keystores are not implemented by this decision.

## References

- `docs/security/threat-model.md`, adversary D.
- `docs/adr/0096-yubikey-seal.md`, the FIDO2 backend and registry extension.
- `crates/baluard-core/src/vault/device_privkey.rs`.
- `crates/baluard-core/src/biometric.rs`.
- `crates/baluard-core/src/hwkey/`.
- `docs/security/post-quantum-readiness.md`.
