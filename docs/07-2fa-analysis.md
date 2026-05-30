# 2FA / Second Factor Analysis

**Status**: Design exploration — NOT for immediate implementation
**Last updated**: 2026-05-30
**Reviewers**: peer review (analysis), TARS (synthesis)

---

## Context

IDtty is a serverless, local-first password manager. No backend. No cloud. Vault is encrypted files on disk. Sync via optional git remote.

The question: **What does 2FA mean when there is no server to enforce it?**

---

## Threat Model

| Attacker has | Can they unlock the vault? | What stops them? |
|---|---|---|
| Master password only | No — no vault files | Nothing needed. Files are the second factor. |
| Disk access only | No — no master password | Encryption. Argon2id KDF. |
| Master password + disk access | **Yes** | Nothing. Game over regardless of 2FA. |
| Running session (unattended machine) | Yes — daemon has keys in memory | Auto-lock timer. Screen lock integration. |
| GitHub PAT + remote repo access | No — vault contents are encrypted | End-to-end encryption. Git repo is ciphertext. |
| Master password + GitHub access | No — still no disk access to vault files | Local-only decryption. |

**Key insight**: In a serverless app, there is no remote attack surface for vault unlock. The "second factor" is the physical device holding the encrypted files.

---

## Why TOTP Is Theater Here

TOTP's security model:

```
Traditional (server-based):
  User holds: password + TOTP code (from authenticator app)
  Server holds: password hash + TOTP shared secret
  Attack separation: compromising the password hash ≠ compromising the TOTP secret
  Result: real second factor

Serverless (IDtty):
  User holds: master password + TOTP code
  Vault holds: KEK-derived encryption + TOTP shared secret
  Attack separation: same master password decrypts BOTH the vault AND the TOTP secret
  Result: attacker derives KEK → decrypts TOTP secret → generates valid codes
```

If the TOTP secret is encrypted with the same KEK that protects the vault, the attacker who knows the master password can derive the KEK, decrypt the TOTP secret, and generate valid codes. The second factor collapses into the first.

**Derived TOTP secret** (`HKDF(master_password_hash, device_salt)`) is equally theater: the salt is on disk, the master password is known, so the TOTP secret is derivable.

TOTP only adds real security if the shared secret is stored behind a **different security boundary** than the master password. In a serverless app, that means hardware.

---

## What Actually Works

### Tier 1: Correct Framing (zero cost, do now)

IDtty is already 2FA by design:

- **Something you know**: master password
- **Something you have**: the encrypted vault files on your physical device(s)

Document this explicitly in UX. Make it a feature, not an apology. "Your vault only exists on your devices. No server can be breached because there is no server."

### Tier 2: FIDO2 for Vault Unlock (real second factor)

```
unlock(vault_path, master_password):
  1. master_password → Argon2id → KEK
  2. KEK → decrypt root key (as today)
  3. FIDO2 challenge: IDtty generates random nonce
  4. Platform authenticator signs nonce with hardware-bound private key
  5. Verify Ed25519 signature against stored public key (in vault header)
  6. Only then: root key used for vault operations
```

**Why this is real**: The FIDO2 private key never leaves the TPM/Secure Enclave/YubiKey. Full disk access + master password does NOT give the attacker the signing key. The hardware IS the second factor.

**Platform authenticator availability**:

| Platform | Authenticator | Rust crate |
|---|---|---|
| macOS | Touch ID / Secure Enclave | `libfido2` bindings |
| Windows | Windows Hello (PIN + biometric) | `webauthn` crate |
| Linux | TPM2 via `libfido2` | `libfido2` crate |
| Android | Fingerprint / biometric prompt | UniFFI → Rust `libfido2` |
| iOS | Face ID / Touch ID | UniFFI → Rust `libfido2` |
| Physical | YubiKey (CTAP2) | `libfido2` |

**Storage**: FIDO2 credential public key in vault header (plaintext is fine — it's public). Private key stays in hardware.

**Registration flow**:
```
1. User enables "Hardware unlock" in settings
2. IDtty calls FIDO2 make_credential() on platform authenticator
3. User authenticates via biometric (Touch ID, Windows Hello, fingerprint)
4. IDtty stores credential_id + public_key in vault header
5. From now on, vault unlock requires both master password + FIDO2 assertion
```

**Fallback**: Devices without FIDO2 hardware fall back to master-password-only. Explicit UX warning: "This device has no hardware second factor. Enable on a device with biometric support for maximum protection."

**Impact on existing code**: Minimal. FIDO2 check is a gate after KEK derivation, before root key use. Add `fido2_public_key: Option<Ed25519PublicKey>` to vault header. `Option` = feature is opt-in, vaultes created before this feature work unchanged.

### Tier 3: Git Sync Gate (compartmentalization)

Protect the git sync channel independently of vault unlock.

**Problem**: Attacker gains access to a running session (malware, unattended machine). Daemon has vault unlocked in memory. Attacker can `git push` to exfiltrate or tamper.

**Solution**: Separate auth for sync operations.

```
sync_authorization:
  sync_key = HKDF(root_key, "git-sync-v1")

  storage (NOT in vault files):
    macOS:    Security.framework Keychain
    Linux:    GNOME Keyring / libsecret
    Windows:  Credential Manager

  re-auth cadence: every N hours (configurable, default 4h)

  re-auth method: platform biometric (Touch ID, Windows Hello)
                  or FIDO2 assertion
                  or master password re-entry (weakest)
```

**Why this is real**: The sync key lives in the OS keychain, which has its own security boundary (user login, biometric unlock). Compromising the vault process memory does NOT compromise the OS keychain. These are separate attack surfaces.

**PAT protection**: Git PAT is encrypted with the sync key. Even if attacker dumps process memory, PAT is not in it. PAT only decrypted on-demand during push/pull, after re-auth.

**Value**: Narrows blast radius of a compromised session from "full vault + sync" to "full vault, no sync." Attacker can read secrets in memory but cannot push tampered data to remote or pull from remote without re-auth.

### Tier 4: TOTP for Device Enrollment (correct use case)

This is the one scenario where TOTP is genuinely the right tool.

```
Device enrollment with TOTP confirmation:

Existing device:
  1. Generate ephemeral TOTP secret (random 160-bit)
  2. Display QR code containing the secret (standard otpauth:// URI)
  3. User scans QR in any authenticator app (Google Auth, Authy, etc.)
  4. Display 6-digit TOTP code on screen (from the same secret)
  5. Wait for new device to enter the code within 60 seconds

New device:
  1. Scan enrollment QR from existing device
  2. Prompt: "Enter confirmation code from existing device"
  3. User reads 6-digit code from existing device screen, types it on new device
  4. Verify TOTP code matches
  5. If valid: proceed with pairing bundle exchange
  6. Ephemeral secret deleted from both devices

Why this works:
  - Secret is ephemeral (exists for <60 seconds)
  - Not stored alongside vault encryption keys
  - Proves physical proximity / user presence on both devices
  - Standard TOTP = works with any authenticator app
```

**Why this is NOT theater**: The TOTP secret is transient and never stored in the vault. Its purpose is to confirm the user physically possesses both devices during enrollment. It's a liveness check, not a persistent second factor.

### Tier 5: FIDO2-Only Mode (future consideration)

For maximum security: vault unlock via FIDO2 only, no master password.

```
unlock(vault_path):
  1. FIDO2 assertion → signs challenge
  2. Signature used as key material via HKDF
  3. HKDF(FIDO2_signature, vault_salt) → KEK
  4. KEK decrypts root key
```

Requires hardware token or platform authenticator. No password to remember. No password to phish. But: lose the hardware → lose the vault (unless BIP-39 recovery).

**Status**: Not recommended for now. Too much friction for mainstream users. Reserve for high-security org/team vaults.

---

## What NOT To Do

| Approach | Why it fails |
|---|---|
| TOTP secret encrypted with KEK | Same master password decrypts both. Theater. |
| Derived TOTP from master password + salt | Salt is on disk. Derivable. Theater. |
| TOTP for vault unlock (any storage in vault) | Attacker with master password extracts secret. Theater. |
| SMS-based 2FA | Requires phone number + server. Violates no-server constraint. |
| Email-based 2FA | Requires email server. Violates no-server constraint. |
| Push notification 2FA | Requires push service. Violates no-server constraint. |
| "Remember this device for 30 days" | Defeats the purpose. No server to enforce revocation. |

---

## Implementation Priority

| Tier | Description | Effort | Value | When |
|---|---|---|---|---|
| 1 | Document local-only = 2FA | Hours | Framing | Now |
| 2 | FIDO2 vault unlock | Weeks | Real second factor | After mobile MVP |
| 3 | OS keychain sync gate | Days | Compartmentalization | After Tier 2 |
| 4 | TOTP enrollment confirmation | Days | Enrollment liveness | With multi-device |
| 5 | FIDO2-only mode | Weeks | Max security | Future (orgs) |

---

## Open Questions

1. **FIDO2 crate maturity**: `libfido2` bindings in Rust — how stable? Audit status? Need to evaluate before Tier 2 commitment.

2. **Android/iOS FIDO2 via UniFFI**: Can `libfido2` build for mobile targets? Or do we need platform-specific FFI (Android SafetyNet, iOS LAContext)? This affects UniFFI API surface.

3. **Keychain availability in CI/testing**: OS keychain requires a user session. How do we test Tier 3 in headless CI? Mock keychain trait?

4. **Multiple FIDO2 credentials**: User has YubiKey at home, platform authenticator on laptop. Store multiple public keys? Rotate between them?

5. **Recovery after FIDO2 credential loss**: User enables FIDO2, loses hardware token. Fallback to master password only? Or BIP-39 recovery required? UX tension between security and lockout risk.

6. **Org/team vaults**: Different threat model (multiple users, not just multiple devices). 2FA requirements may differ. Deferred to org feature design.

---

## Cross-References

- [06-device-lifecycle.md](06-device-lifecycle.md) — enrollment, pairing, epoch rotation
- [02-threat-model.md](02-threat-model.md) — formal threat model
- [03-key-lifecycle.md](03-key-lifecycle.md) — key hierarchy and derivation
