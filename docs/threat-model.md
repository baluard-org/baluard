# Baluard: Threat Model

> Formal adversary model for the Rust-backed Space Manager.
> Covers: adversary classes, in-scope threats, local socket security, bucket metadata leakage, biometric attack surface, attachment handling, import parser risks, TOTP secret lifecycle, and JIT sync security.

---

## Summary Table

| Adversary Class | Capability Level | Primary Threat | Security Guarantee |
|-----------------|-----------------|----------------|-------------------|
| A — Honest-but-curious Git Provider | Passive read of all repository objects | Metadata inference (bucket distribution), timing analysis | Cannot read entry plaintexts. File names are UUID hashes; entry sizes are uniform buckets (5KB, 30KB, 100KB, 250KB, 2MB). Cover commits obscure push frequency. |
| B — Malicious Git Provider | Active: can modify refs, inject corrupted index | Rollback attacks, corrupted index injection | index.enc auto-healed locally by baluard-core. Rebuilt from entries if corrupted or conflicted. Unsigned commits rejected. Integrity manifest (Ed25519 checkpoints) detects rollback. |
| C — Local Process (on same device) | Read IPC socket or pipes | Intercept IPC commands, steal secrets | Mitigated via `0600` socket permissions on Unix and system ACLs on Windows named pipes. Session token required for all cipher/sync operations (R7-2). SO_PEERCRED peer UID verification on Linux, getpeereid on macOS. |
| D — Local Attacker (physical disk access) | Read stored files directly | Offline brute force or cache recovery | Files are AES-256-GCM encrypted. Keys are isolated in host OS Keyring or `zeroize`-protected memory. |
| E — Malware with OS root privileges | Full process memory interception | Dump memory, steal secrets | `zeroize`-protected memory with `mlock` guards prevents standard paging and core dump leakage. Key material mlock'd to prevent swap persistence (R7-3). |
| F — Evicted Space Member | Possesses historical local git checkout | Read new entries or make unauthorized commits | Rotated Space Group Key renders future additions unreadable. Root key rotation re-encrypts all entries under new epoch. Git credential rotation is out-of-band (user must rotate deploy keys/PATs manually). |
| G — Active Git Remote Adversary | Modify encrypted files on git remote | Swap/replace entries, cause victim to decrypt wrong data | SHA-256 hashed AAD identity binding in every envelope blocks swap attacks (T5). Git commit signing (Ed25519) provides repository-level integrity. |
| H — Malicious Import File | Supply crafted CSV/JSON/XML/1PUX file | Parser exploitation, injected malicious data | Import parsers run in Rust (memory-safe). Parsed into `CipherInput` structs, batch-created. No code execution from import data. |
| I — OS Keychain Compromise | Extract master password from OS keyring | Full vault access without user interaction | Biometric unlock is opt-in. Keychain-stored MP is no stronger than the OS keychain itself. See T10. |

---

## 1. In-Scope Threats & Security Controls

### T1: Git Provider Observing File Counts and Sizes
- **Threat**: Attacker infers vault contents based on specific file size signatures.
- **Control**: All entries under `entries/` are padded to uniform bucket sizes (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB) prior to encryption. Filenames are random UUID hashes. Attacker only observes counts of files per size bucket. `Tier::fit()` auto-selects the smallest bucket that fits the plaintext.

### T2: Local IPC Interception
- **Threat**: Another application on the same machine connects to the daemon and requests secrets.
- **Control**: IPC sockets are locked to `0600` permissions, allowing only the current user's process to connect. On Windows, Named Pipes use restrictive security descriptors (ACLs). Peer credential verification (SO_PEERCRED on Linux, getpeereid on macOS) rejects connections from other UIDs.
- **R7-2 Enhancement**: After unlock, the daemon generates a random 256-bit session token. All subsequent requests for cipher data, sync operations, and device listing must include this token. Without it, the daemon rejects the request. This prevents any same-UID process from extracting secrets after unlock without having participated in the unlock exchange.

### T3: JIT Autofill Hook Timing Attacks
- **Threat**: Network attacker maps when mobile users autofill by observing quick `git fetch` spikes.
- **Control**: JIT fetches check SHA delta against standard Git refs without revealing targeted credentials. JIT timing incorporates minor randomized network delay.

### T4: Evicted Space Member (Offboarding Revocation)
- **Threat**: Evicted member tries to decrypt new entries pushed to the Space.
- **Control**: The Admin rotates the Space Group Key. Every remaining entry is re-encrypted with the new Group Key. The access list `metadata/access_list.json` is updated to exclude the evicted member's public key wrapper. Future commits are unreadable to the evicted user.

### T5: Active Git Remote Adversary (Swap/Rollback)
- **Threat**: The git remote host (or any party with push access) modifies vault entries by renaming, replacing, or rolling back encrypted files. Without integrity binding, the victim decrypts the wrong entry and sends its contents to an attacker-controlled service (CVE-2020-28086 class attack).
- **Control**: Every encrypted envelope includes AES-256-GCM AAD (Additional Authenticated Data). The AAD is derived via SHA-256 hash over length-prefixed fields: `vault_id || object_type || object_id || tier || alg_id || key_epoch || update_seq` with domain separation prefix `baluard-aad-v2`. On decryption, the daemon recomputes expected AAD from caller parameters and asserts before decryption. Mismatches are rejected with `Corrupt("cipher identity mismatch")`. This blocks swap attacks, rename attacks, and cross-entry cut-and-paste.
- **Control**: Git commit signing (Ed25519) provides repository-level integrity. Unsigned commits are rejected.
- **Control**: Ed25519-signed integrity manifest checkpoints detect rollback. Fresh devices bootstrap trust from the manifest.

### T6: Key Material Paged to Swap
- **Threat**: OOM kill, `kill -9`, or process crash bypasses Rust `Drop` destructors. Key material (RootKey, ItemKey, TOTP secrets) may persist in RAM pages or be paged to swap/hibernation files, where it can be recovered by anyone with disk access.
- **Control**: All key material buffers (RootKey 64 bytes, ItemKey 32 bytes) are `mlock`'d immediately on creation. `munlock` + zeroize on drop. Best-effort: failures are logged but not fatal (RLIMIT_MEMLOCK may be low on some systems). TOTP `TotpParams.secret` is zeroized on drop.

---

### T7: Attachment Plaintext Leakage
- **Threat**: During upload or download, unencrypted attachment data exists in process memory or as a temp file on disk.
- **Control**: Attachments are encrypted with the cipher's item key (AES-256-GCM, random nonce) in memory. No temp files are written. Plaintext is zeroized in both daemon and CLI after use. Max attachment size: 2MB, enforced before encryption to prevent resource exhaustion.

### T8: Import Parser Exploitation
- **Threat**: A crafted import file (CSV, JSON, XML, 1PUX) exploits a parser bug to cause memory corruption or code execution.
- **Control**: All import parsers are written in Rust (memory-safe). Parsed data flows into typed `CipherInput` structs before batch-creation. No code execution from import data. Parser errors produce `BaluardError` without panicking.

### T9: TOTP Secret Exposure
- **Threat**: TOTP secret is extracted from daemon memory or intercepted over IPC.
- **Control**: TOTP secrets are stored encrypted in the vault (part of Login cipher data). The daemon generates time-based codes internally and returns only the derived numeric code over IPC. The seed never crosses the socket boundary. `TotpParams.secret` is zeroized on drop. TOTP codes are short-lived (30/60s), limiting replay window.

### T10: Biometric Unlock / OS Keychain Compromise
- **Threat**: An attacker with access to the OS keychain extracts the stored master password, gaining full vault access without user interaction.
- **Control**: Biometric unlock is opt-in (disabled by default). On macOS, the master password is stored using the native `security-framework` API with `SecAccessControl` configured for biometric validation (`AccessControlOptions::BIOMETRY_ANY`), ensuring Touch ID / Face ID is required on read. On other platforms, it uses the `keyring` crate (utilizing Windows Credential Manager, Linux libsecret, etc.). The daemon performs vault unlock server-side: the secret never returns over IPC. Users who distrust the OS keychain should not enable biometric unlock.
- **Residual**: Keychain access typically requires OS-level authentication (TouchID, Windows Hello, Linux PAM). Compromise implies the attacker has already bypassed OS security.

### T11: Reprompt Grant Window Abuse
- **Threat**: A same-UID process exploits the 30-second reprompt grant window to access a protected cipher after the user authenticates.
- **Control**: Reprompt opens a temporary vault handle, verifies the master password, and issues a short-lived grant (30s). The grant is scoped to a single cipher. The daemon tracks grant state internally. After 30s, the grant expires and re-authentication is required. Session token (R7-2) is still required on top of the grant.

### T12: Online Brute Force (Master Password)
- **Threat**: An attacker with local or daemon access attempts rapid password guesses.
- **Control**: `VaultHandle::check_attempt_rate_limit()` enforces exponential backoff on failed unlock attempts. Failed attempts are recorded in vault metadata. Argon2id KDF (memory-hard) makes each attempt computationally expensive (tunable memory/iterations), further limiting brute-force throughput.

### T13: Recovery Phrase Exposure
- **Threat**: The BIP-39 24-word recovery phrase is written down, photographed, or observed during vault creation.
- **Control**: The phrase is displayed once during creation and never stored in plaintext. Derived via BIP-39 from 256 bits of CSPRNG entropy. The recovery phrase bypasses all device enrollment and quorum controls. Physical security of the phrase is the user's responsibility. **Mandatory write-down verification** during creation (user must re-enter 4 random words) reduces the risk that the user proceeds without actually writing it down.
- **Residual**: The phrase IS the root of trust. If compromised, full vault access is possible from any device. No mitigating control exists beyond physical protection. With `EnrollmentPolicy::Personal`, the phrase can also be used to enroll new devices (non-destructive). With `Strict`, it only works via destructive `recover_from_phrase`.

### T14: Cover Commit Correlation
- **Threat**: Despite cover commits, an adversary correlates real commits (accompanying entry changes) with cover commits (no-op) by analyzing commit diff sizes or timing patterns.
- **Control**: Cover commits use CSPRNG-backed timing jitter on push/pull intervals. Commit content is padded to uniform bucket sizes, so diff sizes are indistinguishable from real commits. The adversary can only observe commit frequency, not content.
- **Residual**: High-frequency push patterns may still leak usage timing. Mitigation is probabilistic, not deterministic.

## 2. Platform Trust Boundaries

```
+-------------------------------------------------------------+
| TRUSTED BOUNDARY (Rust Daemon, zeroize memory, mlock)       |
|                                                             |
|  +----------------------+  +-----------------------------+  |
|  | Root Key / SGK /     |  | Device Private Key          |  |
|  | Item Keys            |  | (HPKE-wrapped in keywrap/)  |  |
|  | (zeroize + mlock)    |  | (zeroize + mlock)           |  |
|  +----------------------+  +-----------------------------+  |
+------------------------------+------------------------------+
                               |
              +----------------+----------------+
              |                                 |
    SEMI-TRUSTED boundary            SEMI-TRUSTED boundary
    (OS Keyring / Keychain)          (Protobuf IPC Gateway)
    - Biometric: MP stored here      - Unix Socket 0600
    - OAuth PAT stored here          - Session token gated
    - Keyring = OS security          - SO_PEERCRED / getpeereid
              |                                 |
              |       Unified IPC Protobuf      |
              |       v (Unix Socket 0600)       |
+-------------------------------------------------------------+
| SEMI-TRUSTED (Tauri v2 SolidJS Webview, CLI, KMP UI)       |
|                                                             |
|  - No cryptographic logic or direct vault keys in UI        |
|  - Communicates strictly via HandleRequest(action, payload) |
|  - TOTP codes, not secrets. Attachments streamed, not cached|
+------------------------------+------------------------------+
                               | Network / Git Synchronization
                               v
+-------------------------------------------------------------+
| UNTRUSTED (Git Provider Host, Host OS Filesystem)           |
|                                                             |
|  - entries/*.enc (Uniformly padded, UUID hashed)            |
|  - index.enc (Encrypted fast-lookup index)                  |
|  - meta/device_activity.json (Plaintext, UUIDs only)        |
|  - meta/devices.json (Plaintext, public keys + names)       |
+-------------------------------------------------------------+
```

---

## 3. Residual Risks

1. **Host OS Root Compromise**: If malware obtains root-level keylogger or debugger capabilities, it can intercept user input (Master Password) or compromise the OS Keyring. No defense within application scope.
2. **Metadata Pattern Inference**: High-frequency Git pushes reveal active usage periods. Mitigated through optional cover commits with CSPRNG jitter (T14). Probabilistic, not deterministic.
3. **Lost Device Quorum Override**: Single-device emergency force-evict relies on the user proving possession of both the Master Password (KEK) and the remaining hardware token. If both are compromised, the vault is fully taken over.
4. **Revoked Device Stale Snapshot**: A revoked device retains a readable copy of the vault at the epoch of revocation. Root key rotation ensures the copy becomes stale, but historical data remains readable. Fundamental to serverless model.
5. **Git Credentials Out-of-Band**: Revoking vault access does NOT revoke git push access. User must manually rotate deploy keys/PATs on GitHub/GitLab. Fleet dashboard shows persistent warning, but no automated enforcement.
6. **Recovery Phrase is Root of Trust**: If the BIP-39 phrase is compromised, full vault access is possible from any device, bypassing all device enrollment and quorum controls. No mitigating control beyond physical protection.
7. **Plaintext Metadata Files**: `meta/devices.json` (device names, public keys) and `meta/device_activity.json` (UUIDs, timestamps) are plaintext in the git repo. Acceptable for single-user private repos, but leaks device names and sync patterns to anyone with repo read access.
8. **Keywrap Gap After Revocation**: After device revocation, the keywrap file for the revoked device is not cleaned up. Recovery phrase is the fallback. (Known gap, tracked in progress doc.)
