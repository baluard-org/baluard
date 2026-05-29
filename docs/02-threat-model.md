# IDtty: Threat Model

> Formal adversary model for the Rust-backed Master Architecture and Space Manager.
> Covers: adversary classes, in-scope threats, local socket security, bucket metadata leakage, and JIT sync security.

---

## Summary Table

| Adversary Class | Capability Level | Primary Threat | Security Guarantee |
|-----------------|-----------------|----------------|-------------------|
| A — Honest-but-curious Git Provider | Passive read of all repository objects | Metadata inference (bucket distribution), timing analysis | Cannot read entry plaintexts. File names are hashed; entry sizes are uniform buckets (1KB, 8KB, 64KB, 1MB). |
| B — Malicious Git Provider | Active: can modify refs, inject corrupted index | Rollback attacks, corrupted index injection | index.enc auto-healed locally by idtty-core. Rebuilt from entries if corrupted or conflicted. Unsigned commits rejected. |
| C — Local Process (on same device) | Read `/tmp/idtty.sock` or pipes | Intercept IPC commands, steal secrets | Mitigated via `0600` socket permissions on Unix and system ACLs on Windows named pipes. Session token required for all cipher/sync operations (R7-2). |
| D — Local Attacker (physical disk access) | Read stored files directly | Offline brute force or cache recovery | Files are AES-GCM encrypted. Keys are isolated in host OS Keyring or `zeroize`-protected memory. |
| E — Malware with OS root privileges | Full process memory interception | Dump memory, steal secrets | `zeroize`-protected memory with `mlock` guards prevents standard paging and core dump leakage. Hardened boundary. Key material mlock'd to prevent swap persistence (R7-3). |
| F — Evicted Space Member | Possesses historical local git checkout | Read new entries or make unauthorized commits | Rotated Space Group Key renders future additions unreadable. OAuth token revoked, blocking pushes to Git provider. |
| G — Active Git Remote Adversary | Modify encrypted files on git remote | Swap/replace entries, cause victim to decrypt wrong data | AAD identity binding in every envelope blocks swap attacks (R7-1). Git commit signing provides repository-level integrity. |

---

## 1. In-Scope Threats & Security Controls

### T1: Git Provider Observing File Counts and Sizes
- **Threat**: Attacker infers vault contents based on specific file size signatures.
- **Control**: All entries under `entries/` are padded to uniform bucket sizes (1KB, 8KB, 64KB, 1MB) prior to encryption. Filenames are random UUID hashes. Attacker only observes counts of files per size bucket.

### T2: Local IPC Interception
- **Threat**: Another application on the same machine connects to the daemon and requests secrets.
- **Control**: Sockets at `/tmp/idtty.sock` are locked to `0600` permissions, allowing only the current user's process to connect. On Windows, Named Pipes use restrictive security descriptors (ACLs). Peer credential verification (SO_PEERCRED on Linux, getpeereid on macOS) rejects connections from other UIDs.
- **R7-2 Enhancement**: After unlock, the daemon generates a random 256-bit session token. All subsequent requests for cipher data, sync operations, and device listing must include this token. Without it, the daemon rejects the request. This prevents any same-UID process from extracting secrets after unlock without having participated in the unlock exchange.

### T3: JIT Autofill Hook Timing Attacks
- **Threat**: Network attacker maps when mobile users autofill by observing quick `git fetch` spikes.
- **Control**: JIT fetches check SHA delta against standard Git refs without revealing targeted credentials. JIT timing incorporates minor randomized network delay.

### T4: Evicted Space Member (Offboarding Revocation)
- **Threat**: Evicted member tries to decrypt new entries pushed to the Space.
- **Control**: The Admin rotates the Space Group Key. Every remaining entry is re-encrypted with the new Group Key. The access list `metadata/access_list.json` is updated to exclude the evicted member's public key wrapper. Future commits are unreadable to the evicted user.

### T5: Active Git Remote Adversary (Swap/Rollback)
- **Threat**: The git remote host (or any party with push access) modifies vault entries by renaming, replacing, or rolling back encrypted files. Without integrity binding, the victim decrypts the wrong entry and sends its contents to an attacker-controlled service (CVE-2020-28086 class attack).
- **Control**: Every encrypted envelope includes AES-256-GCM AAD (Additional Authenticated Data) that binds `vault_id || object_type || object_id || tier || alg_id || key_epoch || update_seq` into the authentication tag. On decryption, the daemon recomputes expected AAD from caller parameters and compares it to the stored AAD before decryption. Mismatches are rejected with `Corrupt("cipher identity mismatch")`. This blocks swap attacks, rename attacks, and cross-entry cut-and-paste.
- **Control**: Git commit signing (Ed25519) provides additional integrity at the repository level. Unsigned commits are rejected.

### T6: Key Material Paged to Swap
- **Threat**: OOM kill, `kill -9`, or process crash bypasses Rust `Drop` destructors. Key material (RootKey, ItemKey) may persist in RAM pages or be paged to swap/hibernation files, where it can be recovered by anyone with disk access.
- **Control**: All key material buffers (RootKey 64 bytes, ItemKey 32 bytes) are `mlock`'d immediately on creation. `munlock` + zeroize on drop. Best-effort: failures are logged but not fatal (RLIMIT_MEMLOCK may be low on some systems).

---

## 2. Platform Trust Boundaries

```
+-------------------------------------------------------------+
| TRUSTED BOUNDARY (Rust Daemon, zeroize memory, OS Keyring)  |
|                                                             |
|  +----------------------+  +-----------------------------+  |
|  | Space Group Key      |  | Device Private Key          |  |
|  | (zeroize + mlock)    |  | (Enclave / DPAPI / Keystore)|  |
|  +----------------------+  +-----------------------------+  |
+------------------------------+------------------------------+
                               | Unified IPC Protobuf Gateway
                               v (Unix Socket 0600 / Named Pipes)
+-------------------------------------------------------------+
| SEMI-TRUSTED (Tauri v2 SolidJS Webview, CLI, KMP UI)       |
|                                                             |
|  - No cryptographic logic or direct vault keys in UI        |
|  - Communicates strictly via HandleRequest(action, payload) |
+------------------------------+------------------------------+
                               | Network / Git Synchronization
                               v
+-------------------------------------------------------------+
| UNTRUSTED (Git Provider Host, Host OS Filesystem)           |
|                                                             |
|  - entries/*.enc (Uniformly padded, UUID hashed)            |
|  - index.enc (Encrypted fast-lookup index)                  |
+-------------------------------------------------------------+
```

---

## 3. Residual Risks

1. **Host OS Root Compromise**: If malware obtains root-level keylogger or debugger capabilities, it can intercept user input (Master Password) or compromise the OS Keyring.
2. **Metadata Pattern Inference**: High-frequency Git pushes reveal active usage periods. Mitigated through optional cover commits.
3. **Lost Device Quorum Override**: Single-device emergency force-evict relies on the user proving possession of both the Master Password (KEK) and the remaining hardware token. If both are compromised, the vault is fully taken over.
