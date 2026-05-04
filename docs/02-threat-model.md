# IDtty: Threat Model

> Formal adversary model for the Rust-backed Master Architecture and Space Manager.
> Covers: adversary classes, in-scope threats, local socket security, bucket metadata leakage, and JIT sync security.

---

## Summary Table

| Adversary Class | Capability Level | Primary Threat | Security Guarantee |
|-----------------|-----------------|----------------|-------------------|
| A — Honest-but-curious Git Provider | Passive read of all repository objects | Metadata inference (bucket distribution), timing analysis | Cannot read entry plaintexts. File names are hashed; entry sizes are uniform buckets (1KB, 8KB, 64KB, 1MB). |
| B — Malicious Git Provider | Active: can modify refs, inject corrupted index | Rollback attacks, corrupted index injection | index.enc auto-healed locally by idtty-core. Rebuilt from entries if corrupted or conflicted. Unsigned commits rejected. |
| C — Local Process (on same device) | Read `/tmp/idtty.sock` or pipes | Intercept IPC commands, steal secrets | Mitigated via `0600` socket permissions on Unix and system ACLs on Windows named pipes. |
| D — Local Attacker (physical disk access) | Read stored files directly | Offline brute force or cache recovery | Files are AES-GCM encrypted. Keys are isolated in host OS Keyring or `zeroize`-protected memory. |
| E — Malware with OS root privileges | Full process memory interception | Dump memory, steal secrets | `zeroize`-protected memory with `mlock` guards prevents standard paging and core dump leakage. Hardened boundary. |
| F — Evicted Space Member | Possesses historical local git checkout | Read new entries or make unauthorized commits | Rotated Space Group Key renders future additions unreadable. OAuth token revoked, blocking pushes to Git provider. |

---

## 1. In-Scope Threats & Security Controls

### T1: Git Provider Observing File Counts and Sizes
- **Threat**: Attacker infers vault contents based on specific file size signatures.
- **Control**: All entries under `entries/` are padded to uniform bucket sizes (1KB, 8KB, 64KB, 1MB) prior to encryption. Filenames are random UUID hashes. Attacker only observes counts of files per size bucket.

### T2: Local IPC Interception
- **Threat**: Another application on the same machine connects to the daemon and requests secrets.
- **Control**: Sockets at `/tmp/idtty.sock` are locked to `0600` permissions, allowing only the current user's process to connect. On Windows, Named Pipes use restrictive security descriptors (ACLs).

### T3: JIT Autofill Hook Timing Attacks
- **Threat**: Network attacker maps when mobile users autofill by observing quick `git fetch` spikes.
- **Control**: JIT fetches check SHA delta against standard Git refs without revealing targeted credentials. JIT timing incorporates minor randomized network delay.

### T4: Evicted Space Member (Offboarding Revocation)
- **Threat**: Evicted member tries to decrypt new entries pushed to the Space.
- **Control**: The Admin rotates the Space Group Key. Every remaining entry is re-encrypted with the new Group Key. The access list `metadata/access_list.json` is updated to exclude the evicted member's public key wrapper. Future commits are unreadable to the evicted user.

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
