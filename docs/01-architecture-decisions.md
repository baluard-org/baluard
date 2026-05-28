# IDtty: Architecture Decisions Record

> Master Blueprint for the Git-backed Password Manager (Space Manager).
> Pure Rust core, Single-String Protobuf Gateway, Padded Buckets, UniFFI mobile bridge, SolidJS/KMP UI layers.

---

## DOMAIN 1: CRYPTO, STORAGE & KEY HIERARCHY

### D1. Rust Core & Memory Security

**Decision: Compiled Rust Core with `zeroize`-protected memory**

All cryptographic operations, Git operations (git2-rs), padding, and secret loading are handled entirely in the `idtty-core` Rust crate. Secrets (decrypted keys, entries) are held in `Zeroize`-derived structs. The daemon process keeps vault data in locked memory regions via `memsec`/`zeroize` to prevent paging to disk or leaking via core dumps.

---

### D2. Storage Engine: Padded Buckets & Hashed Filenames

**Decision: Hashed files-per-entry system padded into uniform size buckets**

To eliminate metadata leaks (website names, usernames, specific file sizes) and prevent Git merge conflicts:
1. **Entries Folder**: Located under `entries/`. All entries are named using a random UUID hash.
2. **Padding Engine**: Plaintext Protobuf payloads are padded with random bytes before AES-256-GCM encryption to fit exact bucket sizes:
   - **1 KB Bucket**: Standard Logins, TOTPs, Passkeys
   - **8 KB Bucket**: Extended Secure Notes
   - **64 KB Bucket**: Small Attachments, Scanned IDs
   - **1 MB Bucket**: Larger documents or media files
3. **Index Lookup (`index.enc`)**: An encrypted lookup table mapping human-readable metadata (URLs, Titles) to their corresponding hashed filenames under `entries/`. Decrypted on demand by idtty-core.

---

### D3. Key Hierarchy & Device Bootstrapping

**Decision: Envelope encryption + Private Key Escrow**

```
Master Password
    |
    v (Argon2id derivation)
Master KEK
    |
    v (decrypts Identity key)
Private Key Escrow (metadata/identity.enc)
    |
    v (yields Device Private Key)
Decrypts Space Group Key (metadata/access_list.json)
    |
    v
Decrypts Entries (entries/*.enc)
```

- **Device Digital Identity**: Each device has an asymmetric keypair (X25519 for HPKE wrapping, Ed25519 for commit signatures).
- **Private Key Escrow**: The user's device-specific asymmetric private key is symmetrically encrypted by their Master Password and committed to the repository at `metadata/identity.enc`.
- **OAuth Bootstrapping**: Logging into a new device utilizes GitHub/GitLab OAuth to clone the repository. The user then enters their Master Password to decrypt their device private key from `metadata/identity.enc` and escrow it into the local hardware enclave (Keychain, Secret Service, Android Keystore).
- **OAuth Token Storage**: The OAuth Personal Access Token (PAT) used for background git2-rs sync is stored securely in the host OS keyring (Apple Keychain / Secret Service), never committed to Git.

---

## DOMAIN 2: CONFLICT RESOLUTION & SYNCHRONIZATION

### D4. Index & Conflict Auto-Healing

**Decision: Automatic Index Rebuild & File Conflict Resolution**

- **Index Auto-Heal**: If `index.enc` experiences a Git conflict due to concurrent multi-device updates, idtty-core resolves the conflict programmatically. It decrypts the entire local `entries/` folder, reconstructs the index table from scratch, and silently force-pushes the clean resolution.
- **Entry Conflict Healing**: If a single padded file (`entries/3a7f82...enc`) experiences a conflict, idtty-core renames the local version, accepts the remote commit, and flags a notification to the UI layer: *"Two updates happened at once. Which do you keep?"*

---

### D5. Mobile JIT Sync

**Decision: Just-In-Time (JIT) sync fetch before biometric challenge**

To circumvent mobile OS sandboxes that aggressively terminate background synchronization loops:
1. **JIT Hook**: Triggered immediately when the mobile browser or credential provider requests autofill.
2. **Micro-Fetch**: idtty-core (via UniFFI binding) initiates a rapid `git fetch` to evaluate the remote branch SHA delta.
3. **Pulls Delta**: If a delta is present, idtty-core pulls changes, decrypts entries, and updates the local cache *before* prompting the user for biometrics (FaceID/Fingerprint).

---

## DOMAIN 3: PLATFORM ECOSYSTEMS & INTEGRATIONS

### D6. Single-String Protobuf Gateway

**Decision: Unification via `HandleRequest(action, payload)`**

**Current state**: Protobuf schemas exist in `proto/` but are not yet compiled into Rust. The daemon has a JSON echo stub. The CLI links idtty-core directly.

**Target**: All layers will communicate with idtty-core through a unified, serialized gateway interface:
- **Input**: A single Protobuf serialized string containing the action command and its parameters.
- **Output**: A serialized response string.
- This decoupling allows front-end tiers to compile with `MOCK_BACKEND=true` to skip native builds during UI development, feeding hardcoded mock Protobuf payloads directly to components.

---

### D7. Desktop Tier: Client-Server IPC Socket

**Decision: Rust Daemon (Server) + CLI Client (socket) + Tauri v2 (SolidJS/Tailwind UI)**

- **Rust Daemon (`idtty-daemon`)**: Started on boot by Tauri. Unlocks the vault into `zeroize`-protected memory. Listens on a local domain socket (`/tmp/idtty.sock` set to `0600` permissions via umask before bind) or Named Pipes on Windows. Built on tokio for async I/O. Handles both SIGINT and SIGTERM for graceful shutdown. **Current state: JSON echo stub with no vault state management.**
- **CLI (`idtty-cli`)**: **Target**: lightweight socket client that serializes flags into Protobuf, transmits to daemon, prints response. **Current state**: links idtty-core directly and calls vault/crypto functions in-process. Each command prompts for master password. Socket client conversion is a Phase 3 milestone.
- **Tauri v2 UI**: Lightweight SolidJS/Tailwind webview that communicates with the daemon. Intercepts close events (`api.prevent_close()`) to minimize to system tray and preserve memory-unlocked states for browser extension autofill. **Current state: placeholder.**

---

### D8. Mobile Tier: UniFFI Bindings (Planned)

**Decision: Mozilla UniFFI for Rust-to-Kotlin/Swift bridge**

Mobile apps will bind directly to idtty-core via UniFFI-generated native bindings:
- **Kotlin (Android)**: UniFFI generates Kotlin data classes and function bindings from `#[uniffi::export]` proc-macros on idtty-core's public API. Compiled into the KMP project as a static library.
- **Swift (iOS)**: UniFFI generates Swift bindings compiled into an xcframework.
- **No intermediate language**: The Rust core is the single source of truth. No Go, no cgo, no gomobile. UniFFI's serialization-based FFI provides a clean security boundary between Rust memory and foreign memory.
- **JIT Autofill**: The UniFFI-exposed `sync::fetch_and_decrypt()` method will be called directly from the Kotlin/Swift autofill adapter before biometric prompt.
- **Current state**: idtty-core has no `#[uniffi::export]` annotations yet. Mobile app is a placeholder scaffold.

---

### D9. Zero-Knowledge RBAC B2B & Family Sharing

**Decision: Envelope Asymmetric Key Wrapping via `metadata/access_list.json`**

1. **Space Invitation**: An Admin enters an invitee's email. idtty-core fetches their public key from the Git host.
2. **Group Key wrapping**: idtty-core encrypts the Space's AES-GCM **Group Key** with the recipient's public key and appends the wrapped payload to `metadata/access_list.json`.
3. **Acceptance**: Invitee decrypts the group key with their local device private key.
4. **Revocation / Offboarding**: The Admin rotates the Group Key. idtty-core re-encrypts the `entries/` directory, updates `access_list.json` for remaining members, and pushes the changes. The evicted user's local instance is instantly locked out of new commits, and all local entries are reduced to unreadable ciphertext.

---

## DOMAIN 4: CONSUMER-FRIENDLY TERMINOLOGY

To optimize accessibility and eliminate user-facing cryptographic jargon:

| Technical Cryptographic Term | Consumer UI Translation |
|------------------------------|-------------------------|
| Git Repository / Remote URL | **Space** (e.g., Personal Space, Work Space) |
| Git Clone / SSH / PAT Setup  | **"Sign in with GitHub"** (Silent OAuth) |
| Git Merge Conflict           | **"Two updates happened at once. Which do you keep?"** |
| Asymmetric Device Keypair     | **"Your Device Digital Identity"** |

---

## Staged Implementation Roadmap

- **Phase 1: Cryptographic Core & Padding Engine**: Rust idtty-core (crypto, keys, vault, padding). Protobuf schemas. DONE.
- **Phase 2: Git Sync Engine**: git2-rs sync, conflict auto-healing, state machine. DONE.
- **Phase 3: IPC Daemon & CLI**: idtty-daemon (tokio Unix socket server), idtty-cli (socket client), Protobuf gateway handler.
- **Phase 4: Desktop UI & Open-Source Launch**: SolidJS/Tailwind Tauri v2 app, system tray, MIT license.
- **Phase 5: Mobile & Extension**: UniFFI Kotlin/Swift bindings, KMP mobile app, MV3 browser extension with native messaging.
