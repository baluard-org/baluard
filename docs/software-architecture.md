# Baluard: Software Architecture

> Monorepo software architecture for the Rust Core Space Manager.
> Covers: monorepo structure, Single-String Protobuf Gateway, Unix Domain Sockets IPC, Tauri v2 tray integration, UniFFI mobile bindings (baluard-uniffi), Kotlin Multiplatform JIT mobile sync, and Mock Engine.

---

## 1. Monorepo Structure

```text
baluard/
├── proto/                      # Shared Protobuf Schemas (vault.proto, space.proto, auth.proto)
│                               # Compiled into Rust via prost-build in daemon + CLI
├── crates/                     # Rust Workspace
│   ├── baluard-core/             # Core Engine: crypto, keys, vault, padding, git sync, providers, bridge
│   │   └── src/
│   │       ├── crypto/         # AES-256-GCM (aead), KDF Argon2id (kdf), HKDF (hkdf_derive), HPKE wrap (hpke_wrap), Ed25519 (signature), TOTP (RFC 6238), + webauthn/ subdir
│   │       ├── keys/           # Key hierarchy (hierarchy), epochs (epoch), rotation (rotation), nonces (nonce)
│   │       ├── vault/          # Padding engine (5KB/30KB/100KB/250KB/2MB tiers), envelope, manifest, CRUD, canary, attachment, avatar, slug, registry, keywrap, index
│   │       ├── sync/           # git2-rs sync engine, conflict 3-way merge, state machine, known_hosts, credentials, operations, commit
│   │       ├── import/         # 8 import parsers (bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, 1password_1pux, 1password_csv, keepass_xml) + 2 export formats
│   │       ├── providers/      # Git provider abstraction: github, gitlab, codeberg adapters + token store + shared types
│   │       ├── bridge/         # Browser extension bridge: pairing file format + atomic writes (pairing), bridge token mint/verify (token)
│   │       ├── biometric.rs    # OS-keychain-backed master password escrow (per-vault scoped, deterministic vault_id from KDF salt)
│   │       ├── device_manager.rs # Device registry, rotation, activity, enrollment, recovery-phrase enrollment
│   │       ├── devices.rs      # Lower-level device entry types
│   │       ├── emergency.rs    # Break-glass access
│   │       ├── health.rs       # Password health report
│   │       ├── integrity.rs    # Canary checks + rollback manifest
│   │       ├── orgs.rs         # Team sharing / RBAC
│   │       ├── recovery.rs     # BIP-39 recovery
│   │       ├── paths.rs        # Platform-correct base dirs (data, socket, logs, token)
│   │       ├── types.rs        # CipherKind, CipherInput, CipherMeta, all cipher data structs
│   │       └── error.rs        # BaluardError enum
│   ├── baluard-cli/              # CLI Client (clap): daemon-first with --direct fallback
│   │   └── src/
│   │       ├── main.rs         # Command dispatch
│   │       ├── client.rs       # Protobuf socket client, session tokens
│   │       └── commands/       # Dual-mode handlers (daemon + --direct) in commands/mod.rs
│   ├── baluard-runtime/          # Shared in-process vault runtime (daemon, NMH, mobile)
│   │   └── src/
│   │       ├── host.rs         # VaultHost multi-vault: RwLock<VaultHostInner> with HashMap + active pointer
│   │       ├── state.rs        # VaultState (per-vault handle, session token, cover timer, auto-lock, autosync handle)
│   │       ├── autosync.rs     # Auto-sync coordinator (debounced push, periodic pull, offline retry)
│   │       ├── pin.rs          # Session PIN escrow (in-memory KEK, 5-strike nuke)
│   │       ├── bridge.rs       # Bridge-token registry + mobile pairing ceremony
│   │       ├── rate_limit.rs   # Per-vault rate limiting: unlock/recovery/emergency/biometric/PIN
│   │       ├── providers.rs    # Token refresh serialization, device flow, PAT connect, pre-unlock enrollment
│   │       └── crypto.rs       # constant_time_eq + crypto helpers for session tokens
│   ├── baluard-daemon/           # Background IPC Daemon (thin shell over baluard-runtime)
│   │   └── src/
│   │       ├── main.rs         # tokio Unix socket listener, auto-lock walker, SIGINT/SIGTERM, 0600 perms
│   │       ├── handler.rs      # Protobuf routing, ~72 routes, token-gated actions, SO_PEERCRED, bridge allowlist
│   │       ├── socket_path.rs  # Platform socket path resolution
│   │       └── lib.rs          # Test surface
│   ├── baluard-nmh/              # Native Messaging Host (browser extension bridge): stdio-JSON <-> varint-protobuf
│   └── baluard-uniffi/           # UniFFI bindings consumed by Kotlin Multiplatform mobile app
├── desktop/                    # Tauri v2 Desktop App (SolidJS/Tailwind, full CRUD, 8 cipher types)
│   ├── src-tauri/              # Rust backend: daemon sidecar + baluard-nmh sidecar + tray + proto codegen
│   ├── src/                    # SolidJS webview: login, vault, cipher CRUD, settings
│   │   ├── components/         # 38 components (VaultView, CipherDetail, SshKeyGenerator, SetupScreen, FocusTrap, WelcomeScreen, CloneFromProviderScreen, BridgeTab, ConflictBanner, ConflictResolutionPanel, DetachVaultModal, SwitchUnlockModal, VaultSwitcher, AutoSyncIndicator, DeviceFleetPanel, SyncTab, SettingsModal, ...)
│   │   ├── context/            # AuthContext, VaultContext, VaultSwitcherContext, AutoSyncContext, ConflictResolutionContext, themeSignal, toastSignal
│   │   ├── lib/                # daemon.js, payload.js, cipherSchema.js, filters.js, utils.js, helpers.js, biometry.js, clipboard.js, vaultPrefetch.js, vaultTimeout.js, slug.js, cloneFlow.js, providerConnect.js, disableAutofill.js, eff-words.js, wordlist-{en,es}.js
│   │   ├── __tests__/          # vitest tests (payload, utils, filters, cipherSchema, cloneFlow, conflictResolution, ConflictResolutionPanel, conflictSwitchClear)
│   │   └── i18n/locales/       # en.json, es.json (all user-facing strings)
│   └── package.json            # SolidJS, Tailwind v4, Tauri API v2
├── browser/                    # MV3 Browser Extensions (Chromium + Firefox, shared codebase)
│   ├── shared/                 # 95% of code: SolidJS popup, service worker, content script, nmh wrapper, autofill, pair
│   ├── chrome/                 # Chrome MV3 wrapper (manifest.extra.json)
│   └── firefox/                # Firefox MV3 wrapper (manifest.extra.json)
├── mobile/                     # Kotlin Multiplatform Mobile App (Compose UI + UniFFI integration)
│   ├── shared/                 # Common Compose UI, ViewModels, repository, and platform implementations
│   └── androidApp/             # Android host application (single-Activity, BaluardAutofillService, BaluardAccessibilityService, BaluardA11yTileService, adaptive icons, R8 rules)
└── docs/                       # Architecture, design, plans, PRDs, threat model, post-quantum, 2fa, brand, app icons
```

---

## 2. Single-String Protobuf Gateway

**Current state**: Protobuf gateway fully wired. CLI has dual-mode (daemon-first + `--direct` fallback). Daemon has ~72 routes (vault CRUD, sync, devices, folders, TOTP, settings, SSH key generation, avatar, tags, providers, vaults host, autosync, bridge, passkey, biometric, pin, clone, favicon). Tauri desktop with full CRUD UI, i18n (en/es). Browser extensions (Chromium + Firefox) connect via the `baluard-nmh` native messaging host: stdio-JSON over the browser API, varint-protobuf over the daemon socket.

**Target state**: All application tiers (Tauri Webview, CLI, KMP Mobile, Browser Extension) communicate with baluard-core through a serialized Single-String Protocol Buffer Gateway:

```rust
// crates/baluard-daemon/src/handler.rs (target)
pub async fn handle_request(action: &str, payload: &[u8]) -> Result<Vec<u8>, BaluardError> {
    // 1. Deserialize payload to the corresponding Protobuf schema
    // 2. Route action to the appropriate baluard-core module
    // 3. Serialize response back to Protobuf
    // 4. Return bytes
}
```

### Mobile Direct Binding (UniFFI)

On mobile, the Protobuf gateway is bypassed. UniFFI generates direct Kotlin and Swift bindings over `baluard-runtime` and `baluard-core`:

```kotlin
val entries = vaultRepository.listCiphers()
val decrypted = vaultRepository.getCipher(cipherId)
```

### Mock Engine Support (Planned)
For front-end contributors, both the Tauri Desktop UI and the KMP Mobile UI will support a `MOCK_BACKEND=true` build flag.
- When enabled, the UI bypasses native compilation entirely.
- The UI feeds hardcoded Protobuf strings directly to frontend components.

---

## 3. Platform Tier Architecture

### 3.1 Desktop Tier (B2C & B2B)

**Current state**: CLI dual-mode (daemon-first via socket + `--direct` fallback). Daemon fully implemented with multi-vault host, sync coordinator, devices, TOTP, auto-lock, auto-sync (debounced push + event-driven pull + 30-min idle fallback + offline retry + conflict auto-resolve), PIN escrow, biometric unlock (per-vault scoped), bridge module for browser extension. Tauri desktop with full CRUD UI, 8 cipher types, generator, TOTP widget, multi-vault switcher, browser-extension pairing UI, conflict resolution panel, vault detach.

**Implemented**:
- **Rust Daemon (`baluard-daemon`)**: Started by the Tauri tray wrapper on boot. Unlocks the vault directly in `zeroize`-protected memory. Opens a platform-aware Unix domain socket (Linux: `$XDG_RUNTIME_DIR/baluard/baluard.sock`, macOS: `~/Library/Application Support/baluard/baluard.sock`) with 0600 permissions (set via umask before bind to avoid TOCTOU race). Listens for length-delimited Protobuf requests via tokio async I/O. SO_PEERCRED peer UID verification on Linux. **VaultHost multi-vault (Phase 6)**: single `RwLock<VaultHostInner>` over `HashMap<String, Arc<VaultState>>` + `active: Option<String>` pointer (one critical section). Per-vault session tokens; `vault.unlock` returns `{slug, token}`. Auto-lock walker iterates the map every 30s. Cover-commit timers are per-vault, keyed to locked/unlocked (never to active). Lock-all on `Tauri WindowEvent::Focused(false)`; OS suspend/screen-lock hooks documented as follow-up. `log_mlock_budget` reports resident key bytes + RLIMIT_MEMLOCK after every unlock.
- **CLI (`baluard-cli`)**: Dual-mode binary. Default: compiles flags into Protobuf, transmits over socket, prints response. `--direct` fallback links baluard-core in-process. `--socket <path>` for custom daemon path. `--vault <slug>` targets a specific vault (uses daemon if open in map, `--direct` otherwise). Commands: `init`, `unlock`, `lock`, `add`, `tags`, `get`, `list`, `edit`, `delete`, `archive`, `folders`, `sync`, `import`, `export`, `health`, `attach-*`, `devices`, `passkey`, `vaults`, `provider`, `ssh-key`, `biometric`, `pin`, `bridge`, `ping`.
- **Tauri v2 UI**: SolidJS/Tailwind v4 webview. `daemon_request` Tauri command (async + `spawn_blocking`) proxies to daemon via Protobuf over Unix socket. System tray with Show/Quit menu (monochrome support). Full cipher CRUD with 8 types (Login, Card, Identity, SSH Key, Secure Note, Bank Account, Driver's License, Passport/ID). Password generator (CSPRNG + EFF 7776-word passphrase). TOTP code widget with boundary-aligned refresh. Auto-lock settings. Dark/light/system themes. Nested folders. Import/export (8 formats). Device fleet dashboard. **Biometric unlock (per-vault scoped)** via `security-framework` v3 (macOS `SecAccessControl BIOMETRY_ANY`) + `keyring` crate (other platforms). **Session PIN** (Linux + Windows-without-Hello fallback): in-memory `PinEscrow` on `VaultState`, 5-strike nuke, survives soft-lock, dies on close/restart. SSH key generation (Ed25519/ECDSA P-256; RSA 4096 removed in L7 fix for RUSTSEC-2023-0071). User profile (display name, subtitle, avatar). Tag management with sidebar pills. Modal accessibility (FocusTrap on 9 modals). Full i18n (English + Spanish). Toast notifications. Vault creation wizard (3-step: language+password, recovery phrase, profile+preferences). **Multi-vault switcher** (`VaultSwitcher` dropdown, 30s heartbeat, per-vault unlock screen via `SwitchUnlockModal`). **Vault detach** (`DetachVaultModal`: safe detach only; destructive arm CLI-only). **Favicons** (opt-in persisted website icons fetched at save time). **Auto-sync**: sidebar header shows provider + repo link (`SyncTab` one-click UI replaces git jargon); `AutoSyncIndicator` status pill (idle/syncing/dirty/offline). **Conflict resolution panel** (top-floating, drives on destructive field-level merge outcomes). **Browser extension pairing** (`BridgeTab`: list, pair new, revoke; approve-don't-type flow). Global browser-autofill suppression (`disableAutofill.js`, opt-in via `data-autofill="on"`).

### 3.2 Mobile Tier (B2C)

**Current state**: Android Phases 0-6 implemented. Compose Multiplatform codebase compiles to native Android and iOS targets. Consumes `baluard-runtime` and `baluard-core` in-process via `baluard-uniffi` bindings (no background daemon on mobile). Onboarding (new vault and git provider clone + device enrollment), home hub with categories and count pills, filtered entry lists, detail/edit for all 8 cipher types at desktop parity, deep search, password generator, TOTP widget, biometric unlock, auto-lock, sync feedback, settings (including favicon opt-in), and full system autofill integration are operational. Phase 7 (iOS AutoFill extension) is next.

**Architecture properties**:
- **KMP UI**: Shared Android/iOS screens written in Compose Multiplatform.
- **UniFFI Bindings**: `baluard-uniffi` exposes `baluard-runtime` and `baluard-core` to Kotlin and Swift without manual JNI boilerplate.
- **In-process runtime**: The mobile app hosts the runtime directly in-process; no local daemon or socket layer.
- **Isolated Autofill Service (`:autofill`)**: System autofill provider (`BaluardAutofillService`) runs in its own process. Unlocks via biometric-gated KEK (`unlock_with_kek`) to avoid the high-memory Argon2id KDF on memory-constrained service paths. Inline suggestions and dropdowns presentation.
- **Offline-first fill path**: `onFillRequest` matches against local decrypted login metadata (`VaultState::autofill_query`) with no network calls or sync operations on the critical path.
- **Save handoff**: `onSaveRequest` routes new credential creation to the main app via a single-use token (`AutofillSaveToken`).
- **Accessibility fill tile**: `BaluardA11yTileService` + `BaluardAccessibilityService` offer quick-settings tile fill for browsers and applications that do not support Android Autofill APIs.

---

## 4. Key Lifecycle & Cryptographic Design

### 4.1 Key Types Summary

| Key Type | Primitive | Stored Where | Purpose | Lifetime / Rotation |
|----------|-----------|--------------|---------|---------------------|
| **Master Password** | Plaintext user input | Never stored | Derived into Master KEK | Ephemeral in RAM; discarded after KDF |
| **Master KEK** | Argon2id, 256-bit | Process memory (`zeroize`-protected) | Decrypts escrowed Device Private Key | Purged on vault locking or daemon exit |
| **Device Private Key** | X25519, 256-bit | Decrypted: `zeroize` buffer. Escrowed: `meta/device-privkey.json` (or OS keyring) | Decrypts Space Group Key from access list | Permanent; wrapped with Master Password in repo |
| **Space Group Key** | AES-256-GCM | Decrypted: `zeroize` buffer. Wrapped: `meta/access_list.json` | Encrypts entries and lookup index (`index.enc`) | Rotated on member offboarding or manual rekey |
| **Item Keys** | 256-bit | Derived per-cipher via HKDF | Encrypts individual cipher entries | Epoch-bound; re-derived on root key rotation |
| **Commit Signing Key** | Ed25519 | Private: Escrowed in repo. Public: Git host / Access List | Cryptographically signs Git commits | Permanent; bound to Digital Identity |

### 4.2 Key Wrapping & Escrow Mechanics

#### Private Key Escrow (`meta/device-privkey.json`)

To support bootstrap on new devices without manual peer-to-peer verification:

1. When a vault (Space) is initialized, a unique Device Asymmetric Keypair (X25519/Ed25519) is generated.
2. The private key is symmetrically encrypted using the **Master KEK** (derived via Argon2id).
3. The encrypted private key is committed to the Git repository as `meta/device-privkey.json` (the OS keyring is the preferred live location; this file is the synced fallback).
4. On a new device, the user clones the repo via GitHub/GitLab OAuth, types their Master Password, decrypts the escrowed private key, and imports it to the local OS Keychain / Enclave.

#### Access List Wrapping (`meta/access_list.json`)

Sharing a Space relies on envelope encryption:

1. Every Space possesses a symmetric **Space Group Key** (AES-256-GCM).
2. The `meta/access_list.json` contains a map of member public keys to their corresponding wrapped copies of the Group Key:
   ```json
   {
     "members": [
       {
         "email": "member@example.com",
         "device_id": "uuid-here",
         "public_key": "X25519_PUBLIC_HEX",
         "wrapped_group_key": "HPKE_CIPHERTEXT_HEX"
       }
     ]
   }
   ```
3. A member opens a Space by decapsulating their `wrapped_group_key` with their local escrowed Device Private Key.

### 4.3 Platform Keyring

- **OAuth PAT**: The token is never stored in Git. It is escrowed securely in the host OS Keyring (Keychain on macOS/iOS, Secret Service on Linux, DPAPI on Windows, Android Keystore).
- **Device Digital Identity**: User's asymmetric private key is encrypted using KEK (derived from Master Password via Argon2id) and committed to the repository at `meta/device-privkey.json`.
- **Enrollment Flow**: A user signing in on a new device clones the Space via OAuth, inputs their Master Password to decrypt `meta/device-privkey.json`, extracts their private key, and writes it to the new device's local hardware enclave.

### 4.4 Cryptographic Ceremonies

#### Space Creation Ceremony

1. **Key Generation**: baluard-core generates the X25519 and Ed25519 keys for the first device.
2. **Space Group Key**: baluard-core generates a random 256-bit AES key for the Space.
3. **Escrow wrapping**: Master Password is run through Argon2id to yield KEK; KEK encrypts the private key into `meta/device-privkey.json` (or directly into the OS keyring when the platform supports it).
4. **Access wrapping**: Space Group Key is wrapped with the first device's public key and written to `meta/access_list.json`.
5. **Lookup index**: An empty lookup table is created, AES-GCM encrypted with the Space Group Key, and written to `index.enc`.
6. **Git Initialization**: git2-rs initializes the repository, commits all files (including an initial dummy entry), and pushes to the Git provider using the OAuth PAT stored in the OS Keyring.

#### Member Invitation & Acceptance

1. **Invite**: The Space Admin enters the invitee's email. baluard-core queries the Git provider (GitHub/GitLab) for the invitee's public key.
2. **Wrapping**: baluard-core encrypts the Space Group Key with the invitee's public key, appends the wrapped payload to `meta/access_list.json`, and pushes.
3. **Accept**: The invitee logs in via OAuth, clones the Space, inputs their Master Password to fetch their device identity, decapsulates the Space Group Key from `access_list.json`, and unlocks the local database.

#### Offboarding Rekey Flow

When a member is removed from a Space:

1. **Group Key Rotation**: baluard-core generates a brand new 256-bit Space Group Key.
2. **Re-encryption**: baluard-core decrypts all entries under `entries/` using the old Group Key, pads them to their respective uniform buckets (5KB, 30KB, 100KB, 250KB, 2MB), and re-encrypts them using the new Group Key.
3. **Access List Update**: baluard-core removes the revoked member's public key and entry from `meta/access_list.json`. It re-encrypts the new Group Key for all remaining members using their public keys.
4. **Index Rebuild**: Re-encrypts the lookup index `index.enc` with the new Group Key.
5. **Git Push**: baluard-core commits the re-encrypted entries and the modified metadata files, then pushes the state to the Git provider. The revoked user's local instance is completely locked out of updates, and their local clone contains outdated, unreadable entries.

---

## 5. Security Architecture

- **Single crypto implementation**: All cryptographic operations live in `baluard-core/src/crypto/`. No duplicate implementations across languages.
- **FFI security boundary**: UniFFI's serialization approach provides a clean memory boundary. Rust heap allocations for secrets never share pointers with foreign code.
- **Socket permissions**: Socket born with 0600 via `umask(0177)` before `bind()` (no TOCTOU race between bind and chmod).
- **Graceful shutdown**: Daemon handles both SIGINT and SIGTERM for clean socket removal and vault zeroization.
- **Zeroize**: All passwords zeroized server-side (handler) and client-side (CLI unlock, Tauri proxy). `zeroize` crate with `derive` feature for guaranteed memory scrubbing via `write_volatile` + `compiler_fence`.
- **Capability broker**: The daemon is the sole trust boundary. Clients receive scoped, opaque capabilities (per-vault session token, derived TOTP code, signed passkey assertion), never raw key material. A same-UID process that missed the unlock exchange is refused. See `docs/threat-model.md` § Design Principle.
