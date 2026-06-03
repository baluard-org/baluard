# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-31 | **Updated:** 2026-06-02

## OVERVIEW
Project: **IDtty** (Git-native password manager / Space Manager)
Stack: Rust (core crypto + CLI + daemon), SolidJS/Tailwind/Tauri v2 (desktop), Kotlin Multiplatform via UniFFI (mobile, planned), SolidJS (browser extension, planned), Protobuf (IPC schema, wired)
License: GPL-3.0

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets. Mobile apps will bind directly to the Rust core via UniFFI-generated Kotlin/Swift bindings.

**Supported platforms**: Windows, Linux (deb/rpm), macOS, Android, iOS. CLI: bash, zsh, PowerShell.

## STRUCTURE
```
idtty/
├── crates/                     # Rust workspace
│   ├── idtty-core/             # Core library: crypto, vault format, key lifecycle, git sync
│   │   └── src/
│   │       ├── crypto/         # KDF (Argon2id), AEAD (AES-256-GCM), HKDF, HPKE, Ed25519, TOTP (RFC 6238)
│   │       ├── keys/           # Key hierarchy (Root/Item/Session), epochs, rotation, nonces
│   │       ├── vault/          # Vault handle, cipher CRUD, envelope format, creation ceremony, padding, attachment encrypt/decrypt
│   │       ├── sync/           # Git sync engine (git2-rs), commit, conflict resolution, state machine
│   │       ├── import/         # Import parsers (8 formats) + export (2 formats)
│   │       ├── health.rs       # Password health analysis (weak/reused/old)
│   │       ├── biometric.rs    # OS keychain biometric unlock (keyring crate)
│   │       ├── devices.rs      # Device registry (enrollment, public keys)
│   │       ├── emergency.rs    # Emergency access / break-glass
│   │       ├── integrity.rs    # Canary checks (KEK/RK verification)
│   │       ├── orgs.rs         # Organization / team sharing
│   │       ├── providers.rs    # Credential provider abstraction
│   │       ├── recovery.rs     # BIP-39 recovery phrase
│   │       ├── types.rs        # CipherKind, CipherInput, CipherMeta, CustomFieldType (incl Linked), AttachmentMeta, etc.
│   │       └── error.rs        # IdttyError enum
│   ├── idtty-cli/              # CLI binary (clap) - daemon-first with --direct fallback
│   │   └── src/
│   │       ├── main.rs         # Command dispatch, --direct/--socket flags
│   │       ├── client.rs       # Protobuf socket client (request_to)
│   │       └── commands/       # Dual-mode handlers (daemon + direct)
│   └── idtty-daemon/           # Background IPC daemon (vault state + Protobuf gateway)
│       └── src/
│           ├── main.rs         # Socket listener, SIGINT/SIGTERM, 0600 perms, auto-lock timer
│           ├── handler.rs      # Protobuf routing, password zeroize, varint framing, token-gated actions
│           └── state.rs        # VaultState (Arc<RwLock<Option<VaultHandle>>>), auto-lock, activity tracking
├── desktop/                    # Tauri v2 desktop app (full CRUD, 8 cipher types, generator, auto-lock, TOTP, attachments, nested folders, biometric, custom fields)
│   └── src/
│       ├── App.jsx             # SolidJS frontend (2500+ lines)
│       ├── i18n/               # Internationalization (en.json + template)
│       └── main.jsx            # Entry point
├── mobile/                     # Kotlin Multiplatform mobile app [PLACEHOLDER]
│   └── build.gradle.kts        # KMP targets: Android, iOS (x64/arm64/sim)
├── extension/                  # MV3 browser extension (SolidJS thin client) [PLACEHOLDER]
│   └── package.json            # vite, solid-js
├── proto/                      # Shared Protobuf schemas (compiled into Rust via prost)
│   ├── vault.proto             # VaultEntry, CustomField
│   ├── space.proto
│   └── auth.proto
├── plans/                      # Implementation plans (bw-parity.md)
├── docs/                       # Architecture & design docs (see docs/index.md)
│   ├── index.md                # Documentation TOC
│   ├── progress.md             # Master progress document
│   ├── architecture-decisions.md  # Design rationale (DOMAIN 1-6)
│   ├── threat-model.md         # Adversaries, attack surfaces, mitigations
│   ├── software-architecture.md   # Components, IPC, key lifecycle, ceremonies
│   ├── dev-setup.md            # Prerequisites, build commands, troubleshooting
│   ├── 2fa-analysis.md         # TOTP RFC 6238/4226, second-factor roadmap
│   ├── brand-guidelines.md   # Color palette, design tokens, visual identity rules
│   ├── full-gaps.md            # Gap analysis: docs vs code
│   ├── prd-bitwarden-parity.md # BW parity PRD (43 user stories)
│   └── bw-parity.md            # Original analysis
└── justfile                    # Build system (just, cargo install just)
```

## COMMANDS
| Action | Command |
|--------|--------|
| List all targets | `just` |
| Build entire workspace (debug) | `just build` |
| Build release | `just build-release` |
| Build + codesign | `just build-signed` |
| Run all tests | `just test` |
| Run core tests only | `just test-core` |
| E2E smoke test | `just e2e` |
| Full CI check | `just check` |
| Format | `just fmt` |
| Lint (clippy) | `just lint` |
| Install to ~/.local/bin | `just install-local` |
| Install to /usr/local/bin | `just install` |
| Desktop dev server | `just desktop-dev` |
| Desktop production build | `just desktop-build` |
| Release archives | `just release` |
| Clean | `just clean` |
| Show version | `just version` |

## CODING STANDARDS
* **Rust**: Edition 2024, MSRV 1.85. Workspace deps in root `Cargo.toml`. Feature flags: `git-sync`, `org`, `emergency`. `thiserror` for library errors, `anyhow` for CLI. `proptest` for property-based tests.
* **JS/TS**: ES modules, SolidJS, Vite. Tailwind utility classes for layout. `crypto.getRandomValues` for all random generation (never `Math.random`).
* **Kotlin**: KMP 1.9.20, Android compileSdk 34, iOS multi-target. Compose Multiplatform for shared UI.
* **Protobuf**: proto3 syntax, `idtty.vault` package. Compiled into Rust types via prost in idtty-daemon.
* **Security**: AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket permissions 0600 (umask before bind). Zeroize on drop for key material and TOTP secrets.

## WHERE TO LOOK
* **Rust crypto primitives**: `crates/idtty-core/src/crypto/` (includes `totp.rs`)
* **Key hierarchy & lifecycle**: `crates/idtty-core/src/keys/`
* **Vault CRUD & format**: `crates/idtty-core/src/vault/`
* **CipherKind sum type & data structs**: `crates/idtty-core/src/types.rs`
* **Git sync engine**: `crates/idtty-core/src/sync/`
* **CLI commands**: `crates/idtty-cli/src/commands/mod.rs` (dual-mode: daemon + direct)
* **CLI socket client**: `crates/idtty-cli/src/client.rs`
* **Daemon IPC handler**: `crates/idtty-daemon/src/handler.rs` (token-gated routes)
* **Daemon vault state**: `crates/idtty-daemon/src/state.rs` (CRUD, auto-lock, TOTP code gen)
* **Desktop frontend**: `desktop/src/App.jsx` (all UI components)
* **Design docs**: `docs/architecture-decisions.md` (authoritative for all decisions)
* **Protobuf schemas**: `proto/` (compiled by prost-build in daemon + CLI)
* **Device fleet visibility**: `crates/idtty-core/src/device_manager.rs` (activity index, abort markers, selective revoke)
* **Device fleet architecture**: DOMAIN 5 in `docs/architecture-decisions.md`

## NOTES
* **Single Rust core**: All crypto, vault format, padding, key lifecycle, and git sync live in `idtty-core`. No duplicate implementations.
* **CipherKind sum type**: `CipherKind` is a serde-tagged enum (`Login(LoginData)`, `Card(CardData)`, `Identity(IdentityData)`, `SshKey(SshKeyData)`, `BankAccount(BankAccountData)`, `DriversLicense(DriversLicenseData)`, `Passport(PassportData)`, `SecureNote`). 8 variants. Invalid states are unrepresentable at compile time. Tagged JSON: `{type: "login", data: {...}}`.
* **CipherMeta for list rendering**: `vault.list` returns `{ciphers: [CipherMeta]}` with `id`, `name`, `cipher_type`, `favorite`, `username`. Frontend renders the list without decrypting full cipher data.
* **Daemon get_cipher response**: Returns BOTH nested `kind` object AND flat top-level fields for backward compat. Frontend reads `kind.card.*`, `kind.identity.*`, etc.
* **update_cipher parses kind from payload**: Does NOT clone existing kind. Allows type-aware field edits through the daemon.
* **Password history**: Auto-appended on password change. Cap at 10 entries (FIFO eviction). `PasswordHistoryEntry { password, last_used_date }`.
* **Folder CRUD**: `list_folders`, `create_folder` (with optional `parent_id` for nesting), `rename_folder`, `delete_folder` (cascades to children, unassigns ciphers). Stored as `folders.json` in vault meta. Max nesting depth: 16.
* **Nested folders**: `parent_id` on Folder struct. Desktop FolderTree component renders recursively. Folder filter includes subfolder ciphers (BFS descendant collection).
* **TOTP code generation**: `crypto/totp.rs` — RFC 6238/4226. SHA1/SHA256/SHA512, 6/8 digits, 30/60s periods. Daemon route `cipher.totp_code <id>` returns `{code, period_seconds, expires_at}` — seed NEVER in response. `TotpParams.secret` zeroized on drop.
* **Auto-lock timer**: Daemon tracks `last_activity` (AtomicU64). Background tokio task checks every 30s. Reads `auto_lock_minutes` from settings (default 15). Locks vault on timeout.
* **CLI dual-mode (daemon-first)**: All vault commands route through the daemon by default. `--direct` flag falls back to idtty-core in-process. `--socket <path>` accepts custom daemon socket.
* **Daemon holds vault state**: Runs tokio Unix socket server with vault CRUD, sync, TOTP, folder ops. Locks vault (zeroizes keys) on SIGTERM. All passwords zeroized via `zeroize` crate.
* **Protobuf schemas compiled**: `proto/*.proto` define the IPC message formats. Rust codegen via prost-build.
* **Mobile via UniFFI (planned)**: Not yet annotated.
* **Feature flags control sync**: `git-sync` feature gate; CLI enables it by default.
* **Padded buckets**: All vault entries padded to uniform sizes (1KB/8KB/64KB/1MB) to prevent metadata leakage.
* **IPC via Unix sockets**: Platform-aware socket path. 0600 via umask. Peer credential verification (SO_PEERCRED/getpeereid). `--socket` overrides default.
* **Key hierarchy**: Master Password -> KEK (Argon2id) -> Device Private Key (escrowed) -> Space Group Key -> Item Keys.
* **BIP-39 recovery**: Vault creation generates a recovery phrase for key recovery.
* **CodeGraph available**: `.codegraph/` index exists for codebase navigation.
* **Import/Export (Phase A)**: 8 import parsers in `import/` (bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, onepassword_1pux, onepassword_csv, keepass_xml). 2 export formats (bw_json, bw_csv). Daemon routes `vault.import`, `vault.export`. CLI `idtty import/export`. Desktop ImportExportButton.
* **Reprompt (Phase B)**: `reprompt: bool` on Cipher, CipherMeta, CipherInput. Daemon `vault.reprompt_verify` (opens temp handle, verifies MP, 30s grant). Desktop RepromptModal + shield icon on entries.
* **Password Health (Phase C)**: `health.rs` detects weak (<8 chars, common, sequential), reused (same password across entries), old (>90 days). Daemon `vault.health`. CLI `idtty health`.
* **Attachments (Phase D)**: `vault/attachment.rs` encrypts with cipher's item key (AES-256-GCM, random nonce). Max 2MB. Stored at `<vault>/entries/<cipher_id>/attachments/<id>.enc`. Daemon upload/download/delete routes. Plaintext zeroized in daemon and CLI after use. AttachmentMeta tracked in cipher JSON.
* **Biometric Unlock (Phase E)**: `biometric.rs` stores master password in OS keychain (keyring crate: macOS Keychain, Windows Credential Manager, Linux libsecret). Daemon `biometric_unlock` performs vault unlock internally (secret never returns over IPC). `biometric_status/enable/disable` routes. Desktop Quick Unlock button + settings toggle.
* **Linked Custom Fields (Phase F)**: `CustomFieldType::Linked(LinkedFieldType)` with 24 variants across Login/Card/Identity. `resolve_linked_field()` for type-safe resolution. Desktop custom field editor with type dropdown + linked field selector. Rust serde format: `"Text"`, `"Hidden"`, `"Boolean"`, `{"Linked":"LoginUsername"}`.
* **Nested Folders (Phase G)**: `create_folder_with_parent` with depth limit (16). `delete_folder` cascades via `collect_descendant_ids` (BFS). Desktop FolderTree/FolderNode recursive components.
* **Device Lifecycle (MISS-1 through MISS-5)**: `device_manager.rs` owns registry, epoch state machine, rotation coordinator. VaultHandle holds a DeviceManager instance. `rotate_root_key()` performs atomic re-encryption with staged `.tmp` writes. `recover_from_phrase()` returns `RecoveryResult` with private keys. `RotationObserver` trait for sync engine hooks. Epoch state machine: CREATED→ACTIVE→ROTATING→RETIRED→DESTROYED. Cipher writes blocked during ROTATING.
* **ItemKey derivation**: `HKDF(SGK, "idtty-item-v1" || epoch || cipher_id)`. SGK derived from RootKey via `HKDF(RootKey, "idtty-sgk-v1" || epoch)`. Epoch-bound: rotation forces full re-encryption. Space Group Key is the intermediate layer between RootKey and ItemKeys.
* **Device Fleet Visibility (Phase 1-5, done)**: Activity index at `meta/device_activity.json` updated on every commit. `last_seen_epoch` on DeviceEntry. Selective revoke via `revoke_device_and_rotate()` (not force-evict). Daemon routes: `device.revoke`, `vault.device_activity`. Abort marker: `.idtty/rekey/{new_epoch}.aborted` (cleaned after detection). Desktop: Devices tab with status badges, "This device" indicator, revoke button (hidden for self). **Known gap**: keywrap file not written after revocation; recovery phrase is fallback.
* **Full gap analysis**: See `docs/full-gaps.md` for comprehensive docs-vs-code diff.

## UX PRINCIPLES
* **Plain language**: No hard tech terms in user-facing UI. "Cipher" -> "entry", "UUID" -> hidden, "session token" -> invisible.
* **Everybody-first**: Every screen must be understandable without a CS degree. If a term needs a tooltip, replace the term.
* **No server backend**: IDtty must NOT depend on any server backend. Desktop and mobile apps work standalone/offline. Git sync with GitHub/GitLab is optional.
* **i18n**: All user-facing strings in `desktop/src/i18n/locales/en.json`. Use `t("key")` in components.

## IMPLEMENTATION STATUS
| Component | Status |
|-----------|--------|
| `idtty-core` crypto/keys/vault | Built, tested, security-reviewed (10 rounds) |
| `idtty-core` device lifecycle | Built, tested, peer-reviewed (MISS-1 through MISS-5, all Critical/High/Medium findings fixed) |
| `idtty-core` sync engine | Built, tested |
| `idtty-core` TOTP (RFC 6238) | Built, tested |
| `idtty-core` import/export | 8 import parsers + 2 export formats, tested |
| `idtty-core` health | Weak/reused/old password detection, tested |
| `idtty-core` biometric | OS keychain unlock via keyring crate, tested |
| `idtty-core` attachments | AES-256-GCM encrypted file storage, tested |
| `idtty-core` Space Group Key | RootKey → SGK → ItemKey hierarchy, tested (7 new tests) |
| `idtty-core` DeviceManager refactoring | DESIGN-1 (pub(crate)), DESIGN-2 (DeviceManagerStore trait), DESIGN-3 (SGK layer) complete |
| `idtty-cli` (dual-mode) | Daemon-first + `--direct` fallback. CRUD + folders + edit + import/export + health + attachments |
| `idtty-daemon` socket server | Protobuf wire, VaultState, full CRUD, TOTP, auto-lock, attachments, biometric, import/export, health, archive, device fleet activity, device revocation. SIGTERM safe |
| Protobuf codegen | Compiled via prost in daemon + CLI build.rs |
| Desktop Tauri app | Full CRUD, 8 cipher types, generator, TOTP widget, auto-lock, nested folders, attachments, biometric unlock, custom fields (incl linked), reprompt, import/export, health, archive, device fleet dashboard, dark/light themes |
| UniFFI annotations | Not yet applied to idtty-core |
| Mobile KMP app | Placeholder |
| Browser extension | Placeholder |


### BW Parity Phases 1-8 (Original)
| Phase | Description | Tests | Peer Reviewed |
|-------|-------------|-------|---------------|
| 1 | CipherKind sum type | 99 | Yes (7 findings) |
| 2 | Multi-URI + match strategy + settings CRUD | 107 | Yes (4 findings) |
| 3 | CipherMeta + vault.update + vault.list | 109 | Yes |
| 4 | Password history (10 cap) + clone | 112 | Yes |
| 5 | Folder CRUD wiring | 115 | Yes (7 findings) |
| 6a | Desktop: Login + SecureNote forms | 115 | Yes (8 findings) |
| 6b | Desktop: Card + Identity forms | 115 | Yes (5 Critical) |
| 6c | Desktop: SSH Key form | 115 | Yes (1 bug) |
| 7 | Generator + auto-lock timer | 115 | Yes (2C, 2H, 1M) |
| 8 | TOTP code generation (RFC 6238) | 130 | Yes (1H, 2M, 4L) |

### Desktop BW Parity Phases A-G (Final Push)
| Phase | Description | Tests | Peer Reviewed | Findings Fixed |
|-------|-------------|-------|---------------|---------------|
| A | Import/Export (8 formats in, 2 out) | 156 | Yes (1C, 2H, 4M) | Yes |
| B | Reprompt (per-entry MP challenge) | 156 | N/A (field addition) | - |
| C | Password Health Reports | 162 | N/A (self-contained) | - |
| D | Attachments (encrypted file storage) | 168 | Yes (2C, 3H, 5M, 3L) | Yes |
| E | Biometric/Quick Unlock via OS Keychain | 170 | Yes (3C, 4H, 3M, 2L) | Yes |
| F | Linked Custom Fields (24 variants) | 170 | Yes (2C, 2H, 2M, 1L) | Yes |
| G | Nested Folders UI (tree + cascade delete) | 170 | Yes (1C, 2H, 2M) | Yes |
