# PROJECT KNOWLEDGE BASE

**Updated:** 2026-06-12

## OVERVIEW
Project: **Baluard** (Git-native password manager)
Stack: Rust (core crypto + CLI + daemon), SolidJS/Tailwind/Tauri v2 (desktop), Protobuf (IPC schema)
License: GPL-3.0

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets.

**Platforms**: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell.

## STRUCTURE
```
baluard/
├── crates/
│   ├── baluard-core/             # Core library: crypto, keys, vault, sync
│   │   └── src/
│   │       ├── crypto/         # KDF (Argon2id), AEAD (AES-256-GCM), HKDF, HPKE, Ed25519, TOTP
│   │       ├── keys/           # Key hierarchy (Root/SGK/Item/Session), epochs, rotation
│   │       ├── vault/          # Vault handle, cipher CRUD, envelope, padding, attachments
│   │       ├── sync/           # Git sync engine (git2-rs), conflict resolution
│   │       ├── providers/      # Git providers: ForgeProvider trait (github, gitlab, codeberg), OAuth device/web flow, PAT, keyring tokens, providers.json
│   │       ├── import/         # Import parsers (8 formats) + export (2 formats)
│   │       ├── crypto/webauthn/  # FIDO2/WebAuthn ceremony: store.rs, ceremony.rs, mod.rs
│   │       ├── device_manager.rs # Device fleet: registry, rotation, activity, enrollment
│   │       ├── paths.rs        # Platform-correct base dirs (data, socket, logs, token)
│   │       ├── types.rs        # CipherKind, CipherInput, CipherMeta, CustomFieldType, etc.
│   │       └── error.rs        # BaluardError enum
│   ├── baluard-cli/              # CLI (clap) — daemon-first with --direct fallback
│   │   └── src/
│   │       ├── main.rs         # Command dispatch
│   │       ├── client.rs       # Protobuf socket client
│   │       └── commands/       # Dual-mode handlers
│   └── baluard-daemon/           # Background IPC daemon
│       └── src/
│           ├── main.rs         # Socket listener, SIGINT/SIGTERM, 0600 perms
│           ├── handler.rs      # Protobuf routing, token-gated IPC
│           └── state.rs        # VaultState (Arc<RwLock>), auto-lock
├── desktop/                    # Tauri v2 + SolidJS frontend
│   └── src/
│       ├── App.jsx             # Root component (thin provider wrapper)
│       ├── components/         # UI components (VaultView, CipherDetail, SshKeyGenerator, SetupScreen, etc.)
│       ├── context/            # AuthContext, VaultContext, themeSignal, toastSignal
│       ├── lib/                # daemon.js, payload.js, cipherSchema.js, filters.js, utils.js, helpers.js, biometry.js, clipboard.js, vaultPrefetch.js, eff-words.js, wordlist-{en,es}.js
│       ├── __tests__/          # vitest tests (payload, utils, filters, cipherSchema)
│       └── i18n/locales/       # en.json, es.json (all user-facing strings)
├── proto/                      # Protobuf schemas (compiled via prost)
│   ├── vault.proto
│   ├── space.proto
│   └── auth.proto
├── docs/                       # Architecture & design docs
└── justfile                    # Build system
```

## COMMANDS
| Action | Command |
|--------|--------|
| Build (debug) | `just build` |
| Build (release) | `just build-release` |
| Run all tests | `just test` |
| Core tests only | `just test-core` |
| Full CI check | `just check` |
| Format | `just fmt` |
| Lint (clippy) | `just lint` |
| Format check | `just fmt-check` |
| Lint fix | `just lint-fix` |
| Install to ~/.local/bin | `just install-local` |
| Install to /usr/local/bin | `just install` |
| Desktop dev server | `just desktop-dev` |
| Desktop debug mode | `just desktop-debug` |
| Desktop production build | `just desktop-build` |
| Desktop npm deps | `just desktop-deps` |
| Clean | `just clean` |

## MINIMUM PLATFORM COMPATIBILITY

All code must run on these platforms at minimum. No APIs, crates, or features that require newer versions.

| Platform | Minimum Version | Notes |
|----------|----------------|-------|
| macOS | 15 (Sequoia) | Apple Silicon + Intel. Security framework SecAccessControl + Touch ID. |
| Windows | 11 (2025 update) | Windows Hello (PIN + biometric). Credential Manager via keyring. |
| Ubuntu | 26.04 | libsecret / Secret Service API for keyring. |
| Fedora | 43 | libsecret / Secret Service API for keyring. |

Implications:
* Rust edition 2024, MSRV 1.85 (ships in all targets above).
* macOS: `security-framework` v3 + SecAccessControl BIOMETRY_ANY. No APIs deprecated after macOS 15.
* Linux: `keyring` crate with `linux-native` + `sync-secret-service` + `crypto-rust`. Requires `libsecret` dev packages at build time.
* Windows: `keyring` crate with `windows-native`. Windows Credential Manager via DPAPI.
* Tauri v2 WebView2: bundled on Windows, WebKit on macOS/Linux (system-provided on these versions).

## CODING STANDARDS
* **Rust**: Edition 2024, MSRV 1.85. Feature flags: `full` (default) = `git-sync` + `org` + `emergency`. `thiserror` for library errors, `anyhow` for CLI. `proptest` for property-based tests.
* **JS/TS**: ES modules, SolidJS, Vite. Tailwind for layout. `crypto.getRandomValues` only (never `Math.random`).
* **Protobuf**: proto3, `baluard.vault` package. Compiled via prost in daemon + CLI.
* **Security**: AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket 0600. Zeroize on drop for key material, TOTP secrets, and passkey private keys.
* **WebAuthn/Passkey**: passkey-rs 0.5.x for ceremony. ES256 only. Private key encrypted under item key, never crosses IPC, zeroized on drop. Counter `max(local, remote)` for git-sync safety.

## DEBUG LOGGING
`just desktop-debug` runs the desktop app with `BALUARD_DEBUG=1`. Logs go to `./logs/` at cwd.
* `daemon.log` -- IPC routing, vault CRUD, serde errors, crypto ops (via `env_logger`)
* `desktop.log` -- Tauri bridge: every daemon request with action, payload size, success/error (via `tauri-plugin-log`)

Env vars (set automatically by `just desktop-debug`):
* `BALUARD_DEBUG=1` -- enables Debug level (otherwise Warn only)
* `BALUARD_LOG_DIR=<path>` -- overrides log directory (defaults vary by platform: `$XDG_STATE_HOME/baluard/` on Linux, `~/Library/Logs/baluard/` on macOS, `%LOCALAPPDATA%\baluard\logs\` on Windows)

Share logs: paste the file contents or `zip logs/ logs.zip`.

## WHERE TO LOOK
* **Crypto primitives**: `crates/baluard-core/src/crypto/`
* **Key hierarchy & lifecycle**: `crates/baluard-core/src/keys/`
* **Vault CRUD & format**: `crates/baluard-core/src/vault/`
* **Platform paths (data, socket, logs)**: `crates/baluard-core/src/paths.rs`
* **CipherKind & data structs**: `crates/baluard-core/src/types.rs`
* **Git sync**: `crates/baluard-core/src/sync/`
* **Git providers (ForgeProvider trait, OAuth/PAT)**: `crates/baluard-core/src/providers/`
* **CLI commands**: `crates/baluard-cli/src/commands/mod.rs`
* **Daemon IPC**: `crates/baluard-daemon/src/handler.rs`
* **Daemon vault state**: `crates/baluard-daemon/src/state.rs`
* **Desktop frontend**: `desktop/src/App.jsx`
* **Device fleet**: `crates/baluard-core/src/device_manager.rs`
* **Passkey ceremony (WebAuthn)**: `crates/baluard-core/src/crypto/webauthn/`
* **Passkey data structure**: `crates/baluard-core/src/types.rs` (`PasskeyData`)
* **Passkey plan**: `docs/plan-passkey-support.md` (authoritative)
* **Git provider app registration & tokens**: `docs/git-provider-apps-and-tokens.md`
* **Git provider sync plan**: `docs/plan-git-providers-multi-vault.md`
* **Post-quantum readiness**: `docs/post-quantum-readiness.md` (PQC status: data-at-rest PQ-safe, identity layer is the gap)
* **Protobuf schemas**: `proto/`

## KEY CONCEPTS

### Key Hierarchy
Master Password -> KEK (Argon2id) -> Device Private Key (X25519, HPKE-escrowed) -> Root Key (512-bit, per-epoch) -> Space Group Key (256-bit) -> Item Keys (256-bit, HKDF-derived).

### CipherKind
Serde-tagged enum: `#[serde(tag = "type", content = "data")]`. 8 variants: Login, Card, Identity, SshKey, BankAccount, DriversLicense, Passport, SecureNote. Invalid states unrepresentable. Tagged JSON: `{type: "login", data: {...}}`. **Passkeys are embedded inside `LoginData::fido2_credentials: Option<Vec<PasskeyData>>`** (Bitwarden-compatible model, no standalone Passkey variant in CipherKind).

### CipherMeta
`vault.list` returns `CipherMeta` with `id`, `name`, `cipher_type`, `favorite`, `username`. Desktop uses `vault.list_full` (batch endpoint: all decrypted ciphers + folders + trash + archived in 1 IPC call) instead of N+1 `vault.list` + N×`vault.get`.

### Daemon Wire Format
JSON strings inside `GatewayRequest.payload`. `get_cipher` returns BOTH nested `kind` object AND flat top-level fields. `update_cipher` parses `kind` from payload (does NOT clone existing kind). `vault.list_full` returns all decrypted ciphers + folders + trash + archived in a single IPC call (used by desktop for fast unlock).

### IPC
Unix domain sockets. 0600 via umask. Peer credential verification (SO_PEERCRED/getpeereid). `--socket` overrides default. Token-gated: 256-bit session token on unlock, constant-time comparison. All platform paths centralized in `baluard_core::paths` (`crates/baluard-core/src/paths.rs`).

### Padded Buckets
5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()`. Prevents metadata leakage.

### Device Lifecycle
Epoch state machine: CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED. `revoke_device_and_rekey()` performs full rotation: validates preconditions, writes crash marker, re-encrypts all ciphers + attachments, writes keywrap, updates in-memory state. `rotate_root_key()` for non-revocation rotation. Recovery via BIP-39 phrase.

### CLI Dual-Mode
All vault commands route through daemon by default. `--direct` falls back to baluard-core in-process. `--socket <path>` accepts custom socket.

### Attachments
AES-256-GCM encrypted with cipher's item key. Max 2MB. Stored at `<vault>/entries/<cipher_id>/attachments/<id>.enc`. Plaintext zeroized after use.

### SSH Key Generation
Daemon-side via `ssh-key` crate. 2 key types: Ed25519 (default/recommended), ECDSA P-256 (FIPS compliance). RSA 4096 removed in L7 fix (the `rsa` crate had RUSTSEC-2023-0071 Marvin Attack, no upstream fix). Returns OpenSSH public key, SHA256 fingerprint, OpenSSH private key PEM. Private key material never crosses IPC boundary.

### User Profile
Display name, subtitle, avatar stored in `VaultSettings`. Avatar as file in vault (`meta/avatar.{ext}`). Sidebar reads from VaultContext profile signals. SettingsModal syncs on close via `createEffect`.

### Vault Creation Wizard
Multi-step wizard for both CLI and desktop. CLI: `baluard init` with `--profile`, `--name`, `--slug`, `--theme`, `--lang`, `--auto-lock` flags + interactive fallback. Desktop: 3-step flow (language+password -> recovery phrase -> profile+preferences). `VaultCreator` builder chains `.profile()` + `.preferences()` on `execute()`. Desktop applies post-creation via `settings.set` + `locale.save` IPC. `--subtitle` was removed (2026-06-11) after the profile step absorbed it.

### ThemeMode
Typed enum (`Light`/`Dark`/`System`) replacing `Option<String>` on `VaultSettings.theme`. Case-insensitive serde for backward compat. Default: `System`.

### Locale Persistence
Language stored in two places: encrypted `VaultSettings.lang` (post-unlock) + plaintext `meta/locale` (pre-unlock, login screen). `locale.save` daemon route writes plaintext file.

### Modal Accessibility
All modals use `<FocusTrap>` component: `role="dialog"`, `aria-modal`, `aria-labelledby`, Tab/Shift+Tab trap, Escape dismiss, auto-focus first interactive element, restore focus on close. Applied to: DeleteConfirm, ArchiveConfirm, Reprompt, Generator, Settings, EmptyTrash, SetupScreen.

### Auth State Machine
7 states: `locked`, `unlocking`, `unlocked`, `init`, `creating`, `recovery`, `setup`. Wizard flow: `init` -> `creating` -> `recovery` -> `setup` -> `unlocked`. `setup` state added for post-creation profile/preferences step.

### Tag Deletion
Hover X on sidebar tag pills triggers confirmation modal. Calls `tag.delete` daemon command. Removes tag from all ciphers + rebuilds index.

### Passkeys (FIDO2/WebAuthn)
Passkeys are stored **inside `LoginData::fido2_credentials: Option<Vec<PasskeyData>>`** (Bitwarden-compatible, no standalone cipher variant). A single Login can hold multiple passkeys (e.g. one for YubiKey, one for iPhone). BW imports embed fido2 credentials directly in Login. Each `PasskeyData` contains: `credential_id`, `key_type`, `key_algorithm`, `key_curve`, `key_value` (COSE public key), `rp_id`, `rp_name`, `user_handle`, `user_name`, `user_display_name`, `counter`, `aaguid`, `prf_key`, `private_key` (encrypted under item key), `private_key_missing`, `linked_login_id`, `creation_date`, `name` (per-credential display name).

- **Algorithm**: ES256 only (passkey-rs 0.5.x limitation)
- **WebAuthn library**: `passkey-rs` 0.5.x (1Password), wraps `coset` for COSE
- **Ceremony module**: `crates/baluard-core/src/crypto/webauthn/` (mod.rs, store.rs, ceremony.rs)
- **Daemon IPC**: 7 routes (list, delete, rename, challenge_register, finish_register, challenge_assert, finish_assert). All token-gated.
- **State cache**: `CeremonyCache` (300s TTL, max 64 pending, FIFO eviction, OsRng challenges)
- **CLI**: `baluard passkey list/delete/rename`. `--credential-id` required for delete/rename.
- **delete/rename semantics**: take `(cipher_id, credential_id)`. Only the matching `PasskeyData` is removed/renamed. Login cipher itself is preserved unless it has no other data (no password, no TOTP, no URIs) and only one passkey is removed.
- **Private key**: encrypted under cipher item key, never crosses IPC, zeroized on drop
- **Counter**: `max(local, remote)` on git-sync. `PasskeyIndex` indexes all ciphers' fido2 credentials for fast lookup during assertion.
- **Two-phase ceremony** (Phase 1 trust model): `challenge_*` runs the ceremony + caches state, `finish_*` consumes state + persists cipher. Echo-back of passkey_data accepted in Phase 1 (same-process desktop). Phase 2 (browser extension) MUST store results in `CeremonyState` to prevent client forgery — see SEC-1 in `docs/plan-passkey-support.md`.
- **BaluardCredentialStore** trait impl: bridges passkey-rs `CredentialStore` to cipher envelopes. `Arc<Mutex<StoreInner>>` for mutation tracking via `take_new_credentials()` + `take_counter_updates()`.

## GOTCHAS
* **Password history**: Auto-appended on password change. Cap 10 entries (FIFO).
* **Folder depth**: Max 16 levels. `delete_folder` cascades via BFS descendant collection.
* **TOTP**: Seed NEVER crosses IPC. Only derived numeric code sent to frontend.
* **`RotationGuard`**: RAII guard cleans up `.tmp` files and crash marker on error. Disarmed after successful atomic commit.
* **CodeGraph available**: `.codegraph/` index exists. Route codebase exploration through CodeGraph tools when available.
* **Feature flags control sync**: `git-sync` feature gate; CLI enables it by default.
* **SSH key generation**: Private key material generated daemon-side via `ssh-key` crate. Only formatted OpenSSH strings cross IPC.
* **Avatar storage**: Unencrypted `meta/avatar.{ext}` in vault directory. Vault encrypts at rest; avoids bloating settings.json diffs. Ext validated against whitelist (png/jpg/jpeg/gif/webp), 350KB base64 cap.
* **Profile data**: Stored in `VaultSettings` (`meta/settings.json`). `display_name`, `subtitle`, `avatar_ext` fields.
* **Toast notifications**: `toastSignal.js` standalone signals. All user feedback via toasts, not inline text.
* **i18n**: All user-facing strings use `t()` keys. Both `en.json` and `es.json` must stay in sync. No hardcoded strings.
* **FocusTrap**: All modals use `<FocusTrap>` component for keyboard accessibility (Tab trap, Escape dismiss, auto-focus, restore focus).
* **Locale file**: `meta/locale` is plaintext (not secret data). Needed before vault unlock for login screen i18n. Written by both CLI (`VaultCreator`) and desktop (`locale.save` IPC).
* **Auth `setup` state**: Recovery screen transitions to `setup` (not `unlocked`). SetupScreen unlocks vault + applies profile/prefs before transitioning to `unlocked`.
* **Passkey embedded in Login**: No standalone `CipherKind::Passkey` variant. Passkeys live in `LoginData::fido2_credentials`. `passkey.delete` and `passkey.rename` take `credential_id` (base64url) as a required arg to identify which passkey in a multi-credential Login. `passkey.list` returns `login_name`, `has_password`, `pk_name` per passkey for context.
* **Passkey private key storage**: Encrypted under the Login's item key, never crosses IPC. BW imports mark `private_key_missing: true` (re-register needed). Zeroized in vault handle's cipher zeroize match block.
* **WebAuthn ceremony trust model (Phase 1)**: `passkey_data` is echoed from `challenge_*` to `finish_*` in Phase 1 (same-process desktop = trusted). Phase 2 (browser extension = untrusted) MUST store results in `CeremonyState` to prevent counter forgery + cross-RP credential update.
* **Git provider default client_ids are placeholders**: GitLab (`REPLACE_WITH_GITLAB_CLIENT_ID`) + Codeberg (`REPLACE_WITH_CODEBERG_CLIENT_ID`) are sentinels, not real OAuth apps. Replace before the automatic flows work for third-party users. Users can override via Advanced Options in the meantime.
* **Git provider device flow scope**: GitLab requires the `api` scope for `POST /projects` (repo creation). `read_repository`/`write_repository` are insufficient. Broad but unavoidable; documented at connect time.
* **Codeberg OAuth = full account access**: Forgejo OAuth2 tokens have no scope support. The scoped PAT (`write:repository`) is more secure. Desktop surfaces `codebergFullAccessWarning` at connect.
* **connect_pat config ordering**: `parse_provider_config` MUST run before `req.payload.zeroize()` (B2 fix) or Advanced Options overrides are silently dropped.
* **GitLab token refresh is rolling**: GitLab invalidates the prior access+refresh pair on refresh. Concurrent refreshes must be serialized (per-provider mutex in `ensure_valid_token`).
* **Web-OAuth session keyed by provider**: `OAUTH_SESSIONS` is `HashMap<Provider, OAuthSession>`, not a single global Option (B1 fix). Restarting a flow for the same provider aborts the prior callback listener (JoinHandle abort, frees the port).
* **Codeberg endpoint**: use `/user/repos` (returns array directly). `/repos/list` does not exist; `/repos/search` wraps in `{ok, data}`.

## UX PRINCIPLES
* **Plain language**: No hard tech terms in user-facing UI. "Cipher" -> "entry", "UUID" -> hidden.
* **No server backend**: Desktop and mobile apps work standalone/offline. Git sync is optional.
* **i18n**: All user-facing strings in `desktop/src/i18n/locales/en.json` and `es.json`. Use `t("key")` in components. Both files must stay in sync.
