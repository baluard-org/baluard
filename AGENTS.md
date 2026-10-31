# OVERVIEW
Project: **Baluard** (Git-native password manager)
Stack: Rust (core crypto + daemon runtime + CLI + NMH + UniFFI), SolidJS/Tailwind/Tauri v2 (desktop), JS/MV3 (browser extension), Kotlin Multiplatform/Compose (mobile), Protobuf (IPC schema)
License: GPL-3.0

Git-native password manager with padded-bucket encrypted storage, device-identity bootstrapping, and multi-platform UI clients. All secrets flow through a Single-String Protobuf Gateway over Unix domain sockets.
Absolute primary focuses: security, privacy, and easy to use for non-technical users.
**Context**: Baluard is my first product. First-release quality bar applies: early users judge the product (and me) on every rough edge. Non-technical users must never need to know what runs underneath: git storage, crypto epochs, key hierarchy, sync, IPC. All of it stays invisible.

**Platforms**: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell. Browser: Chrome + Firefox (MV3). Mobile: Android, iOS.

## STATUS
Baluard is pre-1.0 Work In Progress. **Breakage is expected and OK.** Move things forward; do not preserve backwards compatibility at the cost of progress. The vault format, IPC routes/JSON payloads, CLI flags, protobuf schema, and config shapes may all change without notice, deprecation period, shim, or migration path. No stable API/ABI contract exists yet.

Implications for contributors (human + agent):
* Prefer the cleaner design over the compatible one.
* Breaking a route, flag, field, or format? Just do it, and update every call site in the same change.
* No deprecation periods, compat layers, or feature flags to keep old behavior alive (yet).
* **Breakage is not UX debt.** Wire-format, vault-format, and data breaks (old files undecryptable, size caps changed, storage reshaped) are acceptable any time and need no migration or shim. Do not weigh them as user-experience regressions when evaluating a change. The only evaluation axis is *ongoing ease of use* for non-technical users (flows, friction, confusion in the current experience).
* **Security can push format breaks.** If a security fix requires breaking a format, route, or storage layout, do it: during alpha/beta, security outranks format stability. It never outranks ease of use: prefer designs that keep flows simple (warn instead of block, confirm instead of deny) and surface the tradeoff when they conflict.
* **Still load-bearing (NOT "breakage"):** the crypto/security invariants in CODING STANDARDS (AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroize-on-drop, 0600 socket, token-gating). Those must not regress.
* **Sharing (multi-user): COMPLETE** — every planned phase shipped, including the full S4 power pack and the post-pack hardening rounds (signed approvals, role-aware flipped keys, the admin marker, the removed-device notice, recovery-phrase rotation). `docs/plan-sharing.md` and `docs/plan-power-pack.md` are the closed design records; the D-records in `docs/software-architecture-decisions.md` (D59–D74) carry the per-slice history. Build S1a+ features on these foundations, not on pre-P assumptions.

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
│   ├── baluard-cli/              # CLI (clap): daemon-first with --direct fallback
│   │   └── src/
│   │       ├── main.rs         # Command dispatch
│   │       ├── client.rs       # Protobuf socket client
│   │       └── commands/       # Dual-mode handlers
│   ├── baluard-runtime/          # Shared vault-session runtime (hosted in-process by daemon, NMH, mobile)
│   │   └── src/
│   │       ├── host.rs         # VaultHost (Phase 6 multi-vault map + active pointer)
│   │       ├── state.rs        # VaultState (per-vault handle, session token, cover timer, auto-lock, autosync handle)
│   │       ├── autosync.rs     # Auto-sync coordinator (debounced push, periodic pull, offline retry)
│   │       ├── pin.rs          # Session PIN escrow (in-memory KEK, 5-strike nuke)
│   │       ├── bridge.rs       # Bridge-token registry + mobile pairing ceremony (approve-don't-type)
│   │       ├── rate_limit.rs   # Per-vault rate limiting: unlock/recovery/emergency/biometric/PIN (M4)
│   │       ├── providers.rs    # Token refresh serialization, device flow, PAT connect, pre-unlock enrollment
│   │       └── crypto.rs       # constant_time_eq + crypto helpers for session tokens
│   ├── baluard-nmh/             # Browser native messaging host: stdio JSON <-> daemon protobuf relay
│   ├── baluard-uniffi/          # UniFFI bindings consumed by mobile/shared (Kotlin Multiplatform)
│   └── baluard-daemon/          # Background IPC daemon (lib + bin): thin shell over baluard-runtime
│       └── src/
│           ├── main.rs         # Socket listener, SIGINT/SIGTERM, 0600 perms
│           ├── handler.rs      # Protobuf routing, per-vault token-gated IPC
│           └── socket_path.rs  # Socket path discovery
├── desktop/                    # Tauri v2 + SolidJS frontend
│   └── src/
│       ├── App.jsx             # Root component (thin provider wrapper)
│       ├── components/         # UI components (VaultView, CipherDetail, SshKeyGenerator, SetupScreen, etc.)
│       ├── context/            # AuthContext, VaultContext, VaultSwitcherContext, AutoSyncContext, themeSignal, toastSignal
│       ├── lib/                # daemon.js, payload.js, cipherSchema.js, filters.js, utils.js, helpers.js, biometry.js, clipboard.js, vaultPrefetch.js, eff-words.js, wordlist-{en,es}.js, disableAutofill.js
│       ├── __tests__/          # vitest tests (payload, utils, filters, cipherSchema)
│       └── i18n/locales/       # en.json, es.json, pt.json (all user-facing strings)
├── browser/                    # Browser extension (MV3, Chrome + Firefox)
│   ├── shared/src/             # background.js, content.js, inline.js, offscreen.js, autofill.js, settings.js
│   ├── shared/manifest.base.json + vite.config.js
│   ├── chrome/ + firefox/      # Per-store packaging (manifest.extra.json, dist builds)
│   └── shared/tests/           # vitest (background, content, inline, offscreen, autofill, settings)
├── mobile/                     # Kotlin Multiplatform app (Compose Multiplatform UI)
│   ├── shared/src/commonMain/  # App UI + ViewModels (auth, list, detail, edit, sync, generator, settings)
│   ├── shared/src/androidMain/ # Android platform expect/actual (SecureFlag, Biometric, Clipboard, paths, a11y)
│   ├── shared/src/iosMain/     # iOS platform expect/actual
│   └── androidApp/             # Android host app (BaluardAutofillService, BaluardAccessibilityService, BaluardA11yTileService, AutofillActivity)
├── proto/                      # Protobuf schemas (compiled via prost)
│   ├── vault.proto
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
| Ubuntu | 26.04 | Secret Service (gnome-keyring or compatible) at runtime for keyring storage. |
| Fedora | 43 | Secret Service (gnome-keyring or compatible) at runtime for keyring storage. |

Implications:
* Rust edition 2024, MSRV 1.85 (ships in all targets above). The optional `fido2` feature needs Rust 1.89 (ctap-hid-fido2 documents it); default builds stay 1.85.
* macOS: `security-framework` v3 + SecAccessControl BIOMETRY_ANY. No APIs deprecated after macOS 15.
* Linux: `keyring` crate with `linux-native-sync-persistent` + `crypto-rust` (pure-Rust D-Bus Secret Service client). No libsecret build dep; a Secret Service provider (gnome-keyring, KeePassXC) must be reachable at runtime. Build deps: `protoc` (cargo builds), WebKitGTK/GTK dev headers (desktop app). `just sysdeps` prints the per-distro install line.
* Windows: `keyring` crate with `windows-native`. Windows Credential Manager via DPAPI.
* Tauri v2 WebView2: bundled on Windows, WebKit on macOS/Linux (system-provided on these versions).

## CODING STANDARDS
* **Compatibility**: Pre-1.0 WIP (see STATUS). Backwards compatibility is NOT a goal yet. Break vault format, IPC routes/payloads, CLI flags, protobuf, and config freely; update all call sites in the same change. Crypto/security invariants below stay load-bearing.
* **Rust**: Edition 2024, MSRV 1.85. Feature flags: `full` (default) = `git-sync` + `passkey-ceremony` + `uri-match` (the `org`/`emergency` flags gated nothing and are gone). `thiserror` for library errors, `anyhow` for CLI. `proptest` for property-based tests.
* **JS/TS**: ES modules, SolidJS, Vite. Tailwind for layout. `crypto.getRandomValues` only (never `Math.random`).
* **Protobuf**: proto3, `baluard.vault` package. Compiled via prost in daemon + CLI.
* **Security**: AES-256-GCM only. Argon2id for KDF. X25519/Ed25519 for device keys. HPKE for key wrapping. No secrets in code. Socket 0600. Zeroize on drop for key material, TOTP secrets, and passkey private keys.
* **WebAuthn/Passkey**: passkey-rs 0.5.x for ceremony. ES256 only. Private key encrypted under item key, never crosses IPC, zeroized on drop. Counter: synced/provider passkeys carry BE=BS=1 with the counter pinned to 0 and never incremented (W3C L3 multi-device guidance); `max(local, remote)` applies only to device-bound legacy counters on git-sync.

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
* **Daemon runtime (shared by daemon/NMH/mobile)**: `crates/baluard-runtime/src/`: `host.rs` (`VaultHost` multi-vault map), `state.rs` (`VaultState`, one per open vault), `autosync.rs`, `pin.rs`, `bridge.rs` (mobile pairing + bridge tokens), `rate_limit.rs` (unlock/PIN/biometric/recovery throttling)
* **Daemon IPC**: `crates/baluard-daemon/src/handler.rs` (protobuf host-level dispatcher) + `main.rs` (Unix socket listener). Thin shell; session logic lives in baluard-runtime
* **Auto-sync coordinator**: `crates/baluard-runtime/src/autosync.rs` (`AutoSyncHandle`: debounced push after CRUD, periodic pull, offline retry, field-level conflict resolution). Core workflow: `SyncEngine::run_sync_cycle_with_resolver` / `resolve_conflict_keep_local` / `finalize_conflicts` in `sync/engine.rs`. Conflict merge: `conflict_decrypt_and_merge` + `conflict_resolve_keep_both` in `state.rs`. Desktop: `AutoSyncContext`, `AutoSyncIndicator`, `ConflictBanner`, `ConflictResolutionPanel`, `conflictFlow.js`.
* **Browser extension**: `browser/shared/src/` (background, content, inline, offscreen, autofill, settings). Manifest: `browser/shared/manifest.base.json`. NMH relay: `crates/baluard-nmh/src/main.rs`
* **Mobile app**: `mobile/shared/src/` (commonMain UI/VMs, androidMain/iosMain platform impls) + `mobile/androidApp/`. Rust bridge: `crates/baluard-uniffi/src/lib.rs` (full vault lifecycle over UniFFI)
* **Android Autofill & Accessibility**: `mobile/androidApp/src/androidMain/kotlin/xyz/actitud/baluard/autofill/` (`BaluardAutofillService`, `BaluardAccessibilityService`, `BaluardA11yTileService`, `AutofillSession`, `AutofillActivity`, `AutofillA11yBridge`, `AutofillSaveToken`, `AutofillResponseBuilder`). Rust URI matching & equivalence: `crates/baluard-core/src/types.rs` (`UriMatchStrategy::matches`, `matches_with`, `app_domain_candidates`) + `crates/baluard-core/src/resources/global_equivalent_domains.json`. Batch match query: `crates/baluard-runtime/src/state.rs` (`VaultState::autofill_query` returning `{matches, app_suggestions}`) + `crates/baluard-uniffi/src/lib.rs` (`MobileVault.autofill_query`, `autofill_app_trust`, `autofill_app_reject`). Plans: `docs/plan-android-autofill.md`, `docs/plan-android-accessibility-tile.md`
* **Desktop frontend**: `desktop/src/App.jsx`
* **Device fleet**: `crates/baluard-core/src/device_manager.rs`
* **Passkey ceremony (WebAuthn)**: `crates/baluard-core/src/crypto/webauthn/`
* **Passkey data structure**: `crates/baluard-core/src/types.rs` (`PasskeyData`)
* **Passkey plan**: `docs/plan-passkey-support.md` (authoritative)
* **Git provider app registration & tokens**: `docs/git-provider-apps-and-tokens.md`
* **Git provider sync plan**: `docs/plan-git-providers-multi-vault.md`
* **Encrypted backup container**: `crates/baluard-core/src/import/backup_container.rs` (.bldbak format; authoritative spec + golden-vector transcript in `docs/plan-encrypted-backup.md`; reference decryptor `scripts/decrypt_backup.py`, run via `just decrypt-vector`)
* **Family Spaces plan (active)**: `docs/plan-family-spaces.md` - purpose flag, classification union, roles, journeys, kit rules, G24 wiring; steps 1-8 landed
* **Merged search & autofill plan (landed)**: `docs/plan-merged-search.md` - daemon fan-out behind the merge ceiling; all nine steps landed
* **Feature parity matrix**: `docs/feature-parity.md` (CLI/desktop/mobile matrix, 23 numbered gaps, five-track order — the gap tracker for the parity era)
* **E2E test plan**: `docs/e2e-testing.md` (four-phase plan; Phase 1 harness lives in `crates/baluard-cli/tests/e2e`, run via `just test-e2e`)
* **Sharing plan (closed design record)**: `docs/plan-sharing.md` (COMPLETED 2026-09-28: P, S1a/S1b, S2, S3-1..S3-9, §4.8, §6.5, S4-1). **S4 power pack (also a closed design record)**: `docs/plan-power-pack.md` (all eight items shipped 2026-09-28 through 2026-09-30; post-pack hardening in the D-records)
* **S4 module map**: `crates/baluard-core/src/vault/approvals.rs` (signed quorum asks, format-2 records), `vault/groups.rs` (Group Key layer + gkwrap/ckwrap chain), `vault/policies.rs` (advisory org recommendations), `vault/recovery_kit.rs` (Space Recovery Kit escrow), `sync/timeline.rs` + the `derive_timeline` walk in `sync/engine.rs` (S4-5 derived timeline; the engine walk stays inline because the roster/verification helpers are file-private)
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

### VaultHost (Phase 6 Multi-Vault)
Daemon shares `Arc<VaultHost>` across handlers (replaces pre-Phase 6 single `Arc<VaultState>`). `VaultHost` wraps ONE `RwLock<VaultHostInner>` holding both `vaults: HashMap<String, Arc<VaultState>>` AND `active: Option<String>`. **Invariant: if `active` is `Some(slug)`, slug MUST be in the map.** Switch = pointer flip only (no zeroization, no token change). Per-vault session tokens (vault-A token rejected for vault-B op). Handler snapshots target `Arc<VaultState>` once per request (no TOCTOU). `vaults.close` = Arc-drain (returns immediately, in-flight handlers zeroize on last drop). Single auto-lock walker iterates map every 30s. Routes: `vaults.list/switch/active/close/set_active/lock_all`. CLI: `baluard vaults list|switch <slug>|close <slug>|set-default <slug>|add <slug> <clone-url>|prune [--dry-run]`. Desktop: `VaultSwitcher` dropdown + 30s heartbeat. **Lock-all on resign-active:** Tauri `WindowEvent::Focused(false)` fires `vaults.lock_all` (desktop clears token cache, refreshes on focus regain). OS suspend/screen-lock hooks still TBD (platform-specific). **mlock budget:** `VaultHost::log_mlock_budget` logs resident key bytes (96 B/vault: RootKey+SGK) + RLIMIT_MEMLOCK after every unlock (T15 legibility).

### IPC
Unix domain sockets. 0600 via umask. Peer credential verification (SO_PEERCRED/getpeereid). `--socket` overrides default. Token-gated (capability broker): 256-bit session token on unlock, constant-time verified; the client holds an opaque capability, never raw key material. All platform paths centralized in `baluard_core::paths` (`crates/baluard-core/src/paths.rs`).

### Quick Unlock (per-vault, multi-platform)
Three unlock-shortcut mechanisms, all **per-vault** (never per-app). The frontend queries both `vault.biometric_status` and `vault.pin_status` (slug-routed, pre-unlock safe) and shows whichever buttons are enabled for the selected vault.
- **Biometric keychain (macOS Touch ID):** master password stored in the OS keychain under account `quick-unlock:<vault_id>`, gated by `SecAccessControl(BIOMETRY_ANY)` (Touch ID/passcode on read). `vault_id` = deterministic UUID from KDF salt (`VaultHandle::derive_vault_id` / `vault_id_for_path`), stable across renames + git-sync. `biometric.rs` platform modules. A legacy global `quick-unlock` entry (pre-QU, shared across vaults) is wiped once at daemon startup via `disable_legacy_global()`.
- **Session PIN (Linux + Windows-without-Hello):** in-memory KEK escrow (`crates/baluard-runtime/src/pin.rs` `PinEscrow`). After the first master-password unlock the user enables a 6-digit PIN; the daemon retains the Argon2id-derived KEK + an Argon2id verifier over the PIN (both zeroized on drop, never on disk). PIN unlock calls `VaultHandle::unlock_with_kek` (skips the master KDF, still verifies keywrap + canaries). **Session-bound:** dies on daemon restart / vault close; **survives soft-lock** (escrow is a separate `VaultState` field from the handle). **5-strike nuke:** after `pin::MAX_PIN_FAILURES` (=5) wrong PINs the escrow is destroyed and the master password becomes mandatory (Bitwarden-equivalent policy; the 10^6 keyspace cannot be brute-forced through this in-process cap). Routes: `vault.pin_status` (not token-gated), `vault.pin_enable`/`vault.pin_disable` (token-gated), `vault.pin_unlock` (host-level, not token-gated, mirrors `handle_vault_biometric_unlock`).
- **Windows Hello (future, not yet implemented):** TPM-backed `KeyCredential` API. The current `keyring` `windows-native` backend is NOT biometric-gated per-read (Credential Manager / DPAPI), hence the session-PIN fallback above.

### Padded Buckets
5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()`. Prevents metadata leakage.

### Auto-Sync (Desktop)
When a vault has a remote + connected provider, the daemon coordinator (`crates/baluard-runtime/src/autosync.rs`) syncs automatically. **Debounced push** (5s coalesce) after every CRUD mutation via the `COVER_MUTATION_ACTIONS` hook in `handler.rs`: a burst of edits becomes one commit + one round-trip; the push cycle itself is commit→pull→push so concurrent remote edits land immediately after a local change. **Event-driven pull**: pull immediately on vault unlock (`VaultState::unlock` calls `pull_only` after `activate`), and on window focus (desktop fires `sync.autosync_nudge_pull`; daemon applies a 10-min `FOCUS_PULL_MIN_GAP_SECS` guard so flicker collapses to one pull per 10 min). **Idle fallback pull** every 30 min (`PULL_INTERVAL_SECS`) catches the rare "left open on two machines" case; deliberately quiet (no predictable periodic heartbeat, T14 timing-fingerprint). Serverless architecture (git remote IS the server, no push channel) - unlike Bitwarden's SignalR inbound we must poll, but event triggers do the snappy work and the timer is just a backstop. **Offline handling**: network failures (`SyncError::Network`, classified via `is_network_error` from `git2::Error::class()` Net/Http/Ssh/Ssl) -> `Offline` state -> 30s retry probe. **Canonical git workflow** (`SyncEngine::run_sync_cycle`): commit local -> pull -> resolve conflicts -> push (committing first keeps the worktree clean so the pull's force-checkout can't discard uncommitted edits). **Conflict policy (Phase 2, 2026-07-02)**: field-level 3-way merge is now wired into the cycle via `run_sync_cycle_with_resolver(..., Pause)`. The daemon decrypts base/local/remote (`VaultHandle::decrypt_cipher_bytes`) and runs `conflict::merge_ciphers` (semantic atomic groups for username/password/TOTP). `MergeResult::Merged` -> re-encrypt under `current_epoch` + `max(local_seq,remote_seq)+1` + `finalize_conflicts` (no UI). `MergeResult::Conflict` -> pause as `SyncCycleOutcome::NeedsDecision`, surface masked details via `sync.conflict`, resume on `sync.conflict.resolve` (keep_local/keep_remote = raw blob; keep_both = new-uuid clone mirroring `add_cipher`). Cross-epoch decrypt failure (foreign epoch) bails to keep-local raw blob with a `cross_epoch` UI flag. The backward-compat `run_sync_cycle` wrapper still delegates with `ConflictResolution::KeepLocal`. Desktop: `AutoSyncContext` polls `sync.conflict` on `needsdecision` state and feeds the `ConflictResolutionPanel`; sync status dot + transient label top-right (`AutoSyncIndicator`); conflict banner (`ConflictBanner`). Activated in `VaultState::unlock` (immediate, not lazy); deactivated on lock. **C3 mutex**: `cycle_lock` (tokio Mutex) guarantees only one sync cycle touches the on-disk repo at a time. **No daemon-side cache**: `get_cipher`/`list_folders` read from disk every call, so after a pull the handle serves fresh data without a reload (root_key/SGK stay valid). **Index rebuild**: all three verdict paths call `rebuild_cipher_index()` after finalize (they write via `SyncEngine`, bypassing the `VaultHandle` index-rebuild hooks: critical for keep_both's new cipher_id).

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

### Slug & Repo Prefix (enforced)
Every vault slug and provider repo name carries the `baluard-` prefix. All entry points (CLI `init`, daemon `vault.create`, `provider.clone`, `vault.setup_sync`, `provider.create_repo`) run `slug::normalize_slug()`, which auto-prepends it: users type "personal", the slug and the remote repo become "baluard-personal". Normalization, never rejection - `validate_slug` stays a shape check applied AFTER normalization. Desktop previews normalize through the mirrored `normalizeSlug` in `desktop/src/lib/slug.js`. Provider repo detection is marker-based, never name-based: `provider.vault_repos` probes the `.baluard` file (slug + vault_id) - GitHub lists OWNED repos + probes primary with code search (`filename:.baluard user:<login>`) as a supplementary deduped pass (code search lags, indexes default branches only, can miss private repos); GitLab/Codeberg paginate + probe (Codeberg scoped `type=owner`). Unrelated repos never surface in pickers.

### Vault Creation Wizard
Multi-step wizard for both CLI and desktop. CLI: `baluard init` with `--profile`, `--name`, `--slug`, `--theme`, `--lang`, `--auto-lock` flags + interactive fallback. Desktop: 3-step flow (language+password -> recovery phrase -> profile+preferences). `VaultCreator` builder chains `.profile()` + `.preferences()` on `execute()`. Desktop applies post-creation via `settings.set` + `locale.save` IPC. `--subtitle` was removed (2026-06-11) after the profile step absorbed it.

### ThemeMode
Typed enum (`Light`/`Dark`/`System`) replacing `Option<String>` on `VaultSettings.theme`. Case-insensitive serde for backward compat. Default: `System`.

### Locale Persistence
Language stored in plaintext `meta/settings-pub.json` (consolidated 2026-06-26; deprecated the standalone `meta/locale` sidecar). Single source: the pre-unlock login screen reads it via `load_locale()`, and post-unlock `VaultSettings.lang` reflects the same value. `locale.save` daemon route writes `settings-pub.json` (merging with the existing `theme` so it isn't clobbered).

### Modal Accessibility
All modals use `<FocusTrap>` component: `role="dialog"`, `aria-modal`, `aria-labelledby`, Tab/Shift+Tab trap, Escape dismiss, auto-focus first interactive element, restore focus on close. Applied to: DeleteConfirm, ArchiveConfirm, Reprompt, Generator, Settings, EmptyTrash, SetupScreen.

### Auth State Machine
7 states: `locked`, `unlocking`, `unlocked`, `init`, `creating`, `recovery`, `setup`. Wizard flow: `init` -> `creating` -> `recovery` -> `setup` -> `unlocked`. `setup` state added for post-creation profile/preferences step.

### Vault Detach (UI vs CLI)
Detaching a vault (drop registry entry so it stops appearing in the app) is exposed in the VaultSwitcher dropdown on the login screen. The **destructive arm (delete-from-disk) is deliberately NOT exposed in the UI**: only the safe, reversible detach. Rationale: irrecoverable deletion of an unsynced vault is a real harm surface (accidental click, casual adversary at an unattended machine), and a typed-name confirmation echoes a name the UI itself displays (weak proof). The power-user escape hatch is the CLI: `baluard vaults detach <slug> --delete-from-disk` (gated by slug retyping + the daemon-side `.baluard` marker check). A future revision may add a master-password-reprompt gated destructive arm back to the UI (Bitwarden-style); until then the UI is destructive-action-free. The daemon route `vaults.detach` still supports `delete_from_disk` + `force` for the CLI caller.

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
- **Counter**: `max(local, remote)` on git-sync for device-bound counters; provider/synced passkeys stay 0 (never incremented). `PasskeyIndex` indexes all ciphers' fido2 credentials for fast lookup during assertion; the provider path narrows it to the selected credential via `PasskeyIndex::single`.
- **Two-phase ceremony** (Phase 1 trust model): `challenge_*` runs the ceremony + caches state, `finish_*` consumes state + persists cipher. Echo-back of passkey_data accepted in Phase 1 (same-process desktop). Phase 2 (browser extension) MUST store results in `CeremonyState` to prevent client forgery: see SEC-1 in `docs/plan-passkey-support.md`.
- **BaluardCredentialStore** trait impl: bridges passkey-rs `CredentialStore` to cipher envelopes. `Arc<Mutex<StoreInner>>` for mutation tracking via `take_new_credentials()` + `take_counter_updates()`.

### Android Autofill & Quick-Settings Accessibility Fill
System autofill provider (`BaluardAutofillService`) runs in an isolated `:autofill` process (`android:process=":autofill"`). **OOM invariant**: service unlock uses `unlock_with_kek` with the biometric-gated KEK only; the Argon2id master-password KDF (64-256 MB) never runs in `:autofill`. Matching runs in `baluard-core` (`UriMatchStrategy::matches`, `matches_with`) with 6 strategies (BaseDomain via `public-suffix`, Host, StartsWith, Exact, RegularExpression, Never), bundled Bitwarden global equivalent domains, user-defined custom equivalent domain groups (`custom_equivalent_domains`), and strict scheme isolation (`androidapp://` never cross-matches `https://`). Batch query endpoint `VaultState::autofill_query` returns ranked JSON containing `{matches, app_suggestions}` without passwords or "password" keys; passwords cross FFI only on explicit dataset selection. **App-to-web matching with per-app trust (path B)**: opt-in setting (`suggest_app_logins`) parses package labels into candidate domains; first encounter presents an in-process trust prompt in `AutofillActivity`, storing confirmed choices in `trusted_app_packages` or `rejected_app_packages` in `settings.enc`. Cold sessions respond with response-level authentication ("Unlock Baluard" placeholder), launching transparent `AutofillActivity` for `BiometricPrompt` with `CryptoObject`. Inline IME suggestions (`supportsInlineSuggestions`, default INLINE) attach `InlinePresentation` chips alongside dropdown `RemoteViews`. Save prompt (`onSaveRequest`) captures committed fields with `FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE`, splits username/password save info, and hands off to `MainActivity` via a one-time sandbox file token (`AutofillSaveToken`). Quick-Settings tile accessibility fill (`BaluardA11yTileService` + `BaluardAccessibilityService`) provides an opt-in fallback for apps and browsers lacking standard autofill support: scrapes URL-bar nodes from a browser table, displays an in-process picker via `AutofillA11yBridge`, fills via `ACTION_SET_TEXT`, copies TOTP to clipboard with auto-clear, and caps retries at 3 per selection.

## GOTCHAS
* **vault.unlock proves the master password on every path**: since the B1 fix the already-unlocked short-circuit verifies the presented password against the KEK canary before acknowledging or re-minting the session token, so a wrong password on an open vault fails and charges the rate-limit budget; the short-circuit only skips the unlock tail (privkey load, sync activation). `VaultState::reprompt_verify` remains the dedicated re-prompt verifier (30-second no-token grant; failed checks burn the shared per-vault budget). Per-cipher re-prompt is enforced on desktop and mobile via `vault.reprompt_verify` / `MobileVault.repromptVerify`.
* **Guest sharing is opt-in**: VaultSettings.guest_enabled is OFF unless explicitly Some(true) (absent/None/Some(false) all refuse new guest reveals; already-exported reveal files stay openable until expiry — the door is a policy, not a revocation). The 2026-10-03 product decision supersedes the closed plan-sharing §6.5 guests-on row; consumers must test `== Some(true)`, never `!= Some(false)`.
* **in_path/out_path are desktop-forbidden payload keys** (D2 forbidden-keys gate): a compromised webview must never gain a file-read/write primitive through vault.import/vault.export. Desktop backup flows use the dedicated Rust-side dialog commands (backup_save_encrypted/backup_import_encrypted); the daemon caps container reads at 300 MB and refuses non-regular files.
* **Baluard encrypted backup (.bldbak) invariants**: the file key derives ONLY from the passphrase (NFKC, no trim) plus a per-file salt — zero vault id/epoch/device material, so cross-vault restore and master-password/rotation changes can never brick a backup; wrong passphrase and corruption are deliberately indistinguishable ('wrong password or damaged file'); header integers are little-endian but the STREAM chunk counter and in-band payload length are big-endian (age convention); containers never ride the UTF-8-decoding import path.
* **Autofill query wire format**: `autofill_query` returns a JSON object with top-level keys `matches` (array of directly matching credentials) and `app_suggestions` (array of `{domain, matches}` candidate groups for untrusted native apps). Callers must parse the object rather than assuming a top-level array.
* **App-to-web trust isolation**: package lookalikes (`com.mybank.evil`) derive the same candidate web domain as legitimate apps, but trust decisions are strictly scoped to the exact package name (`trusted_app_packages`). Lookalike packages cannot inherit trust from another package and must independently pass the explicit user trust prompt.
* **Custom domain equivalence sanitization**: user-defined equivalent domain entries strip any pasted URL schemes and path prefixes before domain normalization, folding each entry to its registrable domain.
* **Hermetic test keyring bypass**: `just test` sets `BALUARD_DISABLE_KEYRING=1` so cargo test runs hermetically without hanging on locked system Secret Service collections or headless display prompts.
* **AutofillSession lifecycle**: `AutofillSession` mutex-serializes vault mutations (open/unlock/lock) across dispatchers. Superseded handles are explicitly locked before drop so key material zeroizes deterministically.
* **AutofillSaveToken**: `getLaunchedFromPackage()` is API 34+; on minSdk 32 it throws `NoSuchMethodError`. Save handoff uses a random UUID written to app sandbox storage before launching `MainActivity` and consumed on read, blocking intent spoofing across all API levels.
* **TileService U+ dispatch**: `TileService.startActivityAndCollapse(Intent)` is rejected on Android 14+ (targetSdk 34+); branch to the `PendingIntent` overload on U+ and `Intent` below.
* **Autofill Dataset empty field guard**: `Dataset.build()` throws `IllegalStateException` when no field values are set; empty datasets must be skipped.
* **Accessibility main thread ANR**: `BaluardAccessibilityService` must run session decrypts on a background coroutine scope (`AutofillSession.scope`), never with `runBlocking` on the accessibility service main looper.
* **URI matching boundaries and scheme isolation**: `StartsWith` entry URIs ending in a slash treat the trailing slash as segment boundary. Non-regex strategies reject mixed-scheme pairs (e.g., `androidapp://` target against `https://` entry).
* **Inter-process settings flags**: `SharedPreferences` cache per-process; `AutofillFlagFile` coordinates accessibility and inline-suggestion settings between the main app and `:autofill` processes via filesystem flags.
* **Password history**: Auto-appended on password change. Cap 10 entries (FIFO).
* **Conflict resolution (Phase 2)**: `pull_inner` MUST leave the sync state machine in `Merging` (NOT `Idle`) on `PullResult::Conflict` - the resolution path's final `Merging→Idle` transition is what completes the cycle. Pre-2a it pre-transitioned to `Idle`, making `resolve_conflicts`'s final `Idle→Idle` invalid on every real conflict (latent bug, fixed in 2a). `finalize_conflicts` is HEAD-guarded against double-resolve. **Cross-epoch decrypt**: `VaultHandle::decrypt_cipher_bytes` uses `SpaceGroupKey::try_derive_item_key` (returns `None` on epoch mismatch, NOT the panicking `derive_item_key`); a remote/local side at an unreachable epoch fails closed and the conflict surfaces a `cross_epoch` flag (keep_local/keep_remote raw blob are the only safe verdicts; keep_both refused). **Index rebuild**: all three verdict paths must call `rebuild_cipher_index()` after finalize: they write cipher files via `SyncEngine`, bypassing the `VaultHandle` add/update/delete hooks that normally rebuild `meta/index.enc`; without it a keep_both clone (new cipher_id) is invisible in `vault.list`. **Push-failure ≠ nothing-landed**: `finalize_conflicts` returns `SyncError::Network` when the merge commit landed but the push failed; the caller MUST still `note_resolved()` or the conflict wedges against the now-advanced HEAD.
* **Conflict queue lifecycle (Phase 4)**: the frontend `ConflictResolutionContext` queue clears on lock (vault subtree unmounts via `<Show>`, signals destroyed) AND on vault switch (`AutoSyncContext`'s `activeSlug` effect calls `conflicts.clear()` - the keep-unlocked model keeps the provider mounted across switches, so without this a vault-A conflict bleeds into vault-B's view). `refresh()` captures the slug before its awaits and re-checks after, so a stale poll for vault A can't re-enqueue into vault B after the clear. The daemon-side `pending_conflicts` drains on `deactivate()` (lock).
* **Family-space invariants (landing steps 1-2, 2026-10-06)**: Space classification is the union of `purpose` (absent/pair/family/org in `settings-pub.json`), flipped shape, or the legacy `space:true` flag — flag-only checks misclassify flipped orgs as personal; `pair_gate` caps only pair-Space vaults. `space_flip` demands a family or org purpose and auto-stamps org for a purpose-less personal vault (the shipped flip button), so pair Spaces refuse. The sealed minor record `meta/members/<id>/minor.enc` is Admin-writable via a dedicated policy row ahead of the any-role members subtree row; a minor cannot rewrite their own flag. Ownership transfer targets must be live and non-minor, Admin rank on family purpose only. `collection_rotate_key` rotates the CK AND prunes the evicted member's grants (the expiry sweep prunes only expired grants); re-keying alone leaves the old key live in stolen hands. Plain `collections.revoke` on a member also rotates (revoke-with-rotation, 2026-10-12): the removed member already held the old CK, so wrap deletion alone never cut access; group revokes keep wrap-only semantics, collection names are unique per vault (create and rename refuse duplicates case-insensitively), and every rotate-shaped op converges the shared `.sweep-pending` marker first via `converge_pending_sweeps`. Departure (journeys, 2026-10-06): an approved leave record runs the removal with tombstone reason `left`, rotates EVERY collection an Admin leaver could open (the SGK unwraps all CKs, so admin departures rotate all collections; expired-but-unswept grants still count), re-issues the kit (new phrase returned exactly once), refuses while the leaver owns the repo, and surfaces rotation/re-issue failures in the response (never swallows them). Kit recovery is phrase-only: the password parameter is the recoverer's OWN new master password (8-char floor, per-device member unlock) and the ceremony ends in a fresh unflagged member row (Owner when no live admin row exists, else Admin). Wizard wave (2026-10-06): minor invites mint only at Editor/Viewer rank and admins/owners cannot be flagged as minors; family creation enables the kit (idempotent); the stolen-device journey is one op (`members.replace_device`) whose replacement invite embeds the member's captured grants, plus optional revoke-and-rekey and grant-pruning rotations. Kit enable-over and disable run the shared approval gate at the FIXED threshold min(2, live admins) (never the quorum knob), with enable-over's ask bound to the kit's created_at; first enable is ungated because creation auto-enables. Ownership claims on family vaults run the D61 contest window: a confirmed claim against a live Owner writes meta/contests/ownership-claim.json (the synced gate-proof record), the owner cancels via members.contest_cancel for 30 days, and the re-touch claim executes only after the window; quorum 2-5 is settable on family with the kit phrase as the last-admin deadlock escape. The arming surfaces as success (armed:true) so the daemon covers and nudges the record to the owner's devices; the window is enforced on the executing device's clock, so quorum 2 stays the cryptographic control. G24 merge ceiling (step 7): `personal_merge` absent follows the purpose (family on, else off) via `space::effective_personal_merge`; eligibility is the device-local keyless predicate `VaultRegistry::merge_eligible` (personal always eligible, Spaces need the `merge_ceiling_seen` cache refreshed at unlock and settings save, `merge_opt_in` opt-out wins); legacy flipped orgs and pair Spaces classify as Spaces and stay out of merge. Member add-routing (the family-defaults block in runtime `add_cipher`) must gate on `space_meta::shape_flipped`, never `is_space`: shape_flipped is exactly the set whose flat namespace is admin-only (family vaults born team-shaped, orgs flipped through `space_flip`, legacy flipped orgs), while pair Spaces keep a Root-Key-holding Editor partner who must keep writing flat, and a mid-transaction family vault (purpose stamped, flip failed) has no members yet so flat adds stay correct.
* **Folder depth**: Max 16 levels. `delete_folder` cascades via BFS descendant collection.
* **TOTP**: The dedicated `cipher.totp` route returns only derived numeric codes. The otpauth seed itself DOES ride full cipher reads (`vault.get` / `vault.list_full`, flattened to a top-level `totp` key in list JSON) so the editor can round-trip it - the seed is bound to an unlocked session with the daemon, not absent from the wire. Keep new surfaces on the derived-code route.
* **Session PIN escrow**: in-memory ONLY (never disk). The KEK + Argon2id PIN verifier live on `VaultState::pin`. After `pin::MAX_PIN_FAILURES` (=5) wrong PINs the escrow is nuked and the master password becomes mandatory: there is NO soft recovery, the user must re-enable PIN after a master-password unlock. PIN survives soft-lock but dies on daemon restart / vault close. `VaultHandle::unlock_with_kek` (shared unlock tail) is what PIN unlock calls; it skips Argon2id but still verifies keywrap + canaries, so a stale KEK (password changed on another device) fails closed.
* **`RotationGuard`**: RAII guard cleans up `.tmp` files and crash marker on error. Disarmed after successful atomic commit.
* **CodeGraph available**: `.codegraph/` index exists. Route codebase exploration through CodeGraph tools when available.
* **Feature flags control sync**: `git-sync` feature gate; CLI enables it by default.
* **Git `pull()` MUST force-checkout** (C1 fix, `sync/engine.rs`): the fast-forward and merge paths must call `checkout_head(Some(CheckoutBuilder::new().force()))`, NOT `checkout_head(None)`. `None` is `GIT_CHECKOUT_NONE`, a dry-run no-op: HEAD advances but the worktree keeps stale files. Auto-sync / manual sync then commits the stale tree and pushes, silently reverting the other device's changes. The test suite force-checkouts after pull; production must too.
* **Sync cycle order = commit → pull → push** (H2 fix, `SyncEngine::run_sync_cycle`): never pull into a dirty worktree. Committing local changes first keeps the tree clean so the pull's force-checkout cannot discard uncommitted edits.
* **Network errors need explicit classification** (H1 fix, `classify_remote_err` in `sync/engine.rs`): libgit2 transport failures come back as `SyncError::Network` ONLY because push/fetch map `git2::Error::class()` (Net/Http/Ssh/Ssl) to `SyncError::Network`. Without this, all failures are `SyncError::Git(string)` and the auto-sync Offline state never triggers. Use `is_network_error()` to check.
* **Local-only engine files must stay gitignored** (`sync-head.json`, `sync-state.json`, `.baluard/`): rewritten outside the commit cycle (push saves sync-head, transitions save sync-state). Tracked-but-modified = worktree dirty forever = sync badge stuck on "Changes pending". `status()` filters them defensively; `open_repo` refreshes `.gitignore` for old vaults.
* **macOS keychain ACLs bind to code signature**: ad-hoc-signed binaries re-prompt every rebuild because the cdhash changes. `just _sign-sidecar` signs the daemon with the Apple Development identity + stable identifier `xyz.actitud.baluard.daemon` so "Always Allow" persists across rebuilds.
* **Tauri sync commands must be async + spawn_blocking** (`desktop/src-tauri/src/lib.rs` `daemon_request`): a sync `#[tauri::command] fn` runs on the main UI thread; blocking socket I/O freezes the webview. Async + `spawn_blocking` moves it to the Tokio pool so SolidJS can paint spinners.
* **SSH key generation**: Private key material generated daemon-side via `ssh-key` crate. Only formatted OpenSSH strings cross IPC.
* **Avatar storage**: Unencrypted `meta/avatar.{ext}` in vault directory. Vault encrypts at rest; avoids bloating settings.json diffs. Ext validated against whitelist (png/jpg/jpeg/gif/webp), 350KB base64 cap.
* **Settings split (privacy)**: `meta/settings.json` (plaintext, leaked slug/lang/theme/enrollment_policy to the git remote) is split into `meta/settings-pub.json` (plaintext: theme + lang only, pre-unlock) + `meta/settings.enc` (AES-256-GCM under root key: vault_timeout, default_uri_match, fetch_favicons, slug, enrollment_policy). Mirrors the `profile.enc`/`folders.enc` pattern (`derive_settings_key`). Legacy `settings.json` is migrated + removed on first `save_settings`. `slug` confirmed post-unlock-only (authoritative source = `.baluard` marker + registry, not settings). `settings.enc` is git-tracked (synced), NOT gitignored.
* **Toast notifications**: `toastSignal.js` standalone signals. All user feedback via toasts, not inline text.
* **i18n**: All user-facing strings use `t()` keys. Both `en.json` and `es.json` must stay in sync. No hardcoded strings.
* **FocusTrap**: All modals use `<FocusTrap>` component for keyboard accessibility (Tab trap, Escape dismiss, auto-focus, restore focus).
* **Locale persistence**: Language lives in plaintext `meta/settings-pub.json` (consolidated 2026-06-26; the old standalone `meta/locale` sidecar is deprecated and migrated on read). Needed before vault unlock for login screen i18n. `locale.save` daemon route writes `settings-pub.json`.
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
* **Linux package deps**: `bundle.linux` in `desktop/src-tauri/tauri.conf.json` declares deb/rpm runtime deps (webkit2gtk, gtk3, ayatana-appindicator, libgit2, openssl, libssh2; gnome-keyring as `recommends`). Deb soname package names (`libgtk-3-0t64`, `libgit2-1.9`, `libssl3t64`) drift between distro releases: verify them on the target-release builder before shipping (`apt-cache policy <pkg>`). `just sysdeps` is the build-time preflight; missing runtime services print the install command instead of auto-installing (AGENTS.md UX PRINCIPLES). Gotcha: `just sysdeps` only covers the core/git deps — it reported OK while the GTK stack was missing; and brew's pkg-config shadows the system one, so Tauri builds need `PKG_CONFIG_PATH=/usr/lib64/pkgconfig` even with the headers installed (the 2026-10-16 "desktop cannot build here" baseline was exactly this shadowing).
* **Tray icon on Linux** needs `libayatana-appindicator` at build AND runtime (`tray-icon` crate links it via pkg-config `ayatana-appindicator3-0.1`).
* **Commit-signature verification (P2, repaired 2026-09-18)**: rosters resolve per commit from the first-parent tree's `meta/devices.json` (UUID-keyed) — the old test-only `meta/device-registry.json` fixture path is deleted; unsigned commits are refused at creation on enrolled vaults (fail-closed); clone paths verify full fetched history; pull refusals restore the index. Content smuggling via parent-order swap is closed by the P8a merge-residue rule (2026-09-19). Enrollment propagation (D78, 2026-10-04): a phrase-enrolled device's first commit rides a Root-Key-derived enrollment proof (`meta/enrollments/<id>.proof`); when the first-parent roster cannot vouch for the signer, the walk falls back to the proof — root-keyed signature, epoch match, genuine roster extension — and staging mirrors it via the on-disk proof file. Remaining boundary: forged fully-stripped parallel histories are a TOFU limit at first clone (proofs are structural-only there), closed at pull time by head-anchored verification and at enroll time by the post-enrollment full-history re-verification. Kit recovery joins the same chain (family-spaces plan, 2026-10-06): the kit file carries the public half of a phrase-derived Ed25519 verifier, a kit-recovered device signs its first commit with the matching key from a sealed device-local `meta/recovery-signer.key`, and the walk falls back to the parent tree's kit verifier then the commit's exactly-one registry addition; the signer file clears on first push and the commit path re-derives the device key, so later commits verify normally. Per-clone identity (2026-10-11, from the two-phone journey): daemon/CLI sync once picked a HashMap-order device from the roster — on any multi-device vault that could adopt another device's identity and strand the real device's commits as unsigned; `first_device_id` now prefers `meta/device-id` (the gitignored plain-UUID marker written per clone, authoritative at push/pull time) with the roster scan kept only as the legacy fallback for vaults predating the file.
* **Rekey survivor unlock (P3, fixed 2026-09-19)**: `rotate_root_key` stages HPKE wraps of the new Root Key for EVERY enrolled device (not actor-only); revoke-path survivors adopt their per-device entry from the committed rekey txn at unlock (`meta/rekey/<epoch>.txn`, binding: file name == txn epoch == canary epoch, fail-closed; adoption runs BEFORE the F1 cross-device heal so the survivor keeps its own identity; adopted wrap persisted 0600 for the fast path). Concurrent multi-admin rotation re-apply (loser re-applies removal) awaits S1a role flows.
* **Rotation coverage (P4, complete 2026-09-19)**: `settings.enc`, generator history, attachments, the emergency escrow, and the avatar (`meta/avatar.enc` re-encrypted under the new SGK-epoch key, staged with the atomic rename) are covered in both rotation fns with propagated failures. Known boundary: a crash between the keywrap commit and the metadata re-saves leaves the marker + a warned mixed-epoch state (P8 manifests harden).
* **One master password per vault**: a single `meta/kek-canary.enc` + one KDF salt; `change_master_password` rewrites the shared canary. Multi-member Spaces require the identity-rooted pivot (sharing plan P1).
* **Multi-writer git layer (P5, shipped)**: the conflict resolver still rejects multi-file conflicts (single-cipher 3-way merge), but every device commits: `commit_all` stages ONLY paths the signer's policy admits (P5 staged path sets, D60 — merge commits stage the authenticated merge output; skipped files revert in the worktree), and `meta/devices.json` is deterministic + skip-if-unchanged (P5a) so registry churn is a no-op unless state really moved.
* **`orgs.rs` is an envelope only**: `WrappedKeyBundle` + `wrap_to_bundle` feed the emergency escrow (`EmergencyConfig.wrapped_root_key`, rebuilt by both rotation paths). The Space-wrap engine shipped as `vault/space_meta.rs`; the old org member/access-list code is deleted. No routes, CLI, or UI.
* **`vaults.*` daemon routes are not token-gated**, and `vaults.list` cannot be (login screen, pre-token). A shared OS account is not a security boundary (same UID, shared biometric enrollment).
* **AES runs in software**: no hardware-AES feature flag is set (`aes 0.8.4` fixslice; ~25–40 MB/s class on mid-range mobile). Sharing plan P5 enables it.
* **The index key derives from RootKey** (`derive_index_key`), not SGK — older docs say SGK. Index read failures are swallowed and the list silently degrades to a full scan. Spaces without a RootKey must generalize the derivation (sharing plan §4.3).

## UX PRINCIPLES
* **Hide the machinery**: the user sees entries, folders, and a sync status dot. Never a git term, a crypto term, an epoch, a token, a socket, or an error code. If a flow cannot be explained without technical vocabulary, redesign the flow.
* **Ease-of-use is the evaluation axis**: a change "breaks UX" only if it removes working functionality, adds friction, or confuses a non-technical user in the ongoing experience. Format and data incompatibilities during alpha/beta do not count as UX breaks (see STATUS).
* **Plain language**: No hard tech terms in user-facing UI. "Cipher" -> "entry", "UUID" -> hidden. Optional visible "advanced" mode for tech-savvy users. Terminology (2026-10-17, following Bitwarden's client redesign): user-facing "Collections" are "Shared folders" (es "Carpetas compartidas", pt "Pastas compartilhadas") and "space" never reaches users — a vault's own name carries the identity ("this vault", "Join a shared vault"). Internal names (collections.* routes, vault/collections.rs, space.* keys) are unchanged; only display strings carry the new terms.
* **No server backend**: Desktop and mobile apps work standalone/offline. Git sync is optional.
* **The app prints commands, the user runs them**: dependency automation belongs to the package manager. When a system component is missing (e.g. the Secret Service keyring on Linux), tell the user what is missing and show the exact install command for their distro (never run it, never ask for the sudo password). The app UI collects exactly one credential in its life: the master password. Any second password prompt is phishing-shaped and forbidden.
* **i18n**: All user-facing strings in `desktop/src/i18n/locales/` (`en.json`, `es.json`, `pt.json`) and `mobile/.../i18n/` (`StringsEn.kt`, `StringsEs.kt`, `StringsPt.kt`). Use `t("key")` in components. All files must stay in sync with key-parity tests.
