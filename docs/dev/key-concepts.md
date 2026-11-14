# Key Concepts and Domain Architecture

> Architectural models, domain concepts, and subsystem design patterns for Baluard.

---

## 1. Key Hierarchy

Master Password -> KEK (Argon2id) -> Device Private Key (X25519, HPKE-escrowed) -> Root Key (512-bit, per-epoch) -> Space Group Key (256-bit) -> Item Keys (256-bit, HKDF-derived).

For detailed cryptographic ceremony specifications, see [Software Architecture](software-architecture.md#4-key-lifecycle--cryptographic-design) and the [Security White Paper](../security/security-white-paper.md).

---

## 2. Cipher Data Model

### CipherKind
Serde-tagged enum: `#[serde(tag = "type", content = "data")]`. Eight variants: Login, Card, Identity, SshKey, BankAccount, DriversLicense, Passport, SecureNote. Invalid states are unrepresentable in the type system. Tagged JSON format: `{type: "login", data: {...}}`.

**Passkeys are embedded inside `LoginData::fido2_credentials: Option<Vec<PasskeyData>>`** (Bitwarden-compatible model, no standalone Passkey variant in CipherKind).

### CipherMeta
`vault.list` returns `CipherMeta` containing `id`, `name`, `cipher_type`, `favorite`, and `username`. Desktop uses `vault.list_full` (batch endpoint returning all decrypted ciphers + folders + trash + archived in 1 IPC call) instead of N+1 `vault.list` + N×`vault.get`.

### Attachments
AES-256-GCM encrypted with the cipher's item key. Maximum size 2MB. Stored at `<vault>/entries/<cipher_id>/attachments/<id>.enc`. Plaintext buffers are zeroized on drop.

### Password History
Auto-appended on password change. Capped at 10 entries (FIFO).

---

## 3. Daemon and IPC Architecture

### Daemon Wire Format
JSON strings inside `GatewayRequest.payload`. `get_cipher` returns BOTH nested `kind` object AND flat top-level fields. `update_cipher` parses `kind` from payload (does NOT clone existing kind). `vault.list_full` returns all decrypted ciphers + folders + trash + archived in a single IPC call (used by desktop for fast unlock).

### IPC Socket Security
Unix domain sockets. 0600 permissions enforced via umask (`0177`) before binding to eliminate TOCTOU races. Peer credential verification via `SO_PEERCRED` (Linux) / `getpeereid` (macOS/BSD). `--socket` overrides default path. Token-gated capability broker: 256-bit session token issued on unlock, constant-time verified; client holds an opaque capability, never raw key material. All platform paths are centralized in `baluard_core::paths` (`crates/baluard-core/src/paths.rs`).

### VaultHost (Multi-Vault Architecture)
Daemon shares `Arc<VaultHost>` across handlers. `VaultHost` wraps ONE `RwLock<VaultHostInner>` holding both `vaults: HashMap<String, Arc<VaultState>>` AND `active: Option<String>`.
- **Invariant:** If `active` is `Some(slug)`, `slug` MUST be present in the map.
- Switch is a pointer flip only (no zeroization, no token change).
- Per-vault session tokens (vault-A token rejected for vault-B operations).
- Handler snapshots target `Arc<VaultState>` once per request (no TOCTOU).
- `vaults.close` drains the `Arc` (returns immediately; in-flight handlers zeroize on last drop).
- Single auto-lock walker iterates the map every 30s.
- Routes: `vaults.list`, `vaults.switch`, `vaults.active`, `vaults.close`, `vaults.set_active`, `vaults.lock_all`.
- CLI commands: `baluard vaults list|switch <slug>|close <slug>|set-default <slug>|add <slug> <clone-url>|prune [--dry-run]`.
- Desktop UI: `VaultSwitcher` dropdown + 30s heartbeat.
- Lock-all on resign-active: Tauri `WindowEvent::Focused(false)` fires `vaults.lock_all` (desktop clears token cache, refreshes on focus regain).
- Resident key budget: `VaultHost::log_mlock_budget` logs resident key bytes (96 B/vault: RootKey+SGK) + RLIMIT_MEMLOCK after every unlock.

### CLI Dual-Mode
All vault commands route through the background daemon by default. `--direct` falls back to `baluard-core` in-process execution. `--socket <path>` accepts a custom socket path.

---

## 4. Vault Lifecycle and Synchronization

### Auto-Sync Coordinator
When a vault has a remote and a connected provider, the daemon coordinator (`crates/baluard-runtime/src/autosync.rs`) syncs automatically.
- **Debounced push (5s coalesce):** After every CRUD mutation via `COVER_MUTATION_ACTIONS` in `handler.rs`, a burst of edits becomes one commit + one round-trip. The push cycle is commit -> pull -> push, so concurrent remote edits land immediately after a local change.
- **Event-driven pull:** Pull runs immediately on vault unlock (`VaultState::unlock` calls `pull_only` after `activate`), and on window focus (desktop fires `sync.autosync_nudge_pull` with a 10-minute `FOCUS_PULL_MIN_GAP_SECS` guard).
- **Idle fallback pull:** Every 30 minutes (`PULL_INTERVAL_SECS`) to catch unattended remote changes. Deliberately quiet to prevent predictable periodic timing fingerprints.
- **Serverless Git model:** The Git remote is the server; there is no inbound push channel (like SignalR). Event triggers provide responsiveness, and the periodic timer serves as backstop.
- **Offline handling:** Network failures (`SyncError::Network`) transition the coordinator to `Offline` state with a 30s retry probe.
- **Canonical Git workflow:** Commit local -> pull -> resolve conflicts -> push. Committing local changes first keeps the worktree clean so a pull force-checkout cannot discard uncommitted edits.
- **Field-level 3-way conflict merge:** `run_sync_cycle_with_resolver(..., Pause)`. The daemon decrypts base/local/remote (`VaultHandle::decrypt_cipher_bytes`) and executes `conflict::merge_ciphers` with semantic atomic groups for username, password, and TOTP.
  - `MergeResult::Merged`: Re-encrypts under `current_epoch` + `max(local_seq, remote_seq) + 1` and finalizes automatically without UI intervention.
  - `MergeResult::Conflict`: Pauses as `SyncCycleOutcome::NeedsDecision`, surfaces masked details via `sync.conflict`, and resumes on `sync.conflict.resolve` (`keep_local`, `keep_remote`, or `keep_both` clone).
  - Cross-epoch decrypt failure fails closed to `keep_local` raw blob with a `cross_epoch` UI indicator.
- **Concurrency & Caching:** A Tokio mutex (`cycle_lock`) ensures only one sync cycle touches the on-disk repository at a time. No daemon-side cipher cache: `get_cipher` and `list_folders` read fresh data from disk on every call.
- **Index rebuild:** All conflict resolution paths invoke `rebuild_cipher_index()` after finalize to ensure cloned entries (`keep_both`) are indexed.

### Padded Buckets
Five fixed-size padding tiers (XS: 5KB, S: 30KB, M: 100KB, L: 250KB, XL: 2MB). Auto-selected via `Tier::fit()`. Prevents file-size metadata leakage across encrypted Git commits.

### Attachment Side Channel
Attachment blobs live outside `main` on `refs/notes/baluard-attachments` (`crates/baluard-core/src/sync/attachments.rs`): a signed, append-only, content-addressed line keyed by the SHA-256 of the stored ciphertext (`AttachmentMeta.blob_sha256`, empty meaning legacy blobs grandfathered on main). Every sync publishes untracked worktree blobs to the line before the main push (best-effort); downloads fall back worktree-then-line and verify fetched bytes against the pin inside the fetch, so a hostile remote cannot substitute foreign bytes and a missing line entry surfaces as "not finished syncing". Deleting an entry is logical until compaction (`vault.attach_compact`, a Settings action on desktop and mobile): the daemon refuses when any entry is unreadable locally (owner/admin action on shared vaults) or when an upload is still syncing, then force-replaces the line with a fresh signed genesis carrying only still-referenced pins, parented on the vault root. See ADR 0106 and docs/designs/attachment-storage.md.

### Device Lifecycle
Epoch state machine: `CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED`.
- `revoke_device_and_rekey()` executes full rotation: validates preconditions, writes a crash marker, re-encrypts all ciphers + attachments, writes keywrap, and updates in-memory state.
- `rotate_root_key()` executes non-revocation key rotation.
- Recovery phrase uses BIP-39 standard wordlists.

### Slug and Repository Prefix
Every vault slug and provider repository name carries the `baluard-` prefix. All entry points (`init`, `vault.create`, `provider.clone`, `vault.setup_sync`, `provider.create_repo`) run `slug::normalize_slug()`, which prepends `baluard-` automatically (e.g. typing "personal" creates "baluard-personal").
- Normalization, never rejection: `validate_slug` is a format validator applied after normalization.
- Provider repository detection probes for the `.baluard` marker file (containing slug and vault ID), never relying on repository name alone.

---

## 5. Authentication, Unlock, and Access Control

### Quick Unlock Mechanisms
Three per-vault unlock shortcut mechanisms. The frontend queries `vault.biometric_status` and `vault.pin_status` (slug-routed, pre-unlock safe) and displays enabled options.
- **Biometric Keychain (macOS Touch ID):** Master password stored in OS keychain under account `quick-unlock:<vault_id>`, protected by `SecAccessControl(BIOMETRY_ANY)`. `vault_id` is a deterministic UUID derived from KDF salt (`VaultHandle::derive_vault_id`). Deleted when vault data directory is removed (`vaults.detach --delete-from-disk`).
- **Session PIN (Linux & Windows-without-Hello):** In-memory KEK escrow (`crates/baluard-runtime/src/pin.rs` `PinEscrow`). After first master-password unlock, user can enable a 6-digit PIN. Daemon retains Argon2id-derived KEK and Argon2id PIN verifier (both zeroized on drop, never written to disk).
  - Skips master KDF, verifies keywrap and canaries.
  - Session-bound: Dies on daemon restart or vault close; survives soft lock.
  - 5-strike nuke: After `pin::MAX_PIN_FAILURES` (5) incorrect attempts, the escrow is destroyed and master password input becomes mandatory.
- **Windows Hello (Future):** TPM-backed `KeyCredential` API path.

### Auth State Machine
Seven explicit states: `locked`, `unlocking`, `unlocked`, `init`, `creating`, `recovery`, `setup`.
- Creation wizard flow: `init` -> `creating` -> `recovery` -> `setup` -> `unlocked`.
- `setup` state handles post-creation profile and preferences configuration before opening the vault.

### Vault Creation Wizard
Multi-step creation wizard for CLI and desktop:
- CLI: `baluard init` with `--profile`, `--name`, `--slug`, `--theme`, `--lang`, `--auto-lock` flags plus interactive prompts.
- Desktop: Three-step flow (language + password -> recovery phrase -> profile + preferences). `VaultCreator` builder pattern.

### Vault Detach Semantics
Detaching a vault drops its registry entry so it stops appearing in clients.
- Reversible detach is available in the desktop UI (`VaultSwitcher`).
- Destructive deletion (`--delete-from-disk`) is strictly restricted to CLI (`baluard vaults detach <slug> --delete-from-disk`) requiring explicit slug retyping and `.baluard` validation. The UI never exposes destructive file deletion.

---

## 6. Passkeys (FIDO2 / WebAuthn)

Passkeys are stored within `LoginData::fido2_credentials: Option<Vec<PasskeyData>>`. A single Login entry can store multiple passkeys (e.g. YubiKey and mobile authenticator).
- **Algorithm:** ES256 only (via `passkey-rs` 0.5.x).
- **Ceremony Module:** `crates/baluard-core/src/crypto/webauthn/` (`mod.rs`, `store.rs`, `ceremony.rs`).
- **Daemon IPC:** 7 routes (`list`, `delete`, `rename`, `challenge_register`, `finish_register`, `challenge_assert`, `finish_assert`), all token-gated.
- **State Cache:** `CeremonyCache` (300s TTL, maximum 64 pending, FIFO eviction, CSPRNG challenges).
- **CLI Commands:** `baluard passkey list/delete/rename`.
- **Private Key Isolation:** Encrypted under the individual cipher item key, never crosses IPC boundary, zeroized on drop.
- **Counter Handling:** Sycned/provider passkeys pin counter to 0 (W3C L3 guidance). Device-bound legacy counters use `max(local, remote)` on Git sync.
- **Two-Phase Ceremony:** `challenge_*` initializes ceremony and caches state; `finish_*` consumes state and persists updated cipher.

---

## 7. Android Autofill and Accessibility Integration

System autofill provider (`BaluardAutofillService`) runs in an isolated `:autofill` process (`android:process=":autofill"`).
- **OOM Invariant:** Service unlock uses `unlock_with_kek` with the biometric-gated KEK only. The memory-intensive Argon2id master-password KDF (64-256 MB) never runs inside `:autofill`.
- **URI Matching:** Runs in `baluard-core` (`UriMatchStrategy::matches`) with 6 strategies: BaseDomain (public-suffix), Host, StartsWith, Exact, RegularExpression, Never.
- **Domain Equivalence:** Bundled Bitwarden global equivalent domains plus user-defined custom equivalent domain groups (`custom_equivalent_domains`). Strict scheme isolation prevents `androidapp://` from cross-matching `https://`.
- **Batch Query Endpoint:** `VaultState::autofill_query` returns ranked JSON containing `{matches, app_suggestions}` without plaintext passwords. Passwords cross FFI only on explicit user selection of a dataset.
- **App-to-Web Matching with Per-App Trust:** Opt-in `suggest_app_logins` parses package labels into candidate web domains. First encounter displays an in-process trust prompt in `AutofillActivity`, saving decisions to `trusted_app_packages` or `rejected_app_packages` in `settings.enc`.
- **Save Handoff:** `onSaveRequest` captures committed credentials and hands off to `MainActivity` via a one-time sandbox file token (`AutofillSaveToken`).
- **Accessibility Fallback Tile:** `BaluardA11yTileService` + `BaluardAccessibilityService` offer Quick-Settings tile fill for applications and browsers lacking standard Android Autofill support.

---

## 8. Frontend and UI Patterns

### SSH Key Generation
Generated daemon-side via the `ssh-key` crate. Supports Ed25519 (recommended) and ECDSA P-256. Private key PEM and public key are formatted daemon-side; private key material never crosses IPC unformatted.

### User Profile and Avatar Storage
Display name, subtitle, and avatar stored in `VaultSettings`. Avatars are stored as files in the vault (`meta/avatar.{ext}`), encrypted at rest under the SGK-epoch key, avoiding large diffs in settings files.

### Theme and Locale Persistence
- **ThemeMode:** Typed enum (`Light`, `Dark`, `System`) on `VaultSettings.theme`.
- **Locale Persistence:** Stored in plaintext `meta/settings-pub.json`. Pre-unlock login screen reads this file to render localized UI before the vault is decrypted.

### Modal Accessibility
All modals implement the `<FocusTrap>` component: `role="dialog"`, `aria-modal`, `aria-labelledby`, Tab/Shift+Tab focus cycling, Escape key dismissal, autofocus on first interactive element, and focus restoration on dismiss.

### Tag Management
Tags are managed via `tag.delete` daemon command, which removes the tag from all ciphers and rebuilds the cipher index.
