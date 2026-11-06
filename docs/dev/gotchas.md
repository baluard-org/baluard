# Engineering Invariants and Gotchas

> Implementation invariants, platform quirks, and architectural edge cases across the Baluard codebase.

---

## 1. Cryptographic and Security Invariants

- **Master Password Verification:** `vault.unlock` proves the master password on every invocation path. The already-unlocked short-circuit verifies the supplied password against the KEK canary before acknowledging or minting a session token; a wrong password burns the rate-limit budget. `VaultState::reprompt_verify` is the dedicated 30-second tokenless verification path.
- **Index Key Derivation:** The cipher index key derives from `RootKey` (`derive_index_key`), not `SpaceGroupKey`. Index read failures degrade gracefully to a full vault entry scan.
- **Single Master Password per Vault:** Each vault has exactly one `meta/kek-canary.enc` and one KDF salt. `change_master_password` updates the single canary. Multi-user spaces use identity-rooted envelope wrapping.
- **Software AES Execution:** No hardware-AES compiler flags are configured; the codebase uses `aes 0.8.4` fixslice implementation (25–40 MB/s on mid-range devices).
- **Rekey Survivor Unlock:** `rotate_root_key` generates HPKE wraps of the new `RootKey` for every enrolled device in the roster. Survivors adopt their wrapped keys from `meta/rekey/<epoch>.txn` before cross-device healing.
- **Rotation Coverage:** Both key rotation functions must re-encrypt and cover `settings.enc`, generator history, attachments, emergency escrow, and avatars (`meta/avatar.enc`).
- **Encrypted Backup Invariants:** In `.bldbak` containers, the file key derives solely from the passphrase (NFKC normalized, untrimmed) and per-file salt, with zero vault ID or epoch coupling. Header integers are little-endian; STREAM chunk counters and in-band payload lengths are big-endian (age convention).
- **RotationGuard RAII:** `RotationGuard` ensures temporary files and atomic crash markers are cleaned up on error, disarming only after a clean commit.
- **Key Material Zeroization:** All master passwords, KEKs, session PIN escrows, passkey private keys, and intermediate cryptographic buffers must implement zeroize-on-drop.

---

## 2. Git Sync and Multi-Writer Engine

- **Force Checkout on Pull:** `git2` pull operations must call `checkout_head(Some(CheckoutBuilder::new().force()))`. Using `None` defaults to `GIT_CHECKOUT_NONE` (a dry-run no-op), advancing HEAD while leaving stale worktree files that silently revert remote changes on the next commit.
- **Sync Cycle Ordering:** Sync cycle execution must strictly follow `commit -> pull -> push`. Local changes must be committed before pulling so that worktree checkout cannot overwrite uncommitted modifications.
- **Network Error Classification:** `libgit2` transport errors must be explicitly classified via `git2::Error::class()` into `SyncError::Network`. Unclassified errors fall back to generic Git errors, preventing the auto-sync engine from entering its offline retry state.
- **Local-Only Ignored Files:** Transient and host-local state files (`sync-head.json`, `sync-state.json`, `.baluard/`) must remain gitignored. Tracking them causes dirty worktrees and stalled sync states.
- **Conflict State Machine:** `pull_inner` leaves the sync state machine in `Merging` on conflict. Double-resolution is prevented by HEAD-guarded commits. `finalize_conflicts` must invoke `note_resolved()` even if the push fails after the merge commit lands.
- **Conflict Queue Lifecycle:** The desktop `ConflictResolutionContext` queue clears on vault lock and vault switch (`activeSlug` change) to prevent conflicts from leaking across vaults.
- **Commit-Signature Verification:** Commit signatures are validated against device Ed25519 signing keys from the first-parent tree's `meta/devices.json`. Phrase-enrolled devices carry root-derived proofs (`meta/enrollments/<id>.proof`). Per-clone identity uses `meta/device-id` (gitignored local UUID) rather than arbitrary roster discovery.
- **Multi-Writer Path Policies:** Multi-device commits stage only paths permitted by the signer's role policy (ADR 0063). `meta/devices.json` writes are sorted deterministically and skipped when contents are unchanged.

---

## 3. Daemon IPC and Session Lifecycle

- **Socket Permissions:** Sockets are created with `0600` permissions via `umask(0177)` before binding to prevent access by other users on shared Unix systems.
- **Non-Token-Gated Routes:** `vaults.*` routes (such as `vaults.list` and `vaults.switch`) cannot be token-gated because they drive the pre-unlock login screen and switcher. A shared OS account (same UID) is not treated as an adversarial security boundary.
- **Forbidden Desktop Payload Keys:** `in_path` and `out_path` are rejected on `vault.import` and `vault.export` IPC calls to eliminate arbitrary file read/write primitives from compromised webviews (ADR 0008).
- **Session PIN Escrow:** Session PIN escrow (`PinEscrow`) lives exclusively in daemon memory and is never written to disk. Five consecutive incorrect attempts destroy the escrow, enforcing a master password unlock.
- **Settings Privacy Split:** Settings are partitioned into plaintext `meta/settings-pub.json` (theme and language needed before unlock) and AES-256-GCM encrypted `meta/settings.enc` (timeout, matching preferences, sync policies).

---

## 4. Android Autofill and Mobile Invariants

- **Autofill Memory Footprint:** The `:autofill` process uses `unlock_with_kek` to avoid running the memory-heavy Argon2id KDF on memory-constrained service paths.
- **App-to-Web Trust Isolation:** Domain candidate matching from application package labels requires explicit user confirmation. Trust decisions are bound to exact package names (`trusted_app_packages`); lookalike package names cannot inherit trust.
- **Save Token Handoff:** Intent handoffs between `:autofill` and `MainActivity` use random UUID tokens stored in app sandbox storage (`AutofillSaveToken`), bypassing spoofing risks on older Android versions.
- **TileService Intent Dispatch:** Android 14+ (targetSdk 34+) rejects `startActivityAndCollapse(Intent)`. Handlers must branch to use the `PendingIntent` overload on API 34+.
- **Accessibility Service Concurrency:** `BaluardAccessibilityService` must run session decrypts on a background coroutine scope (`AutofillSession.scope`), never calling `runBlocking` on the Android accessibility main thread.
- **Dataset Validation:** `Dataset.build()` throws `IllegalStateException` when fields are empty; empty datasets must be guarded and omitted.
- **Inter-Process Coordination:** Main and `:autofill` processes communicate settings changes via filesystem flags (`AutofillFlagFile`) because `SharedPreferences` instances cache within process boundaries.

---

## 5. Desktop and Tauri UI Invariants

- **Async Tauri Commands:** All IPC socket commands from Tauri Rust backends to the daemon must run inside `spawn_blocking` to prevent blocking the webview's main UI thread.
- **Hermetic Keyring Testing:** `just test` sets `BALUARD_DISABLE_KEYRING=1` to allow cargo test suites to run in headless environments without hanging on D-Bus Secret Service prompts.
- **macOS Ad-Hoc Signatures:** Binaries must be signed with stable bundle identifiers (`app.baluard.desktop.daemon`) via `just _sign-sidecar` so macOS Keychain access permissions persist across local rebuilds.
- **Modal Accessibility:** Modals must use `<FocusTrap>` to maintain focus containment, Esc key dismissal, and proper ARIA dialog attributes.
- **Internationalization:** User-facing strings must use `t("key")` and maintain key parity across `en.json`, `es.json`, and `pt.json`.

---

## 6. Git Provider Integrations

- **Client ID Sentinels:** Default OAuth client IDs for GitLab and Codeberg in source code are placeholder sentinels (`REPLACE_WITH_*`). Users must configure custom OAuth applications or use PAT credentials.
- **GitLab Scope Requirements:** GitLab OAuth device flow requires `api` scope for project creation; repository-only scopes are insufficient.
- **Codeberg Token Scope:** Forgejo/Codeberg OAuth tokens grant broad account access; scoped personal access tokens (`write:repository`) are recommended.
- **Config Parsing Order:** In `connect_pat`, `parse_provider_config` must be executed before clearing sensitive payload buffers to avoid dropping configuration overrides.
- **GitLab Token Refresh Serialization:** GitLab rolling token refresh invalidates earlier token pairs immediately; concurrent refresh calls must be mutex-serialized.

---

## 7. Packaging, Build, and Release Invariants

- **Linux Tray Icon Dependencies:** The system tray requires `libayatana-appindicator3` at build and runtime.
- **Linux Dependency Verification:** Check distro-specific package naming drifts (`libgtk-3-0t64`, `libgit2-1.9`, `libssl3t64`) on target build environments.
- **Build Preflight Environment:** Homebrew's `pkg-config` may shadow system paths on Linux; set `PKG_CONFIG_PATH=/usr/lib64/pkgconfig` when building desktop packages.
- **Release Protocol:** All release processes must follow `docs/dev/release-protocol.md`, ensuring version synchronization across the seven canonical version manifests.
- **Changelog Maintenance:** User-facing pull requests must update `CHANGELOG.md` under `## [UNRELEASED]`.
