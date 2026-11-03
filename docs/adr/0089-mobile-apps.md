# ADR 0089. Mobile Applications

> Status: Accepted (2026-09-27). The Android client is implemented (runtime extraction, UniFFI bridge, onboarding, eight cipher types with detail and edit, sync, conflict panel, multi-vault, autofill, accessibility tile). Several Android acceptance items were wired but still await on-device verification. iOS platform actuals and the credential-provider extension are deferred past 1.0.

## Context

Baluard needs a first-class mobile vault client with offline access, sync, and biometric unlock. Once a vault is cloned the phone works without a network. The mobile app must use the same encrypted vault format and Rust engine as desktop, without requiring a paired desktop or a mobile-specific sync protocol. Everything security-sensitive stays in Rust.

The Rust daemon is a Unix-socket IPC gateway intended for desktop clients, where the CLI and the Tauri app share one unlocked session over a `0600` socket. Mobile operating systems do not support the same long-lived daemon model: iOS cannot run a background Unix-socket daemon, and Android background services are out of scope. Binding the daemon directly is also not an option, because it pulls in socket listeners, protobuf, and desktop keychain code that mobile must not ship.

Autofill and credential-provider extensions run in separate, memory-constrained OS processes. Those processes cannot share the main app's in-memory keys. The vault KDF profile uses 64 MiB by default and 256 MiB in high-security mode (a property fixed at vault creation), while an iOS credential-provider extension has roughly a 50 MB resident cap and an Android autofill service is similarly constrained. Re-deriving the KEK from the master password inside such a process exhausts memory before unlock completes.

## Decision

### Framework and sequence

Use Kotlin Multiplatform and Compose Multiplatform: one Kotlin codebase compiles to Android (Jetpack Compose) and iOS (Skia-rendered Compose), with shared business logic in `commonMain` and `expect/actual` boundaries for OS APIs in `androidMain` and `iosMain`. Alternatives were rejected for these reasons:

| Alternative | Reason rejected |
|-------------|-----------------|
| Two native codebases (Compose and SwiftUI) | Doubles the UI surface and duplicates every bug fix. |
| Tauri v2 mobile | Cannot implement `AutofillService` or `ASCredentialProviderViewController`, which must be native, and WebView autofill is unreliable on Android. Two native extensions would still be required. |
| Flutter | Adds Dart beside Rust, and `dart:ffi` to Rust is manual and error-prone compared with UniFFI-generated Kotlin bindings. |
| React Native | iOS AutoFill is broken there, and the JS-to-native bridge adds attack surface to a security-critical app. |

Android ships first and iOS starts only when the owner signals it, after Play Store release and a period of daily personal use. Reasons: the Rust core, bindings, Compose UI, and conflict logic are written once and consumed by both platforms, so parallel UI work splits attention and delays both; Android autofill is the harder surface (broader `AssistStructure` parsing variability than the constrained iOS API) and the largest single UX win, so proving it first de-risks the mobile bet; and iOS background sync is unreliable by OS design whichever platform leads.

### No daemon: `baluard-runtime` hosted in-process

The app is a native UI shell over `baluard-runtime` and `baluard-core`, hosted in-process through `baluard-uniffi`. Mobile does not run `baluard-daemon`, use its socket, or use protobuf IPC. Rust remains responsible for cryptography, vault CRUD, key lifecycle, sync, conflict resolution, TOTP, passkey storage, password generation (`baluard-core::generator`, a single source for desktop and mobile), and provider operations.

The orchestration that was welded into the daemon was extracted into the `baluard-runtime` crate: `autosync.rs`, `host.rs`, `state.rs`, `pin.rs`, `crypto.rs`, `rate_limit.rs`, and `bridge.rs`, moved with history. The daemon keeps only `handler.rs` (protobuf routing), `main.rs` (socket listener and permissions), and `socket_path.rs`, and re-exports the runtime so both hosts resolve to one implementation. The regression gate was the existing daemon test suite, which had to pass unchanged, especially the conflict lifecycle. Because one implementation serves both hosts, a signature change in `VaultState`, `VaultHost`, or `AutoSyncHandle` affects the daemon and mobile together.

Alternatives rejected: reimplementing the coordinator in Kotlin duplicates the riskiest concurrent code across two languages and guarantees drift; calling `SyncEngine` directly without a coordinator loses debounce and offline recovery and gives a worse sync experience than desktop on day one.

Two extraction decisions remain open design questions rather than settled housekeeping. `bridge.rs` moved into the runtime (lowest churn, reusable by a future mobile companion-unlock), which makes `VaultHost` own browser-pairing state that mobile does not use; if that leaks into mobile's object model, the fix is to decouple the field and have the daemon hold its own registry. And `baluard-core` links `keyring` unconditionally, so mobile links it transitively even though the runtime has no direct dependency; its Android and iOS cross-compilation must be confirmed, with feature-gating in core as the fix if it fails. `VaultState::rebuild_cipher_index` was widened from `pub(crate)` to `pub` for the daemon, and the sync operation timeout constant moved into `autosync.rs`.

### UniFFI boundary

`baluard-uniffi` is a dedicated wrapper that absorbs FFI constraints (owned values, thread-safety, no `&mut self` async patterns, no lifetimes crossing the boundary) so `baluard-core` and `baluard-runtime` stay idiomatic Rust with no UniFFI annotations. It uses UniFFI 0.28 in proc-macro mode (no UDL; `uniffi::setup_scaffolding!()` handles scaffolding; boundary structs need `#[derive(uniffi::Record)]`). UniFFI 0.28 ships no standalone bindgen binary, so bindings are generated by a runner calling `uniffi_bindgen::library_mode::generate_bindings`. Legacy UniFFI functions that lived in core were removed and re-homed in this crate.

UniFFI exposes typed Rust enums, including the eight `CipherKind` variants, as native sum types (Kotlin sealed classes, Swift enums with associated values), not flattened records. Serde's tag model is irrelevant here. Flattening would re-admit illegal combinations such as card fields on a login and push validation into hand-written Kotlin. Async functions map to Kotlin `suspend` and Swift `async` over one shared Tokio runtime owned by the UniFFI layer and dispatched off the UI thread; a Kotlin or Swift caller must never block the UI thread on an FFI call. TOTP seeds and passkey private keys never cross the boundary, only derived codes and formatted strings do.

The 256-bit session token still exists in the runtime (constant-time compared, minted on unlock, invalidated on lock), but in-process on mobile the same-UID oracle threat it defends against on desktop does not arise, so it is defense in depth only. It is memory-only and never persisted. What persists across restarts for quick unlock is the biometric-gated KEK. `VaultHost` and `VaultState` remain the source of truth for multi-vault state; the active-pointer invariant holds, and switching vaults changes only the pointer and never copies or serializes key material (see ADR 0088).

### Per-process unlock and KEK quick unlock

Each OS process that accesses the vault owns an independent runtime and unlock state; key material never crosses a process boundary. With no long-lived background process, each foreground consumer unlocks on demand and zeroizes when done. Autofill and extension processes store a biometric-gated wrapped KEK (StrongBox or Secure Enclave where available) and call `VaultHandle::unlock_with_kek`, which skips Argon2id but still verifies keywraps and canaries. The master-password KDF must never run in a memory-capped extension process. The main app has no such cap and may run the full KDF on first unlock. The keychain therefore holds a wrapped KEK rather than the password, which is a different blast radius that the threat model must document.

The Android actual for `Biometric` has KEK semantics (`isAvailable`, `isEnrolled`, `enroll`, `unlock`): a `BiometricPrompt` `CryptoObject` over an AndroidKeystore AES-GCM key (user authentication required, STRONG biometrics only, invalidated on new biometric enrollment, re-enroll rotates the key) wraps the KEK blob in app-private preferences. After a master-password unlock the app offers a one-time enrollment, which is the single explicit KDF run. The main activity is a `FragmentActivity` for the prompt. Auto-lock is lifecycle-driven (no background walker): the app checks `shouldAutoLock()` on every start, before the pull so no vault UI flashes after a long background, and inside a 15-second foreground poll; a lock zeroizes keys, clears the conflict queue, and returns to the unlock screen.

### Event-driven sync

The daemon runs `AutoSyncHandle::background_loop` as a long-lived task. Mobile instead drives the same coordinator through host-called event methods from lifecycle hooks, over one parked Tokio runtime (nearly free, so the battery claim holds, but required, not avoided). The state machine (Idle, Dirty, Syncing, Offline, NeedsDecision), the 5-second push debounce, the offline-retry counter, the 10-minute focus-pull guard, and the conflict queue stay inside the runtime as one implementation.

| Event | Behavior |
|-------|----------|
| `on_unlock` | Pull on unlock. |
| `on_mutation` | Arm the 5-second debounced push, coalescing bursts. |
| `on_foreground` | Pull with the 10-minute guard (collapses flicker to one pull per 10 minutes). |
| `on_background` | Flush any pending debounce immediately (genuinely new logic). |
| `pull_now` | User pull-to-refresh or "Sync now". |
| `offline_tick` | Host-scheduled 30-second probe while Offline and foregrounded; a no-op unless Offline, so it is safe to fire every tick. |
| `on_conflict` | Read-only peek at the pending conflict (the binding should expose it as a peek, since it acts differently from its siblings). |

Most events are thin wrappers over the daemon's existing methods (`pull_only`, `nudge`, `nudge_focus_pull`, `peek_pending_conflict`), so drift risk is low. The flush on background is mandatory. The debounce is a spawned task with a sleep, and the OS suspends a mobile process seconds after backgrounding, so an edit made just before backgrounding would otherwise sit local-only. The flush aborts the debounce handle first, then runs the sync with a shorter timeout (`BG_FLUSH_TIMEOUT`, 15 seconds) than the 60-second desktop bound, which can exceed Android `goAsync` budgets; iOS `beginBackgroundTask` allows roughly 30 seconds. A kill mid-flush leaves the edit local, and the commit, pull, push order is corruption-safe; the next unlock or foreground pull catches up. The double-flush guard is the state transition under the shared inner lock, with `cycle_lock` as a second layer. `pull_only` refuses to run while a conflict is paused in `NeedsDecision`, because the three new public entry points would otherwise touch a mid-merge worktree.

Accepted divergence from the daemon loop: mobile does not reproduce the 30-minute idle pull, because foreground is the heartbeat. It does reproduce Offline recovery, since `offline_tick` delegates to the same `pull_only` the loop calls. Network failures are classified from git2 transport error classes and move the state to Offline until a probe succeeds; offline handling is core to the offline-first promise, not polish.

Sync triggers and defaults: unlock (default on), after every change (on), foreground with the 10-minute guard (on), explicit pull-to-refresh and "Sync now", the foreground offline probe, and background flush. Optional periodic background sync is off by default, with a 15-minute minimum interval and a 30-minute default when enabled. The reasons for off by default: zero battery cost when closed, most multi-device edits are caught by pull-on-unlock, and iOS rate-limits background fetch regardless. `MobileSyncConfig` carries `sync_on_unlock`, `sync_after_change`, `sync_on_foreground`, `background_sync_enabled`, `background_interval_minutes`, `wifi_only`, and `offline_retry_foreground_secs`.

Background sync on Android uses a locked fetch path: `SyncEngine::fetch_locked` is an objects-only fetch with no unlock, decrypt, checkout, or state transition, and it refuses when the state machine is busy; `background_fetch` in UniFFI exposes it, and a WorkManager periodic worker registered only when the user opts in drives it. Fetched objects are consumed by the next unlock's pull, and conflicts resolve foreground-side. Wi-Fi-only (default on) is advisory at the runtime, because git2 has no network-type awareness. The host gates automatic triggers (unlock, mutation, foreground, offline tick) through an unmetered-network check that fails open, and the WorkManager unmetered constraint enforces it for background fetch. Explicit user gestures and the mandatory background flush are never network-gated.

Conflict resolution runs the shared `merge_ciphers` engine and `NeedsDecision` state machine, surfaced through a Compose port of the desktop conflict panel (no dismiss, since the decision gates sync; cross-epoch hides keep-both). The desktop invariants apply verbatim: `pull_inner` leaves the machine in `Merging` on conflict, `finalize_conflicts` is HEAD-guarded, cross-epoch decrypt fails closed with a `cross_epoch` marker, index rebuild runs on all verdict paths, and resolution bookkeeping happens after a landed merge commit even if the push fails (see ADR 0093).

Mobile folds a probabilistic cover commit into the foreground pull cycle instead of running the desktop 2 to 6 hour timer, because event-driven mobile with background sync off would otherwise leak a cleaner activity signal to the git remote (threat T14). This is a deliberate divergence from the desktop timer model; the mobile path in code has not been verified to implement it.

### Storage

A full shallow Git clone (depth 20) lives in app-private storage (`/data/data/app.baluard.mobile/files/vault/` on Android, `Library/Application Support` on iOS), preserving `.baluard`, `.git`, `meta`, and encrypted `envelopes`. A non-tracked `session/` directory holds ephemeral state such as PIN escrow. Attachments are lazy-downloaded. Typical footprint is 30 to 80 MB for about 1,000 entries (envelopes about 25 MB, shallow history 5 to 30 MB). A SQLite cache like Bitwarden's was rejected: the clone reuses every line of the sync code, keeps the offline promise, lets field-level `merge_ciphers` work unchanged, and makes the Git history the schema, so there are no migrations. Planned storage-pressure mitigations are a "compact history" action (`git gc` and repack) and partial-clone attachment fetch; neither is verified in code.

### Plaintext boundary, autofill, and scope

Rust zeroizes key material, but plaintext handed to Kotlin or Swift lives on the managed heap with unbounded GC lifetime. This is inherent to FFI UIs and a deliberate, documented boundary: secrets are returned only on explicit reveal or copy, list and detail payloads avoid eager plaintext, copies are minimized, and the clipboard clears on a timer.

Android Autofill is a native `AutofillService` in a separate process with View-based picker UI (faster cold launch, strict memory limits); see ADR 0090 and ADR 0091. iOS uses a native `ASCredentialProviderViewController` extension with UIKit, not Compose, with its own runtime and KEK unlock; the extension's memory cap is primarily a crypto constraint, not a UI one. Both pickers are separate from the main app UI.

Mobile supports the existing eight cipher types. Passkey storage stays in `LoginData::fido2_credentials`. The original decision made passkeys display-only on mobile with no platform credential-provider integration. The source has since moved past that: Android now ships a `CredentialProviderService` for passkeys (API 34 and later, origin-validated and fail-closed; see ADR 0095). iOS passkey integration remains unbuilt.

Minimum versions are Android API 32 (Android 12L: modern `BiometricPrompt`, autofill, and network semantics; API 34 is needed only for credential-provider passkeys) and iOS 17. Distribution is Play Store first; F-Droid is deferred. Crash logging is local-file only on both platforms (no Firebase, no ACRA network upload, since Baluard has no server and default ACRA upload would block F-Droid), and users attach logs manually to bug reports. Explicitly out of scope: new mobile cipher types (such as camera scan), a standalone TOTP authenticator app, share-sheet or iOS extension import, and a mobile companion unlock via desktop.

## Consequences

The Git vault and Rust synchronization engine remain consistent across desktop and mobile, and the app works offline after cloning. Mobile has no dependency on a desktop daemon, and one runtime implementation serves both hosts.

OS-specific extension processes must unlock independently. Their biometric KEK storage has a different threat boundary from a master-password unlock. The mobile threat-model update must record: the wrapped KEK in the platform keychain and the never-in-extension KDF rule; un-zeroizable managed-heap plaintext with reveal-on-demand secrets; and memory-only session tokens.

Background sync remains best-effort under OS scheduling and is opt-in. The 30-minute idle pull and the desktop cover timer do not exist on mobile.

Open items from the original scope: iOS builds need a macOS host with Xcode (the Kotlin/Native extension-linking path is the least-traveled and not yet de-risked), the `keyring` cross-compile check, a Rust-side full-text search with a 200 ms target on 1,000 entries, a Material 3 brand pass, battery targets (under 1 percent per day with background sync off, under 3 percent on), crash-free and performance targets, an F-Droid-compatible build pipeline, and a security review of the `baluard-uniffi` boundary. Planned later work: platform credential-provider support on iOS, a paired-companion unlock reusing the browser bridge token kind, a standalone TOTP companion, tablet layouts, and wearable surfaces. Apple review of password managers is strict, especially around autofill.

## References

- `docs/adr/0088-git-providers-multi-vault.md`
- `docs/adr/0090-android-autofill.md`
- `docs/adr/0091-android-accessibility-tile.md`
- `docs/adr/0093-conflict-resolution-panel.md`
- `docs/adr/0095-passkey-support.md`
- `docs/adr/0005-mobile-jit-sync.md`
- `docs/adr/0010-mobile-tier-uniffi-bindings.md`
- `docs/dev/dev-setup-mobile.md`
- `docs/security/threat-model.md`
- `crates/baluard-runtime/src/`
- `crates/baluard-uniffi/src/lib.rs`
- `mobile/shared/src/`
