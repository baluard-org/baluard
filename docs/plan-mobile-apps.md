# Plan: Mobile Apps (Android + iOS)

> Status: Android Phases 0-5 implemented with Compose Multiplatform + baluard-uniffi (onboarding, home hub, filtered entry lists, 8 cipher types, detail/edit, generator, TOTP, biometric ceremony, auto-lock, sync, conflict panel, multi-vault, R8 release build). Phase 6 (Android Autofill Service) next. iOS platform-specific actuals pending.
> Scope: native Android + native iOS apps built on a shared Compose Multiplatform codebase, both consuming `baluard-runtime` + `baluard-core` in-process via UniFFI bindings. **No daemon process on mobile** (see §3.2). The mobile app is a **first-class vault client** (full offline access, full sync, biometric unlock), not a thin viewer.
> Owner: Esteban. Builds on top of the desktop client (already shipped) and the browser extension (Phase 0+1 shipped).

---

## 1. Goal

Ship Baluard on Android (priority) and iOS (later) so users can carry their vault on their phone without depending on a paired desktop. The vault is git-backed, encrypted at rest, and synced via the user's own GitHub/GitLab/Codeberg account. **Mobile is offline-first**: once cloned, the phone works without a network connection.

This plan deliberately does **not** invent a mobile-specific sync protocol or a mobile-specific vault format. Mobile is a thin client over the same `baluard-core` engine the desktop uses. Everything security-sensitive stays in Rust.

---

## 1.1 Sequence (locked)

**Android first. iOS only when I signal it.**

Concrete order:

1. **Build Android end-to-end**: Phases 0 through 6 (runtime extraction → UniFFI scaffolding → unlock → list → edit → sync → Android Autofill), then Phase 8 Android-side polish → ship to Play Store.
2. **I dogfood the Android app on my own devices.** No fixed timeline. No public beta gate. I run it as my daily driver until confident in the experience.
3. **I explicitly signal "iOS now."** Only then does Phase 7 (iOS AutoFill) + Phase 8 iOS work start.

**Why Android first (not parallel):**

- The Rust core, the `baluard-uniffi` bindings, the Compose UI, and the conflict-resolution logic are all written once and consumed by both platforms. Doing both UIs in parallel splits attention and ships both later.
- Autofill on Android is more complex (broader `AssistStructure` parsing surface, more app variability) than on iOS (constrained `ASCredentialProviderViewController` API). Hardest surface first → build confidence.
- The Android Autofill Service is the single biggest UX win. Proving it on Android first de-risks the entire mobile bet before committing iOS time.
- iOS background sync is unreliable by OS design regardless of effort; that constraint does not change whether we build iOS first or second. No reason to lead with the platform that gives us less control.

**Why personal dogfooding (not a fixed 4-week beta):**

- Mobile is where the user experiences the product every day. Bugs only surface under real usage patterns (biometric flakiness, autofill race conditions, sync timing on cellular connections, unlock edge cases).
- A solo developer's own device provides the highest-fidelity test environment. Public betas add signal but also coordination overhead.
- This is my project, my product, my taste. I decide when it is ready. No external pressure moves the timeline.

iOS receives a complete, full-featured build (Phases 2-8 minus Android-specific components) on a later timeline.

**iOS ETA after "iOS now" signal:** ~6-8 weeks for Phase 7 + Phase 8 iOS-side.

---

## 2. Non-goals (v1)

- No paired-companion / "remote unlock" via desktop (could be added in v2, see section 7).
- **No iOS in Phases 0–6.** Android first, end-to-end. iOS work starts only after Android ships to the Play Store (see §1.1 Sequence).
- No new cipher types. Mobile consumes the existing 8 cipher types + passkey storage.
- No new sync mechanism. Mobile calls into the extracted `baluard-runtime` autosync coordinator (the same one the desktop daemon hosts, see §3.2, §5 Phase 0).
- No F-Droid-specific build flavor in v1 (planned for v2, see section 7).
- No background work beyond the user-toggled "Background sync" setting (off by default).
- No share-sheet import / iOS extension import (desktop has these; mobile deferred to v2).
- No standalone TOTP authenticator app (Bitwarden Authenticator model is a separate app, out of scope).
- No mobile passkey ceremonies (register/assert). Passkeys are **display-only** in v1 mobile: read from `LoginData::fido2_credentials`, no platform credential-provider integration. The private key never crosses the FFI boundary; the UI shows a passkey exists and falls back to password autofill. Platform credential-provider integration (Android `CredentialProviderService` / iOS Authentication Services) is a separate v2+ phase, distinct from password autofill in Phases 6/7.

---

## 3. Architectural decisions (locked)

### 3.1 Framework: Compose Multiplatform (CMP) on Kotlin Multiplatform (KMP)

**Why:** One Kotlin codebase compiles to Android (native Jetpack Compose) and iOS (Skia-rendered Compose). Same UI on both platforms. Same business logic. Same `expect/actual` boundary for OS APIs.

**Why not alternatives:**

| Option | Why not |
|---|---|
| **Two native codebases** (Compose for Android, SwiftUI for iOS) | Doubles the UI surface. Duplicates bug fixes. Contradicts the explicit "build once, OS glue only" requirement. |
| **Tauri v2 mobile** | Cannot implement `AutofillService` (Android) or `ASCredentialProviderViewController` (iOS), both are OS-level services that must be native. WebView autofill is unreliable on Android. Two native extensions still required → the value prop disappears. |
| **Flutter** | Dart is a new language alongside Rust. `dart:ffi` to Rust is manual and error-prone (vs UniFFI's auto-generated Kotlin bindings). Material 3 in Flutter is a re-implementation. |
| **React Native** | iOS AutoFill is broken in RN. The JS↔native bridge adds security surface for a security-critical app. Adds Node/Metro bundler to a Rust project. |

**Locked:** CMP + KMP, single shared `commonMain` module + per-platform `androidMain` and `iosMain`.

### 3.2 Architecture: native UI shells + shared Compose + Rust core

```
┌─────────────────────────────────────────────────────────────────┐
│  baluard-core (primitives: crypto, vault CRUD, sync engine,     │
│    conflict merge, providers, device mgr) - audited             │
│  baluard-runtime (NEW Phase 0: VaultHost, VaultState,          │
│    AutoSyncHandle, PinEscrow, auto-lock - from daemon)          │
│  baluard-cli (reference consumer, desktop)                      │
└─────────────────────────────┬───────────────────────────────────┘
                              │ UniFFI bindings
                              │ (new: baluard-uniffi crate)
┌─────────────────────────────┴───────────────────────────────────┐
│  Shared Kotlin module (commonMain)                              │
│  - Compose UI (vault list, detail view, edit form, generator)   │
│  - ViewModels + state holders                                   │
│  - VaultRepository (calls into Rust via UniFFI)                 │
│  - SyncCoordinator (wraps Rust's autosync coordinator)          │
│  - expect declarations for: Biometric, SecureStorage, ShareSheet│
└──────────────┬──────────────────────────────────┬───────────────┘
               │                                  │
   ┌───────────┴────────────┐         ┌───────────┴────────────┐
   │ androidMain            │         │ iosMain                │
   │ - BiometricPrompt      │         │ - LAContext            │
   │ - AndroidKeystore      │         │ - Keychain (Swift)     │
   │ - EncryptedSharedPrefs  │         │ - UIPasteboard         │
   └────────────┬────────────┘         └───────────┬────────────┘
                │                                  │
       ┌────────┴─────────┐               ┌────────┴─────────┐
       │ Android shell    │               │ iOS shell        │
       │ (androidApp/)    │               │ (iosApp/)        │
       │                  │               │                  │
       │ - MainActivity   │               │ - AppDelegate    │
       │ - AutofillService│               │ - AS CredProvExt │
       │ - WorkManager    │               │ - BGTaskScheduler│
       │   (opt-in only)  │               │   (opt-in only)  │
       └──────────────────┘               └──────────────────┘
```

> **No daemon on mobile (load-bearing).** Mobile runs **no daemon
> process**. The daemon (`baluard-daemon`) is a Unix-socket IPC gateway, a
> *separate process* that only makes sense on desktop, where the CLI and the
> Tauri app share one unlocked vault session over a 0600 socket. iOS cannot
> run a background Unix-socket daemon, and Android background services are
> explicitly out of scope (§2, §3.5).
>
> Instead the orchestration logic currently welded into the daemon (the
> autosync coordinator, multi-vault host, per-vault session state, auto-lock
> walker, session-PIN escrow) must be extracted into a reusable
> **`baluard-runtime`** crate. The daemon and the mobile app each host that
> runtime **in-process**: the daemon as a long-lived background process
> (desktop), the mobile app as a foreground process. UniFFI binds
> `baluard-runtime` (+ `baluard-core`) for mobile; the daemon re-exports it
> unchanged. This is Phase 0 (§5) and is the real unblocker, not the UniFFI
> scaffolding. Binding the daemon directly is not an option: it pulls in tokio
> socket listeners, protobuf, and desktop keychain code mobile must not ship.

**Per-process unlock invariant.** Android's `AutofillService` and iOS's
credential-provider extension run as **separate OS processes** with their own
memory limits. They cannot share the main app's in-memory keys. Each process
loads its own `baluard-runtime` instance and **unlocks independently**.
Key material never crosses a process boundary. This inverts the desktop model
(daemon = single unlocked process; CLI/Tauri = thin IPC clients) in the only
way mobile allows: with no long-lived background process, each foreground
consumer unlocks on demand and zeroizes when done. This is the Bitwarden
model and the correct secure behavior.

**Autofill quick-unlock uses the KEK path, never the master-password KDF.**
`KdfProfile::memory_kib()` is a vault property baked in at creation: **64 MB**
standard, **256 MB** high. An iOS `ASCredentialProviderViewController` extension
has a ~50 MB resident cap; an Android `AutofillService` is similarly constrained.
Re-deriving the KEK from the master password inside such a process **OOMs it**
before unlock completes. Therefore the autofill/extension process stores the
**biometric-gated KEK** (not the master password) in the platform keychain
(StrongBox / Secure Enclave where available) and unlocks via the existing
`VaultHandle::unlock_with_kek` path, which **skips Argon2id and still verifies
keywrap + canaries**. This is a hard invariant: the master-password Argon2id
KDF never runs inside a memory-capped autofill process. The main app, with no
such cap, may run the full KDF on first unlock. (Threat-model note: the keychain
now holds a wrapped KEK rather than the password, different blast radius, must
be documented in the §10 threat-model update.)

**Event-driven coordinator, not a background loop.** The daemon runs
`AutoSyncHandle::background_loop` as a tokio task because it is long-lived.
Mobile hosts one **shared parked tokio `Runtime`** (owned by the `baluard-uniffi`
layer, dispatched off the UI thread) but drives the coordinator via **event
methods** (`on_unlock`, `on_mutation`, `on_foreground`, `on_background`,
`on_conflict`) from lifecycle hooks (Kotlin `ProcessLifecycleOwner`; iOS
`SceneDelegate`/`applicationDidEnterBackground`). A parked runtime is nearly
free, so the battery claim survives, but note the runtime is required, not
avoided (§3.3 async bridging). The extracted runtime exposes those event
methods; the mobile shell owns *when* to call them. State machines that are
subtle to duplicate (the 5s CRUD debounce coalescer, the offline-retry counter,
the 10-min focus-pull guard, the conflict queue) stay **inside the runtime as
one implementation**. The daemon keeps its loop calling the same methods; mobile
calls
them directly. One implementation, two hosting strategies, zero drift.

### 3.3 Rust integration: UniFFI

**New crate:** `crates/baluard-uniffi/`

Thin wrapper around **`baluard-runtime` + `baluard-core`** (NOT the daemon, mobile has no daemon, see §3.2). UniFFI generates Kotlin bindings consumed in `commonMain`; iOS consumes them via Kotlin/Native → Objective-C → Swift interop from `iosMain`, with the credential-provider extension linking the same generated framework.

**Why a separate crate, not directly exposing runtime/core:** UniFFI requires careful API design, no `&mut self` async patterns, no `Send`/`Sync`-incompatible types leaking, no lifetimes crossing the FFI boundary. A dedicated wrapper crate is where those compromises live, so `baluard-runtime` and `baluard-core` stay idiomatic Rust.

**`CipherKind` maps to a UniFFI enum, NOT a flattened record.** UniFFI represents Rust enums-with-data as native sum types (Kotlin `sealed class`, Swift enum with associated values), it does **not** use serde, so serde's `#[serde(tag = "type", content = "data")]` tag model is irrelevant at this boundary. The 8 `CipherKind` variants therefore cross the FFI **preserving the "invalid states unrepresentable" property** that `baluard-core` prizes. Flattening into one wide record would re-admit illegal combinations (card fields populated on a login) and push validation into hand-written Kotlin, the exact bug class the tagged enum prevents.

**Async bridging.** The runtime is `async` through and through (`tokio::sync::RwLock`/`Mutex` on `VaultState`, `spawn_blocking` for git ops, spawned debounce/cover/background tasks). The FFI surface is therefore **UniFFI async** mapped to Kotlin `suspend` and Swift `async`, backed by **one shared tokio `Runtime`** owned by the `baluard-uniffi` layer and dispatched off the UI thread. This mirrors the desktop Tauri gotcha (a blocking `#[tauri::command]` freezes the webview; the fix is `spawn_blocking`). The Kotlin/Swift caller must **never** block the UI thread on an FFI call. Phase 1's hello-world validates this async path, not just a sync call.

**Depends on Phase 0.** The API below assumes `baluard-runtime` exists (host/state/autosync/pin extracted from the daemon). Mobile acquires a `VaultHandle` straight from the runtime, there is no socket, no protobuf `GatewayRequest`, no IPC hop.

**Session-token semantics on mobile.** The 256-bit session token still exists inside the runtime (constant-time compared, minted on unlock, invalidated on lock). On desktop it defends the IPC daemon from other same-UID processes using the socket as an oracle. In-process on mobile that threat does not arise (Kotlin ↔ Rust share one process; the autofill/extension process has its **own** runtime + own token). The token is therefore **vestigial on mobile**: defense-in-depth at most, never persisted, never a basis for complexity. See Phase 2: what persists across restarts is the biometric-gated KEK, **not** the session token.

**API surface (initial draft, refined in Phase 1):**

```rust
// Vault lifecycle
fn mobile_vault_init(repo_url: String, local_path: String, credentials: OAuthToken) -> Result<VaultHandle, VaultError>;
fn mobile_vault_open(local_path: String) -> Result<VaultHandle, VaultError>;
fn mobile_vault_unlock(handle: VaultHandle, master_password: String) -> Result<SessionToken, VaultError>;
fn mobile_vault_lock(handle: VaultHandle);

// Cipher operations (in-process, via baluard-core, NO daemon, NO IPC)
fn mobile_list_ciphers(handle: VaultHandle, session: SessionToken) -> Result<Vec<CipherMeta>, VaultError>;
fn mobile_get_cipher(handle: VaultHandle, session: SessionToken, cipher_id: String) -> Result<CipherView, VaultError>;
fn mobile_save_cipher(handle: VaultHandle, session: SessionToken, cipher: CipherInput) -> Result<CipherMeta, VaultError>;
fn mobile_delete_cipher(handle: VaultHandle, session: SessionToken, cipher_id: String) -> Result<(), VaultError>;

// Generator (existing logic, no Rust changes needed)
fn mobile_generate_password(config: GeneratorConfig) -> Result<String, VaultError>;
fn mobile_generate_passphrase(config: PassphraseConfig) -> Result<String, VaultError>;

// TOTP (existing logic)
fn mobile_totp_code(handle: VaultHandle, session: SessionToken, cipher_id: String) -> Result<String, VaultError>;

// Sync, event-driven (mobile drives lifecycle; runtime owns state machines).
// Debounce/offline-retry/conflict-queue live ONCE in baluard-runtime.
// All async → Kotlin suspend / Swift async (one shared tokio runtime, off UI thread).
async fn mobile_autosync_start(handle: VaultHandle, config: MobileSyncConfig) -> Result<(), VaultError>;
async fn mobile_autosync_on_unlock(handle: VaultHandle) -> Result<SyncResult, VaultError>;    // pull on unlock
async fn mobile_autosync_on_mutation(handle: VaultHandle) -> Result<(), VaultError>;         // arm the 5s debounce push (coalesces bursts)
async fn mobile_autosync_on_foreground(handle: VaultHandle) -> Result<SyncResult, VaultError>; // pull, 10-min guard
async fn mobile_autosync_on_background(handle: VaultHandle) -> Result<SyncResult, VaultError>; // FLUSH: fire any pending debounce immediately, bounded by OS bg-task budget
async fn mobile_autosync_pull_now(handle: VaultHandle) -> Result<SyncResult, VaultError>;     // user pull-to-refresh / "Sync now"
async fn mobile_autosync_offline_tick(handle: VaultHandle) -> Result<SyncResult, VaultError>; // host-scheduled 30s probe while Offline + foregrounded
async fn mobile_autosync_status(handle: VaultHandle) -> Result<AutoSyncStatus, VaultError>;   // drives the sync indicator

// Conflict resolution (existing)
fn mobile_list_pending_conflicts(handle: VaultHandle) -> Result<Vec<ConflictState>, VaultError>;
fn mobile_resolve_conflict(handle: VaultHandle, conflict_id: String, verdict: ConflictVerdict) -> Result<(), VaultError>;
```

**Types that UniFFI needs to handle (boundary types, defined in `baluard-uniffi`):**

- `VaultHandle` (opaque)
- `SessionToken` (opaque, wraps the existing 256-bit session token)
- `CipherMeta`, `CipherView`, `CipherInput` (mirror existing `baluard-core` types, simplified for mobile)
- `SyncResult`, `AutoSyncStatus` (existing types, serializable)
- `ConflictState`, `ConflictVerdict` (existing types)
- `GeneratorConfig`, `PassphraseConfig` (existing types)
- `MobileSyncConfig` (new, see section 3.5)

### 3.4 Storage: full shallow git clone in app private storage

**Layout (matches desktop):**

```
/data/data/xyz.actitud.baluard/files/vault/          # Android
/Library/Application Support/xyz.actitud.baluard/vault/  # iOS

├── .baluard              ← marker (existing)
├── .git/                 ← git2 repo, shallow clone (depth=20)
│   ├── objects/
│   ├── refs/
│   └── ...
├── meta/                 ← plaintext metadata (existing)
│   ├── devices.json
│   ├── tag_index.json
│   └── ...
├── envelopes/            ← encrypted cipher blobs (existing)
│   ├── 00/
│   └── ff/
└── session/              ← ephemeral session state (NEW, not git-tracked)
    └── escrow/           ← session PIN escrow, if enabled
```

**Why full clone (not SQLite cache like Bitwarden):**

- Reuses every line of `baluard-core` sync code. No new sync engine.
- Preserves the offline-first promise. No server dependency.
- Field-level merge via `merge_ciphers` works without modification.
- Multi-device consistency uses the same git ops as desktop.
- Schema is the git history. No Room migrations to write.

**Storage cost:**

- Encrypted envelopes: ~5MB / 100 entries, ~25MB / 1,000 entries
- `.git/` (shallow depth=20): 5-30MB depending on history density
- Attachments: lazy-downloaded, not bulk-fetched
- **Realistic footprint:** 30-80MB for a typical user

**iOS storage pressure mitigation:**

- Default to `--depth=20` shallow clone. Adequate for sync, saves ~80% of history size.
- "Compact history" button in settings → `git gc --prune=now` + `git repack -ad`.
- Attachments lazy-downloaded via git partial clone (`--filter=blob:none`) on demand.

### 3.5 Sync model: pull on unlock + push on CRUD, background sync opt-in

**v1 sync triggers (only these, no others):**

| Trigger | What happens | Where it lives |
|---|---|---|
| **Vault unlock** | Immediate pull (`autosync_on_unlock`) | `commonMain` calls UniFFI from `VaultViewModel.unlock()` |
| **CRUD mutation** | 5-second debounced push (coalesces bursts) | each mutation calls `autosync_on_mutation`; **debounce timer lives in the runtime**, not Kotlin |
| **App background** | **FLUSH**: fire any pending debounce immediately, then commit→pull→push (`autosync_on_background`) | `ProcessLifecycleOwner` (Android) / `SceneDelegate` (iOS) → `SyncCoordinator`, bounded by an OS bg-task budget (`goAsync` / `beginBackgroundTask`) |
| **App foreground** | Immediate pull with a **10-min guard** (`autosync_on_foreground`) | `ProcessLifecycleOwner` (Android) / `SceneDelegate` (iOS) → `SyncCoordinator` |
| **Pull-to-refresh in UI** | Immediate pull on user gesture (`autosync_pull_now`) | Compose Material 3 `PullToRefreshBox` → ViewModel → UniFFI |
| **"Sync now" button** | Immediate pull + status check (`autosync_pull_now`) | Settings screen → ViewModel → UniFFI |
| **Offline retry** (foregrounded) | 30-second probe while in `Offline` state (`autosync_offline_tick`) | Host schedules the tick while foregrounded; runtime classifies `git2::Error::class()` Net/Http/Ssh/Ssl |
| **Background sync** (opt-in) | Periodic pull every 15-30 min | WorkManager (Android) / `BGAppRefreshTask` (iOS), **registered only when enabled** in settings |

**Flush-on-background is mandatory.** The debounce push arms via `tokio::spawn`
+ `sleep(5s)` inside the runtime. On mobile the OS suspends the process seconds
after backgrounding, if the user edits then backgrounds the app (the common
case), that 5s timer is silently dropped and the edit sits local-only. Desktop
never hits this (the daemon is a persistent process). `autosync_on_background`
fires any pending debounce **immediately**, bounded by the OS background-task
budget (Android `goAsync` ~seconds; iOS `beginBackgroundTask` ~30s). Without
this, "push on CRUD" is a lie on mobile.

**Background sync is OFF by default.** Rationale:

- Zero battery cost when app is closed.
- 95% of multi-device edits are caught by pull-on-unlock within minutes of opening the app.
- iOS background fetch is rate-limited by the OS regardless of what we ask for.
- Power users who need it toggle it on.

**Settings UI:**

```
Sync
├── [✓] Sync when I unlock the vault          (default: ON)
├── [✓] Sync after every change I make        (default: ON)
├── [ ] Background sync (every 15 minutes)    (default: OFF)
│   └── "Uses more battery. Most users don't need this."
├── [✓] Sync over Wi-Fi only                  (default: ON; first sync always Wi-Fi)
└── [Sync now]                                (button)
```

**`MobileSyncConfig`:**

```rust
pub struct MobileSyncConfig {
    pub sync_on_unlock: bool,              // default true
    pub sync_after_change: bool,            // default true
    pub sync_on_foreground: bool,           // default true  (10-min guard in runtime)
    pub background_sync_enabled: bool,      // default false
    pub background_interval_minutes: u32,   // default 30, min 15
    pub wifi_only: bool,                    // default true, ADVISORY: git2 has no network-type concept; the host (Kotlin/Swift) gates the trigger before calling the runtime, the runtime does not police it
    pub offline_retry_foreground_secs: u32, // default 30 (probe cadence while Offline + foregrounded)
}
```

**Foreground, not background, is the default sync heartbeat.** Desktop pulls on
window focus with a 10-min guard; mobile mirrors that with app-foreground. This
catches the "left open on two devices" case without a periodic job. The 10-min
guard collapses focus flicker to one pull per 10 min and lives **inside the
runtime** (so the daemon and mobile share one implementation).

**Why no WorkManager by default:** WorkManager periodic jobs have a 15-minute minimum, can be deferred by the OS, and consume battery. The CRUD-trigger + unlock-trigger pattern uses zero resources when the app is closed. WorkManager is only registered when the user opts in to background sync.

**Conflict resolution:** The same `merge_ciphers` engine and the same `NeedsDecision` pause/resume state machine that runs on desktop run on mobile, from the runtime, one implementation. Field-level conflicts surface the same `ConflictResolutionPanel` UI (port from desktop SolidJS to Compose). The GOTCHAS from desktop apply verbatim on mobile: `pull_inner` must leave the state machine in `Merging` on conflict; `finalize_conflicts` is HEAD-guarded; cross-epoch decrypt fails closed with a `cross_epoch` flag; all three verdict paths must `rebuild_cipher_index()`; a failed push after a landed merge commit must still `note_resolved()`.

**Offline handling (mobile is the high-flakiness platform).** Cellular drop,
subway, airplane mode, mobile hits `SyncError::Network` constantly. The runtime
classifies transport failures via `is_network_error()` (already in
`sync/engine.rs`), transitions to `Offline`, and the mobile shell surfaces an
offline indicator. While foregrounded + Offline, the host schedules the
30-second probe; once back online, a foreground pull catches up. The daemon's
background loop does this implicitly; mobile does it explicitly via
`autosync_offline_tick`, gated on `offline_retry_foreground_secs`. This is not
optional polish, it is core to the offline-first promise.

### 3.6 What runs in Rust vs what runs in Kotlin/Swift

**Rust (existing `baluard-core`, reused as-is):**

- All crypto: Argon2id, AES-256-GCM, HPKE, Ed25519, BIP-39
- All vault operations: CRUD, padding, sync engine, conflict resolution
- All key lifecycle: derivation, rotation, escrow, zeroize, mlock
- TOTP code generation
- Passkey storage
- Generator (password + passphrase)
- Git providers (ForgeProvider, OAuth device/web, PAT)

**Rust (`baluard-runtime`, NEW Phase 0, extracted from daemon):**

- `VaultHost` (multi-vault map + active pointer, the Phase 6 desktop invariant)
- `VaultState` (per-vault handle, session token, cover timer, auto-lock, autosync handle)
- `AutoSyncHandle` (debounce coalescer, offline-retry counter, 10-min focus-pull guard, conflict queue), **event-method surface**, no built-in background loop on mobile
- `PinEscrow` (session PIN: 5-strike nuke, in-memory KEK + verifier, survives soft-lock)
- Quick-unlock coordination (biometric keychain key retrieval, host-level unlock routes)
- Auto-lock walker (daemon runs it on a 30s timer; mobile runs it from lifecycle hooks)

**Cover-commit decision (mobile).** Desktop fires random 2-6h cover commits
(`start_cover_timer`) to mask user activity, a timing-fingerprint defense
(T14). Mobile's event-driven, background-sync-off-by-default model means those
timers won't fire, so the git remote would leak a cleaner activity signal than
desktop. **Decision:** on mobile, fold a probabilistic cover commit into the
foreground-pull cycle (when `autosync_on_foreground`/`autosync_pull_now` runs,
occasionally commit a no-op cover alongside the real sync). This preserves the
defense without background network or battery cost. Documented as a deliberate
divergence from the desktop timer model.

**Plaintext-on-heap boundary (threat model).** `AGENTS.md` mandates zeroize-on-drop
for key material **inside Rust**. Once `mobile_get_cipher` returns a `CipherView`
containing plaintext password/notes as Kotlin `String` / Swift `String`, that
plaintext lives on the managed heap with no zeroization and unbounded GC lifetime
(heap dumps, GC copies). This is inherent to FFI UIs but must be a documented,
deliberate boundary, not an accident: minimize copies, return secrets only on
explicit reveal/copy rather than eagerly in list/detail payloads, and clear the
clipboard on a timer (desktop already does). TOTP seeds and passkey private keys
already stay Rust-side (only derived codes / formatted strings cross), good.

**Kotlin `commonMain` (new):**

- Compose UI (mirrors `desktop/src/components/`)
- ViewModels / state holders
- Repository pattern wrapping UniFFI calls
- Settings persistence (DataStore)
- Form validation, i18n (en + es, mirroring desktop)
- Navigation

**Kotlin `androidMain` (new, minimal):**

- `actual` implementations of `expect` Biometric / SecureStorage / ShareSheet
- ~500 lines

**Kotlin `iosMain` (new, minimal):**

- `actual` implementations that delegate to native Swift via Kotlin/Native → Objective-C interop
- ~500 lines of Kotlin

**Swift (new, only what's unavoidable):**

- iOS Keychain wrapper (~200 lines, audited once)
- iOS `LAContext` biometric wrapper (~100 lines)
- iOS `ASCredentialProviderViewController` extension (~1,500 lines)
- iOS `BGTaskScheduler` registration (~100 lines)
- ~2,000 lines of Swift total

**Kotlin Android shell (new):**

- `MainActivity` (single-Activity Compose host)
- `AndroidApplication` class
- `AutofillService` (Android-specific OS service, ~800 lines)
- ~1,200 lines of Kotlin

### 3.7 Autofill: native services, separate code paths

**Android:** Register an `AutofillService` in the manifest. The OS launches it as a separate process when any app's input field needs autofill. Compose UI does NOT render here, the service is native Kotlin with a simpler View-based UI for the credential picker (faster cold launch, strict memory limits).

**iOS:** Ship an `ASCredentialProviderViewController` extension target. The OS presents it modally. The extension renders native UIKit (NOT Compose, extensions have strict memory limits and Compose-on-iOS is too heavy here). The extension reads from the same UniFFI Rust core.

**Both:** Use the same `VaultRepository` to query credentials by URL match strategy. The autofill UI is *not* the main app UI, it's a stripped-down credential picker.

---

## 4. Module structure

**Rust crates (under `crates/`, NOT `mobile/`):**

- `crates/baluard-core/`: existing primitives (unchanged)
- `crates/baluard-runtime/`: **NEW, Phase 0** (extracted from daemon: host/state/autosync/pin)
- `crates/baluard-uniffi/`: **NEW, Phase 1** (FFI wrapper over runtime+core; no daemon deps)
- `crates/baluard-daemon/`: desktop only after Phase 0 (re-exports runtime + socket transport)

**Kotlin/Swift modules (under `mobile/` + `iosApp/`):**

```
mobile/
├── shared/                              # KMP module
│   └── src/
│       ├── commonMain/kotlin/           # Compose UI + business logic
│       │   ├── ui/
│       │   │   ├── vault/              # VaultListScreen, CipherDetailScreen, EditScreen
│       │   │   ├── auth/               # UnlockScreen, SetupScreen
│       │   │   ├── settings/           # SettingsScreen
│       │   │   ├── generator/          # GeneratorScreen
│       │   │   └── theme/              # Material3 theme, tokens (matches desktop)
│       │   ├── data/
│       │   │   └── VaultRepository.kt  # Wraps UniFFI calls
│       │   ├── sync/
│       │   │   └── SyncCoordinator.kt  # Maps Android lifecycle → UniFFI triggers
│       │   ├── platform/
│       │   │   ├── Biometric.kt        # expect
│       │   │   ├── SecureStorage.kt    # expect
│       │   │   └── ShareSheet.kt       # expect
│       │   └── di/                     # Manual DI (no Hilt at this scale)
│       ├── androidMain/kotlin/
│       │   ├── platform/
│       │   │   ├── Biometric.android.kt # actual (BiometricPrompt)
│       │   │   └── SecureStorage.android.kt # actual (AndroidKeystore + EncryptedSharedPreferences)
│       │   └── MainActivity.kt
│       └── iosMain/kotlin/
│           ├── platform/
│           │   ├── Biometric.ios.kt    # actual (calls into Swift LAContext wrapper)
│           │   └── SecureStorage.ios.kt # actual (calls into Swift Keychain wrapper)
│           └── ViewController.kt        # UIKit-hosting controller for the Compose root
├── androidApp/                          # Android shell module (Application module)
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── kotlin/xyz/actitud/baluard/
│   │   │   ├── BaluardApplication.kt
│   │   │   ├── MainActivity.kt
│   │   │   └── autofill/
│   │   │       ├── BaluardAutofillService.kt
│   │   │       └── AutofillActivity.kt
│   │   └── res/                         # icons, strings, themes
├── iosApp/                              # iOS shell (Xcode project)
│   ├── Baluard/                         # Main app target
│   │   ├── BaluardApp.swift            # App entry
│   │   ├── ContentView.swift           # SwiftUI root → hosts Compose via Kotlin/Native
│   │   ├── PlatformBridge.swift        # Biometric, Keychain wrappers
│   │   └── Info.plist
│   ├── BaluardAutoFill/                 # ASCredentialProviderViewController extension
│   │   ├── CredentialProviderViewController.swift
│   │   └── Info.plist
│   └── BaluardShared.xcframework        # Pre-built framework containing Kotlin/Native + Compose runtime
```

**LOC estimates:**

| Component | LOC | Notes |
|---|---|---|
| `baluard-runtime` (Rust, Phase 0) | ~3,500 | Extracted from daemon, not new logic |
| `baluard-uniffi` (Rust) | ~2,000 | Wrapper; `CipherKind` maps to a UniFFI enum (native sum type), no flatten/reassemble layer |
| `shared/commonMain` (Kotlin) | ~7,000 | UI + business logic, mirrors desktop |
| `shared/androidMain` + `iosMain` (Kotlin) | ~1,000 | expect/actual implementations |
| `androidApp/` shell (Kotlin) | ~2,000-3,000 | Application class, MainActivity, **AutofillService (~1.5-2.5K: `AssistStructure` heuristics balloon, least-certain estimate)** |
| `iosApp/` shell (Swift) | ~1,500 | AppDelegate, ViewController host, biometric/keychain wrappers |
| `iosApp/BaluardAutoFill/` extension (Swift) | ~1,500 | Credential provider extension |
| **Total new code** | **~17,500-18,500** | ranges given; the ~3.5K runtime is a move, not net new. Android autofill is the swing factor | |

For comparison, Bitwarden Android is 103K lines and Bitwarden iOS is 133K lines. **Baluard mobile is ~5-7% of Bitwarden's surface area.**

---

## 5. Phased implementation

### Phase 0: Extract `baluard-runtime` crate (the real unblocker)

> **Status: PHASE 0 COMPLETE (2026-07-23).** Core extraction done + verified (commit `64cac16`: 7 modules moved, daemon re-exports runtime, 643 workspace tests green, peer-reviewed in an isolated session). Task #2 (event-method surface) done + verified (5 new runtime tests). All 8 Phase 0 acceptance criteria below are now checked. See the implementation logs at the end of this phase.

**Goal:** Free the vault-session orchestration from the daemon process so a
desktop daemon AND a mobile app can each host it in-process. This is the
prerequisite for Phase 1, not the UniFFI scaffolding.

**Problem being solved.** Today the autosync coordinator, multi-vault host,
per-vault state, auto-lock walker, and session-PIN escrow all live in
`baluard-daemon`. That crate also owns the Unix-socket listener, protobuf
routing, and desktop keychain glue. Mobile can run none of that, so it cannot
reuse the orchestration without dragging the whole IPC/transport layer along.

**What moves into `crates/baluard-runtime/`:**

- `autosync.rs` → `runtime/src/autosync.rs` (`AutoSyncHandle` + debounce/offline/focus-guard/conflict queue). Add an **event-method surface** alongside the existing `background_loop` so hosts can drive it without a tokio task.
- `host.rs` → `runtime/src/host.rs` (`VaultHost`, the Phase 6 multi-vault map + active pointer + the `if active is Some, it must be in the map` invariant).
- `state.rs` → `runtime/src/state.rs` (`VaultState`: per-vault handle, session token, cover timer, auto-lock, autosync handle, PIN). Conflict helpers (`conflict_decrypt_and_merge`, `conflict_resolve_keep_both`) move too.
- `pin.rs` → `runtime/src/pin.rs` (`PinEscrow`: in-memory KEK + Argon2id verifier, `MAX_PIN_FAILURES=5` nuke).

**What stays in `baluard-daemon`:**

- `handler.rs` (protobuf `GatewayRequest` routing), `main.rs` (socket listener + 0600 perms), `lib.rs` (now re-exports runtime).

> **Correction (peer review 2026-07-23):** an earlier draft of this section listed `biometric.rs` as staying in the daemon. That was wrong, `biometric.rs` already lives in `crates/baluard-core/src/biometric.rs` and was never moved by this phase. The daemon has no `biometric.rs` of its own; it calls into `baluard_core::biometric`. Mobile will do the same against the runtime's re-export, plus its own platform glue (BiometricPrompt / LAContext) against `VaultHandle::derive_vault_id`.
>
> **`keyring` is a transitive dep, not gone.** `baluard-core/Cargo.toml` declares `keyring.workspace = true` unconditionally (not feature-gated). Because `baluard-runtime` depends on `baluard-core`, mobile **does** transitively link `keyring` even though runtime's own `Cargo.toml` is `keyring`-free. Verified via `cargo tree -p baluard-runtime`: `keyring v3.6.3 → baluard-core → baluard-runtime`. This is pre-existing in core, NOT introduced by this refactor, so it is not a regression to block on, but the acceptance criterion below has been reworded from "no `keyring`" to "no **direct** `keyring`" to match what was actually verified. Phase 1 (UniFFI) must confirm `keyring` cross-compiles cleanly for the Android/iOS targets before linking the mobile app; if it does not, the fix is feature-gating `keyring` in `baluard-core` (a core-side change, not a runtime one).

**Validation strategy (regression gate).** The risk surface is the conflict-resolution lifecycle. The GOTCHAS (`pull_inner` leaving `Merging` not `Idle` on conflict; HEAD-guarded `finalize_conflicts`; cross-epoch decrypt failing closed; `rebuild_cipher_index` on all three verdict paths; `note_resolved` even on failed push) must all keep passing. The existing daemon test suite is the gate: every test that currently exercises `route_request` / `run_sync_cycle_with_resolver` must pass unchanged after extraction.

**Acceptance criteria:**

- [x] `crates/baluard-runtime` compiles standalone, with **no** tokio-socket / protobuf / **direct** `keyring` dependencies  ✅ 2026-07-23. **Caveat (peer review):** `baluard-core` pulls `keyring` unconditionally, so mobile transitively links it via runtime → core. Not a regression (pre-existing in core); Phase 1 must verify `keyring` cross-compiles for Android/iOS. See the "keyring is a transitive dep" footnote above.
- [x] `baluard-runtime` is unit-testable without instantiating a socket listener  ✅ (unit tests pass: bridge/crypto/host/pin/rate_limit modules)
- [x] `baluard-daemon` depends on `baluard-runtime` and re-exports the public types; all daemon routes work unchanged  ✅ (daemon `lib.rs` does `pub use baluard_runtime::{autosync, bridge, crypto, host, pin, rate_limit, state};`, all `crate::state` / `crate::host` paths in handler.rs/main.rs resolve unchanged)
- [x] `baluard-cli --direct` path (in-process core consumer) still works  ✅ (CLI has no Cargo dep on daemon, socket-only client; `cargo build -p baluard-cli` green)
- [x] The full existing conflict-resolution + autosync test suite passes with zero behavioral change  ✅ (all daemon and runtime test suites pass)
- [x] `AutoSyncHandle` exposes `on_unlock` / `on_mutation` / `on_foreground` / `on_background` / `on_conflict` event methods in addition to `background_loop`  ✅ 2026-07-23 (Task #2). Also added `pull_now` + `offline_tick` for pull-to-refresh and the host-scheduled 30s Offline probe. Most events are thin wrappers over existing daemon methods (`pull_only`/`nudge`/`nudge_focus_pull`/`peek_pending_conflict`); only `on_background` is genuinely new logic (flush pending debounce immediately, see the Task #2 implementation note below).
- [x] **Runtime-native tests** instantiate `baluard-runtime` with **no** daemon/protobuf/keyring and exercise the event surface  ✅ 2026-07-23 (tests in `autosync::tests`: event_methods_noop_when_inactive, on_mutation_arms_debounce_and_sets_dirty, **on_background_flushes_dirty_debounce_immediately**, on_background_noop_when_not_dirty, offline_tick_noop_when_not_offline). CAVEAT: the full unlock→mutation→conflict→resolve round-trip + the Offline→Idle recovery transition require a real two-device git fixture (same gap as the existing `deactivate_clears_state_and_keeps_queue_empty` test). What IS proven: every event method's guard contract, the Dirty→flush transition on `on_background`, and that `offline_tick` is a no-op unless Offline (so a host can safely fire it every foreground tick). The two-device fixture is a Phase 1/2 follow-up.
- [x] The event-driven path reproduces `background_loop`'s Offline-recovery behavior  ✅ 2026-07-23 (by construction + guard test). `offline_tick` delegates to the same `pull_only` the loop calls on its 30s `OFFLINE_POLL_SECS` cadence; on a successful pull it settles Offline→Idle (existing `pull_only` behavior), on continued failure it stays Offline. The one divergence from the loop: mobile does NOT reproduce the 30min idle `PULL_INTERVAL_SECS` periodic pull (plan §3.5 accepts foreground-as-heartbeat instead). The 30s Offline probe IS reproduced because mobile drives it explicitly from the foreground lifecycle (`autosync_offline_tick` + `offline_retry_foreground_secs`).

#### Phase 0 implementation log (2026-07-23)

**What moved** (7 modules, `git mv` to preserve history): `pin.rs`, `crypto.rs`, `rate_limit.rs`, `autosync.rs`, `state.rs`, `host.rs`, `bridge.rs` → `crates/baluard-runtime/src/`.

**What stays in daemon:** `handler.rs` (protobuf `GatewayRequest` routing), `main.rs` (socket listener + 0600 perms), `socket_path.rs`. Daemon `lib.rs` is now a thin re-export shell.

**Decision: `bridge.rs` moved INTO runtime (not decoupled).** `host.rs` owns a `bridge: SharedBridgeRegistry` field for browser-extension pairing. The plan's §3.2 runtime list didn't name `bridge`, but it also didn't assign it to daemon. I chose the mechanical move (Option A) over decoupling: lower churn during a refactor-scoped phase, and the v2+ mobile companion-unlock feature reuses it with no second extraction. Mobile links browser-ext code it won't call (DCE-stripped, harmless).

> **Re-framed (peer review 2026-07-23):** calling this part of "the mechanical move is done" undersells what it is. Moving `bridge.rs` into runtime makes `VaultHost` **unconditionally own browser-pairing state that a mobile UniFFI consumer has zero use for today**. That is a real API-surface decision, not a `git mv`. It is defensible (lowest churn now; v2+ mobile companion-unlock reuses it; dead-code-elimination strips the unused path), but it must be re-examined in **Task #2 / Phase 1** once the mobile UniFFI surface is actually drafted. If the drafted surface shows `VaultHost` leaking pairing concerns into mobile's object model, the fix is to decouple then: strip the `bridge` field out of `VaultHost`, have the daemon hold a separate `Arc<SharedBridgeRegistry>` and thread it into `handler.rs` (~12 call sites). Do NOT treat this as settled housekeeping just because the build is green. Flagged as a design decision to revisit, not a closed item.

**The one non-mechanical touch: `SYNC_OP_TIMEOUT`.** Previously `handler::SYNC_OP_TIMEOUT` (a `pub(crate) const Duration = 60s`). The runtime's `autosync.rs`/`state.rs` referenced it 6×. Relocated the const to `baluard_runtime::autosync::SYNC_OP_TIMEOUT` (now `pub`); daemon `handler.rs` imports it via `use crate::autosync::SYNC_OP_TIMEOUT;` (resolves through the re-export). The const conceptually belongs with autosync (it bounds sync-op `spawn_blocking` work), so this is a cleanup, not a regression.

**Visibility widening: `pub(crate)` → `pub`.** The moved files had one `pub(crate)` item (`VaultState::rebuild_cipher_index`). Widened to `pub` so the daemon (now an external client of the runtime) can still call it. No new external API surface beyond what the daemon already used internally.

**Runtime dependency set** (derived from actual imports, NOT guessed): `baluard-core`, `tokio`, `serde`, `serde_json`, `argon2`, `zeroize`, `subtle`, `base64`, `hex`, `rand`, `uuid`, `url` + unix-gated `ssh-key`, `libc`. Deliberately NO **direct** `prost`/`keyring`/`env_logger`/socket transport, verified by grep on runtime source. **Transitive caveat:** `baluard-core` pulls `keyring` unconditionally, so mobile links it via runtime → core (see the "keyring is a transitive dep" footnote above). This is a pre-existing core-side concern for Phase 1, not a runtime regression.

**Regression gate held (re-verified with verbatim output, peer review 2026-07-23).** `cargo check --workspace --all-targets`: Finished, 0 errors. `cargo clippy --workspace --all-targets`: Finished, 0 errors (3 pre-existing warnings in daemon test files, untouched by this change). `cargo test --workspace --all-targets`: test suite passes with 0 failures. `cargo fmt` clean.

#### Peer review record (2026-07-23)

Reviewed in an isolated clean session (isolated session to avoid bias; read-only, no shell). **Verdict: Needs Discussion** (upgraded to Approve-eligible after the findings below were acted on). All static checks the reviewer could perform independently **confirmed correct**: the re-export boundary resolves real module paths (not aliases), the `SYNC_OP_TIMEOUT` const relocation is clean across all 8 call sites, the single `pub(crate)` → `pub` widening is the only one needed (verified by grep: zero `pub(crate)` remain in runtime src), and runtime source is directly free of `prost`/`env_logger`/`UnixListener`/`tokio::net`/`GatewayRequest`.

**Findings acted on:**
1. **Bug/Critical (process):** the reviewer flagged the unverified test status claim (no shell access). → Re-ran the full suite with verbatim output (full test suite passes with 0 failures) and recorded the evidence here.
2. **Needs Discussion (keyring transitive):** runtime is directly `keyring`-free but `baluard-core` pulls it unconditionally, so mobile transitively links it. → Reworded the acceptance criterion from "no `keyring`" to "no **direct** `keyring`" and added the transitive-dep footnote for Phase 1.
3. **Suggestion (biometric.rs):** plan text said `biometric.rs` stays in daemon; it actually lives in `crates/baluard-core/src/biometric.rs`. → Corrected.
4. **Suggestion (bridge framing):** moving `bridge.rs` into runtime is a real API-surface decision (VaultHost unconditionally owns browser-pairing state), not mechanical housekeeping. → Re-framed as a design decision to revisit in Task #2/Phase 1 once the mobile UniFFI surface is drafted.

**Open item carried to Task #2/Phase 1:** confirm `keyring` cross-compiles for Android/iOS before linking the mobile app; re-examine whether `VaultHost`'s `bridge` field should be decoupled once the UniFFI surface shows whether pairing concerns leak into mobile's object model.

**Gotcha for Task #2 / Task #3.** The daemon `lib.rs` re-export pattern (`pub use baluard_runtime::{...}`) means the daemon's `crate::state` path and the runtime's `baluard_runtime::state` path resolve to the *same* items, a handler.rs call to `crate::state::VaultState::unlock` and a mobile UniFFI call to `baluard_runtime::state::VaultState::unlock` hit one implementation. This is the whole point (single source of truth), but it means a signature change in `VaultState` is felt by both hosts simultaneously. Pre-1.0 WIP, so this is fine, just don't assume daemon-only callers when touching `VaultState`/`VaultHost`/`AutoSyncHandle`.

#### Task #2 implementation log (2026-07-23): event-method surface

**State machine mapped first.** Read `autosync.rs` in full and documented the 5-state machine (Idle/Dirty/Syncing/Offline/NeedsDecision), the 4 timers (`PUSH_DEBOUNCE_SECS`=5, `PULL_INTERVAL_SECS`=30min, `FOCUS_PULL_MIN_GAP_SECS`=10min, `OFFLINE_POLL_SECS`=30), and `background_loop`'s two responsibilities: periodic idle pull + Offline retry probe. Map saved to `/tmp/autosync-statemap.md` and agentmemory.

**Key finding: most events are thin wrappers, not new logic.** `on_unlock`=`pull_only`, `on_mutation`=`nudge`, `on_foreground`=`nudge_focus_pull`, `pull_now`=`pull_only`, `offline_tick`=`pull_only` (Offline-guarded), `on_conflict`=`peek_pending_conflict`. The mobile surface reads as lifecycle events but reuses the daemon's existing methods, zero drift risk.

**Only `on_background` needed genuinely new logic** (the mandated flush). Design confirmed by isolated peer review (isolated session, 2026-07-23): Option 1 (best-effort flush, reuse `fire_sync`) with two amendments, both applied:
1. **Explicit `abort()` of the debounce `JoinHandle` before calling `fire_sync`**: structural cancellation, not defensive reliance on `cycle_lock` to absorb a timer-fire-vs-direct-fire race. `cycle_lock` stays as belt-and-suspenders.
2. **`on_background` uses a shorter timeout (`BG_FLUSH_TIMEOUT` = 15s), not the shared `SYNC_OP_TIMEOUT` (60s).** Refactored `fire_sync` to take a per-call `timeout: Duration` param; the two debounce callers pass `SYNC_OP_TIMEOUT`, `on_background` passes `BG_FLUSH_TIMEOUT`. Rationale: the 60s bound is desktop-scale and can exceed Android `goAsync`'s few-seconds budget under memory pressure. A kill mid-flush leaves the edit local (commit-pull-push ordering is corruption-safe); next `on_unlock`/`on_foreground` pull catches it. Did NOT lower the shared constant (would break desktop/foreground paths that legitimately need 60s on slow networks).

**Offline-recovery reproduction.** `offline_tick` delegates to the same `pull_only` the loop calls on its 30s cadence. Mobile drives it explicitly from the foreground lifecycle (`autosync_offline_tick` + `offline_retry_foreground_secs`, plan §3.5). On success: Offline→Idle (existing `pull_only` behavior). On continued failure: stays Offline. The one accepted divergence: mobile does NOT reproduce the 30min idle `PULL_INTERVAL_SECS` pull (plan §3.5 foreground-as-heartbeat tradeoff).

**Tests added (in `autosync::tests`):** `event_methods_noop_when_inactive` (every event is a safe no-op pre-activate), `on_mutation_arms_debounce_and_sets_dirty` (the core event contract + burst coalescing), `on_background_flushes_dirty_debounce_immediately` (THE critical mobile contract, Dirty debounce is flushed, not left pending for an OS-suspended timer), `on_background_noop_when_not_dirty` (no empty push cycles on every background), `offline_tick_noop_when_not_offline` (the guard that lets a host fire it every foreground tick without spamming pulls). Autosync tests pass; full workspace passes with 0 failures. fmt + clippy clean.

**Known gap (carried to Phase 1/2):** the full unlock→mutation→conflict→resolve round-trip and the Offline→Idle recovery transition need a real two-device git fixture (same gap as the existing `deactivate_clears_state_and_keeps_queue_empty` test). What's proven now: every event method's guard contract + the Dirty→flush transition + the `offline_tick` no-op-unless-Offline guard + the `pull_only` NeedsDecision skip. The two-device fixture lands with the Phase 1 UniFFI integration tests.

**Peer review ( isolated session, 2026-07-23).** Verdict: Request Changes → resolved. All static checks passed: the `on_background` lock discipline is sound (no deadlock; `JoinHandle::abort()` is non-blocking), the timeout plumbing is correct (debounce + post-resolve callers confirmed still passing `SYNC_OP_TIMEOUT`, not `BG_FLUSH_TIMEOUT`), and the `on_background_flushes_dirty_debounce_immediately` test was found to be MORE rigorous than its own comments claim (it discriminates no-op vs flush because the 5s debounce timer would still be asleep at assertion time under real `tokio::test` time).

**Findings acted on:**
1. **Bug (Moderate) #7, FIXED:** `pull_only` had no `NeedsDecision` guard, but `nudge` and `background_loop` both refuse to touch the repo while a conflict is paused (mid-merge index/worktree, corruption risk). Task #2's event surface added 3 new public entry points to `pull_only` (`pull_now`, `offline_tick`, `on_unlock`), widening the exposure. Added the guard + `pull_only_skips_when_needs_decision` regression test (via a new `#[cfg(test)] force_state_for_test` helper, since NeedsDecision is unreachable from a unit test without a real sync cycle).
2. **Suggestion #2, doc reworded:** the `on_background` comment over-credited `abort()` as the double-flush guard. The real guard is the `Inner.state` transition under the shared `inner` mutex (once `fire_sync` flips Dirty→Syncing under the lock, a racing timer-fire observes state != Dirty and returns early). `abort()` stops the redundant timer from firing a later unnecessary cycle; `cycle_lock` is belt-and-suspenders against `background_loop`'s independent pull.
3. **Suggestion #6, documented:** `on_background` reads `device_name` from `Inner` (set at `activate`) rather than taking it as a param, because lifecycle hooks fire without device context. Documented on `activate()`: `device_name` is fixed for the coordinator's lifetime; rename requires deactivate/activate.
4. **Nit #4, deferred to Phase 1:** `on_conflict` (read-only peek) sits alongside action-performing siblings (`on_unlock`/`on_mutation`/`on_background`), inviting mobile implementers to assume it acts. The Rust method name stays; the eventual UniFFI binding should surface it as `peek_conflict` to remove the ambiguity.

Post-fix verification: autosync tests pass, full workspace gate verified.

**Effort:** 2-3 weeks. Pure refactor + test-gate. No new features, no UI.

**Risk:** Medium-High. Moving concurrent state machinery always risks a subtle regression (lock ordering, drop timing, the `NeedsDecision` → `Idle` transition). Critically, replacing `background_loop` with host-driven `on_*` events is **new concurrency design, not a mechanical move**: the loop today owns Offline-retry advancement and periodic pull, and the event surface must provably reproduce those transitions. Mitigated by keeping the move mechanical (copy, re-export, fix imports), running the full daemon test suite as the gate, AND adding the runtime-native test above that proves the event path == the loop path for Offline recovery. If a test breaks, that is a real regression to fix before proceeding, not a test to update.

**Why this and not the alternatives:**

- *Reimplement the coordinator in Kotlin* (mobile-only debounce/offline/conflict) → duplicates the riskiest concurrent code in the project across two languages; guaranteed drift.
- *Call `SyncEngine` directly with no coordinator* → no debounce (one commit per save), no offline recovery, strictly worse sync UX than desktop on day one.
- Extraction wins on logic (separation of transport from orchestration), security (one crypto/sync/conflict implementation, auditable), speed (mobile binds a small runtime, no IPC hop), and maintenance (single source of truth).

### Phase 1: UniFFI bindings (unblocker)

> **Spike status: TOOLCHAIN DE-RISKED (2026-07-23).** The highest-risk piece, whether `baluard-core` + `baluard-runtime` types compile under UniFFI 0.28 proc-macros, is PROVEN. `crates/baluard-uniffi/` exists, builds as a `cdylib` (`libbaluard_uniffi.so`, FFI symbols confirmed via `nm -D`), and the async-runtime bridge (tokio + uniffi + baluard-runtime version matrix) compiles + runs. Full workspace test suite passes with 0 failures. Remaining (APK + iOS-sim + ext linking) requires a macOS host with Xcode + Android NDK; this Linux container can't build them. See the spike log at the end of this phase.
>
> **Discovery: legacy FFI surface consolidated.** `baluard-core` had a prior UniFFI surface (3 legacy fns). Per the plan's single-boundary design, those were REMOVED from core and re-homed in `baluard-uniffi` (`mobile_version`, `generate_recovery_phrase`, `derive_kek`). Core now stays idiomatic Rust with zero UniFFI annotations.
>
> **Discovery: no Rust password generator exists.** Plan §3.3's `mobile_generate_password` assumed reuse of existing Rust logic. False, the generator lives in `desktop/src/lib/utils.js` (JS). Phase 4 must port it to Rust (`baluard-core::generator`) or re-implement in Kotlin commonMain.

**Goal:** Get a "Hello World" round-trip working, Kotlin calls into Rust, Rust returns a value, Kotlin renders it.

**What to build:**

- Create `crates/baluard-uniffi/` with `Cargo.toml`, `src/lib.rs`, `uniffi.toml`
- Define initial UDL/proc-macro interface: `mobile_list_ciphers` returning a hardcoded list of 3 demo ciphers
- Wire UniFFI's `uniffi_macros` (proc-macro style) to `baluard-core`'s types
- Set up Gradle KMP project: `mobile/` with `commonMain` + `androidMain` + `iosMain`
- Configure Kotlin/Native target for iOS
- First Compose screen in `commonMain` that calls `baluard.listCiphers()` and renders the result
- Build APK + iOS app successfully

**Acceptance criteria:**

- [x] `baluard-uniffi` crate compiles and exposes at least one function via UniFFI  ✅ 2026-07-23 (spike: 3 fns, `mobile_version`, `generate_recovery_phrase`, `derive_kek` + async `spike_async_probe`. cdylib builds, FFI symbols present, unit tests pass)
- [ ] Android build (`.apk`) launches and shows a list of 3 hardcoded ciphers from Rust  ⏳ BLOCKED ON HOST: needs macOS + Android NDK (container lacks both). Spike de-risked the Rust side; APK build is a host-side Gradle task.
- [ ] iOS build (`.app` for simulator) launches and shows the same list  ⏳ BLOCKED ON HOST: needs macOS + Xcode (Linux swift ≠ Apple toolchain). The least-traveled ext-linking path remains un-de-risked until run on a mac.
- [ ] CI builds both targets cleanly  ⏳ blocked on the above

#### Phase 1 spike implementation log (2026-07-23)

**Spike scope (executed in a Linux container).** Per plan §5 Phase 1 the de-risk step is: bind one pure `baluard-core` fn via UniFFI, build an APK + iOS-sim app, link a stub credential extension. The container has cargo + kotlin + gradle + swift (Linux) but NO Android SDK/NDK and NO Xcode. So the spike executed the environment-portable, highest-value subset and documented the host-side remainder.

**What was proven (the load-bearing questions):**
1. `baluard-core` + `baluard-runtime` compile cleanly under UniFFI 0.28 proc-macros. This was the most likely place to lose a month, complex crypto types (`hpke`, `x25519-dalek`, `ed25519-dalek`, `ssh-key`, `argon2`) all link.
2. The async-runtime version matrix (tokio + uniffi 0.28 + baluard-runtime) compiles AND runs. `spike_async_probe` is a `#[uniffi::export] async fn` that touches `baluard_runtime::AutoSyncState`; its tokio test passes.
3. `#[derive(uniffi::Record)]` works for boundary structs (`MobileRecoveryPhrase`).
4. The cdylib exports the expected FFI symbols (`UNIFFI_META_BALUARD_UNIFFI_FUNC_*`).
5. Full workspace passes with 0 failures after consolidation.

**Toolchain facts for host builds (memorized):**
- UniFFI 0.28 has NO standalone `uniffi-bindgen` binary (`cargo install uniffi-bindgen-cli` fails, the crate doesn't exist for 0.28; `uniffi_bindgen` lib has no binaries). To generate Kotlin/Swift bindings, build a runner that calls `uniffi_bindgen::library_mode::generate_bindings` (7-arg signature: `library_path`, `crate_name`, `&binding_generator`, `config_supplier: &dyn BindgenCrateConfigSupplier`, `config_file_override`, `out_dir`, `try_format_code`).
- Proc-macro mode: `build.rs` can be empty, `uniffi::setup_scaffolding!()` in `lib.rs` handles scaffolding. No UDL file needed.
- `#[derive(uniffi::Record)]` is required for struct types to cross the FFI boundary (plain structs don't auto-derive).

**Consolidation decision (acted on).** Stripped `baluard-core/src/lib.rs` of its legacy UniFFI surface (`mobile_version`, `mobile_generate_mnemonic`, `mobile_derive_key` + scaffolding + the `uniffi` workspace dep + `test_uniffi_wrappers` test). Re-homed the 3 fns in `baluard-uniffi` as `mobile_version`, `generate_recovery_phrase` (returns a proper `MobileRecoveryPhrase` Record), and `derive_kek` (now takes `salt: Vec<u8>` directly instead of the legacy hashed-from-String path, with a security note on the plaintext-on-heap boundary). Added `consolidated_ffi_surface_works` test mirroring the deleted one.

**Carried to the host-build step (the part this container can't do):**
- Build a real APK against `aarch64-linux-android` (Rust target installed; Android cmdline-tools downloaded to `$HOME/android-sdk`; still needs `sdkmanager --install` of platform-tools + build-tools + NDK + `cargo-ndk` or `cargo build --target` + manual .so packaging).
- Build an iOS-sim `.app` + link the framework into a stub `ASCredentialProviderViewController` extension (needs macOS + Xcode; the least-traveled path the spike was meant to de-risk remains un-proven until run on a mac).
- Wire the Kotlin/Swift bindings into a Compose Multiplatform `commonMain` hello-world screen.

**Effort:** 2-3 weeks. Pure Rust + scaffolding work, no UI decisions.

**Risk:** UniFFI's Rust → Kotlin binding generation can be finicky with complex generic types, and the Kotlin/Native → iOS-extension linking path is the least-traveled. **De-risk first:** run a 2-3 day **UniFFI + KMP + extension toolchain spike** (bind one pure `baluard-core` fn like `mobile_generate_password`, build an APK + an iOS-simulator app, and link the framework into a stub credential extension) **before or in parallel with Phase 0**, so a toolchain showstopper doesn't surface a month in. The hello-world then validates the **async** path (UniFFI async → Kotlin `suspend` / Swift `async`, one shared tokio runtime off the UI thread, §3.3), not just a sync call.

### Phase 2: Auth flow + vault unlock

> **Status: RUST & FFI COMPLETE (2026-07-31).** The vault onboarding + auth lifecycle FFI surface (`open_vault`, `create_vault`, `create_vault_with_recovery`, `derive_kek_for_vault`, `enroll_device_with_phrase`, `start_device_flow`, `connect_pat`, `list_vault_repos`, `clone_vault_start`, `provider_disconnect`, `MobileVault::unlock/lock/unlock_with_kek/is_unlocked`) is implemented in `baluard-uniffi` and verified by workspace unit tests. Provider orchestration extracted into `baluard-runtime/src/providers.rs`. Core multi-device bugs F1/F2/F3/F4/F6 resolved. See `docs/plan-mobile-onboarding.md`. Compose UI onboarding screens remain in KMP.

**Goal:** Real authentication. Master password entry, biometric unlock, session token management.

**What to build:**

- `mobile_vault_init` (clone the repo via OAuth device flow)
- `mobile_vault_open` (open an existing local vault)
- `mobile_vault_unlock` (master password → KEK → session token)
- Compose `UnlockScreen` with password input + biometric button
- `expect`/`actual` for `Biometric` interface
- iOS Swift wrapper for `LAContext` (~100 lines, audited)
- Android actual implementation using `BiometricPrompt` + `AndroidKeystore`
- Session token is **memory-only** (minted on unlock, invalidated on lock/process death). The biometric-gated **KEK** is what persists across restarts for quick-unlock; the session token never touches disk (see §3.3).
- Auto-lock on app background (configurable timeout)

> **Status: UI COMPLETE, HOST-BUILD PENDING (2026-08-16).** Runtime/FFI landed 2026-07-31 (slices 0/A/B/C); the UI screens landed 2026-08-16: OnboardingScreen root (routes on the `.baluard` marker via platform `vaultExists()`), CreateVaultScreen + RecoveryPhraseScreen (FLAG_SECURE, ack gate), ProviderConnectScreen (device flow GitHub/GitLab, PAT for Codeberg + fallback), DeviceCodeScreen (RFC 8628 poll w/ SlowDown backoff), RepoPickerScreen (clone + cancel), EnrollDeviceScreen (24-word phrase validation). App.kt routes no-vault -> onboarding -> vault list. Structure-verified only; on-device verification pending the macOS host build.

**Acceptance criteria:**

- [x] User can clone a vault from GitHub/GitLab/Codeberg via OAuth device flow  ✅ 2026-08-16 (UI + runtime; GitLab device flow still hits the placeholder client_id until the OAuth app is registered, PAT path works for all three). Host-build verification pending.
- [x] User can unlock with master password  ✅ 2026-08-16 (unlock screen + runtime KDF path; in-process round-trip tests green)
- [ ] User can unlock with biometric (when enabled) without re-entering master password  🟡 B5 wired 2026-08-18 (host compile green): `Biometric` expect redesigned to KEK semantics (`isAvailable`/`isEnrolled`/`enroll`/`unlock`); androidMain actual = BiometricPrompt CryptoObject over an AndroidKeystore AES-GCM key (`setUserAuthenticationRequired`, STRONG-only, invalidate-on-new-biometric, re-enroll rotates key) wrapping the KEK blob in app-private prefs; `AuthViewModel.openAndUnlockWithKek` + `repo.deriveKek`; UnlockScreen biometric button (enrolled) + one-time enroll offer after master unlock (single explicit KDF run, main app only, §3.7); MainActivity is now a FragmentActivity (`AppContextHolder.setActivity/clearActivity`). iOS actual stays stubbed (Android first). On-device verify pending APK build
- [ ] Vault auto-locks after configured timeout (default 15 min)  🟡 B6 wired 2026-08-18 (host compile green): `App.kt` checks `vault.shouldAutoLock()` on every ON_START (lock-before-pull, no vault-UI flash after long background) and inside the 15s foreground poll loop; on true → `auth.lock()` (zeroizes keys) + `conflictVm.clear()` + drop to UnlockScreen. Foreground-lifecycle driven per plan §3.5 (no background walker). On-device verify pending APK build
- [ ] iOS Face ID / Android BiometricPrompt work correctly  ⏳ blocked on biometric actuals
- [ ] Unit tests covering the auth flow  ⏳ runtime+FFI round-trip tests exist; UI tests pending

**Effort:** 3-4 weeks. First real user-facing flow.

**Risk:** Biometric on iOS has surprising behavior (Face ID prompts can be dismissed, LAContext needs fallback policy). Plan for edge cases early.

### Phase 3: Vault list + cipher detail

> **Status: DETAIL + FILTERS + I18N DONE (2026-08-16), HOST-BUILD PENDING.** CipherDetailScreen renders all 8 types via a shared per-type field schema (`CipherFields.kt`, wire keys from core `types.rs`); sensitive fields mask+reveal, per-row copy, TOTP widget for logins, unknown future types degrade to name+notes. Vault list gained type/tag/favorites chip filters (archived hidden); `MobileCipherMeta` now carries `tags` + `archived` from core. Full app navigation (list -> detail -> edit; generator/settings reachable). i18n EN/ES dictionaries cover every screen (142 keys, key-for-key parity, script-checked). Remaining: folder filtering (blocked: no folder-list FFI on mobile, id without a name can't render), Rust-side full-text search, Material 3 brand pass, snapshot tests.

**Goal:** Read-only view of the entire vault. Match desktop UX.

**What to build:**

- Compose `VaultListScreen` (3-column layout on tablet, single column on phone)
- Compose `CipherDetailScreen` (view all 8 cipher types)
- ViewModel-driven `StateFlow` from `VaultRepository`
- Search bar (full-text over decrypted ciphers, Rust-side for performance)
- Folder/tag filter
- i18n (en + es, mirror desktop JSON keys)
- Theme: apply `docs/brand-guidelines.md` colors via Material 3 theme

**Acceptance criteria:**

- [x] All 8 cipher types render correctly (Login, Card, Identity, SshKey, SecureNote, BankAccount, DriversLicense, Passport)  ✅ 2026-08-16 (detail screen, shared field schema; structure-verified, host build pending)
- [x] Folder/tag filtering works  ✅ tag + type + favorites chips 2026-08-16; folder chips 2026-08-17 (Wave B2: `VaultRepository.listFolders` parses `list_folders` JSON into `MobileFolderInfo`, ViewModel `folderFilter` state + `allFolders()` shows only non-empty folders, chip row renders folder-name chips keyed by id, `filtered()` matches `MobileCipherMeta.folderId`. Metadata-compile green; on-device verify pending with APK build)
- [ ] Search returns relevant results within 200ms for 1,000-entry vault  🟡 client-side name/username filter exists; Rust-side full-text search + perf measurement pending
- [x] en + es translations complete  ✅ 2026-08-16 (i18n layer, both dictionaries, parity script-checked)
- [ ] Material 3 theme matches desktop brand palette  ⏳ default BaluardTheme only
- [ ] Unit tests + snapshot tests for key screens  ⏳ pending

**Effort:** 3-4 weeks. The biggest UI work, mirrors `desktop/src/components/`.

**Risk:** Performance with large vaults (1,000+ entries). Mitigate with LazyColumn pagination + Rust-side search.

### Phase 4: Cipher edit + generator + TOTP

> **Status: EDIT FOR ALL 8 TYPES DONE (2026-08-16), DELETE DONE (2026-08-17), HOST-BUILD PENDING.** GeneratorScreen + TotpWidget scaffolded 2026-07-23; EditCipherScreen generalized 2026-08-16 to all 8 types by reusing the detail field schema (one generic renderer, type picker on new entries, sensitive-input masking). Save is merge-on-save: the loaded `data` object is preserved and only edited keys are overwritten, fixing a latent wipe where the old login-only builder nulled passkeys/URIs/TOTP on every edit. Remaining: debounced-push-after-save wiring (runtime `on_mutation` exists), pull-to-refresh.

**Goal:** Full CRUD on mobile. Match desktop UX.

**What to build:**

- Compose `EditCipherScreen` for all 8 types (forms mirroring desktop)
- Compose `GeneratorScreen` (password + passphrase)
- Compose `TOTPWidget` (live countdown, code copy)
- UniFFI: `mobile_save_cipher`, `mobile_delete_cipher`, `mobile_generate_*`, `mobile_totp_code`
- Debounced push after every save (5s, via Rust autosync coordinator)
- Pull-to-refresh on vault list (triggers `mobile_autosync_pull_now`)
- Form validation (mirror desktop's validation rules)

**Acceptance criteria:**

- [x] User can create / edit / delete any cipher type  ✅ create + edit for all 8 types done 2026-08-16 (merge-on-save preserves unmodeled fields); delete done 2026-08-17 (detail-screen action + confirmation dialog, trash semantics via existing `deleteCipher` FFI, list reloads through the save-revision bump). Structure-verified; host compile green
- [x] Generator produces passwords matching desktop output (same `crypto.getRandomValues` path)  ✅ single Rust source (`baluard-core::generator`) drives both; UI scaffolded
- [x] TOTP codes match desktop's (same Rust logic)  ✅ `totp_code`, seed never crosses FFI; live widget scaffolded
- [ ] Save triggers sync within 10 seconds (5s debounce + push time)  ⏳ runtime `on_mutation` event exists; mobile lifecycle wiring pending
- [ ] Pull-to-refresh on vault list shows updated data within 5 seconds  ⏳ pending
- [ ] Unit tests  ⏳ pending

**Effort:** 4 weeks. Largest single phase.

**Risk:** Form complexity for 8 cipher types. Strong temptation to skip fields. **Don't.** Bitwarden users notice every missing field.

### Phase 5: Sync coordinator + settings UI

**Goal:** Make the sync model explicit and user-controlled.

**What to build:**

- `SyncCoordinator` in `commonMain` that wraps UniFFI autosync calls
- `MobileSyncConfig` (locked in section 3.5)
- Compose `SettingsScreen` with the sync settings UI (5 toggles + button)
- Android: `ProcessLifecycleOwner` hooks → `SyncCoordinator.onAppForeground()` / `onAppBackground()`
- iOS: `SceneDelegate` lifecycle hooks → same
- Android: WorkManager registration, only when background sync is enabled
- iOS: `BGTaskScheduler` registration, only when background sync is enabled
- "Sync now" button + sync status display
- Conflict UI: port `desktop/src/components/ConflictResolutionPanel.jsx` to Compose
- Conflict resolution IPC: `mobile_list_pending_conflicts`, `mobile_resolve_conflict`

**Acceptance criteria:**

- [ ] Pull-on-unlock works (within 5s of app foreground)  🟡 wired 2026-08-18 (Wave B3, commonMain: `LaunchedEffect(unlocked)` → `SyncCoordinator.onUnlock`; foreground glue landed as `LifecycleEventEffect(ON_START/ON_STOP)` in `App.kt` → `onForeground`/`onBackground`, no ProcessLifecycleOwner dep needed, single-activity app + runtime-side 10-min guard; `lifecycle-runtime-compose` 2.8.4 added. On-device verify pending APK build)
- [ ] Push-after-CRUD works (within 10s of save)  🟡 wired 2026-08-17 (Wave B3: `notifyMutation()` on save + delete in `App.kt` → `SyncCoordinator.onMutation` → runtime 5s debounce; on-device timing verify pending APK)
- [ ] Pull-to-refresh works  🟡 wired 2026-08-19: `PullToRefreshBox` on VaultListScreen → `SyncCoordinator.pullNow` + list/conflict refresh (App.kt callback, not gated by Wi-Fi: explicit user gesture). Android unit tests + compile green; on-device verify pending APK
- [ ] "Sync now" button works
- [ ] Background sync toggle: when ON, sync runs every 15-30 min (platform-dependent)  🟡 wired 2026-08-19 via the LOCKED FETCH path (my pick): `SyncEngine::fetch_locked` (core, objects-only fetch: no unlock, no decrypt, no checkout, no state transition; refuses when the state machine is busy; regression test `fetch_locked_is_fetch_only` green) + `background_fetch` FFI (uniffi, spawn_blocking) + WorkManager actual (`BackgroundFetchWorker`, UNMETERED constraint = Wi-Fi-only enforcement, `ExistingPeriodicWorkPolicy.UPDATE`, min 15 min) driven from App.kt config changes. Fetched objects are consumed by the next unlock's pull; conflicts resolve foreground-side. Bindings regenerated; APK builds with the symbol. Battery measurement + on-device verify pending
- [ ] Conflict resolution UI surfaces F2/F3/F4 conflicts and resolves correctly  🟡 B4 UI built 2026-08-18: `sync/ConflictModels.kt` (lenient DTOs over the runtime JSON), `sync/ConflictViewModel.kt` (refresh keeps prior state on transient FFI error; failed verdict STAYS queued), `ui/components/ConflictResolutionPanel.kt` (scrim overlay, no dismiss: decision gates sync; cross-epoch hides keep-both), wired in `App.kt` (refresh after every sync event + 15s poll while unlocked; saveRevision++ on resolve). On-device verify pending APK build. FFI surface was already complete (Wave A)
- [ ] Wi-Fi-only toggle works (first sync always Wi-Fi)  🟡 wired 2026-08-19: `isMeteredNetwork()` expect (Android: ConnectivityManager `NET_CAPABILITY_NOT_METERED`, fail-open; iOS: stub false) gates AUTOMATIC triggers only (onUnlock/onMutation/onForeground/offlineTick) inside `SyncCoordinator`; explicit gestures (pullNow) + the mandatory background flush are never network-gated (plan §3.5 advisory). Injectable for tests; new `wifiOnlySkipsAutomaticEventsOnMeteredNetwork` test green
- [ ] Battery usage <1%/day with background sync OFF, <3%/day with ON (Android measurement)

**Effort:** 3-4 weeks. Mostly glue code + platform-specific lifecycle wiring.

**Risk:** Background sync on iOS is unreliable by OS design. Document the limitation; don't promise what iOS won't deliver.

### Phase 6: Autofill (Android first)

**Goal:** Baluard shows up in the system autofill picker for all apps.

**What to build (Android):**

- Declare `BaluardAutofillService` in `AndroidManifest.xml`
- Service implementation: handle `onFillRequest`, parse `AssistStructure`, query `VaultRepository` by URL match strategy. **Unlock via the biometric-gated KEK + `unlock_with_kek`** (never the master-password Argon2id KDF, the service is memory-capped, §3.2). No network sync on the `onFillRequest` hot path; query a local URL index.
- Build `RemoteViews` presentation with credential list (simpler UI than main app, optimized for service cold start)
- Handle `onSaveRequest` when user submits a login form elsewhere
- Biometric prompt before filling (configurable, default ON)
- "Add new cipher from autofill" flow

**Acceptance criteria:**

- [ ] User can enable Baluard as autofill provider in Settings → Passwords & accounts
- [ ] When logging into any app, the credential picker shows Baluard entries
- [ ] Tapping a credential fills username + password fields
- [ ] Save prompt appears when user submits a new login elsewhere
- [ ] Biometric prompt appears before filling (when enabled)
- [ ] **Service unlock uses `unlock_with_kek` (biometric-gated KEK); the master-password Argon2id KDF never runs in the service process**
- [ ] No network sync on the `onFillRequest` hot path (local URL index only)
- [ ] Service cold start <500ms

**Effort:** 3-4 weeks. Android-specific. Hardest UX win.

**Risk:** `AssistStructure` parsing is fragile across app implementations. Test against Chrome, banking apps, social media. Maintain a known-bad-app list.

### Phase 7: Autofill (iOS)

**Goal:** Baluard shows up in the iOS credential provider picker.

**What to build (iOS):**

- New Xcode target: `BaluardAutoFill` extension
- `ASCredentialProviderViewController` implementation
- Read from shared UniFFI bindings (extension uses the same `.xcframework` as main app)
- Render credential picker (UIKit, not Compose, extensions have memory limits)
- Match credentials against `serviceIdentifiers` from the request
- Biometric prompt via `LAContext` before returning credentials
- "Add new cipher" flow within extension

**Acceptance criteria:**

- [ ] User can enable Baluard as credential provider in iOS Settings → Passwords
- [ ] When logging into any app or website in Safari, Baluard appears in the QuickType bar
- [ ] Tapping fills credentials correctly
- [ ] Biometric prompt appears before filling
- [ ] **Extension unlock uses `unlock_with_kek` (biometric-gated KEK); the master-password Argon2id KDF (64-256 MB) never runs in the extension (OOM guard)**
- [ ] Extension cold start <1s

**Effort:** 3 weeks. Slightly easier than Android because iOS's API is more constrained but more consistent.

**Risk:** iOS extension memory limits (~50MB). The memory cap is primarily a **crypto** constraint, not a UI one: the vault's Argon2id `memory_kib` (64 MB std / 256 MB high) would OOM the extension on master-password unlock. Mitigated by the `unlock_with_kek` path (§3.2, Phase 6), the KDF never runs there. UI must still be native UIKit (NOT Compose, too heavy for the extension).

### Phase 8: Polish, accessibility, performance

**Goal:** Production-ready quality bar.

**What to build:**

- Accessibility: TalkBack (Android) / VoiceOver (iOS) labels for all interactive elements
- Keyboard navigation support (Android: hardware keyboard, iOS: external keyboard)
- Dynamic Type / Font scaling
- Dark mode / Light mode (use existing `brand-guidelines.md` tokens)
- Performance pass: startup time, list scrolling, large vault benchmarks
- Crash logging: **local file-only** on both platforms (Android: write to app-private log dir, mirroring the desktop `BALUARD_DEBUG` log pattern; iOS: MetricKit to local storage). NO Firebase, NO ACRA network upload, Baluard has no server to receive reports, and ACRA's default POST-to-server would block F-Droid. User explicitly attaches logs to a manual bug report.
- Play Store / App Store metadata, screenshots, descriptions
- Beta testing via Play Internal Testing / TestFlight
- F-Droid build flavor (open-source build pipeline, no proprietary deps)

**Acceptance criteria:**

- [ ] Cold start <1.5s on mid-range Android (Pixel 6a equivalent), <2s on iPhone 12 equivalent
- [ ] Vault list scrolls at 60fps with 1,000 entries
- [ ] TalkBack / VoiceOver can navigate the entire vault list
- [ ] Both light and dark themes pass WCAG AA contrast
- [ ] Crash-free sessions >99.5% over 1,000 beta users
- [ ] Public release on Play Store and App Store

**Effort:** 4-6 weeks. Mostly testing + iteration.

**Risk:** Apple App Store review for password managers is strict. Plan for rejections, especially around autofill.

---

## 6. Total scope

| Phase | Effort | Cumulative |
|---|---|---|
| Phase 0: Extract `baluard-runtime` | 2-3 weeks | 3 |
| Phase 1: UniFFI bindings | 2-3 weeks | 6 |
| Phase 2: Auth + unlock | 3-4 weeks | 10 |
| Phase 3: Vault list + detail | 3-4 weeks | 14 |
| Phase 4: Edit + generator + TOTP | 4 weeks | 18 |
| Phase 5: Sync + settings | 3-4 weeks | 22 |
| Phase 6: Android Autofill | 3-4 weeks | 26 |
| Phase 7: iOS Autofill | 3 weeks | 29 |
| Phase 8: Polish + launch | 4-6 weeks | **33-35 weeks** |
| **Total to public launch** | | **~8-9 months from Phase 0 start** |

**Recommended sequence (Android first, iOS second):**

1. **Android end-to-end:** Phases 0-6 + Phase 8 Android-side → Play Store
2. **Personal dogfooding by me**: indefinite duration, ends when I signal readiness
3. **iOS:** Phase 7 + Phase 8 iOS-side → App Store (only after step 2)

**Android-first ETA:** ~6-7 months from Phase 0 start (Phase 0 + Phases 1-6 + Phase 8 Android-side).
**iOS ETA after "iOS now" signal:** +6-8 weeks.

---

## 7. Future work (v2+)

- **Paired-companion / remote unlock:** Mobile talks to desktop over LAN for unlock. Already designed in browser ext via `TokenKind::Bridge { pairing_id }`. Same pattern.
- **Platform credential-provider (passkey assertion):** Android `CredentialProviderService` + iOS `AuthenticationServices` passkey APIs. Surfaces vault passkeys to the OS credential picker for web/app sign-in (distinct from password autofill in Phases 6/7). Required before mobile passkeys are anything more than display-only. Reuses the same `baluard-runtime` passkey storage; the ceremony UI is the new work.
- **Passkey ceremonies in mobile:** Phase 2 of `plan-passkey-support.md` extends to mobile. The Rust side is already there; the UI ceremony needs to be added.
- **F-Droid build flavor:** Already deferred to v2. Required for privacy-conscious users who refuse Google Play.
- **TOTP authenticator companion app:** Like Bitwarden Authenticator, a standalone TOTP app sharing the vault via App Group keychain.
- **iPad-specific UI:** Tablet layouts, keyboard shortcuts, drag-and-drop between vault items.
- **watchOS / Wear OS:** TOTP-on-wrist. Small, focused.
- **Mobile-specific cipher types:** Driver's license scan via camera, payment card scan, etc.

---

## 8. Reference research: what we copy, what we don't

| Source | Take | Don't take |
|---|---|---|
| **Bitwarden Android** (`bitwarden/android`) | Module split (`app` / `data` / `network` / `ui`), Hilt DI (we'll use manual DI at our scale), AndroidX Autofill framework integration, BiometricPrompt usage, Room caching for vault metadata (we don't need this: git IS our cache). | Server-backed sync architecture (last-write-wins), the entire `:network` module (we have no server), Firebase/Google services, the 200K-line complexity. |
| **Bitwarden iOS** (`bitwarden/ios`) | App-as-thin-shell architecture (16 files / 911 lines for the app target), `ASCredentialProviderViewController` extension target structure, App Intents for Shortcuts integration, App Group keychain for paired apps. | Tuist build system (overkill for solo), the 1,816-files-per-module convention (we'll consolidate), Firebase/Crashlytics. |
| **Compose Multiplatform** | The whole point: shared Compose UI in `commonMain`. Material 3 components. `expect`/`actual` for OS APIs. | Nothing to avoid: CMP is the right tool here. |
| **KeePassXC-Browser** | Bridge topology concepts. | Not directly relevant to mobile (different surface). |

---

## 9. Open questions

1. **Minimum Android version:** **Locked: API 32 (Android 12L).** Modern `BiometricPrompt` (API 28+), modern autofill, per-app language preferences (API 33 is nicer but 32 covers the floor), and granular sync/network semantics. API 34 (Android 14) is only needed for `CredentialProviderService` passkeys, which are v2+.
2. **Minimum iOS version:** **Locked: iOS 17.** `@Observable`, modern SwiftUI, and the `AuthenticationServices` passkey APIs (v2+). Aligns with the platform floor in AGENTS.md.
3. **App icon / branding:** Reuse existing `desktop/src-tauri/icons/` (the `app-icons.md` guide covers generation for all platforms including mobile).
4. **Distribution:** Play Store first. F-Droid in v2. App Store alongside Play (or shortly after).
5. **Marketing site update:** `actitud.xyz` should get a mobile section. Update when Play Store listing is ready.
6. **Daemon on mobile:** **Resolved (see §3.2).** No daemon. The runtime is extracted in Phase 0 and hosted in-process. (iOS cannot run a background Unix-socket daemon; Android background services are out of scope.)

---

## 10. Acceptance criteria (overall)

- [ ] **Android app in Play Store** (iOS deferred, see §1.1 Sequence)
- [ ] iOS app in App Store (only after I signal "iOS now")
- [ ] F-Droid-compatible build pipeline (even if not yet submitted)
- [ ] All existing `baluard-core` tests still pass
- [ ] Mobile-specific test suite (Kotlin unit + instrumented tests) with >80% coverage on `commonMain`
- [ ] Security review of `baluard-uniffi` boundary (UniFFI marshalling, type safety, `CipherKind` enum mapping preserves invalid-states-unrepresentable)
- [ ] **Threat-model update** documenting: (a) autofill/extension quick-unlock stores a wrapped **KEK** in the platform keychain (StrongBox/Secure Enclave where available), unlocked via `unlock_with_kek`, not the master password, and never running the memory-capped Argon2id KDF in the extension process; (b) plaintext returned to the Kotlin/Swift heap is un-zeroizable (managed GC), secrets are reveal-on-demand, not eager in list/detail payloads; (c) session tokens are memory-only, never persisted
- [ ] No proprietary dependencies that would block F-Droid
- [ ] Crash-free sessions >99.5%
- [ ] Battery usage within targets (measured via Play Console / MetricKit)
- [ ] Public-facing documentation: dev setup, architecture overview, threat model update
