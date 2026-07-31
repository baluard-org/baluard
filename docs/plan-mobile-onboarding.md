# Plan: Mobile Onboarding (Phase 2)

> Status: v2 (2026-07-30). Revised twice after two isolated peer reviews. Review
> #1: clone->unlock is impossible; no tokio runtime; KDF mismatch; plan
> orchestration belongs in the runtime. Review #2: a multi-device correctness
> bug cluster in the core (`find_device_id`, SecureKeystore/load mismatch, stale
> `device_id`, the `uniffi` tokio feature, the clone cancel flag). Both verdicts
> were Request Changes; this version folds all of it in. Owner: Esteban. Builds on
> `docs/plan-mobile-apps.md` and the desktop provider flow in
> `docs/plan-git-providers-multi-vault.md`.

## 0. Review record (traceability)

Peer review #1 (isolated session, no inherited context). I independently verified the
three most consequential claims against the code before acting on them:

| Finding | Verified? | Evidence |
|---|---|---|
| Clone->master-password-unlock is impossible | YES | `meta/device-privkey.json` gitignored (`engine.rs:1700`); Root Key recovered via HPKE-unwrap with the device private key (`handle.rs:300`), master password is only a canary. A fresh clone has no device key. |
| No tokio runtime in `baluard-uniffi` | YES | `tokio` is dev-only (`Cargo.toml:29`); no `async_runtime = "tokio"` anywhere. Async FFI runs on the Kotlin executor; `tokio::time`/`reqwest`/`spawn` panic. |
| KDF mismatch breaks autofill | YES | `derive_kek` hardcodes `MobileLow`; `create_vault` uses `DesktopStd`. Different params -> different KEK -> `unlock_with_kek` fails for mobile-created vaults. |
| Codeberg has no device flow | YES | `codeberg.rs:122-135` returns `Err` for both device-flow methods. |
| `SyncEngine::clone` ignores shallow | YES | param is `_shallow` (`engine.rs:1193`), unused; no depth set. |

Two scope decisions locked with Esteban (2026-07-30):

1. **Device enrollment is a core fix across all platforms** (not mobile-only). It
   fixes desktop's second-device path too, which is likely broken (its
   `vault.enroll_with_phrase` is token-gated chicken-and-egg).
2. **Provider/clone/token-refresh orchestration moves into `baluard-runtime`** as a
   prerequisite Slice 0. `baluard-uniffi` becomes a thin type-mapping layer. The
   daemon is refactored to call the same functions. iOS gets it free.

### Peer review #2 (isolated, 2026-07-30)

A second isolated review surfaced six more issues; I verified the four load-bearing
ones against the code (all accurate). The standout is a **critical core bug** that
breaks multi-device unlock on every platform today:

| # | Sev | Finding (verified) | Best fix |
|---|---|---|---|
| F1 | Critical | `find_device_id` (`handle.rs:2288`) returns the FIRST `*.json` in `meta/keywrap/`; no match against the local device's public key. In any multi-device / post-enroll vault it picks the wrong keywrap -> HPKE decap fails -> non-deterministic unlock. Desktop multi-device unlock is likely already broken. | Match the local x25519 pubkey against `meta/devices.json` registry, not `read_dir` order. |
| F2 | High | `SecureKeystore` (`creation.rs:436`) stores keys as `"device_x25519_secret"`; `load_device_privkeys` (`handle.rs:3360`) reads keyring-by-`device_id` / plaintext file and never consults `SecureKeystore`. Slice A's Android-Keystore plan would create fine but unlock-every-time-fails. | Unify: `SecureKeystore` keyed by `device_id`; `load_device_privkeys` consults it. creation + enroll + open share one path. |
| F3 | Bug | `VaultState::enroll_with_recovery_phrase` writes the new keywrap/privkey but leaves `self.inner` on the stale `device_id` -> in-process post-enroll unlock breaks. | Re-open `VaultHandle` under the write lock post-enroll. |
| F4 | Build | `baluard-uniffi/Cargo.toml:16` has `uniffi = { workspace = true }` with NO `tokio` feature -> `async_runtime="tokio"` won't compile. | `uniffi = { workspace = true, features = ["tokio"] }`. |
| F5 | Plan | `connect_pat` + `detect_vault_repos` only at the FFI layer, not in `runtime::providers`; the per-provider mutex has no process-global holder on mobile (no daemon). | Add both to the runtime; give the runtime a process-global lock map. |
| F6 | High | `clone_remote`'s `transfer_progress` (`engine.rs:1330`) returns `true` hardcoded -> `MobileCloneJob.cancel()` cannot abort the git2 transfer. | Add `cancel_flag: Option<Arc<AtomicBool>>`; return `false` when set. |

F1/F2/F3 are the **multi-device correctness cluster**: they are not new work, they
are the prerequisites that make enrollment correct at all, so they fold into Slice 0
(see 2.5). F4 attaches to the Slice A runtime fix; F6 to the Slice B clone job.

## 1. Goal

Replace the broken first-run (the app jumps to a master-password unlock with
`vaultPath=""`, nothing to unlock) with a real onboarding root that mirrors desktop:
**Open from git provider** (connect -> choose repo -> clone -> **enroll this device**
-> unlock) OR **Create new vault** (with recovery-phrase display). Both end in an
unlocked `MobileVault`.

This is mobile Phase 2. It is larger than the draft implied because it includes a
**Slice 0** (runtime extraction of orchestration) and a **core enrollment fix** that
the draft missed entirely.

## 2. Blocking defects fixed by this phase

### 2.1 No async runtime (FIX, Slice A prerequisite)
`baluard-uniffi` has no tokio runtime; async exports run on the Kotlin executor.
Symptom: any `tokio::time`/`reqwest`/`tokio::spawn` inside the `.so` panics
("no reactor"). The shipped `sync_on_*` methods are likely already broken on-device
(they only passed under `#[tokio::test]`). Second-order: Argon2id inside
`pub async fn unlock` runs on `Dispatchers.Main` -> ANR.

**Fix:**
```rust
// crates/baluard-uniffi/Cargo.toml [dependencies] (move tokio out of dev-deps;
// the async_runtime="tokio" macro also needs the uniffi tokio feature -- F4)
uniffi = { workspace = true, features = ["tokio"] }
tokio = { workspace = true, features = ["rt-multi-thread", "time", "sync", "macros"] }

// lib.rs: own one shared runtime
static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2).enable_all().build().expect("tokio runtime"))
}
```
Annotate every async export `#[uniffi::export(async_runtime = "tokio")]`. Wrap the
Argon2id KDF in `tokio::task::spawn_blocking` so it leaves the async worker (and the
UI thread). Prove it with an on-device test that hits `tokio::time::sleep` through
the FFI, not a `#[tokio::test]`.

### 2.2 KDF profile/salt mismatch (FIX, Slice A prerequisite)
`derive_kek` hardcodes `KdfProfile::MobileLow` and pads/truncates a caller salt to
32 bytes. `create_vault` uses `DesktopStd`. Different params -> different KEK -> the
biometric/autofill `unlock_with_kek` path fails for any mobile-created vault. Also,
`KdfParams.profile` is `skip_serializing`, so the profile is not recoverable from
disk; only `memory_kib`/`time_cost`/`parallelism`/`salt` are.

**Fix:** read the vault's own params; drop the profile parameter and the salt hack:
```rust
#[uniffi::export]
pub fn derive_kek_for_vault(vault_path: String, password: String) -> Result<Vec<u8>, BaluardError>;
// reads meta/kdf-params.json, uses its memory_kib/time_cost/parallelism/salt verbatim
```
And set `.kdf_profile(KdfProfile::MobileLow)` explicitly in
`create_vault_with_recovery`. A real vault salt is always 32 bytes; silently accepting
a wrong-length salt converts a bug into an undebuggable unlock failure.

### 2.3 Plaintext device key on Android (FIX, Slice A prerequisite)
`VaultCreator::execute()` writes `meta/device-privkey.json` as plaintext hex whenever
no `SecureKeystore` is injected (`creation.rs:441-455`); the current FFI injects
nothing. Because the master password is not an input to the Root-Key unwrap (2.4
below), **vault dir + `device-privkey.json` = Root Key, no password required.**
Android auto-backup is on by default, so `filesDir` is eligible for exfiltration to
Google Drive, plus `adb backup` and rooted extraction. The "sandbox = 0600-equivalent"
claim is wrong.

**Fix:** implement the `SecureKeystore` trait (`creation.rs:180-183`) against Android
Keystore/StrongBox and pass it via `.keystore()` (extend the existing
`KeystoreKekProvider.kt` plumbing). Set `android:allowBackup="false"` and
`dataExtractionRules` in the manifest. A hardware-backed device key is a Slice A exit
criterion, not a later hardening pass. At minimum, make the plaintext-file fallback
opt-in and loud rather than silent.

**F2 prerequisite (keystore unification).** The `SecureKeystore` write path
(`creation.rs:436`) and the read path `load_device_privkeys` (`handle.rs:3360`) are
not wired together today: creation stores keys named `"device_x25519_secret"`, while
the loader queries keyring-by-`device_id` or the plaintext file and never consults
`SecureKeystore`. Unify both ends on a `device_id`-keyed interface before this is
useful -- `SecureKeystore::{store,load}_device_keys(device_id, &[u8])`, and
`load_device_privkeys` consults the keystore first. Otherwise create-succeeds /
unlock-fails on Android (and anywhere else a `SecureKeystore` is injected).

### 2.4 Device enrollment is required post-clone (the core defect)
Clone->unlock is impossible: the clone has no `device-privkey.json` (gitignored), and
the Root Key is HPKE-unwrapped with the device private key, not the password. A new
device must be **enrolled** via `CeremonyMode::Join { recovery_phrase }`
(`creation.rs:535`): generate a new keypair, HPKE-unwrap the Root Key with the
recovery-derived key, write `meta/keywrap/<new-device-id>.json`. This is a first-class
flow, not an afterthought. It fixes desktop's second-device path too.

**Fix:** surface enrollment as a core/runtime path usable pre-unlock (the daemon's
`vault.enroll_with_phrase` is token-gated and cannot fire for the case it was written
for; revisit that gating):
```rust
#[uniffi::export(async_runtime = "tokio")]
pub async fn enroll_device_with_phrase(
    vault_path: String,
    master_password: String,
    recovery_phrase: String,
    device_name: String,
) -> Result<std::sync::Arc<MobileVault>, BaluardError>;
```
Backed by `VaultCreator::new(path, pw, device).mode(CeremonyMode::Join{recovery_phrase})`.
The provider path becomes: clone -> "this device is not trusted by the vault yet" ->
enter 24 words + master password -> enroll -> unlock.

### 2.5 Multi-device correctness cluster (FIX, Slice 0 prerequisites)
Enrollment is meaningless if `find_device_id` can pick the wrong device and the
in-memory handle goes stale. Verified core bugs (peer review #2):

- **F1 -- `find_device_id` is non-deterministic** (`handle.rs:2288`). It returns the
  first `*.json` in `meta/keywrap/`, with no match against the local device's public
  key. Any vault with >1 keywrap (multi-device, post-enroll) can pick another device's
  keywrap -> HPKE decap fails -> unlock fails. This likely breaks desktop multi-device
  unlock today.
  **Fix:** match the local x25519 public key (from the loaded `DevicePrivKeys`)
  against `meta/devices.json`'s `pub_enc` per device; fall back to the single-keywrap
  legacy path only when the registry is absent.
- **F3 -- stale `device_id` after in-process enroll** (`state.rs` enroll path).
  Enrollment writes a new keywrap + privkey for the new device, but `VaultState.inner`
  keeps the old `device_id` -> the next in-process op targets the wrong device.
  **Fix:** after a successful enroll, re-open the `VaultHandle` and replace
  `self.inner` under the write lock.

(F2, the keystore read/write unification, is tracked under 2.3 -- same slice, same
interface.)

## 3. Architectural decisions (locked)

### 3.1 Slice 0: orchestration lives in `baluard-runtime`, not Kotlin
The draft rebuilt provider-connect/clone/token-refresh orchestration in Kotlin. That
is a second implementation of policy that already lives in `daemon/handler.rs`, and it
would drift (then a third copy for iOS). `baluard-runtime` was extracted precisely so
mobile and daemon share orchestration. Provider connect and clone ARE orchestration.

New `crates/baluard-runtime/src/providers.rs` (the daemon, mobile, and iOS all call
these; `baluard-uniffi` is a thin type-mapping layer over them):
```rust
connect_device_flow(provider, config) -> DeviceFlowHandle  // owns loop, RFC8628 backoff, deadline
connect_pat(provider, token, config) -> ProviderInfo        // PAT path (Codeberg, GitLab w/o OAuth app) -- F5
detect_vault_repos(provider) -> Vec<VaultRepo>              // repo detection lives in the runtime -- F5
ensure_valid_token(provider) -> ProviderToken               // per-provider tokio::Mutex (GitLab rolling-refresh)
clone_and_register(provider, url, target) -> CloneJob       // .baluard marker check + .partial + cleanup + progress
disconnect(provider)
enroll_device(vault_path, master_password, recovery_phrase, device_name) -> ...  // pre-unlock enrollment
```
`ensure_valid_token`'s per-provider mutex needs a process-global home: a
`ProviderManager` holding a `Provider -> Arc<tokio::Mutex<()>>` map (lazy static). On
mobile there is no daemon process, so the runtime owns it; the daemon keeps using the
same map for parity.
`baluard-uniffi` becomes a thin type-mapping layer (Records/Enums that mirror these,
no policy). The daemon is refactored onto the same functions in the same slice. This
is the highest-leverage change in the plan and does not increase total work; it moves it.

### 3.2 OAuth device flow where supported; PAT otherwise (Codeberg has no device flow)
Device flow works for GitHub and GitLab. Codeberg (Forgejo) returns errors for both
device-flow methods (`codeberg.rs:122-135`). So: device flow for GitHub/GitLab, and
**PAT back in scope** for Slice B (`connect_pat` wrapping `authenticate_pat`). PAT
also makes GitLab work today without registering an OAuth app, sidesteps the
placeholder-client_id problem, and is the more-secure Codeberg option (Forgejo OAuth
tokens have no scope support; scoped PAT is `write:repository`).

### 3.3 Tokens in the OS keyring; refresh owned by the runtime
`token::store_token`/`load_token` are keyring-backed; mobile reuses them. **Refresh
lives in the runtime** behind `ensure_valid_token` with a per-provider `tokio::Mutex`
(GitLab invalidates the prior access+refresh pair on refresh; concurrent refreshes
brick the connection). Kotlin never triggers two concurrent refreshes. The FFI record
keeps `expires_at` (absolute), not a relative duration.

### 3.4 Provider tokens cross the FFI as plaintext Strings (documented boundary)
`ProviderToken` holds `SecretString`s; UniFFI cannot preserve zeroize. The FFI converts
to `MobileProviderToken { access_token, refresh_token, scopes, expires_at }`. Blast
radius is the OAuth scope, not vault secrets. Matches how the daemon stringifies tokens.

### 3.5 Recovery phrase: display + ack on create; entry on enroll
Create shows the 24 words (HPKE-wrapped to `meta/recovery.json` by the ceremony, never
plaintext-persisted). Enroll requires the user to enter them. Add `FLAG_SECURE` on the
phrase screens (recompose + screenshot capture is the real risk on a managed heap) and
clear the holder on navigation. **Do not** wire the existing `generate_recovery_phrase()`
FFI into the create flow: it generates an *unrelated* phrase that unlocks nothing.

## 4. FFI surface (`baluard-uniffi`, thin mapping over runtime)

Corrected from the draft. The device-flow session is an **opaque object** (the
polling credential `device_code` is in the same class as a token and must not cross
the FFI), and backoff lives in Rust.

```rust
#[derive(uniffi::Enum)] pub enum MobileProvider { GitHub, GitLab, Codeberg }
#[derive(uniffi::Record)] pub struct MobileProviderConfig {
    pub client_id: Option<String>, pub instance_url: Option<String>,
}

// Opaque: device_code, mutable interval, deadline stay Rust-side.
#[derive(uniffi::Object)]
pub struct MobileDeviceFlow { /* runtime::DeviceFlowHandle */ }
#[uniffi::export(async_runtime = "tokio")]
pub async fn start_device_flow(provider: MobileProvider, config: MobileProviderConfig)
    -> Result<std::sync::Arc<MobileDeviceFlow>, BaluardError>;
#[uniffi::export] impl MobileDeviceFlow {
    fn user_code(&self) -> String;
    fn verification_uri(&self) -> String;
    fn expires_at(&self) -> u64;
    async fn poll(&self) -> Result<MobileDeviceFlowStatus, BaluardError>; // applies RFC8628 backoff internally
}
#[derive(uniffi::Enum)]
pub enum MobileDeviceFlowStatus { Pending, Success, Expired, SlowDown }

// PAT path (Codeberg, or GitLab without an OAuth app).
#[uniffi::export(async_runtime = "tokio")]
pub async fn connect_pat(provider: MobileProvider, token: String, config: MobileProviderConfig)
    -> Result<(), BaluardError>;

// Repos: use detect_vault_repos (purpose-built), mirror VaultRepo honestly.
#[derive(uniffi::Record)]
pub struct MobileRepo {
    pub name: String, pub full_name: String, pub clone_url: String,
    pub private: bool, pub vault_slug: Option<String>, pub vault_id: Option<String>,
}
#[uniffi::export(async_runtime = "tokio")]
pub async fn list_vault_repos(provider: MobileProvider) -> Result<Vec<MobileRepo>, BaluardError>;

// Clone is a job (progress + cancel). Auth is internal (runtime loads creds via keyring);
// no token param. Clones into <local_path>.partial, renames on success, sweeps *.partial at start.
#[derive(uniffi::Object)] pub struct MobileCloneJob { /* runtime::CloneJob */ }
#[uniffi::export(async_runtime = "tokio")]
pub async fn clone_vault_start(provider: MobileProvider, clone_url: String, local_path: String)
    -> Result<std::sync::Arc<MobileCloneJob>, BaluardError>;
#[uniffi::export] impl MobileCloneJob {
    fn progress(&self) -> MobileCloneProgress; // objects/bytes/deltas
    fn cancel(&self);                          // AtomicBool checked in transfer_progress
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn enroll_device_with_phrase(vault_path: String, master_password: String,
    recovery_phrase: String, device_name: String) -> Result<std::sync::Arc<MobileVault>, BaluardError>;
#[uniffi::export(async_runtime = "tokio")]
pub async fn provider_disconnect(provider: MobileProvider) -> Result<(), BaluardError>;

// Create (returns the recovery phrase).
#[derive(uniffi::Record)]
pub struct MobileCreateResult { pub vault: std::sync::Arc<MobileVault>,
                                pub recovery_phrase: MobileRecoveryPhrase }
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_vault_with_recovery(path: String, master_password: String, device_name: String)
    -> Result<MobileCreateResult, BaluardError>;
```
NOTE: `MobileCreateResult` puts `Arc<MobileVault>` inside a `uniffi::Record`; supported
in 0.28 but verify with a real bindgen run before building the screen on it.

### Error type (enriched; the blanket `From<String>` is removed)
The single `BaluardError::Vault{detail}` defeats Slice C error routing. New variants,
each call site classifies explicitly:
```rust
Network { detail }, Provider { kind: MobileProviderErrorKind, detail },
DeviceNotEnrolled { detail },  // routes the user to the recovery-phrase screen, not an opaque error
WrongPassword,                 // canary/keywrap verify failure; no detail leaks
NotFound { detail }, Crypto { detail }, Vault { detail }, Creation { detail }, InvalidInput { detail }
```

## 5. UI screens (commonMain, Compose)

1. **`OnboardingScreen`** (NEW root; replaces the direct `UnlockScreen` in `App.kt`):
   shown when no vault exists at the default app-private path. Buttons: "Open from git
   provider", "Create new vault". Needs `expect fun defaultVaultPath()` / `vaultExists()`
   (androidMain actual via `Context.filesDir`).
2. **`ProviderConnectScreen`**: provider picker + Advanced Options. Connect ->
   `DeviceCodeScreen` (user code, "Open browser" launches `verification_uri`) for
   GitHub/GitLab, or PAT entry for Codeberg.
3. **`RepoPickerScreen`**: lists `list_vault_repos` (vault repos only); on select ->
   `clone_vault_start` with a progress bar (`MobileCloneJob.progress`) + cancel ->
   on completion -> `EnrollDeviceScreen`.
4. **`EnrollDeviceScreen`** (NEW): "This device is not trusted by the vault yet" ->
   enter 24-word recovery phrase + master password -> `enroll_device_with_phrase` ->
   unlock -> vault list.
5. **`CreateVaultScreen`**: master password (x2 confirm) + device name ->
   `create_vault_with_recovery` -> `RecoveryPhraseScreen` (24 words, copy,
   `FLAG_SECURE`, "I wrote it down" gate) -> unlock -> vault list.

`App.kt` routing: no vault -> `OnboardingScreen`; vault exists -> `UnlockScreen`;
unlocked -> `VaultListScreen`.

## 6. Slices (verifiable verticals)

### Slice 0: runtime owns orchestration + multi-device correctness (core + runtime + daemon)
- New `crates/baluard-runtime/src/providers.rs`: `connect_device_flow`, `connect_pat`,
  `detect_vault_repos`, `ensure_valid_token` (per-provider mutex, process-global
  `ProviderManager`), `clone_and_register` (marker check + `.partial` + cleanup +
  progress), `disconnect`, `enroll_device` (pre-unlock).
- **Multi-device correctness cluster (F1/F2/F3):** fix `find_device_id` to match the
  local public key against `meta/devices.json`; unify `SecureKeystore` <->
  `load_device_privkeys` on a `device_id`-keyed interface (creation + enroll + open
  share one path); re-open `VaultHandle` after in-process enroll so `VaultState.inner`
  is not stale.
- Daemon refactored to call the new runtime functions (removes the duplicated policy
  from `handler.rs`).
- Mobile/disk cleanup: sweep `*.partial` at app start; port the `.baluard` marker
  verification so mobile refuses non-Baluard repos.
- **Verifies:** full daemon + core test suites green; **desktop two-device unlock +
  enroll verified end-to-end** (F1 fixed; the core defect closed on all platforms).

### Slice A: mobile prerequisites + create flow
- Async runtime (2.1) incl. the `uniffi` `tokio` feature (F4); KDF fix (2.2);
  Android-Keystore device-key storage + manifest hardening + the keystore read/write
  unification (2.3 / F2); `BaluardError` enrichment.
- `OnboardingScreen`, vault-existence `expect`/`actual`, `App.kt` routing.
- `create_vault_with_recovery` (fixes the recovery-phrase discard) +
  `CreateVaultScreen` + `RecoveryPhraseScreen`.
- **Verifies:** first launch shows onboarding; create a vault, see + ack the phrase,
  land in the vault list; lock/unlock round-trips; KDF off the UI thread; device key
  in Keystore not plaintext; an on-device `tokio::time::sleep` FFI call succeeds.

### Slice B: provider connect + repos + clone + enrollment
- FFI: `start_device_flow`/`poll`/`MobileDeviceFlow`, `connect_pat`, `list_vault_repos`,
  `clone_vault_start`/`MobileCloneJob`, `enroll_device_with_phrase`, `disconnect`.
- `ProviderConnectScreen` + `DeviceCodeScreen` + `RepoPickerScreen` +
  `EnrollDeviceScreen`.
- Token refresh via runtime `ensure_valid_token`; cancellation + progress.
- **F6 prerequisite:** `SyncEngine::clone_remote` gains a `cancel_flag: Option<Arc<AtomicBool>>`
  and returns `false` from `transfer_progress` when cancelled, so `MobileCloneJob.cancel()`
  actually aborts the git2 transfer (today the callback hardcodes `true`).
- **Verifies:** connect GitHub (device flow) and Codeberg/GitLab (PAT); clone a synced
  vault; **enroll this device with the recovery phrase**; unlock; see synced ciphers.
  keyring-on-Android proven (token survives restart).

### Slice C: polish + disconnect + error states
- Disconnect/reconnect in settings; all error states surfaced (`DeviceNotEnrolled`,
  `WrongPassword`, `Network`, expired/denied device code).
- **Verifies:** full lifecycle matches desktop; no regressions in unlock/list.

## 7. Security invariants (load-bearing, corrected)

- **Master-password Argon2id runs only in the main app process**, off the UI thread
  (`spawn_blocking`), never in the AutofillService (OOM guard).
- **Device private key is hardware-backed** (Android Keystore/StrongBox), not plaintext
  on `filesDir`. `allowBackup=false` + `dataExtractionRules`. Until 2.3 lands, a
  mobile vault is protected only by the sandbox, and that is documented, not hidden.
- **Recovery phrase** shown once on create, entered on enroll, never logged, never
  plaintext-persisted. `FLAG_SECURE` on phrase screens.
- **Provider tokens** keyring-stored, refreshed via the runtime's per-provider mutex,
  cross the FFI as plaintext `String` (documented). Never logged.
- **Clone** writes to app-private storage; `.partial` + sweep prevents orphan dirs;
  `.baluard` marker check refuses non-vault repos.
- **No secrets in logs.** `device_code` and access tokens never cross the FFI / never
  logged.

## 8. Risks (corrected)

1. **keyring on Android (HIGH).** Unverified runtime behavior. Slice B proves it.
   Mitigation if broken: feature-gate `keyring` in `baluard-core` + Android-native
   token store (EncryptedSharedPreferences) via `actual`.
2. **Desktop second-device path (HIGH, core).** Likely broken (token-gated enroll).
   Slice 0's enrollment work fixes it; verify desktop clone->second-device end-to-end
   as part of Slice 0 acceptance.
3. **Cancellation across FFI (MED).** UniFFI 0.28 does not propagate Kotlin coroutine
   cancel into Rust. Solved by the `MobileCloneJob` object (`cancel()` flips an
   `AtomicBool` checked in `transfer_progress`, which aborts the git2 transfer).
4. **Large repos over cellular (MED).** No shallow clone today (`_shallow` ignored).
   Real fix is implementing shallow in `SyncEngine::clone`; until then, show a
   pre-clone warning. (The draft's `size_kb` field does not exist in `VaultRepo`; do
   not invent it.)
5. **`MobileCreateResult` with `Arc<MobileVault>` in a Record (LOW).** Verify with a
   real bindgen run before building on it.
6. **`provider_store_token` idempotency (LOW).** `store_token` writes the token but
   not the `ProviderInfo` entry; `revoke_and_disconnect` then cannot find the username.
   The runtime `connect()` writes both; do not expose a half-write at the FFI.

## 9. Acceptance criteria

### Slice 0
- [ ] `baluard-runtime::providers` implements connect/refresh/clone/enroll/disconnect (+ `connect_pat`, `detect_vault_repos`).
- [ ] Daemon refactored onto them; full daemon + core test suites green.
- [ ] `find_device_id` matches the local public key, not `read_dir` order (F1); a multi-keywrap vault unlocks deterministically for the right device.
- [ ] `SecureKeystore` write (creation) and read (`load_device_privkeys`) share one `device_id`-keyed interface (F2).
- [ ] Post-enroll, `VaultState.inner` holds the new `device_id` (F3).
- [ ] Desktop clone->second-device enrollment + unlock verified end-to-end (the core defect fixed on all platforms).

### Slice A
- [ ] First launch with no vault shows `OnboardingScreen`, never the bare unlock.
- [ ] Create vault -> recovery phrase shown -> ack -> empty vault list; lock/unlock works.
- [ ] KDF runs off the UI thread (no ANR); `derive_kek_for_vault` unlocks a mobile-created vault via `unlock_with_kek`.
- [ ] Device private key in Android Keystore, not plaintext; `allowBackup=false`.
- [ ] On-device `tokio::time::sleep` FFI call succeeds (reactor proven); `uniffi` `tokio` feature enabled (F4).
- [ ] `create_vault_with_recovery` test asserts the phrase is returned + non-empty.

### Slice B
- [ ] GitHub connect (device flow) + Codeberg/GitLab connect (PAT).
- [ ] Clone a synced vault; progress + cancel work (cancel aborts the git2 transfer via F6).
- [ ] **Enroll this device with the recovery phrase**; unlock; synced ciphers render.
- [ ] keyring-on-Android confirmed (token + refresh survive app restart).
- [ ] Token refresh serialized (no GitLab double-refresh brick).

### Slice C
- [ ] Disconnect revokes + clears; reconnect works.
- [ ] All error states surfaced (`DeviceNotEnrolled`, `WrongPassword`, `Network`,
      expired/denied code).
- [ ] No regressions in unlock/list.

## 10. Out of scope (v1 mobile onboarding)

- Multi-vault on mobile (one vault at a time; adding later is a `HashMap` + pointer
  flip, as `VaultHost` already does).
- Create-then-attach-remote in one step.
- Web OAuth flow (device flow + PAT cover all three providers).
- Repo size display (field does not exist; deferred with shallow-clone work).
