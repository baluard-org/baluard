# Baluard: Architecture Decisions Record

> Master Blueprint for the Git-backed Password Manager (Space Manager).
> Pure Rust core, Single-String Protobuf Gateway, Padded Buckets, UniFFI mobile bridge, SolidJS/KMP UI layers.

---

## DOMAIN 1: CRYPTO, STORAGE & KEY HIERARCHY

### D1. Rust Core & Memory Security

**Decision: Compiled Rust Core with `zeroize`-protected memory**

All cryptographic operations, Git operations (git2-rs), padding, and secret loading are handled entirely in the `baluard-core` Rust crate. Secrets (decrypted keys, entries) are held in `Zeroize`-derived structs. The daemon process keeps vault data in locked memory regions via `memsec`/`zeroize` to prevent paging to disk or leaking via core dumps.

---

### D2. Storage Engine: Padded Buckets & Hashed Filenames

**Decision: Hashed files-per-entry system padded into uniform size buckets**

To eliminate metadata leaks (website names, usernames, specific file sizes) and prevent Git merge conflicts:
1. **Entries Folder**: Located under `entries/`. All entries are named using a random UUID hash.
2. **Padding Engine**: Plaintext Protobuf payloads are padded with random bytes before AES-256-GCM encryption to fit exact bucket sizes:
   - **Xs Bucket (5 KB)**: Standard Logins
   - **S Bucket (30 KB)**: Extended logins, TOTPs
   - **M Bucket (100 KB)**: Extended Secure Notes
   - **L Bucket (250 KB)**: Small Attachments, Scanned IDs
   - **XL Bucket (2 MB)**: Larger documents or media files
3. **Index Lookup (`meta/index.enc`)**: An encrypted lookup table mapping human-readable metadata (URLs, Titles) to their corresponding hashed filenames under `entries/`. Decrypted on demand by baluard-core.

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
Private Key Escrow (meta/device-privkey.json)
    |
    v (yields Device Private Key)
Decrypts Space Group Key (meta/access_list.json)
    |
    v
Decrypts Entries (entries/*.enc)
```

- **Device Digital Identity**: Each device has an asymmetric keypair (X25519 for HPKE wrapping, Ed25519 for commit signatures).
- **Private Key Escrow**: The user's device-specific asymmetric private key is symmetrically encrypted by their Master Password and committed to the repository at `meta/device-privkey.json` (the OS keyring is the preferred live location; this file is the synced fallback).
- **OAuth Bootstrapping**: Logging into a new device utilizes GitHub/GitLab OAuth to clone the repository. The user then enters their Master Password to decrypt their device private key from `meta/device-privkey.json` and escrow it into the local hardware enclave (Keychain, Secret Service, Android Keystore).
- **OAuth Token Storage**: The OAuth Personal Access Token (PAT) used for background git2-rs sync is stored securely in the host OS keyring (Apple Keychain / Secret Service), never committed to Git.

---

## DOMAIN 2: CONFLICT RESOLUTION & SYNCHRONIZATION

### D4. Conflict Auto-Resolution & Index Healing

**Decision: Field-level 3-way merge with user-verdict backstop (Phase 2, 2026-07-02)**

- **Field-level merge** (`sync/conflict.rs::merge_ciphers`): on a pull conflict, the daemon decrypts base/local/remote cipher versions (`VaultHandle::decrypt_cipher_bytes`) and merges non-overlapping field changes automatically. Security-sensitive field groups (username + password + TOTP) are atomic: if any field in the group conflicts, the whole group flags for user resolution. URIs and custom fields union.
- **Auto-merge path** (`MergeResult::Merged`): the merged cipher is re-encrypted under the merging device's `current_epoch` + `max(local_seq, remote_seq)+1` and finalized via `SyncEngine::finalize_conflicts` (writes a 2-parent merge commit + pushes). No UI prompt.
- **User-verdict path** (`MergeResult::Conflict`): same-field conflicts surface the top-floating `ConflictResolutionPanel` (D22) with a masked `MaskedConflict`. Verdicts: keep_local / keep_remote (raw blob from the chosen OID, no re-encrypt) or keep_both (new uuid clone under current epoch + seq 1, mirrors `add_cipher`).
- **Cross-epoch safety**: if any side's envelope is at an epoch the held `SpaceGroupKey` cannot reach (remote pre-rotation with destroyed old RootKey, or local behind post-rotation), `try_derive_item_key` returns `None` and the conflict surfaces with a `cross_epoch` flag; only keep_local/keep_remote (raw blob) remain safe verdicts. `keep_both` is refused (can't clone a side we can't decrypt).
- **Keep-local fallback** (`SyncEngine::resolve_conflict_keep_local`): the pre-Phase-2 path, still the default when a caller uses `run_sync_cycle` (the backward-compat wrapper delegates with a `ConflictResolution::KeepLocal` closure). The daemon's auto-sync coordinator opts in via `run_sync_cycle_with_resolver(..., Pause)`.
- **Engine integration** (Phase 2a): `run_sync_cycle_with_resolver` + `ConflictResolution { KeepLocal, Pause }` + `PendingConflictState` + `SyncCycleOutcome::NeedsDecision`. Additive; the cycle still falls back to keep-local when the caller doesn't opt in. `finalize_conflicts` is HEAD-guarded against double-resolve.
- **Index rebuild**: all three verdict paths call `rebuild_cipher_index()` after finalize (they write cipher files via `SyncEngine`, bypassing the `VaultHandle::add/update/delete` hooks that normally rebuild `meta/index.enc`). Critical for keep_both (the new clone cipher_id was never indexed).
- **Latent bug fixed in 2a**: `pull_inner` pre-transitioned the sync state machine to `Idle` before returning `Conflict`, making the subsequent `resolve_conflicts` final `Idle→Idle` transition invalid on any real conflict. Now leaves the state in `Merging` so the resolution path completes `Merging→Idle` legitimately. Pre-existing, untested before the 2a conflict tests.

> NOTE: earlier versions of this ADR described "silently force-pushes" and "renames the local version, accepts the remote commit." That was inaccurate and unsafe. The current policy preserves local edits and creates merge commits; never force-pushes.

---

### D5. Mobile JIT Sync

**Decision: Just-In-Time (JIT) sync fetch before biometric challenge**

To circumvent mobile OS sandboxes that aggressively terminate background synchronization loops:
1. **JIT Hook**: Triggered immediately when the mobile browser or credential provider requests autofill.
2. **Micro-Fetch**: baluard-core (via UniFFI binding) initiates a rapid `git fetch` to evaluate the remote branch SHA delta.
3. **Pulls Delta**: If a delta is present, baluard-core pulls changes, decrypts entries, and updates the local cache *before* prompting the user for biometrics (FaceID/Fingerprint).

---

### D5-bis. Desktop Auto-Sync (2026-06-26)

**Decision: Daemon-side debounced push + periodic pull + offline retry, diverging from Bitwarden's model**

**Context**: Bitwarden does immediate-push-per-save + server-side HTTP 409 last-write-wins + read-only mobile offline + 5-min full sync. That model is server-mediated; copying it onto a shared git remote would (a) spam N commits per burst + slow round-trips, and (b) lose data on conflicts because Bitwarden's server can't field-level merge.

**Decision**:
- **Debounced push** (5s coalesce) after every CRUD mutation via the `COVER_MUTATION_ACTIONS` hook in `handler.rs`. A burst of edits = one commit + one round-trip.
- **Periodic pull** every 30 min when idle + online (a quiet fallback, NOT the primary sync path). Event-driven pulls do the real work: pull immediately on vault unlock, on window focus (desktop fires `sync.autosync_nudge_pull`, server-side 10-min guard collapses flicker), and the push cycle itself commits→pulls→pushes so concurrent edits land right after a local mutation. Serverless architecture (git remote IS the server, no push channel), so unlike Bitwarden's SignalR inbound we must poll; 30 min is quiet enough to avoid a predictable periodic heartbeat (T14 timing-fingerprint) while the event triggers cover snappiness.
- **Offline handling**: network failures (classified from `git2::Error::class()` Net/Http/Ssh/Ssl → `SyncError::Network`) → `Offline` state → 30s retry probe. Offline edits queue locally until reconnect.
- **Canonical git workflow** (`SyncEngine::run_sync_cycle`): commit local → pull → resolve conflicts → push. Committing first keeps the worktree clean so the pull's force-checkout (C1 fix) cannot discard uncommitted edits (H2 fix).
- **Conflict policy (Phase 1)**: keep local via `resolve_conflict_keep_local` (2-parent merge commit → next push fast-forwards), surface a non-blocking banner. Field-level 3-way merge (`conflict::merge_ciphers`) is NOT yet wired into the cycle; Phase 2 will run it for silent non-destructive merge and only force-resolve true same-field conflicts.
- **Mutual exclusion** (C3 fix): `cycle_lock` tokio Mutex guarantees only one sync cycle touches the on-disk repo at a time; losers bail cleanly.
- **Activation**: in `VaultState::unlock` (immediate, not lazy); deactivated on lock. No daemon-side decrypted cache, so a pull does not require reloading the vault handle.

**Frontend**: desktop polls `sync.autosync_status` every 10s (`AutoSyncContext`); status pill in sidebar header (`AutoSyncIndicator`); non-blocking conflict banner (`ConflictBanner`). No Tauri event channel (request/response only).

**Mobile (future)**: the daemon is the single source of truth for sync; the mobile client will reuse the same IPC contract, so the coordinator serves both platforms. No duplicate logic.

---

## DOMAIN 3: PLATFORM ECOSYSTEMS & INTEGRATIONS

### D6. Single-String Protobuf Gateway

**Decision: Unification via `HandleRequest(action, payload)`**

**Current state**: Protobuf wire protocol fully implemented. Daemon compiles all 3 protos via prost-build. CLI compiles auth.proto. Length-delimited framing (varint prefix) on Unix sockets. 30+ daemon routes operational.

**Target**: All layers will communicate with baluard-core through a unified, serialized gateway interface:
- **Input**: A single Protobuf serialized string containing the action command and its parameters.
- **Output**: A serialized response string.
- This decoupling allows front-end tiers to compile with `MOCK_BACKEND=true` to skip native builds during UI development, feeding hardcoded mock Protobuf payloads directly to components.

---

### D7. Desktop Tier: Client-Server IPC Socket

**Decision: Rust Daemon (Server) + CLI Client (socket) + Tauri v2 (SolidJS/Tailwind UI)**

- **Rust Daemon (`baluard-daemon`)**: Started on boot by Tauri. Unlocks the vault into `zeroize`-protected memory. Listens on a platform-aware domain socket (Linux: `$XDG_RUNTIME_DIR/baluard/baluard.sock`, macOS: `~/Library/Application Support/baluard/baluard.sock`, Windows: Named Pipes) with `0600` permissions via umask before bind. Built on tokio for async I/O. Handles both SIGINT and SIGTERM for graceful shutdown. SO_PEERCRED peer UID verification on Linux. **Current state: fully implemented with 30+ routes, vault state, sync, devices.**
- **CLI (`baluard-cli`)**: Dual-mode socket client. Default: serializes flags into Protobuf, transmits to daemon via Unix socket, prints response. `--direct` fallback links baluard-core in-process. `--socket <path>` for custom daemon socket. All vault, sync, and devices commands implemented.
- **Tauri v2 UI**: SolidJS/Tailwind v4 webview. Communicates with the daemon via a `daemon_request` Tauri command that proxies Protobuf over Unix sockets. System tray with Show/Quit menu. Full cipher CRUD with 8 types (Login, Card, Identity, SSH Key, Secure Note, Bank Account, Driver's License, Passport/ID). Password generator (CSPRNG + EFF 7776-word passphrase). TOTP widget with boundary-aligned refresh. Auto-lock settings. Dark/light themes. Import/export (8 formats). Nested folders. Device fleet dashboard. Biometric unlock. **Current state: fully implemented.**

---

### D7-bis. Daemon Rationale: Why a Resident Process (2026-12)

**Decision: the vault engine runs in a separate daemon process, sidecar-owned by the desktop app. It is not folded into the UI process (the Bitwarden / KeePassXC / 1Password model).**

Every mainstream competitor ships a daemonless desktop app: Electron/standalone process, crypto in-process, extension integration via native messaging pointed at the app itself. The single-app model is viable and proven. Baluard keeps a daemon anyway, for four reasons that outrank the packaging simplicity it would buy.

**Why the split (priority order):**

1. **Key-process isolation (the load-bearing reason).** The daemon is the only process holding KEK, Root Key, and SGKs. The desktop webview parses remote-influenced content: favicons, imported files, entry strings. A decoder or rendering bug in the UI tier therefore reaches displayed plaintext and clipboard, never key material. Folding `baluard-runtime` into the app process converts "compromised UI" into "compromised vault". Bitwarden accepts exactly this exposure because its crypto already lives in the renderer process; we do not have to.
2. **Single sync writer per machine.** The daemon is the only process running sync cycles against the on-disk repo (`cycle_lock`, C3). A daemonless design needs the NMH and the CLI to run the same commit→pull→push cycles in parallel processes. Git file locks serialize raw writes but not semantic intent: parallel cycles churn merge conflicts and race on `sync-state.json`. Bitwarden's server arbitrates per-object revisions; a git remote arbitrates far less. With the weaker arbiter, single-writer is not optional.
3. **One unlocked session, three clients.** Desktop, CLI, and the browser extension (NMH relay) share the daemon's in-memory unlocked vaults and bridge tokens: unlock once, every client is served. Per-client sessions mean each process holds its own key material and runs its own unlock flow (Bitwarden CLI and extension each unlock separately; its desktop biometric bridge is the same resident role, merely embedded in the app).
4. **Capability enforcement for the webview.** The D2 webview hardening (action allowlist, forbidden-key filter) works because the webview is a dumb client: authority and key material sit on the daemon side of the socket. Trust boundary and capability boundary coincide. In-process, the allowlist becomes advisory.
5. **Deterministic teardown.** App quit = SIGTERM → 200 ms grace → keys zeroized. No key material outlives the UI lifecycle, and no second process lingers with secrets in memory.

**Lifecycle facts (what the daemon does NOT do):**

- The daemon is a Tauri sidecar: started on app launch, stopped on app quit. NMH and CLI never spawn it: NMH fails closed on a dead socket; the CLI points users at `baluard-daemon` or `--direct`.
- Window close is NOT quit: the window hides to the system tray (macOS Dock optional) and the daemon keeps running, so debounced pushes, periodic pulls, and conflict resolution continue while the UI is hidden.
- App quit DOES stop everything: no background git sync, no headless operation after quit. Autosync is tied to the app lifecycle by design.
- A headless daemon (system autostart, sync with no UI ever) is architecturally possible — the binary runs standalone — but is not built. It would trade away the zeroize-on-quit guarantee in point 5 and needs its own threat model (keys resident while the user believes the app is closed). Not planned.

**Alternative rejected (2026-12, egui + daemonless evaluation):** hosting the daemon role inside the desktop app process (serve the socket in-process). Rejected on points 1-3. Availability was NOT the differentiator: the extension is app-gated today either way, because the sidecar dies with the app. The differentiators are key isolation, single-writer sync, and the shared unlocked session.

---

### D8. Mobile Tier: UniFFI Bindings (baluard-uniffi)

**Decision: Mozilla UniFFI for Rust-to-Kotlin/Swift bridge**

Mobile apps bind to the vault engine via the `baluard-uniffi` crate over `baluard-runtime` and `baluard-core`:
- **Kotlin (Android)**: UniFFI generates Kotlin bindings from the UDL interface and library metadata. The native cdylib builds for 4 Android ABIs into `mobile/androidApp/src/main/jniLibs/`.
- **Swift (iOS)**: UniFFI generates Swift bindings compiled into an xcframework.
- **No intermediate language**: The Rust core is the single source of truth. No Go, no cgo, no gomobile. UniFFI provides a clean memory boundary between Rust memory and foreign code.
- **Direct in-process host**: The mobile client hosts `baluard-runtime` in-process directly without a background daemon.
- **Status**: Implemented in `crates/baluard-uniffi/`. Android Phases 0 through 6 are complete (Compose Multiplatform onboarding, home hub, filtered entry lists, 8 cipher types, detail/edit at desktop parity, deep search, generator, TOTP, biometric ceremony, auto-lock, sync, conflict panel, multi-vault, R8 build, Android Autofill Service with inline suggestions, save prompt, and quick-settings tile accessibility fill). Phase 7 iOS credential extension is next. iOS platform-specific actuals are pending.

---

### D9. Zero-Knowledge RBAC B2B & Family Sharing

**Decision: Envelope Asymmetric Key Wrapping via `meta/access_list.json`**

1. **Space Invitation**: An Admin enters an invitee's email. baluard-core fetches their public key from the Git host.
2. **Group Key wrapping**: baluard-core encrypts the Space's AES-GCM **Group Key** with the recipient's public key and appends the wrapped payload to `meta/access_list.json`.
3. **Acceptance**: Invitee decrypts the group key with their local device private key.
4. **Revocation / Offboarding**: The Admin rotates the Group Key. baluard-core re-encrypts the `entries/` directory, updates `access_list.json` for remaining members, and pushes the changes. The evicted user's local instance is instantly locked out of new commits, and all local entries are reduced to unreadable ciphertext.

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

## DOMAIN 5: DEVICE FLEET & REVOCATION

### Hard Constraints

1. **No server backend.** The git repository IS the coordination channel. No WebSocket, no ping endpoint, no real-time anything.
2. **Git commits are the heartbeat.** A device is "alive" if it has recently pushed. There is no other signal.
3. **Revocation is eventual, not instant.** A revoked device can continue reading locally until it pulls and sees the revocation. Inherent to serverless, non-negotiable.
4. **Git credentials are out-of-band.** Revoking vault access does NOT revoke git push access. Users must rotate deploy keys / PATs on GitHub/GitLab separately. Documented, not solved.

### Activity Index

**File**: `meta/device_activity.json`: Plaintext, UUID-only activity index. Last-writer-wins per UUID key. One file, merged on every push.

```json
{
  "v": 1,
  "devices": {
    "a1b2c3d4-...": {
      "last_push": "2026-06-02T14:30:00Z",
      "last_commit": "abc123def456...",
      "epoch": 7
    }
  }
}
```

| Field | Source | Purpose |
|-------|--------|----------|
| `last_push` | Self-reported ISO-8601 (corroborated by git committer date) | Fleet dashboard freshness |
| `last_commit` | SHA of the push commit | Verifiable via `git log` |
| `epoch` | Current epoch at push time | Shows if device is behind |

Why plaintext: UUIDs are opaque. Device names in `devices.json` are also plaintext (per D1). File lives in a private git repo. Exposure is "two UUIDs sync at these times." Acceptable for single-user vaults.

Why single file: One file with merge-by-key is simpler than N files with directory fanout. Git merge conflicts on a single JSON file resolve via union of keys, latest timestamp wins.

### Device Registry

`DeviceRegistry` in `devices.rs`: enroll, revoke, force-evict, quorum calculation. Stored in `meta/devices.json` (plaintext).

```rust
pub struct DeviceEntry {
    pub device_id: DeviceId,
    pub name: String,
    pub encryption_public_key: String,
    pub signing_public_key: String,
    pub enrolled_at: u64,
    pub enrolled_by: Option<DeviceId>,   // Which device approved enrollment (None for founding device)
    pub last_seen_epoch: u64,            // Last epoch this device was active in
}
```

### Stale Device Thresholds

Never auto-revoke. UI badges only:

| Threshold | Label | Color | UI Action |
|-----------|-------|-------|----------|
| < 7 days | Active | Green | None |
| 7-30 days | Idle | Yellow | None |
| 30-90 days | Stale | Orange | "Review devices" prompt |
| > 90 days | Dormant | Red | "Consider revoking" prompt |

Stale and dormant are prompts, not actions. A laptop in a drawer for 3 months is the common case. Compromise response is the existing `force_evict` flow.

### Revocation Flow

**Normal revocation** (quorum available, >= 2 devices):

1. Device A pulls latest, verifies all incoming commit signatures
2. User opens fleet dashboard, selects Device B, clicks "Revoke"
3. `device_manager.revoke(B)` removes B from `DeviceRegistry`
4. Epoch advances: N -> N+1 (ROTATING)
5. Root key rotation: new RootKey -> new SGK -> all ItemKeys re-derived -> all entries re-encrypted
6. KEK re-wrapped only for surviving devices (B excluded)
7. `meta/device_activity.json` updated: B's entry removed
8. A commits + pushes: `[device-revoke] removed <B-uuid>, epoch N+1`

**Force-evict** (single surviving device, emergency):

1. `revoke_device_and_rotate(target_id, self_id)` removes only the target, preserves all other enrolled devices
2. Root key rotation (epoch increment)
3. `meta/device_activity.json` cleaned for revoked device
4. Push with signed commit
5. Fallback: `force_evict(surviving_id)` for disaster recovery (all other devices lost)

**Revoked device experience**:

- Online: B pulls. Sync engine detects its signing key is no longer in registry. B enters read-only mode. Cannot decrypt epoch N+1 entries. Pushes rejected (signature verification fails on other devices).
- Offline: B retains readable copy at epoch N. Root key rotation ensures B's copy becomes stale.
- Git credential rotation is out-of-band. Fleet dashboard shows persistent warning after revocation: "Rotate git credentials for full security."

### ROTATING Epoch Timeout

If the device initiating rotation goes offline mid-ROTATING, cipher writes are blocked indefinitely. Solution: deterministic coordinator election after timeout.

```
if epoch.state == ROTATING && elapsed > configured_timeout && no_progress_commit:
    if cipher_files_written_at(new_epoch) > 0:
        // Cannot abort. Re-initiate rotation as new coordinator.
        return
    candidates = sorted(enrolled_devices, by=uuid_bigendian)
    new_coordinator = candidates[0]  // lowest UUID, deterministic
    if self.device_id == new_coordinator:
        epoch.abort_rotation()
        write_abort_marker(new_epoch)
```

Rules:
- Configurable timeout (default 1h, range 15min-24h). Stored in VaultSettings.
- UUID big-endian comparison: sort enrolled UUIDs as 128-bit integers, elect lowest.
- Elected device aborts stalled rotation (epoch -> ACTIVE) and can re-initiate.
- User confirmation required before aborting another device's rotation.
- Abort marker: `meta/rekey/{new_epoch}.aborted`

### Signed Commits

- Sync engine signs every commit with Ed25519 device key. Signature in `gpgsig` header.
- `verify_commit_signatures()` validates incoming commits against device signing keys.
- Pre-unlock: reads from plaintext `meta/devices.json`. Post-unlock: reads from encrypted `DeviceRegistry`. Plaintext never overrides encrypted after unlock.

### Architectural Decisions

**D1: `devices.json` stays plaintext.** Public keys are public. Device names carry no secrets. Private git repo is the access boundary. Encrypting gains nothing while breaking pre-unlock fleet visibility.

**D2: `devices.json` is the canonical key file.** Eliminates `device-registry.json` and `device-pks`. Single source of truth for signing keys.

**D3: No `push_count` in activity index.** Self-reported, unverifiable. Entries are `{last_push, last_commit, epoch}` only.

**D4: No enrollment approval signature.** Single-user tool. `enrolled_by: Option<DeviceId>` is the right level. Attacker who can tamper with DeviceEntry on disk can also tamper with a signature.

**D5: Last-writer-wins for activity index conflicts.** Ephemeral timestamps, no secrets. No custom git merge driver needed.

**D6: Persistent git credential rotation banner.** Parse remote URL, construct direct link to `github.com/<repo>/settings/keys`, show numbered steps. Dismiss only after explicit checkbox confirmation.

### Security Considerations

| Risk | Mitigation | Accepted because |
|------|-----------|------------------|
| No real-time revocation | Eventual consistency via git pull | Fundamental to serverless model |
| Revoked device retains epoch N data | Root key rotation limits to stale snapshot | Cannot remote-wipe without server |
| Git credentials not auto-rotated | Post-revocation warning + documentation | No GitHub API access from vault |
| Plaintext activity index (UUIDs) | UUIDs opaque; private repo boundary | Low-sensitivity metadata |
| Self-reported timestamps | Corroborated by git committer date + commit SHA | Display from git log, not file |

### Multi-User / Org Considerations (Future)

Not in scope for current implementation:

1. Per-user device registries: `meta/users/<user_id>/devices.json`
2. Role-based revocation: Admin revokes any, users self-revoke only
3. Per-collection SGKs: Separate Space Group Keys per collection
4. Activity privacy: Split `device_activity.json` per user
5. M-of-N root key recovery: Shamir secret sharing for multi-owner vaults
6. Admin fleet dashboard: Admin sees all users' devices

---

## DOMAIN 6: DEVICE LIFECYCLE & ROOT KEY ROTATION

### Hard Constraints

1. **No server backend.** Desktop and mobile apps work standalone, fully offline. Git sync with GitHub/GitLab is optional.
2. **Single-device is the default.** Multi-device is opt-in via git sync or local transport.
3. **All crypto is local.** Rust core via UniFFI. Zero platform-native crypto on mobile.

### DeviceManager Aggregate

```
DeviceManager
├── DeviceRegistry      (pure data: HashMap<Uuid, DeviceEntry>, serializable)
├── EpochInfo           (pure state machine: CREATED→ACTIVE→ROTATING→RETIRED→DESTROYED)
└── RotationCoordinator (two-phase commit logic, owns the transaction)
```

`DeviceManager` lives in `crates/baluard-core/src/device_manager.rs`. It owns the coordination between registry, epoch state, and rotation. Individual components remain independently testable pure structs. `VaultHandle` holds a `DeviceManager`. All vault ops check epoch state through it.

### Three Operational Modes

#### Mode 1: Single Device, No Network

The default. 90%+ of users.

```
1. Generate new Root Key (RK')
2. HPKE(RK', this_device_x25519_pk) → write new keywrap file
3. Re-derive Space Group Keys under RK'
4. Re-encrypt all space headers under new SGKs
5. Self-acknowledge → epoch ROTATING → RETIRED → new ACTIVE
6. Zeroize old RK, old SGKs
7. Commit to local git repo (no remote push)
```

Single atomic local transaction. No `.ack` files. No quorum wait. `quorum_required()` returns 1 for N=1.

#### Mode 2: Multi-Device, Git Remote Configured

Multiple devices sharing a vault via GitHub/GitLab/self-hosted git.

**Rotation flow (two-phase commit via git):**

```
Phase 1: PROPOSE (initiating device, online now):
  1. Generate RK'
  2. For each enrolled device:
     HPKE(RK', device_x25519_pk) → wrapped_keys[device_id]
  3. Build RekeyTransaction:
     { old_epoch, new_epoch, wrapped_keys, initiator, timestamp }
  4. Write meta/rekey/{new_epoch}.txn
  5. Git commit + push
  6. Transition epoch → ROTATING
  7. Vault: READS allowed (old epoch), WRITES blocked

Phase 2: ACKNOWLEDGE (each device, async, on next sync):
  1. Pull from remote
  2. Read meta/rekey/{new_epoch}.txn
  3. Unwrap own HPKE(RK', my_pk) → verify RK' is sane
  4. Compute txn_hash = SHA-256(serialized .txn file)
  5. Sign: Ed25519(my_signing_sk, "ack" || epoch || device_id || txn_hash)
  6. Write meta/rekey/{new_epoch}.ack.{device_id}
  7. Git commit + push

Phase 3: COMMIT (any device observing quorum):
  1. Pull from remote
  2. Collect all .ack.* files for this epoch
  3. For each ack:
     - Verify Ed25519 signature against enrolled device's signing key
     - Verify txn_hash matches the .txn file (prevents ack transplant)
  4. If verified ack count >= quorum (ceil(N/2)):
     - Re-derive SGKs under new RK'
     - Write meta/rekey/{new_epoch}.committed
     - Transition: old epoch → RETIRED, new epoch → ACTIVE
     - Delete old keywrap files for evicted devices
     - Vault WRITES re-enabled
     - Git commit + push
```

**Quorum rules:**

| Enrolled devices | Quorum required | Rationale |
|---|---|---|
| 0 | 0 | Empty vault |
| 1 | 1 | Self-ack, immediate |
| 2 | 1 | Unilateral rotation accepted (single-user) |
| 3 | 2 | Majority |
| 4 | 2 | Majority |
| 5 | 3 | Majority |

#### Mode 3: Multi-Device, No Git Remote (Local Transport)

Two devices on the same desk, no cloud.

**Transport options** (priority order):
1. **QR codes**: small payloads (enrollment, ack bundles)
2. **File export/import**: larger payloads (pairing bundle, git bundle)
3. **USB drive**: `git bundle` for full vault sync

Rotation uses the same two-phase commit as Mode 2, but ack delivery is physical. The `ROTATING` epoch state persists between transfers.

### Enrollment

#### First Device

Automatic. No approval needed. The empty registry auto-approves the first enrollment.

#### Additional Devices

Requires physical presence + master password confirmation on an existing enrolled device.

**Transfer methods:**

| Method | How | Best for |
|--------|-----|----------|
| **QR code** | Display string as QR, scan with camera | Phones, tablets |
| **Manual copy** | Display string as text, user copies/types on other device | No camera, accessibility needs, terminals |
| **File export** | Save as .json file, transfer via USB/LAN | Large payloads, batch enrollment |

**Two-way pairing flow:**

```
New device                          Existing device
   |                                      |
   | 1. Generate keypair                  |
   | 2. Display QR #1:                    |
   |    {device_id, x25519_pk,            |
   |     ed25519_pk, nonce, timestamp,    |
   |     name: "Esteban's iPhone"}        |
   |                                      |
   | ------- QR #1 scanned ------->       |
   |                                      | 3. Validate timestamp/nonce/keys
   |                                      | 4. Prompt: "Approve device?"
   |                                      | 5. User enters master password
   |                                      | 6. Sign approval + HPKE wrap RK
   |                                      | 7. Build pairing bundle
   |                                      |
   | <---- QR #2 / file export --------  |
   |                                      |
   | 8. Import pairing bundle             |
   | 9. Verify approval_sig               |
   | 10. Unwrap RK via own x25519_sk     |
   | 11. Enrollment complete              |
```

**Anti-replay:**
- Nonce: 32 random bytes, unique per enrollment attempt
- Nonces stored in `meta/seen-nonces.json` (persisted across restarts)
- Timestamp: ±5 minute window

### Recovery-Phrase Enrollment (D14-bis, 2026-06-11)

**Motivation.** The original D14 design required an enrolled device to approve any new device. This is hostile to single-user, serverless workflows: a solo user who loses all devices cannot add a new one without a pre-existing device to produce the approval signature. The product intent (no central server, easy to use, future-proof) demands that the recovery phrase (which is already the root authority for `recover_from_phrase`) also work for non-destructive enrollment.

**Two-path enrollment controlled by `VaultSettings::enrollment_policy`:**

- `Personal` (default for new vaults): either an enrolled-device signature OR the recovery phrase can authorize enrollment. The recovery phrase is the root authority and can already perform full disaster recovery; non-destructive enrollment via phrase is a strict subset of that authority.
- `Strict` (default for existing vaults, backward compat): only an enrolled-device signature can authorize enrollment. Recovery phrase only works via destructive `recover_from_phrase`.

**New method:** `DeviceManager::enroll_with_recovery_phrase(payload, phrase)`. Non-destructive: enrolls into the existing registry without resetting devices. Unwraps Root Key from `meta/recovery.json`, writes a new keywrap for the new device, persists state. Reuses the same timestamp/nonce replay protection as `enroll()`.

**Mandatory write-down verification.** During vault creation, the user MUST re-enter 4 random words from the recovery phrase before they can proceed. Positions are deterministic (FNV-1a hash of the phrase) so the same phrase always asks for the same words. Applied in both desktop (`RecoveryScreen.jsx`) and CLI (`init` flow). This is not security theater: it is the only defense against permanent vault loss when all devices fail.

**CLI surface:** `baluard devices enroll-with-phrase [--phrase <24 words>]`. Prompts for phrase if not provided. Requires typed `enroll` confirmation (warns user that the phrase is root authority). Enforces policy: rejects if `Strict` with a clear error directing to `baluard recover`.

**IPC surface:** `vault.enroll_with_phrase` (daemon route). Validates 24-word shape, checks `enrollment_policy`, builds `EnrollmentPayload` for the current device, calls `enroll_with_recovery_phrase`, writes `meta/device-privkey.json`.

**Threat model.** The recovery phrase is already the root authority: `recover_from_phrase` exists for full disaster recovery. Phrase-based enrollment is a strict subset of that authority. If the phrase is compromised, the vault is already compromised. The master password alone remains insufficient to add a device.

**Files:**
- `crates/baluard-core/src/vault/manifest.rs`: `EnrollmentPolicy` enum
- `crates/baluard-core/src/device_manager.rs`: `enroll_with_recovery_phrase`
- `crates/baluard-daemon/src/handler.rs`, `crates/baluard-runtime/src/state.rs`: IPC route
- `crates/baluard-cli/`: subcommand + handler
- `desktop/src/components/RecoveryScreen.jsx`: verification step
- `desktop/src/i18n/locales/{en,es}.json`: translations

### Epoch State Machine

```
CREATED → ACTIVE → ROTATING → RETIRED → DESTROYED
                      ↑           │
                      └───────────┘
                    (new epoch becomes ACTIVE)
```

| State | Reads | Writes | Description |
|-------|-------|--------|-------------|
| CREATED | No | No | New epoch initiated, not yet pushed |
| ACTIVE | Yes | Yes | Normal operation |
| ROTATING | Yes (old epoch) | **No** | Rotation in progress. Writes blocked. |
| RETIRED | No | No | Old epoch deprecated. Keys purged. |
| DESTROYED | No | No | Old epoch key material zeroized. |

### Force Eviction

**Selective revocation** (preferred, multi-device vaults):

1. User authenticates on surviving device
2. `DeviceManager.revoke_device_and_rotate(target_id, self_id)` removes only target, preserves others
3. Epoch rotation initiated immediately
4. New Root Key generated, HPKE-wrapped for all remaining devices
5. Self-ack, immediate commit
6. Activity index cleaned for revoked device
7. Vault writes re-enabled under new epoch

**Emergency force-evict** (single-survivor disaster recovery):

1. `DeviceManager.force_evict_and_rotate(surviving_device_id)` clears all non-surviving devices
2. Epoch rotation initiated immediately
3. New Root Key generated, HPKE-wrapped only for surviving device(s)
4. Self-ack, immediate commit
5. Old keywrap files for evicted devices deleted
6. Vault writes re-enabled under new epoch

Force eviction without rotation is NOT eviction. The evicted device can decrypt everything until rekey happens. Both paths are atomic.

### Recovery Phrase (BIP-39)

The offline backup mechanism. When all devices are lost.

1. User enters BIP-39 recovery phrase on new device
2. Derive master key from phrase
3. Re-derive Root Key from master key
4. Create new single-device vault
5. Old device registry abandoned

Recovery bypasses DeviceManager enrollment entirely. The recovery phrase IS the root of trust. No quorum, no approval, no other device needed.

### File Layout

```
.baluard                   # Vault detection marker FILE (version, vault_id, slug). Not a dir.

meta/
  rekey/
    {epoch}.txn            # Rotation proposal (HPKE-wrapped RK' per device)
    {epoch}.ack.{device}   # Device acknowledgment (signed, with txn_hash binding)
    {epoch}.committed      # Finalized rotation (populated commit_barrier)
    {epoch}.aborted        # Abort marker for a cancelled rotation
  devices.json             # DeviceRegistry (enrolled devices, keys)
  epoch.json               # EpochInfo (current epoch state)
  seen-nonces.json         # Anti-replay enrollment nonces
  keywrap/
    {device_id}.json       # HPKE-wrapped Root Key per device
  settings-pub.json        # Plaintext display prefs (theme, lang), pre-unlock readable
  settings.enc             # AES-256-GCM under root key: vault_timeout, default_uri_match,
                          #   fetch_favicons, slug, enrollment_policy (privacy: slug/policy
                          #   must not leak to the git remote in plaintext)
  profile.enc              # AES-256-GCM under root key: display_name, subtitle, avatar_ext
  folders.enc / tags.enc   # AES-256-GCM under root key: folder + tag manifests
  activity.enc             # AES-256-GCM under root key: device activity index
  avatar.{ext}             # Unencrypted avatar file (vault is encrypted at rest)
```

### Sequence Diagram: Full Rotation (Multi-Device, Git Remote)

```
Device A (initiator)          Git Remote           Device B
     |                            |                    |
     |-- initiate_rotation() ---->|                    |
     |   (epoch → ROTATING)       |                    |
     |   (writes .txn)            |                    |
     |-- git push --------------->|                    |
     |                            |                    |
     |                            |-- git pull ------->|
     |                            |                    |
     |                            |   read .txn
     |                            |   unwrap RK'
     |                            |   sign ack
     |                            |   write .ack.B
     |                            |<-- git push -------|
     |                            |                    |
     |-- git pull --------------->|                    |
     |                            |                    |
     |   read .ack.B              |                    |
     |   verify signature         |                    |
     |   verify txn_hash          |                    |
     |   ack count >= quorum?     |                    |
     |   commit_rotation()        |                    |
     |   (epoch → new ACTIVE)     |                    |
     |   write .committed         |                    |
     |-- git push --------------->|                    |
     |                            |                    |
     |                            |-- git pull ------->|
     |                            |                    |
     |                            |   read .committed
     |                            |   unwrap new RK'
     |                            |   update local epoch
     |                            |   vault WRITES re-enabled
```

---

## DOMAIN 7: FRONTEND ARCHITECTURE (SolidJS + Tauri v2)

The desktop frontend is a SolidJS + Tailwind v4 app inside Tauri v2. All IPC via `daemon(action, payload)` through Tauri's `invoke("daemon_request")`. Request/response. No SSE, no streaming.

### D10. Store Split (Completed 2026-06-04)

**Decision: 2-provider split with standalone signals. No external state library.**

Replaced monolithic `AppContext` (30 signals) + `useActions` hook (243 lines) with:

| Module | Type | Signals | Scope |
|---|---|---|---|
| `context/AuthContext.jsx` | Provider | status, vaultInfo, biometricAvailable | App lifecycle. Outermost. Wraps entire app. |
| `context/VaultContext.jsx` | Provider | 12 signals: cipher data, navigation, device fleet, settings modal | Cipher CRUD. Only mounts inside `<Show when={status() === "unlocked"}>`. |
| `context/errorSignal.js` | Standalone `createSignal` | error | Global. Consumed by both auth and vault layers. |
| `context/themeSignal.js` | Standalone `createSignal` | theme | Survives lock/unlock. Syncs `<body>` class + localStorage. |
| Local state in components | `createSignal` in owning component | viewCipher, newCipher, showDeleteConfirm, showGenerator (VaultView); showReprompt (RepromptModal) | Single-consumer signals. Not in any provider. |

**Provider nesting:**

```
<I18nProvider>
  <AuthProvider>           // 3 signals, co-located lock/unlock/createVault
    <App />
  </AuthProvider>
</I18nProvider>

App renders:
  locked   → <LoginScreen />         (useAuth + errorSignal)
  init     → <CreateVaultScreen />   (useAuth + errorSignal)
  recovery → <RecoveryScreen />      (useAuth + errorSignal)
  unlocked → <VaultProvider>          // 12 signals, co-located cipher CRUD
                <VaultView />        (useAuth + useVault + local signals)
             </VaultProvider>
```

**Structural reset on lock:** VaultProvider mounts inside `<Show when={status() === "unlocked"}>`. On `lock()`, setting `status="locked"` causes VaultProvider to unmount, destroying all 12 vault signals + 6 local signals automatically. `lock()` went from 7 manual resets to 2 (`setStatus`, `setVaultInfo`). Impossible to forget a signal.

**Actions co-located.** `useActions.js` deleted. Every store owns its own actions. No cross-store compound actions exist after the split.

**Key principle:** If a signal is consumed by exactly one component subtree, it's local state. Context is for cross-component communication.

### D11. Refactor Candidates (Completed 2026-06-04)

Four candidates analyzed, prioritized, and executed.

#### Candidate D: SVG Icon Component (Completed)

Created `components/Icon.jsx` with 40+ named SVG icon exports. Migrated 67/70 inline SVGs across 12 components. Categories array in VaultView: 13 lines of SVG markup → clean named imports.

#### Candidate B: Filter Pipeline (Completed)

Created `lib/filters.js` with pure functions: `selectSource`, `filterByCategory`, `filterByFolder`, `searchCiphers`. `CATEGORY_TYPE_MAP` as single source of truth mapping UI category names to daemon cipher type strings. VaultView inline 45-line filter replaced with 6-line composed pipeline. Vitest tests cover all helper functions.

#### Candidate C: State Transition Guards (Completed)

`VALID_AUTH_TRANSITIONS` table in AuthContext (7 states, documented valid edges including `init -> locked`, `recovery -> setup`). `VALID_PANE_TRANSITIONS` table in VaultContext (4 states). `guardedSetStatus`/`guardedSetPane` wrap all internal state transitions. Dev-only `console.warn` on invalid transitions.

#### Candidate A: Cipher Schema (Completed)

Created `lib/cipherSchema.js` with schemas for all 8 cipher types. Each schema defines: `fields[]`, `fromKind(structured→flat)`, `toKind(flat→structured)`. Replaced `CipherDetail.startEdit()` 80-line manual field mapping with `cipherToFlat()`. Replaced `payload.buildKind()` 100-line if/else chain with `schema.toKind()`. Vitest tests include roundtrip tests for all 8 types. Single source of truth for field name mappings (was 3-file implicit contract). `AddEditCipherForm.jsx` still uses 8 `<Show>` blocks for field rendering: schema-driven form rendering is future work.

#### Future Work

- Schema-driven form rendering: replace 8 `<Show>` blocks in AddEditCipherForm with schema-driven field iteration (would reduce ~850 lines to ~300)
- `filteredCiphers` in VaultView could use `createMemo` for caching (called twice per render)
- Transition guards are advisory-only: raw setters still exported for external navigation

### Frontend Constraints

1. **SolidJS stays.** No framework migration.
2. **No external state library.** Pure SolidJS primitives (`createSignal`, `createContext`, `createEffect`).
3. **No behavioral changes in refactors.** Same UI, same IPC, same daemon protocol.
4. **Incremental.** Each refactor independently verifiable (build + test).
5. **daemon.js, payload.js, utils.js, app.css, i18n keys are touch-free zones.**
6. **Tests must grow.** Each refactor adds tests for previously untested logic.

### D12. SSH Key Generation (Completed 2026-06-09)

**Decision: Daemon-side SSH key generation with `ssh-key` crate**

SSH keypairs are generated in the daemon process using the `ssh-key` crate. Private key material never crosses the IPC boundary.

**Key types:**
- Ed25519 (default, recommended): Fast, modern, 256-bit seed via ed25519-dalek
- ~~RSA 4096 (legacy compatibility): Generated via ssh-key crate with rand_core adapter~~ Removed in L7 fix (Marvin Attack advisory, no fix).
- ECDSA P-256 (FIPS compliance): Generated via ssh-key crate with NIST P-256 curve

**Daemon command:** `ssh.generate_key` accepts `{type: "ed25519"|"ecdsa256"}`, returns JSON `{public_key, fingerprint, private_key}` in OpenSSH format.

**L7 fix:** RSA 4096 removed. The `rsa` crate has RUSTSEC-2023-0071 (Marvin Attack, timing sidechannel, no fix), pulled in transitively by `ssh-key`'s `rsa` feature. Ed25519 (default) and ECDSA P-256 cover modern needs.

**Desktop UI:** `SshKeyGenerator.jsx` component with type selector, generate button with spinner, copy buttons for public key and fingerprint, private key behind warning disclosure (`<details>` element).

**rand_core compatibility:** The project uses `rand` 0.8 (rand_core 0.6) while `ssh-key` 0.7 requires rand_core 0.10. Ed25519 bypasses this by constructing keypairs directly from seed bytes. RSA/ECDSA use an `Adapter` struct implementing `ssh_key::rand_core::TryRng` and `TryCryptoRng` by delegating to `rand::rngs::OsRng` with `Infallible` error type.

### D13. Modal Accessibility (Completed 2026-06-09)

**Decision: Reusable FocusTrap component for all modals**

All modals use `<FocusTrap containerRef={ref} onEscape={fn} />` providing:
- `role="dialog"`, `aria-modal="true"`, `aria-labelledby`, `aria-describedby` attributes
- Tab/Shift+Tab focus trap within modal container
- Escape key dismiss
- Auto-focus first interactive element on mount
- Restore focus to trigger element on unmount

**Applied to:** DeleteConfirm, ArchiveConfirm, Reprompt, Generator, Settings, EmptyTrash modals.

### D14. User Profile (Completed 2026-06-09)

**Decision: Profile data in encrypted `profile.enc`, avatar as separate file**

Profile fields (`display_name`, `subtitle`, `avatar_ext`) live in `meta/profile.enc` (AES-256-GCM under the root key via `derive_profile_key`), migrated out of the plaintext `settings.json`. Avatar stored as `meta/avatar.{ext}` in vault directory (unencrypted, synced via git). Rationale: vault is already encrypted at rest; storing base64 avatar data inline bloats diffs.

> **2026-06-26 update:** the rest of `settings.json` was also split for privacy (see D16). Display prefs (`theme`, `lang`) → plaintext `meta/settings-pub.json`; vault identity/policy (`slug`, `enrollment_policy`, `vault_timeout`, `fetch_favicons`, `default_uri_match`) → encrypted `meta/settings.enc`.

**Constraints:** Ext validated against whitelist (`png/jpg/jpeg/gif/webp`), size capped at 350KB base64. Path traversal validated. Old avatar file cleaned up on ext change.

**Daemon commands:** `vault.avatar.get` returns base64 data, `vault.avatar.set` accepts base64 + ext. SettingsModal holds local state, syncs back to VaultContext on modal close via `createEffect`.

### D15. Toast Notification System (Completed 2026-06-09)

**Decision: Standalone signal-based toasts, no inline feedback text**

`toastSignal.js` provides `toastSuccess(message)` and `toastError(message)` standalone signals consumed by `ToastContainer.jsx`. All user feedback uses toasts. No inline "Profile saved" or "Copied!" text.

### D16. Tag Deletion with Confirmation (Completed 2026-06-09)

**Decision: Hover-reveal delete with confirmation modal**

Sidebar tag pills reveal an X on hover. Click triggers a confirmation modal. Confirmation calls `tag.delete` daemon command which removes the tag from all ciphers and rebuilds the tag index. Uses existing `DeleteConfirmModal` pattern with FocusTrap.

### D17. Full i18n (Completed 2026-06-09)

**Decision: Zero hardcoded user-facing strings**

All user-facing strings replaced with `t()` keys. Both `en.json` and `es.json` maintained in sync. Covers: cipher schema labels, form fields, modal text, toast messages, settings sections, SSH key generation UI.

### D18. Vault Creation Wizard (Completed 2026-06-10)

**Decision: Split-path wizard with 3-step desktop flow and hybrid CLI flags**

CLI chains profile + preferences into `VaultCreator` builder before `execute()`. Desktop creates vault first, then applies profile/prefs via separate IPC calls (`settings.set`, `locale.save`). This split exists because desktop collects profile AFTER `vault.create` (step 3), so the creation payload cannot include it.

**Schema changes:**
- `ThemeMode` enum (`Light`/`Dark`/`System`) with case-insensitive serde, replacing `Option<String>` on `VaultSettings.theme`
- `VaultSettings.lang` field for language preference
- `save_locale()`/`load_locale()` on VaultHandle for the language pref (2026-06-26: consolidated into `meta/settings-pub.json` with `theme`; the standalone `meta/locale` sidecar is deprecated and migrated on read)
- `locale.save` daemon route (plaintext write of `settings-pub.json` for pre-unlock access)

**CLI (`baluard init`):** `--profile`, `--name`, `--slug`, `--theme`, `--lang`, `--auto-lock` flags (no `--subtitle`: removed 2026-06-11). OS locale auto-detection (`$LANGUAGE > $LC_ALL > $LC_MESSAGES > $LANG`). Interactive prompts when TTY, hard errors when piped. 8-char minimum enforced as hard error.

**Desktop (3-step wizard):**
1. `CreateVaultScreen` -- language selector (auto-detected from `navigator.language`) + password
2. `RecoveryScreen` -- phrase display + copy, transitions to `setup`
3. `SetupScreen` (new) -- profile fields + theme selector + auto-lock, FocusTrap, applies via IPC

**Auth state machine:** Added `setup` state. Transitions: `recovery -> setup -> unlocked`. 7 states total.

**Key design decisions:**
- Avatar deferred to Settings (rarely urgent on first run)
- Crash between creation and profile write accepted (profile is cosmetic, missing = defaults)
- Recovery phrase printed to stdout in CLI (no confirmation prompt -- breaks piped/CI)
- Language persisted in plaintext `meta/settings-pub.json` (single source; login screen needs it before unlock). Pre-2026-06-26 this was duplicated across encrypted settings + `meta/locale`; both are consolidated into `settings-pub.json` now.

### D19. Settings Split: Encrypted Identity + Public Display Prefs (2026-06-26)

**Decision: Split `meta/settings.json` into a plaintext display-prefs file and an encrypted identity/policy file, to stop leaking vault metadata to the git remote.**

**Problem:** the legacy `meta/settings.json` was fully plaintext and synced via git. It exposed `slug` (vault + often user identity), `lang`, `theme`, `enrollment_policy`, `fetch_favicons`, `default_uri_match` to anyone with read access to the remote. For a privacy-focused password manager this is a real smell even though none of the fields are secrets.

**Decision:**
- `meta/settings-pub.json` (plaintext, pre-unlock readable): `theme` + `lang` only. The login screen needs these before the master password is entered.
- `meta/settings.enc` (AES-256-GCM under the root key via `derive_settings_key`, mirrors the `profile.enc`/`folders.enc`/`tags.enc` pattern): `vault_timeout`, `default_uri_match`, `fetch_favicons`, `slug`, `enrollment_policy`. None have a pre-unlock consumer.

**Why `slug` can be encrypted:** confirmed the runtime authoritative source is the `.baluard` marker + the vault registry, never `settings.json`. The settings copy is write-mostly (populated at creation, never read for routing/display).

**`lang` consolidation:** the pre-unlock language pref previously lived in two plaintext places (`settings.json` + `meta/locale`). Both are consolidated into `settings-pub.json`; `meta/locale` is deprecated and migrated on read.

**Migration:** on first `save_settings` post-split, the legacy `settings.json` is read via a fallback path, split into the two new files, and deleted. `get_settings` reassembles the full `VaultSettings` struct from both halves (plus legacy fallback) so callers are unchanged.

**Files NOT touched (already safe):** `kdf-params.json` (salt + cost are public by design; encrypting them is circular), `recovery.json` (already an HPKE-wrapped blob; the public keys it contains are public by definition), `keywrap/*.json` (same: wrapped material).

### D19-bis. Phase 6 Multi-Vault Switching (2026-06-17; DONE)

See `docs/plan-git-providers-multi-vault.md` Phase 6 for the full design and acceptance criteria. Implemented in `crates/baluard-runtime/src/host.rs` + integration tests in `crates/baluard-daemon/tests/phase6_switching.rs`. The keep-unlocked / switch-pointer model replaces the pre-Phase 6 single `Arc<VaultState>`:

- `VaultHost` wraps a single `RwLock<VaultHostInner>` over `vaults: HashMap<String, Arc<VaultState>>` + `active: Option<String>`. One lock guards both (no two-lock race; the `active`-is-in-the-map invariant is provable).
- `vaults.switch` is a pointer flip: validate slug + set `active` under one write lock, touch registry `last_opened` OUTSIDE the lock. No zeroization, no token change.
- Per-vault session tokens (`vault.unlock` returns `{slug, token}`). Desktop keeps `Map<slug, token>`. Token check is per-vault; vault-A token rejected for vault-B op.
- Handler snapshots the target `Arc<VaultState>` clone once per request (no TOCTOU from mid-request `switch`).
- `vaults.close` is Arc-drain: removes the entry, clears `active` if needed, returns immediately. In-flight handlers finish and zeroize on last drop.
- Auto-lock walker iterates the map every 30s, applies each vault's own `auto_lock_minutes` + `last_activity`. **Active-pointer-on-autolock policy:** when the active vault auto-locks, `active` is LEFT pointing at it (re-unlock UX, not the picker).
- Cover-commit timers are per-vault, keyed to locked/unlocked (never to `active`). A switch touches no cover timer.
- Lock-all on `Tauri WindowEvent::Focused(false)` (desktop clears token cache, refreshes on focus regain). OS suspend / screen-lock / lid-close hooks (macOS NSWorkspace, Linux login1 D-Bus PrepareForSleep, Windows WM_POWERBROADCAST/SessionSwitch) documented as follow-up.
- `log_mlock_budget` logs aggregate resident key bytes (96 B/vault: RootKey+SGK) + RLIMIT_MEMLOCK after every unlock.

### D20. Quick Unlock: Per-Vault Biometric Scoping + Session PIN (2026-06-XX; DONE)

**Decision: Split quick-unlock into two distinct mechanisms, both per-vault.**

**Motivation.** The pre-D20 single global keychain entry (`quick-unlock`) was a privacy bug across multi-vault setups: enabling biometric unlock on vault A also unlocked vault B under the same OS keychain entry. It was also wrong for the common case where one vault supports Touch ID and another should require master password only.

**Decision:**

**A) Per-vault biometric (master-password escrow in OS keychain):**
- **Keychain account:** `quick-unlock:<vault_id>` instead of `quick-unlock`. The `vault_id` is a deterministic UUID derived from the KDF salt (`VaultHandle::derive_vault_id` / `vault_id_for_path`), stable across vault renames + git-sync.
- **macOS** (`security-framework` v3): stored with `SecAccessControl(BIOMETRY_ANY)` so Touch ID / passcode is required on every read.
- **Linux**: `keyring` crate with `linux-native` backend + `sync-secret-service` feature + `crypto-rust` (requires `libsecret` dev packages at build time).
- **Windows**: `keyring` crate with `windows-native` backend (Credential Manager / DPAPI). Note: Windows Credential Manager is NOT biometric-gated per-read, hence the session-PIN fallback below.
- **Migration:** legacy global `quick-unlock` entry wiped once at daemon startup via `disable_legacy_global()`.
- **Routes:** `vault.biometric_status` (not token-gated), `vault.biometric_enable` / `vault.biometric_disable` (token-gated), `vault.biometric_unlock` (host-level, not token-gated).

**B) Session PIN (Linux + Windows-without-Hello fallback):**
- **In-memory only.** `PinEscrow` on `VaultState::pin` holds the Argon2id-derived KEK + an Argon2id verifier over the PIN. Both zeroized on drop, NEVER on disk.
- **Skips Argon2id master KDF.** PIN unlock calls `VaultHandle::unlock_with_kek`, which still verifies keywrap + canaries (a stale KEK, such as master password changed on another device, fails closed).
- **Session-bound:** dies on daemon restart / vault close. **Survives soft-lock** (escrow is a separate `VaultState` field from the handle).
- **5-strike nuke:** after `pin::MAX_PIN_FAILURES` (=5) wrong PINs the escrow is destroyed and the master password becomes mandatory. The 10^6 keyspace cannot be brute-forced through this in-process cap.
- **Routes:** `vault.pin_status` (not token-gated), `vault.pin_enable` / `vault.pin_disable` (token-gated), `vault.pin_unlock` (host-level, not token-gated, mirrors `vault.biometric_unlock`).

**Frontend (desktop):** the login screen queries both `vault.biometric_status` and `vault.pin_status` (slug-routed, pre-unlock safe) and shows whichever buttons are enabled for the selected vault.

**Why two mechanisms.** Biometric is the primary UX on macOS (Touch ID). On Linux there's no biometric keychain; the in-memory PIN fills the same role (cheap re-unlock while the daemon is alive) without weakening the master-password-derived KEK chain. Windows-without-Hello gets the same PIN fallback because `keyring` `windows-native` does not gate reads biometrically.

**Vault Detach (asymmetric UI vs CLI):** Detaching a vault (drop registry entry) is exposed in the `VaultSwitcher` dropdown (`DetachVaultModal`). The destructive arm (`delete_from_disk`) is deliberately NOT exposed in the UI: only the safe, reversible detach. The power-user escape hatch is the CLI: `baluard vaults detach <slug> --delete-from-disk` (gated by slug retyping + the daemon-side `.baluard` marker check). A future revision may add a master-password-reprompt gated destructive arm back to the UI; until then the UI is destructive-action-free. The daemon route `vaults.detach` still supports both flags for the CLI caller.

### D21. Browser Extension: Paired-Companion Bridge (2026-06-XX; Phases 0+1 DONE)

**Decision: KeePassXC-Browser-style MV3 extensions talk to `baluard-daemon` via a new `baluard-nmh` native messaging host. The extension is a paired companion: it never unlocks, never holds the master password, never holds the vault session token. It rides the desktop's unlock state via a scoped bridge token.**

**Motivation.** Baluard has no server; Bitwarden/1Password's "extension talks to company API" model does not apply. The correct reference architecture is **KeePassXC-Browser**: extension -> native messaging host (stdio) -> local socket -> app. A 0600 Unix socket cannot be opened by a WebExtension (no raw-socket API in MV3); the only cross-browser escape hatch is `nativeMessaging` (Chrome `runtime.connectNative`/`sendNativeMessage`, Firefox identical).

**Architecture (see `docs/plan-browser-extension.md` for the full design):**
- **`baluard-nmh`**: standalone Rust binary. stdio-JSON <-> varint-protobuf. Stateless.
- **`core/bridge/`** (new module: `mod.rs`, `pairing.rs`, `token.rs`): pairing file format + atomic writes, bridge token mint/verify, action allowlist.
- **Scoped bridge token (`TokenKind::Bridge { pairing_id }`)** lives on a host-level bridge registry (`VaultHost::bridges`, `HashMap<pairing_id, BridgeTokenEntry>`). Vault-agnostic (extension follows the desktop's active pointer per D6-bis Phase 10). TTL parity with the per-vault session token (`SESSION_TOKEN_TTL_SECONDS`, 4h).
- **Action allowlist** (server-enforced in `verify_session_token` after token verification): `bridge.match`, `vault.get` (single, on fill/copy only), `vault.add`, `vault.update` (field-gated: password/username/notes/totp OK; `fido2_credentials` + `uris` REJECTED for bridge tokens), `cipher.totp_code`, `generator.history_add`, `generator.history_clear`, `sync.autosync_status`, `bridge.config`. **Excluded (rejected even with a valid bridge token):** `vault.list_full`, `vault.delete`, `vault.export`, `vault.change_password`, `device.revoke`, all `sync.*` mutations, all `provider.*`, `vault.attach_*`, `ssh.generate_key`, `passkey.*`, `vault.clone_*`, `folder.*`, `tag.*`, `vault.archive`/`unarchive`, `cipher.clone`, `settings.*`, `vault.trash.*`, `generator.history_list`, `favicon.get`.
- **Pairing flow:** approve-don't-type. Desktop user clicks "Add browser extension" -> `bridge.pair_start` (desktop-session-token-gated, one-shot pending-approval flag, short TTL). Extension calls `bridge.pair_complete` (held pending). Desktop UI shows "A Baluard extension wants to connect" with Approve/Deny. Approve consumes the flag, writes pairing file, returns pairing secret to the NMH. **No codes to transcribe, no brute-force surface, no vault nuke on ceremony abuse** (the prior 5-strike nuke was a DoS landmine for non-tech users).
- **Per-`pairing_id` rate cap on `bridge.match` + `vault.get`** via the existing `RateLimiter` (~10-20/min). Bounds a browser compromise to a handful of credentials, not the whole vault. Burst abuse escalates to `bridge.revoke`.
- **Fill policy:** popup-driven, per-fill user gesture. **No auto-fill on load.** Top-frame-only content script (`frameIds: [0]`). Fill-time origin re-check (content script re-verifies `location.origin` against the credential's stored URI before writing to the DOM, fails closed on mismatch). Closes the classic credential-theft vector of cross-origin login iframes + the popup-match/navigate-during-IPC race.
- **Pairing file ownership:** daemon is the sole writer (`<data_dir>/bridge/pairings.json`, atomic tmp+rename). Desktop mutates only via daemon routes. NMH reads its own entry read-only.
- **Lifecycle:** `connectNative` spawns a fresh NMH (browser SIGTERM/SIGKILL on disconnect). On spawn: NMH reads pairing entry via core, presents secret to daemon, daemon re-mints ephemeral bridge token. Token dies with the NMH; pairing file is durable and revocable.

**Why not a direct `vault.list_full` for the extension?** It returns the entire decrypted vault in one call (a de-facto export, and the real blast radius). Instead the extension sees metadata + one credential at a time.

**Why allowlist not deny-list?** Pre-1.0 WIP (per STATUS), expansion is a deliberate allowlist change + same-change call-site update. The friction is intentional: it forces a conscious security decision per route.

**Shared-vault write scope (2026-09-22, sharing plan S1b-5).** The allowlist is action-scoped; sharing added the session-scope dimension: `vault.add`/`vault.update` over a bridge token additionally require the ACTIVE vault's member row to carry cipher write scope (`VaultState::bridge_write_allowed`; legacy vaults without `meta/members` stay owner-equivalent; Viewer rows and unbound/tombstoned devices are refused where the extension can show the error — a viewer-accepted capture would otherwise wedge at push time, since cipher paths are editor-scope in the sharing policy table). Reads are unchanged: `bridge.match`/`vault.get`/`cipher.totp_code` stay open to viewers. The same wave shipped `ensure_access_accepted` (sharing plan §4.5) via the notices transport check: expired GitHub invitations (status `None`) are healed by a permission-matched re-invite and surfaced per member; GitLab/Codeberg `None` is reported only — their grants are immediate, so `None` may be a deliberate out-of-band removal and auto re-adding would resurrect it.

**Files:**
- `crates/baluard-core/src/bridge/{mod,pairing,token}.rs`: pairing + bridge token
- `crates/baluard-runtime/src/bridge.rs`: bridge routes + allowlist enforcement
- `crates/baluard-nmh/`: native messaging host binary
- `browser/{shared,chrome,firefox}/`: MV3 extension codebases (shared 95%, target wrappers)
- `desktop/src/components/BridgeTab.jsx`: paired-extension management UI

### D22. Conflict Resolution Panel (2026-07-02; UI and backend wired)

**Decision: Build the human-in-the-loop UI panel for destructive field-level merge outcomes now; defer the backend wiring (still falls back to `resolve_conflict_keep_local`) until Phase 1 of conflict resolution lands.**

**Motivation.** The auto-sync path today silently keep-locals on any file-level conflict, which can lose non-overlapping field edits from the remote device (F1: same item, non-overlapping fields: HIGH severity). A non-technical user has no way to see this happened. `merge_ciphers` exists and is tested (`sync/conflict.rs`), but is never wired into the cycle. The panel is the user surface for the destructive cases Phase 1 of conflict resolution will eventually surface; it can be built first because it consumes a structured `PendingConflict` queue that's purely frontend-derivable from the current `sync.autosync_status` payload for the mock case.

**Decision (UI side):**
- Top-floating modal-like panel with subtle slide-down animation (`ConflictResolutionPanel.jsx`).
- `ConflictResolutionContext.jsx` holds a queue of `PendingConflict` entries.
- Three options, ordered simplest-first: keep local, keep remote, keep both as separate entries. Per-entry granularity. Per-field picking is intentionally excluded (would require shipping secret values to the UI; rejected).
- The panel **may show**: entry name, cipher type, the list of conflicting field LABELS with a `sensitive` flag. The actual secret value NEVER crosses IPC.
- Lives in `desktop/src/components/ConflictResolutionPanel.jsx` with FocusTrap accessibility.

**Backend wired (Phase 2).** The cycle runs `merge_ciphers` per conflicting cipher via `run_sync_cycle_with_resolver(..., Pause)`; `Merged` writes the merged cipher + finalizes; `Conflict` pauses the cycle (`SyncCycleOutcome::NeedsDecision`), surfaces the conflict via the `sync.conflict` route, and resumes on `sync.conflict.resolve`. keep_local/keep_remote use raw blob selection (no re-encrypt); keep_both clones under a new uuid (mirrors `add_cipher`). Cross-epoch decrypt failure surfaces a `cross_epoch` flag. See D4 for the full mechanic and `docs/plan-conflict-resolution-panel.md` for the contract.

**Stuck-queue escape still open.** The panel is non-dismissable and keeps the conflict in the queue on resolver failure (retry-friendly). A permanently-failing `sync.conflict.resolve` IPC would lock the user out. Tracked as `TODO(stuck-queue)` in `decide()`; resolution options (max-retry fallback / manual escape hatch / hard-blocking product decision) deferred. Today the daemon route exists and works, so the risk is a degraded-network edge case, not a default path.

### D23. Event-Driven Sync Pull (2026-06-XX; DONE; refines D5-bis)

**Decision: Replace the periodic 3-minute heartbeat pull with event-driven triggers + a 30-minute idle fallback.**

**Motivation.** A predictable 3-min heartbeat is a measurable timing fingerprint (T14) and burns git round-trips while the desktop is idle. The events that actually need a fresh vault (unlock, window focus returning, after a local CRUD round-trip) can drive pulls directly.

**Decision:**
- **Pull immediately on vault unlock.** `VaultState::unlock` calls `pull_only` after `activate`.
- **Pull on window focus.** Desktop fires `sync.autosync_nudge_pull` on `Tauri WindowEvent::Focused(true)` (after a refocus); daemon applies a 10-min `FOCUS_PULL_MIN_GAP_SECS` guard so flicker collapses to one pull per 10 min.
- **The push cycle itself commits -> pulls -> pushes.** Concurrent remote edits land right after a local mutation; no separate event needed.
- **30-min idle fallback** (`PULL_INTERVAL_SECS`) catches the rare "left open on two machines" case. Deliberately quiet, with no predictable periodic heartbeat.
- **`cycle_lock` tokio Mutex** (C3 fix) guarantees only one sync cycle touches the on-disk repo at a time; losers bail cleanly.
- **Activation in `VaultState::unlock`** (immediate, not lazy); deactivated on lock.
- **No daemon-side decrypted cache**: `get_cipher` / `list_folders` read from disk every call, so after a pull the handle serves fresh data without a reload (root_key/SGK stay valid).

**Frontend:** desktop polls `sync.autosync_status` every 10s (`AutoSyncContext`); status pill in sidebar header (`AutoSyncIndicator`); non-blocking conflict banner (`ConflictBanner`). No Tauri event channel (request/response only).

**Why we still need the 30-min fallback:** with N unlocked vaults under the keep-unlocked model (D19-bis), an event-driven-only pull can miss the "device A made an edit, device B sat idle" case if device B's events never fire. The 30-min timer is the quiet backstop, not the primary sync path.

### D24. Sync Header Refactor + Favicons (2026-06-XX; DONE)

**Sync header:** replaced git jargon ("push", "pull", "remote", "branch") with a one-click sync UI. Sidebar header shows provider + repo link (`cc09c51`). `AutoSyncIndicator` status pill (idle / syncing / dirty / offline). Sync label gated with `<Show>` inside `<Transition>` to silence background pulls. Provider state scoped to active vault (`58016d4`); multi-vault provider state was previously leaking across switches.

**Favicons:** opt-in persisted website icons fetched at save time. New `favicon` field on cipher envelope (16KB cap, magic-byte check, default-off). `desktop/src/lib/cipherSchema.js` + `Avatar`/`CipherRow` chip treatment. Solves the "every login in the list looks the same" UX problem without bloating every entry with a base64 payload.

**App icons:** `just app-icons SOURCE OUT` builds 48/128 PNG variants from a source logo for all platforms (macOS/Windows/Linux/Android/iOS + tray monochrome + system tray). Replaces the previous hand-curated icon set with a deterministic pipeline; `desktop/src-tauri/icons/` regenerated on build.

### D25. Android Autofill & Quick-Settings Accessibility Architecture (2026-09-16; DONE)

See `docs/plan-android-autofill.md` and `docs/plan-android-accessibility-tile.md` for requirements and verification.

**Isolated service process**: `BaluardAutofillService` runs under `android:process=":autofill"` to separate credential evaluation from the main Compose UI.

**OOM-guard invariant**: unlock within the `:autofill` process exclusively uses `unlock_with_kek` using the biometric-gated KEK from Android Keystore. The Argon2id master-password KDF (64-256 MB) never runs in `:autofill`, preventing process termination by the Android low-memory killer.

**Rust-native URI matching**: `UriMatchStrategy::matches` is implemented directly in `baluard-core` across 6 strategies (BaseDomain via `public-suffix` eTLD+1, Host, StartsWith, Exact, RegularExpression, Never). Enforces scheme isolation (`androidapp://` never cross-matches `https://`) and treats trailing slashes as segment boundaries.

**Secret-absence batch query**: `VaultState::autofill_query` filters login ciphers and returns candidate metadata without passwords or "password" JSON keys. Plaintext credentials cross FFI only upon explicit dataset selection.

**Response-level authentication**: cold sessions render an "Unlock Baluard" placeholder; user interaction launches transparent `AutofillActivity` for a `BiometricPrompt` with `CryptoObject` ceremony before presenting matched datasets.

**Presentation modes**: supports both inline IME keyboard suggestions (`supportsInlineSuggestions`, default INLINE) and dropdown `RemoteViews`.

**Secure save handoff**: `onSaveRequest` generates a single-use token (`AutofillSaveToken`) in app sandbox storage before launching `MainActivity`, securing credential creation from intent spoofing across all supported Android API levels.

**Accessibility fill tile fallback**: `BaluardA11yTileService` + `BaluardAccessibilityService` provide an opt-in fill flow for browsers and apps lacking standard autofill support. Scrapes browser URL bars, presents an in-process picker (`AutofillA11yBridge`), injects credentials via `ACTION_SET_TEXT`, copies TOTP to clipboard, and bounds retries to 3 attempts per selection.

### D26. Domain Equivalence & App-to-Web Matching with Per-App Trust (2026-09-17; DONE)

See `docs/plan-android-autofill.md` and `docs/progress.md` for background and verification.

**Bundled domain equivalence groups**: `baluard-core` embeds Bitwarden equivalent domain groups (`crates/baluard-core/src/resources/global_equivalent_domains.json`). Under the `Domain` match strategy, entries for equivalent domains (for example, `google.com` and `youtube.com`) match bi-directionally without manual alias configuration.

**User-defined custom equivalent domains**: users can configure custom equivalence groups in mobile Settings. Groups persist in `meta/settings.enc` as `custom_equivalent_domains: Option<Vec<Vec<String>>>`. Each entry is sanitized to strip pasted schemes and paths, then folded to its registrable domain. Matching via `UriMatchStrategy::matches_with` evaluates custom groups alongside global groups.

**App-to-web matching with trust-on-first-use (Path B)**: native app fill targets (`androidapp://<package>`) cannot safely auto-match web credentials without risk from malicious package names. When `suggest_app_logins` is enabled, candidate domains are reversed from package labels (`com.mybank.app` -> `mybank.com`) and validated against public suffixes. Candidates surface under `app_suggestions` in `VaultState::autofill_query`.

**Explicit trust boundary and isolation**: the first time a native app encounters matching web credentials, `AutofillActivity` presents an explicit trust banner ("Trust this app for <domain>?"). User decisions are recorded via `MobileVault::autofill_app_trust` or `autofill_app_reject` into `trusted_app_packages` or `rejected_app_packages` in `settings.enc`. Trust is scoped strictly per `(package, domain)` pair: package lookalikes (`com.mybank.evil`) cannot inherit trust from legitimate packages.

---

### D27. One-Shot Item Packages (IS-3) + Contact Card v2 (2026-09-22; S2-1 DONE)

See `docs/plan-sharing.md` §4.6 (IS-3) and the S2 tracking row for the wave context.

**What shipped**: a cipher exports as a self-contained encrypted file (`crates/baluard-core/src/vault/packages.rs`), HPKE-wrapped to a contact's identity X25519 wrap pubkey, delivered out-of-band (chat/email/USB). The recipient opens it and gets a FRESH entry (new id, their vault's item keys). Inert one-shot copy: no live link, no revocation, cannot be un-shared; Level 1 (Channel) trust suffices because packages wrap no live keys. Daemon routes `packages.export`/`packages.import` (token-gated; import is in COVER_MUTATION_ACTIONS).

**Card v2**: the signed contact card now carries the identity X25519 wrap pubkey INSIDE the signed payload (`baluard-contact-v2` domain), so the Level 2 verification-code check covers the wrap key too — a swapped wrap key breaks the card signature. Address-book rows stored before v2 load with an empty key (serde default); package export refuses them with re-share guidance instead of failing cryptically.

**Sender attribution (review round, blocker)**: a card's self-signature only proves the card is self-consistent — anyone can copy a public card verbatim — and HPKE Base mode authenticates neither party. Without more, anyone with a target's public card could seal a malicious item that opens as "from" any identity. Fix: the sender's identity Ed25519 key signs `recipient_wrap_pub || sent_at || item bytes` (`PackagePayload::signing_payload`), verified at open; re-wrapping a package to a different recipient fails the signature.

**Metadata hygiene**: the envelope carries key material only — item, sender card, and timestamp all live inside the `secret_file`-sealed payload (AAD purpose-bound), so an intercepted file leaks nothing. Caps: 2 MB payload (matches the XL cipher tier so a sealed package always survives base64+JSON expansion under the 4 MB daemon socket frame limit; the seal/open size limits were reconciled in review), pre-decode length bound on the route.

**Import stripping**: the recipient's entry drops attachments (bytes never travel), password history, folder assignment, the archived flag, and the sender's creation date — stripped on BOTH sides (export + import) so a hand-built payload cannot resurrect them.

**Boundaries**: no expiry (expiry-in-AAD belongs to the IS-6 guest flavor), no CLI/UI yet (share sheet + "open a shared file" = §4.8 wave), tested against a scripted second vault rather than live transport.

---

### D28. Field-Scoped Reveals, Two Flavors (IS-6) (2026-09-22; S2-2 DONE)

See `docs/plan-sharing.md` §4.6 (IS-6) and the S2 tracking row for the wave context.

**What shipped**: a Login's fields (url, username, password; TOTP opt-in) export as a self-contained expiring file (`crates/baluard-core/src/vault/reveals.rs`) in two flavors. Contact-key (Level 1): HPKE-wrapped to a contact card's wrap pubkey, sender-attributed. Passphrase-guest (Level 0): Argon2id over an app-generated 7-word passphrase, no identity involved, opened by the Baluard app without a vault ("Open a shared file" on first-run). Reveals are VIEW-ONLY: unlike IS-3 packages, opening never mutates the recipient's vault. Daemon routes `reveals.export_contact`/`reveals.export_guest`/`reveals.open_contact` (token-gated) plus `reveals.open_guest` (host-level, tokenless, pure compute). The TOTP seed never crosses IPC: open returns the current code and its validity window.

**Expiry binding**: the envelope carries `expires_at` in plaintext feeding the seal's AAD marker (`item-reveal-payload-v1/exp/<unix>`), so an edited date breaks the GCM tag and the sealed copy must equal it. Expired files refuse in plain language; the recipient asks for a fresh reveal.

**Sender attribution**: the identity key signs `recipient_wrap_pub ‖ expires_at ‖ created_at ‖ item_name ‖ fields` — everything a captured signature could otherwise re-seal (a card's self-signature is copyable and HPKE Base mode authenticates neither party; the label and freshness timestamp are signed so a stale capture cannot masquerade as a new send under a new name).

**Untrusted KDF params (review round, blocker)**: the guest envelope's Argon2id block is attacker-controlled; without a clamp a hostile file could set memory_kib to terabytes and abort the daemon on allocation the moment the victim types the passphrase. The open path clamps params to generous ceilings (128 MiB / 6 / 4 vs the DesktopStd seal path's 64 MiB / 3 / 2), so legit files verify and hostile ones collapse to a normal-cost derivation that fails the GCM tag.

**Passphrase pool caveat**: the generator's passphrase pool is bilingual (EFF English + Spanish BIP-39, 16,380 words, ~98 bits at 7 words). Voice delivery of a mixed-language passphrase is a known wrinkle deferred to the UI wave (the app also shows the words on screen; a language-scoped draw needs a generator option).

**Boundaries**: no UI/CLI yet (share sheet + "Open a shared file" = §4.8 wave); error strings inside core stay technical until that wave maps them to plain copy (packages parity); route-level tests for the three gated actions remain harness-blocked (no session-token minting for vault routes; the P6 pin covers their gating).

---

### D29. Pair Space (IS-5) (2026-09-22; S2-3 DONE)

See `docs/plan-sharing.md` §4.6 (IS-5) and the S2 tracking row for the wave context.

**What shipped**: the S1a membership machinery now covers the two-person Space shape. A Space is a vault whose slug is forced to `baluard-space-<name>` (`space_slug`, idempotent) and whose plaintext `meta/settings-pub.json` carries `"space": true` (pre-unlock readable, rename-safe; absent file/field = personal). `vaults.list` rows expose the flag pre-unlock alongside theme/lang. Daemon route `space.create` (host-level, mirrors `vault.create`: inherits unlock, registry insert, session token) rewrites the payload slug before delegation and writes the shape flag after creation.

**Pair policy**: `space::pair_gate` runs at BOTH invite minting (`create_invite`) and join approval (`approve_join`, before any mutation so a refusal leaves the invite intact for retry). It refuses Owner/Admin roles on a space (a pair shares as Editor or Viewer) and a second joiner once two bound live members exist. The cap counts rows with at least one `.json` device binding and no tombstone — `removed` and `reset` rows are both skipped (a reset predecessor keeps its bindings on disk and must not occupy the slot while the successor is pending), and unbound rows (pending joiners, reset successors) are excluded so a reset approval never self-blocks.

**Review round (agy, 9 findings: 6 accepted + 2 blockers, 1 declined)**: (1) the member counter originally ignored the `reset` tombstone, so a reset predecessor's persisted bindings made the space believe it was full and permanently wedged member reset — tombstones of both kinds are now skipped (blocker). (2) `save_settings`/`save_locale` rebuilt `settings-pub.json` wholesale, silently stripping `space: true` and deactivating the pair gates on the next settings save — both writers now merge with the existing JSON and preserve unknown keys (blocker). (3) `transfer_ownership` demoted the old owner to Admin unconditionally; on a pair space a later reset of that admin would mint an invite the gate refuses, wedging recovery — the demotion lands as Editor on space vaults. (5, partial) `handle_space_create` now zeroizes the master-password-bearing payload on every path (early returns included) before handing to `vault.create`. (6) `space.create` joined the desktop Tauri IPC allowlist. (7) the device-binding count requires a `.json` entry (`.DS_Store`-proof, `list_members` parity). (8) `space_slug("space")` no longer double-suffixes. Declined: failing the `space.create` response when the flag write fails — the flag is a policy guardrail, not a confidentiality control; the created vault is already unlocked with a token issued (registry-add warn precedent), and failing closed would strand the client mid-wizard with a live vault to clean up.

**Boundaries**: CLI/UI deferred (the Family-shape silent share sheet = §4.8 wave + P1); pre-P1 a Space still has its own master password; S3 owns space.adopt/migrate for churn.

---

### D30. Per-Recipient Outboxes with Live Mirror (IS-4b, row C) (2026-09-22; S2-4 DONE)

See `docs/plan-sharing.md` §4.6 (row C) and the S2 tracking row for the wave context.

**What shipped**: an outbox is a small standalone git repo, ONE per recipient (`crates/baluard-core/src/vault/outbox.rs`). Layout: `outbox.json` (plaintext marker: outbox id, owner vault id, owner signed contact card), `share/keywrap.json` (HPKE wrap of the content key to the recipient's identity wrap pubkey + Ed25519 signature binding recipient pubkey + outbox id), `entries/<cipher_id>.enc` (sealed blobs, AAD purpose `outbox-entry-v1/<outbox_id>/<cipher_id>`). Entries carry the sender card + item + a signature binding outbox id, entry id, timestamp, and item bytes. The content key is a fresh random AES-256-GCM key per outbox — no vault key ever wraps into it (Level 1 channel trust). Owner registry `meta/outbox-owner.enc` and recipient links `meta/outbox-links.enc` are sealed under the new RootKey-derived `derive_outbox_key` and are re-encrypted in BOTH `rotate_root_key` and `revoke_device_and_rekey`.

**Live mirror**: `publish_entry` seals from the CURRENT cipher state; a SHA-256 digest over the sealed doc makes re-publish idempotent (unchanged → no write, no commit). The daemon's post-CRUD `COVER_MUTATION` hook runs `outbox_resync()` best-effort between two autosync nudges (the registry file is git-tracked; the second nudge guarantees a cycle commits it). Trashed and purged sources unpublish on the next resync — a purged cipher's `CipherNotFound` is handled, not propagated (a purge would otherwise wedge every later resync). Explicit routes `outbox.publish`/`unpublish`/`revoke`/`resync` are not needed — resync rides the hook; the nine routes are publish/unpublish/revoke/list/link/links/forget/read/entries, all token-gated, the registry-writing five in COVER_MUTATION_ACTIONS.

**Recipient side**: `outbox.link` verifies the marker card, unwraps the content key with the recipient's own identity, and stores the link with the owner's signing pubkey AS SEEN AT LINK TIME. Every open re-checks marker id + owner pubkey against the link — a repo writer who swaps in a complete impostor set (own card, own key, keywrap re-addressed to the victim: HPKE Base wraps need no secret) cannot hijack an existing link. Entry attribution must equal the marker owner's identity (a repo writer cannot inject entries labeled as someone else). Reads are view-only; nothing is imported.

**Review round (agy, 10 findings: 7 accepted incl. 3 blockers, 2 declined)**: (1) registry writes ran under the runtime READ guard — lost-update race; all mutating wrappers now take the write guard and the handle methods are `&mut self`. (2) `git2::Repository::discover` walks parents: an outbox folder inside the vault would commit mirror files into the VAULT repo — `open` + init fallback. (3) a purged source aborted `outbox_resync_all` permanently — CipherNotFound unpublishes now. Plus: `update_all` stages deletions into the outbox git tree (unpublish/revoke reached clones), link/owner-attribution binding (above), content keys stripped from the IPC surface (`outbox.list`/`links`/`link` responses), recipient-keyed reuse on the STABLE signing pubkey with wrap-rotation re-wrapping, and canonicalized registry paths. Declined: forge-seat strike on revoke (this wave grants no seats — the future transport wiring pairs grant+strike) and Zeroizing hex key fields (the key rests inside a sealed blob; the decode path already Zeroizes).

**Review round 2 (agy, on the shipped commit; 13 findings: 10 accepted, 3 declined)**: blocker — the unchanged-skip digest was computed over the payload INCLUDING the live `updated_at` clock, so every resync rewrote + committed + pushed every entry in every outbox (the digest is now a canonical mirror doc: outbox id + entry id + item bytes, no clock). Also accepted: the keywrap signature now binds sha256(ephemeral|ciphertext|tag) so a repo writer cannot swap the ciphertext under the still-valid signature; unpublishing the last entry keeps the registry record (the on-disk marker still carries the outbox id — dropping the record wedged re-publishing to that folder); embedded passkey material is stripped from mirrored items (`strip_fido2`: view-only mirrors never carry passkey keys); the resync loop continues past per-outbox publish failures; entry listing skips unreadable files; `open_entry` size-bounds the file BEFORE reading it; `revoke_outbox` must find an owned record first (a typo'd path can never strip an unrelated folder's `entries/`); publishing refuses outbox paths at or inside the vault (either direction commits the other's files — the git-attachment fix hardened into an invariant); `outbox.resync` route exposed and pinned. Declined: marker re-read per entry in listing (trivial N), git error-string detail (repo-tolerated format strings), typed response DTOs vs the dynamic key-strip (existing pattern). Durable rule: a digest used as a change-detection key must be computed over canonical content, never over a document containing a live clock or nonce.

**Boundaries**: local-folder transport only this wave — origin push is best-effort and provider seat grant/strike for outboxes is the P8c-facade wave; UI share sheet = §4.8 wave; revoke keeps old-key copies readable (the plan's eventual-revocation boundary, stated at share time).

---

### D31. Merged Multi-Vault Item List, `vaults.list_full_all` (S2-5) (2026-09-22; S2 DONE)

See `docs/plan-sharing.md` §4.6 (line 148) and the S2 tracking row.

**What shipped**: one daemon call returns every registered vault as a row (slug, display name, space flag, active flag, presence) — unlocked vaults carry their full `vault.list_full` envelope (active row) or just the cipher list (sibling rows; folders/trash/tags belong to their own vault's view and skipping them keeps the merged frame under the response cap), locked/closed vaults carry metadata only. Rows sort by slug (the registry is a HashMap). A vault that locks mid-scan degrades to a metadata row with corrected `presence`, never failing the merge. `VaultState::full_envelope` is the shared payload builder (list_all wraps it to a string).

**Trust model**: the route is host-level but NOT pre-token — it verifies the caller's session token against the ACTIVE vault's state. That is the same trust that already grants `vault.list_full` for the active vault; sibling vaults belong to the same user. Sibling and empty tokens fail the constant-time compare; bridge pairing tokens can never verify against a vault session, so the extension cannot pull the merge — the D21 no-export boundary holds (the route is absent from BRIDGE_ALLOWED_ACTIONS at NMH, daemon, and token-verification layers).

**Desktop**: `VaultContext` pulls the merge alongside every cipher refresh and tags foreign ciphers with `_vault {slug, name, space}`; the merged list shows foreign rows (with a vault-name chip) in every category except trash/archive, folder/tag/search filters apply naturally (foreign folder/tag ids never match the active vault's), and foreign entries open a READ-ONLY detail: edit/archive/delete/passkey-delete gated off, TOTP and attachment downloads slug-routed to the source vault (the desktop's per-slug token cache carries sibling tokens minted at their unlock), and a read-only notice points the user at the source vault. Staleness bound: a sibling vault can lock (idle timer, blur policy, close) without the merge context hearing about it, so foreign rows re-pull on focus regain and a 30s heartbeat — the daemon stays authoritative, the same design as the switcher's presence refresh. Sidebar All-items badge and row-highlight now count/compare across vaults (composite slug:id key).

**Review round (agy, 10 findings: 8 accepted, 2 declined)**: blocker — stale foreign secrets stayed rendered after a sibling locked/closed (the merge signal had no staleness bound) → the focus/heartbeat re-pull above; major — passkey delete not gated for foreign entries; TOTP and attachment fetches targeted the active vault (now slug-routed); fire-and-forget refresh race → awaited; payload-size blowout → sibling rows trimmed to ciphers; mid-scan lock left `presence: unlocked` with no payload → corrected to `locked`; nondeterministic row order → sorted; badge-count mismatch → summed; row-highlight UUID collision → composite key. Declined: none beyond wording.

**Boundaries**: mobile merged host is the S4 line item; foreign entries are view-only (mutations stay slug-routed to the active vault — no cross-vault write surface exists); locked vaults surface as metadata rows, unlock stays a switcher action.

---

### D32. Collections Core (S3-1) (2026-09-22; S3 OPEN)

See `docs/plan-sharing.md` §4.2/§4.6 (S3 row) and the S3 tracking row.

**What shipped**: the org-granularity data + key layer. `meta/collections/<id>.json` carries plaintext grants (`{member_id, access: read|write, expires_at?}` — plan rule: plaintext is UUIDs + names + trust) plus the collection's display name sealed under a random per-collection content key (CK), so a non-grantee sees an opaque id while grantees see real names. The CK is wrapped under a key HKDF-derived from the Space Group Key and bound to its epoch (plan: "collection key — random; wrapped under SGK"), which is why rotation re-seals: both `rotate_root_key` and `revoke_device_and_rekey` decrypt every collection's CK with the outgoing SGK pre-swap and re-seal post-swap (the outbox-registry pattern). Six admin-gated handle methods + runtime wrappers + daemon routes (`collections.create/list/rename/delete/grant/revoke`; the mutating five in COVER_MUTATION_ACTIONS; desktop allowlist updated). `collections_list` returns grant rows (member, access, expiry) so an admin can see who has what before revoking.

**Trust model**: the admin gate (`assert_can_manage_members`) covers all five mutating ops; list is open to any unlocked member (read-only). The sync policy table already requires Admin for `meta/collections/**`, so commit verification backs the route gate. Grants validate the target is a live member (no `removed`/`reset` tombstone). Malformed files skip inert in the directory walker, and the filename stem must match the embedded id so a misnamed file cannot wedge rotation.

**Review round (agy, 7 findings, all accepted)**: grants were write-only through IPC (list carried only a count); decrypted CK vectors were not zeroized; `format` unvalidated; filename/id mismatch could wedge rotation; editor-refusal coverage existed only for create; a stale doc comment; the rewrap path skipped the size cap. Refutations confirmed the gate coverage on all mutating ops, the epoch-bound wrap derivation, AAD transplant rejection, rotation wiring in both paths, and grant validation.

**Boundaries**: entries stay at personal paths — collection-scoped cipher paths and the policy-table binding are the P5 remainder (the enforcement slice); per-member identity wraps (`meta/collections/<c>/<m>.wrap`) and Team-shape key separation (non-admins never hold the Root Key) arrive with the P1 Space parts; expiry enforcement (expiry-that-rotates + notices surfacing), role templates, delegated manage, JIT request-access, and `space.adopt` are their own S3 slices; no UI yet (the §4.8 sharing-surfaces wave).

---

### D33. Collection-Scoped Cipher Paths + Policy Enforcement (P5 remainder, S3-2) (2026-09-23; S3 in progress)

See `docs/plan-sharing.md` P5 row and §4.4's `ciphers/<collection_id>/**` row.

**What shipped**: a collection's cipher directory is a salted hash (`sha256(dir_salt || id)`, 16 truncated bytes, hex) minted at collection creation and stored as `dir_salt` on the collection file, so the git host sees neither the collection id nor cross-vault links, and every device derives the same opaque dir. The on-disk path IS the collection membership: `cipher.set_collection` (new token-gated route; write-guarded state wrapper) renames the entry's file between the personal flat path and `ciphers/<dir>/<uuid>.enc`, refusing unknown collections and trash. Reads, updates, archive/unarchive, delete-to-trash, metadata scans, and the index rebuild all resolve through a shared probe (flat first, then collection dirs) and `list_cipher_ids` recurses one level into collection dirs with UUID dedup (a grantee can plant a same-UUID copy; the index lists it once).

**Enforcement**: the policy walker builds a `CollectionScope` from the verified commit's OWN tree — the dir->id map plus the collection ids the signer's member holds write grants on (a non-admin cannot forge a definition: `meta/collections/**` is Admin-only, so a referenced dir must be one an admin already defined in that tree). `authorize_scoped` denies any `ciphers/<dir>/**` path whose dir is unknown or ungranted BEFORE the static table, whose `ciphers/**` Editor row still gates the role floor (a Viewer with a grant still cannot write). Legacy vaults carry an empty scope and deny any unexpected 3-segment cipher path.

**Local gate mirrors the policy (review F1, Blocker)**: `assign_cipher_to_collection` requires the session device's member to hold write scope on BOTH the source and target collection (Owner/Admin bypass; legacy vaults bypass); a commit no peer would authorize must not exist locally, because the first policy-denied commit wedges every peer's pull permanently.

**Review round (Claude, first-rotation): 5 accepted, 2 declined**. Accepted: the local write-grant gate (F1 above — a non-grantee Editor could have minted a commit that wedges all peers' pulls); `CollectionScope` now owns its Vecs instead of leaking `'static` slices per verified commit (F2); grant-less directory duplicates deduped in `list_cipher_ids` (F4); the non-grantee refusal test (F6); `load_dir_map` now applies the same filename-stem pin as `list_collections` (F7). Declined: sticky grant revocation (F3) — the walker reads grants from the commit's own tree, so a stale clone can replay a since-revoked grant until its parent ancestry includes the revocation commit; this matches the plan's accepted "revocation is only eventual" boundary (sticky enforcement exists only for member REMOVAL, where removal must fail closed); lib.rs indentation (fmt already green).

**Boundaries**: scope is per-commit-tree, so grant revocation converges only when the revocation commit is in the signer's ancestry (F3 decline); restore lands at the personal flat path (membership re-assigned explicitly); canary ciphers stay flat; attachments stay under `entries/`; `staged path sets` (the other P5 remainder) is deferred; no UI for assignment yet (§4.8 wave); expiry-that-rotates will need grant rows re-checked at verification time.

---

### D34. Grant Expiry-that-Rotates (S3-3) (2026-09-23; S3 in progress)

See plan-sharing line 153 and the `grant_expiry` preset row (§6.5).

**What shipped**: `CollectionGrant.expires_at` is now enforced. The admin client executes it — the sweep drops grants whose `expires_at` has passed and rotates the affected collections' content keys in the SAME atomic save (one write per collection: grant drop + fresh CK + re-sealed name), so a departing grantee's derived item keys stop matching anything minted later. Two execution surfaces: at unlock (the runtime post-pull tail) and on demand (`collections.sweep` route). Pending and expired grants surface member-visible on the notices screen: `grant_expiring` (within 7 days) and `grant_expired` (expired but present — the sweep has not landed yet) in en/es/pt.

**Enforcement placement (settled)**: commit verification stays clock-FREE — an expired-between-authoring-and-verify grant would refuse commits on every peer and wedge the vault (the first-denied-commit rule). Expiry enforcement is admin-side; peers converge on pull, which is the plan's accepted eventual-revocation boundary. The LOCAL write gate (`assign_cipher_to_collection`) DOES check expiry — a locally expired grant must not mint new moves. `expires_at = 0` is the IPC convention for "no expiry" and never expires.

**Review round (agy, second rotation on this codebase): 5 accepted, 1 declined**. Blocker: the sweep originally ran inside core unlock BEFORE the unlock pull — pull's force-checkout would have discarded the uncommitted sweep files, and they would never have been committed or pushed (unlock is not a cover-mutation). The sweep moved to the runtime post-pull tail: pull first, then sweep (admin-gated), then an autosync nudge so the rotation commits and pushes on the normal cycle; vaults without a remote sweep inline after the handle guard drops. Also accepted: the `expires_at=0` semantics alignment, the legacy-vault admin-equivalence bypass in the sweep gate (matching the other collection mutators), the on-demand route (token-gated, COVER_MUTATION_ACTIONS, desktop allowlist), and the expired-notice copy ("will be removed on the next sync" — no unlock prompt, which non-admins cannot act on anyway). Declined: none. The review also caught a self-deadlock the fix introduced (the inline no-remote sweep ran while unlock still held the handle guard — the guard now drops before the unlock tail).

**Boundaries**: expired-but-unenforced grants keep authorizing at the git layer until the admin's sweep lands (surfaced as `grant_expired`); a grantee can replant content with pre-expiry knowledge until rotation converges (eventual); no per-member wraps yet (P1 Space parts), so CK rotation is future-proofing for the Team shape; the sweep is unlock-triggered and route-triggered — no background timer; clock-clamp note 11 holds (the sweep clock is the admin's local clock only for its own writes).

---

### D35. Per-Member Identity Wraps (P1 Space Parts groundwork) (2026-09-23; S3 in progress)

See plan-sharing line 111 (Team shape: non-admins hold only their collection wraps, never K).

**What shipped**: `MemberFile.identity_wrap_pubkey` (hex X25519, serde default) recorded at approval from the intro card's v2 signed payload (card signature verified, wrap key hex+length validated; a malformed key would brick every later re-key). Collections mint per-member CK wraps at `meta/collections/<c>/<m>.wrap` — the collection key HPKE-wrapped to the member's wrap pubkey with the context binding `collection-grant-v1/<collection_id>/<member_id>`, so a wrap transplanted to another collection or member name fails the AEAD tag (the outbox-entry AAD discipline). Minted at grant, removed at revoke, killed with the collection, re-wrapped under the new CK by every rotation path (Root Key rotation, removal rekey, S3-3 expiry sweep), and self-healed across identity rotation by the member's own client (unwrap all with the old secret first, then write — two-phase, and it runs BEFORE any identity byte is written so an abort leaves zero state change). The owner's genesis row carries their wrap pubkey.

**Wraps are additive groundwork**: every member still holds SGK, so consumption via per-member wraps lands with the later Team-shape flip (non-admins stop receiving SGK; the wraps become their only path to granted collections). This slice builds and maintains the wrap set so that flip is a unlock-path change only.

**Wrap survival is grant-gated**: `rewrap_grant_wraps` re-writes a wrap only when the member id is in the collection's LIVE grant list (not expired), the member row is live (no removed/reset tombstone), and the row carries a wrap pubkey; anything else loses its wrap file. Without this, a revoked-before-rotation member (whose tombstone kept a wrap identity) would be handed the NEW collection key by the very rotation meant to lock them out. Both tombstone writers (reset, remove) now also clear `identity_wrap_pubkey`.

**Mint gate**: `upsert_grant` refuses past-dated `expires_at` (a grant expires by time passing, not by being minted expired) and keeps save-before-wrap ordering — a failed wrap write must fail toward NO access, never toward key-without-grant.

**Review round (agy): 8 accepted, 1 partially accepted**. Blockers: the tombstoned-member wrap surviving rotation (above) and the disk-driven rewrap ignoring the grants list. Majors: the static HPKE context (cross-collection transplant), the identity-rotation partial-failure window (reordered + two-phase), and the malformed-wrap-pubkey rotation brick. Minors: owner genesis wrap pubkey, the no-old-identity rotation refusal, expired-at-mint refusal, removal errors inspected (NotFound tolerated). Partially accepted: save/wrap ordering in `upsert_grant` — the suggested wrap-first order was rejected because a failed save would then leave a working wrap for an ungranted state.

**Boundaries**: expired-but-unrotated grants keep their wraps until a rotation path runs (the eventual-revocation boundary, unchanged); no background timer maintains wraps; the Team-shape SGK flip is the next P1 slice.

### D36. Role Templates (S3-4) (2026-09-24; S3 in progress)

An admin-defined reusable invite preset: `RoleTemplate {id, name, role, grants, created_at}` where each grant is `{collection_id, access, expires_in_days}`. Storage is one sealed blob at `meta/templates.enc` under a root-key HKDF (`baluard-role-templates-v1`, purpose `role-templates-v1`), riding the meta/** Admin git-policy row like collections. Caps: 64 templates / 100 name chars / 64 grants; a missing store loads as empty so legacy vaults work.

**The invite is the contract**: inviting with a template embeds a SNAPSHOT (`EmbeddedTemplate`) in `PendingInviteFile` at mint time, with a fail-closed role cross-check (the picked role must equal the template's). Approval applies the embedded grants — never re-reading templates.enc — so deleting or editing a template after minting changes nothing pending. Grant application is best-effort fail-toward-less-access (missing collections skipped with a warning; each applied grant mints the D35 per-member wrap immediately). Expiry is converted to absolute `expires_at` at APPROVAL time (now + days). Rotation re-seals the store in both rekey paths (read-old-then-resave).

**Fail-closed parsing everywhere** (review round): a present-but-mistyped value refuses — negative or non-integer `expires_in_days` (would have silently become permanent access), non-string `template_id` (would have silently minted a template-less invite), non-array `grants`. `templates.list` is open to unlocked members; create/delete are admin-gated; list is correctly NOT in COVER_MUTATION_ACTIONS.

**Viewer+write is unmintable** (review Blocker-class): the git policy floor for cipher commits is Editor, so a Viewer holding a write grant passes locally and wedges their sync at peer verification (the wave-10 wedge class). `validate_template` refuses a Viewer template with write grants, and `upsert_grant` refuses a write grant to a Viewer-role member at the root — covering the template path AND the plain grant route. Template names also reject line breaks (the newline discipline shared with contacts/members).

**Approval-side grant cap**: a git-synced invite file carrying more than MAX_GRANTS_PER_TEMPLATE entries is tampering; the approval peek phase refuses BEFORE any mutation, so a hostile invite cannot run unbounded encrypt+wrap work under the vault lock.

**Boundaries**: templates are advisory presets, not policy — live access is still governed by grants and the git policy table; no template versioning or audit trail (the activity log records the join, not the template); UI surface rides the later §4.8 sharing-surfaces wave.

### D37. Delegated Manage (S3-5) (2026-09-24; S3 in progress)

A third access level on collections: `CollectionAccess::Manage`. A member holding a live manage grant administers that ONE collection — grants, revokes, rename — without admin rights. Collection create and delete stay admin-only (deletion kills the grant list). Manage is mintable to Editor+ only (Viewer+manage refused at `upsert_grant` and `validate_template`, same wedge class as Viewer+write), and manage implies write for cipher moves in the managed collection (scope builder + local move gate both accept it).

**The authority chain is parent-tree scoped** (the wave-10 wedge invariant again): the sync policy's `meta/collections/**` Admin row gains a scoped relaxation — a signer whose manage grants appear in the PARENT tree's def files may write `meta/collections/<id>.json` and `meta/collections/<id>/**` (the Editor role floor still applies). Authority reads from the parent, never the commit's own tree, so a member cannot self-grant manage in the commit being verified. The local `assert_can_manage_collection` gate mirrors the same rule (admin/legacy bypass, else live non-expired manage grant on the exact target), so every locally minted commit stays locally authorizable and can never wedge a peer's pull.

**Review round (agy): 6 accepted, 1 declined**. Blocker: the scope builder trusted a def file's inner `id` without binding it to the filename — a manager of collection A could rebrand their def to collection B and inherit B's scope in the next commit's parent walk (fixed with the load_dir_map/list_collections stem==id pin in both tree walks). Majors: def DELETION was delegable (the policy now takes an is_deletion flag; def removal stays admin-only, wrap removal stays within manage); a demoted Viewer with a stale manage/write grant passed the local gates and wedged sync (both local gates now refuse Viewers up front — role changes never strip grants); the merge conflict-strip loop authorized with the unscoped policy (now uses the same parent-tree scope); and a PRE-EXISTING wave-12 wedge surfaced — a plain grantee rotating their identity rewrites their own `meta/collections/<c>/<member>.wrap`, which the Admin row refused on every peer. Fixed with an own-wrap structural rule at any role (like the members/devices self-rule). Shapes are exact: a def is 3 segments ending .json, a wrap is 4 ending .wrap — nothing hides under loose subpaths. Declined: the local gate decrypting all collection names via list_collections (256-collection cap bounds it; a damaged name fails closed).

**Boundaries**: verification stays clock-free — an expired-but-unrotated manage grant keeps sync authority until the S3-3 sweep lands (the accepted eventual-revocation boundary) while the local gate checks expiry; delegated managers cannot create/delete collections or touch members; UI for managers rides the §4.8 sharing-surfaces wave.

### D38. Request-Access JIT + Collection Catalog (S3-6) (2026-09-24; S3 in progress)

A member asks for collection access instead of waiting for an admin to notice them. The ask lives at `meta/members/<m>/requests/<id>.json` — the members own-subtree Any policy row makes writing it self-service at any role, and another member's subtree stays Admin-only, so approval/denial (which deletes the file) is an admin commit by construction. `collection_id` and `access` ride as plaintext (plan rule: plaintext is UUIDs + names + trust); the free-text note is HPKE-sealed to the approver set (live Owner/Admin rows carrying identity wrap pubkeys) via one random payload key wrapped per approver, with the plaintext fields bound INSIDE the sealed payload so a tampered file decrypts to a mismatch and counts inert instead of granting what the plaintext claims. The optional `meta/collections/catalog.json` is the plan's explicit opt-in: publishing it exposes display names to requesters (whose alternative view is an opaque id); it lives inside `meta/collections/` so the Admin policy row gates it and the UUID-stem walkers skip it inert.

**Approval re-derives from the seal, never the client**: the admin's approve call decrypts the ask with their own identity, and everything granted (collection, requester, requested access) comes from that sealed row; only `access` (read/write) and `expires_at` are admin overrides. `upsert_grant` rules apply unchanged (tombstoned targets, viewer+write unmintable, expiry sanity), and the approval consumes the request file in the same commit. Denial consumes without granting; the grant list is the member-visible outcome surface (clock-free verification: decisions land via sync). New activity events `access-granted`/`access-denied` land on the admin's local log.

**Review round (agy, high): 8 accepted incl. 2 blockers**. Blocker 1 — a hostile member can seal to the approvers' PUBLIC wrap keys, so a crafted `access: manage` ask (consistent plaintext + seal) would have minted delegated-admin powers at approval; manage is now refused at submit, at decrypt, and at approve, and the route parser never produces it (manage grants go through `collections.grant`). Blocker 2 — the seals did not bind the requester, so a pending file copied into another member's requests directory (self-service subtree) redirected the grant; the HPKE context and sealed payload now pin the requester, and a transplanted file counts inert. Also accepted: deterministic inbox walk with a per-member cap (submit-side caps are not verification-enforceable, so a crafted flood must not starve the inbox), grant-aware submit (an ask covered by a live grant refuses, expired grants lapse, upgrade asks are legitimate, viewer+write is unmintable at ask time too), the desktop D21 allowlist additions, Zeroizing on the decrypted payload key, and read-side validation (sealed note re-validated; catalog rows capped/validated/filtered against deleted collections). Declined: catalog names forced from decrypted collection names — curation is the point of an explicit catalog.

**Boundaries**: approvals are admin-only by construction (a delegated manager consuming another member's request file would wedge per the first-denied-commit rule); a pending ask sealed only to a since-rotated approver counts inert (multi-admin vaults keep surviving seals; the asker can withdraw and re-ask); no notices-surface integration yet (the inbox route is the admin surface; the badge rides the §4.8 wave); CLI/UI surfaces are later waves.

### D39. Space Meta Key Groundwork (S3-7a) (2026-09-24; S3 in progress)

The Team-shape promise is that a Viewer or single-collection Editor never receives the Root Key. Today every member's device keywrap carries it, so grants are cosmetic at the crypto layer. Closing that gap needs one missing primitive: a member-readable meta key that is NOT the Root Key. S3-7a ships it additively. The Space Meta Key (SMK) is a random 32-byte key with two distribution paths: a sealed admin store (`meta/space.enc`, Root-Key HKDF) and per-member identity wraps (`meta/members/<m>/space.wrap`, HPKE context-bound to the member like the collection wraps). Nothing derives from the SMK yet: no unlock path changes, and an untouched vault behaves identically until an admin runs `space.prepare`. The S3-7b flip (next wave) re-homes the member-visible meta derivations to the SMK, stops putting the Root Key in non-admin keywraps, and gates the flip on `space.status` readiness (every live member wrapped, none missing a wrap pubkey).

The design center is convergence over wedging. `prepare` is idempotent on a healthy store, and re-mints on a missing OR damaged one: a crash between a rotation commit and its store re-seal orphans the store, and re-running prepare heals (fresh SMK + full re-wrap in one pass). For the same reason, rotation treats a pre-swap store-open failure as "no SMK rides this rotation" and skips the re-seal instead of propagating: a hostile or torn meta file must never block the offboarding rotation. The review challenged this as a P4 violation until the asymmetry is drawn out: post-swap RE-SEAL failures propagate (a healthy store must not be silently dropped mid-rotation), pre-swap OPEN failures skip (the store is already dead or absent, and prepare converges either way).

The review also caught a pre-existing blocker, not from this slice: `rotate_identity`'s refusal (identity lost from memory while wraps exist) fired after the sealed seed, escrow, and member-unlock material had already been overwritten with the new identity. The refusal "protecting" the wraps still destroyed the only copy of the old identity they were wrapped to. The self-heal and the refusal now run before any identity byte is written, which is what the P1 review comment always claimed. Malformed wrap pubkeys no longer abort `prepare` (one hostile member row cannot block readiness; invalid keys count as missing), and member removal rotates the SMK so a removed member's knowledge of the old key retires with them (best-effort this slice; authoritative in 7b).

**Boundaries**: 7b owns the flip itself — meta derivation re-homing, keywrap shape changes, shape-aware rotation staging, and the flip ceremony; sync-engine validation of `identity_wrap_pubkey` lands when the field becomes load-bearing at verification; the desktop surface for prepare/status rides the §4.8 wave.

### D40. Team-Shape Flip (S3-7b) (2026-09-25; S3 in progress)

A team vault must not hand its Root Key to people who only need one collection. S3-7b makes that true at the crypto layer: an admin flips the vault, and from that commit forward member devices hold neither the Root Key nor the Space Group Key. Their unlock path is identity seed → space.wrap → SMK; the seven member-visible meta derivations (index, folders, tags, profile, settings, contacts, events) take HKDF(SMK) where they took Root Key bytes, with every per-file info constant unchanged so admins and members compute identical keys. Admin-only derivations (activity, generator history, templates, outbox, avatar) stay Root-Key-bound and refuse on member devices.

Two ordering decisions carry the design. First, the marker moves before the files: `meta/space-shape.json` (plaintext, admin-row policy) is the point of no return, and every crash window after it is healed by the next admin unlock, which re-reads any old-keyed file with the live Root Key derivation and re-saves under the SMK derivation. A crash before the marker changes nothing. Second, Root-Key distribution is gated by shape everywhere, not just in one loop: the rotation staging filter, the quorum transaction builder, transaction adoption, and the join approval all check the marker, because the review demonstrated that a single unfiltered path (the quorum `.txn`) re-leaks the Root Key to member devices offline — the committed wraps are openable by any listed device's private key, unlock paths notwithstanding.

The review also forced a sharper rule than "refuse politely": a member device must never be handed USABLE-LOOKING dummy key material. The avatar key derivation initially returned a zero key on member devices so callers would not error; any caller that encrypts with it would silently write data no admin can decrypt. Refusals must be errors, not zero keys. Likewise the flip readiness gate now treats an absent wrap pubkey as unusable (a `None`-pubkey row with a stale wrap file on disk previously passed) — a wrap file without a pubkey is leftover mail, not readiness.

**Boundaries**: member devices do not yet read or write ciphers — collection ciphers are still encrypted under SGK-derived item keys, so member listing degrades to an empty index and S3-7c owns the re-key of collection ciphers under CK-derived item keys plus member CRUD through grant wraps. Flat/personal ciphers remain admin-surface. A member pulling mid-flip (marker present, files not yet converged) sees meta read failures until the flipping admin's convergence commit lands — bounded, single-admin-window, and self-healing.

### D41. Member Collection Access (S3-7c) (2026-09-25; S3 in progress)

The Team-shape flip made grants enforce who holds keys; S3-7c makes the keys enforce what grants grant. Collection ciphers now carry item keys HKDF'd from the collection's random content key under the same `baluard-item-v1` info the SGK path uses, so the derivation discipline is identical and only the keying material differs. A path-domain resolver is the single source of truth: a cipher's location decides its key domain (collection dir → CK, flat → SGK, trash mirrors origin), and the CK arrives by role — admins unwrap it from the collection file, members open their per-member grant wrap. Trash preserves the origin subdirectory so restore is a byte-identical same-domain move, and `assign_cipher_to_collection` re-encrypts across domains because the path IS the key domain. Root rotation re-keys collection ciphers as ck@new_epoch: the CK value never changes, so member grant wraps survive every rotation untouched.

The review round converted two latent gaps into rules. First, the rotation loop built flat-only paths and silently skipped every collection cipher at rotation — capability added without re-auditing the loop inventory. Second, the sync policy demanded a write grant from every author of a collection-cipher commit including Owner/Admin, whose authority is structural — an admin-authored collection cipher was unverifiable at every peer. The policy now treats known collection dirs as structurally open to Owner/Admin, scope-checks `trash/<dir>/**` like the ciphers they came from, and gates personal-flat paths to Admin only once the shape marker rides the commit tree (pre-flip members legitimately held SGK and authored flat content; post-flip they cannot). The integrity containment rule keeps an unconditional seq floor — checkpoint seq is the envelope update_seq, which rises on every edit regardless of device, so cross-device handoffs need no seq exception and cannot launder history.

**Boundaries**: flat/personal ciphers stay admin-surface; member-facing collection UI is the §4.8 wave; attachment blobs ride the cipher item key so they follow the domain automatically; S4 groups and dual control untouched.

### D42. Shared-Collection Surfaces (§4.8-4) (2026-09-25; S3 in progress)

One listing route, role-aware output. Admins see every collection with the grant table and an access:"admin" marker; members see only rows they can open, names decrypted through their own grant wrap. The marker is server-derived from holds_root, so no client can badge itself into a managing position. A cipher's collection membership travels as a path-derived field (CipherMeta.collection_id filled from the on-disk location over a single dir-map pass) — never from client input, so an entry cannot claim a collection it is not stored in. Entry creation takes the collection id in the payload and lands inside the collection in one operation, closing the create-then-move window a Read-grantee could otherwise have wedged.

The review round proved the payload contract is a real perimeter: the desktop inbox shipped payloads the daemon refuses (a missing requester_member_id blocks every approve/deny), and an expiry field the daemon never parsed silently turned temporary access into permanent. Cross-layer contracts need a test on BOTH ends, not a shared name. The same round surfaced a pre-existing toolchain break — solid 2.0.0-rc.1 dropped onMount from the default entry, so `vite build` failed on main independent of any wave — closed by moving both importers to the onSettled convention the codebase already uses, and the build smoke joined the verification set.

**Boundaries**: entry move-to-collection UI, trash collection mapping, and catalog opt-out UX stay with the §4.8-5 polish pass; org settings/readiness and the provider checklist are the remaining S3 remainder.

### D43. Collection Polish (§4.8-5) (2026-09-25; S3 in progress)

A move is a re-encryption, not a rename, and the UI now says so without saying it: the entry detail offers the collections the device can actually reach (admin: all, plus back out to personal; member: live write/manage grants only), a read-only source renders as a plain label instead of a select that would promise a move the daemon refuses, and a refusal snaps the control back to the truth. The daemon remains the only validator — the UI filter is ergonomics, never the gate.

Trash rows now carry their origin collection end to end, resolved from the on-disk layout with flats listed before collection subdirs so the listing agrees with the restore resolver regardless of directory order. And the admin catalog gained its opt-out: an empty publish is the off switch. The review round was a lesson in verification symmetry — four findings died against the source or the diff (the payload stringifier the reviewer missed, a trash meta fix already in the working tree), the blocker self-refuted, and the four real ones were all about the UI telling the truth after a refused move.

**Boundaries**: collection-aware extension routes and mobile admin surfaces remain the S3 tail; org settings/readiness and the provider checklist stay deferred.

### D44. Remote Migration and Auto-Adopt (S3-8) (2026-09-26; S3 in progress)

A Space's git remote is transport, and transport dies. The admin moves it: the full history ships to the new remote FIRST, then a plaintext pointer commit goes to the old remote — one last sync every peer still watches — then origin re-points and the pointer lands on the new address. Every device reads the pointer from verified committed HEAD on its next pull and follows within the same forge host. Ordering is the safety mechanism: a follower only ever re-points to a remote that already holds the referenced history, so the classic migration wedge (announced address missing the history) is closed by construction, not by cleanup.

Three rules generalize. (1) A pointer that moves devices must be committed and verified — never read from a worktree that its own author may not have shipped. (2) Automatic re-pointing stays within the forge already in use; cross-host moves are explicit (`vaults repoint`). Paired with this, provider tokens are now host-gated at the credential callback itself — a token is refused to any host outside its provider's enrolled instances — closing a latent exfil path where a pointer to a hostile git server could have collected a member's stored token on an auth challenge (env-var and file tokens, which carry no enrolled hosts, are covered only by the same-host follow gate and remain an explicit-choice residual). (3) Rollback never uses reset --hard on a commit that commit_all may have swept user work into — a failed migration leaves its commit local and unpushed, and re-running converges on top of it. The review round for this slice was unusual: the reviewer timed out mid-remediation and its half-applied fixes were audited, kept where sound, and completed by hand — records of what landed are claims; the tree is the evidence, in both directions.

**Boundaries**: cross-provider migrations need the new provider connected before followers can fetch (provider checklist slice); a pointer to a repo the admin cannot push to strands followers until a newer pointer or a manual repoint (availability only — signature verification still gates every commit); org settings/readiness remain deferred.

### D45. Mobile Member Surfaces over a Thin Bridge (§4.8-6) (2026-09-26; S3 in progress)

A second UI platform should not fork the contract surface. The mobile bridge exposes sharing and join as thin delegation to the same runtime wrappers the desktop daemon routes through — one authoritative parser per payload contract, zero re-implemented validation on the Kotlin side. When a platform re-implements validation, the platforms drift: an earlier desktop wave shipped inbox payloads the daemon refused, and every re-implementation of a parse rule is a new place to be wrong. The member join flow mirrors the daemon's join-poll ordering exactly (status first; the best-effort pull runs only in the locked, introduced-but-not-approved window), because that window is the only state in which touching the repo from an unsynchronized engine cannot race the sync cycle lock.

Two review findings generalized beyond this slice. (1) An entry point hidden behind the state it produces is a deadlock: the ask-for-access control lived inside a section that rendered only when the member already had collections — but asking is how a member gets collections in the first place. Render controls that create state unconditionally; gate their success, not their visibility. (2) Hand-built JSON must escape control characters the moment an input allows multi-line text; the daemon's own newline refusal remains the clear-language backstop.

**Boundaries**: admin surfaces (invite, approve, deny, flip, grants) remain desktop until a mobile admin wave; the joiner's chosen master password crosses the FFI as a String and lives in composable state for the ceremony's duration (the Rust side zeroizes before the introduction write — the same trust model as the desktop flow); iOS remains at its existing parity.

### D46. Mobile Admin Surfaces over the Same Bridge (§4.8-7) (2026-09-26; S3 in progress)

The thin-bridge rule from D45 extends upward: admin surfaces ride the same one-parser contract boundary, and the client-side admin signal (any collections row reporting access:"admin") matches the desktop's server-derived marker instead of inventing a second notion of who manages a space. What stayed desktop is as deliberate as what shipped: destructive member controls (reset/remove/transfer), the space flip, and collection create/rename/delete are exactly the surfaces where a mis-tap carries irreversible weight, and they deserve purpose-built confirmation flows rather than a small-screen port.

Two review findings repeated earlier lessons in new costumes. The hand-built-JSON hazard returned as an escaping-ORDER bug: escaping quotes without first escaping backslashes lets a pasted `\` terminate the string early and inject keys into the payload — the fix order is backslash first, then quotes, every time, and the durable fix remains building JSON structurally instead of by interpolation. And the N+1 shape reappeared across the bridge boundary: the admin rows already carry each collection's grants inline, so a grants editor that re-fetches the collection list per collection pays N round-trips for data it was handed once — parse everything from one response and derive both views from it.

**Boundaries**: destructive member controls, the flip, and collection CRUD remain desktop until a dedicated mobile wave; expiry days convert on the phone clock, and the daemon's own clock checks refuse a past expiry harmlessly; the join-queue secret-check warning is advisory by design (S1a: secret_ok false means verify out of band, not refuse).

### D47. Fail-Loud Offboarding on a Small Screen (§4.8-8) (2026-09-26; S3 in progress)

Destructive controls travel with their confirmation machinery, not just their routes: the typed-confirm word is the member's name with desktop parity guards (non-empty name AND trim-matched input), the strike-failure path keeps the dialog open with the override switch UNCHECKED, and the offboarding report is parsed fail-loud. The reset code is the sharpest edge in the wave: the reset has already happened core-side when the response arrives, so a malformed payload that read as success would silently destroy the one artifact the successor needs. Every parse in this surface therefore fails toward a visible error, never toward an empty success.

Two review lessons generalize. An empty-string confirm word equals an empty-string member name: any typed-confirm guard must require a non-empty typed value, or a display name the system failed to record becomes a zero-friction destruction path. And a dismiss button is part of the failure surface: closing the dialog while the strike network call is in flight would swallow the only report of why the removal did not happen, so dismiss is disabled for the duration of the call.

**Boundaries**: flip/prepare stay off the phone until desktop grows its own flip surface (parity first); ownership transfer confirmation carries no extra secret, but the demotion is irreversible except by the new owner, so its dialog says so plainly; batch removal exists in the core API but the mobile UI removes one member at a time.

### D49. The Address Book Is Dial State, Not Access Control (S2 contact flavors) (2026-09-26; S3 in progress)

The address book records identity, not permission: importing a card proves only that a signed card exists (HPKE base mode authenticates nobody), and Level 1 contacts can receive shared items by design because packages and reveals wrap no live keys. The thing the book actually guards is the verification code, and the wave's sharpest finding was that the code was too weak to guard anything: 32 bits of unilateral hash lets an active man-in-the-middle brute-force a colliding key offline. Out-of-band comparison is only as strong as the code is long \u2014 64 bits is the floor where brute force leaves hobby budgets. The durable rule: any human-comparison secret must be sized against OFFLINE attack by the person best resourced, not against ONCE-THEN-GONE guessing.

The second finding was a plumbing completeness check: the address book had no removal primitive and the UI showed the verification code where the card code belonged, so the surface advertised sharing neither side could actually complete. When a UI exposes a primitive set, enumerate the CRUD gaps first \u2014 a list without remove and an export without display are both silent dead ends.

**Boundaries**: trust is still binary Channel/Verified (the full dial is \u00a74.1); removal is local dial state and revokes nothing already received; contact cards travel out of band with no expiry \u2014 re-issue after identity rotation is the reconcile path; outbox management UI (publish/revoke mirrors) remains unowned.

### D50. The Outbox Is a Folder, Not a Route (S2-4 owner + recipient surfaces) (2026-09-26)

Ten outbox routes shipped with the core module and sat UI-less until this wave, which added only allowlist entries and one tab. The outbox's defining choice is its transport: a plain folder the recipient carries, mirroring items live through digest-driven resync instead of streaming through a route. That inverts the usual sharing posture \u2014 "revoke" stops future mirroring but cannot recall bytes already carried away, so the confirm dialogs say so plainly instead of implying retrieval. The recipient read path stays view-only with a masked password and the auto-clear clipboard utility; the outbox model deliberately has no write-back channel.

Review lesson, self-inflicted: the locale script's dot-in-key branch was inverted, so the new tab label landed inside the `outbox` group while the component looked under `settings` \u2014 i18n parity tests count keys, not positions, so the tab rendered its raw key until the adversarial pass caught it. Scripted key inserts must assert the resolved lookup path (the exact `t()` key), not just that a key with that suffix exists somewhere.

**Boundaries**: outbox entries carry no attachments/password-history/passkeys (stripped at export, handle-side); resync is global (all mirrors at once) rather than per-outbox; the entry viewer covers login items' core fields only \u2014 custom fields and non-login kinds render name/notes but not typed editors; folders are local paths, so this transport never crosses machines by itself.

### D51. The Admin Marker Must Survive the Empty Set (§4.8-9 mobile collection CRUD) (2026-09-26)

Mobile settings entries gate on an admin marker, and the marker the desktop used — any collections row carrying access admin — has a hole: a vault with zero collections returns an empty list, so a real administrator saw neither the People nor the Collections entry and could not create the first collection from the phone. The fix is not a better row count; it is asking the right question. holds_root is what collections_list actually branches on, and it is true exactly for managing devices regardless of how many collections exist. The rule: an entry-point marker must be derived from the capability itself, never counted from the artifacts the capability produces. A proxy that works for populated states silently fails exactly when a surface is newest.

The wave also followed D47's typed-args rule for every new bridge method: the app passes strings and a record list, the Rust bridge builds the JSON, and Kotlin never escapes an id. Re-verified en route: the mid-wave repository edit that accidentally dropped collectionGrant was caught by the Kotlin gate (unresolved reference in PeopleScreen), not by review — the gate earned its keep.

**Boundaries**: catalog publish sends all current collections (no per-item curation on mobile); delete keeps entries but grants die with the collection, and the dialog says so; the screen remains admin-reachable only via the Settings gate — the daemon stays the validator for every call.

### D52. Defaults Are a Contract Written Twice (§6.5 Space settings + the provider gate) (2026-09-27)

Space settings landed as three §6.5 knobs on the encrypted settings store, and the wave's defining defect was not in the enforcement — it was in what "default" means. `guest_enabled` first shipped as a plain bool with a serde default of true, but the struct's derived `Default` produced false: two sources of truth, and any path building the struct by hand got the opposite policy from any path deserializing it. The fix adopts the house Option-toggle convention (None/Some(true) = on) so the absent value and the derived default agree. The rule: a default is a contract that must survive every construction path — serde, derived Default, and hand-built literals — or it is not a default, it is a coin flip.

The second lesson came from the review round: the viewer-export gate's catch-all (`_ => Ok`) trusted `member_role_for_device` returning `None` to mean legacy founder. But None also means tombstoned — a removed member's still-open session resolved to None and exported the vault. The founder equivalence is only sound when the member directory does not EXIST; on a strict vault, None must refuse. Generalized: a fallback interpretation of an ambiguous resolution is only valid inside the context that disambiguates it (directory-absent), never globally.

The provider checklist (`docs/provider-org-readiness.md`) closed the plan's S3 research gate with primary-source facts: GitHub ToS places no code-only restriction on private repos (the folk belief that password managers violate it is wrong); GitLab's free tier caps NEW top-level private groups at 5 members; Codeberg's 100 MiB non-promoted bucket plus its FLOSS-mission clause makes it personal-only. The org-Space readiness gate (repo ownership, app-approval path, scope honesty, seats, ToS fit) is now recorded per provider instead of assumed.

**Boundaries**: join_approval, quorum_admin_ops, trash_policy, and restore_policy stay unimplemented — join_approval needs a code-mode design, quorum touches the finalize path, and trash/restore flips shipped S3-7c behavior and deserve their own slice; the settings surfaces are routes-first (no UI yet); org-shape Spaces remain S4 planning gated on the recorded checklist.

### D53. Absent Is Not Null (the §6.5 settings surface) (2026-09-27)

The settings routes got their UI in this slice, and the review round caught the wave's real defect at the bridge: `serde_json::json!` serializes `Option::None` as JSON `null`, but the runtime partial parser treats a present-null key as a mistyped value — so every mobile write that passed `None` for unchanged knobs failed. The desktop never hit this because its per-control patches only ever carry one key. The fix is structural: the bridge emits present-fields-only JSON. The rule: a partial-update wire contract must give `absent` and `null` different meanings or forbid one of them; here absent means "leave unchanged" and null means nothing at all, so the bridge must never send it.

The second lesson is about optimistic UI on a gated surface: the desktop tab updates its toggle signal before the daemon call and drops the request when a previous one is still in flight — a rapid second click left the toggle flipped with no daemon change. The guard belongs at the mutator (reject while busy) and on the control (disabled), not only inside the async apply. Mobile needed the same discipline in a different shape: the busy flag must be set synchronously before `scope.launch` dispatches, or two taps in one frame both pass the check; and a `catch (e: Exception)` swallows `CancellationException`, so the rethrow comes first.

**Boundaries**: the remaining §6.5 knobs (join_approval, quorum_admin_ops, trash_policy, restore_policy) stay unimplemented pending design and §10 confirmations; the desktop tab renders for members too (tab convention) and the daemon refuses with plain language; the mobile card is capability-gated via is_admin_device.

### D54. Local Truth, Local Surface (mobile notices + activity) (2026-09-27)

The phone gained the S1b surfaces, and the review round caught a contract I had inverted without noticing: the core emits share events in CHRONOLOGICAL order (oldest first, the audit-log convention) while my bridge doc claimed newest-first and the screen rendered the oldest event at the top of a card titled "Recent activity". Nobody lied in code — the doc, the parser, and the renderer just each told a different truth about the same list. The fix puts the reversal in exactly one place (the repository parser) with the core contract quoted beside it. Rule: when a wire payload has a canonical order, every layer's doc must quote that order, and the layer that deviates must say so in its own doc, not inherit the upstream wording.

The second lesson is about empty states. An activity screen that renders "nothing needs attention" while its fetch is still in flight is not neutral — it asserts a clean bill of health it has not verified. The screen now renders blank until the load completes, because a blank pane is honest and a false empty is a claim. Related: the transport seat checks stay off the phone (refresh_transport=false) — the optional network probe is an admin desktop concern, and a phone should never spend a forge round-trip on a status card.

**Boundaries**: notices remain unlocked-gated (any member's device reads its own) — the reset-pending names and grant counts they carry ride the member directory every clone already distributes, so mobile exposes nothing new; the event and refusal logs are per-device local files and never sync; date-only event stamps are the existing shared formatter (ordering carries the precision).

### D55. The Tightening Default (trash + restore policy knobs) (2026-09-27)

Two more §6.5 knobs landed, and the interesting one is restore_policy: it ships single-valued (admins_only) because the plan table lists no member-facing value. Its serde default therefore TIGHTENS every existing vault on load — members who could restore trashed entries yesterday cannot today. That is a deliberate plan-conformant behavior change, made safe by two properties: the knob is visible on both surfaces (a read-only line on the phone and desktop, so the tightening is never silent), and the enforcement is local-only (the keyless sync walker cannot read settings.enc, so peer admission stays grant-scoped — a member's trash commit still lands; the admin restores). Enforcement asymmetry between local API and peer verification is acceptable exactly because the local gate is the security boundary for destructive intent; the git layer only needs to admit what the stricter side may legitimately produce.

The review round caught the other half of the §4.4 row this wave claimed to implement: permanent delete of trashed entries and time-based purge were ungated — a member could purge what it cannot restore, and purging a flat admin cipher would wedge its own sync (flat_admin_only refuses the commit at every peer). A gate pair is only as strong as its weakest destructive sibling: when a policy row names restore AND purge, every entry point into that row's power needs the same gate, including the automatic ones (the unlock-time purge call is best-effort and now simply no-ops for members).

**Boundaries**: join_approval (code-mode needs a new ceremony design) and quorum_admin_ops (§10 open question 1 unconfirmed; touches the rotation finalize path) stay deferred; trash_policy/restore_policy enforce locally only — sync admission stays grant-scoped; purge is admin regardless of trash_policy (the §4.4 row, not the knob).

### D56. The Flip Becomes Reachable (Team-mode surfaces) (2026-09-27)

The S3-7b flip had core, daemon routes, and allowlist entries for five waves but no way for a human to trigger it — the strongest privacy property in the product was tests-only. This wave wires the surface: status, prepare, and the one-way upgrade on the desktop Space tab and the mobile admin space card, three thin uniffi methods over the same runtime wrappers, and a typed “team” confirm on both platforms. The prepare-then-flip two-step is the UX translation of the readiness gate: prepare surfaces the missing-member count in plain language (open Baluard and sign in once), and the upgrade button stays dead until the count is zero — the daemon re-checks everything either way.

The review round caught four classes in one slice: a count-versus-array wire misread (SpaceStatus.missing_wrap_pubkey is a count; PrepareReport carries the id array — two same-named fields with different shapes across sibling payloads is a parser trap, pin both in the repository doc), double-prefixed locale keys (space.space.* from inserting dotted keys into a group — the wave-28 lesson, replayed because the verification gates check key existence, not lookup), a confirm modal that does not auto-close (TypedConfirmModal and ConfirmModal have different close contracts — two components with near-identical prop surfaces; check the component, not the memory of it), and a false-success toast on a failed prepare (null must be a branch, not falsy-success).

**Boundaries**: the desktop tab renders for members too (tab convention); a member's space.status refuses, so the row shows a muted placeholder and dead buttons rather than a wrong status; the flip stays admin-only at the core layer regardless of what any client renders; join_approval and quorum_admin_ops remain deferred.

### D57. The Avatar Follows Its Profile (member-visible meta + the write-gate sweep) (2026-09-27)

The avatar was the last capability keyed to a domain members cannot reach: meta/avatar.enc rode an epoch-bound SGK derivation, so post-flip member devices simply could not see the vault picture. It now derives from the same member-visible meta IKM as the profile it decorates, with three convergence paths instead of a migration — any rewrite re-keys it, the flip converges it (files_reencrypted 6 when one exists), and pre-flip rotation migrates it while post-flip rotation skips the leg entirely (the SMK is rotation-invariant; re-encrypting an unchanged key is churn). The flexible read tries the meta key then the legacy SGK derivation, so pre-wave blobs stay readable until something rewrites them.

The review round then generalized the real lesson: the avatar was one instance of a CLASS — member-reachable wrappers writing git-tracked meta. A member device committing tracked meta commits fine locally and is refused at every peer pull, wedging the whole space; the write succeeds, everyone else pays. The sweep gated the class, not the instance: settings, avatar, locale (at every state — a pre-unlock member write still gets committed by the first post-unlock sync), contacts mutations, and generator history all refuse on non-managing devices with one plain-language sentence. The convergence corollary: the flip's crash-recovery pass must read the avatar inside the same dropped-SMK window as the other meta files, because the crash bytes are root-domain and neither post-flip key opens them.

**Boundaries**: member language/theme preferences are a future local-store item (today the synced admin choice applies and a member change refuses in plain language); legacy plaintext avatar migration on a member device reads bytes without writing (the admin migrates on its next read); pre-wave avatar blobs on vaults that never rotate or re-save stay admin-readable only — the fallback is the bridge, not a guarantee.

### D58. The Code Is the Approval (§6.5 join_approval) (2026-09-27)

The last buildable §6.5 knob splits join approval into two trust modes. `manual` (default) is today's review step. `code` makes possession of a valid invite code the approval itself: the admin device's post-pull and unlock-tail sweep — the same admin-gated executor as the grant-expiry sweep — walks the repo-backed queue and auto-approves every introduction whose one-time-code secret check passes, through the exact `approve_queued_join` path the manual button uses, so every gate (pair-Space cap, flip readiness, role floor, template snapshot) inherits for free. A failed secret check approves nothing: hostile or stale rows stay queued for admin visibility, never auto-denied.

Two review-round rules are worth keeping. First, divergence fails toward the manual path's semantics: the sweep's seat upgrade skips when the invite role is unresolvable (the manual path grants no seat; the sweep briefly defaulted to Write), and it captures the vault id under the lock because reading it after release races the vault locking and silently drops every upgrade. Second, the one-time code consumes at introduction, so the secret check runs against the admin-side invite copy — the queue row carries proof, not the credential.

**Boundaries**: quorum_admin_ops stays deferred on the unconfirmed §10 Q1 default; a leaked invite code under code mode grants membership — that is the knob's stated trade, which is why manual stays the default; the knob is enforced at approval time only, and staged rows approved under manual remain queue-resident until a human decides.

### D75. The Hardening Wave (Claude's full sharing review, seven fixes, agy after each) (2026-10-01)

A full independent review of every sharing surface returned ten top findings plus below-cut items; eight survived Zero-Trust source triage and shipped as seven fixes, each with its own adversarial round. The systemic finds, generalized: (1) a mechanism designed before entries became key-domain-relevant (the S3-3 grant-expiry sweep predates S3-7c's CK-derived item keys) silently destroyed every entry in a collection when a grant expired — the sweep now carries each rotation into the entries, trash, and attachments, with a gitignored crash marker so the def-flip → re-encrypt window converges; (2) a consistency check that verifies payload-to-path agreement (device bindings) does not prevent a member from binding SOMEONE ELSE'S device into their own policy-legal subtree — duplicate device bindings now fail closed in the walk and both local resolvers, with tombstoned subtrees inert so reset re-enrollment stays legal; (3) the desktop allowlist gap class recurred (join routes dead) and the surface-diff rule ran over every surface; (4) commit verification had quietly become clock-dependent through the S4-2 group expansion — the peer walk judges grants by the tree again (now = 0), expiry stays a local enforcement concern; (5) a consumed quorum approval restored from git history re-executed within the staleness window — consumption leaves a tombstone keyed on (kind, digest, nonce), and every ask now carries a random nonce bound into the signed message, which also kills entry-transplant (Ed25519 determinism made a same-second re-ask byte-identical to the ask it superseded — only the nonce distinguishes them); (6) one corrupt entry aborted a removal's rotation after the tombstone (no retry exists) — rotation skips and names it; and the removal SMK rotation re-seals the member-visible meta (the marker-guarded heal runs at the next admin unlock); (7) the flip now prompts the rotation it always required (flipped_epoch in the marker drives a persistent needs_rotation reminder until an epoch bump proves it ran), and the rotation route exists at all for the first time (space.rotate_root, admin+quorum gated — the quorum gate's role check now runs at EVERY threshold, closing a latent hole where threshold 1 skipped authorization entirely). Show-once ceremonies hold their phrase in process memory keyed by ceremony kind, so a blur-lock unmount no longer destroys the only showing. Declined with reasons: quorum-ask Approve buttons for ops whose confirm is re-calling the op (deliberate), rate limits on password-gated routes (in-session brute force is pointless), and the orphan-device finding (the card validation already precedes enrollment — misread by the reviewer). Fourth violation of the no-scripted-edits rule recorded en route (one python two-site patch, self-caught).

### D74. The Owner Rotates, the Thief Cannot (recovery-phrase exit paths) (2026-10-01)

The 24-word phrase is a second master key written in words: either credential alone opens the vault, they simply leak through different doors. Rotation exists for the day the phrase leaks, and the design rule is the whole feature: **rotation is gated on the current master password, never the old phrase.** The owner holds the password, a thief holds only the phrase; gating rotation on the phrase locks out the exact person rotation exists for (the owner who suspects exposure and may no longer have the paper in hand), while gating it on the password means a stolen phrase can never be rotated against the real owner. The core op verifies the KEK canary, re-wraps the live Root Key under a fresh phrase, and overwrites the escrow; the old phrase is dead the moment the write lands, and the new words are shown exactly once with copy and TXT/MD export (the parked recovery-key export item shipped as part of this ceremony).

Esteban's call on the second question: rotation is an **offer, never forced**. Forcing a new 24-word wall during an unrelated password change manufactures lockouts (panic screenshots, mistyped confirmations, stale stored papers) and mostly defends against a leak that did not happen, because password and phrase leak through different doors. When a desktop password-change UI eventually ships, it must offer rotation with a recommendation, not run it. A flipped (team) Space refuses rotation entirely: its recovery contract is the Space Recovery Kit, and the destructive personal recovery would reset the device roster.

Three review-round rules joined it. (1) An escrow swap must reach the remote promptly, so rotation rides the cover-commit mutations: until the swap syncs, the OLD phrase still opens the remote copy, and a ceremony that says "the old phrase no longer works" would be lying across that window. (2) The canary gate fails closed when the password canary file is missing (unlock guarantees a canary somewhere, so absence means this device cannot verify anything), replacing the inherited skip that a deleted canary could wave any string through. (3) The rotation write holds the autosync cycle lock so a background cycle cannot commit the escrow mid-swap. Declined on purpose: rate limiting (in-session brute force is pointless, a session holder already has everything, and change_master_password runs the same shape), and encrypted escrow of the phrase itself (relocates the single point of failure and users guard the escrow less than the phrase).

Boundaries: the destructive personal recovery (registry reset) stays API-only; when it ever ships as a flow it must end with a root rotation AND a fresh phrase (rotation alone would re-arm a leaked phrase through the rotation rewrap), and until then the exit path is exactly this: rotate the moment you suspect exposure. The danger window is bounded by when you rotate, not by any safeguard.

### D73. Notice, Never Wipe (the removed-device signal) (2026-09-30)

When a member is removed from a Space, their provider seat is struck — so the channel that would tell them they are removed is exactly the channel that was locked. Their app used to see sync failures forever, indistinguishable from broken wifi, while a stale vault sat on their machine. The design question was whether to poll and auto-wipe. The answer is no, twice over: a wipe runs on the removed member's own device, so it can never be enforcement (the hostile member patches, blocks, or copies first — they already hold the bytes), and a silent auto-delete keyed on an ambiguous signal (kicked vs repo deleted vs provider outage) is the exact bug class the project forbids. Revocation stays eventual; the removed keep their bytes; that is recorded and accepted.

What ships is detection plus a question. The sync engine classifies access-denied errors inside sync failures (HTTP status text and auth wording, deliberately conservative — bare digits and "not found" never match, and filesystem "permission denied" is excluded because it is a local disk error, not a remote refusal). The autosync coordinator counts consecutive refused pulls; three in a row is the kicked signal, cleared by any success, any full sync cycle, and every fresh session. Independently, the device's own member row on disk is checked keylessly: a landed tombstone is a CONFIRMED removal, no guessing. The banner asks, in plain language, and offers one action: detach the vault from the app, keeping the files. Real deletion stays CLI-only, and the banner prints the command instead of running it. The daemon re-validates everything; the banner is ergonomics.

Three rules recorded with it: arm order matters when one classifier subsumes another (a provider strike arrives inside a Network-class error, so the access-denied check must precede the network check or it is dead code — the review caught the first landing exactly backwards); vault-scoped UI state must reset on vault switch and lock (the banner signal joins resetNavigation and the deactivate sweep); and liveness wins over tombstones when a device carries bindings to both a dead row and a live successor row — read_dir order must never decide whether a user sees "you were removed."

Boundaries: this is hygiene for honest removed users, not enforcement; the offline-forever device is and remains unreachable; a probable-status banner says "may have been removed" because expired tokens and MFA prompts look identical on any single failure; and the pre-existing host-close autosync-loop leak (close never deactivates the coordinator) is recorded as tracked debt — the banner's lock-first ordering deactivates before detach, so the new path is clean.

### D72. Ask the Server, Count Nothing (the admin marker debt round) (2026-09-30)

The desktop's admin signal was a proxy: it counted admin rows in the collections list. Counting the artifacts a capability produces breaks on the empty set — an admin of a zero-collection vault read as a member. The mobile side already asked the server (wave-29); the desktop now does too, through a read-only `vault.is_admin_device` route answering `holds_root()`.

Three rules recorded with it. First, the marker is key state, not live role: a locked vault reports false (no keys in memory, no powers), and a device whose role was demoted server-side keeps reporting admin until it locks — the recorded session-keys-live-until-lock boundary. Surfaces may use it for ergonomics only; the daemon re-validates every mutation. Second, vault-scoped context signals must reset on vault switch: a stale admin flag would show admin controls on a member vault (and the ask button on an admin vault) until the refresh lands — the peer review caught exactly that bleed, and `resetNavigation` now clears collections and the marker with the rest. Third, the flip's quorum-rotation gap closed as a test: threshold-2 rotation on a flipped vault needs a second admin, the ask travels by git, the confirming rotation runs on the confirmer's clone, both admins converge through the rekey wrap, and the SMK never changes — so members keep their wraps across every rotation.

Boundaries: the route leaks one boolean and joins no mutation lists (read-only, default-deny token-gated); `CipherDetail`'s admin-only move-to-flat option inherits the same marker; and the collections empty-set on switch now renders as the honest empty state instead of a stale list.

### D71. The Flip Keeps Keys From Members, Not From Admins (role-aware flipped keywraps) (2026-09-30)

The team-shape flip was coded shape-blind: no post-flip joiner got the Root Key keywrap, and any device with a member-unlock file took the member unlock path. A peer review flagged the consequence (F9): an ADMIN invited after the flip held the Admin role but no admin keys — unable to create collections, grant, rotate, or act on quorum ops. A growing organization could not add a second real admin.

The fix makes the flip's property explicit: it is role-scoped. Members hold nothing; admins keep keys. The invite path now writes the keywrap for elevated joiners on flipped vaults (`!flipped || elevated`), and the unlock dispatch takes the admin path when the device maps to an admin AND its own keywrap file exists. Both sites join the two that already agreed — the flip's own strip loop and rotation staging were role-aware from the start; only invite and unlock lagged.

Three rules recorded with it: the unlock conjunct fails closed (the keywrap-existence check keeps the legacy no-binding fallback from ever riding the admin path, and a copied keywrap is HPKE-bound to the victim's device key); the elevated member unlocks with their OWN password (member canary) and inherits full powers through their keywrap; and the pre-pull window is unchanged — before the approval commit lands, the member tail refuses with sync-and-retry exactly as for every member. The keywrap and the member row ship in one approval commit, so a crash strands nothing.

Boundaries: demotion is unreachable (no role-edit route exists; reset and remove tombstone and rotate); an elevated member device runs the admin convergence pass, which is role-legal and inert on a clean clone; and the design was endorsed independently by two peer reviews (a design consult that read the source and a post-implementation adversarial pass that returned SOUND on six attack invariants).

Amended the same day after a second full-tree review round caught a real Blocker the first round missed: `device_maps_to_admin` read only the role field, so a RESET admin's old device — whose row keeps its role, whose keywrap file stays, and whose Root Key reset deliberately does not rotate — satisfied the new admin-path conjunct and rode it past the member tail's space.wrap lockout, which had been the reset's only unlock-side protection on flipped vaults. The mapping is now tombstone-aware (`reset.is_none() && removed.is_none()`), closing the hole at every consumer at once: unlock dispatch, rotation staging, rekey adoption, and keywrap stripping. Rule recorded: a predicate named "maps to admin" must mean a LIVE admin row — any consumer that resolves role without tombstones inherits the reset/removed bypass. Pinned by reset_locks_out_elevated_member_on_flipped_vault.

### D70. A Yes Is a Signature (approvals records become self-authenticating) (2026-09-30)

The quorum workflow's records were the one remaining trust-me point: an approval was a bare member id in a plaintext file, so any admin with repo access could hand-write a second yes and the gate would count it. Every approval entry now carries the approver's member-identity Ed25519 signature over the ask (kind, params digest, vault id, ask timestamp), and the gate counts only entries whose signature verifies against the member row's published identity key. A forged record parses but approves nothing; on the next touch the record self-heals to the real entries.

Four rules landed with it, each from a review attack: one member counts once (duplicated valid entries dedupe), only live Owner/Admin rows count (a Viewer's yes or an evicted admin's old key never does), the signature binds the vault and the ask timestamp (git-history harvesting cannot replay a yes onto a fresh ask or into another Space), and stale asks past seven days are consumed so a confirming admin past the window simply re-raises fresh. The live threshold governs exactly in both directions: a tampered record can never approve below the knob, and never above it either, so no tamper can brick an ask. Consumption removes every matching record file by discovered path, so renamed or concurrently raised duplicates cannot linger and replay their entries.

Boundaries: the record file itself still rides the meta/** Admin sync row, so visibility of asks stays admin-wide; the signature check is a gate-side read discipline (the keyless sync walker still cannot read the encrypted threshold, so the knob remains local-only like every §6.5 knob); rotating an identity invalidates that member's old signatures by design, and the ask then needs a fresh approval. Old plain-uuid records parse-fail inert (format bump, pre-1.0).

### D69. Share Nothing That Acts (peer-review fix wave) (2026-09-30)

A general Claude pass over the whole sharing surface returned ten findings; source triage accepted four, declined six as designed or documented. Two rules landed with the fixes.

Share nothing that acts: a shared copy must never carry live credentials. The outbox already stripped passkeys; the one-shot package path did not — now both export AND import strip FIDO2 credentials (the importer is defense in depth against a hostile hand-built payload planting a fake live login), and the test pins the end-to-end absence with a passkey-carrying source. Reveals never carried them (field projection).

Initiator and confirmer are different actors on a voluntary op: a voluntary ownership transfer's consent IS the owner's call, but at a raised threshold the house re-call-to-confirm pattern needs a second approver who is not the owner — so transfer gained a confirmer path where an admin completes the owner's pending ask (refusing to start one), fixing a permanent threshold-2 deadlock, and both pending-asks cards (desktop SpaceTab, mobile SettingsScreen) grew the matching approve action. Completes the wave-39 rule: deterministic refusals (self-transfer, bogus or tombstoned target, wrong actor) precede the gate, so a doomed ask never burns a co-approval — the rule's pin test runs at threshold 2, because at the default of 1 a stranded ask is invisible.

Boundaries: the recovery-kit and pre-flip-key findings were declined as recorded design (D64 possession-is-approval; grants cosmetic pre-flip is why the flip exists); other pending-ask kinds (removal, rotation) keep completing by the admin repeating the op itself rather than a one-click approve.

Second round (the tree re-reviewed after the fixes landed): the transfer ask's digest binds the owner of record alongside the successor, so an ask initiated under one owner can never execute against a swapped one (the claim's rule); the confirmer path runs the same deterministic target checks before the gate, so a dead target cannot burn a co-approval; and a fresh ask supersedes the initiator's earlier asks of the same kind, so a changed target invalidates the old ask (approvals restart with it — the owner restarting the ask is the owner resetting the consent). The forged-record finding was declined as the recorded client-side-enforcement class: any admin can hand-write any meta/approvals record for any gated op, which is the priced residual until peer-side record verification lands, and transfer gains nothing special by patching it locally.

### D68. History Is the Ledger (S4-5 derived activity timeline) (2026-09-30)

The space-wide feed writes nothing. Every git commit is already signed, roster-attributed, and policy-checked — so the timeline just re-reads that verified history and names what changed: memberships, grants, groups, keys, and space-shape facts, synthesized on demand. No shared event file ever exists (S1b's per-device log stays per-device), reads leave no trace, and entry-level cipher churn is deliberately absent — the per-device feed covers it locally, and "who viewed what" is unbuildable by design. Unverifiable commits tell no story: the walk skips what they changed and keeps going. Ordering is topological (newest-first, HEAD toward the root); git timestamps render but never sort, because clocks skew across devices. Raw keys, sealed names, and cipher contents never enter the feed — collections and groups appear as short ids.

Two triage rules from the review round: an access CHANGE (Read → Write on the same target) is a revocation plus a grant — two rows, because the old access genuinely stopped; and Modified deltas count — policies re-published, a recovery kit re-wrapped, and a second remote move are all facts, so the space-fact arms match `!*deleted`, not just `added`. Boundaries: admin-gated like the access review (founder-equivalent vaults pass); the walk is bounded (500 commits, limit clamp); a member with no row yet falls back to the device-id prefix, and the genesis commit credits "the space's creator".

### D67. The Department Holds a Key (S4-2 groups as a key layer) (2026-09-29)

Grant a collection to a department instead of person by person — and make leaving the department cheap. A group is `meta/groups/<id>.json`: a plaintext member list, a display name sealed under a random Group Key (GK), and the GK sealed under an SGK-derived wrap key. A collection granted to a group stores its content key AGAIN under that GK (`<g>/<c>.ckwrap`) and every member holds the GK wrapped to their identity key (`<g>/<m>.gkwrap`). The chain is gkwrap → GK → ckwrap → CK — and the indirection is the whole point: removing a member rotates only the group's GK (ckwraps re-seal under it; collection CKs and every direct grantee are untouched), where per-member CK wraps would force a full re-key of every collection the group can open. What the leaver already copied stays the accepted eventual-revocation boundary priced everywhere else.

Four rules carry the design. (1) **Grant targets are typed**: a grant names a member or a group (`GrantTarget`), and the same effective-access predicate (direct + group expansion, max access wins, expired ignored) runs in the sync scope walks, the staging filter, the member listing, the collection write gate, and the JIT ask's covers check — writer and walker read one predicate, so they can never disagree. (2) **Group grants are admin-only**: a delegated manager grants PEOPLE, not departments — a group grant writes ckwraps under meta/groups (an Admin sync row), so a manage-holder's group grant would wedge their commit at every peer (the review's F2; the gate now branches on the target kind). (3) **Offboarding prunes**: reset or removal walks every group the member is in, deletes their gkwrap, and rotates each affected group's GK while the current SGK is still held (the review's F3 — the S1a-6 completeness rule applied to the new key layer). Deleting a group prunes its grant rows from every collection (F4). (4) **Group CK paths end at the name**: resolve_ck falls back through the group chain for members without a direct wrap (the review's F1 — the listing was group-aware but cipher decryption was not, which would have made group access visible-but-unreadable).

**Boundaries**: group membership changes are admin-only (self-leave is not a thing in v1); JIT asks and role templates stay member-targeted (a group cannot ask for access; a template cannot grant one); mobile stays deferred; a removed member's stale grant-wrap residual (CK memorization) applies unchanged to groups.

### D66. The Phone Keeps Its Spaces Open (S4-9 mobile multi-Space host) (2026-09-29)

The plan offered two bridge shapes for multi-unlock on the phone — a `MobileVaultHost` uniffi object over the desktop `VaultHost`, or app-level coordination over the existing per-vault exports. The second won outright: the desktop host is daemon-shaped (active pointer, 30s walker owned by a daemon process the phone does not run), and every export the session needs (`unlock`, `unlockWithKek`, `lock`, `isUnlocked`, `shouldAutoLock`) already crossed the FFI. The wave shipped zero Rust: a bounded `MultiVaultSession` (access-order map, path → handle + retained KEK, max 3) behind the existing `AuthViewModel`, with the fast path living in the vault switcher — a cached, still-unlocked target adopts with no unlock ceremony, desktop `VaultHost` parity.

Three rules carry the design. (1) **The bound is the OOM rule**: three unlocked vaults hold only resident keys (the runtime zeroizes on lock), the Argon2id stays transient and user-serialized, and the `:autofill` process keeps its KEK-only path untouched. (2) **Only the vault on screen rides out a background stretch**: `ON_STOP` locks inactive sessions (the desktop lock-all-on-blur twin) because a cached vault has no timer enforcement while inactive, and the auto-lock poll enforces every session's `shouldAutoLock` — `enforceAutoLock` is the replacement for the desktop walker, which does not exist on mobile. (3) **The fast path lives in the switcher, never in the password unlock**: `openAndUnlock` always verifies, because a password screen that returns success without checking is a gate that lies. Eviction and adopt-replace LOCK the superseded handle for the same walker reason — a merely-dropped handle would hold its keys until process end.

The review round sharpened two edges. The `sessionKek` getter returns a copy: the session wipes its own array on lock/evict, and a wipe reaching into a caller's in-flight biometric re-enroll would encrypt zeros into the platform keystore. And the switcher's slow path clears the conflict queue like `doAutoLock` does, so an outgoing vault's unresolved conflict cannot float over the unlock screen.

**Boundaries**: the LRU bound (3) is a constant, not a setting — a fourth Space costs one unlock ceremony, which is the honest price; session entries die with the app process (no cross-launch session persistence); biometric quick-unlock per vault is unchanged and remains the fast path that survives process death.

### D65. Recovery Is a Fresh Clone and a Phrase (S4-7 ceremony + kit routes) (2026-09-29)

The recovery ceremony closes the S4-7 kit's deferred half: `recover_device_with_kit` unwraps the Root Key with the phrase, verifies it against the vault canary, mints a fresh device (keypairs, keystore sealed under the vault-salt devkey subkey, keywrap under root-key-keywrap), adds the registry entry so commits verify, and binds the device to the live Owner member row — never a roster wipe (D64's registry-reset rule, now code). The KEK derives from the VAULT-level KDF params with no fresh salt, so the recovered device unlocks through the ordinary admin path; identity adoption rides the existing cross-device heal. The route is host-level and pre-token (`vault.recover_kit`), because recovery is by definition a fresh-install op with no session — the same shape as join.introduce.

The review round reshaped the ceremony around one discovery: **a fresh clone of a multi-device Space cannot open() a handle at all** — device resolution needs a local keystore to match keywraps against, and a fresh clone has none, so a handle-taking ceremony was unreachable exactly where it matters (the 1-device test vault masked it). The ceremony is therefore path-only, like create_introduction. Three rules worth keeping. (1) Deterministic refusals run first and in order — brick guard, kit presence, phrase, root canary, KEK canary, live-Owner resolution — all BEFORE any disk mutation, so a mistyped master password (which would otherwise mint an un-unlockable keystore the brick guard then seals forever) or a missing Owner row leaves nothing behind. (2) Both canaries verify: the phrase proves the kit, the root canary proves the vault, the KEK canary proves the password. (3) All three kit surfaces (enable/disable/status) sit behind one Owner/Admin gate, status included: the file's existence is locally readable anyway, so the gate protects the IPC surface, and surfaces render the refusal as the unknown state (the wave-34 null-render rule) rather than pretending the kit is off.

Boundaries: the ceremony assumes the master password is remembered (the kit covers device loss, not password loss — the password is the human's own secret, not device-bound); the disaster path is CLI-first (`baluard vaults recover-kit <slug>` — recovery happens on a fresh machine before any app login exists, so the desktop ships only the everyday admin surface and a login-screen recovery UI stays deferred until demand says otherwise); repeated recovery on successive clones just adds devices, each needing the phrase.

### D64. The Phrase Is the Last Key (S4-7 Space Recovery Kit + the emergency × org × identity doc) (2026-09-29)

The kit escrows a Space's Root Key to an offline BIP-39 phrase (`meta/recovery-kit.json`, plaintext, git-tracked under the meta/** Admin row so it survives total machine loss). The defining rule: **possession of the phrase is the approval** — in-band approval is impossible when every admin device is gone, so the kit carries no status machinery, no request flow, and no expiry, and it deliberately bypasses the quorum gate it exists for the moment no quorum can convene. The only off switch is an admin removing the file.

Three rules worth keeping. (1) The registry-reset rule: the personal vault's phrase recovery wipes the device registry because one human's vault has no peers; a Space kit recovery must never do that — the roster is what every peer verifies signatures against — so the recovered device binds into the live Owner member row's own subtree while the ceremony (routes, enrollment, unlock) lands as its own reviewed slice with `docs/emergency-org-identity.md` as the spec. (2) Rotation rewires the kit in both rotation twins with P4 semantics: an absent kit is a no-op, a damaged kit fails the rotation loudly rather than silently stranding a dead phrase in the safe. (3) The doc's claims were written against named source lines (domain-separation contexts, the flip interaction, the git-tracked file) so the follow-up slice inherits verified text, not intent.

Boundaries: the phrase-holder holds the Space whenever the file exists (the point, not a flaw); losing both the phrase and every admin device loses the Space; the kit only matters when no admin device survives, so a hostile admin rewriting it gains nothing. Review round was SOUND with three minors applied (pin the kit file format at load, un-strand a copy-pasted doc comment, and word the vault-id refusal as a file mismatch — at that point the phrase has not even been parsed).

### D63. Recommend, Never Enforce (S4-6 advisory org policies) (2026-09-29)

The owner publishes recommended settings as a plaintext git-tracked `meta/policies.json` riding the meta/** Admin row — the S3-6 catalog pattern exactly: the file's existence is the setting, an empty publish removes it as the opt-out, values validate fail-closed against the shipped §6.5 knob table (including single-valued restore_policy, so a settings-output roundtrip publishes). Member surfaces read it keylessly and render a "recommended" hint beside the matching row; the mobile card shows only the recommendations that DIFFER from the current value, because a small screen should show what is worth acting on. Advisory is the whole point: no gate anywhere reads the file for decisions — enforcement stays with the shipped knobs — so a stale or absent recommendation can never degrade security or wedge a member.

Two rules from the review round are worth keeping. (1) The recommendation table must accept everything the settings table can EMIT, not just what its own publisher sends — a script round-tripping the settings output is a legitimate caller, and a partial table turns that roundtrip into a refusal. (2) Recommendations render through their chip labels, never as raw wire strings — "Recommended: write_scope_can_trash" is developer language on a non-technical surface. And the recurring integration rule got one more member: policies.set joined daemon COVER_MUTATION_ACTIONS, the token-gate pin list, the desktop allowlist, AND daemon.js MUTATION_ACTIONS — four lists, checked one by one.

Boundaries: publishing is desktop-first (the mobile bridge carries the read for hints; a mobile publish card waits for demand); policies.json is plaintext by design (recommendations are not secrets) and rides the Admin row, so a member writing it locally would see the commit refused at peers — the pre-P5 wedge shape, now filtered at staging per D60; no per-member policy acknowledgment or compliance report (that is a hypothetical S5 need).

### D62. Who Can See What, On Demand (S4-4 access review + the S4-8 exposure summary) (2026-09-29)

The report answers "who can see what" in one place: members (roles, trust, tombstones), collections with decrypted names and every grant (access, expiry), pending asks (quorum approvals, the join queue, access requests), and owner-side outbox mirrors — computed on demand on the admin device from disk state, nothing persisted, JSON export for audits. The S4-8 fold-in rides the same report: a removed or reset member's grant ROWS survive the tombstone by design (only the expiry sweep prunes, and revocation never rotates the collection key), so each surviving row names a collection the departing member could read while active. The report surfaces those as the rotation list — read bytes cannot be un-read; changing the passwords is the mitigation the design resolved on. Raw key material never enters the report (no content keys, no wraps, no identity seeds — pinned by an assertion in the core test).

Three review-round rules are worth keeping. (1) Aggregation gates compose: the report's top gate admits the legacy founder (no member directory), but a sub-call (the JIT ask inbox) resolves the acting device's member id and refuses on exactly those legacy vaults — an aggregate endpoint must guard each sub-reader against the audience its own gate admits, or the founder gets a failed report instead of an empty section. (2) A report row's own label must carry every placeholder it renders — an interpolation helper without vars returns the template verbatim, so "{name}" showed literally, and a prefix name plus a sentence starting with {name} doubled it. (3) Role-gated cards follow their section's siblings: PeopleTab already had yourRole, so the review card hides for non-admins instead of letting them hit a refusal toast.

Boundaries: contact-key grants and outbox LINKS are other devices' local state and stay out (the report shows owner-side mirrors only); pre-flip members held the Root Key so every flat cipher was readable — the flipped flag lets a future surface state that honestly; the removed member's retained content-key knowledge (future writes to a granted collection stay decryptable to them) is the documented eventual-revocation residual the rotation list mitigates; mobile gets the bridge method in a later slice (admin-heavy analysis UI is desktop-first).

### D61. Two Keys to the Owner's Chair (Q5 owner recovery + the S4-3 ratchet) (2026-09-28)

The power pack's first wave closes the owner-recovery gap and hardens the quorum knob, per the locked spec in plan-power-pack.md §13. Ownership continuity now has two purpose-built paths. `ownership_claim(new_owner_id)` is a new gated core op for "owner gone forever": admin-actor only, its own quorum ask, executing through `commit_ownership_swap` — the renamed pure mutator under the promote-first/demote-second single-Owner invariant that voluntary `transfer_ownership` (untouched) also uses, with the pair-Space Editor demotion carrying over. `member_reset` accepts Owner targets for admin callers: the successor row inherits the Owner role, so an owner who returns rejoins as self — the family path. `create_invite` admits an Owner-role invite only when it is successor-bound (binding an existing row mints nothing). The S4-3 ratchet is intrinsic: lowering `quorum_admin_ops` calls the quorum gate at the CURRENT bar (the disk knob still holds the old value at gate time), so a genuine lowering always needs a co-approver while raising stays instant; no separate lock knob.

Five rules from the review round are worth keeping. (1) The co-approver repeats the SAME ask: a claim's params name the claimant, so the claimant id is an explicit parameter and the ask's params now ride the pending record — a digest-only record cannot be confirmed by a peer, and every UI confirm flows from the pending row's params (initiated_by as the pre-params fallback). (2) Self-guards and target pre-flights fire BEFORE the gate: a self-reset fails outright instead of recording a pending ask to reset yourself, and a nonexistent or tombstoned claimant refuses before any approval can burn. (3) Dead buttons are defects: Remove on the Owner row always failed at the core, so the surfaces never render it; Reset on the Owner row is legal and renders on both platforms. (4) The desktop People surface had NEVER been in the D2 allowlist — every members/requests/notices/activity call was denied since the tab shipped, invisible to every suite because no test drives the real Tauri command; this wave's allowlist work admitted the whole surface. (5) Convergence is the test author's job: a claim mutates the confirming device's clone, so ceremonies ship the swap commit back and assert roles only after the peer pull (a role swap rotates no keys, so no re-unlock is needed).

Boundaries: at threshold ≥ 2 a vault with a single admin stalls on owner recovery — the pending ask surfaces in Space settings and the doctrine answers "have two admins before you raise the bar"; the demoted owner's devices keep their old key knowledge (theft-shaped displacement is followed by member_remove: seat strike + rotation); the contest window (owner-device notice and cancel) is an advanced opt-in for a later wave, deliberately not v1.

### D60. The Stage Is the Policy (P5 explicit staged path sets) (2026-09-28)

The last open P item: staging was blind (`add_all("*")`), so a device could author a commit containing paths its policy refuses — the commit landed locally but every peer refused it at pull, wedging the branch behind an unpushable commit. Now `commit_all` stages ONLY the changed paths the signer's own policy admits, evaluated with the same per-path logic the peer verification walks apply: the structural predicates (member-record deltas, integrity manifest, registry own-bump) were factored into pure byte-level functions shared verbatim by both sides, then `authorize_scoped` with the collection scope. A commit is policy-clean by construction while peers keep verifying every delta — defense in depth, not a replacement.

Four rules from the review round are worth keeping. (1) Admission context splits by who can author what. Role and member resolve from the HEAD TREE through the walks' members snapshot — never the worktree, or editing meta files on disk would self-promote a device. Collection dirs, own writable grants (Manage implies write), and the flip marker read from the WORKTREE meta files — the prospective own-tree of the commit being staged — because the walk reads the verified commit's OWN tree for exactly those, and an admin seeds a collection and its first cipher in ONE commit (HEAD-tree-only scope read the dir as unknown and reverted the owner's own cipher; the full-disk first draft let hostile meta edits widen staging). Managed authority stays on the HEAD tree (the walk reads the parent), so a manager cannot self-grant in this commit; a forged disk grant cannot ride into history anyway because the scope FILE itself stages only through the Admin table row, and a hostile local edit at worst recreates the pre-P5 wedge (peers refuse, old behavior). (2) The merge-commit path stages unconditionally: `repo.merge` places every unconflicted remote entry in the index, and resetting or filtering there silently DROPPED the remote half of the merge — the P8a residue check at peers is the governing control for merge commits. (3) Skipped paths get worktree hygiene: tracked files revert to their committed content, untracked files are removed. A file the device may not author cannot sit dirty forever — that stuck the sync badge and pushed an empty commit on every autosync tick. (4) Genesis admits all: with no HEAD the founder's initial commit defines the policy state (and the creator engine signs with the device NAME, not a uuid, so member resolution is meaningless there); peers grandfather the root commit.

Boundaries: a tombstoned signer stages nothing (the walks deny outright); non-UTF-8 paths never stage and stay dirty (they can never be authorized); every skip is eprintln-warned — fail loud, not fatal; the review round's findings (merge data loss, Manage-not-writable under-admission, disk-state trust, the autosync empty-commit loop) plus the one the fixes surfaced (an admin seeding a collection and its first cipher in one commit was under-admitted by the HEAD-tree-only scope) are all fixed and pinned in the staging ceremony and member-access ceremonies.

### D59. Two Admins, Two Signatures (S4-1 quorum + creation authority) (2026-09-27)

The §10 answers became two knobs. `quorum_admin_ops` (default 1 = off; admin raises 2..=5) makes sensitive ops — removals, resets, transfers, root rotation, device revocation, sync-address moves — collect DISTINCT admin approvals through plaintext `meta/approvals/<digest>-<initiator>.json` records riding the meta/** Admin sync row: the first admin's call writes the ask and refuses, further admins confirming the SAME kind+params-digest append, and the confirming call consumes the record and executes on its own device. The per-initiator filename keeps two admins' uncommitted local asks from colliding at pull. `collection_create_authority` opens collection creation to editors on demand. Both enforce locally like every §6.5 knob; the sync walker stays keyless.

Four review-round rules are worth keeping. (1) The live threshold always governs: an approval compares against max(live knob, record's copied threshold), so a lowered or tampered `required` can never approve below what the settings demand now. (2) A chain gates exactly once: the strike-ordering precheck consumes the approval and marks (kind, digest) satisfied on the handle; the op's internal re-validation skips the gate only on a matching mark, so a direct core caller still gates. (3) Ops that rotate internally (removal's offboarding rotation) call the un-gated worker — re-entering the gate mid-offboarding would demand a second, unrelated approval after tombstones landed. (4) A quorum refusal must ship the ask: the runtime wrappers fire a best-effort signed sync cycle on the refusal path, because COVER autosync only runs on success and an unshipped ask is an ask nobody can confirm.

The stale-root corollary surfaced as a test failure: the gate's settings read is the first ENCRYPTED read on op paths that were plaintext-only, so a device whose handle predates a pulled rotation commit hits an authentication mismatch until it re-unlocks (production devices re-lock and adopt the new root; the ceremony test now does the same). Fail-closed stands — a stale root cannot distinguish itself from tampering.

**Boundaries**: approvals burn on failed attempts (a seat-strike failure consumes the confirmation; the retry needs fresh co-approval — the state may have changed); the pending-asks card is desktop-first with the mobile bridge method landed but no card yet; groups, dual-control generalization beyond this knob, access review, the full timeline, advisory policies, and the mobile multi-Space host remain S4.

### D48. Item-Sharing Surfaces over Finished Rails (S2 UI) (2026-09-26; S3 in progress)

The S2 core and daemon layers shipped with no interface; this wave proves the rails pattern in reverse: when the daemon already validates every flavor with plain-language refusals, the client can auto-detect which kind of shared file it holds by trying the flavors in order and reading the failures, instead of asking the user to classify a file format they have no vocabulary for. The receive chain (package import, then contact reveal, then passphrase-guest open) works because the flavors are cryptographically domain-separated — a reveal file cannot succeed as a package import — so trying the wrong one first is always safe. That property is worth defending: any new shared-file flavor should stay mutually exclusive at the crypto layer so client-side detection never needs a magic-number header.

Two small rules re-confirmed at UI layer. Secrets on the clipboard go through the shared auto-clear utility, never a raw write — the utility exists precisely so reviewers only have one clipboard path to audit. And a multi-stage file flow must reset its stage state when the file changes, or a retry silently routes the new file down the previous file's path.

**Boundaries**: contact-key reveals and package send defer until an address-book surface exists (core contacts_list has zero routes today); outbox management UI (publish/revoke mirrors) remains unowned; the reveal view is transient by design and shows no TOTP countdown; the shared-file flavor list is open — new flavors plug into the detection chain in daemon refusal order.

## Staged Implementation Roadmap

- **Phase 1: Cryptographic Core & Padding Engine**: Rust baluard-core (crypto, keys, vault, padding). Protobuf schemas. DONE.
- **Phase 2: Git Sync Engine**: git2-rs sync, conflict auto-healing, state machine. DONE.
- **Phase 3: IPC Daemon & CLI**: baluard-daemon (tokio Unix socket server), baluard-cli (socket client), Protobuf gateway handler. DONE.
- **Phase 4: Desktop UI & Open-Source Launch**: SolidJS/Tailwind Tauri v2 app, system tray, GPL-3.0 license. DONE.
- **Phase 5: Browser Extension & Mobile**: MV3 browser extension (Chromium + Firefox) with native messaging (Phases 0+1 DONE, Phase 2 deferred). Mobile: UniFFI Rust bindings (`baluard-uniffi`) and Compose Multiplatform Android app (Phases 0-6 implemented: core UI, deep search, desktop-parity edit, biometric unlock, and system autofill service with quick-settings tile fill; Phase 7 iOS next).

---

## DOMAIN 8: TAGS & CIPHER CATEGORIZATION

Tags are user-defined labels for organizing ciphers. Unlike folders (single assignment), a cipher can have up to 20 tags.

### Storage Model

- **Encrypted at rest**: `tags: Vec<String>` on the cipher envelope (`CipherEnvelopeData`). Tags are encrypted alongside cipher content.
- **Plaintext cache**: `meta/tag_index.json` stores a sorted list of unique tags for fast autocomplete/filtering. Same visibility tradeoff as folder names (plaintext, committed to git).

### Constraints

- Max 20 tags per cipher
- Max 64 chars per tag (`.chars().count()` for UTF-8 correctness)
- Lowercase-normalized on storage; display preserves user input
- No empty or whitespace-only tags
- Case-insensitive dedup

### Key Components

| Component | Location | Role |
|-----------|----------|------|
| `CipherInput.tags` | `types.rs` | Input field with `#[serde(default)]` |
| `CipherEnvelopeData.tags` | `types.rs` | Encrypted envelope field |
| `Cipher.tags` | `types.rs` | Decrypted cipher field |
| `CipherMeta.tags` | `types.rs` | Metadata for list views (post-decryption) |
| `TagIndex` | `manifest.rs` | Cache struct for `meta/tag_index.json` |
| `VaultHandle::validate_tag(s)` | `handle.rs` | Validation + normalization |
| `VaultHandle::rebuild_tag_index` | `handle.rs` | Rebuilds cache from decrypted ciphers |
| Daemon routes | `handler.rs`, `state.rs` | `tag.list/create/rename/delete/rebuild_index` |
| CLI | `commands/mod.rs` | `baluard tags list/create/rename/delete` |
| Desktop: tag sidebar | Sidebar tag pills with click-to-filter + hover X for deletion |

### Validation Boundary

`add_cipher` and `update_cipher` call `validate_tags` before writing. This enforces length, dedup, and normalization at the core library boundary regardless of caller (daemon, CLI, direct).

### Index Rebuild

- Triggered on every `vault.list_full` (desktop unlock) and after every `add_cipher`/`update_cipher` via daemon.
- `tag_index.json` is rebuilt from decrypted cipher tags (ground truth).
- Sync merge for `tag_index.json`: deferred to future phase. Current behavior: rebuild-from-truth after every pull.
