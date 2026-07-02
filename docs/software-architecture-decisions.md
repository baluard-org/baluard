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
- **Engine seam** (Phase 2a): `run_sync_cycle_with_resolver` + `ConflictResolution { KeepLocal, Pause }` + `PendingConflictState` + `SyncCycleOutcome::NeedsDecision`. Additive; the cycle still falls back to keep-local when the caller doesn't opt in. `finalize_conflicts` is HEAD-guarded against double-resolve.
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
- **Periodic pull** every 30 min when idle + online — a quiet fallback, NOT the primary sync path. Event-driven pulls do the real work: pull immediately on vault unlock, on window focus (desktop fires `sync.autosync_nudge_pull`, server-side 10-min guard collapses flicker), and the push cycle itself commits→pulls→pushes so concurrent edits land right after a local mutation. Serverless architecture (git remote IS the server, no push channel), so unlike Bitwarden's SignalR inbound we must poll; 30 min is quiet enough to avoid a predictable periodic heartbeat (T14 timing-fingerprint) while the event triggers cover snappiness.
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

### D8. Mobile Tier: UniFFI Bindings (Planned)

**Decision: Mozilla UniFFI for Rust-to-Kotlin/Swift bridge**

Mobile apps will bind directly to baluard-core via UniFFI-generated native bindings:
- **Kotlin (Android)**: UniFFI generates Kotlin data classes and function bindings from `#[uniffi::export]` proc-macros on baluard-core's public API. Compiled into the KMP project as a static library.
- **Swift (iOS)**: UniFFI generates Swift bindings compiled into an xcframework.
- **No intermediate language**: The Rust core is the single source of truth. No Go, no cgo, no gomobile. UniFFI's serialization-based FFI provides a clean security boundary between Rust memory and foreign memory.
- **JIT Autofill**: The UniFFI-exposed `sync::fetch_and_decrypt()` method will be called directly from the Kotlin/Swift autofill adapter before biometric prompt.
- **Current state**: baluard-core has no `#[uniffi::export]` annotations yet. Mobile app is a placeholder scaffold.

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

**File**: `meta/device_activity.json` — Plaintext, UUID-only activity index. Last-writer-wins per UUID key. One file, merged on every push.

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
- Abort marker: `.baluard/rekey/{new_epoch}.aborted`

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
Phase 1 — PROPOSE (initiating device, online now):
  1. Generate RK'
  2. For each enrolled device:
     HPKE(RK', device_x25519_pk) → wrapped_keys[device_id]
  3. Build RekeyTransaction:
     { old_epoch, new_epoch, wrapped_keys, initiator, timestamp }
  4. Write .baluard/rekey/{new_epoch}.txn
  5. Git commit + push
  6. Transition epoch → ROTATING
  7. Vault: READS allowed (old epoch), WRITES blocked

Phase 2 — ACKNOWLEDGE (each device, async, on next sync):
  1. Pull from remote
  2. Read .baluard/rekey/{new_epoch}.txn
  3. Unwrap own HPKE(RK', my_pk) → verify RK' is sane
  4. Compute txn_hash = SHA-256(serialized .txn file)
  5. Sign: Ed25519(my_signing_sk, "ack" || epoch || device_id || txn_hash)
  6. Write .baluard/rekey/{new_epoch}.ack.{device_id}
  7. Git commit + push

Phase 3 — COMMIT (any device observing quorum):
  1. Pull from remote
  2. Collect all .ack.* files for this epoch
  3. For each ack:
     - Verify Ed25519 signature against enrolled device's signing key
     - Verify txn_hash matches the .txn file (prevents ack transplant)
  4. If verified ack count >= quorum (ceil(N/2)):
     - Re-derive SGKs under new RK'
     - Write .baluard/rekey/{new_epoch}.committed
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
1. **QR codes** — small payloads (enrollment, ack bundles)
2. **File export/import** — larger payloads (pairing bundle, git bundle)
3. **USB drive** — `git bundle` for full vault sync

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

**Motivation.** The original D14 design required an enrolled device to
approve any new device. This is hostile to single-user, serverless
workflows: a solo user who loses all devices cannot add a new one
without a pre-existing device to produce the approval signature.
The product intent (no central server, easy to use, future-proof)
demands that the recovery phrase — which is already the root
authority for `recover_from_phrase` — also work for non-destructive
enrollment.

**Two-path enrollment controlled by `VaultSettings::enrollment_policy`:**

- `Personal` (default for new vaults): either an enrolled-device
  signature OR the recovery phrase can authorize enrollment. The
  recovery phrase is the root authority and can already perform
  full disaster recovery; non-destructive enrollment via phrase is
  a strict subset of that authority.
- `Strict` (default for existing vaults, backward compat): only an
  enrolled-device signature can authorize enrollment. Recovery
  phrase only works via destructive `recover_from_phrase`.

**New method:** `DeviceManager::enroll_with_recovery_phrase(payload, phrase)`.
Non-destructive — enrolls into the existing registry without resetting
devices. Unwraps Root Key from `meta/recovery.json`, writes a new
keywrap for the new device, persists state. Reuses the same
timestamp/nonce replay protection as `enroll()`.

**Mandatory write-down verification.** During vault creation, the
user MUST re-enter 4 random words from the recovery phrase before
they can proceed. Positions are deterministic (FNV-1a hash of the
phrase) so the same phrase always asks for the same words. Applied
in both desktop (`RecoveryScreen.jsx`) and CLI (`init` flow). This
is not security theater — it's the only defense against permanent
vault loss when all devices fail.

**CLI surface:** `baluard devices enroll-with-phrase [--phrase <24 words>]`.
Prompts for phrase if not provided. Requires typed `enroll` confirmation
(warns user that the phrase is root authority). Enforces policy:
rejects if `Strict` with a clear error directing to `baluard recover`.

**IPC surface:** `vault.enroll_with_phrase` (daemon route). Validates
24-word shape, checks `enrollment_policy`, builds `EnrollmentPayload`
for the current device, calls `enroll_with_recovery_phrase`, writes
`meta/device-privkey.json`.

**Threat model.** The recovery phrase is already the root authority:
`recover_from_phrase` exists for full disaster recovery. Phrase-based
enrollment is a strict subset of that authority. If the phrase is
compromised, the vault is already compromised. The master password
alone remains insufficient to add a device.

**Files:**
- `crates/baluard-core/src/vault/manifest.rs`: `EnrollmentPolicy` enum
- `crates/baluard-core/src/device_manager.rs`: `enroll_with_recovery_phrase`
- `crates/baluard-daemon/src/{state,handler}.rs`: IPC route
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
.baluard/
  rekey/
    {epoch}.txn            # Rotation proposal (HPKE-wrapped RK' per device)
    {epoch}.ack.{device}   # Device acknowledgment (signed, with txn_hash binding)
    {epoch}.committed      # Finalized rotation (populated commit_barrier)

meta/
  devices.json             # DeviceRegistry (enrolled devices, keys)
  epoch.json               # EpochInfo (current epoch state)
  seen-nonces.json         # Anti-replay enrollment nonces
  keywrap/
    {device_id}.json       # HPKE-wrapped Root Key per device
  settings-pub.json        # Plaintext display prefs (theme, lang) — pre-unlock readable
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

Created `lib/filters.js` with pure functions: `selectSource`, `filterByCategory`, `filterByFolder`, `searchCiphers`. `CATEGORY_TYPE_MAP` as single source of truth mapping UI category names to daemon cipher type strings. VaultView inline 45-line filter replaced with 6-line composed pipeline. 18 new vitest tests.

#### Candidate C: State Transition Guards (Completed)

`VALID_AUTH_TRANSITIONS` table in AuthContext (7 states, documented valid edges including `init -> locked`, `recovery -> setup`). `VALID_PANE_TRANSITIONS` table in VaultContext (4 states). `guardedSetStatus`/`guardedSetPane` wrap all internal state transitions. Dev-only `console.warn` on invalid transitions.

#### Candidate A: Cipher Schema (Completed)

Created `lib/cipherSchema.js` with schemas for all 8 cipher types. Each schema defines: `fields[]`, `fromKind(structured→flat)`, `toKind(flat→structured)`. Replaced `CipherDetail.startEdit()` 80-line manual field mapping with `cipherToFlat()`. Replaced `payload.buildKind()` 100-line if/else chain with `schema.toKind()`. 14 new vitest tests including roundtrip tests for all 8 types. Single source of truth for field name mappings (was 3-file implicit contract). `AddEditCipherForm.jsx` still uses 8 `<Show>` blocks for field rendering — schema-driven form rendering is future work.

#### Future Work

- Schema-driven form rendering: replace 8 `<Show>` blocks in AddEditCipherForm with schema-driven field iteration (would reduce ~850 lines to ~300)
- `filteredCiphers` in VaultView could use `createMemo` for caching (called twice per render)
- Transition guards are advisory-only — raw setters still exported for external navigation

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

> **2026-06-26 update:** the rest of `settings.json` was also split for privacy — see D16. Display prefs (`theme`, `lang`) → plaintext `meta/settings-pub.json`; vault identity/policy (`slug`, `enrollment_policy`, `vault_timeout`, `fetch_favicons`, `default_uri_match`) → encrypted `meta/settings.enc`.

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

**Files NOT touched (already safe):** `kdf-params.json` (salt + cost are public by design; encrypting them is circular), `recovery.json` (already an HPKE-wrapped blob; the public keys it contains are public by definition), `keywrap/*.json` (same — wrapped material).

### D19-bis. Phase 6 Multi-Vault Switching (2026-06-17; DONE)

See `docs/plan-git-providers-multi-vault.md` Phase 6 for the full design and acceptance criteria. Implemented in `crates/baluard-daemon/src/host.rs` + 11 integration tests in `crates/baluard-daemon/tests/phase6_switching.rs`. The keep-unlocked / switch-pointer model replaces the pre-Phase 6 single `Arc<VaultState>`:

- `VaultHost` wraps a single `RwLock<VaultHostInner>` over `vaults: HashMap<String, Arc<VaultState>>` + `active: Option<String>`. One lock guards both (no two-lock race; the `active`-is-in-the-map invariant is provable).
- `vaults.switch` is a pointer flip: validate slug + set `active` under one write lock, touch registry `last_opened` OUTSIDE the lock. No zeroization, no token change.
- Per-vault session tokens (`vault.unlock` returns `{slug, token}`). Desktop keeps `Map<slug, token>`. Token check is per-vault; vault-A token rejected for vault-B op.
- Handler snapshots the target `Arc<VaultState>` clone once per request (no TOCTOU from mid-request `switch`).
- `vaults.close` is Arc-drain — removes the entry, clears `active` if needed, returns immediately. In-flight handlers finish and zeroize on last drop.
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
- **Skips Argon2id master KDF.** PIN unlock calls `VaultHandle::unlock_with_kek`, which still verifies keywrap + canaries (a stale KEK — master password changed on another device — fails closed).
- **Session-bound:** dies on daemon restart / vault close. **Survives soft-lock** (escrow is a separate `VaultState` field from the handle).
- **5-strike nuke:** after `pin::MAX_PIN_FAILURES` (=5) wrong PINs the escrow is destroyed and the master password becomes mandatory. The 10^6 keyspace cannot be brute-forced through this in-process cap.
- **Routes:** `vault.pin_status` (not token-gated), `vault.pin_enable` / `vault.pin_disable` (token-gated), `vault.pin_unlock` (host-level, not token-gated, mirrors `vault.biometric_unlock`).

**Frontend (desktop):** the login screen queries both `vault.biometric_status` and `vault.pin_status` (slug-routed, pre-unlock safe) and shows whichever buttons are enabled for the selected vault.

**Why two mechanisms.** Biometric is the primary UX on macOS (Touch ID). On Linux there's no biometric keychain; the in-memory PIN fills the same role (cheap re-unlock while the daemon is alive) without weakening the master-password-derived KEK chain. Windows-without-Hello gets the same PIN fallback because `keyring` `windows-native` does not gate reads biometrically.

**Vault Detach (asymmetric UI vs CLI):** Detaching a vault (drop registry entry) is exposed in the `VaultSwitcher` dropdown (`DetachVaultModal`). The destructive arm (`delete_from_disk`) is deliberately NOT exposed in the UI — only the safe, reversible detach. The power-user escape hatch is the CLI: `baluard vaults detach <slug> --delete-from-disk` (gated by slug retyping + the daemon-side `.baluard` marker check). A future revision may add a master-password-reprompt gated destructive arm back to the UI; until then the UI is destructive-action-free. The daemon route `vaults.detach` still supports both flags for the CLI caller.

### D21. Browser Extension: Paired-Companion Bridge (2026-06-XX; Phases 0+1 DONE)

**Decision: KeePassXC-Browser-style MV3 extensions talk to `baluard-daemon` via a new `baluard-nmh` native messaging host. The extension is a paired companion — it never unlocks, never holds the master password, never holds the vault session token. It rides the desktop's unlock state via a scoped bridge token.**

**Motivation.** Baluard has no server; Bitwarden/1Password's "extension talks to company API" model does not apply. The correct reference architecture is **KeePassXC-Browser**: extension -> native messaging host (stdio) -> local socket -> app. A 0600 Unix socket cannot be opened by a WebExtension (no raw-socket API in MV3); the only cross-browser escape hatch is `nativeMessaging` (Chrome `runtime.connectNative`/`sendNativeMessage`, Firefox identical).

**Architecture (see `docs/plan-browser-extension.md` for the full design):**
- **`baluard-nmh`** — standalone Rust binary. stdio-JSON <-> varint-protobuf. Stateless.
- **`core/bridge/`** (new module: `mod.rs`, `pairing.rs`, `token.rs`) — pairing file format + atomic writes, bridge token mint/verify, action allowlist.
- **Scoped bridge token (`TokenKind::Bridge { pairing_id }`)** lives on a host-level bridge registry (`VaultHost::bridges`, `HashMap<pairing_id, BridgeTokenEntry>`). Vault-agnostic (extension follows the desktop's active pointer per D6-bis Phase 10). TTL parity with the per-vault session token (`SESSION_TOKEN_TTL_SECONDS`, 4h).
- **Action allowlist** (server-enforced in `verify_session_token` after token verification): `bridge.match`, `vault.get` (single, on fill/copy only), `vault.add`, `vault.update` (field-gated: password/username/notes/totp OK; `fido2_credentials` + `uris` REJECTED for bridge tokens), `cipher.totp_code`, `generator.history_add`, `generator.history_clear`, `sync.autosync_status`, `bridge.config`. **Excluded (rejected even with a valid bridge token):** `vault.list_full`, `vault.delete`, `vault.export`, `vault.change_password`, `device.revoke`, all `sync.*` mutations, all `provider.*`, `vault.attach_*`, `ssh.generate_key`, `passkey.*`, `vault.clone_*`, `folder.*`, `tag.*`, `vault.archive`/`unarchive`, `cipher.clone`, `settings.*`, `vault.trash.*`, `generator.history_list`, `favicon.get`.
- **Pairing flow:** approve-don't-type. Desktop user clicks "Add browser extension" -> `bridge.pair_start` (desktop-session-token-gated, one-shot pending-approval flag, short TTL). Extension calls `bridge.pair_complete` (held pending). Desktop UI shows "A Baluard extension wants to connect" with Approve/Deny. Approve consumes the flag, writes pairing file, returns pairing secret to the NMH. **No codes to transcribe, no brute-force surface, no vault nuke on ceremony abuse** (the prior 5-strike nuke was a DoS landmine for non-tech users — removed in sonnet B-2).
- **Per-`pairing_id` rate cap on `bridge.match` + `vault.get`** via the existing `RateLimiter` (~10-20/min). Bounds a browser compromise to a handful of credentials, not the whole vault. Burst abuse escalates to `bridge.revoke`.
- **Fill policy:** popup-driven, per-fill user gesture. **No auto-fill on load.** Top-frame-only content script (`frameIds: [0]`). Fill-time origin re-check (content script re-verifies `location.origin` against the credential's stored URI before writing to the DOM, fails closed on mismatch). Closes the classic credential-theft vector of cross-origin login iframes + the popup-match/navigate-during-IPC race.
- **Pairing file ownership:** daemon is the sole writer (`<data_dir>/bridge/pairings.json`, atomic tmp+rename). Desktop mutates only via daemon routes. NMH reads its own entry read-only.
- **Lifecycle:** `connectNative` spawns a fresh NMH (browser SIGTERM/SIGKILL on disconnect). On spawn: NMH reads pairing entry via core, presents secret to daemon, daemon re-mints ephemeral bridge token. Token dies with the NMH; pairing file is durable and revocable.

**Why not a direct `vault.list_full` for the extension?** It returns the entire decrypted vault in one call (a de-facto export, and the real blast radius). Instead the extension sees metadata + one credential at a time.

**Why allowlist not deny-list?** Pre-1.0 WIP (per STATUS), expansion is a deliberate allowlist change + same-change call-site update. The friction is intentional — it forces a conscious security decision per route.

**Files:**
- `crates/baluard-core/src/bridge/{mod,pairing,token}.rs` — pairing + bridge token
- `crates/baluard-daemon/src/bridge.rs` — bridge routes + allowlist enforcement
- `crates/baluard-nmh/` — native messaging host binary
- `browser/{shared,chrome,firefox}/` — MV3 extension codebases (shared 95%, target wrappers)
- `desktop/src/components/BridgeTab.jsx` — paired-extension management UI

### D22. Conflict Resolution Panel (2026-06-XX; UI BUILT, backend wiring DEFERRED)

**Decision: Build the human-in-the-loop UI panel for destructive field-level merge outcomes now; defer the backend wiring (still falls back to `resolve_conflict_keep_local`) until Phase 1 of conflict resolution lands.**

**Motivation.** The auto-sync path today silently keep-locals on any file-level conflict, which can lose non-overlapping field edits from the remote device (F1: same item, non-overlapping fields — HIGH severity). A non-technical user has no way to see this happened. `merge_ciphers` exists and is tested (`sync/conflict.rs`), but is never wired into the cycle. The panel is the user surface for the destructive cases Phase 1 of conflict resolution will eventually surface; it can be built first because it consumes a structured `PendingConflict` queue that's purely frontend-derivable from the current `sync.autosync_status` payload for the mock case.

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
- **30-min idle fallback** (`PULL_INTERVAL_SECS`) catches the rare "left open on two machines" case. Deliberately quiet — no predictable periodic heartbeat.
- **`cycle_lock` tokio Mutex** (C3 fix) guarantees only one sync cycle touches the on-disk repo at a time; losers bail cleanly.
- **Activation in `VaultState::unlock`** (immediate, not lazy); deactivated on lock.
- **No daemon-side decrypted cache** — `get_cipher` / `list_folders` read from disk every call, so after a pull the handle serves fresh data without a reload (root_key/SGK stay valid).

**Frontend:** desktop polls `sync.autosync_status` every 10s (`AutoSyncContext`); status pill in sidebar header (`AutoSyncIndicator`); non-blocking conflict banner (`ConflictBanner`). No Tauri event channel (request/response only).

**Why we still need the 30-min fallback:** with N unlocked vaults under the keep-unlocked model (D19-bis), an event-driven-only pull can miss the "device A made an edit, device B sat idle" case if device B's events never fire. The 30-min timer is the quiet backstop, not the primary sync path.

### D24. Sync Header Refactor + Favicons (2026-06-XX; DONE)

**Sync header:** replaced git jargon ("push", "pull", "remote", "branch") with a one-click sync UI. Sidebar header shows provider + repo link (`cc09c51`). `AutoSyncIndicator` status pill (idle / syncing / dirty / offline). Sync label gated with `<Show>` inside `<Transition>` to silence background pulls. Provider state scoped to active vault (`58016d4`) — multi-vault provider state was previously leaking across switches.

**Favicons:** opt-in persisted website icons fetched at save time. New `favicon` field on cipher envelope (16KB cap, magic-byte check, default-off). `desktop/src/lib/cipherSchema.js` + `Avatar`/`CipherRow` chip treatment. Solves the "every login in the list looks the same" UX problem without bloating every entry with a base64 payload.

**App icons:** `just app-icons SOURCE OUT` builds 48/128 PNG variants from a source logo for all platforms (macOS/Windows/Linux/Android/iOS + tray monochrome + system tray). Replaces the previous hand-curated icon set with a deterministic pipeline; `desktop/src-tauri/icons/` regenerated on build.

---

## Staged Implementation Roadmap

- **Phase 1: Cryptographic Core & Padding Engine**: Rust baluard-core (crypto, keys, vault, padding). Protobuf schemas. DONE.
- **Phase 2: Git Sync Engine**: git2-rs sync, conflict auto-healing, state machine. DONE.
- **Phase 3: IPC Daemon & CLI**: baluard-daemon (tokio Unix socket server), baluard-cli (socket client), Protobuf gateway handler. DONE.
- **Phase 4: Desktop UI & Open-Source Launch**: SolidJS/Tailwind Tauri v2 app, system tray, GPL-3.0 license. DONE.
- **Phase 5: Browser Extension & Mobile**: MV3 browser extension (Chromium + Firefox) with native messaging (Phases 0+1 DONE, Phase 2 deferred). UniFFI Kotlin/Swift bindings, KMP mobile app — not started.

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
