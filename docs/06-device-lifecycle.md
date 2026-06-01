# Device Lifecycle & Root Key Rotation

**Status**: Candidate 3 — Peer reviewed (peer review), 3 rounds of fixes applied
**Last updated**: 2026-06-01
**Reviewers**: Peer review (architecture advice + 2 rounds), TARS (implementation), peer review (of MISS-1 through MISS-5)

---

## Hard Constraints

1. **No server backend.** Desktop and mobile apps work standalone, fully offline. Git sync with GitHub/GitLab is optional and must be easy for non-tech users.
2. **Single-device is the default.** Multi-device is opt-in via git sync or local transport.
3. **All crypto is local.** Rust core via UniFFI. Zero platform-native crypto on mobile.

---

## Architecture

### DeviceManager Aggregate

```
DeviceManager
├── DeviceRegistry      (pure data: HashMap<Uuid, DeviceEntry>, serializable)
├── EpochInfo           (pure state machine: CREATED→ACTIVE→ROTATING→RETIRED→DESTROYED)
└── RotationCoordinator (two-phase commit logic, owns the transaction)
```

`DeviceManager` lives in `crates/idtty-core/src/device_manager.rs`. It owns the coordination between registry, epoch state, and rotation. Individual components (`DeviceRegistry`, `EpochInfo`) remain independently testable pure structs.

`VaultHandle` holds a `DeviceManager`. All vault ops check epoch state through it.

### Key Hierarchy

```
Master Password
  └→ KEK (Argon2id KDF)
       └→ Device Private Key (X25519, escrowed via HPKE in keywrap file)
            └→ Root Key (512-bit, per-epoch)
                 └→ Space Group Key (256-bit, per-space)
                      └→ Item Keys (256-bit, per-cipher)
```

Root Key is HPKE-wrapped per device (not KEK-wrapped). Epoch rotation generates a new Root Key and re-wraps it for all surviving devices.

---

## Three Operational Modes

The system behaves differently depending on device count and transport availability. All three must work correctly.

### Mode 1: Single Device, No Network

The default. 90%+ of users.

**Threat model:**
- Device stolen
- Master password compromised
- Local file corruption

**Key rotation triggers:**
- Master password change
- Manual key rotation (user action)

**Rotation flow (local transaction):**
```
1. Generate new Root Key (RK')
2. HPKE(RK', this_device_x25519_pk) → write new keywrap file
3. Re-derive Space Group Keys under RK'
4. Re-encrypt all space headers under new SGKs
5. Self-acknowledge → epoch ROTATING → RETIRED → new ACTIVE
6. Zeroize old RK, old SGKs
7. Commit to local git repo (no remote push)
```

This is a single atomic local transaction. No `.ack` files. No quorum wait. `quorum_required()` returns 1 for N=1. The self-ack is immediate.

**Critical**: Old password must NOT decrypt the vault after rotation. This requires Space Group Key re-derivation under the new Root Key. Without this step, the old KEK (from old password) still decrypts the old Root Key, which still decrypts old SGKs, which still decrypts all items. The rotation would be cosmetic. See [MISS-1: SGK Re-wrap](#miss-1-sgk-re-wrap).

### Mode 2: Multi-Device, Git Remote Configured

Multiple devices sharing a vault via GitHub/GitLab/self-hosted git.

**Threat model (adds to Mode 1):**
- Device lost or stolen → other devices must be protected
- Compromised device → forward secrecy after eviction
- Colluding devices (unlikely for single-user vault, relevant for orgs)

**Rotation flow (two-phase commit via git):**

```
Phase 1 — PROPOSE (initiating device, online now):
  1. Generate RK'
  2. For each enrolled device:
     HPKE(RK', device_x25519_pk) → wrapped_keys[device_id]
  3. Build RekeyTransaction:
     { old_epoch, new_epoch, wrapped_keys, initiator, timestamp }
  4. Write .idtty/rekey/{new_epoch}.txn
  5. Git commit + push
  6. Transition epoch → ROTATING
  7. Vault: READS allowed (old epoch), WRITES blocked

Phase 2 — ACKNOWLEDGE (each device, async, on next sync):
  1. Pull from remote
  2. Read .idtty/rekey/{new_epoch}.txn
  3. Unwrap own HPKE(RK', my_pk) → verify RK' is sane
  4. Compute txn_hash = SHA-256(serialized .txn file)
  5. Sign: Ed25519(my_signing_sk, "ack" || epoch || device_id || txn_hash)
  6. Write .idtty/rekey/{new_epoch}.ack.{device_id}
  7. Git commit + push

Phase 3 — COMMIT (any device observing quorum):
  1. Pull from remote
  2. Collect all .ack.* files for this epoch
  3. For each ack:
     - Verify Ed25519 signature against enrolled device's signing key
     - Verify txn_hash matches the .txn file (prevents ack transplant)
  4. If verified ack count >= quorum (ceil(N/2)):
     - Populate RekeyTransaction.commit_barrier with all verified ack signatures
     - Re-derive SGKs under new RK'
     - Write .idtty/rekey/{new_epoch}.committed
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
| 2 | 1 | Unilateral rotation accepted. See [SEC-1 note](#sec-1-two-device-quorum). |
| 3 | 2 | Majority |
| 4 | 2 | Majority |
| 5 | 3 | Majority |

**Single surviving device after eviction**: N=1, quorum=1. Self-ack is immediate. Rotation commits in one step.

### Mode 3: Multi-Device, No Git Remote (Local Transport)

Two devices on the same desk, no cloud.

**Transport options** (priority order):
1. **QR codes** — small payloads (enrollment, ack bundles)
2. **File export/import** — larger payloads (pairing bundle, git bundle)
3. **USB drive** — `git bundle` for full vault sync
4. **LAN** — future: mDNS discovery + encrypted local transfer

**Rotation flow:**
Same two-phase commit as Mode 2, but ack delivery is physical:
```
1. Device A initiates rotation, writes .txn locally
2. Export .txn as file or QR-encoded bundle
3. Transfer to Device B physically (USB, QR scan, shared folder)
4. Device B imports .txn, generates .ack, exports .ack
5. Transfer back to Device A
6. Device A imports .ack, checks quorum, commits
```

Rotation is not instant. It requires physical interaction. This is acceptable — security events deserve friction. The `ROTATING` epoch state persists between transfers.

**`git bundle` for full sync:**
The vault IS a git repo. Offline sync between two devices:
```bash
# Device A: create bundle
git bundle create vault.bundle --all

# Transfer vault.bundle to Device B (USB/LAN)

# Device B: pull from bundle
git pull vault.bundle main
```

No server. No cloud. Git handles delta compression and merge logic.

---

## Enrollment

### First Device

Automatic. No approval needed. The empty registry auto-approves the first enrollment. This creates the initial device entry with X25519 encryption key and Ed25519 signing key.

### Additional Devices

Requires physical presence + master password confirmation on an existing enrolled device.

**Transfer methods** (all first-class, user picks what works):

| Method | How | Best for |
|--------|-----|----------|
| **QR code** | Display string as QR, scan with camera | Phones, tablets |
| **Manual copy** | Display string as text, user copies/types on other device | No camera, accessibility needs, terminals |
| **File export** | Save as .json file, transfer via USB/LAN | Large payloads, batch enrollment |

All payloads are base64url-encoded JSON strings. Same data, same security, different UX. The code does not care which method the user chose.

**Two-way pairing flow:**

```
New device                          Existing device
   |                                      |
   | 1. Generate keypair                  |
   |    (x25519_sk, x25519_pk)            |
   |    (ed25519_sk, ed25519_pk)          |
   | 2. Display QR #1:                    |
   |    {device_id, x25519_pk,            |
   |     ed25519_pk, nonce, timestamp,    |
   |     name: "Esteban's iPhone"}        |
   |                                      |
   | ------- QR #1 scanned ------->       |
   |                                      | 3. Validate:
   |                                      |    - timestamp ±5 min
   |                                      |    - nonce not seen before
   |                                      |    - keys valid curve points
   |                                      | 4. Prompt: "Approve
   |                                      |    'Esteban's iPhone'?"
   |                                      | 5. User enters master password
   |                                      | 6. Sign: Ed25519(existing_sk,
   |                                      |    H("enroll" || payload || nonce))
   |                                      | 7. HPKE(current_RK, new_x25519_pk)
   |                                      | 8. Build pairing bundle:
   |                                      |    {wrapped_rk, approval_sig,
   |                                      |     updated_device_registry}
   |                                      |
   | <---- QR #2 / file export --------  |
   |                                      |
   | 9. Import pairing bundle             |
   | 10. Verify approval_sig against      |
   |     existing device's ed25519_pk     |
   | 11. Unwrap RK via own x25519_sk     |
   | 12. Enrollment complete              |
```

**No server, no relay, no network.** Pure local exchange. All crypto in Rust core via UniFFI. Mobile UI handles camera (QR scan), text display (manual copy), and file pickers. All three paths always available.

**Anti-replay:**
- Nonce: 32 random bytes, unique per enrollment attempt
- Nonces stored in `meta/seen-nonces.json` (persisted across restarts)
- Timestamp: ±5 minute window
- Both checked before enrollment is accepted

**Transfer for large payloads**: Pairing bundles may exceed QR capacity. In that case, the app shows the string as copyable text (user pastes in a message, email draft, or shared document) or exports as a .json file. The format is identical; only the transport changes. Manual copy is NOT a fallback. It is always available.

### UniFFI Exports for Mobile

```rust
// Step 1-2: new device generates enrollment payload
generate_enrollment_payload(device_name: String) -> EnrollmentPayload

// Step 3-8: existing device approves
approve_enrollment(
    payload: EnrollmentPayload,
    master_password: String
) -> Result<PairingBundle>

// Step 9-12: new device completes enrollment
complete_enrollment(bundle: PairingBundle) -> Result<()>
```

Zero platform-native crypto. Full Rust throughout.

---

## Epoch State Machine

```
CREATED → ACTIVE → ROTATING → RETIRED → DESTROYED
                      ↑           │
                      └───────────┘
                    (new epoch becomes ACTIVE)
```

| State | Reads | Writes | Description |
|-------|-------|--------|-------------|
| CREATED | No | No | New epoch initiated, not yet pushed |
| ACTIVE | Yes | Yes | Normal operation. All reads/writes use this epoch. |
| ROTATING | Yes (old epoch) | **No** | Rotation in progress. Old epoch readable, new writes blocked. |
| RETIRED | No | No | Old epoch deprecated. Keys purged. |
| DESTROYED | No | No | Old epoch key material zeroized. |

**Transition rules:**
- `CREATED → ACTIVE`: epoch is ready for use
- `ACTIVE → ROTATING`: rotation initiated, quorum collection begins
- `ROTATING → RETIRED`: quorum reached, old epoch retiring
- `RETIRED → DESTROYED`: old key material zeroized

Only one epoch can be ACTIVE or ROTATING at any time.

---

## Force Eviction

When a device is lost or compromised, the surviving device(s) must evict it and rekey.

**Flow:**
```
1. User authenticates on surviving device (master password)
2. DeviceManager.force_evict_and_rotate(surviving_device_id)
3. Registry cleared of all non-surviving devices
4. Epoch rotation initiated immediately
5. New Root Key generated
6. HPKE(RK', surviving_device_pk) only — evicted device excluded
7. If surviving_count <= quorum: self-ack, immediate commit
8. Old keywrap files for evicted devices deleted
9. Vault writes re-enabled under new epoch
```

**Security guarantee**: Evicted device retains its old wrapped key, but the new Root Key is never wrapped for it. It can decrypt old (pre-rotation) entries but never new ones. Forward secrecy achieved.

**Important**: Force eviction without rotation is NOT eviction. The evicted device can decrypt everything until rekey happens. This is why `force_evict_and_rotate` is atomic — rotation always follows eviction.

---

## Recovery Phrase (BIP-39)

The offline backup mechanism. When all devices are lost.

**Flow:**
```
1. User enters BIP-39 recovery phrase on new device
2. Derive master key from phrase (same KDF as original creation)
3. Re-derive Root Key from master key
4. Create new single-device vault
5. Old device registry abandoned
6. Old keywrap files irrelevant (old keys, old epoch)
```

Recovery bypasses DeviceManager enrollment entirely. The recovery phrase IS the root of trust. No quorum, no approval, no other device needed.

---

## Open Bugs (from Peer Review)

### BUG-1: Double-ack Quorum Bypass (P0) — **Fixed**

`record_ack()` pushed to `collected_acks` without dedup by `device_id`. Quorum gate checked `collected_acks.len()`. A single device submitting N acks reached quorum without other devices participating.

**Fix**: Reject duplicate acks from same device. Use `epoch.acknowledged_devices.len()` for quorum check (already deduped). Single source of truth.

### BUG-2: Seen Nonces Not Persisted (P1) — **Fixed**

`seen_nonces: Vec<String>` was in-memory only. Daemon restart cleared it. An attacker who captures an enrollment QR before use could replay it after restart.

**Fix**: Persist to `meta/seen-nonces.json` on `save_to_vault()`, load on `load_from_vault()`. FIFO eviction at 10,000 entries.

### BUG-3: Commit Barrier Computed Then Dropped (P1) — **Fixed**

In `commit_rotation()`, `_commit_barrier` was built from acks but never written back to the transaction. The `.txn` file's `commit_barrier` field stayed empty. Audit trail was hollow.

**Fix**: Populate `tx.commit_barrier` before commit. Write finalized `.committed` file with populated barrier.

### BUG-4: Two Ack-Tracking Structures Diverge (P1) — **Fixed**

`epoch.acknowledged_devices` and `collected_acks` tracked the same logical set but could disagree after a duplicate ack.

**Fix**: `epoch.acknowledged_devices` is canonical for quorum. `collected_acks` provides signed payloads only. Duplicate acks rejected before recording.

---

## Open Design Issues (from Peer Review)

### MISS-1: Root Key Rotation with Cipher Re-encryption (P0) — **Fixed**

VaultHandle now has a `rotate_root_key()` method that performs the full atomic rotation:
1. Generates new Root Key
2. Re-encrypts all ciphers with new-epoch Item Keys (derived via HKDF from new Root Key)
3. Updates RK canary with new Root Key
4. Writes new keywrap file for this device
5. Zeroizes old Root Key

After rotation, the old Root Key cannot decrypt any cipher. Forward secrecy is achieved. Item Keys are derived deterministically from `(root_key, epoch, cipher_id)`, so epoch change forces full re-encryption.

### MISS-2: VaultHandle Signing Integration — **Fixed**

VaultHandle now holds a `DeviceManager` instance (loaded on `open()`). Methods added:
- `initiate_key_rotation()` — generates new Root Key, wraps for all devices
- `finalize_rotation()` — loads Ed25519 signing key, builds and signs ack, calls `record_ack()`
- `force_evict_and_rotate()` — delegates to DeviceManager
- `recover_from_phrase()` — delegates to DeviceManager
- `has_pending_rotation()` — checks epoch state
- `epoch_state()` — returns current EpochState

### MISS-3: Rotation Observer for Git Sync — **Fixed**

Added `RotationObserver` trait with hooks: `on_rotation_proposed`, `on_ack_recorded`, `on_rotation_committed`, `on_device_enrolled`, `on_devices_evicted`. Injected via `set_observer()`. Default no-op. Sync engine can implement to trigger git commit/push after state transitions.

### MISS-4: Auto-Save After State Transitions — **Fixed**

Added `auto_save()` helper (pub(crate)) that calls `save_to_vault()` if vault_path is set. Called after every mutation: `enroll`, `initiate_rotation`, `record_ack`, `commit_rotation`, `force_evict_and_rotate`, and `recover_from_phrase`. No state is lost on restart.

### MISS-5: Recovery Phrase Path Through DeviceManager — **Fixed**

Added `recover_from_phrase(phrase, device_name)` method to DeviceManager:
1. Parses BIP-39 phrase
2. Derives recovery key, HPKE-unwraps Root Key from `meta/recovery.json`
3. Resets device registry (old devices abandoned)
4. Enrolls new device as sole survivor
5. Resets epoch to 1
6. Auto-persists

### SEC-1: Two-Device Quorum = 1

`ceil(2/2) = 1`. Either device can unilaterally rotate. Device B receives no notification. A compromised device A can rotate repeatedly, denying B sync.

**Status**: Documented as intentional. For a single-user password manager, unilateral rotation is acceptable — the user owns both devices. For org/team vaults (future), quorum should be unanimous for N=2.

### DESIGN-1: Public Fields

All `DeviceManager` fields are `pub`. Direct `registry.enroll()` bypasses the nonce/timestamp/approval gate. Production callers can break invariants.

**Fix**: `pub(crate)` fields. `#[cfg(test)]` accessors for test setup.

### DESIGN-2: Persistence Mixed Into Lifecycle Logic

`save_to_vault()` / `load_from_vault()` are on `DeviceManager`. `vault_path: Option<PathBuf>` in the struct. Mixing I/O with lifecycle logic makes tests heavier.

**Recommendation**: Split persistence into a separate `DeviceManagerStore`. DeviceManager stays pure. VaultHandle owns the store.

---

## peer review (2026-06-01)

All 4 Critical, 7 High, and 8 Medium findings addressed:

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| C1 | Critical | `add_cipher` hardcoded `key_epoch: 1` - post-rotation ciphers undecryptable | **Fixed** |
| C2 | Critical | `rotate_root_key()` not atomic - crash corrupts vault | **Fixed** (staged .tmp writes + rename pass) |
| C3 | Critical | `recover_from_phrase()` discards private keys - vault unlockable | **Fixed** (returns RecoveryResult with secrets) |
| C4 | Critical | `UnlockedState::Drop` doesn't zeroize Root Key | **Fixed** |
| H1 | High | Cipher writes not blocked during ROTATING epoch | **Fixed** (guards on add/update/delete/clone) |
| H2 | High | `auto_save()` silently swallows I/O errors | **Fixed** (added `auto_save_result()` for critical paths) |
| H3 | High | Trash ciphers not re-encrypted during rotation | **Fixed** (rotate_root_key re-encrypts both dirs) |
| H4 | High | `rotate_root_key()` bypasses DeviceManager epoch lifecycle | **Fixed** (proper epoch transition + observer hooks) |
| H5 | High | `force_evict_and_rotate()` discards new Root Key | **Fixed** (ForceEvictResult.new_root_key field) |
| H6 | High | DeviceManager empty registry in creation ceremony | **Fixed** (sync registry after enrollment) |
| H7 | High | Recovery epoch reset to 1 conflicts with existing cipher epochs | **Fixed** (read epoch from vault data) |
| M1 | Medium | `compute_txn_hash` duplicated | **Fixed** (pub(crate) + reuse) |
| M2 | Medium | `atomic_write` doesn't set 0o600 | **Fixed** (pre-existing fix) |
| M6 | Medium | VaultHandle.registry diverges from device_manager.registry | **Fixed** (sync helper) |
| M8 | Medium | Test helper missing `ed25519_private` | **Fixed** (pre-existing fix) |

---

## File Layout

```
.idtty/
  rekey/
    {epoch}.txn            # Rotation proposal (HPKE-wrapped RK' per device)
    {epoch}.ack.{device}   # Device acknowledgment (signed, with txn_hash binding)
    {epoch}.committed      # Finalized rotation (populated commit_barrier)

meta/
  devices.json             # DeviceRegistry (enrolled devices, keys)
  epoch.json               # EpochInfo (current epoch state)
  seen-nonces.json         # Anti-replay enrollment nonces (TODO: not yet persisted)
  keywrap/
    {device_id}.json       # HPKE-wrapped Root Key per device
```

---

## Test Plan

Priority-ordered. All must pass before production.

| # | Test | Validates |
|---|------|-----------|
| 1 | Enrollment auto-approve (first device) | Empty registry accepts first enrollment |
| 2 | Enrollment rejection (no approval for 2nd device) | D14 gate enforced |
| 3 | Enrollment with valid approval signature | Happy path multi-device enrollment |
| 4 | Replay nonce rejection | Anti-replay: same nonce rejected on reuse |
| 5 | Stale timestamp rejection | ±5 minute window enforced |
| 6 | Initiate rotation → ROTATING | State machine transition |
| 7 | Single-device self-commits | `force_evict_and_rotate` immediate commit for N=1 |
| 8 | Force evict removes devices | Registry cleared correctly |
| 9 | Concurrent rotation rejected | Second `initiate_rotation` while ROTATING fails |
| 10 | Ack with wrong txn_hash rejected | Ack-transplant attack prevented |
| 11 | Ack signature forgery rejected | Wrong signing key rejected |
| 12 | Quorum gate multi-device | `ceil(N/2)` acks required before commit |
| 13 | Epoch state transitions | CREATED→ACTIVE→ROTATING→RETIRED→DESTROYED |
| 14 | **Quorum dedup** (BUG-1 fix) | Same device submitting 2 acks does NOT reach quorum of 2 |
| 15 | **SGK re-wrap** (MISS-1 fix) | Old RK cannot decrypt items after rotation |
| 16 | **Vault write-blocked during ROTATING** | `writes_allowed() == false` in ROTATING state |
| 17 | **proptest: N devices, evict M, vault accessible** | Property test for all surviving device counts |

---

## Sequence Diagram: Full Rotation (Multi-Device, Git Remote)

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
     |   read .ack.B                                     |
     |   verify signature                                 |
     |   verify txn_hash                                  |
     |   ack count >= quorum? (yes for N=2, q=1)        |
     |   commit_rotation()                                |
     |   (epoch → RETIRED → new ACTIVE)                   |
     |   re-wrap SGKs under new RK'                       |
     |   write .committed                                 |
     |-- git push --------------->|                    |
     |                            |                    |
     |                            |-- git pull ------->|
     |                            |                    |
     |                            |   read .committed
     |                            |   unwrap new RK'
     |                            |   update local epoch
     |                            |   vault WRITES re-enabled
```
