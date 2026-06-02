# Device Lifecycle & Root Key Rotation

**Last updated**: 2026-06-02

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

### Mode 1: Single Device, No Network

The default. 90%+ of users.

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

Single atomic local transaction. No `.ack` files. No quorum wait. `quorum_required()` returns 1 for N=1.

### Mode 2: Multi-Device, Git Remote Configured

Multiple devices sharing a vault via GitHub/GitLab/self-hosted git.

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
| 2 | 1 | Unilateral rotation accepted (single-user) |
| 3 | 2 | Majority |
| 4 | 2 | Majority |
| 5 | 3 | Majority |

### Mode 3: Multi-Device, No Git Remote (Local Transport)

Two devices on the same desk, no cloud.

**Transport options** (priority order):
1. **QR codes** — small payloads (enrollment, ack bundles)
2. **File export/import** — larger payloads (pairing bundle, git bundle)
3. **USB drive** — `git bundle` for full vault sync

Rotation uses the same two-phase commit as Mode 2, but ack delivery is physical. The `ROTATING` epoch state persists between transfers.

---

## Enrollment

### First Device

Automatic. No approval needed. The empty registry auto-approves the first enrollment.

### Additional Devices

Requires physical presence + master password confirmation on an existing enrolled device.

**Transfer methods** (all first-class, user picks what works):

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

### UniFFI Exports for Mobile

```rust
generate_enrollment_payload(device_name: String) -> EnrollmentPayload
approve_enrollment(payload: EnrollmentPayload, master_password: String) -> Result<PairingBundle>
complete_enrollment(bundle: PairingBundle) -> Result<()>
```

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
| ACTIVE | Yes | Yes | Normal operation |
| ROTATING | Yes (old epoch) | **No** | Rotation in progress. Writes blocked. |
| RETIRED | No | No | Old epoch deprecated. Keys purged. |
| DESTROYED | No | No | Old epoch key material zeroized. |

---

## Force Eviction

When a device is lost or compromised, the surviving device(s) must evict it and rekey.

**Selective revocation** (preferred, multi-device vaults):
```
1. User authenticates on surviving device
2. DeviceManager.revoke_device_and_rotate(target_id, self_id)
3. Only target device removed from registry (others preserved)
4. Epoch rotation initiated immediately
5. New Root Key generated, HPKE-wrapped for all remaining devices
6. Self-ack, immediate commit
7. Activity index cleaned for revoked device
8. Vault writes re-enabled under new epoch
```

**Emergency force-evict** (single-survivor disaster recovery):
```
1. User authenticates on surviving device
2. DeviceManager.force_evict_and_rotate(surviving_device_id)
3. Registry cleared of all non-surviving devices
4. Epoch rotation initiated immediately
5. New Root Key generated, HPKE-wrapped only for surviving device(s)
6. Self-ack, immediate commit
7. Old keywrap files for evicted devices deleted
8. Vault writes re-enabled under new epoch
```

Force eviction without rotation is NOT eviction. The evicted device can decrypt everything until rekey happens. Both paths are atomic.

---

## Recovery Phrase (BIP-39)

The offline backup mechanism. When all devices are lost.

```
1. User enters BIP-39 recovery phrase on new device
2. Derive master key from phrase
3. Re-derive Root Key from master key
4. Create new single-device vault
5. Old device registry abandoned
```

Recovery bypasses DeviceManager enrollment entirely. The recovery phrase IS the root of trust. No quorum, no approval, no other device needed.

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
  seen-nonces.json         # Anti-replay enrollment nonces
  keywrap/
    {device_id}.json       # HPKE-wrapped Root Key per device
```

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
