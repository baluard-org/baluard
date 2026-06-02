# Device Fleet Visibility & Revocation

**Status**: Plan
**Last updated**: 2026-06-02
**Reviewers**: Esteban (lead architect), peer review (security architecture review)

---

## Hard Constraints

1. **No server backend.** The git repository IS the coordination channel. No WebSocket, no ping endpoint, no real-time anything.
2. **Git commits are the heartbeat.** A device is "alive" if it has recently pushed. There is no other signal.
3. **Revocation is eventual, not instant.** A revoked device can continue reading locally until it pulls and sees the revocation. This is inherent to serverless and non-negotiable.
4. **Git credentials are out-of-band.** Revoking vault access does NOT revoke git push access. Users must rotate deploy keys / PATs on GitHub/GitLab separately. We document this, not solve it.

---

## Current State (What's Already Built)

### Signed commits (partial)
- Sync engine signs every commit with Ed25519 device key (`create_signed_commit` in `sync/engine.rs`)
- Signature embedded as `gpgsig` header: `-----BEGIN IDTTY SIGNATURE-----\n<base64>\n-----END IDTTY SIGNATURE-----`
- `verify_commit_signatures()` validates incoming commits against `meta/device-registry.json` verifying keys
- **Gap**: Verification rejects ANY commit from an unknown key. But it reads from a plaintext `device-registry.json` (name -> key map), NOT from the encrypted `meta/devices.json`. This needs reconciliation with the encrypted registry.

### Device registry
- `DeviceRegistry` in `devices.rs`: enroll, revoke, force-evict, quorum calculation
- Stored encrypted in `meta/devices.json` via `DeviceManager`
- `DeviceEntry`: UUID, name, X25519 pubkey, Ed25519 pubkey, `enrolled_at`
- **Missing**: No `last_seen`, `last_sync`, `enrolled_by`, `last_seen_epoch` fields

### Epoch state machine
- CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED
- Root key rotation re-encrypts all entries, wraps KEK only for surviving devices
- **Missing**: No timeout for stalled ROTATING state. If the rotating device goes offline mid-rotation, cipher writes are blocked indefinitely.

---

## Architecture

### New file: `meta/device_activity.json`

Plaintext, UUID-only activity index. No device names (those stay encrypted in `devices.json`). One file, merged on every push. Last-writer-wins per UUID key.

```json
{
  "v": 1,
  "devices": {
    "a1b2c3d4-...": {
      "last_push": "2026-06-02T14:30:00Z",
      "last_commit": "abc123def456...",
      "push_count": 42,
      "epoch": 7
    },
    "e5f6a7b8-...": {
      "last_push": "2026-05-15T09:00:00Z",
      "last_commit": "789abc012def...",
      "push_count": 17,
      "epoch": 7
    }
  }
}
```

| Field | Source | Visibility | Purpose |
|-------|--------|------------|---------|
| `last_push` | Self-reported ISO-8601 (corroborated by git committer date) | Plaintext | Fleet dashboard freshness |
| `last_commit` | SHA of the push commit | Plaintext | Verifiable: `git log` confirms |
| `push_count` | Monotonic counter | Plaintext | Quick liveness indicator |
| `epoch` | Current epoch at time of push | Plaintext | Shows if device is behind |

**Why plaintext**: UUIDs are opaque. Without the encrypted `devices.json` (which maps UUID -> name), this file reveals nothing meaningful. The repo is already private (GitHub/GitLab). The exposure is: "two UUIDs sync at these times." Acceptable.

**Why not per-device files**: One file with merge-by-key is simpler than N files with directory fanout. Git merge conflicts on a single JSON file are easy to resolve (union of keys, latest timestamp wins). N files means N potential conflicts.

### Enhanced `DeviceEntry`

Add fields to the existing struct in `vault/manifest.rs`:

```rust
pub struct DeviceEntry {
    pub device_id: DeviceId,
    pub name: String,
    pub encryption_public_key: String,
    pub signing_public_key: String,
    pub enrolled_at: u64,
    // New fields:
    pub enrolled_by: Option<DeviceId>,   // Which device approved enrollment
    pub last_seen_epoch: u64,            // Last epoch this device was active in
}
```

`enrolled_by` is `None` for the first device (self-enrolled). All subsequent devices record which existing device approved them. This enables "Device X was added by your MacBook on 2026-03-15" in the fleet dashboard.

`last_seen_epoch` tracks how far behind a device is. If current epoch is 7 and a device's `last_seen_epoch` is 3, it literally cannot read any new data. The activity file's `epoch` field corroborates this.

### Signed commit verification (hardening)

Current `verify_commit_signatures()` reads from `meta/device-registry.json` (plaintext name -> key map). This should read from the encrypted `DeviceRegistry` instead (or cross-check both). A revoked device's signing key must be rejected even if the plaintext file is stale.

Flow on pull:
1. Decrypt `meta/devices.json` -> get current `DeviceRegistry` with valid signing keys
2. For each incoming commit, extract Ed25519 signature
3. Verify signature against registry's signing keys
4. **Drop** commits signed by revoked/unregistered devices (reject the pull, warn user)

### Stale device thresholds

Never auto-revoke. UI badges only:

| Threshold | Label | Color | UI Action |
|-----------|-------|-------|-----------|
| < 7 days | Active | Green | None |
| 7-30 days | Idle | Yellow | None |
| 30-90 days | Stale | Orange | "Review devices" prompt |
| > 90 days | Dormant | Red | "Consider revoking" prompt |

Stale and dormant are prompts, not actions. A laptop in a drawer for 3 months is the common case. Compromise response is the existing `force_evict` flow.

---

## Revocation Flow (End-to-End)

### Normal revocation (quorum available)

Prerequisites: >= 2 devices enrolled, quorum can be reached.

1. Device A pulls latest, verifies all incoming commit signatures
2. User opens fleet dashboard, selects Device B, clicks "Revoke"
3. `device_manager.revoke(B)` removes B from `DeviceRegistry`
4. Epoch advances: N -> N+1 (ROTATING)
5. Root key rotation: new RootKey -> new SGK -> all ItemKeys re-derived -> all entries re-encrypted
6. KEK re-wrapped only for surviving devices (B excluded)
7. `meta/device_activity.json` updated: B's entry removed
8. A commits + pushes: `[device-revoke] removed <B-uuid>, epoch N+1`

### Force-evict (single surviving device, emergency)

Already built. Enhances with:

1. `force_evict(surviving_id)` rewrites registry with only surviving device
2. Root key rotation + full re-encryption
3. `meta/device_activity.json` rewritten with only surviving device
4. Push with signed commit

### What the revoked device experiences

- **B is online**: B pulls. Sync engine detects its signing key is no longer in registry. B enters **read-only mode**. Local vault decryptable with epoch N keys (B has them). B cannot decrypt new epoch N+1 entries. B's pushes are dropped by other devices (signature verification fails).
- **B is offline for weeks**: B's local state is a snapshot at revocation time. When B eventually syncs, same outcome as above.
- **B refuses to sync**: B retains a readable copy of the vault at epoch N. Cannot be prevented without a server. Mitigation: root key rotation ensures B's copy becomes stale (new entries are encrypted with keys B doesn't have).

### Git credential rotation (out-of-band, documented)

After revocation, the user SHOULD:
1. Go to GitHub/GitLab repo settings
2. Remove the revoked device's deploy key or PAT
3. Optionally regenerate the remaining device's deploy key

The app CANNOT do this automatically (no GitHub API access from the vault). The fleet dashboard shows a persistent warning after revocation: "Rotate git credentials for full security."

---

## ROTATING Epoch Timeout

**Problem**: If the device initiating rotation goes offline mid-ROTATING, cipher writes are blocked indefinitely (by design). No other device can write.

**Solution**: Deterministic coordinator election after timeout.

```
if epoch.state == ROTATING && elapsed > 24h && no_progress_commit:
    candidates = sorted(enrolled_devices, by=uuid)
    new_coordinator = candidates[0]  // deterministic
    if self.device_id == new_coordinator:
        // Abort the stalled rotation, reset to ACTIVE with current epoch
        epoch.abort_rotation()
        // Re-attempt rotation (or wait for user action)
```

Rules:
- 24-hour timeout before election
- Lowest UUID hash wins (deterministic, no coordination needed)
- The elected device aborts the stalled rotation (epoch -> ACTIVE) and can re-initiate
- User confirmation required before aborting another device's rotation

---

## Implementation Phases

### Phase 1: Activity Index (core + daemon)
**Effort**: 1-2 days

1. Create `meta/device_activity.json` read/write functions in `device_manager.rs`
   - `read_activity_index(vault_path) -> DeviceActivityIndex`
   - `update_activity_index(vault_path, device_id, commit_sha, epoch) -> Result<()>`
   - Merge strategy: union of keys, latest timestamp wins
2. Hook into sync engine: call `update_activity_index()` after every `commit_all()`
3. Add daemon route: `vault.device_activity` -> returns `{devices: [{id, last_push, last_commit, push_count, epoch}]}`
4. Tests: activity index merge, concurrent updates, missing file fallback

Files changed:
- `crates/idtty-core/src/device_manager.rs` (activity index read/write/update)
- `crates/idtty-core/src/sync/engine.rs` (hook after commit_all)
- `crates/idtty-daemon/src/state.rs` (device_activity route)
- `crates/idtty-daemon/src/handler.rs` (route registration)

### Phase 2: Enhanced DeviceEntry + Revocation Cleanup
**Effort**: 1 day

1. Add `enrolled_by: Option<DeviceId>` and `last_seen_epoch: u64` to `DeviceEntry`
2. Update `enroll()` to accept `enrolled_by` parameter
3. Update `commit_all` hook to write `last_seen_epoch` to activity index
4. Update `revoke()` and `force_evict()` to also clean `meta/device_activity.json`
5. Cross-check: `verify_commit_signatures()` should read from encrypted registry, not plaintext
6. Tests: new fields serialize/deserialize, revocation cleans activity index

Files changed:
- `crates/idtty-core/src/vault/manifest.rs` (DeviceEntry fields)
- `crates/idtty-core/src/devices.rs` (enroll_with_enrolled_by, revoke cleanup)
- `crates/idtty-core/src/device_manager.rs` (activity cleanup on revoke)
- `crates/idtty-core/src/sync/engine.rs` (verify from encrypted registry)

### Phase 3: Epoch Timeout + Coordinator Election
**Effort**: 1 day

1. Add `rotation_started_at: Option<u64>` to `EpochInfo`
2. Add `abort_rotation()` method to `DeviceManager`
3. In sync engine pull hook: check if incoming epoch is ROTATING and stale
4. Election logic: lowest UUID hash among enrolled devices
5. CLI command: `idtty rotation-abort` (manual override)
6. Tests: timeout detection, deterministic election, abort resets state

Files changed:
- `crates/idtty-core/src/device_manager.rs` (abort_rotation, timeout check)
- `crates/idtty-core/src/sync/engine.rs` (stall detection on pull)
- `crates/idtty-cli/src/commands/mod.rs` (rotation-abort command)

### Phase 4: Fleet Dashboard (desktop)
**Effort**: 2-3 days

1. New "Devices" tab in sidebar (below Trash/Archive)
2. Call `vault.device_activity` on open
3. Cross-reference with decrypted `DeviceRegistry` (UUID -> name mapping)
4. Device cards showing:
   - Name (from encrypted registry)
   - Status badge (active/idle/stale/dormant based on `last_push`)
   - Enrolled date
   - Enrolled by (if available)
   - Last sync time
   - Current epoch vs device epoch
   - Push count
5. "Revoke" button per device (triggers daemon revocation flow)
6. Post-revocation warning banner: "Rotate git credentials on GitHub/GitLab"
7. Stale device prompt: "Review devices" notification
8. Tests: manual verification with multi-device setup

Files changed:
- `desktop/src/App.jsx` (Devices tab, device cards, revoke UI, warnings)
- `crates/idtty-daemon/src/handler.rs` (device_activity route)
- `crates/idtty-daemon/src/state.rs` (device fleet data, revoke endpoint)

### Phase 5: CLI Fleet Commands
**Effort**: 0.5 days

1. `idtty devices list` - table output: name, status, last sync, epoch
2. `idtty devices revoke <uuid>` - revoke a device
3. `idtty devices info` - show current device's enrollment details
4. Tests: output formatting, revoke flow

Files changed:
- `crates/idtty-cli/src/commands/mod.rs` (devices subcommands)

---

## Data Flow Diagram

```
DEVICE A (push)                         GIT REPO                         DEVICE B (pull)
─────────────────                       ──────────                       ─────────────────
1. Edit cipher                       │                              │
2. commit_all()                      │                              │
   ├─ sign commit (Ed25519)          │                              │
   └─ update_activity_index()        │                              │
      └─ write meta/device_activity.json                           │
3. push_with_jitter() ─────────────►  │  commit + activity file  │
                                      │  signed, verifiable       │
                                      │                           │  4. pull_with_jitter()
                                      │  ◄─────────────────────────
                                      │                              5. verify_commit_signatures()
                                      │                                 └─ check against registry
                                      │                              6. read_activity_index()
                                      │                                 └─ update fleet display
                                      │                              7. Decrypt vault data
                                      │                                 └─ new entries readable
```

```
REVOCATION FLOW

DEVICE A (initiator)
────────────────────
1. Pull latest
2. User clicks "Revoke Device B"
3. device_manager.revoke(B)
   ├─ Remove B from registry
   ├─ Remove B from activity index
   └─ Advance epoch N -> N+1
4. Root key rotation
   ├─ New RootKey -> new SGK -> new ItemKeys
   ├─ Re-encrypt all entries
   └─ Wrap KEK for A only (not B)
5. Commit + push: [device-revoke] epoch N+1

DEVICE B (revoked, when it next syncs)
──────────────────────────────────────
1. Pull latest
2. verify_commit_signatures() fails for B's own key
   OR: B detects it's not in registry
3. Enter read-only mode
4. Display: "This device has been revoked"
5. Local data at epoch N still decryptable
6. New data at epoch N+1 NOT decryptable
7. Pushes rejected by A (signature invalid)
```

---

## Multi-User / Org Considerations (Future)

Not in scope for this plan. Documented for awareness:

1. **Per-user device registries**: `meta/users/<user_id>/devices.json`. Each user manages their own fleet. Org admin has read access to all.
2. **Role-based revocation**: Admin can revoke any device. Users self-revoke only.
3. **Per-collection SGKs**: Separate Space Group Keys per collection. User with Collection A access cannot read Collection B.
4. **Activity privacy**: Split `device_activity.json` per user. UUID patterns across users leak org behavior.
5. **M-of-N root key recovery**: Shamir secret sharing for multi-owner vaults.
6. **Admin fleet dashboard**: Admin sees all users' devices. Users see own only.

---

## Security Considerations

### Accepted risks

| Risk | Mitigation | Accepted because |
|------|-----------|-----------------|
| No real-time revocation | Eventual consistency via git pull | Fundamental to serverless model |
| Revoked device retains epoch N data | Root key rotation limits damage to stale snapshot | Cannot remote-wipe without a server |
| Git credentials not auto-rotated | Post-revocation warning + documentation | No GitHub API access from vault |
| Plaintext activity index (UUIDs) | UUIDs opaque without encrypted registry | Low-sensitivity metadata in private repo |
| Self-reported timestamps | Corroborated by git committer date + commit SHA | Display from git log, not from file |

### New attack surfaces

| Surface | Mitigation |
|---------|-----------|
| Malicious activity index (forged timestamps) | Commit SHA is verifiable. UI derives freshness from git log, not self-reported `last_push` |
| Revoked device pushes garbage commits | `verify_commit_signatures()` rejects unknown keys. Garbage commits visible in git history but ignored by all devices |
| Activity index merge conflicts | Union merge, latest timestamp wins. No data loss possible (only timestamps) |
| Epoch stall (ROTATING forever) | 24h timeout + deterministic coordinator election (Phase 3) |

---

## Open Questions

1. **Activity index prune**: Should dormant devices (no push in 90+ days) be removed from the activity index, or kept indefinitely? Recommend: keep indefinitely, prune from UI only.
2. **Push count overflow**: `push_count` is u64. Will never overflow. But should it reset on epoch rotation? Recommend: no, monotonic.
3. **First device enrolled_by**: First device self-enrolls. `enrolled_by` is `None`. Should it be `Some(self)` instead? Recommend: `None` is clearer.
4. **Verification key source**: `verify_commit_signatures()` currently reads plaintext `device-registry.json`. Should we switch entirely to encrypted `devices.json`? Recommend: yes, but needs vault unlocked to sync. Chicken-and-egg if vault is locked. Keep plaintext as fallback, cross-check both.
5. **Coordinator election timing**: 24h timeout. Too aggressive? Too lenient? Recommend: configurable via vault settings (15min / 1h / 6h / 24h / never).
