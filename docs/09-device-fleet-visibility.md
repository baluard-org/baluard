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
- `verify_commit_signatures()` validates incoming commits against device signing keys from `meta/devices.json`
- **Gap**: Verification rejects ANY commit from an unknown key. But it reads from a plaintext `device-registry.json` (name -> key map), NOT from the encrypted `meta/devices.json`. This needs reconciliation with the encrypted registry.

### Device registry
- `DeviceRegistry` in `devices.rs`: enroll, revoke, force-evict, quorum calculation
- Stored in `meta/devices.json` (plaintext, per D1) via `DeviceManager`
- `DeviceEntry`: UUID, name, X25519 pubkey, Ed25519 pubkey, `enrolled_at`
- **Missing**: No `last_seen`, `last_sync`, `enrolled_by`, `last_seen_epoch` fields

### Epoch state machine
- CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED
- Root key rotation re-encrypts all entries, wraps KEK only for surviving devices
- **Missing**: No timeout for stalled ROTATING state. If the rotating device goes offline mid-rotation, cipher writes are blocked indefinitely.

---

## Architecture

### New file: `meta/device_activity.json`

Plaintext, UUID-only activity index. Device names are in `devices.json` (also plaintext, per D1). One file, merged on every push. Last-writer-wins per UUID key.

```json
{
  "v": 1,
  "devices": {
    "a1b2c3d4-...": {
      "last_push": "2026-06-02T14:30:00Z",
      "last_commit": "abc123def456...",
      "epoch": 7
    },
    "e5f6a7b8-...": {
      "last_push": "2026-05-15T09:00:00Z",
      "last_commit": "789abc012def...",
      "epoch": 7
    }
  }
}
```

| Field | Source | Visibility | Purpose |
|-------|--------|------------|---------|
| `last_push` | Self-reported ISO-8601 (corroborated by git committer date) | Plaintext | Fleet dashboard freshness |
| `last_commit` | SHA of the push commit | Plaintext | Verifiable: `git log` confirms |
| `epoch` | Current epoch at time of push | Plaintext | Shows if device is behind |

**Why plaintext**: UUIDs are opaque. Device names are in `devices.json` (also plaintext, per D1). The file is in a private git repo. The exposure is: "two UUIDs sync at these times." Acceptable for single-user vaults.

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

Current `verify_commit_signatures()` reads from `meta/device-registry.json` (legacy, to be consolidated in Phase 2 per D2). This should read from the encrypted `DeviceRegistry` instead (or cross-check both). A revoked device's signing key must be rejected even if the plaintext file is stale.

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
if epoch.state == ROTATING && elapsed > configured_timeout && no_progress_commit:
    // Safety check: abort is only safe if no ciphers were re-encrypted at new epoch
    if cipher_files_written_at(new_epoch) > 0:
        // Cannot abort. Must complete rotation with different device.
        // Re-initiate rotation as new coordinator.
        return
    candidates = sorted(enrolled_devices, by=uuid_bigendian)
    new_coordinator = candidates[0]  // lowest UUID, deterministic
    if self.device_id == new_coordinator:
        // Safe to abort: no ciphers at new epoch
        epoch.abort_rotation()
        // Write abort marker for other devices to detect
        write_abort_marker(new_epoch)
        // Re-attempt rotation (or wait for user action)
```

Rules:
- Configurable timeout (default 1h, range 15min-24h) before election
- UUID big-endian comparison: sort enrolled UUIDs as 128-bit integers, elect lowest. No hash needed.
- The elected device aborts the stalled rotation (epoch -> ACTIVE) and can re-initiate
- User confirmation required before aborting another device's rotation

---

## Implementation Phases

### Phase 1: Activity Index (core + daemon)
**Effort**: 1-2 days

1. Create `meta/device_activity.json` read/write functions in `device_manager.rs`
   - `read_activity_index(vault_path) -> DeviceActivityIndex`
   - `update_activity_index(vault_path, device_id, commit_sha, epoch) -> Result<()>`
   - Merge strategy: last-writer-wins (git default, per D5)
2. Hook into sync engine: call `update_activity_index()` after every `commit_all()`
3. Add daemon route: `vault.device_activity` -> returns `{devices: [{id, last_push, last_commit, epoch}]}`
4. Tests: activity index read/write, missing file fallback

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
5. Update `verify_commit_signatures()` to read from `meta/devices.json` (per D2). Deprecate and remove `meta/device-registry.json` and `meta/device-pks`
6. Tests: new fields serialize/deserialize, revocation cleans activity index, old files no longer read

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
- `crates/idtty-core/src/keys/epoch.rs` (rotation_started_at field, abort_rotation)
- `crates/idtty-core/src/device_manager.rs` (abort_rotation, timeout check, abort marker)
- `crates/idtty-core/src/sync/engine.rs` (stall detection on pull, abort marker detection)
- `crates/idtty-cli/src/commands/mod.rs` (rotation-abort command)

### Phase 4: CLI Fleet Commands
**Effort**: 0.5 days

1. `idtty devices list` - table output: name, status, last sync, epoch
2. `idtty devices revoke <uuid>` - revoke a device
3. `idtty devices info` - show current device's enrollment details
4. Tests: output formatting, revoke flow

Files changed:
- `crates/idtty-cli/src/commands/mod.rs` (devices subcommands)

### Phase 5: Fleet Dashboard (desktop)
**Effort**: 2-3 days

1. New "Devices" tab in sidebar (below Trash/Archive)
2. Call `vault.device_activity` on open
3. Cross-reference with decrypted `DeviceRegistry` (UUID -> name mapping)
4. Device cards showing:
   - Name (from encrypted registry)
   - Status badge (active/idle/stale/dormant based on `last_push`)
   - Enrolled date
   - Enrolled by (if available, "Founding device" for `None`)
   - Last sync time
   - Current epoch vs device epoch
   - Push count (label as "self-reported, unverified" or derive from git log)
5. "Revoke" button per device (triggers daemon revocation flow)
6. Post-revocation warning banner: persistent checkbox acknowledgment "I have rotated git credentials on GitHub/GitLab". Parse remote URL for direct link to `github.com/<repo>/settings/keys`
7. Stale device prompt: "Review devices" notification
8. Tests: manual verification with multi-device setup

Files changed:
- `desktop/src/App.jsx` (Devices tab, device cards, revoke UI, warnings)
- `crates/idtty-daemon/src/handler.rs` (device_activity route)
- `crates/idtty-daemon/src/state.rs` (device fleet data, revoke endpoint)

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
| Plaintext activity index (UUIDs) | UUIDs opaque; device names in `devices.json` also plaintext (see C1). Low-sensitivity metadata in private repo. Acceptable for single-user. |
| Self-reported timestamps | Corroborated by git committer date + commit SHA | Display from git log, not from file |

### New attack surfaces

| Surface | Mitigation |
|---------|-----------|
| Malicious activity index (forged timestamps) | Commit SHA is verifiable. UI derives freshness from git log, not self-reported `last_push` |
| Revoked device pushes garbage commits | `verify_commit_signatures()` rejects unknown keys. Garbage commits visible in git history but ignored by all devices |
| Activity index merge conflicts | Union merge, latest timestamp wins. No data loss possible (only timestamps) |
| Epoch stall (ROTATING forever) | Configurable timeout (default 1h) + deterministic coordinator election (Phase 3) |

---

## Architectural Decisions (Resolved)

Six decisions resolved with the security review. All prioritize simplicity and non-technical UX.

### D1: devices.json stays plaintext

Public keys are public by definition. Device names ("MacBook Pro") carry no secrets. The private git repo is the access boundary. Encrypting gains nothing while breaking the fleet dashboard's pre-unlock visibility. Don't add SGK re-encryption complexity to protect non-secret data.

**Implication**: Activity index UUID-opacity argument is weakened (device names are already exposed in git history). Acceptable: the repo is private, names are low-sensitivity.

### D2: Consolidate to devices.json as canonical key file

`meta/devices.json` already has `signing_public_key`. Eliminate `device-registry.json` and `device-pks`. Fewer canonical sources = fewer consistency bugs. Update `verify_commit_signatures()` to read from `meta/devices.json` instead of `device-registry.json`.

**Implication**: Deprecate and remove `meta/device-registry.json` and `meta/device-pks` in Phase 2.

### D3: Remove push_count from activity index

Self-reported data that can't be verified is worse than no data. "Approximate / self-reported" labels add disclaimers to misleading information. Git log derivation is expensive. Remove the field entirely.

**Implication**: `meta/device_activity.json` entries are `{last_push, last_commit, epoch}` only. No push_count.

### D4: No enrollment approval signature persistence

IDtty is a single-user password manager. The enrollment ceremony requires the approver's vault to be unlocked. `enrolled_by: Option<DeviceId>` is the right level of UX truth ("Added by MacBook"). On-disk cryptographic proof adds serialization complexity with zero practical benefit. The attacker who can tamper with DeviceEntry on disk can also tamper with the approval signature.

**Implication**: Only `enrolled_by` and `last_seen_epoch` are added to DeviceEntry. No approval_signature field.

### D5: Last-writer-wins for activity index conflicts

Activity index entries are ephemeral timestamps. No secrets, no access control. A lost `last_push` timestamp self-heals on the next sync. Custom git merge drivers add install complexity. Inline union-merge adds Rust complexity. Neither justified for ephemeral metadata.

**Implication**: No `.gitattributes` merge driver needed. Standard git last-writer-wins is sufficient.

### D6: Persistent step-by-step banner with parsed link for git credential rotation

A revoked device with stale git credentials can still clone/pull the repo. Parse the remote URL, construct direct link to `github.com/<repo>/settings/keys`, show numbered steps. Dismiss only after explicit user confirmation (checkbox). Non-technical users need a map, not a signpost.

**Implication**: Phase 5 (desktop dashboard) includes URL parsing for GitHub/GitLab remote URLs + persistent acknowledgment banner.

1. **Activity index prune**: Keep indefinitely, prune from UI after 180 days (not 90). Never auto-delete from the file. **Resolved**.
2. **Push count**: Monotonic, no reset. Adds cross-epoch evidence of device continuity. **Resolved**.
3. **First device enrolled_by**: `None`. Dashboard renders as "Founding device." **Resolved**.
4. **Verification key source**: Plaintext ONLY pre-unlock (when vault is locked, no decryption possible). Encrypted registry ONLY post-unlock. Never allow plaintext to override encrypted after unlock. **Resolved (changed from original cross-check recommendation)**.
5. **Coordinator election timing**: Configurable in Phase 3. Default 1h (not 24h). Range: 15min / 1h / 6h / 24h / never. Stored in VaultSettings. **Resolved (changed from 24h default)**.

---

## Peer Review (peer review, Round 1)

Reviewed against: `devices.rs`, `device_manager.rs`, `sync/engine.rs`, `vault/manifest.rs`. 17 findings total.

### Critical

| # | Finding | Resolution |
|---|---------|------------|
| C1 | `devices.json` written as raw JSON (no encryption). manifest.rs comment says "encrypted" but code writes plaintext. | **Resolved (D1)**: Keep plaintext. Public keys are public. Device names are low-sensitivity. Private git repo is the access boundary. Encrypting would break pre-unlock fleet dashboard. |
| C2 | `abort_rotation` + partial re-encryption = irrecoverable data loss. If rotating device re-encrypted some ciphers with new epoch keys before going offline, abort back to old epoch leaves those ciphers undecryptable by any device. | Abort path must scan for any cipher files written at the new epoch. If found, abort is unsafe. Only recovery: different device re-does the key wrap. Add `abort_is_safe()` check before allowing abort. |
| C3 | Original OQ4 "cross-check both" creates revocation bypass (OR gate). If plaintext `device-registry.json` is stale and still has revoked key, commits pass via plaintext path. | **Resolved in Open Questions**: plaintext ONLY pre-unlock, encrypted ONLY post-unlock. No cross-checking. |

### High

| # | Finding | Resolution |
|---|---------|------------|
| H1 | Three conflicting plaintext key files: `device-registry.json`, `devices.json`, `device-pks`. No canonical source for commit verification. | **Resolved (D2)**: Consolidate to `meta/devices.json`. Deprecate and remove `device-registry.json` and `device-pks` in Phase 2. |
| H2 | `push_count` is self-reported and unverifiable. Displayed alongside security fields creates false confidence. | **Resolved (D3)**: Removed from activity index entirely. |
| H3 | Enrollment approval signature not persisted in `DeviceEntry`. No on-disk proof that Device A approved Device B. | **Resolved (D4)**: No signature persistence. `enrolled_by` UUID reference is sufficient for single-user threat model. |
| H4 | Original coordinator returning after abort creates split-brain. Device A has persisted ROTATING state, B aborts. A cannot know B aborted. | Define abort marker file: `.idtty/rekey/<epoch>.aborted`. A detects on pull and transitions out of ROTATING. |
| H5 | Per-user registries in org-mode incompatible with admin revocation without key escrow. | Flag for org-mode architecture. Requires key hierarchy or escrow mechanism. |

### Medium

| # | Finding | Resolution |
|---|---------|------------|
| M1 | New `DeviceEntry` fields need `#[serde(default)]` for backward compat with existing `devices.json` files. | Add `#[serde(default)]` on `enrolled_by` (None) and `last_seen_epoch` (0). |
| M2 | Phase 5 (CLI) should precede Phase 4 (Desktop). CLI is simpler, provides early integration testing. | Swap Phase 4 and 5. |
| M3 | `keys/epoch.rs` missing from Phase 3 file change list. | Add `crates/idtty-core/src/keys/epoch.rs` to Phase 3 changes. |
| M4 | Activity index merge requires custom strategy before `PullResult::Conflict`. | **Resolved (D5)**: Last-writer-wins (git default). No custom merge driver needed. Ephemeral metadata self-heals on next sync. |
| M5 | Coordinator election spec incomplete: "lowest UUID hash" undefined. | Use UUID big-endian comparison (no hash needed). UUIDs already random 128-bit. Sort by byte order, elect lowest. |
| M6 | 24h default timeout too long for compromise scenarios. Must be configurable in Phase 3. | **Resolved**: default 1h, range 15min-24h, stored in VaultSettings. |
| M7 | Single activity file leaks cross-user coordination in org mode. | Flag for org-mode: split per user, acknowledge UUID-timing correlation. |

### Low

| # | Finding | Resolution |
|---|---------|------------|
| L1 | `enrolled_by: None` for founding device needs explicit "Founding device" UI copy, not empty/null. | Add to Phase 4 dashboard spec. |
| L2 | Post-revocation warning must be persistent (require checkbox acknowledgment), not dismissible on first click. Parse remote URL for direct GitHub settings link. | Add to Phase 4 dashboard spec. |
