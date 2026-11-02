# ADR 0101. Domain Appendix: Device Fleet, Lifecycle, Terminology, and Tags

> Status: Accepted. Reference appendix retained from the original architecture record and reconciled with the current implementation.

## Context

This appendix preserves the domain reference decisions that sit under the numbered ADRs: consumer terminology, the device fleet and revocation model, the device lifecycle and Root Key rotation protocol, the frontend entry point, and tags. Cryptographic primitives, storage format, and synchronization are decided in ADR 0001 through ADR 0004. The multi-user design that builds on these foundations is recorded in `docs/adr/0085-sharing.md` and `docs/adr/0086-family-spaces.md`.

Four hard constraints bound every decision here.

1. There is no server backend. The Git repository is the coordination channel. There is no WebSocket, ping endpoint, push channel, or other real-time signal. Desktop and mobile applications work standalone and offline; Git synchronization is optional.
2. Git commits are the heartbeat. A device counts as alive if it has recently pushed. There is no other signal.
3. Revocation is eventual, not instant. A revoked device keeps reading its local copy until it pulls and sees the revocation. This is inherent to a serverless design and is not negotiable.
4. Git credentials are out of band. Revoking vault access does not revoke Git push access. Users must rotate deploy keys or tokens at the provider. This is documented, not solved.

Two further constraints apply to the lifecycle. Single-device use is the default, and multi-device use is opt-in through Git sync or local transport. All cryptography runs locally in the Rust core, exposed to mobile through UniFFI, with no platform-native cryptography on mobile.

## Decision

### Consumer terminology

User-facing text hides the machinery. The original translation table is:

| Technical term | Consumer wording |
|---|---|
| Git repository or remote URL | "Space" (for example Personal Space, Work Space) |
| Git clone, SSH, or PAT setup | "Sign in with GitHub" (silent OAuth) |
| Git merge conflict | "Two updates happened at once. Which do you keep?" |
| Asymmetric device keypair | "Your Device Digital Identity" |

The "Space" row is superseded. The current terminology rule is that "space" never reaches users: a vault's own name carries its identity ("this vault", "Join a shared vault"), and collections are shown as "Shared folders". Internal names such as the `collections.*` routes and `space.*` keys are unchanged. The other three rows stand. All strings live in the locale files, and a flow that cannot be explained without technical vocabulary must be redesigned.

### Device registry

`DeviceRegistry` in `crates/baluard-core/src/devices.rs` implements enroll, revoke, force-evict, and quorum calculation. It is serialized to plaintext `meta/devices.json` as a version number plus a map keyed by device UUID. Each `DeviceEntry` holds:

- `device_id`
- `name` (a display name, see below)
- `encryption_public_key` (X25519, 32 bytes, hex)
- `signing_public_key` (Ed25519, 32 bytes, hex)
- `enrolled_at`
- `enrolled_by` (optional; absent for the founding device)
- `last_seen_epoch` (the last epoch the device was active in; 0 means unknown)

Decisions that shape this file:

- `devices.json` stays plaintext. Public keys are public, the private Git repository is the access boundary, and encryption would gain nothing while breaking pre-unlock fleet visibility. After unlock, the encrypted `DeviceRegistry` takes precedence; the plaintext file never overrides it.
- `devices.json` is the single canonical key file. The earlier `device-registry.json` and `device-pks` files are removed.
- Device display names are personal data ("Esteban's MacBook") and the file is Git-tracked. After the first unlock, names are folded into the encrypted `device_names` map inside `settings.enc` and blanked in `devices.json`. The fold is idempotent, writes the encrypted map before the stripped registry, and re-folds names that a legacy remote reintroduces. Between pre-unlock enrollment and the first unlock a name may briefly sit in the plaintext file. This supersedes the original statement that names are plaintext.
- Serialization is deterministic (entries sorted by UUID) and a write is skipped when the bytes are unchanged. A randomized map order would make every device rewrite the one shared file on every commit and guarantee multi-writer conflicts. The sync engine bumps the committing device's `last_seen_epoch` before staging, so the change rides the commit and the worktree stays clean.
- There is no enrollment approval signature. `enrolled_by` is the right level for a single-user tool, because an attacker able to alter a `DeviceEntry` on disk can alter a stored signature too. Enrollment authorization is verified when it happens (see Enrollment), not stored in the entry.

### Signed commits

The sync engine signs every commit with the device Ed25519 key, carried in the `gpgsig` header. `verify_commit_signatures()` validates incoming commits against device signing keys. Before unlock it reads the plaintext `meta/devices.json`; after unlock it reads the encrypted registry. Plaintext never overrides the encrypted registry after unlock.

On an enrolled vault (one with `meta/devices.json`) a missing signing key makes commit creation fail closed rather than produce an unsigned commit. Only pre-enrollment local vaults fall back to unsigned local commits. The detailed verification rules (per-commit roster resolution from the first-parent tree, staged path sets, enrollment proofs) are decided in `docs/adr/0063-the-stage-is-the-policy.md` and `docs/adr/0081-the-proof-rides-the-commit.md`.

### Activity index

Fleet freshness uses `{last_push, last_commit, epoch}` per device UUID:

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
|---|---|---|
| `last_push` | Self-reported ISO-8601, corroborated by the Git committer date | Fleet dashboard freshness |
| `last_commit` | SHA of the push commit | Verifiable through `git log` |
| `epoch` | Epoch at push time | Shows whether a device is behind |

Decisions: there is no `push_count` (self-reported and unverifiable); conflicts resolve last-writer-wins per UUID key with the latest timestamp, with no custom Git merge driver, because the data is ephemeral and holds no secrets; and display uses Git log evidence rather than trusting the file timestamp alone. UUIDs are opaque, so the exposure is "two UUIDs synced at these times", which is acceptable for single-user vaults. The index is local activity evidence, not an authoritative liveness signal.

Current storage differs from the original single plaintext synced file. The sync engine writes `meta/device_activity.json` after each commit and push; that file is gitignored, so writing it does not dirty the worktree. `load_activity_enc` re-seals it into `meta/activity.enc`, encrypted under a key derived from the Root Key (`derive_activity_key`). Rotation re-encrypts `activity.enc`, and on a team-shape vault the derivation is administrator-only (`docs/adr/0043-team-shape-flip.md`). The `device_activity.json` file is listed as legacy plaintext metadata in the vault `.gitignore`.

### Stale-device thresholds

Stale devices are never revoked automatically. The UI shows badges only:

| Age since last activity | Label | Color | UI action |
|---|---|---|---|
| Under 7 days | Active | Green | None |
| 7 to 30 days | Idle | Yellow | None |
| 30 to 90 days | Stale | Orange | "Review devices" prompt |
| Over 90 days | Dormant | Red | "Consider revoking" prompt |

Stale and dormant are prompts, not actions: a laptop in a drawer for three months is the common case. Compromise response uses the existing force-evict flow.

### DeviceManager aggregate

`DeviceManager` in `crates/baluard-core/src/device_manager.rs` coordinates three parts: the serializable `DeviceRegistry`, the pure `EpochInfo` state machine, and the rotation coordination logic that owns the pending transaction and collected acknowledgments. The parts stay independently testable. `VaultHandle` owns the manager, and vault operations check epoch state through it.

Persistence is behind the `DeviceManagerStore` trait so the state machine stays free of I/O. The filesystem implementation writes a combined `meta/device-state.json` (registry, epoch, seen nonces) as one atomic file and also writes `devices.json`, `epoch.json`, and `seen-nonces.json`; the combined file is authoritative on load. Files under `meta/rekey/` are written one at a time, each atomically, because each device produces them independently and Git moves them between devices. The combination is therefore not atomic, and a crash between writes can leave partially updated state. Security-critical mutations use the error-returning save path. A `RotationObserver` hook reports proposals, acks, commits, enrollments, and evictions so callers can trigger sync or notifications.

Rotation artifacts live under `meta/rekey/`. The `.baluard` path is exclusively the vault detection marker file; an older layout that stored rekey files under a `.baluard` directory is migrated best effort and idempotently on load.

### Epoch state machine

```
CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED
```

A completed rotation does not return the old epoch to ACTIVE. It retires the old epoch and creates a fresh epoch record for the new number, which is activated.

| State | Reads | Writes | Description |
|---|---|---|---|
| CREATED | No | No | New epoch initiated, not yet pushed |
| ACTIVE | Yes | Yes | Normal operation |
| ROTATING | Yes (old epoch) | No | Rotation in progress; writes blocked |
| RETIRED | No | No | Old epoch deprecated; keys purged |
| DESTROYED | No | No | Old epoch key material zeroized |

Transitions are enforced and each fails otherwise: `activate` only from CREATED; `begin_rotation` only from ACTIVE (it records the start timestamp used for the stall timeout); `retire` only from ROTATING; `destroy` only from RETIRED; `abort_rotation` only from ROTATING, which returns to ACTIVE and clears the timestamp and acknowledgments. Only one epoch can be ACTIVE or ROTATING at a time. `writes_allowed()` is true only in ACTIVE, and `initiate_rotation` refuses unless the state is ACTIVE and the initiating device is enrolled. The epoch record also carries the set of acknowledging devices; that set is the canonical, deduplicated quorum counter.

### Rotation modes

**Single device, no network (the default).** Generate a new Root Key, HPKE-wrap it to the device's X25519 public key and write a new keywrap file, re-derive Space Group Keys, re-encrypt headers and entries, self-acknowledge, retire the old epoch and activate the new one, zeroize the old Root Key and SGKs, and commit to the local repository without a push. This is one local transaction with no ack files and no quorum wait; `quorum_required()` is 1 for one device. The staging order and crash handling are described under Rotation execution.

**Multi-device with a Git remote.** Rotation is a two-phase commit through Git.

1. Propose (initiating device). Generate the new Root Key. For each eligible enrolled device, HPKE-wrap it to that device's X25519 key under the context `keywrap:rotation:{new_epoch}`. Build a `RekeyTransaction` holding `old_epoch`, `new_epoch`, the per-device wrapped keys, the initiating device, a timestamp, and an initially empty `commit_barrier`. Write `meta/rekey/{new_epoch}.txn`, commit and push, and move to ROTATING. Reads stay allowed under the old epoch; writes are blocked.
2. Acknowledge (each device, asynchronously, on its next sync). Pull, read the transaction, unwrap its own wrap and confirm the key is sane, compute `txn_hash` as a SHA-256 over the transaction's old and new epoch, initiator, timestamp, and every wrapped-key entry, then sign `"ack" || epoch || device_id || txn_hash` with its Ed25519 key (the epoch is little-endian). Write `meta/rekey/{new_epoch}.ack.{device_id}`, commit, and push.
3. Commit (any device that observes quorum). Pull and collect the acks. For each, verify the enrolled device's Ed25519 signature, verify that the epoch matches the pending transaction, and verify that `txn_hash` matches the transaction, which prevents an ack from being transplanted onto another proposal. A repeated ack from the same device is rejected. When the verified count reaches quorum, re-derive the SGKs, populate `commit_barrier` with the verified ack signatures, write `meta/rekey/{new_epoch}.committed`, retire the old epoch, activate the new epoch, delete the keywraps of evicted devices, re-enable writes, then commit and push.

Quorum is `ceil(N/2)` of enrolled devices, with 0 for an empty registry:

| Enrolled devices | Quorum | Rationale |
|---|---|---|
| 0 | 0 | Empty vault |
| 1 | 1 | Self-ack, immediate |
| 2 | 1 | Unilateral rotation accepted (single user) |
| 3 | 2 | Majority |
| 4 | 2 | Majority |
| 5 | 3 | Majority |

On a team-shape vault the proposal wraps the new Root Key only for devices that map to an Owner or Admin member (a missing member row means a legacy device and counts as admin-equivalent). The roster read is strict: an unreadable directory or damaged row fails the rotation rather than defaulting a device to admin. The committed `.txn` carries wraps that any listed device can open with its private key, so a member entry would leak the Root Key offline. See `docs/adr/0043-team-shape-flip.md` and `docs/adr/0074-the-flip-keeps-keys-from-members-not-from-admins.md`.

**Multi-device without a Git remote (local transport).** The same two-phase commit applies, but acknowledgments are delivered physically. Transports in priority order: QR codes for small payloads (enrollment, ack bundles); file export and import for larger payloads (pairing bundle, Git bundle); a USB drive carrying a full Git bundle. ROTATING persists between transfers.

### Rotation execution and crash safety

`VaultHandle::rotate_root_key` (non-revocation rotation) and `VaultHandle::revoke_device_and_rekey` (revocation rotation) share one staging discipline.

1. Both refuse unless the vault is unlocked, and `rotate_root_key` also refuses while a rotation is already in progress.
2. Both pass the admin approval gate (the `quorum_admin_ops` threshold, default 1; a legacy vault with no member directory passes). Revoking a device rotates the Root Key, so it must not become a bypass of the gate. The gate is enforced locally only, like every such knob.
3. `revoke_device_and_rekey` refuses to revoke the current device ("use force-evict from another device") and checks that the device private key is readable before any irreversible change.
4. Write the crash marker `meta/.rotation-pending` (mode 0600) holding `old_epoch` and `new_epoch`, and arm the `RotationGuard`.
5. Re-encrypt every active and trashed entry, including collection-scoped entries, and every attachment blob, to `.tmp` files. Attachment ids are validated as UUIDs before they touch a path. An entry this build cannot parse (for example a kind from a newer client) is re-wrapped at the byte level so it still moves to the new epoch, because a revoked device keeps every old key; true corruption is skipped loudly and left behind rather than aborting an offboarding. Decrypted plaintext is zeroized after re-encryption on both paths. The avatar is re-keyed when it still rides the Root Key domain; after a team-shape flip it rides the space metadata key, which rotation does not touch.
6. Stage the new Root Key canary and the new keywrap files.
7. Commit by rename in a fixed order: entries and attachments first, the canary second, the keywrap last. The keywrap rename is the point of no return.
8. Before the swap, read every Root Key derived artifact with the old key: folders, tags, profile, activity index, settings, generator history, contacts, outbox registries, templates, collection content keys, the space metadata key store, group keys, device names, and the activity event log. Refuse a tampered recovery kit before the point of no return, because a post-commit failure would leave the marker armed and the vault wedged until finalize.
9. Swap the in-memory Root Key and re-derive the SGK, zeroizing the old ones, then advance the epoch through `DeviceManager`. Re-save every artifact above under the new key, re-seal the legacy contact stores, re-wrap `meta/recovery.json` to the stored recovery public key, and re-wrap the Space Recovery Kit. Failures at this stage propagate; a skipped re-seal would strand an artifact at the old epoch or orphan a key.
10. Only after every fallible step has succeeded, disarm the guard and delete the marker.

The `RotationGuard` is an RAII guard. If the function returns early or panics while the guard is armed, it sweeps staged `.tmp` files from `meta/`, `meta/keywrap/`, `ciphers/`, and `trash/` recursively, and deliberately keeps the marker. An incomplete rotation must never look complete.

`VaultHandle::open` reconciles a surviving marker. A hard process kill leaves both the marker and leftover `.tmp` files, and open cannot finish a half-applied rotation because it holds no new Root Key. It therefore warns loudly that the vault may be in a mixed-epoch state, sweeps staged `.tmp` files so the next rotation starts clean, and leaves the marker in place. A sweep is not a successful commit.

Known boundary: a crash between the keywrap commit and the metadata re-saves leaves the marker and a warned mixed-epoch state. Rotation manifests are the planned hardening for that window.

Rotation distributes wraps as follows. The single-device and revocation rotation functions write the current device's keywrap. `rotate_root_key` also stages a fresh Root Key wrap for every other enrolled device that is eligible (pre-flip every device, post-flip admin devices only), so survivors can unlock after their next pull. Survivors of a revocation committed by another device hold a stale keywrap. At unlock they adopt their entry from the committed `meta/rekey/{epoch}.txn`: adoption requires that the file name, the transaction's `new_epoch`, and the canary epoch all agree, verifies the unwrapped key against the canary, runs before the cross-device heal so the survivor keeps its own identity, persists the adopted wrap for the fast path, and fails closed (the original unlock error stands). A member device on a team-shape vault never adopts Root Key material.

### Revocation

Ordinary revocation with a quorum available (two or more devices):

1. The device pulls the latest state and verifies all incoming commit signatures.
2. The user selects the target in the fleet dashboard and revokes it, which removes the target from the `DeviceRegistry`.
3. The epoch advances (N to N+1, ROTATING) and the Root Key rotates: new Root Key, new SGK, all item keys re-derived, all entries re-encrypted.
4. The Root Key is wrapped only for surviving devices; the revoked device's keywrap is deleted.
5. The revoked device's activity row is removed.
6. The device commits and pushes with a signed commit, for example `[device-revoke] removed <uuid>, epoch N+1`.

`revoke_device_and_rotate(target_id, self_id)` is the selective path. It refuses to revoke self, snapshots the registry, and restores it if the rotation cannot start, so a half-revoked in-memory fleet never reaches a save. It always self-acknowledges and commits. The justification is that Baluard personal vaults have a single administrator: quorum here means "enough devices to prove the admin authorized this", and a revoked device's old wrap cannot unwrap the new Root Key because the epoch changed. For vaults with four or more devices this commits without full multi-party quorum verification, and the other devices accept the new epoch on their next pull. Genuine multi-admin quorum is provided separately by the approval gate in ADR 0062 (`docs/adr/0062-two-admins-two-signatures.md`). The caller must write the new keywrap with the new Root Key afterward; `revoke_device_and_rekey` does this.

`force_evict_and_rotate(surviving_device_id)` is the emergency path for the case where every other device is lost. It clears all non-surviving devices, rotates immediately, wraps the new Root Key for the survivor, self-acknowledges, deletes evicted keywraps, and re-enables writes. Its `.committed` file has an empty `commit_barrier`, which is correct for a single-device emergency operation, not a multi-device quorum proof. As with the selective path, the registry is restored if the rotation cannot start. Force eviction without rotation is not eviction: the evicted device can decrypt everything until the rekey happens. Both paths are atomic.

A revoked device that pulls finds its signing key absent from the registry, so it cannot verify its own commits and enters read-only mode. It cannot decrypt new-epoch entries, and other devices reject its pushes because signature verification fails. Offline, it retains a readable copy at epoch N; the rotation makes that copy stale but cannot erase it, because remote wipe needs a server.

After a revocation the dashboard shows a persistent banner to rotate Git credentials ("Rotate git credentials for full security"). It parses the remote URL, builds a direct link to the provider's key settings page (for example `github.com/<repo>/settings/keys`), and lists numbered steps. It is dismissed only after an explicit checkbox confirmation. Credentials are not rotated automatically because the vault has no provider API access.

| Risk | Mitigation | Accepted because |
|---|---|---|
| No real-time revocation | Eventual consistency through Git pull | Fundamental to the serverless model |
| Revoked device retains epoch N data | Root Key rotation limits it to a stale snapshot | No remote wipe without a server |
| Git credentials not auto-rotated | Post-revocation warning and documentation | No provider API access from the vault |
| Activity index metadata (opaque UUIDs, times) | UUIDs opaque; private repository boundary; sealed locally in `activity.enc` | Low-sensitivity metadata |
| Self-reported timestamps | Corroborated by Git committer date and commit SHA | Display comes from Git log, not the file |

### Stalled rotation

If the initiating device goes offline during ROTATING, entry writes stay blocked. The design is a deterministic coordinator election after a timeout:

```
if state == ROTATING and elapsed > timeout and no progress commit:
    if any cipher file exists at the new epoch:
        re-initiate the rotation as the new coordinator; never abort
    candidates = enrolled device UUIDs sorted as big-endian 128-bit integers
    coordinator = candidates[0]
    if self is coordinator:
        abort the rotation (epoch returns to ACTIVE)
        write meta/rekey/{new_epoch}.aborted
```

Rules: the timeout defaults to one hour, within a range of 15 minutes to 24 hours; only the elected device may abort; the user must confirm before one device aborts another device's rotation; and abort is refused once new-epoch cipher files exist, because the rotation has begun to land. Aborting resets the epoch to ACTIVE, clears the pending transaction and acknowledgments, and propagates the write of the `.aborted` marker, since a silently dropped marker would wedge other devices on the stale transaction. After a pull, the daemon checks for `meta/rekey/{epoch+1}.aborted` and surfaces it.

Implementation status differs from the design. `DeviceManager` provides `rotation_stalled_secs`, `is_abort_coordinator` (lowest UUID by byte order), `abort_stalled_rotation`, and `has_abort_marker`. The shipped abort entry is the CLI command `baluard --direct devices rotation-abort`, which uses a fixed 3600-second threshold and only warns, without enforcing, that no cipher was re-encrypted at the new epoch; `rotation-status` reports state and elapsed time. A configurable timeout in `VaultSettings`, automatic election, and the enforced cipher-file check are specified but not yet wired.

### Enrollment

The first device enrolls automatically, because an empty registry auto-approves. Every additional device requires physical presence and master password confirmation on an enrolled device.

The enrollment payload holds the device id, X25519 and Ed25519 public keys, a timestamp, a nonce, the device name, and a binding to the target vault state: `vault_id`, `epoch`, and `registry_version`. Transfer is a base64url JSON string with three equivalent methods, chosen by what the device can do:

| Method | How | Best for |
|---|---|---|
| QR code | Display the string as a QR code and scan it | Phones and tablets |
| Manual copy | Display the string as text and type or paste it | No camera, accessibility needs, terminals |
| File export | Save as a `.json` file and move it by USB or LAN | Large payloads, batch enrollment |

The two-way pairing flow is:

1. The new device generates its keypair and shows payload #1 (device id, both public keys, nonce, timestamp, name).
2. The existing device validates timestamp, nonce, and keys, asks "Approve device?", and requires the master password.
3. The existing device signs the approval (Ed25519 over `"enroll" || JSON(payload)`), HPKE-wraps the Root Key to the new device, and builds a pairing bundle holding the wrapped key, the updated registry, and the approval signature.
4. The new device imports the bundle, verifies the approval signature, and unwraps the Root Key with its own X25519 key. Enrollment is complete.

The enrolling side checks, in order: the nonce was not seen before; the timestamp is within five minutes; both public keys decode to exactly 32 bytes; for a non-first device an approval is present, the approver is enrolled, and the signature verifies against the approver's registered signing key; and the payload's `epoch` and `registry_version` equal the vault's current values. A missing binding field is a rejection. The binding prevents a captured approval from being replayed against a different vault state; only the first device skips it. Anti-replay uses a unique 32-byte random nonce per attempt, persisted in `meta/seen-nonces.json` across restarts and capped at 10,000 entries with first-in-first-out eviction.

`VaultSettings::enrollment_policy` selects between two authorization paths. `Personal` is the default for new vaults: either an enrolled-device signature or the recovery phrase may authorize non-destructive enrollment. `Strict` is the default for existing vaults (a missing field reads as Strict): only an enrolled-device signature authorizes enrollment, and phrase use requires destructive recovery. The policy is stored in `settings.enc`, so it does not leak to the Git remote.

The motivation for the phrase path is that requiring an enrolled device to approve every new device is hostile to a solo, serverless user who has lost every device. The phrase is already the root authority behind `recover_from_phrase`, so non-destructive enrollment through it is a strict subset of that authority. If the phrase is compromised, the vault is already compromised. The master password alone remains insufficient to add a device.

`DeviceManager::enroll_with_recovery_phrase` is non-destructive. It unwraps the Root Key from `meta/recovery.json`, then reads the real enrollment policy from `settings.enc` decrypted with that recovered key, because a locked clone cannot decrypt settings and a caller-supplied policy misreported Strict. This read fails closed: a missing `settings.enc` (a legacy vault) enforces Strict, and a corrupt one is an error. `Strict` returns an error that points to `recover_from_phrase`. Post-flip team-shape vaults derive their settings key from a different root, so phrase enrollment fails there by design and directs the user to the Space Recovery Kit (`docs/adr/0067-the-phrase-is-the-last-key.md`). The method then applies the same timestamp and nonce replay checks, rejects an already enrolled device, and re-verifies the whole fetched history (when the vault has a Git repository) with Root-Key-keyed enrollment-proof checks, closing the clone-time window where proofs were only structurally checked. Only then does it enroll the device with no approver, write the keywrap using the caller's own X25519 key (so registry, keywrap, and local private key agree), bind the device to the Owner member, and write `meta/enrollments/<device_id>.proof`. The proof is an Ed25519 signature over the device's roster entry, keyed from a derivation of the Root Key, so peers can accept that device's first commit (`docs/adr/0081-the-proof-rides-the-commit.md`). Persisting the private keys is the caller's job.

Surfaces: the CLI command `baluard devices enroll-with-phrase [--phrase <24 words>]` prompts when no phrase is given, requires the typed word `enroll` after warning that the phrase is root authority, and rejects under Strict with a pointer to `baluard recover`. The `vault.enroll_with_phrase` IPC route validates the 24-word shape and policy, builds the current device's `EnrollmentPayload`, enrolls it, and writes `meta/device-privkey.json`.

During vault creation, desktop and CLI require the user to re-enter four recovery words before proceeding. Positions are derived deterministically by FNV-1a over the phrase, so the same phrase always asks for the same words. This is not security theater; it is the only defense against permanent loss when every device fails.

### Recovery from the phrase

Disaster recovery on a new device is destructive and bypasses `DeviceManager` enrollment and quorum entirely. The phrase is the root of trust, so no quorum, approval, or other device is needed. It parses and validates the BIP-39 phrase, derives the recovery key and X25519 secret, HPKE-unwraps the Root Key from `meta/recovery.json` (wrap context `recovery-keywrap`), takes the current epoch from the Root Key canary, resets the registry, generates fresh X25519 and Ed25519 keys for the new device, enrolls it as the sole device with no approver, sets the epoch active, writes the new keywrap, deletes every other keywrap, binds the device to the Owner member, and writes `meta/device-privkey.json` through the owner-only secret-file writer (no world-readable window). Key material is zeroized after use. The old registry is abandoned.

Rotation keeps recovery usable by re-wrapping the Root Key in `meta/recovery.json` to the stored recovery public key. A legacy vault whose `recovery.json` lacks that public key cannot be re-wrapped; the rotation warns loudly that the phrase will not work afterward and the user must re-enroll through the phrase.

### File layout

The `.baluard` marker is a file holding the vault version, ID, and slug. Under `meta/`:

```
rekey/
  {epoch}.txn             rotation proposal (HPKE-wrapped new Root Key per device)
  {epoch}.ack.{device}    signed device acknowledgment with txn_hash binding
  {epoch}.committed       finalized rotation (populated commit barrier)
  {epoch}.aborted         marker for a cancelled rotation
enrollments/{device}.proof  Root-Key-keyed proof for a phrase-enrolled device
devices.json              DeviceRegistry (plaintext; names stripped after first unlock)
device-state.json         combined atomic registry, epoch, and nonce snapshot
epoch.json                EpochInfo
seen-nonces.json          anti-replay enrollment nonces
keywrap/{device_id}.json  HPKE-wrapped Root Key per device
recovery.json             Root Key wrapped to the recovery phrase key
.rotation-pending         crash marker (old and new epoch), local, mode 0600
settings-pub.json         plaintext pre-unlock fields: theme, language, and the vault purpose and shape markers (ADR 0021)
settings.enc              AES-256-GCM: timeout, URI-match defaults, favicon setting, slug,
                          enrollment policy, device names (kept out of plaintext remote metadata)
profile.enc               display name, subtitle, avatar extension
folders/{id}.enc          one encrypted file per folder (legacy folders.enc, folders.json)
tags/{digest}.enc         one encrypted file per tag (legacy tags.enc, tag_index.json)
activity.enc              device activity index, encrypted under the activity key
avatar.enc                encrypted avatar image (see ADR 0016; legacy avatar.{ext} files are removed on rewrite)
```

Settings and profile encryption and the plaintext display-preferences split are decided in `docs/adr/0021-settings-split-encrypted-identity-plus-public-display-prefs.md`. Local-only files such as `device_activity.json`, `device-privkey.json`, and `device-id` are excluded by the vault `.gitignore` and never synced.

### Frontend

The desktop frontend is SolidJS with Tailwind v4 inside Tauri v2. IPC is request/response through `daemon(action, payload)`, which calls Tauri `invoke("daemon_request")`. There is no SSE and no streaming. Tauri commands that perform socket I/O are async and use `spawn_blocking`, so the webview thread never blocks on the daemon. Store structure, modal accessibility, and internationalization are decided in `docs/adr/0012-store-split.md`, `docs/adr/0015-modal-accessibility.md`, and `docs/adr/0019-full-i18n.md`.

### Tags

Tags are user-defined labels. Unlike a cipher's single folder assignment, a cipher may carry up to 20 tags.

Storage: `tags: Vec<String>` is encrypted inside `CipherEnvelopeData` with the cipher content, and decrypted ciphers are the source of truth. For autocomplete and filtering, the tag name set is cached as one encrypted file per tag at `meta/tags/<digest>.enc`, where the digest is the first 16 bytes of the SHA-256 of the name in hex, the name sits inside the encrypted body, and the key comes from the metadata key material (`derive_tags_key`). A filename is never user-controlled text. Saves skip unchanged tags and prune removed ones. Reads never delete anything; legacy sources are read as fallbacks (the single `tags.enc` envelope, then plaintext `tag_index.json`) and removed on write once the per-tag files are authoritative. The original design kept a plaintext sorted `meta/tag_index.json` with the same visibility tradeoff as plaintext folder names; that layout is now legacy and gitignored, so tag names no longer reach the remote in plaintext.

Constraints: at most 20 tags per cipher; at most 64 Unicode characters per tag, counted with `.chars().count()`; input is trimmed and lowercased on storage while display preserves what the user typed; empty or whitespace-only tags are rejected; and duplicates are removed case-insensitively before the 20 tag cap is applied. Violations are rejected, not truncated.

Components: `CipherInput.tags` (with `#[serde(default)]`), `CipherEnvelopeData.tags`, `Cipher.tags`, and `CipherMeta.tags` in `types.rs`; `TagIndex` in `manifest.rs`; and `VaultHandle::validate_tag` and `validate_tags`, `rebuild_tag_index`, `create_tag`, and `rename_tag` in `handle.rs`. Daemon routes are `tag.list`, `tag.create`, `tag.rename`, `tag.delete`, and `tag.rebuild_index`. The CLI provides `baluard tags list`, `create`, `rename`, and `delete`. In the desktop sidebar, tag pills filter on click and support deletion through a confirmation modal that removes the tag from every cipher (`docs/adr/0018-tag-deletion-with-confirmation.md`).

Validation boundary: `add_cipher` and `update_cipher` call `validate_tags` before writing, so length, deduplication, and normalization hold at the core library boundary regardless of caller (daemon, CLI, or direct).

Index rebuild: the tag index is rebuilt from decrypted cipher tags on every `vault.list_full` (desktop unlock), after every add or update through the daemon, and after pulls. A synchronized merge of the cache is deliberately not implemented: the cache is rebuilt from ground truth rather than merged, which avoids independent merge conflicts at the cost of decrypting after a pull. Rotation re-saves the tag set under the new key.

## Consequences

The private Git repository is the access boundary for the plaintext device registry. Public keys and opaque UUIDs are visible to anyone who can read the repository, while display names, the activity index, and tag names are encrypted. Revocation is eventual: it cannot erase offline copies or revoke provider credentials, and the persistent banner is the only mitigation. Stale-device labels prompt a review but never revoke automatically.

Multi-device rotation blocks writes until quorum and convergence, and a stalled rotation needs an operator abort until election is wired. Local transport requires physical transfer of acknowledgments. Rotation correctness depends on staged renames with the keywrap last, on the crash marker staying armed after any failure, and on propagating every post-swap re-seal error; a hard kill between the keywrap commit and the metadata re-saves leaves a warned mixed-epoch vault, not a silent one.

Recovery-phrase enrollment is a strict subset of the phrase's existing root authority, while Strict policy requires an enrolled device. The master password alone never adds a device. Because the phrase can enroll and can destructively recover, losing it and every device loses the vault, which is why creation forces a write-down check.

Known gaps and source divergences carried by this appendix:

- The stall timeout setting, automatic coordinator election, and the enforced new-epoch cipher check are design only; the CLI abort uses a fixed one-hour threshold and a warning.
- `revoke_device_and_rotate` commits on a self-acknowledgment for vaults of any size. Multi-admin protection comes from the separate approval gate, not from the ack quorum.
- The write sequence in `FileDeviceManagerStore::save_state` is not atomic across files.
- The original text described the activity index as a plaintext synced file and device names and tag names as plaintext. The code now keeps the activity working file local and gitignored, seals it in `activity.enc`, folds names into `settings.enc`, and stores tags as encrypted per-tag files. This appendix follows the code.

The original multi-user section listed per-user device registries, role-based revocation, per-collection Space Group Keys, per-user activity privacy, Shamir recovery, and an administrator fleet dashboard as out of scope. Roles, collection keys, signed approvals, and admin-gated rotation have since shipped under `docs/adr/0085-sharing.md` and the ADRs that follow it through `docs/adr/0084-signing-keys-and-certificates-are-a-first-class-cipher.md`. Shamir M-of-N recovery and an all-users fleet dashboard remain unspecified here.

## References

- `docs/adr/0003-key-hierarchy-device-bootstrapping.md`
- `docs/adr/0043-team-shape-flip.md`
- `docs/adr/0062-two-admins-two-signatures.md`
- `docs/adr/0063-the-stage-is-the-policy.md`
- `docs/adr/0067-the-phrase-is-the-last-key.md`
- `docs/adr/0074-the-flip-keeps-keys-from-members-not-from-admins.md`
- `docs/adr/0081-the-proof-rides-the-commit.md`
- `docs/adr/0085-sharing.md`
- `docs/adr/0097-hardware-backed-keys.md`
- `docs/security/forward-secrecy-model.md`
- `docs/security/threat-model.md`
- `docs/security/emergency-org-identity.md`
