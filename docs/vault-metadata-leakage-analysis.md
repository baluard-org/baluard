# Vault Metadata Leakage Analysis

**Date:** 2026-06-09
**Peer Review:** 2026-06-09 (peer review via peer, Agy via agy)
**Scope:** Filesystem-level metadata exposure in the current vault format
**Threat model:** Observer with read access to the vault directory (no decryption keys). Includes: malware, cloud storage scanner, git remote host, any process on the user machine.

---

## 0. Peer Review Verdict

Two independent security architects (peer review, Agy) reviewed this analysis against the Baluard Rust/Tauri codebase.

**Consensus: Critical.** Two findings were independently classified as critical by both reviewers:

1. **`device-privkey.json`** -- Raw hex X25519/Ed25519 private keys on disk. `handle.rs:248-271` reads them as the production code path (the comment `"NOT for production!"` is aspirational). Any same-user process can extract device identity keys with `cat`. Combined with master password compromise, fully breaks the vault.

2. **`folders.json` + `tag_index.json`** -- Committed to git in cleartext. Baluard's identity is "git-native password manager." Any remote host with repo access (GitHub, GitLab, Gitea, S3, any cloud sync) gets full content classification without decryption. This is the highest-probability external attacker path.

Everything else is medium or below. The cipher encryption (AES-256-GCM, padded buckets, random UUID filenames) is sound. The vulnerability is exclusively in metadata handling.

Full peer review with implementation plans: `docs/vault-metadata-leakage-peer-review.md`

---

## 1. Plaintext Data Leaks

These files contain cleartext information that reveals vault content, identity, or operational state directly.

### 1.1 `meta/folders.json` -- CRITICAL

**Peer severity upgrade:** High -> Critical (both reviewers, git-sync threat model)

**What it contains:** Full folder names and hierarchy.

```json
[
  { "id": "c6dbb768-...", "name": "Otra Si", "parent_id": null, "icon": null },
  { "id": "1185b71c-...", "name": "Sub folder", "parent_id": "c6dbb768-...", "icon": null }
]
```

**What leaks:**
- Folder names in cleartext. Names like "Banking", "Work VPN", or "Crypto Wallets" directly expose what types of secrets the vault holds.
- Parent-child relationships reveal organizational structure. An attacker can reconstruct the full folder tree.
- The number of folders reveals vault complexity.

**Why critical (peer rationale):** These files are committed to git. A remote host with read access to the repository gets full content classification without any decryption. In a breach of a private repo or a misconfigured public repo, the attacker immediately knows the user's secret categories. This is the highest-probability external attacker path for a git-native password manager.

**Impact:** Critical (git-sync). High (local).

### 1.2 `meta/tag_index.json` -- CRITICAL

**Peer severity upgrade:** High -> Critical (both reviewers, git-sync threat model)

**What it contains:** All tag labels and last update timestamp.

```json
{
  "tags": ["personal", "private", "social", "tag uno", "tres"],
  "updated_at": 1780976864
}
```

**What leaks:**
- Every tag label in cleartext. Tags like "banking", "2fa", "crypto", or "work-credentials" directly classify cipher content.
- `updated_at` timestamp reveals when tags were last modified, adding to the activity timeline.
- Tag count hints at vault complexity and categorization habits.

**Why critical (peer rationale):** Same as folders. Committed to git. Remote host gets full content classification. Combined with folder names, they provide a near-complete map of vault contents without ever decrypting a single cipher.

**Impact:** Critical (git-sync). High (local).

### 1.3 `meta/settings.json` -- Medium-High

**What it contains:** User profile and vault preferences.

```json
{
  "auto_lock_minutes": 15,
  "theme": null,
  "default_uri_match": null,
  "fetch_favicons": true,
  "display_name": "EstebanForge",
  "subtitle": "The Architect",
  "avatar_ext": null
}
```

**What leaks:**
- `display_name` and `subtitle` directly identify the vault owner. Enables correlation with other data sources.
- `auto_lock_minutes` reveals security posture. 15 minutes is relaxed; 1 minute is paranoid.
- `fetch_favicons: true` reveals the vault has entries with URIs (otherwise this setting would be irrelevant).
- `theme` could reveal platform or accessibility preferences.

**Impact:** Medium-High. Identity correlation is the primary risk. An attacker can link this vault to a specific person and assess their security habits. Committed to git, so exposed to remote hosts.

### 1.4 `meta/devices.json` -- Medium

**What it contains:** Device registry with names, public keys, enrollment data.

```json
{
  "version": 1,
  "devices": {
    "96295570-add3-4c85-8526-b8ffeca51d82": {
      "device_id": "96295570-...",
      "name": "this-device",
      "encryption_public_key": "7ddb6ecd...",
      "signing_public_key": "b2adb3b6...",
      "enrolled_at": 1780527602,
      "enrolled_by": null,
      "last_seen_epoch": 0
    }
  }
}
```

**What leaks:**
- Device names. "this-device" is generic, but "MacBook Pro Work" or "iPhone 15 Pro" reveals fleet composition and hardware.
- `enrolled_at` (Unix timestamp) reveals when the vault was first created on this device.
- `enrolled_by: null` confirms this is the founding device (first enrollment, no approver).
- `last_seen_epoch: 0` reveals no key rotation has ever occurred.
- Device count (1) reveals this is a single-device vault. An attacker knows there is no second device to revoke from.
- Public keys are not secret by definition, but they uniquely fingerprint the device and can be used for tracking across vaults.

**Impact:** Medium. Device fleet intelligence is operationally valuable. A single-device vault with no key rotation is a softer target. Public keys are designed for exposure; encrypting them has low ROI per both reviewers.

### 1.5 `meta/device_activity.json` -- Medium

**What it contains:** Per-device sync activity record.

```json
{
  "v": 1,
  "devices": {
    "96295570-...": {
      "last_push": "2026-06-03T23:00:02Z",
      "last_commit": "84f34355...",
      "epoch": 0
    }
  }
}
```

**What leaks:**
- `last_push` timestamp reveals when the vault was last synced or committed.
- `last_commit` SHA correlates with git history (confirming the commit timeline).
- `epoch: 0` confirms no key rotation has happened since vault creation.

**Impact:** Medium. Contributes to the activity timeline. Reveals usage patterns and security posture (no rotation). Committed to git.

### 1.6 `meta/kdf-params.json` -- Low-Medium

**What it contains:** Full Argon2id parameter set.

```json
{
  "profile": "DesktopStd",
  "memory_kib": 65536,
  "time_cost": 3,
  "parallelism": 2,
  "salt": "68f4854c1d4f538f..."
}
```

**What leaks:**
- `profile: "DesktopStd"` reveals the device class. An attacker knows this is a desktop machine, not mobile.
- Exact `memory_kib`, `time_cost`, and `parallelism` tell the attacker precisely how much computation a brute-force attempt requires per guess. They can size their hardware accordingly.
- The salt is designed to be public (prevents rainbow tables), so its exposure is expected and not a vulnerability.

**Peer note:** The profile name is redundant for the vault format. It aids attackers by revealing device class. Both reviewers recommend removing it (`#[serde(skip_serializing)]`). The numeric parameters alone are sufficient for decryption.

**Impact:** Low-Medium. Salt exposure is expected. Profile name is an unnecessary hint.

---

## 2. Structural and Behavioral Metadata Leaks

These vectors leak information through file properties, directory layout, and filesystem metadata, not file contents.

### 2.1 Cipher Count

**Vector:** File count in `ciphers/` directory.

**What leaks:** The exact number of secrets stored in the vault.

**Observed:** 5 files = exactly 5 ciphers.

**Impact:** Low-Medium. A vault with 3 entries suggests a casual user. A vault with 500 suggests an enterprise target. Small vaults are easier to brute-force (less data to validate against). Agy suggests dummy padding files as mitigation; both reviewers agree the ROI is low.

### 2.2 File Modification Timestamps -- Medium

**Vector:** `mtime` on each cipher `.enc` file.

**Observed:**
```
4f39ce0d  2026-06-08 20:07:53
6c647014  2026-06-08 19:14:28
75cb32d1  2026-06-07 13:52:49
b443f301  2026-06-08 20:11:07
eaefc02d  2026-06-08 21:04:47
```

**What leaks:**
- When each cipher was created or last edited (to the second).
- Activity patterns: a burst of 4 edits on Jun 8 between 19:14 and 21:04 reveals an active session.
- Gaps between edits reveal user behavior (continuous creation vs. sporadic updates).
- Combined with folder/tag metadata, timestamps can correlate cipher creation with specific events.

**Peer verdict:** Mitigate (both reviewers). Cannot be fixed -- timestamps are inherent to filesystems. Normalize to a common timestamp on lock. Accept as v1 limitation.

**Impact:** Medium. Timestamps are a rich behavioral signal but require local filesystem access.

### 2.3 File Permissions Inconsistency

**Vector:** Mixed permission modes across vault files.

**Observed:**
```
600  device-privkey.json, device_activity.json, folders.json,
     kdf-params.json, kek-canary.enc, recovery.json, rk-canary.enc,
     settings.json, tag_index.json

644  ciphers/*.enc, devices.json, index.enc
```

**What leaks:**
- `644` on cipher files means any process on the machine can read encrypted ciphers. While the content is encrypted, the file existence and metadata are exposed.
- `644` on `devices.json` leaks the device registry to any process.
- The inconsistency itself is a signal: an attacker can infer which files contain sensitive metadata (0600) vs. which are considered less sensitive (0644).

**Impact:** Low-Medium. Permissions limit exposure to local processes, but the inconsistency reveals the developer's sensitivity classification.

### 2.4 Git Commit History

**Vector:** Git log in `.git/`.

**Observed:** Single commit `84f3435 vault update` at `2026-06-03 19:00:02 -0400`.

**What leaks:**
- Commit timestamps (even with the static `"vault update"` message) reveal when vault changes were committed.
- Author name and email from git config are embedded in commits. With sync to a remote, this identifies the vault owner.
- Commit frequency reveals usage patterns.
- The static message `"vault update"` is good (no operational hints), but commit count and timing are still visible.

**Peer verdict:** Mitigate. Agy recommends generic git author config at vault init (`user.name "Baluard User"`, `user.email "vault@baluard.local"`) and normalized commit dates. peer review did not address this but agrees static messages are already in place.

**Impact:** Medium with local access. High with remote sync (git push to a server).

### 2.5 Directory Structure

**Vector:** Named subdirectories in the vault.

**Observed:**
```
vault/
  ciphers/          # encrypted blobs
  meta/
    keywrap/        # per-device wrapped keys
    sequences/      # per-device sequence manifests
  trash/            # soft-deleted items
```

**What leaks:** The full vault schema is visible. An attacker knows exactly where each type of data lives, what the key hierarchy looks like (keywrap per device), and that soft-delete exists (trash/).

**Impact:** Low. Schema visibility aids targeted attacks but does not directly expose secrets.

### 2.6 Keywrap Filename = Device UUID

**Vector:** `meta/keywrap/<device-uuid>.json`

**Observed:** `meta/keywrap/96295570-add3-4c85-8526-b8ffeca51d82.json`

**What leaks:** The filename directly links the device identity (UUID) to its key wrap file. Combined with `devices.json`, an attacker can map each device to its wrapped key material.

**Impact:** Low. The UUID is already in `devices.json`. But the filename confirms which keywrap belongs to which device without cross-referencing.

---

## 3. Crypto-Operational Leaks

These vectors reveal cryptographic parameters, envelope structure, or key material handling that could aid cryptanalysis or targeted attacks.

### 3.1 Device Private Keys on Disk -- CRITICAL

**Peer severity upgrade:** High -> Critical (both reviewers, local threat model)

**File:** `meta/device-privkey.json` (179B)

**What leaks:**
```json
{
  "x25519_private": "<64 hex chars>",
  "ed25519_private": "<64 hex chars>"
}
```

- Full device private keys in plaintext hex. Not encrypted.
- Any process with file read access (even without root) can extract device identity keys.
- Listed in `.gitignore` (not committed to git), but sits unprotected on local disk.
- File permissions are `0600`, which restricts to owner only. This is the only protection.

**Why critical (peer review):** `handle.rs:248-271` reads raw hex X25519 private keys from a plaintext file on disk. The comment at line 247 says `"NOT for production!"` but there is no keyring path implemented -- this IS the production code path. Any process running as the same user (browser, npm package, any Electron app, any script with file read access) can extract the device private key. Combined with the master password (keylogger, shoulder surfing, reuse) it fully compromises the vault. The `.gitignore` entry prevents git exposure but does nothing for local malware. This is real-world exploitable with a single `cat` command.

**Why critical (Agy):** Raw private keys stored on disk allow local processes to impersonate the device, bypassing sync enrollment gates.

**Impact:** Critical (local). Not exposed via git (gitignored).

### 3.2 Canary Envelope Structure

**Files:** `meta/kek-canary.enc` (89B), `meta/rk-canary.enc` (87B)

**What leaks:**
- Envelope header (version, algorithm ID, key epoch, nonce counter, tier) is embedded in the serialized envelope.
- The size difference (89B vs 87B) reveals different payloads or parameters between KEK and RK canaries.
- Format is known: EnvelopeHeader + nonce + ciphertext + tag.

**Impact:** Low. Reveals the envelope format and algorithm, but this is standard Kerckhoffs-principle exposure. The key material remains protected.

### 3.3 Recovery Key Envelope

**File:** `meta/recovery.json` (288B)

**What leaks:**
```json
{
  "encrypted_key": "14e90b5f...",
  "ephemeral_public": "3df85a85...",
  "tag": "342bab94..."
}
```

- Confirms HPKE usage for key wrapping.
- Reveals the exact HPKE structure: ephemeral public key + encrypted key + authentication tag.
- The `ephemeral_public` key is not secret but uniquely identifies this recovery wrap.

**Impact:** Low. HPKE public keys are designed for exposure. But confirming the exact crypto scheme removes trial-and-error for attackers.

### 3.4 Padded Bucket Tier Determinism

**Vector:** `Tier::fit()` is deterministic based on plaintext size.

**What leaks:**
- All 5 ciphers are exactly 5.1KB (Xs tier, 5KB boundary). This is the padding working correctly.
- However, if an attacker can observe the vault over time (adding/removing entries), they can infer approximate plaintext sizes when a cipher moves from one tier to another (e.g., Xs to S = plaintext grew past 5KB).
- The tier boundaries are known (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB), so file size maps directly to a tier.

**Impact:** Low. Padded buckets are effective for static observation. The weakness is longitudinal analysis across edits.

---

## 4. Defenses Already in Place

These are the mitigations the current format implements correctly.

### 4.1 Cipher Content Encryption

All cipher blobs are encrypted with AES-256-GCM using per-cipher item keys derived via HKDF from the Space Group Key. No plaintext secret material crosses the filesystem.

### 4.2 Random UUID Cipher Names

Cipher filenames are random UUIDs (e.g., `4f39ce0d-fdb2-41d2-9fde-a6e0c92021ae.enc`). They carry no information about cipher type, content, or creation order.

### 4.3 Padded Bucket Sizes

All cipher blobs are padded to a fixed tier boundary. In this vault, all 5 ciphers are 5.1KB (Xs tier). An observer cannot distinguish which cipher has more or fewer fields. Size-based fingerprinting is neutralized for static observation.

### 4.4 Static Git Commit Messages

All commits use the constant message `"vault update"` (defined in `sync/commit.rs`). No operational hints are embedded in commit messages.

### 4.5 Cover Commits

The `cover_commit()` method creates empty commits (same tree as HEAD) that are indistinguishable from real vault updates. This pads the commit timeline to obscure real activity patterns.

### 4.6 Encrypted Index

`meta/index.enc` is fully encrypted. Cipher metadata (name, type, favorite status, URIs) is not readable without the root key.

### 4.7 Device Private Keys Gitignored

`meta/device-privkey.json` is listed in `.gitignore` and will not be pushed to a remote repository.

---

## 5. Attack Surface Summary

### What an attacker learns from filesystem access alone (no keys needed):

| Category | Data | Source |
|----------|------|--------|
| **Identity** | Display name, subtitle | `settings.json` |
| **Vault size** | Exact cipher count (5) | `ciphers/` file count |
| **Content classification** | All folder names, all tag names | `folders.json`, `tag_index.json` |
| **Organizational structure** | Folder hierarchy, tag taxonomy | `folders.json`, `tag_index.json` |
| **Activity timeline** | Per-cipher edit timestamps (second-precision) | Filesystem `mtime` |
| **Creation date** | Vault enrollment date | `devices.json` `enrolled_at` |
| **Last activity** | Last push/commit date | `device_activity.json`, git log |
| **Security posture** | KDF params, auto-lock timeout, single device, no key rotation | `kdf-params.json`, `settings.json`, `devices.json` |
| **Device identity keys** | X25519 + Ed25519 private keys | `device-privkey.json` (local only) |
| **Crypto scheme** | HPKE structure, envelope format, AES-256-GCM | Canary files, recovery.json, keywrap files |
| **Vault schema** | Full directory structure | Directory listing |

### Risk Rating by Attack Vector (Peer-Confirmed)

| Vector | Risk | Exploitability | Fix/Mitigate |
|--------|------|----------------|--------------|
| Device private keys on disk | **Critical** | Trivial (local `cat`) | FIX |
| Plaintext folder names (git-sync) | **Critical** | Trivial (git push) | FIX |
| Plaintext tag names (git-sync) | **Critical** | Trivial (git push) | FIX |
| User identity in settings | **Medium** | Trivial (read file) | FIX (partial) |
| Device activity timestamps | **Medium** | Trivial (read file) | FIX |
| Filesystem timestamps | **Medium** | Trivial (`stat`) | MITIGATE |
| Device fleet composition | **Medium** | Trivial (read file) | MITIGATE |
| Git commit timeline + author | **Medium** | Trivial (`git log`) | MITIGATE |
| KDF profile name | **Low** | Trivial (read file) | FIX (trivial) |
| File permissions mix | **Low** | Trivial (local) | FIX |
| Envelope structure | **Low** | Requires format knowledge | Accept (Kerckhoffs) |
| Padded bucket tier inference | **Low** | Requires longitudinal observation | Accept |
| Cipher UUID names | **None** | Random, no information | N/A |

---

## 6. Remediation Plan

Based on peer review consensus (peer review + Agy). All recommendations have unanimous reviewer agreement unless noted.

**Definitions:**
- **Fix** = eliminate the root cause. The secret data no longer exists in the exposed location.
- **Mitigate** = reduce exposure without solving the root cause. Accept residual risk.

### 6.1 Encrypt `folders.json` and `tag_index.json` -- Rank 1

**Impact:** Highest. **Effort:** Low. **Verdict:** FIX (both reviewers).

The highest-priority fix. Addresses the git-sync threat model: the core product identity. The `index.enc` pattern proves the infrastructure works. This is a straight copy.

**Implementation:**

In `crates/baluard-core/src/crypto/hkdf_derive.rs`, add derivation functions:

```rust
pub fn derive_folders_key(root_key: &[u8]) -> Result<[u8; 32], BaluardError> {
    derive_subkey(root_key, b"baluard-folders-v1")
}
pub fn derive_tags_key(root_key: &[u8]) -> Result<[u8; 32], BaluardError> {
    derive_subkey(root_key, b"baluard-tags-v1")
}
```

In `vault/handle.rs`:
- `save_folders()` and `list_folders()` -- require unlocked state, derive folders key from `root_key`, encrypt/decrypt as AES-256-GCM envelope. Write to `meta/folders.enc`.
- `rebuild_tag_index()` / `list_tags()` -- same pattern. Write to `meta/tags.enc`.
- Migration: in `open()`, if `meta/folders.json` exists and vault unlocks, encrypt, write `.enc`, delete `.json`.

**UX impact:** Zero. Folders and tags are only shown in unlocked view. No screen needs them before unlock.

**Design choice:** Separate `.enc` files rather than merging into `index.enc`. Independent read/write avoids re-encryption cascades when only folders or tags change. The `index.enc` pattern is proven and well-understood.

### 6.2 Move `device-privkey.json` to OS Keyring -- Rank 2

**Impact:** Highest (local threat). **Effort:** Medium. **Verdict:** FIX (both reviewers).

The `keyring` crate is already in the dependency tree. The comment at `handle.rs:247` is a TODO in disguise.

**Implementation:**

In `vault/handle.rs`, replace the privkey read at lines 248-271:

```rust
fn load_device_privkey(vault_path: &Path, device_id: Uuid) -> Result<DevicePrivKeys, BaluardError> {
    let service = format!("baluard-{}", derive_vault_fingerprint(vault_path));
    let entry = keyring::Entry::new(&service, &device_id.to_string())
        .map_err(|e| VaultError::Metadata(format!("keyring: {e}")))?;

    // 1. Try keyring first
    if let Ok(secret) = entry.get_password() {
        return parse_privkey_json(&secret);
    }

    // 2. Fall back to file (backward compat), then migrate
    let privkey_path = vault_path.join("meta/device-privkey.json");
    if privkey_path.exists() {
        let json = std::fs::read_to_string(&privkey_path)?;
        let secret = parse_privkey_json(&json)?;
        let _ = entry.set_password(&json);   // migrate to keyring
        let _ = std::fs::remove_file(&privkey_path); // delete plaintext
        return Ok(secret);
    }

    Err(VaultError::NotFound("device private key not found".into()).into())
}
```

Keyring service name: `hex::encode(&kdf_params.salt[..8])` -- stable per vault, unique across multiple vaults on same machine.

Call sites to update:
- `rotate_root_key()` (lines 1695-1717)
- `revoke_device_and_rekey()` (lines 1820-1841)
- Both read `device-privkey.json` directly. Replace with `load_device_privkey()`.

In `vault/creation.rs`: store to keyring first at vault creation. Fall back to file on keyring error (headless Linux without libsecret).

### 6.3 Uniform `write_vault_file()` Helper + 0600 Everywhere -- Rank 3

**Impact:** Medium (local). **Effort:** Low. **Verdict:** FIX (permissions consistency).

Several write paths skip permissions: `add_cipher` (line 966), `delete_cipher` (line 853), `restore_cipher` (line 899), rotation staged writes.

**Implementation:**

In `vault/mod.rs` or new `vault/io.rs`:

```rust
pub(crate) fn write_vault_file(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
```

Replace every `std::fs::write()` in the vault module with this. Approximately 12 call sites. Also consider `umask 0077` at daemon startup as defense-in-depth.

### 6.4 Remove KDF Profile Name -- Rank 4

**Impact:** Low. **Effort:** Trivial. **Verdict:** FIX (both reviewers).

In `types.rs`, add `#[serde(skip_serializing)]` to the `profile` field on `KdfParams`, or remove it entirely. The profile name is not needed for decryption. The numeric parameters alone are sufficient.

Done in 5 minutes.

### 6.5 Encrypt Identity Fields in `settings.json` -- Rank 5

**Impact:** Medium (git sync). **Effort:** Medium. **Verdict:** FIX partial (both reviewers).

Split `VaultSettings` into:
- `AppPrefs` (plaintext: `auto_lock_minutes`, `theme`, `fetch_favicons`, `default_uri_match`) -- stays at `meta/settings.json`. Needed pre-unlock for UI.
- `UserProfile` (encrypted: `display_name`, `subtitle`, `avatar_ext`) -- goes to `meta/profile.enc`, encrypted with `hkdf_derive::derive_profile_key(root_key)`.

On unlock, decrypt and merge into memory. On lock, drop from memory.

### 6.6 Normalize Filesystem Timestamps -- Rank 6

**Impact:** Medium. **Effort:** Low. **Verdict:** MITIGATE (both reviewers).

Use `filetime` crate to set all vault file timestamps to a fixed constant on lock. Accept residual risk of timestamps visible during an active unlocked session. Normalizing on every write is N disk operations and triggers git noise; on lock is the cleaner approach.

### 6.7 Obscure Git Author Metadata -- Rank 7

**Impact:** Medium (git sync). **Effort:** Low. **Verdict:** MITIGATE (Agy; peer review did not address).

At vault init, configure local repo with generic author:
```
git config user.name "Baluard User"
git config user.email "vault@baluard.local"
```
The static commit message (`"vault update"`) is already in place. Generic author config completes the picture.

---

## 7. Implementation Roadmap

Ordered by dependency and priority. Each phase is independently deployable.

### Phase 1: Critical Fixes (2-3 days)

| Task | Files | Effort |
|------|-------|--------|
| Encrypt `folders.json` -> `folders.enc` | `crypto/hkdf_derive.rs`, `vault/handle.rs` | Low |
| Encrypt `tag_index.json` -> `tags.enc` | `crypto/hkdf_derive.rs`, `vault/handle.rs` | Low |
| Migration: `.json` -> `.enc` on unlock | `vault/handle.rs` | Low |
| Uniform `write_vault_file()` helper | `vault/mod.rs` or new `vault/io.rs` | Low |

### Phase 2: Keyring Migration (2-3 days)

| Task | Files | Effort |
|------|-------|--------|
| `load_device_privkey()` with keyring primary | `vault/handle.rs` | Medium |
| Update `creation.rs` to store in keyring | `vault/creation.rs` | Medium |
| Update `rotate_root_key()` and `revoke_device_and_rekey()` | `vault/handle.rs` | Medium |
| Backward-compatible file fallback + auto-migration | `vault/handle.rs` | Low |

### Phase 3: Hardening (1-2 days)

| Task | Files | Effort |
|------|-------|--------|
| Remove KDF profile name | `types.rs` | Trivial |
| Encrypt `settings.json` identity fields -> `profile.enc` | `vault/handle.rs`, `crypto/hkdf_derive.rs`, `vault/manifest.rs` | Medium |
| Normalize timestamps on lock | `vault/handle.rs` (new helper, `filetime` crate) | Low |
| Generic git author config at vault init | `sync/engine.rs` | Low |
| Enforce 0600 on all vault files (via `write_vault_file`) | All vault write sites | Low |

### Phase 4: Defense-in-Depth (Future)

| Task | Notes |
|------|-------|
| Encrypt `device_activity.json` (merge into `index.enc`) | Requires index schema change |
| Encrypt device names in `devices.json` | Low ROI, complex enrollment flow impact |
| Cover commit scheduling policy | Already implemented, needs scheduling policy |

---

## 8. What Not To Do (Low ROI)

Both reviewers agreed these are not worth the complexity:

| Item | Reason |
|------|--------|
| **Dummy cipher padding files** | Obfuscates count but adds sync complexity. Attacker can still observe file count changes over time. |
| **Encrypt `devices.json` fully** | Public keys are designed to be public. Encrypting device names alone is low ROI. File needed for enrollment before full unlock. |
| **Timestamp normalization on every write** | N disk writes per cipher operation. Triggers git status noise. Normalize on lock instead. |

---

## 9. Open Questions

Decisions required before implementation begins:

1. **Keyring fallback policy:** If OS keyring is unavailable (headless Linux, CI, container), refuse to operate or fall back to encrypted file? peer review: plaintext file fallback with auto-migration. Agy: hardware-derived key encryption for fallback.

2. **Folders/tags encryption approach:** Separate `.enc` files (recommended: independent read/write, no re-encryption cascade) or merge into `index.enc` (single blob, simpler git diffs, larger re-encryption surface)?

3. **Timestamp normalization trigger:** On lock (recommended: fewer writes, cleaner) or on every write (more thorough, more I/O and git noise)?

4. **Git author identity:** Enforce generic config at vault init (prevents identity leaks) or respect user's global git config (user expectation for attribution)?

5. **Backward compatibility window:** How long to maintain `.json` -> `.enc` migration? Until next major version, or permanently?
