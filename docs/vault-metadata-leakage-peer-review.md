# Vault Metadata Leakage: Peer Security Review

**Date:** 2026-06-09
**Reviewers:** TARS (lead), peer review (via peer), Agy (via agy)
**Subject:** `docs/vault-metadata-leakage-analysis.md`
**Scope:** Independent security architects assessing the same leakage report against the IDtty Rust/Tauri codebase

---

## 1. Is This Critical?

### Consensus: Yes.

Both peer agents independently classified the findings as critical, identifying the same two root causes.

### the Assessment

> **Finding 1 -- `device-privkey.json`: CRITICAL.** Look at `handle.rs:248-271`. The unlock path reads raw hex X25519 private keys from a plaintext file on disk. The comment at line 247 says `"NOT for production!"` but there is no keyring path implemented -- this IS the production code path. Any process running as the same user (browser, npm package, any Electron app, any script with file read access) can extract the device private key. Combined with the master password (keylogger, shoulder surfing, reuse) it fully compromises the vault. The `.gitignore` entry prevents git exposure but does nothing for local malware. This is real-world exploitable with a single `cat` command.

> **Finding 2 -- `folders.json` + `tag_index.json`: CRITICAL in the git-sync threat model.** IDtty's entire identity is "git-native password manager." These files are committed to git. A remote host (GitHub, GitLab, Gitea, S3, any cloud sync) with read access to the repository gets full content classification without any decryption. In a breach of a private repo -- or a misconfigured public repo -- the attacker immediately knows `["Banking", "Crypto Wallets", "Work VPN", "2FA Seeds"]`. This is the highest-probability external attacker path for this product.

> **Everything else is medium** -- real information leakage, but requires local filesystem access and doesn't directly break the crypto.

### Agy's Assessment

> While the core cipher payloads remain secure under AES-256-GCM, the metadata exposure is critical. Under the defined threat model, a passive observer (such as a cloud sync provider, git host, or local user-space malware) can reconstruct the user's identities, exact account categories, active usage hours, and extract device private keys.

> **Criticality rationale:**
> - **Trivial Exploitability:** Trivial read access is all that is required for most leaks. No decryption keys or complex exploitation techniques are needed.
> - **Identity and Structure Correlation:** Cleartext folder and tag indices allow attackers to catalog vault contents.
> - **Device Impersonation:** Raw private keys stored on disk allow local processes to impersonate the device, bypassing sync enrollment gates.

### Combined Verdict

| Finding | Severity | Exploitability | Attack Path |
|---------|----------|----------------|-------------|
| `device-privkey.json` plaintext | **Critical** | Trivial (local `cat`) | Malware, any same-user process |
| `folders.json` plaintext | **Critical** | Trivial (git push) | Remote: any git host with repo access |
| `tag_index.json` plaintext | **Critical** | Trivial (git push) | Remote: any git host with repo access |
| `settings.json` identity fields | **Medium** | Trivial (local + git) | Remote + local |
| `device_activity.json` | **Medium** | Trivial (local + git) | Remote + local |
| File timestamps (mtime) | **Medium** | Trivial (local `stat`) | Local |
| `devices.json` fleet info | **Medium** | Trivial (local + git) | Remote + local |
| KDF profile name | **Low** | Trivial (local + git) | Remote + local |
| File permissions mix (0644 vs 0600) | **Low** | Trivial (local) | Local |
| Cipher count | **Low** | Trivial (local `ls`) | Local |

---

## 2. Fix or Mitigate?

### Definitions

- **Fix** = eliminate the root cause. The secret data no longer exists in the exposed location.
- **Mitigate** = reduce exposure without solving the root cause. Accept residual risk.

### Agent-by-Agent Classification

#### the Fix/Mitigate Table

| Finding | Verdict | Reason |
|---------|---------|--------|
| `device-privkey.json` | **FIX** | Move to OS keyring. Permissions don't help; same-user processes bypass 0600. |
| `folders.json` plaintext | **FIX** | Committed to git. Permissions irrelevant. Encrypt it. |
| `tag_index.json` plaintext | **FIX** | Same. Encrypt it. |
| `settings.json` display_name | **FIX** (partial) | Encrypt identity fields. Keep theme/auto-lock plaintext -- needed pre-unlock for UI. |
| `device_activity.json` | **FIX** | Committed to git, reveals epoch state and sync timestamps. Merge into `index.enc`. |
| File timestamps (cipher mtimes) | **MITIGATE** | Can't fix. Normalize mtimes on lock. Accept as v1 limitation. |
| `devices.json` | **MITIGATE** | Public keys are designed to be public. Encrypt device names only, or leave. Low-ROI fix. |
| KDF profile name | **FIX** (trivial) | Drop the field. One `#[serde(skip)]`. |
| Permissions mix (0644 vs 0600) | **MITIGATE** | Use one write helper that always sets 0600. Won't help git remotes but helps local. |

#### Agy's Fix/Mitigate Table

| Finding | Verdict | Strategy |
|---------|---------|----------|
| Folders & Tags | **Fix** | Move these data structures inside the encrypted `index.enc` payload. |
| Device Private Keys | **Fix** | Move keys to OS keychain; delete the plaintext file. |
| File Modification Timestamps | **Mitigate** | Normalize file timestamps on disk to a constant value. |
| Git Commit History & Config | **Mitigate** | Obscure git author details and normalize commit time vectors. |
| User Identity (`settings.json`) | **Fix** | Move sensitive identity fields to encrypted storage. |
| File Permissions Inconsistency | **Fix** | Enforce strict `0600` permissions on all vault files. |
| KDF Parameters Profile Name | **Fix** | Remove the redundant `"profile"` key from the parameters. |
| Cipher Count | **Mitigate** | Introduce dummy files to obscure exact count (padding). |

### Combined Consensus

| Finding | peer review | Agy | Consensus |
|---------|--------|-----|-----------|
| `device-privkey.json` | FIX | FIX | **FIX** |
| `folders.json` + `tag_index.json` | FIX | FIX | **FIX** |
| `settings.json` identity fields | FIX (partial) | FIX | **FIX** |
| `device_activity.json` | FIX | *(not addressed)* | **FIX** |
| File permissions (0644 vs 0600) | MITIGATE | FIX | **FIX / MITIGATE** |
| File timestamps (mtime) | MITIGATE | MITIGATE | **MITIGATE** |
| Git author identity | *(not addressed)* | MITIGATE | **MITIGATE** |
| KDF profile name | FIX (trivial) | FIX | **FIX** |
| Cipher count | *(not addressed)* | MITIGATE | **MITIGATE** |

---

## 3. Implementation Paths (Ranked by Impact / Effort)

Both agents independently converged on the same top priorities. Paths are ranked by security impact divided by development effort.

### Rank 1: Encrypt `folders.json` and `tag_index.json`

**Impact:** Highest. **Effort:** Low. **Agent consensus:** Unanimous.

This is the highest-priority fix because it addresses the git-sync threat model: the core product identity. Any remote host with repo access gets full content classification. The fix eliminates this entirely.

#### the Implementation Plan

The pattern already exists. `index.enc` proves the infrastructure works. This is a straight copy of that pattern.

**In `crates/idtty-core/src/crypto/hkdf_derive.rs`:** Add two derivation functions:

```rust
pub fn derive_folders_key(root_key: &[u8]) -> Result<[u8; 32], IdttyError> {
    derive_subkey(root_key, b"idtty-folders-v1")
}

pub fn derive_tags_key(root_key: &[u8]) -> Result<[u8; 32], IdttyError> {
    derive_subkey(root_key, b"idtty-tags-v1")
}
```

**In `vault/handle.rs`:**

- `save_folders()` and `list_folders()` -- both already require vault state for other operations (note: `delete_folder` checks `VaultState::Unlocked` at line 531). Make both require unlocked state explicitly, derive the folders key from `root_key`, encrypt/decrypt as an AES-256-GCM envelope. Write to `meta/folders.enc`.
- Same for `rebuild_tag_index()` / `list_tags()` -> `meta/tags.enc`.
- Add a migration: in `open()`, if `meta/folders.json` exists and the vault gets unlocked, encrypt and delete the plaintext file.

**UX impact:** Zero. Folder list is only shown in the unlocked view. No screen needs folders before unlock.

#### Agy's Alternative Approach

Merge the folder list and tag index into the JSON schema serialized inside `meta/index.enc` directly. The Tauri Rust backend decrypts `index.enc` into memory upon unlock and exposes the taxonomy to the SolidJS frontend. Delete `meta/folders.json` and `meta/tag_index.json` from disk.

This avoids creating separate encrypted files by consolidating everything into the existing index blob.

#### Design Decision

| Approach | Pros | Cons |
|----------|------|------|
| Separate `.enc` files (peer review) | Independent read/write, no index rebuild on folder change, follows existing pattern | More files, more derivation keys |
| Merge into `index.enc` (Agy) | Single encrypted blob, fewer files, simpler git diffs | Must rebuild entire index on any folder/tag change, larger single payload |

**Recommendation:** Separate `.enc` files. The `index.enc` pattern is proven, and independent read/write avoids unnecessary re-encryption cascades. The folder and tag data change at different rates than cipher metadata.

---

### Rank 2: Move `device-privkey.json` to OS Keyring

**Impact:** Highest (local threat). **Effort:** Medium. **Agent consensus:** Unanimous.

The `keyring` crate is already in the dependency tree per platform targets. The comment at `handle.rs:247` is a TODO in disguise.

#### the Implementation Plan

**In `vault/handle.rs`:** Replace the privkey read at lines 248-271 with:

```rust
fn load_device_privkey(vault_path: &Path, device_id: Uuid) -> Result<x25519_dalek::StaticSecret, IdttyError> {
    // 1. Try keyring
    let service = format!("idtty-{}", derive_vault_fingerprint(vault_path));
    let entry = keyring::Entry::new(&service, &device_id.to_string())
        .map_err(|e| VaultError::Metadata(format!("keyring: {e}")))?;
    if let Ok(secret) = entry.get_password() {
        return parse_privkey_json(&secret);
    }
    // 2. Fall back to file (backward compat)
    let privkey_path = vault_path.join("meta/device-privkey.json");
    if privkey_path.exists() {
        let json = std::fs::read_to_string(&privkey_path)?;
        let secret = parse_privkey_json(&json)?;
        // Migrate: move to keyring, delete file
        let _ = entry.set_password(&json);
        let _ = std::fs::remove_file(&privkey_path);
        return Ok(secret);
    }
    Err(VaultError::NotFound("device private key not found".into()).into())
}
```

**In `vault/creation.rs`:** At vault creation, store to keyring first, fall back to file on keyring error (headless Linux without libsecret).

**Vault fingerprint for keyring service name:** Use `hex::encode(&kdf_params.salt[..8])` -- stable per vault, avoids collision between multiple vaults on the same machine.

**Call sites to update:**
- `rotate_root_key()` (lines 1695-1717)
- `revoke_device_and_rekey()` (lines 1820-1841)
- Both currently read `device-privkey.json` directly. Replace with `load_device_privkey()`.

#### Agy's Implementation Plan

Store the private key material under service name `xyz.actitud.idtty` and account identifier `device_identity`. Fall back to an encrypted local file using a key derived from system-level hardware identifiers only if the system keyring is unavailable.

#### Design Decision

Both approaches agree on `keyring` crate as primary storage. the plan is more specific (salt-based fingerprint, explicit migration path, all call sites enumerated). Agy's fallback (hardware-derived key encryption) is an alternative to plaintext file fallback.

**Recommendation:** the migration approach. Try keyring first, fall back to plaintext file, auto-migrate on first successful read. This is the safest backward-compatible path. The plaintext file gets deleted after successful migration.

---

### Rank 3: Uniform `write_vault_file()` Helper + 0600 Everywhere

**Impact:** Medium (local). **Effort:** Low. **Agent consensus:** Aligned.

`save_folders`, `save_settings`, `rebuild_tag_index` already do the atomic write + chmod pattern. But `add_cipher` at line 966 does not:

```rust
std::fs::write(&file_path, &file.envelope_bytes)?;  // no permissions set
```

Same at `delete_cipher` line 853, `restore_cipher` line 899, and the rotation staged writes.

#### Implementation

**In `vault/mod.rs`** (or a new `vault/io.rs`), add:

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

Replace every `std::fs::write()` in the vault module with this. One grep, approximately 12 call sites.

Agy additionally recommends setting the process `umask` to `0077` at startup as a defense-in-depth measure alongside explicit permissions.

---

### Rank 4: Remove KDF Profile Name from `kdf-params.json`

**Impact:** Low. **Effort:** Trivial. **Agent consensus:** Unanimous.

In `types.rs`, find `KdfParams` and add `#[serde(skip_serializing)]` to the profile field, or remove it entirely and rebuild the KDF parameter set from the numeric values alone. The profile name is not needed for decryption -- it is metadata only.

Done in 5 minutes. Deploy in the next release.

---

### Rank 5: Encrypt Identity Fields in `settings.json`

**Impact:** Medium (git sync). **Effort:** Medium. **Agent consensus:** Aligned.

Split `VaultSettings` into two structs: `AppPrefs` (plaintext: `auto_lock_minutes`, `theme`, `fetch_favicons`, `default_uri_match`) and `UserProfile` (encrypted: `display_name`, `subtitle`, `avatar_ext`).

`AppPrefs` stays at `meta/settings.json`. `UserProfile` goes to `meta/profile.enc`, encrypted with `hkdf_derive::derive_profile_key(root_key)`. On unlock, decrypt and merge into memory. On lock, drop from memory.

The split is needed because `auto_lock_minutes` and `theme` are required pre-unlock for the UI. Display name and subtitle are not.

---

### Rank 6: Normalize Filesystem Timestamps (Mitigate)

**Impact:** Medium. **Effort:** Low. **Agent consensus:** Aligned (mitigate, not fix).

Both agents agree this is a mitigation, not a fix. Timestamps are inherent to filesystems and cannot be fully eliminated.

**Implementation (Agy's plan):** In the Rust backend, run a utility function using `filetime::set_file_mtimes` after vault write or sync operations. Set the modification and access times of all files in the vault to a fixed constant (e.g., UNIX Epoch 0 or a coarse hourly boundary).

**Implementation (the plan):** Touch all cipher files to a common timestamp on lock. Accept as v1 limitation.

**Recommendation:** Normalize on lock is cleaner than normalizing on every write (fewer disk operations). Accept residual risk of timestamps visible during an active unlocked session.

---

### Rank 7: Obscure Git Author Metadata (Mitigate)

**Impact:** Medium (git sync). **Effort:** Low. **Agent consensus:** Agy-only (peer review did not address).

During vault initialization, programmatically configure the local repository:

```bash
git config user.name "IDtty User"
git config user.email "vault@idtty.local"
```

Set `GIT_AUTHOR_DATE` and `GIT_COMMITTER_DATE` environment variables to a fixed epoch when executing commit commands from the Tauri backend.

**Recommendation:** Worth doing as defense-in-depth. Low effort, prevents identity correlation via git log on remote hosts. The static commit message (`"vault update"`) already helps; generic author config completes the picture.

---

## 4. What Not To Do (Low ROI)

Both agents identified items where the return on investment is too low to justify the complexity:

| Item | Reason |
|------|--------|
| **Dummy cipher padding files** | Obfuscates count but adds complexity. An attacker can still observe file count changes over time. Not worth the sync complexity. |
| **Encrypt `devices.json` fully** | Public keys are designed to be public. Encrypting device names alone is low ROI. The file is needed for device enrollment before full unlock in some flows. |
| **Timestamp normalization on every write** | N disk writes per cipher operation. Triggers git status noise. Normalize on lock instead. |

---

## 5. Implementation Roadmap

Ordered by dependency and priority. Each phase is independently deployable.

### Phase 1: Critical Fixes (Estimated: 2-3 days)

| Task | Files | Effort |
|------|-------|--------|
| Encrypt `folders.json` -> `folders.enc` | `crypto/hkdf_derive.rs`, `vault/handle.rs` | Low |
| Encrypt `tag_index.json` -> `tags.enc` | `crypto/hkdf_derive.rs`, `vault/handle.rs` | Low |
| Migration: encrypt `.json` -> `.enc` on unlock | `vault/handle.rs` | Low |
| Uniform `write_vault_file()` helper | `vault/mod.rs` (or new `vault/io.rs`) | Low |

### Phase 2: Keyring Migration (Estimated: 2-3 days)

| Task | Files | Effort |
|------|-------|--------|
| `load_device_privkey()` with keyring primary | `vault/handle.rs` | Medium |
| Update `creation.rs` to store in keyring | `vault/creation.rs` | Medium |
| Update `rotate_root_key()` and `revoke_device_and_rekey()` | `vault/handle.rs` | Medium |
| Backward-compatible file fallback + auto-migration | `vault/handle.rs` | Low |

### Phase 3: Hardening (Estimated: 1-2 days)

| Task | Files | Effort |
|------|-------|--------|
| Remove KDF profile name | `types.rs` | Trivial |
| Encrypt `settings.json` identity fields -> `profile.enc` | `vault/handle.rs`, `crypto/hkdf_derive.rs`, `vault/manifest.rs` | Medium |
| Normalize timestamps on lock | `vault/handle.rs` (new helper) | Low |
| Generic git author config at vault init | `sync/engine.rs` | Low |
| Enforce 0600 on all vault files | `vault/handle.rs`, `vault/creation.rs` | Low |

### Phase 4: Defense-in-Depth (Future)

| Task | Notes |
|------|-------|
| Encrypt `device_activity.json` (merge into `index.enc`) | Requires index schema change |
| Encrypt device names in `devices.json` | Low ROI, complex enrollment flow impact |
| Cover commit automation | Already implemented, needs scheduling policy |

---

## 6. Open Questions

These require product/architect decisions before implementation:

1. **Keyring fallback policy:** If OS keyring is unavailable (headless Linux, CI, container), should we refuse to operate or fall back to encrypted file? peer review recommends plaintext file fallback with auto-migration. Agy recommends hardware-derived key encryption for the fallback.

2. **Folders/tags encryption approach:** Separate `.enc` files (independent read/write, more files) or merged into `index.enc` (single blob, simpler but larger re-encryption surface)?

3. **Timestamp normalization trigger:** On lock (cleaner, fewer writes) or on every write (more thorough, more disk I/O and git noise)?

4. **Git author identity:** Should the vault enforce generic author config at init, or respect the user's global git config? Enforcing prevents identity leaks but may conflict with user expectations for commit attribution.

5. **Backward compatibility window:** How long should the `.json` -> `.enc` migration path be maintained? Until next major version, or permanently?

---

## 7. Summary

**Both independent security reviewers reached the same conclusions:**

- Two findings are critical: plaintext metadata committed to git (folders, tags) and device private keys on disk.
- Both must be fixed (not mitigated): encrypt the metadata, move keys to OS keyring.
- The implementation paths are clear and well-understood: reuse the existing `index.enc` encryption pattern, use the already-available `keyring` crate.
- Phase 1 + Phase 2 close approximately 80% of the attack surface.
- Remaining items are mitigations and hardening, deployable incrementally.

The cipher encryption itself (AES-256-GCM, padded buckets, random UUID filenames, static commit messages) is sound. The vulnerability is exclusively in metadata handling, not in the cryptographic core.
