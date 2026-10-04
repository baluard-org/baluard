//! Vault handle: locked/unlocked session state.
//!
//! The VaultHandle is the primary interface for vault operations.
//! Locked: can list cipher metadata (filenames, envelope headers).
//! Unlocked: can decrypt ciphers, add/update/delete with proper key material.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::crypto::hkdf_derive;
use crate::crypto::hpke_wrap;
use crate::crypto::kdf;
use crate::crypto::signature;
use crate::device_manager::DeviceManager;
use crate::devices::DeviceRegistry;
use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::{ItemKey, RootKey};
use crate::types::{Cipher, CipherInput, KdfParams, Tier};
use crate::vault::cipher;
use crate::vault::index;

use base64::Engine as _;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Vault session state.
/// Collect a folder ID and all its descendant folder IDs.
fn collect_descendant_ids(
    folder_id: Uuid,
    folders: &[crate::vault::manifest::Folder],
) -> HashSet<Uuid> {
    let mut result = HashSet::new();
    result.insert(folder_id);
    let mut queue = vec![folder_id];
    while let Some(current) = queue.pop() {
        for f in folders {
            if f.parent_id == Some(current) {
                result.insert(f.id);
                queue.push(f.id);
            }
        }
    }
    result
}

pub struct VaultHandle {
    /// Path to the vault directory on disk.
    pub path: PathBuf,
    /// Vault ID (set at creation, loaded from metadata).
    pub vault_id: Uuid,
    /// KDF parameters (loaded from meta/kdf-params.json).
    pub kdf_params: KdfParams,
    /// Device registry (loaded from meta/devices.json).
    /// Kept for backward compat; DeviceManager is the authoritative owner.
    pub registry: DeviceRegistry,
    /// Current device ID.
    pub device_id: Uuid,
    /// Device lifecycle coordinator (MISS-2).
    /// Loaded on open, manages epoch state, enrollment, and rotation.
    pub device_manager: DeviceManager,
    /// The (kind, params digest) whose quorum THIS handle already
    /// satisfied via a precheck, consumed by the op that follows.
    /// Bridges the runtime's strike-ordering precheck to member_remove's
    /// internal re-validation so the gate runs exactly once per chain.
    /// Mutex (not RefCell) so VaultState stays Sync across the spawned
    /// sync tasks.
    pub quorum_satisfied: std::sync::Mutex<Option<(String, String)>>,
    /// Session state.
    pub state: VaultState,
}

/// Vault lock state with key material.
// large_enum_variant: UnlockedState legitimately carries ~200 B of key
// material (RootKey, SGK, session/sync keys); boxing would add indirection
// on every access for no real gain.
#[allow(clippy::large_enum_variant)]
pub enum VaultState {
    /// Vault is locked. No key material in memory.
    Locked,
    /// Vault is unlocked. Root Key and session keys available.
    Unlocked(UnlockedState),
}

/// Key material held while vault is unlocked.
///
/// S3-7b: `root_key` and `space_group_key` are `None` on member devices
/// of a flipped (team-shape) vault. Members hold only the SMK (from
/// their identity-keyed space.wrap) and the meta IKM expanded from it;
/// every Root-Key/SGK-consuming operation refuses via [`Self::root`]
/// / [`Self::sgk`] instead of silently using absent material.
pub struct UnlockedState {
    /// Root Key (512-bit, per-epoch). `None` for team members.
    pub root_key: Option<RootKey>,
    /// Space Group Key (256-bit, per-space). DESIGN-3: intermediate layer.
    /// Derived from RootKey for single-user; random for multi-user/org.
    /// `None` for team members.
    pub space_group_key: Option<crate::keys::hierarchy::SpaceGroupKey>,
    /// S3-7b: the Space Meta Key, when the vault carries one (flipped
    /// admin: from the sealed store; member: from the identity wrap).
    pub smk: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// Session Key (for local cache encryption).
    pub session_key: [u8; 32],
    /// Sync-Only Key (for locked background sync).
    pub sync_key: [u8; 32],
    /// Cached Item Keys: cipher_id → ItemKey.
    /// Loaded on-demand, cached for performance.
    pub item_keys: HashMap<Uuid, ItemKey>,
    /// Device-privkey seal subkey (C1): HKDF(KEK, "baluard-devkey-v1").
    /// Lets post-unlock consumers (sync signing, password change) open the
    /// sealed `meta/device-privkey.json` without keeping the KEK resident.
    pub devkey_seal: [u8; 32],
    /// Current key epoch (read from RK canary or envelope).
    pub current_epoch: u64,
    /// P1a: the per-human identity (cached unsealed while unlocked).
    /// `None` until loaded (keystore/fallback) or when unavailable.
    pub identity: Option<crate::vault::identity::IdentityKeys>,
    /// P1a: the identity sealing wrap key (keystore-held random key or the
    /// warned passphrase-derived fallback). Cached at unlock so
    /// `rotate_identity` can re-seal. Zeroized on lock/drop.
    pub identity_wrap_key: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl UnlockedState {
    /// Root Key access. Refuses on team-member devices, which hold none.
    pub fn root(&self) -> Result<&RootKey, BaluardError> {
        self.root_key.as_ref().ok_or_else(|| {
            VaultError::InvalidOperation(
                "this operation requires a managing device (team members hold no Root Key)".into(),
            )
            .into()
        })
    }

    /// Space Group Key access. Refuses on team-member devices.
    pub fn sgk(&self) -> Result<&crate::keys::hierarchy::SpaceGroupKey, BaluardError> {
        self.space_group_key.as_ref().ok_or_else(|| {
            VaultError::InvalidOperation(
                "this operation requires a managing device (team members hold no group key)".into(),
            )
            .into()
        })
    }

    /// S3-7b: the IKM every member-visible meta derivation consumes:
    /// HKDF(SMK) post-flip, the live Root Key bytes pre-flip. Computed
    /// per call so a rotation that swaps the Root Key (pre-flip) never
    /// leaves a stale derivation input behind.
    pub fn meta_ikm(&self) -> zeroize::Zeroizing<[u8; 64]> {
        match (&self.smk, &self.root_key) {
            (Some(smk), _) => {
                zeroize::Zeroizing::new(crate::crypto::hkdf_derive::meta_root_from_smk(smk))
            }
            (None, Some(rk)) => zeroize::Zeroizing::new(*rk.as_bytes()),
            // Unreachable (locked handles never expose UnlockedState);
            // a zeroed IKM fails every read closed instead of panicking.
            (None, None) => zeroize::Zeroizing::new([0u8; 64]),
        }
    }

    /// Whether this device holds the Root Key (admin/founding device).
    pub fn holds_root(&self) -> bool {
        self.root_key.is_some()
    }
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        if let Some(mut k) = self.root_key.take() {
            k.zeroize();
        }
        if let Some(mut k) = self.space_group_key.take() {
            k.zeroize();
        }
        self.session_key.zeroize();
        self.sync_key.zeroize();
    }
}

/// Key domain of a cipher file, decided by its on-disk location (S3-7c).
/// Collection and trash-collection domains resolve to a collection id via
/// the salted dir map; flat domains are SGK-keyed admin surface.
#[derive(Debug, Clone, PartialEq)]
enum CipherDomain {
    Flat,
    Collection(String),
    TrashFlat,
    TrashCollection(String),
}

/// Report for the S3-7b team-shape flip.
#[derive(Debug, Clone)]
pub struct SpaceFlipReport {
    /// True when the vault was already in team shape (idempotent call).
    pub already_flipped: bool,
    /// Tracked meta files re-sealed under the SMK derivation.
    pub files_reencrypted: usize,
    /// Member-device keywraps removed (the Root Key exit).
    pub keywraps_removed: usize,
}

/// Offboarding report for a batch member removal (S1a-6).
#[derive(Debug, Clone)]
pub struct MemberRemovalReport {
    pub removed_members: Vec<uuid::Uuid>,
    pub removed_devices: Vec<uuid::Uuid>,
    /// Root Key epoch after the offboarding rotation.
    pub new_epoch: u64,
    /// P8c: forge usernames that held transport seats on the removed
    /// rows. The daemon route strikes these BEFORE calling member_remove;
    /// anything still listed here that the route did not strike (a
    /// member added between the pre-flight and the rotation) is reported
    /// as `unstruck_seats` for the notices surface.
    pub transport_usernames: Vec<String>,
}

impl VaultHandle {
    /// Open a vault from disk (locked state).
    /// Reads metadata files but does NOT decrypt anything.
    pub fn open(path: &Path) -> Result<Self, BaluardError> {
        let kdf_path = path.join("meta/kdf-params.json");
        if !kdf_path.exists() {
            return Err(VaultError::NotInitialized.into());
        }

        let kdf_json = std::fs::read_to_string(&kdf_path)
            .map_err(|e| VaultError::Metadata(format!("reading kdf params: {e}")))?;
        let kdf_params: KdfParams = serde_json::from_str(&kdf_json)
            .map_err(|e| VaultError::Corrupt(format!("kdf params: {e}")))?;

        let registry_path = path.join("meta/devices.json");
        let registry = if registry_path.exists() {
            let reg_json = std::fs::read_to_string(&registry_path)
                .map_err(|e| VaultError::Metadata(format!("reading devices: {e}")))?;
            serde_json::from_str(&reg_json)
                .map_err(|e| VaultError::Corrupt(format!("devices: {e}")))?
        } else {
            DeviceRegistry::new()
        };

        // Find our device ID from the keywrap files
        let device_id = Self::find_device_id(path)?;

        // Derive vault_id deterministically from KDF salt (stable, unique per vault).
        // No meta file needed: same salt always produces the same UUID.
        let vault_id = Self::derive_vault_id(&kdf_params);

        // MISS-2: Load DeviceManager from vault directory
        let mut device_manager = if DeviceManager::vault_files_exist(path) {
            DeviceManager::load_from_vault(path)?
        } else {
            let mut dm = DeviceManager::new();
            dm.set_vault_path(path);
            dm.epoch
                .activate()
                .map_err(|e| BaluardError::from(crate::error::KeyError::InvalidEpochState(e)))?;
            dm
        };
        // Ensure epoch is ACTIVE for existing vaults (may be CREATED after load)
        if device_manager.epoch_state() == crate::keys::epoch::EpochState::Created {
            device_manager
                .epoch
                .activate()
                .map_err(|e| BaluardError::from(crate::error::KeyError::InvalidEpochState(e)))?;
        }

        // B-1 fix: reconcile an interrupted root-key rotation.
        //
        // `rotate_root_key` writes staged .tmp files then renames them in
        // order (ciphers -> canary -> keywrap, keywrap being the point of no
        // return). The RAII RotationGuard sweeps .tmp on drop if the function
        // unwinds, but a hard process kill leaves the marker + leftover .tmp
        // behind. We cannot finish a half-applied rotation here (no new
        // RootKey), so the safe reconciliation is: sweep any staged .tmp
        // files so the next rotation starts clean, and surface the marker
        // loudly so the user knows the vault may be in a mixed-epoch state.
        //
        // The marker only exists for the brief rotation window; if it
        // survives to here the rotation did not commit cleanly.
        let pending_marker = path.join("meta/.rotation-pending");
        if pending_marker.exists() {
            eprintln!(
                "WARNING: vault at {} has a leftover .rotation-pending marker; \
                 a root-key rotation did not complete cleanly. Sweeping staged files.",
                path.display()
            );
            for dir_name in &["meta", "meta/keywrap"] {
                remove_tmp_files(&path.join(dir_name));
            }
            // S3-7c review F9: collection-scoped ciphers stage into
            // ciphers/<dir>/ and trash/<dir>/ — the sweep must recurse.
            remove_tmp_files_recursive(&path.join("ciphers"));
            remove_tmp_files_recursive(&path.join("trash"));
            remove_tmp_files_recursive(&path.join("entries"));
            // Leave the marker in place: a sweep is not a successful commit,
            // and the epoch state below may still need operator attention.
        }

        // H3 fix: Rollback detection on vault open.
        // Load integrity manifest and compare against actual file state.
        // Warn on rollback (don't block: manifest is in writable tree, not externally anchored).
        if let Ok(manifest) = crate::integrity::IntegrityManifest::load(path) {
            let mut actual_seqs = HashMap::new();
            let ciphers_dir = path.join("ciphers");
            if ciphers_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&ciphers_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str.ends_with(".enc") {
                            let object_id = name_str.trim_end_matches(".enc").to_string();
                            if let Ok(data) = std::fs::read(entry.path()) {
                                if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                                    actual_seqs.insert(object_id, envelope.header.update_seq);
                                }
                            }
                        }
                    }
                }
            }
            let rollbacks = manifest.detect_rollback(&actual_seqs);
            if !rollbacks.is_empty() {
                eprintln!(
                    "WARNING: rollback detected! {} object(s) have lower sequence numbers than expected:",
                    rollbacks.len()
                );
                for rb in &rollbacks {
                    eprintln!(
                        "  - {} expected_seq={} actual_seq={}",
                        rb.object_id, rb.expected_seq, rb.actual_seq
                    );
                }
            }
        }

        Ok(VaultHandle {
            path: path.to_path_buf(),
            vault_id,
            kdf_params,
            registry,
            device_id,
            device_manager,
            state: VaultState::Locked,
            quorum_satisfied: std::sync::Mutex::new(None),
        })
    }

    /// Unlock the vault with the master password.
    ///
    /// Flow:
    /// 1. Derive KEK from password + KDF params
    /// 2. Read our device's keywrap file
    /// 3. HPKE-decapsulate Root Key using device X25519 private key
    ///
    /// Note: In CLI mode, the device X25519 private key is stored in the
    /// keywrap JSON for simplicity. In production, this lives in OS keystore.
    fn assert_can_manage_members(&self) -> Result<(), BaluardError> {
        // Legacy vault (no member directory): the founder manages.
        if !self.path.join(crate::vault::members::MEMBERS_DIR).exists() {
            return Ok(());
        }
        // Strict vault: the device's OWN binding decides. Unbound =
        // pending joiner = refused (fail closed; the review round on
        // S1a-5 caught the None->legacy fallback admitting unbound
        // devices on strict vaults).
        match crate::vault::members::member_role_for_device(&self.path, self.device_id) {
            Some(crate::vault::members::MemberRole::Owner)
            | Some(crate::vault::members::MemberRole::Admin) => Ok(()),
            Some(_) => Err(VaultError::InvalidOperation(
                "only the owner or an admin can manage members".into(),
            )
            .into()),
            None => {
                Err(VaultError::InvalidOperation("this device is not a vault member".into()).into())
            }
        }
    }

    /// Space policy (§6.5 invite_authority): after the manage floor, an
    /// Owners-only Space additionally requires the actor's member row to
    /// BE the Owner. Legacy founders (no member directory) pass — they
    /// ARE the owner. Reset invites bypass this by design: they are
    /// offboarding machinery, not membership growth.
    fn assert_invite_authority(&self) -> Result<(), BaluardError> {
        if self.get_settings()?.space_invite_authority
            != crate::vault::manifest::InviteAuthority::Owners
        {
            return Ok(());
        }
        match crate::vault::members::member_role_for_device(&self.path, self.device_id) {
            Some(crate::vault::members::MemberRole::Owner) | None => Ok(()),
            _ => Err(BaluardError::from(VaultError::InvalidOperation(
                "this space only allows the owner to send invites".into(),
            ))),
        }
    }

    /// Sensitive-op quorum (§6.5 `quorum_admin_ops`, decided 2026-09-27).
    /// Threshold 1 (the default): one admin acts alone, pass. Above 1,
    /// the op must collect DISTINCT admin approvals — see
    /// `vault::approvals`. Only Owner/Admin devices participate; a
    /// legacy vault (no member directory) has a single admin by
    /// construction, so the gate passes there. Enforcement is
    /// local-only like every §6.5 knob (the keyless sync walker cannot
    /// read the encrypted threshold); the pending record itself is
    /// plaintext under `meta/approvals/` and rides the meta/** Admin
    /// sync row, so every admin device sees the ask on its next pull.
    fn quorum_gate(&self, kind: &str, params: &serde_json::Value) -> Result<(), BaluardError> {
        let required = self.get_settings()?.quorum_admin_ops.unwrap_or(1).max(1);
        // The role gate runs at EVERY threshold: the required<=1 early
        // return used to skip it, which made root rotation (via the new
        // space.rotate_root surface) available to any unlocked session at
        // the default knob — a latent hole the surface exposed
        // (2026-10-01 fix-7 review). Legacy founder: no member directory
        // means the founding device is the admin by construction.
        if !self.path.join(crate::vault::members::MEMBERS_DIR).exists() {
            if required <= 1 {
                crate::vault::approvals::consume_matching(&self.path, kind, params);
            }
            return Ok(());
        }
        let is_admin = matches!(
            crate::vault::members::member_role_for_device(&self.path, self.device_id),
            Some(crate::vault::members::MemberRole::Owner)
                | Some(crate::vault::members::MemberRole::Admin)
        );
        if !is_admin {
            return Err(
                VaultError::InvalidOperation("only admins can approve this change".into()).into(),
            );
        }
        if required <= 1 {
            // The knob dropped below the ask: nothing stays pending.
            crate::vault::approvals::consume_matching(&self.path, kind, params);
            return Ok(());
        }
        let Some(member_id) =
            crate::vault::members::member_id_for_device(&self.path, self.device_id)
        else {
            return Err(
                VaultError::InvalidOperation("only admins can approve this change".into()).into(),
            );
        };
        // The approval is signed with the member identity key, so a
        // hand-written record cannot forge it (post-commit review
        // round): the gate counts only entries whose signature
        // verifies against the approver's member row.
        let digest = crate::vault::approvals::op_digest(kind, params);
        let now = crate::vault::collections::now_secs_pub();
        // Confirming an existing ask signs ITS ask timestamp; raising a
        // fresh one signs now. A stale ask is consumed first, so the
        // call re-raises as a fresh initiator. The message binds the
        // vault and the timestamp, so a signature harvested from git
        // history cannot be replayed onto a fresh ask or into another
        // Space.
        let existing = crate::vault::approvals::list_pending(&self.path)
            .into_iter()
            .find(|p| p.kind == kind && p.params_digest == digest);
        let (ask_time, stale) = match existing.as_ref() {
            Some(op)
                if now.saturating_sub(op.initiated_at)
                    >= crate::vault::approvals::APPROVAL_STALE_SECS =>
            {
                (now, true)
            }
            Some(op) => (op.initiated_at, false),
            None => (now, false),
        };
        // The ask's nonce binds every signature to one concrete record:
        // confirming signs the record's own nonce; a fresh (or stale-
        // consumed) ask mints a new one, so a consumed record's harvested
        // signatures never verify against the re-raise.
        let ask_nonce = match existing.as_ref().filter(|_| !stale) {
            Some(op) => op.nonce.clone().unwrap_or_default(),
            None => {
                let mut b = [0u8; 16];
                rand::Rng::fill(&mut rand::rngs::OsRng, &mut b);
                hex::encode(b)
            }
        };
        if stale {
            crate::vault::approvals::consume_matching(&self.path, kind, params);
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation(
                "this device cannot sign approvals; unlock with your identity".into(),
            )
        })?;
        let msg = crate::vault::approvals::approval_message(
            kind,
            &digest,
            self.vault_id,
            ask_time,
            &ask_nonce,
        );
        let sig = hex::encode(
            crate::crypto::signature::sign(identity.signing_key(), &msg)
                .map_err(BaluardError::Crypto)?
                .to_bytes(),
        );
        let entry = crate::vault::approvals::ApprovalEntry {
            member: member_id,
            sig,
        };
        let verify_entry = crate::vault::approvals::EntryVerifier {
            nonce: ask_nonce.clone(),
            verify: Box::new(
                |candidate: &crate::vault::approvals::ApprovalEntry| -> bool {
                    let Some(row) =
                        crate::vault::members::member_file_by_id(&self.path, candidate.member)
                    else {
                        return false;
                    };
                    // Only live Owner/Admin rows count toward an admin quorum:
                    // a Viewer's yes or an evicted admin's old key never does.
                    if !matches!(
                        row.role,
                        crate::vault::members::MemberRole::Owner
                            | crate::vault::members::MemberRole::Admin
                    ) || row.reset.is_some()
                        || row.removed.is_some()
                    {
                        return false;
                    }
                    let Some(pub_hex) = row.identity_signing_pubkey.as_deref() else {
                        return false;
                    };
                    let (Ok(pk_bytes), Ok(sig_bytes)) =
                        (hex::decode(pub_hex), hex::decode(&candidate.sig))
                    else {
                        return false;
                    };
                    let (Ok(pk_arr), Ok(sig_arr)) = (
                        <[u8; 32]>::try_from(pk_bytes.as_slice()),
                        <[u8; 64]>::try_from(sig_bytes.as_slice()),
                    ) else {
                        return false;
                    };
                    let Ok(pk) = crate::crypto::signature::verifying_key_from_bytes(&pk_arr) else {
                        return false;
                    };
                    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                    crate::crypto::signature::verify(&pk, &msg, &sig).is_ok()
                },
            ),
        };
        if !(verify_entry.verify)(&entry) {
            return Err(VaultError::InvalidOperation(
                "this device's identity does not match its member record; unlock again before approving"
                    .into(),
            )
            .into());
        }
        match crate::vault::approvals::present(
            &self.path,
            kind,
            params,
            entry,
            required,
            now,
            &verify_entry,
        ) {
            crate::vault::approvals::ApprovalOutcome::Approved => Ok(()),
            crate::vault::approvals::ApprovalOutcome::Pending => {
                Err(VaultError::InvalidOperation(format!(
                    "this change needs {required} admin approvals before it runs — ask another admin to confirm the same change"
                ))
                .into())
            }
            crate::vault::approvals::ApprovalOutcome::AlreadyApproved => {
                Err(VaultError::InvalidOperation(
                    "you already approved this change — a different admin must confirm it".into(),
                )
                .into())
            }
            crate::vault::approvals::ApprovalOutcome::Consumed => {
                Err(VaultError::InvalidOperation(
                    "this exact ask was already executed; raise a fresh one".into(),
                )
                .into())
            }
        }
    }

    /// Public gate for runtime callers (e.g. `space.migrate`).
    pub fn assert_op_quorum(
        &self,
        kind: &str,
        params: &serde_json::Value,
    ) -> Result<(), BaluardError> {
        self.quorum_gate(kind, params)
    }

    /// Pending sensitive-op asks, for the admin surface.
    pub fn pending_op_approvals(&self) -> Vec<crate::vault::approvals::PendingOp> {
        crate::vault::approvals::list_pending(&self.path)
    }

    /// Create or rotate the Space Recovery Kit (admin-only). Returns
    /// the 24-word phrase, which the caller must show exactly once and
    /// the owner stores offline (the physical safe).
    pub fn space_recovery_kit_enable(&self) -> Result<String, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Self::assert_kit_admin(&self.path, self.device_id)?;
        crate::vault::recovery_kit::enable_kit(&self.path, self.unlocked().root()?, self.vault_id)
    }

    /// Remove the kit (admin-only). Returns whether a kit existed.
    pub fn space_recovery_kit_disable(&self) -> Result<bool, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Self::assert_kit_admin(&self.path, self.device_id)?;
        crate::vault::recovery_kit::disable_kit(&self.path)
    }

    /// Whether a kit is set up (admin-only; the file's existence is
    /// already locally readable, so this gates nothing secret).
    pub fn space_recovery_kit_status(&self) -> Result<bool, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Self::assert_kit_admin(&self.path, self.device_id)?;
        crate::vault::recovery_kit::kit_exists(&self.path)
    }

    /// Owner/Admin gate shared by the kit surfaces, with the legacy
    /// no-member-directory founder equivalence (same shape as the
    /// policies gate so every Space-settings surface reads alike).
    fn assert_kit_admin(vault_path: &Path, device_id: Uuid) -> Result<(), BaluardError> {
        let members_dir = vault_path.join(crate::vault::members::MEMBERS_DIR);
        let allowed = if !members_dir.exists() {
            true // legacy personal vault: the founder manages
        } else {
            matches!(
                crate::vault::members::member_role_for_device(vault_path, device_id),
                Some(crate::vault::members::MemberRole::Owner)
                    | Some(crate::vault::members::MemberRole::Admin)
            )
        };
        if !allowed {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "Only the owner or an admin can manage the recovery kit.".into(),
            )));
        }
        Ok(())
    }

    /// Recover a lost admin device with the kit phrase: unwrap the Root
    /// Key, verify both canaries, enroll a fresh device, and bind it to
    /// the live Owner member row. Never resets the device registry (the
    /// multi-device roster is what peers verify signatures against).
    /// Path-only BY DESIGN: a fresh clone of a multi-device Space cannot
    /// open() a handle (no local keystore to resolve the device keywrap
    /// against), so the ceremony must never require one. The recovered
    /// device adopts the owner identity through the existing cross-device
    /// heal at first unlock.
    pub fn recover_device_with_kit(
        vault_path: &Path,
        phrase: &str,
        password: &str,
        device_name: &str,
    ) -> Result<Uuid, BaluardError> {
        if device_name.contains(['\n', '\r']) {
            return Err(VaultError::InvalidOperation(
                "device name must not contain newlines".into(),
            )
            .into());
        }
        // Brick guard first (needs no secret): recovery mints THIS
        // device's keystore; running it where keys already exist would
        // clobber them.
        if vault_path.join("meta/device-privkey.json").exists() {
            return Err(VaultError::InvalidOperation(
                "This device already has its own keys; kit recovery is for fresh installs.".into(),
            )
            .into());
        }
        if !crate::vault::recovery_kit::kit_exists(vault_path)? {
            return Err(VaultError::InvalidOperation(
                "No recovery kit is set up for this vault.".into(),
            )
            .into());
        }
        let vault_id = Self::vault_id_for_path(vault_path)?;
        let root = crate::vault::recovery_kit::recover_root_from_kit(vault_path, vault_id, phrase)
            .map_err(|_| {
                BaluardError::from(VaultError::InvalidOperation(
                    "That recovery phrase does not open this vault's recovery kit.".into(),
                ))
            })?;
        // Root canary: the recovered key must be THIS vault's key. The
        // kit targets vaults that carry the canary (creation writes it);
        // a vault without one is out of the kit's scope.
        let canary_data = std::fs::read(vault_path.join("meta/rk-canary.enc")).map_err(|_| {
            BaluardError::from(VaultError::InvalidOperation(
                "This vault has no root canary; the recovery kit cannot verify it.".into(),
            ))
        })?;
        crate::vault::canary::verify_rk_canary(&root, &canary_data).map_err(|_| {
            BaluardError::from(VaultError::InvalidOperation(
                "The recovered key does not match this vault.".into(),
            ))
        })?;

        let kdf_raw = std::fs::read_to_string(vault_path.join("meta/kdf-params.json"))
            .map_err(|e| VaultError::Metadata(format!("kdf params: {e}")))?;
        let kdf_params: crate::types::KdfParams = serde_json::from_str(&kdf_raw)
            .map_err(|e| VaultError::Metadata(format!("kdf params: {e}")))?;
        let kek = Zeroizing::new(crate::crypto::kdf::derive_kek(password, &kdf_params)?);
        // KEK canary: a mistyped master password would mint a keystore
        // this device could never unlock with the real password. Verify
        // BEFORE anything is written.
        let kek_canary_data = std::fs::read(vault_path.join("meta/kek-canary.enc")).map_err(
            |_| {
                BaluardError::from(VaultError::InvalidOperation(
                    "This vault has no master-password canary; the recovery kit cannot verify the password.".into(),
                ))
            },
        )?;
        let session_key = crate::crypto::hkdf_derive::derive_session_key(&kek)?;
        crate::vault::canary::verify_kek_canary(&session_key, &kek_canary_data).map_err(|_| {
            BaluardError::from(VaultError::InvalidOperation(
                "That master password does not open this vault.".into(),
            ))
        })?;

        // Resolve the Owner row BEFORE any disk mutation: a failure here
        // must not strand a half-written keystore that trips the brick
        // guard on retry.
        let owner = crate::vault::members::list_members(vault_path)?
            .into_iter()
            .find(|m| {
                m.role == crate::vault::members::MemberRole::Owner
                    && m.removed.is_none()
                    && m.reset.is_none()
            })
            .ok_or_else(|| {
                BaluardError::from(VaultError::InvalidOperation(
                    "No live owner member row was found to bind the recovered device to.".into(),
                ))
            })?;

        // Fresh device identity (mirrors create_introduction). The KEK
        // derives from the VAULT-level KDF params with no fresh salt —
        // this device unlocks through the admin path like any other
        // admin device.
        let (x25519_secret, x25519_public) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let (ed25519_signing, ed25519_verifying) =
            crate::crypto::signature::generate_ed25519_keypair();
        let device_id = Uuid::new_v4();
        let devkey_seal = Zeroizing::new(crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek)?);

        let mut inner = serde_json::json!({
            "device_id": device_id.to_string(),
            "x25519_private": hex::encode(x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(ed25519_signing.to_bytes()),
        })
        .to_string();
        crate::vault::device_privkey::seal_file(
            &vault_path.join("meta/device-privkey.json"),
            &inner,
            &devkey_seal,
            Some(device_id),
        )?;
        inner.zeroize();
        crate::vault::device_privkey::write_device_id(vault_path, device_id)?;

        // Keywrap carrying the recovered Root Key (the same shape the
        // rotation staging and approve_join write; the admin unlock tail
        // unwraps it under root-key-keywrap).
        let (eph, ct, tag) =
            hpke_wrap::wrap_key(root.as_bytes(), &x25519_public, "root-key-keywrap")?;
        let keywrap = serde_json::json!({
            "device_id": device_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        super::write_vault_file(
            &vault_path.join(format!("meta/keywrap/{device_id}.json")),
            serde_json::to_string_pretty(&keywrap).unwrap().as_bytes(),
        )?;

        // Registry entry so the device's commits verify against the roster.
        let mut dm = crate::device_manager::DeviceManager::load_from_vault(vault_path)?;
        dm.registry.enroll_with_id(
            device_id,
            device_name.to_string(),
            *x25519_public.as_bytes(),
            crate::crypto::signature::verifying_key_bytes(&ed25519_verifying),
            None,
        )?;
        dm.save_to_vault()?;

        crate::vault::members::write_device_binding(
            vault_path,
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: owner.id,
            },
        )?;
        Ok(device_id)
    }

    /// Publish (or clear) the advisory org policies (S4-6). Owner/Admin
    /// gated with the legacy-founder equivalence; the file rides the
    /// meta/** Admin row, values validate fail-closed in the module.
    pub fn policies_set(
        &self,
        policies: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let members_dir = self.path.join(crate::vault::members::MEMBERS_DIR);
        let allowed = if !members_dir.exists() {
            true // legacy personal vault: the founder manages
        } else {
            matches!(
                crate::vault::members::member_role_for_device(&self.path, self.device_id),
                Some(crate::vault::members::MemberRole::Owner)
                    | Some(crate::vault::members::MemberRole::Admin)
            )
        };
        if !allowed {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "Only the owner or an admin can publish space policies.".into(),
            )));
        }
        crate::vault::policies::write_policies(&self.path, policies)
    }

    /// Read the published advisory policies. Any unlocked device may
    /// read (member surfaces render the hints); no keys involved.
    pub fn policies_list(&self) -> Result<Option<serde_json::Value>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::policies::read_policies(&self.path)
    }

    /// Access review (S4-4, plan-power-pack §3): one admin-facing JSON
    /// report answering "who can see what". Computed on demand from
    /// disk state; nothing persists. The S4-8 exposure summary rides
    /// here: a removed or reset member's grant ROWS survive the
    /// tombstone by design (only the expiry sweep prunes), so each
    /// surviving row names a collection the departing member could
    /// read while active — the credentials an admin should rotate
    /// (read bytes cannot be un-read; changing the passwords is the
    /// mitigation). Raw key material never enters the report.
    /// S4-5: the derived activity timeline — the space-wide feed
    /// synthesized from verified signed git history (newest-first).
    /// Reads leave no trace; nothing is persisted. Admin-gated like the
    /// access review: this is the audit surface.
    #[cfg(feature = "git-sync")]
    pub fn activity_timeline(&self, limit: usize) -> Result<serde_json::Value, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let engine = crate::sync::engine::SyncEngine::new(&self.path, "timeline", None);
        let repo = engine.open_repo()?;
        let entries = crate::sync::engine::SyncEngine::derive_timeline(&repo, limit)?;
        Ok(serde_json::json!({ "timeline": entries }))
    }

    pub fn access_review(&self) -> Result<serde_json::Value, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let sgk = self.unlocked().sgk()?;
        let now = crate::vault::collections::now_secs_pub();

        // Members: roles, trust, tombstones — the review's spine.
        let members = crate::vault::members::list_members(&self.path)?;
        let mut member_rows = Vec::new();
        for m in &members {
            member_rows.push(serde_json::json!({
                "id": m.id,
                "display_name": m.display_name,
                "email": m.email,
                "role": m.role,
                "trust": m.trust,
                "removed": m.removed,
                "reset": m.reset.as_ref().map(|r| serde_json::json!({
                    "successor": r.successor, "at": r.at,
                })),
            }));
        }

        // Collections: every grant with target + access + expiry,
        // decrypted names (admin device holds the SGK).
        let mut collection_rows = Vec::new();
        for (file, name) in crate::vault::collections::list_collections(&self.path, sgk)? {
            collection_rows.push(serde_json::json!({
                "id": file.id,
                "name": name,
                "grants": file.grants.iter().map(|g| serde_json::json!({
                    "kind": match g.target {
                        crate::vault::collections::GrantTarget::Member { .. } => "member",
                        crate::vault::collections::GrantTarget::Group { .. } => "group",
                    },
                    "id": match g.target {
                        crate::vault::collections::GrantTarget::Member { id } => id,
                        crate::vault::collections::GrantTarget::Group { id } => id,
                    },
                    "access": g.access,
                    "expires_at": g.expires_at,
                })).collect::<Vec<_>>(),
            }));
        }

        // Exposure (S4-8): tombstoned members × surviving grant rows.
        let exposed_ids: Vec<Uuid> = members
            .iter()
            .filter(|m| m.removed.is_some() || m.reset.is_some())
            .map(|m| m.id)
            .collect();
        let mut exposure = Vec::new();
        for tid in &exposed_ids {
            let mut hit_collections = Vec::new();
            for row in &collection_rows {
                for g in row["grants"].as_array().expect("grants array") {
                    if g["kind"] == "member"
                        && g["id"]
                            .as_str()
                            .map(|s| s == tid.to_string())
                            .unwrap_or(false)
                    {
                        hit_collections.push(serde_json::json!({
                            "id": row["id"],
                            "name": row["name"],
                            "access": g["access"],
                            "expires_at": g["expires_at"],
                        }));
                    }
                }
            }
            let m = members.iter().find(|m| m.id == *tid);
            exposure.push(serde_json::json!({
                "member_id": tid,
                "display_name": m.map(|m| m.display_name.clone()).unwrap_or_default(),
                "kind": if m.and_then(|m| m.removed).is_some() { "removed" } else { "reset" },
                "collections": hit_collections,
            }));
        }

        // Pre-flip boundary: members held the Root Key, so every flat
        // cipher was readable. Post-flip, flats are admin-surface only.
        let flipped = crate::vault::space_meta::shape_flipped(&self.path);

        // Groups (S4-2): membership lists are plaintext; the names ride
        // the GK, which the admin reaches through the SGK.
        let groups: Vec<_> = crate::vault::groups::list_groups(&self.path, sgk)?
            .into_iter()
            .map(|(f, name)| {
                serde_json::json!({
                    "id": f.id,
                    "name": name,
                    "member_count": f.members.len(),
                })
            })
            .collect();

        // Pending asks: quorum approvals, the join queue, and access
        // requests — everything waiting on an admin decision.
        let approvals: Vec<_> = self
            .pending_op_approvals()
            .iter()
            .map(|p| {
                serde_json::json!({
                    "kind": p.kind,
                    "params_digest": p.params_digest,
                    "initiated_by": p.initiated_by,
                    "required": p.required,
                    "approvals": p.approvals,
                    "params": p.params,
                })
            })
            .collect();
        let (join_rows, join_malformed) = crate::vault::members::list_requests(&self.path)?;
        let join_requests: Vec<_> = join_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "req_id": r.req_id,
                    "display_name": r.display_name,
                    "secret_ok": r.secret_ok,
                })
            })
            .collect();
        let (access_rows, access_malformed) =
            // The JIT inbox resolves the acting device's member id and
            // refuses on legacy vaults (no member directory); the
            // founder sees an empty inbox instead of a failed report.
            if self.path.join(crate::vault::members::MEMBERS_DIR).exists() {
                self.access_requests_inbox()?
            } else {
                (Vec::new(), 0)
            };
        let access_requests: Vec<serde_json::Value> = access_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "request_id": r.request_id,
                    "requester_name": r.requester_name,
                    "collection_id": r.collection_id,
                    "collection_name": r.collection_name,
                    "access": r.access,
                    "note": r.note,
                })
            })
            .collect();

        // Outbox mirrors (owner side): what is being mirrored to whom.
        // Contact display names resolve by signing pubkey; raw content
        // keys never leave this function.
        let outboxes = self.outbox_list()?;
        let contacts = self.contacts_list().unwrap_or_default();
        let contact_name = |pub_hex: &str| {
            contacts
                .iter()
                .find(|c| c.card.identity_signing_pubkey == pub_hex)
                .map(|c| c.card.display_name.clone())
        };
        let outbox_rows: Vec<_> = outboxes
            .iter()
            .map(|o| {
                serde_json::json!({
                    "outbox_id": o.outbox_id,
                    "path": o.path,
                    "recipient": contact_name(&o.recipient_signing_pub),
                    "recipient_signing_pub": o.recipient_signing_pub,
                    "published": o.published.len(),
                })
            })
            .collect();

        Ok(serde_json::json!({
            "generated_at": now,
            "flipped": flipped,
            "members": member_rows,
            "collections": collection_rows,
            "groups": groups,
            "exposure": exposure,
            "pending": {
                "approvals": approvals,
                "join_requests": join_requests,
                "join_malformed": join_malformed,
                "access_requests": access_requests,
                "access_malformed": access_malformed,
            },
            "outboxes": outbox_rows,
        }))
    }

    /// Delegated manage (S3-5): Owner/Admin pass structurally; a legacy
    /// vault (no member directory) is admin-equivalent; otherwise the
    /// device's member must hold a LIVE `manage` grant on this exact
    /// collection. Mirrors the sync-layer authority (the policy admits
    /// `meta/collections/<id>/**` writes from the parent tree's manage
    /// grants), so a commit this gate allows is verifiable on every
    /// peer and can never wedge the vault's sync.
    fn assert_can_manage_collection(&self, id: Uuid) -> Result<(), BaluardError> {
        if !self.path.join(crate::vault::members::MEMBERS_DIR).exists() {
            return Ok(());
        }
        match crate::vault::members::member_role_for_device(&self.path, self.device_id) {
            Some(crate::vault::members::MemberRole::Owner)
            | Some(crate::vault::members::MemberRole::Admin) => Ok(()),
            // S3-5 review F3: a demoted Viewer can carry a stale manage
            // grant (role changes never strip grants). The sync layer's
            // Editor floor would refuse their commits on every peer and
            // wedge the vault, so the local gate refuses up front,
            // grant or no grant.
            Some(crate::vault::members::MemberRole::Viewer) => Err(VaultError::InvalidOperation(
                "You do not have permission to manage that collection.".into(),
            )
            .into()),
            Some(_) => {
                let member_id =
                    crate::vault::members::member_id_for_device(&self.path, self.device_id);
                let collections =
                    crate::vault::collections::list_collections(&self.path, self.unlocked().sgk()?)
                        .unwrap_or_default();
                let manages = member_id.is_some_and(|m| {
                    collections.into_iter().any(|(f, _)| {
                        f.id == id
                            && crate::vault::groups::effective_access(
                                &f.grants,
                                m,
                                &|gid| {
                                    crate::vault::collections::load_group_memberships(&self.path)
                                        .into_iter()
                                        .find(|(id2, _)| *id2 == gid)
                                        .map(|(_, ms)| ms)
                                },
                                crate::vault::collections::now_secs_pub(),
                            ) == Some(crate::vault::collections::CollectionAccess::Manage)
                    })
                });
                if manages {
                    Ok(())
                } else {
                    Err(VaultError::InvalidOperation(
                        "You do not have permission to manage that collection.".into(),
                    )
                    .into())
                }
            }
            None => Err(VaultError::InvalidOperation(
                "You do not have permission to manage that collection.".into(),
            )
            .into()),
        }
    }

    // ── S1a-3: contact cards + trust dial ──

    fn contacts_key(&self) -> Result<[u8; 32], BaluardError> {
        crate::crypto::hkdf_derive::derive_contacts_key(&self.unlocked().meta_ikm())
            .map_err(BaluardError::from)
    }

    fn load_contacts(&self) -> Result<Vec<crate::vault::contacts::ContactEntry>, BaluardError> {
        crate::vault::contacts::load_contacts(&self.path, &self.contacts_key()?)
    }

    fn save_contacts(
        &self,
        entries: &[crate::vault::contacts::ContactEntry],
    ) -> Result<(), BaluardError> {
        crate::vault::contacts::save_contacts(&self.path, &self.contacts_key()?, entries)
    }

    /// S2: this vault member's identity-signed contact card (card v2,
    /// carries the X25519 wrap pubkey so item packages can be sent to
    /// it). Requires the identity to be available on this device.
    pub fn contact_card_signed(
        &self,
    ) -> Result<crate::vault::contacts::SignedContactCard, BaluardError> {
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let vk_hex = hex::encode(identity.signing_key().verifying_key().as_bytes());
        let wrap_hex = hex::encode(identity.wrapping_pub_bytes());
        let display_name = self
            .load_profile()
            .ok()
            .and_then(|p| p.display_name)
            .unwrap_or_else(|| "unnamed".into());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::vault::contacts::SignedContactCard::sign(
            &display_name,
            &vk_hex,
            &wrap_hex,
            None,
            now,
            identity.signing_key(),
        )
    }

    /// S1a-3: export this vault member's identity-signed contact card
    /// (out-of-band code). Requires the identity to be available on this
    /// device.
    pub fn contact_card_create(&self) -> Result<String, BaluardError> {
        let card = self.contact_card_signed()?;
        let code_bytes = serde_json::to_vec(&card)
            .map_err(|e| VaultError::Metadata(format!("encode card: {e}")))?;
        Ok(base64::engine::general_purpose::URL_SAFE.encode(code_bytes))
    }

    /// S1a-3: import a standalone contact card code (out-of-band card
    /// exchange, not tied to a join). Signature is verified against the
    /// card's own identity key; the entry lands at Channel until the
    /// code check.
    pub fn contacts_import_card(
        &mut self,
        card_code: &str,
    ) -> Result<crate::vault::contacts::ContactTrust, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let code_bytes = base64::engine::general_purpose::URL_SAFE
            .decode(card_code)
            .map_err(|e| VaultError::Metadata(format!("bad card code: {e}")))?;
        let card: crate::vault::contacts::SignedContactCard =
            serde_json::from_slice(&code_bytes)
                .map_err(|e| VaultError::Metadata(format!("bad card code: {e}")))?;
        card.verify()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::vault::contacts::upsert_contact(
            &self.path,
            &self.contacts_key()?,
            &card.card,
            crate::vault::contacts::ContactTrust::Channel,
            now,
        )
    }

    /// S1a-3: import a joiner's contact card from their introduction
    /// code. Signature is verified against the card's own identity key;
    /// the entry lands at Channel (Level 1) until the code check.
    pub fn contacts_import_intro(
        &mut self,
        intro_code: &str,
    ) -> Result<crate::vault::contacts::ContactTrust, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let intro = crate::vault::members::Introduction::decode(intro_code)?;
        let Some(card) = intro.contact_card else {
            return Err(VaultError::InvalidOperation(
                "introduction carries no contact card".into(),
            )
            .into());
        };
        card.verify()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::vault::contacts::upsert_contact(
            &self.path,
            &self.contacts_key()?,
            &card.card,
            crate::vault::contacts::ContactTrust::Channel,
            now,
        )
    }

    /// S1a-3: record the Level 2 code check — both sides displayed the
    /// verification code and confirmed the match. Upgrades the contact
    /// to Verified.
    pub fn contacts_mark_verified(
        &mut self,
        identity_signing_pubkey: &str,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::contacts::mark_verified(
            &self.path,
            &self.contacts_key()?,
            identity_signing_pubkey,
        )
    }

    /// Remove a contact from the address book. The dial position is
    /// local state; removing a contact never revokes anything the
    /// contact already received.
    pub fn contacts_remove(&mut self, identity_signing_pubkey: &str) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::contacts::remove_contact(
            &self.path,
            &self.contacts_key()?,
            identity_signing_pubkey,
        )
    }

    /// S2 IS-3: export a cipher as a one-shot item package, HPKE-wrapped
    /// to the recipient contact's identity wrap pubkey. The copy is
    /// inert: no live link, cannot be un-shared (the pre-send UI states
    /// this). Attachments, history, and vault-specific state do not travel.
    pub fn export_item_package(
        &self,
        cipher_id: Uuid,
        contact: &crate::vault::contacts::ContactCard,
    ) -> Result<Vec<u8>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let recipient_wrap: [u8; 32] = hex::decode(&contact.identity_wrap_pubkey)
            .map_err(|_| {
                VaultError::InvalidOperation(
                    "this contact's card has no sharing key: ask them to share their card again"
                        .into(),
                )
            })?
            .try_into()
            .map_err(|_| {
                VaultError::InvalidOperation(
                    "this contact's card has no sharing key: ask them to share their card again"
                        .into(),
                )
            })?;

        let cipher = match self.get_cipher(cipher_id)? {
            crate::vault::handle::CipherRead::Decrypted(c) => *c,
            crate::vault::handle::CipherRead::Locked(_) => {
                return Err(VaultError::Locked.into());
            }
        };
        let mut item = crate::types::CipherInput::from_cipher(&cipher);
        // Attachment bytes, history, and vault-specific pointers do not travel:
        // the recipient gets the item data only as a fresh entry.
        item.attachments.clear();
        item.password_history.clear();
        item.folder_id = None;
        item.archived = false;
        item.created_at = None;
        // Sharing-posture symmetry with the outbox: a one-shot package
        // must never carry a live passkey private key. A recipient who
        // needs the passkey re-registers it on their own device.
        Self::strip_fido2(&mut item);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sender_card = self.contact_card_signed()?;
        crate::vault::packages::seal_package(
            sender_card,
            now,
            item,
            &recipient_wrap,
            identity.signing_key(),
        )
    }

    /// S2 IS-3: open an item package and import the item as a fresh
    /// entry (new id, this vault's keys). Returns (new cipher id, sender
    /// display name from the verified card).
    pub fn import_item_package(
        &mut self,
        package_bytes: &[u8],
    ) -> Result<(Uuid, String), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let payload = crate::vault::packages::open_package(package_bytes, identity)?;
        let mut item = payload.item;
        // Defense in depth: the exporter strips these, a hostile
        // hand-built payload does not get to resurrect them. Passkeys
        // included: a planted credential would import a fake live
        // login the recipient might trust.
        item.attachments.clear();
        item.password_history.clear();
        item.folder_id = None;
        item.archived = false;
        item.created_at = None;
        Self::strip_fido2(&mut item);
        let cipher_id = self.add_cipher(&item)?;
        Ok((cipher_id, payload.sender_card.card.display_name.clone()))
    }

    /// S2 IS-6: pull the revealable fields out of a Login cipher.
    /// Only Login ciphers reveal: the field set is login-shaped (url,
    /// username, password, TOTP opt-in).
    fn reveal_fields_from_cipher(
        cipher: &crate::types::Cipher,
        include_totp: bool,
    ) -> Result<crate::vault::reveals::RevealFields, BaluardError> {
        let crate::types::CipherKind::Login(login) = &cipher.kind else {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "Only logins can be shared as a reveal.".into(),
            )));
        };
        Ok(crate::vault::reveals::RevealFields {
            url: login.uris.first().map(|u| u.uri.clone()),
            username: login.username.clone(),
            password: login.password.clone(),
            totp_uri: if include_totp {
                login.totp_uri.clone()
            } else {
                None
            },
        })
    }

    fn checked_reveal_expiry(expires_at: u64) -> Result<(), BaluardError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if expires_at <= now {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "Pick an expiry date in the future.".into(),
            )));
        }
        Ok(())
    }

    /// S2 IS-6 contact-key flavor: seal the reveal fields of a Login
    /// cipher to a contact card's wrap pubkey (Level 1 trust).
    pub fn export_contact_reveal(
        &self,
        cipher_id: Uuid,
        contact: &crate::vault::contacts::ContactCard,
        expires_at: u64,
        include_totp: bool,
    ) -> Result<Vec<u8>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Self::checked_reveal_expiry(expires_at)?;
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let recipient_wrap: [u8; 32] = hex::decode(&contact.identity_wrap_pubkey)
            .map_err(|_| {
                VaultError::InvalidOperation(
                    "this contact's card has no sharing key: ask them to share their card again"
                        .into(),
                )
            })?
            .try_into()
            .map_err(|_| {
                VaultError::InvalidOperation(
                    "this contact's card has no sharing key: ask them to share their card again"
                        .into(),
                )
            })?;
        let cipher = match self.get_cipher(cipher_id)? {
            crate::vault::handle::CipherRead::Decrypted(c) => *c,
            crate::vault::handle::CipherRead::Locked(_) => {
                return Err(VaultError::Locked.into());
            }
        };
        let fields = Self::reveal_fields_from_cipher(&cipher, include_totp)?;
        let sender_card = self.contact_card_signed()?;
        crate::vault::reveals::seal_contact_reveal(
            sender_card,
            identity.signing_key(),
            &cipher.name,
            &fields,
            expires_at,
            &recipient_wrap,
        )
    }

    /// S2 IS-6 passphrase-guest flavor: seal the reveal fields of a
    /// Login cipher under an app-generated passphrase (Level 0). The
    /// passphrase travels by voice, never beside the file.
    pub fn export_guest_reveal(
        &self,
        cipher_id: Uuid,
        expires_at: u64,
        include_totp: bool,
    ) -> Result<(Vec<u8>, String), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        // §6.5 guest_enabled, flipped 2026-10-03 by product decision: guest
        // sharing is OFF by default — only Some(true) opens the guest door
        // for NEW reveals. Already-created reveal files stay openable until
        // expiry — they are self-contained and carried by the recipient.
        if self.get_settings()?.guest_enabled != Some(true) {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "Guest sharing is turned off for this space.".into(),
            )));
        }
        Self::checked_reveal_expiry(expires_at)?;
        let cipher = match self.get_cipher(cipher_id)? {
            crate::vault::handle::CipherRead::Decrypted(c) => *c,
            crate::vault::handle::CipherRead::Locked(_) => {
                return Err(VaultError::Locked.into());
            }
        };
        let fields = Self::reveal_fields_from_cipher(&cipher, include_totp)?;
        crate::vault::reveals::seal_guest_reveal(&cipher.name, &fields, expires_at)
    }

    /// S2 IS-6: open a contact-key reveal with this vault's identity
    /// (the recipient side). Never mutates the vault.
    pub fn open_contact_reveal(
        &self,
        reveal_bytes: &[u8],
    ) -> Result<crate::vault::reveals::OpenedReveal, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::vault::reveals::open_contact_reveal(reveal_bytes, identity, now)
    }

    /// S1a-3: address book contents (People screen, thin).
    pub fn contacts_list(&self) -> Result<Vec<crate::vault::contacts::ContactEntry>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.load_contacts()
    }

    // ── S2 IS-4b: per-recipient outboxes (live mirror) ──

    fn outbox_key(&self) -> Result<[u8; 32], BaluardError> {
        crate::crypto::hkdf_derive::derive_outbox_key(self.unlocked().root()?.as_bytes())
            .map_err(BaluardError::from)
    }

    /// S3-4: role templates — named presets bundling a vault role plus
    /// collection grants, applied at invite time (see templates.rs).
    pub fn templates_list(
        &self,
    ) -> Result<Vec<crate::vault::templates::RoleTemplate>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::templates::load_templates(&self.path, self.unlocked().root()?.as_bytes())
    }

    /// Mint a role template (admin-gated). Names and grant structure
    /// are sealed inside meta/templates.enc, never on disk in the clear.
    pub fn template_create(
        &mut self,
        name: &str,
        role: crate::vault::members::MemberRole,
        grants: Vec<crate::vault::templates::TemplateGrant>,
    ) -> Result<crate::vault::templates::RoleTemplate, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::templates::validate_template(name, role, &grants)?;
        let root_key = self.unlocked().root()?.as_bytes();
        let mut all = crate::vault::templates::load_templates(&self.path, root_key)?;
        if all.len() >= crate::vault::templates::MAX_TEMPLATES {
            return Err(VaultError::InvalidOperation(
                "That vault has too many templates. Delete one first.".into(),
            )
            .into());
        }
        let template = crate::vault::templates::RoleTemplate {
            id: uuid::Uuid::new_v4(),
            name: name.trim().to_string(),
            role,
            grants,
            created_at: crate::vault::templates::now_secs(),
        };
        all.push(template.clone());
        crate::vault::templates::save_templates(&self.path, root_key, &all)?;
        Ok(template)
    }

    /// Delete a role template (admin-gated). Pending invites keep their
    /// embedded copy — the invite is the contract.
    pub fn template_delete(&mut self, template_id: uuid::Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let root_key = self.unlocked().root()?.as_bytes();
        let mut all = crate::vault::templates::load_templates(&self.path, root_key)?;
        let before = all.len();
        all.retain(|t| t.id != template_id);
        if all.len() == before {
            return Err(
                VaultError::InvalidOperation("That template no longer exists.".into()).into(),
            );
        }
        crate::vault::templates::save_templates(&self.path, root_key, &all)
    }

    /// Invite from a role template: the template's role must match the
    /// requested role (fail closed on divergence), and the template's
    /// grants are embedded in the invite at MINT time so approval
    /// applies exactly what the admin picked — even if the template is
    /// deleted before the joiner approves.
    pub fn invite_create_with_template(
        &mut self,
        role: crate::vault::members::MemberRole,
        transport_username: Option<String>,
        template_id: uuid::Uuid,
    ) -> Result<String, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        self.assert_invite_authority()?;
        let templates = crate::vault::templates::load_templates(
            &self.path,
            self.unlocked().root()?.as_bytes(),
        )?;
        let template = templates
            .into_iter()
            .find(|t| t.id == template_id)
            .ok_or_else(|| {
                BaluardError::from(VaultError::InvalidOperation(
                    "That template no longer exists.".into(),
                ))
            })?;
        if template.role != role {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "The picked role does not match that template.".into(),
            )));
        }
        crate::vault::members::create_invite(
            &self.path,
            self.vault_id,
            role,
            None,
            transport_username,
            Some(crate::vault::templates::EmbeddedTemplate {
                name: template.name,
                grants: template.grants,
            }),
        )
    }

    /// Publish (or re-publish) one cipher into a recipient's outbox.
    /// The entry is sealed from the CURRENT cipher state, so calling
    /// this after an edit IS the live mirror. Attachments and password
    /// history are stripped (attachment bytes never travel; history is
    /// stale on arrival), mirroring packages.
    pub fn outbox_publish(
        &mut self,
        outbox_path: &std::path::Path,
        cipher_id: Uuid,
        contact: &crate::vault::contacts::ContactCard,
    ) -> Result<crate::vault::outbox::OutboxReport, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let card = self.contact_card_signed()?;
        let mut item = match self.get_cipher(cipher_id)? {
            CipherRead::Decrypted(c) => crate::types::CipherInput::from_cipher(&c),
            CipherRead::Locked(_) => {
                return Err(VaultError::Locked.into());
            }
        };
        item.attachments.clear();
        item.password_history.clear();
        // View-only mirror: no passkey material travels (the embedded
        // encrypted blobs are useless to the recipient and private).
        Self::strip_fido2(&mut item);
        let report = crate::vault::outbox::publish_entry(
            &self.path,
            outbox_path,
            &card,
            identity.signing_key(),
            &self.outbox_key()?,
            cipher_id,
            &item,
            &contact.identity_signing_pubkey,
            &contact.identity_wrap_pubkey,
        )?;
        Ok(report)
    }

    /// Mirror hygiene shared by publish and resync: view-only reads never
    /// need passkey material, so the embedded credentials are stripped
    /// before an item is sealed into any outbox.
    fn strip_fido2(item: &mut crate::types::CipherInput) {
        if let crate::types::CipherKind::Login(ref mut login) = item.kind {
            login.fido2_credentials = None;
        }
    }

    /// Live-mirror tick: re-publish EVERY published entry from the
    /// current cipher state. Called best-effort after cipher CRUD (the
    /// daemon's COVER_MUTATION hook) and on the explicit resync route.
    /// Unchanged entries digest-match and cost nothing.
    pub fn outbox_resync_all(&mut self) -> Result<Vec<(Uuid, bool)>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let card = self.contact_card_signed()?;
        let key = self.outbox_key()?;
        // A trashed source is a deletion for mirror purposes: the
        // recipient must not keep serving stale bytes.
        let trashed: std::collections::HashSet<Uuid> = self.list_trash_ids()?.into_iter().collect();
        let mut results = Vec::new();
        for record in crate::vault::outbox::load_owner_registry(&self.path, &key)? {
            let path = std::path::Path::new(&record.path);
            for pref in &record.published {
                if trashed.contains(&pref.cipher_id) {
                    let _ = crate::vault::outbox::unpublish_entry(
                        &self.path,
                        path,
                        &key,
                        pref.cipher_id,
                    );
                    results.push((pref.cipher_id, true));
                    continue;
                }
                let mut item = match self.get_cipher(pref.cipher_id) {
                    Ok(CipherRead::Decrypted(c)) => crate::types::CipherInput::from_cipher(&c),
                    // Locked (trashed/locked) source: the entry must
                    // not keep serving stale bytes — unpublish it.
                    Ok(CipherRead::Locked(_)) => {
                        let _ = crate::vault::outbox::unpublish_entry(
                            &self.path,
                            path,
                            &key,
                            pref.cipher_id,
                        );
                        results.push((pref.cipher_id, true));
                        continue;
                    }
                    // Purged (hard-deleted) source: get_cipher errors
                    // CipherNotFound — the mirror must unpublish, not
                    // abort (a purge would otherwise wedge every later
                    // resync on this outbox).
                    Err(e) if matches!(&e, BaluardError::Vault(VaultError::CipherNotFound(_))) => {
                        let _ = crate::vault::outbox::unpublish_entry(
                            &self.path,
                            path,
                            &key,
                            pref.cipher_id,
                        );
                        results.push((pref.cipher_id, true));
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                item.attachments.clear();
                item.password_history.clear();
                Self::strip_fido2(&mut item);
                let report = match crate::vault::outbox::publish_entry(
                    &self.path,
                    path,
                    &card,
                    identity.signing_key(),
                    &key,
                    pref.cipher_id,
                    &item,
                    &record.recipient_signing_pub,
                    &record.recipient_wrap_pub,
                ) {
                    Ok(report) => report,
                    // One broken outbox (unmounted drive, stale lock)
                    // must not starve every later resync: report the
                    // miss and keep going.
                    Err(e) => {
                        eprintln!(
                            "warning: outbox resync: publish {} failed: {e}",
                            pref.cipher_id
                        );
                        results.push((pref.cipher_id, false));
                        continue;
                    }
                };
                results.push((pref.cipher_id, report.committed));
            }
        }
        Ok(results)
    }

    /// Remove one published entry from a recipient's outbox
    /// (source-deleted → entry unpublished).
    pub fn outbox_unpublish(
        &mut self,
        outbox_path: &std::path::Path,
        cipher_id: Uuid,
    ) -> Result<crate::vault::outbox::OutboxReport, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::outbox::unpublish_entry(
            &self.path,
            outbox_path,
            &self.outbox_key()?,
            cipher_id,
        )
    }

    /// Revoke a whole outbox: unpublish everything, drop the keywrap,
    /// forget the record. Provider seat removal is the runtime's job.
    pub fn outbox_revoke(&mut self, outbox_path: &std::path::Path) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::outbox::revoke_outbox(&self.path, outbox_path, &self.outbox_key()?)
    }

    /// The owner's outbox records (which folder belongs to whom, what
    /// is published, the dirty-check digests).
    pub fn outbox_list(&self) -> Result<Vec<crate::vault::outbox::OwnerOutbox>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::outbox::load_owner_registry(&self.path, &self.outbox_key()?)
    }

    /// Recipient side: link an outbox folder (view-only; nothing is
    /// imported — reads resolve live against the folder).
    pub fn outbox_link(
        &mut self,
        outbox_path: &std::path::Path,
    ) -> Result<crate::vault::outbox::OutboxLink, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        crate::vault::outbox::link_outbox(&self.path, &self.outbox_key()?, identity, outbox_path)
    }

    pub fn outbox_links(&self) -> Result<Vec<crate::vault::outbox::OutboxLink>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::outbox::load_links(&self.path, &self.outbox_key()?)
    }

    pub fn outbox_forget(&mut self, outbox_id: Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        crate::vault::outbox::forget_link(&self.path, &self.outbox_key()?, outbox_id)
    }

    /// Read one shared entry from a linked outbox (view-only; the item
    /// is NOT imported). Sender name comes from the verified card.
    pub fn outbox_read(
        &self,
        outbox_id: Uuid,
        cipher_id: Uuid,
    ) -> Result<crate::vault::outbox::OpenedEntry, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let link = crate::vault::outbox::load_links(&self.path, &self.outbox_key()?)?
            .into_iter()
            .find(|l| l.outbox_id == outbox_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("that shared folder is not linked anymore".into())
            })?;
        crate::vault::outbox::open_entry(std::path::Path::new(&link.path), &link, cipher_id)
    }

    /// List the entries of one linked outbox (view-only).
    pub fn outbox_list_entries(
        &self,
        outbox_id: Uuid,
    ) -> Result<Vec<crate::vault::outbox::OpenedEntry>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let link = crate::vault::outbox::load_links(&self.path, &self.outbox_key()?)?
            .into_iter()
            .find(|l| l.outbox_id == outbox_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("that shared folder is not linked anymore".into())
            })?;
        crate::vault::outbox::list_entries(std::path::Path::new(&link.path), &link)
    }

    // ── Collections (S3-1) ──────────────────────────────────────────────

    /// Mint a collection (admin-gated). Entries keep their personal keys;
    /// the collection is the grant/organization layer for now.
    pub fn collection_create(&mut self, name: &str) -> Result<Uuid, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        // §6.5 collection_create_authority (decided 2026-09-27): admins
        // only by default; `editors` lets any bound live Editor-or-above
        // create. Viewer and unbound devices refuse either way.
        match self.get_settings()?.collection_create_authority {
            crate::vault::manifest::CollectionCreateAuthority::Admins => {
                self.assert_can_manage_members()?
            }
            crate::vault::manifest::CollectionCreateAuthority::Editors => {
                if self.path.join(crate::vault::members::MEMBERS_DIR).exists() {
                    match crate::vault::members::member_role_for_device(&self.path, self.device_id)
                    {
                        Some(crate::vault::members::MemberRole::Viewer) => {
                            return Err(VaultError::InvalidOperation(
                                "creating collections is limited to admins in this space.".into(),
                            )
                            .into());
                        }
                        Some(_) => {}
                        None => {
                            return Err(VaultError::InvalidOperation(
                                "This change can only be made on a managing device.".into(),
                            )
                            .into());
                        }
                    }
                }
            }
        }
        let file =
            crate::vault::collections::create_collection(&self.path, self.unlocked().sgk()?, name)?;

        Ok(file.id)
    }

    /// List collections with decrypted names (any unlocked member).
    pub fn collections_list(
        &self,
    ) -> Result<
        Vec<(
            Uuid,
            String,
            Vec<crate::vault::collections::CollectionGrant>,
        )>,
        BaluardError,
    > {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Ok(
            crate::vault::collections::list_collections(&self.path, self.unlocked().sgk()?)?
                .into_iter()
                .map(|(f, name)| (f.id, name, f.grants))
                .collect(),
        )
    }

    /// S3-7c / 4.8: the member-side listing — collections this device's
    /// member can open, names decrypted through the per-member grant
    /// wrap. No group key involved.
    pub fn my_collections_list(
        &self,
    ) -> Result<Vec<crate::vault::collections::MemberCollectionRow>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let unlocked = self.unlocked();
        let identity = unlocked.identity.as_ref().ok_or_else(|| {
            BaluardError::from(VaultError::InvalidOperation(
                "This device has no member identity.".into(),
            ))
        })?;
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                BaluardError::from(VaultError::InvalidOperation(
                    "This device is not a member of this space yet.".into(),
                ))
            })?;
        Ok(crate::vault::collections::list_member_collections(
            &self.path,
            &member_id,
            identity.wrapping_secret(),
        ))
    }

    /// Rename a collection (admin, or the collection's delegated
    /// manager — S3-5).
    pub fn collection_rename(&mut self, id: Uuid, name: &str) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_collection(id)?;
        crate::vault::collections::rename_collection(
            &self.path,
            self.unlocked().sgk()?,
            &id,
            name,
        )?;
        Ok(())
    }

    /// Delete a collection (admin-gated). Entries stay; grants die.
    pub fn collection_delete(&mut self, id: Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::collections::delete_collection(&self.path, &id)
    }

    // ── Groups (S4-2) ─────────────────────────────────────────────────

    /// Admin-gated throughout: group management is the admin surface
    /// (who may do what defaults to admins per the power-pack doctrine).
    fn assert_group_admin(&self) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()
    }

    /// Mint a group: random Group Key, SGK-sealed, name sealed under
    /// the GK, empty membership.
    pub fn group_create(&mut self, name: &str) -> Result<Uuid, BaluardError> {
        self.assert_group_admin()?;
        let file = crate::vault::groups::create_group(&self.path, self.unlocked().sgk()?, name)?;
        Ok(file.id)
    }

    /// List groups with decrypted names (any unlocked member — the
    /// membership lists are plaintext and the names ride the GK, which
    /// members reach through their gkwrap only for groups they are in;
    /// this listing is the ADMIN view, so it needs the SGK).
    pub fn groups_list(&self) -> Result<Vec<(Uuid, String, Vec<Uuid>)>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Ok(
            crate::vault::groups::list_groups(&self.path, self.unlocked().sgk()?)?
                .into_iter()
                .map(|(f, name)| (f.id, name, f.members))
                .collect(),
        )
    }

    /// Rename a group (re-seals the name under the GK).
    pub fn group_rename(&mut self, id: Uuid, name: &str) -> Result<(), BaluardError> {
        self.assert_group_admin()?;
        crate::vault::groups::rename_group(&self.path, self.unlocked().sgk()?, &id, name)?;
        Ok(())
    }

    /// Delete a group. Collection grants naming it are pruned; entries
    /// stay.
    pub fn group_delete(&mut self, id: Uuid) -> Result<(), BaluardError> {
        self.assert_group_admin()?;
        crate::vault::groups::delete_group(&self.path, self.unlocked().sgk()?, &id)
    }

    /// Add a member to a group: membership row + gkwrap mint.
    pub fn group_member_add(&mut self, id: Uuid, member_id: Uuid) -> Result<(), BaluardError> {
        self.assert_group_admin()?;
        crate::vault::groups::add_group_member(
            &self.path,
            self.unlocked().sgk()?,
            &id,
            &member_id,
        )?;
        Ok(())
    }

    /// Remove a member from a group: the GK rotates (ckwraps re-seal
    /// under it; collection CKs stay invariant) and the leaver's gkwrap
    /// dies.
    pub fn group_member_remove(&mut self, id: Uuid, member_id: Uuid) -> Result<(), BaluardError> {
        self.assert_group_admin()?;
        crate::vault::groups::remove_group_member(
            &self.path,
            self.unlocked().sgk()?,
            &id,
            &member_id,
        )?;
        Ok(())
    }

    /// Grant or update access on a collection (admin, or the
    /// collection's delegated manager — S3-5). The target names a
    /// member or a group (S4-2).
    pub fn collection_grant(
        &mut self,
        id: Uuid,
        target: crate::vault::collections::GrantTarget,
        access: crate::vault::collections::CollectionAccess,
        expires_at: Option<u64>,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        match &target {
            // S4-2: group grants write ckwraps under meta/groups — an
            // Admin row. A delegated manager grants PEOPLE, not
            // departments: a group grant from a manage-holder would
            // wedge their commit at every peer's policy walk.
            crate::vault::collections::GrantTarget::Group { .. } => {
                self.assert_can_manage_members()?;
            }
            crate::vault::collections::GrantTarget::Member { .. } => {
                self.assert_can_manage_collection(id)?;
            }
        }
        crate::vault::collections::upsert_grant(
            &self.path,
            self.unlocked().sgk()?,
            &id,
            crate::vault::collections::CollectionGrant {
                target,
                access,
                expires_at,
            },
        )?;
        Ok(())
    }

    /// Revoke one grant (a member's or a group's) on a collection
    /// (admin, or the collection's delegated manager — S3-5).
    pub fn collection_revoke(
        &mut self,
        id: Uuid,
        target: crate::vault::collections::GrantTarget,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        match &target {
            // Revoking a group grant removes the group's ckwrap — also a
            // meta/groups write, so the same admin-only rule applies
            // (delegated managers revoke PEOPLE, not departments).
            crate::vault::collections::GrantTarget::Group { .. } => {
                self.assert_can_manage_members()?;
            }
            crate::vault::collections::GrantTarget::Member { .. } => {
                self.assert_can_manage_collection(id)?;
            }
        }
        crate::vault::collections::revoke_grant(&self.path, self.unlocked().sgk()?, &id, &target)?;
        Ok(())
    }

    /// Expiry-that-rotates (plan line 153): drop grants whose
    /// `expires_at` has passed and rotate the affected collections'
    /// keys. Admin-gated — meta/collections/** is Admin-only at the git
    /// layer, so a non-admin sweep would mint a refused commit and wedge
    /// every peer's pull.
    pub fn collections_sweep(
        &mut self,
    ) -> Result<Vec<crate::vault::collections::ExpiredGrant>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let sgk = self.unlocked().sgk()?.clone();
        // Converge a crash-interrupted sweep first: rotations recorded on
        // the pending marker are carried only when the live def actually
        // holds the new CK (a rotation whose def never flipped is dropped —
        // its files are still old-keyed and the fresh sweep below will
        // rotate again). The marker clears only after the carry pass.
        let pending_rotations = crate::vault::collections::read_sweep_pending(&self.path);
        if !pending_rotations.is_empty() {
            for rot in &pending_rotations {
                let flipped = crate::vault::collections::open_collection(
                    &self.path,
                    &sgk,
                    &rot.collection_id,
                )
                .ok()
                .and_then(|(def, _)| {
                    crate::vault::collections::unwrap_ck(&def, &sgk)
                        .ok()
                        .map(|ck| ck.as_ref() == rot.new_ck.as_ref())
                })
                .unwrap_or(false);
                if flipped {
                    self.reencrypt_after_sweep(rot);
                }
            }
            crate::vault::collections::clear_sweep_pending(&self.path);
        }
        let swept = crate::vault::collections::sweep_expired_grants(&self.path, &sgk)?;
        // Carry each key rotation into the entry files. Their item keys
        // derive from the CK (S3-7c path-derived domains), so a rotated CK
        // without this pass destroys every entry in the collection.
        for rot in &swept.rotations {
            self.reencrypt_after_sweep(rot);
        }
        crate::vault::collections::clear_sweep_pending(&self.path);
        Ok(swept.removed)
    }

    /// Re-encrypt every entry and trash item under one swept collection's
    /// directory from the outgoing CK's item key to the new CK's, at the
    /// envelope's own epoch and seq (content unchanged). Per-file
    /// best-effort: one corrupt entry must not wedge the sweep — it is
    /// named loudly and left behind instead.
    fn reencrypt_after_sweep(&self, rot: &crate::vault::collections::SweptRotation) {
        let Some(dir) = &rot.dir else {
            return;
        };
        for sub in ["ciphers", "trash"] {
            let dir_path = self.path.join(sub).join(dir);
            let Ok(entries) = std::fs::read_dir(&dir_path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                    continue;
                }
                let result = self.reencrypt_one_after_sweep(rot, &path);
                if let Err(e) = result {
                    eprintln!(
                        "sweep: could not carry {} into the collection's new key ({e}); the entry is left behind",
                        path.display()
                    );
                }
            }
        }
    }

    fn reencrypt_one_after_sweep(
        &self,
        rot: &crate::vault::collections::SweptRotation,
        path: &std::path::Path,
    ) -> Result<(), BaluardError> {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| VaultError::Corrupt("entry path has no name".into()))?;
        let cipher_id: Uuid = stem
            .parse()
            .map_err(|e| VaultError::Corrupt(format!("entry name is not an id: {e}")))?;
        let envelope_bytes = std::fs::read(path)?;
        let envelope = crate::vault::envelope::deserialize(&envelope_bytes)?;
        let key_epoch = envelope.header.key_epoch;
        let old_item = crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
            &rot.old_ck,
            cipher_id,
            key_epoch,
        );
        let file = crate::vault::cipher::CipherFile {
            id: cipher_id,
            envelope_bytes,
        };
        let mut existing =
            crate::vault::cipher::decrypt_cipher(self.vault_id, cipher_id, &file, &old_item)?;
        let input = CipherInput {
            name: existing.name.clone(),
            folder_id: existing.folder_id,
            collection_id: None,
            kind: existing.kind.clone(),
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes.clone(),
            custom_fields: existing.custom_fields.clone(),
            created_at: Some(existing.created_at),
            password_history: existing.password_history.clone(),
            attachments: existing.attachments.clone(),
            archived: existing.archived,
            tags: existing.tags.clone(),
        };
        let new_item = crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
            &rot.new_ck,
            cipher_id,
            key_epoch,
        );
        // Attachment blobs are encrypted with the cipher's item key, so
        // they ride the same CK rotation (the mirror of the rotation
        // twins' attachment block — without this every blob is stranded).
        for attach_meta in &existing.attachments {
            let attach_path = self
                .path
                .join("entries")
                .join(cipher_id.to_string())
                .join("attachments")
                .join(format!("{}.enc", attach_meta.id));
            if !attach_path.exists() {
                continue;
            }
            let attach_uuid: Uuid = attach_meta
                .id
                .parse()
                .map_err(|e| VaultError::Corrupt(format!("attachment id not a uuid: {e}")))?;
            let enc_blob = std::fs::read(&attach_path)?;
            let mut plaintext = crate::vault::attachment::decrypt_attachment(
                self.vault_id,
                cipher_id,
                attach_uuid,
                old_item.as_bytes(),
                &enc_blob,
            )?;
            let new_enc = crate::vault::attachment::encrypt_attachment(
                self.vault_id,
                cipher_id,
                attach_uuid,
                new_item.as_bytes(),
                &plaintext,
                key_epoch,
                existing.update_seq,
            )?;
            plaintext.zeroize();
            let attach_tmp = attach_path.with_extension("enc.tmp");
            std::fs::write(&attach_tmp, &new_enc)?;
            std::fs::rename(&attach_tmp, &attach_path)?;
        }
        let new_file = crate::vault::cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input,
            &new_item,
            key_epoch,
            existing.update_seq,
        )?;
        Self::zeroize_decrypted_cipher(&mut existing);
        let tmp_path = path.with_extension("enc.tmp");
        std::fs::write(&tmp_path, &new_file.envelope_bytes)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    // ── S3-7a: Space Meta Key groundwork ──

    /// Mint (or idempotently refresh) the SMK store + per-member wraps.
    /// Admin-gated. The report names live members that can never be
    /// wrapped (legacy rows without an identity wrap pubkey); the 7b
    /// flip gate refuses until that list is empty.
    pub fn space_prepare(
        &mut self,
    ) -> Result<crate::vault::space_meta::PrepareReport, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::space_meta::prepare(&self.path, self.unlocked().root()?)
    }

    /// Readiness counts for the Team-shape flip. Admin-gated.
    pub fn space_status(&self) -> Result<crate::vault::space_meta::SpaceStatus, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let mut st = crate::vault::space_meta::status(&self.path, self.unlocked().root()?)?;
        // S3-7b completion: the rotation reminder is PERSISTENT — a flip
        // without a following rotation leaves pre-flip members' historical
        // keywraps able to unwrap the current root, so status says so
        // until an epoch bump proves the rotation ran.
        st.needs_rotation = st.flipped_epoch == Some(self.unlocked().current_epoch);
        Ok(st)
    }

    /// S3-7b: flip the vault to team shape. After this commit:
    /// - the seven member-visible meta derivations take HKDF(SMK);
    /// - member devices stop receiving the Root Key (their device
    ///   keywraps are removed) and unlock via identity seed + space.wrap;
    /// - future rotations stage Root Key wraps for admin devices only.
    ///
    /// Admin-gated. Readiness-gated: every live non-admin member must
    /// carry a usable identity wrap pubkey AND a minted space.wrap, or
    /// the flip refuses (they would be locked out at the next unlock).
    /// Marker-first ordering keeps every crash window recoverable: the
    /// next admin unlock converges any half-flipped files.
    pub fn space_flip(&mut self) -> Result<SpaceFlipReport, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let already = crate::vault::space_meta::shape_flipped(&self.path);
        if already {
            // Idempotent: report, converge leftovers, strip any re-grown
            // member keywraps (e.g. from a pre-flip enrollment sync).
            let removed = self.strip_member_keywraps();
            return Ok(SpaceFlipReport {
                already_flipped: true,
                files_reencrypted: 0,
                keywraps_removed: removed,
            });
        }

        // Readiness: prepare is idempotent and closes mint/pending gaps.
        let report = crate::vault::space_meta::prepare(&self.path, self.unlocked().root()?)?;
        let mut blocked = Vec::new();
        let members = crate::vault::members::list_members(&self.path)?;
        for m in members
            .iter()
            .filter(|m| m.removed.is_none() && m.reset.is_none())
        {
            let is_admin = matches!(
                m.role,
                crate::vault::members::MemberRole::Owner | crate::vault::members::MemberRole::Admin
            );
            if is_admin {
                continue;
            }
            let usable = m
                .identity_wrap_pubkey
                .as_deref()
                .and_then(|k| crate::vault::collections::wrap_pubkey_bytes(k).ok())
                .is_some();
            if !usable || !crate::vault::space_meta::has_space_wrap(&self.path, &m.id) {
                blocked.push(m.id);
            }
        }
        if !blocked.is_empty() {
            let _ = report;
            return Err(VaultError::InvalidOperation(format!(
                "cannot flip: {} member(s) have no usable identity wrap or space wrap yet; run prepare after they re-verify ({})",
                blocked.len(),
                blocked
                    .iter()
                    .map(|u| u.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .into());
        }

        // Snapshot the five tracked meta files under the CURRENT (Root
        // Key) derivation, before the marker moves the IKM. The avatar
        // rides the same domain; snapshot its bytes too when present.
        let folders = self.list_folders()?;
        let tags = self.list_tags()?;
        let profile = self.load_profile()?;
        let settings = self.get_settings()?;
        let contacts = self.load_contacts()?;
        let avatar_path = self.path.join("meta/avatar.enc");
        let avatar_bytes = avatar_path
            .exists()
            .then(|| std::fs::read(&avatar_path).ok())
            .flatten()
            .and_then(|blob| self.decrypt_avatar_blob(&blob).ok());

        // Point of no return: the marker switches every device's unlock
        // and meta derivation. Files converge after (crash-safe: the next
        // admin unlock re-runs convergence).
        crate::vault::space_meta::write_shape_marker(&self.path, self.unlocked().current_epoch)?;
        let smk = crate::vault::space_meta::open_store(&self.path, self.unlocked().root()?)?;
        self.unlocked_mut().smk = Some(smk);

        // Re-seal the tracked meta files under the new derivation.
        let mut files = 0usize;
        self.save_folders(&folders)?;
        files += 1;
        let index = crate::vault::manifest::TagIndex {
            tags,
            updated_at: crate::vault::templates::now_secs(),
        };
        self.save_tags_enc(&index)?;
        files += 1;
        self.save_profile(&profile)?;
        files += 1;
        self.save_settings(&settings)?;
        files += 1;
        self.save_contacts(&contacts)?;
        files += 1;

        // The avatar joins the member-visible domain so members can
        // actually see it; counted only when one exists.
        if let Some(bytes) = avatar_bytes {
            let key = zeroize::Zeroizing::new(self.derive_avatar_key()?);
            let new_blob = crate::vault::avatar::encrypt_avatar(&key, &bytes)?;
            super::write_vault_file(&avatar_path, &new_blob)?;
            files += 1;
        }

        // Team members stop receiving the Root Key, effective immediately.
        let keywraps_removed = self.strip_member_keywraps();

        self.emit_share_event(
            crate::vault::events::ShareEventKind::AccessGranted,
            "space switched to team shape; members now hold scoped keys only",
        );
        Ok(SpaceFlipReport {
            already_flipped: false,
            files_reencrypted: files,
            keywraps_removed,
        })
    }

    /// S3-7b: whether this device belongs to an Owner/Admin member (or
    /// to no member row — legacy/founding devices are admin-equivalent).
    fn device_maps_to_admin(&self, dev_id: Uuid) -> bool {
        // Legacy founder: no member directory at all — the founding device
        // is the admin by construction. With a directory present, ANY
        // unresolvable device (no binding, tombstoned row, ambiguous
        // bindings) is NOT admin-mapped: the unwrap_or(true) fallback here
        // let a reset admin's tombstoned resolution ride the admin unlock
        // path again (the 2026-10-01 fix round; same class as the
        // bc38e16 tombstone fix).
        if !self.path.join(crate::vault::members::MEMBERS_DIR).exists() {
            return true;
        }
        crate::vault::members::member_id_for_device(&self.path, dev_id)
            .and_then(|m| {
                crate::vault::members::list_members(&self.path)
                    .ok()
                    .and_then(|rows| {
                        rows.iter().find(|r| r.id == m).map(|r| {
                            // Tombstones kill the mapping: a reset or
                            // removed row keeps its role field, but the
                            // device behind it must not read as an
                            // admin anywhere — unlock dispatch, rotation
                            // staging, rekey adoption, and keywrap
                            // stripping all share this predicate.
                            matches!(
                                r.role,
                                crate::vault::members::MemberRole::Owner
                                    | crate::vault::members::MemberRole::Admin
                            ) && r.reset.is_none()
                                && r.removed.is_none()
                        })
                    })
            })
            .unwrap_or(false)
    }

    /// Delete the device keywraps of non-admin members' devices (S3-7b:
    /// their unlock path no longer needs — and must no longer hold — the
    /// Root Key). Devices that cannot be resolved to a member (legacy
    /// solo vaults, founding devices) are left untouched.
    fn strip_member_keywraps(&self) -> usize {
        let keywrap_dir = self.path.join("meta/keywrap");
        let Ok(entries) = std::fs::read_dir(&keywrap_dir) else {
            return 0;
        };
        let mut removed = 0usize;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id_str) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(dev_id) = Uuid::parse_str(id_str) else {
                continue;
            };
            if dev_id == self.device_id {
                continue; // never strip the acting device's own wrap
            }
            if !self.device_maps_to_admin(dev_id) {
                // Best-effort; a leftover file is stripped on the next flip
                // call. Non-admin members' unlock tail never opens it; an
                // elevated member's admin unlock path needs it, and
                // device_maps_to_admin keeps their wraps right here.
                if std::fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        removed
    }

    // ── S3-6: request-access JIT ──

    /// Submit a JIT ask for collection access (any live member, any role).
    /// The ask ships to the repo via autosync; approvers see it in
    /// [`Self::access_requests_inbox`] after their next pull.
    pub fn collection_access_request(
        &mut self,
        collection_id: Uuid,
        access: crate::vault::collections::CollectionAccess,
        note: &str,
    ) -> Result<Uuid, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("This device is not a member of this vault.".into())
            })?;
        let (collection, _) = crate::vault::collections::open_collection(
            &self.path,
            self.unlocked().sgk()?,
            &collection_id,
        )?;
        crate::vault::access_requests::submit_request(
            &self.path,
            member_id,
            &collection,
            access,
            note,
        )
    }

    /// The caller's own pending asks.
    pub fn my_access_requests(
        &self,
    ) -> Result<Vec<crate::vault::access_requests::OwnRequestRow>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("This device is not a member of this vault.".into())
            })?;
        crate::vault::access_requests::list_own_requests(&self.path, member_id)
    }

    /// Withdraw one of the caller's own pending asks.
    pub fn withdraw_access_request(&mut self, request_id: Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("This device is not a member of this vault.".into())
            })?;
        crate::vault::access_requests::withdraw_request(&self.path, member_id, request_id)
    }

    /// The approver inbox (admin surface): decrypted pending asks plus a
    /// count of inert files (malformed, tampered, or not addressed to this
    /// approver).
    pub fn access_requests_inbox(
        &self,
    ) -> Result<(Vec<crate::vault::access_requests::AccessRequestRow>, usize), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let approver = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("This device is not a member of this vault.".into())
            })?;
        crate::vault::access_requests::list_inbox(
            &self.path,
            approver,
            identity.wrapping_secret(),
            self.unlocked().sgk()?,
        )
    }

    /// Approve a JIT ask: issue the grant (the admin may override access
    /// and set an expiry; the granted collection and requester always come
    /// from the sealed ask) and consume the request file. Admin-gated:
    /// consuming another member's request file writes outside the own
    /// subtree, and delegated managers have no such reach (S3-5 boundary).
    pub fn approve_access_request(
        &mut self,
        requester_member_id: Uuid,
        request_id: Uuid,
        access: Option<crate::vault::collections::CollectionAccess>,
        expires_at: Option<u64>,
    ) -> Result<crate::vault::access_requests::AccessRequestRow, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let identity = self.identity().ok_or_else(|| {
            VaultError::InvalidOperation("identity not available on this device".into())
        })?;
        let approver = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation("This device is not a member of this vault.".into())
            })?;
        let row = crate::vault::access_requests::open_inbox_row(
            &self.path,
            requester_member_id,
            request_id,
            approver,
            identity.wrapping_secret(),
            self.unlocked().sgk()?,
        )?;
        let final_access = access.unwrap_or(row.access);
        // The askable set is read/write (refused at submit); a crafted or
        // overridden manage approval must refuse here too — manage grants
        // go through collections.grant, never the inbox (review F1).
        if final_access == crate::vault::collections::CollectionAccess::Manage {
            return Err(VaultError::InvalidOperation(
                "Manage access cannot be granted through a request approval.".into(),
            )
            .into());
        }
        crate::vault::collections::upsert_grant(
            &self.path,
            self.unlocked().sgk()?,
            &row.collection_id,
            crate::vault::collections::CollectionGrant {
                target: crate::vault::collections::GrantTarget::Member {
                    id: requester_member_id,
                },
                access: final_access,
                expires_at,
            },
        )?;
        crate::vault::access_requests::consume_request(
            &self.path,
            requester_member_id,
            request_id,
        )?;
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::AccessGranted,
            format!(
                "granted {} access to {} on collection \"{}\"",
                row.requester_name,
                match final_access {
                    crate::vault::collections::CollectionAccess::Read => "view",
                    crate::vault::collections::CollectionAccess::Write
                    | crate::vault::collections::CollectionAccess::Manage => "edit",
                },
                row.collection_name.as_deref().unwrap_or("a collection"),
            ),
        );
        Ok(row)
    }

    /// Deny a JIT ask: consume the request file, grant nothing. Admin-gated
    /// (same reason as approval).
    pub fn deny_access_request(
        &mut self,
        requester_member_id: Uuid,
        request_id: Uuid,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::access_requests::consume_request(
            &self.path,
            requester_member_id,
            request_id,
        )?;
        let name = crate::vault::members::member_file_by_id(&self.path, requester_member_id)
            .map(|m| m.display_name)
            .unwrap_or_else(|| "unknown".into());
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::AccessDenied,
            format!("denied an access request from {name}"),
        );
        Ok(())
    }

    /// Publish (or replace/clear) the plaintext collection catalog (admin
    /// surface; the git policy's meta/collections/** Admin row is the
    /// enforcement twin).
    pub fn catalog_publish(
        &mut self,
        entries: Vec<crate::vault::access_requests::CatalogEntry>,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::access_requests::catalog_set(&self.path, self.unlocked().sgk()?, entries)
    }

    /// The catalog as requesters see it (any unlocked member; empty when
    /// the org has not published one).
    pub fn catalog_entries(
        &self,
    ) -> Result<Vec<crate::vault::access_requests::CatalogEntry>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        Ok(crate::vault::access_requests::catalog_list(&self.path))
    }

    /// S1a-4: reconcile the address book against member identity records
    /// after a sync. A Verified contact whose pubkey no longer matches
    /// its member's current identity (the member rotated) drops to
    /// Channel — the trust reset that makes rotation visible and
    /// contestable. Returns the downgraded identity pubkeys.
    pub fn reconcile_stale_member_contacts(&mut self) -> Result<Vec<String>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let downgraded =
            crate::vault::contacts::reconcile_stale_contacts(&self.path, &self.contacts_key()?)?;
        // S1b-1: activity log (best-effort).
        if !downgraded.is_empty() {
            self.emit_share_event(
                crate::vault::events::ShareEventKind::ContactTrustReset,
                format!(
                    "trust reset for {} contact(s): their identity was rotated or removed",
                    downgraded.len()
                ),
            );
        }
        Ok(downgraded)
    }

    /// S1a-2: mint a one-time member invite (owner side). The returned
    /// code travels out-of-band; the repo-side pending file records only
    /// the role and the secret hash. Consumed at approval.
    pub fn invite_create(
        &mut self,
        role: crate::vault::members::MemberRole,
        transport_username: Option<String>,
    ) -> Result<String, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        self.assert_invite_authority()?;
        crate::vault::members::create_invite(
            &self.path,
            self.vault_id,
            role,
            None,
            transport_username,
            None,
        )
    }

    /// S1a-5: member reset (§5.F-8 / scenario L — "tablet died, phrase
    /// gone", the #1 family ticket). Admin-only, never on the owner row,
    /// never on yourself. Tombstones the old row (identity dead,
    /// bindings inert, contacts reconcile to Channel) and returns the
    /// successor member id plus a one-time reset invite code: the member
    /// rejoins through the normal ceremony (introduce → approve) and the
    /// approval binds the successor row. Entries are preserved.
    pub fn member_reset(
        &mut self,
        member_id: uuid::Uuid,
    ) -> Result<(uuid::Uuid, String), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        // Review F5: the self guard fires BEFORE the gate — a self-reset
        // must fail outright, never record a pending ask to reset
        // yourself.
        if crate::vault::members::member_id_for_device(&self.path, self.device_id)
            == Some(member_id)
        {
            return Err(VaultError::InvalidOperation(
                "resetting your own member row would lock you out".into(),
            )
            .into());
        }
        self.quorum_gate(
            "member_reset",
            &serde_json::json!({ "member_id": member_id }),
        )?;
        let (successor, code) =
            crate::vault::members::reset_member(&self.path, self.vault_id, member_id)?;
        // S4-2: group memberships die with the reset — the successor
        // re-joins fresh, and each affected group's GK rotates so the
        // reset row's gkwrap opens nothing (review F3). The successor
        // can be re-added to groups by an admin.
        crate::vault::groups::prune_member(&self.path, self.unlocked().sgk()?, &member_id)?;
        // S3-7a: the successor row re-joins with a fresh identity, so the
        // stale identity-keyed wrap is dead mail. Best-effort (the 7b
        // gate counts it via status; prepare re-mints on the new card).
        let _ = crate::vault::space_meta::remove_space_wrap(&self.path, &member_id);
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::MemberReset,
            format!("member reset; re-join with the new invite (successor {successor})"),
        );
        Ok((successor, code))
    }

    /// S1a-6: member removal + offboarding (§4.2, scenario J; the
    /// boundary S1a-5 documented). Admin-only batch: tombstones each
    /// member row (terminal, entries preserved), strikes their devices
    /// from the registry, deletes their keywraps and activity entries,
    /// then rotates the Root Key once — survivors are re-keyed via the
    /// P3 keywrap staging, the removed devices' wrapped copies die.
    /// Pre-flight refusals: locked vault, non-admin actor, owner rows,
    /// the actor's own member, unknown or already-tombstoned rows.
    /// Provider seat removal is confirmed separately (S1b collaborator
    /// ops) — this call is repo-side only.
    /// P8c-2: the removal pre-flight — authorization, batch validation,
    /// and the transport seats to strike. Single source of truth: called
    /// by member_remove (authoritative) and by the daemon route BEFORE
    /// its provider strikes, so seat operations can never run for an
    /// unauthorized caller or an invalid batch.
    pub fn member_remove_precheck(
        &self,
        member_ids: &[uuid::Uuid],
    ) -> Result<Vec<String>, BaluardError> {
        self.member_remove_precheck_inner(member_ids, true)
    }

    fn member_remove_precheck_inner(
        &self,
        member_ids: &[uuid::Uuid],
        check_quorum: bool,
    ) -> Result<Vec<String>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        if member_ids.is_empty() {
            return Err(VaultError::InvalidOperation(
                "member_remove needs at least one member".into(),
            )
            .into());
        }
        // Quorum first: a refusal must land BEFORE any seat strike.
        // check_quorum is false ONLY for member_remove's internal
        // re-validation — the approval was already consumed by the
        // caller's precheck, and re-entering the gate here would raise
        // a fresh ask after the seats were struck.
        if check_quorum {
            // Digest over the SORTED ids: two admins listing the same
            // batch in different orders must approve the same ask.
            let mut sorted = member_ids.to_vec();
            sorted.sort();
            let params = serde_json::json!({ "member_ids": sorted });
            self.quorum_gate("member_remove", &params)?;
            // Mark the chain: member_remove's internal re-validation
            // must not re-enter the gate (the approval is consumed).
            *self.quorum_satisfied.lock().expect("quorum flag") = Some((
                "member_remove".to_string(),
                crate::vault::approvals::op_digest("member_remove", &params),
            ));
        }
        self.assert_can_manage_members()?;
        let actor_member = crate::vault::members::member_id_for_device(&self.path, self.device_id);

        // S1a-6 review: the offboarding rotation's own preconditions are
        // checked HERE, before any row/seam mutation — otherwise a
        // rotation failure would strand tombstoned rows + deleted
        // keywraps with the Root Key unrotated, and a retry would be
        // refused as "already tombstoned".
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt(
                "rotation in progress, use finalize_rotation()".into(),
            )
            .into());
        }
        {
            let seal_key = self.devkey_seal();
            load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())?;
        }
        let mut seen = std::collections::BTreeSet::new();
        // P8c: transport seats to strike at the provider BEFORE the
        // rotation push (collected during pre-flight row reads).
        let mut transport_usernames: Vec<String> = Vec::new();
        for id in member_ids {
            if !seen.insert(*id) {
                return Err(VaultError::InvalidOperation(
                    "duplicate member in removal batch".into(),
                )
                .into());
            }
            if actor_member == Some(*id) {
                return Err(VaultError::InvalidOperation(
                    "removing your own member row would lock you out".into(),
                )
                .into());
            }
            let Some(row) = crate::vault::members::member_file_by_id(&self.path, *id) else {
                return Err(VaultError::InvalidOperation(format!("member {id} not found")).into());
            };
            if row.role == crate::vault::members::MemberRole::Owner {
                return Err(VaultError::InvalidOperation(
                    "the owner row cannot be removed (transfer ownership first)".into(),
                )
                .into());
            }
            if row.reset.is_some() || row.removed.is_some() {
                return Err(VaultError::InvalidOperation(format!(
                    "member {id} is already tombstoned"
                ))
                .into());
            }
            // P8c: remember the transport seat so the caller can strike it
            // at the provider BEFORE pushing the rotation.
            if let Some(username) = row
                .transport_username
                .as_deref()
                .filter(|u| !u.trim().is_empty())
            {
                transport_usernames.push(username.to_string());
            }
        }
        Ok(transport_usernames)
    }

    pub fn member_remove(
        &mut self,
        member_ids: &[uuid::Uuid],
    ) -> Result<MemberRemovalReport, BaluardError> {
        // Quorum: satisfied when THIS handle's precheck already consumed
        // the approval (the strike-ordering chain); a direct core caller
        // without that chain gates here. Either way exactly one gate.
        {
            let mut sorted = member_ids.to_vec();
            sorted.sort();
            let digest = crate::vault::approvals::op_digest(
                "member_remove",
                &serde_json::json!({ "member_ids": sorted }),
            );
            if self.quorum_satisfied.lock().expect("quorum flag").as_ref()
                == Some(&("member_remove".to_string(), digest.clone()))
            {
                *self.quorum_satisfied.lock().expect("quorum flag") = None;
            } else {
                self.quorum_gate(
                    "member_remove",
                    &serde_json::json!({ "member_ids": sorted }),
                )?;
            }
        }
        // P8c-2: the pre-flight is the single source of truth for removal
        // authorization + validation, and it returns the transport seats
        // to strike. The daemon route calls THIS SAME fn before its
        // provider strikes, so seat ops can never run for an
        // unauthorized caller or an invalid batch.
        let transport_usernames = self.member_remove_precheck_inner(member_ids, false)?;

        // ── Offboard: tombstone rows, strike seats, rotate once ──
        let mut removed_members = Vec::new();
        let mut removed_devices_set = std::collections::BTreeSet::new();
        // S1a-6 review: prune the ENCRYPTED activity index (not just the
        // legacy plaintext) — DeviceActivityIndex::remove_device would
        // otherwise create an empty plaintext file that shadows the real
        // activity.enc history on the next load.
        let mut activity = self.load_activity_enc()?;
        for id in member_ids {
            let devices = crate::vault::members::remove_member(&self.path, *id)?;
            removed_members.push(*id);
            // S4-2 (review F3): group memberships die with the removal —
            // each affected group's GK rotates while the CURRENT SGK is
            // still held, so the removed member's gkwrap opens nothing
            // going forward.
            crate::vault::groups::prune_member(&self.path, self.unlocked().sgk()?, id)?;
            // S3-7a: the removed member's identity-keyed wrap dies with
            // the tombstone (same semantics as the collection wraps).
            let _ = crate::vault::space_meta::remove_space_wrap(&self.path, id);
            for device in devices {
                if device == self.device_id {
                    continue; // defense in depth: the actor's own seat stays
                }
                let _ = self.device_manager.registry.revoke(device);
                activity.devices.remove(&device.to_string());
                let _ = std::fs::remove_file(self.path.join(format!("meta/keywrap/{device}.json")));
                removed_devices_set.insert(device);
            }
        }
        self.save_activity_enc(&activity)?;
        self.sync_registry_from_device_manager();
        self.device_manager.auto_save_result()?;
        self.rotate_root_key_internal()?;
        // S3-7a (review F4): the removed member knew the SMK, so retire
        // it under the fresh root. Best-effort in this additive slice
        // (nothing is SMK-encrypted yet); status surfaces any gap and
        // the 7b flip makes this authoritative.
        if crate::vault::space_meta::status(&self.path, self.unlocked().root()?)
            .map(|s| s.prepared)
            .unwrap_or(false)
        {
            // Crash recovery: record the OUTGOING SMK before the store
            // flips, so a crash between the rotation and the meta re-seal
            // converges at the next admin unlock. Local-only, gitignored,
            // carries the retired key until the re-seal is confirmed.
            if let Some(old_smk) = self.unlocked().smk.clone() {
                let _ = crate::vault::space_meta::write_smk_pending(&self.path, &old_smk);
            }
            if let Ok((_, new_smk)) =
                crate::vault::space_meta::rotate(&self.path, self.unlocked().root()?)
            {
                if self.reseal_meta_after_smk_rotate(new_smk) {
                    crate::vault::space_meta::clear_smk_pending(&self.path);
                }
            }
        }
        let new_epoch = match &self.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::MemberRemoved,
            format!(
                "removed {} member(s); {} device seat(s) struck; vault re-keyed",
                removed_members.len(),
                removed_devices_set.len()
            ),
        );
        Ok(MemberRemovalReport {
            removed_members,
            removed_devices: removed_devices_set.into_iter().collect(),
            new_epoch,
            transport_usernames,
        })
    }

    /// S1a-7: ownership transfer (§4.2, first-class action). Owner-only:
    /// the actor's member row must carry the Owner role (disk-backed).
    /// Demotes the old owner to Admin, promotes the successor to Owner
    /// with SelfTrust; exactly one Owner row once the commit lands.
    /// Provider repo transfer + adopt semantics stay with the provider
    /// layer (S1b collaborator ops) — this is the vault-side role
    /// change.
    pub fn transfer_ownership(&mut self, new_member_id: uuid::Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        // S1a-7 review: gate on the ACTOR'S OWN role (disk-backed), not
        // on owner_member_id equality — in the abnormal two-owner state
        // (crash between the transfer's two writes) owner_member_id
        // resolves arbitrarily, and an equality gate would strand the
        // recovery. An owner-role actor can always re-run the transfer,
        // which demotes the extra owner.
        let actor_role = crate::vault::members::member_role_for_device(&self.path, self.device_id);
        if actor_role != Some(crate::vault::members::MemberRole::Owner)
            && actor_role != Some(crate::vault::members::MemberRole::Admin)
        {
            return Err(VaultError::InvalidOperation(
                "only the owner can transfer ownership".into(),
            )
            .into());
        }
        let Some(old_member_id) = crate::vault::members::owner_member_id(&self.path) else {
            return Err(
                VaultError::InvalidOperation("this vault has no owner member row".into()).into(),
            );
        };
        // The ask's digest binds BOTH ids: a changed owner means a
        // different digest, so a stale ask can never execute against a
        // new owner (the claim's rule).
        let params = serde_json::json!({
            "new_member_id": new_member_id,
            "old_owner_id": old_member_id,
        });
        if actor_role == Some(crate::vault::members::MemberRole::Owner) {
            // Initiator path: the owner consents by calling. Wave-39
            // rule (deterministic refusals precede the gate): a
            // self-transfer or a nonexistent/tombstoned successor must
            // fail outright, never record a pending ask that can never
            // execute and burn a co-approval. Mirrors ownership_claim's
            // pre-flight.
            if new_member_id == old_member_id {
                return Err(
                    VaultError::InvalidOperation("you already own this vault".into()).into(),
                );
            }
            let target = crate::vault::members::member_file_by_id(&self.path, new_member_id)
                .ok_or_else(|| {
                    VaultError::InvalidOperation("that member row does not exist".into())
                })?;
            if target.reset.is_some() || target.removed.is_some() {
                return Err(VaultError::InvalidOperation(
                    "that member row is gone; ownership cannot be transferred to it".into(),
                )
                .into());
            }
            // A fresh ask supersedes the owner's earlier transfer asks
            // (a new target invalidates the old one).
            crate::vault::approvals::consume_other_of_kind(
                &self.path,
                "transfer_ownership",
                &crate::vault::approvals::op_digest("transfer_ownership", &params),
            );
            self.quorum_gate("transfer_ownership", &params)?;
        } else {
            // Confirmer path (review round): the house quorum pattern is
            // re-call-to-confirm, so at a raised threshold an ADMIN must
            // be able to complete the owner's ask. An admin can only
            // confirm a pending owner-initiated ask — never start one,
            // because a voluntary transfer's consent IS the owner's
            // call. Deterministic target checks precede the gate here
            // too, so a dead target cannot burn the co-approval; the
            // digest binds the owner of record, so a swapped owner
            // makes the ask unmatchable.
            let target = crate::vault::members::member_file_by_id(&self.path, new_member_id)
                .ok_or_else(|| {
                    VaultError::InvalidOperation("that member row does not exist".into())
                })?;
            if target.reset.is_some() || target.removed.is_some() {
                return Err(VaultError::InvalidOperation(
                    "that member row is gone; ownership cannot be transferred to it".into(),
                )
                .into());
            }
            let digest = crate::vault::approvals::op_digest("transfer_ownership", &params);
            let matching = crate::vault::approvals::list_pending(&self.path)
                .iter()
                .any(|p| p.kind == "transfer_ownership" && p.params_digest == digest);
            if !matching {
                return Err(VaultError::InvalidOperation(
                    "no pending ownership transfer to confirm; the owner starts a transfer, then an admin confirms it"
                        .into(),
                )
                .into());
            }
            self.quorum_gate("transfer_ownership", &params)?;
        }
        let demoted = old_member_id;
        crate::vault::members::commit_ownership_swap(&self.path, old_member_id, new_member_id)?;
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::OwnershipTransferred,
            format!("ownership transferred (member {demoted} is now admin)"),
        );
        Ok(())
    }

    /// §13: an admin claims ownership when the Owner cannot act
    /// (incapacitated, gone, or lost device AND recovery phrase). The
    /// voluntary transfer gate stays untouched; this op is its own
    /// gated entry so peers approving the ask see exactly what they
    /// approve. The quorum gate binds BOTH member ids, so an ask
    /// recorded against one owner can never execute against another.
    /// `new_owner_id` is explicit (the house re-call-to-confirm
    /// pattern): the co-approver repeats the SAME ask, so the params
    /// must not depend on who calls.
    pub fn ownership_claim(&mut self, new_owner_id: uuid::Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let actor_role = crate::vault::members::member_role_for_device(&self.path, self.device_id);
        if actor_role != Some(crate::vault::members::MemberRole::Admin) {
            return Err(
                VaultError::InvalidOperation("only an admin can claim ownership".into()).into(),
            );
        }
        let Some(old_member_id) = crate::vault::members::owner_member_id(&self.path) else {
            return Err(
                VaultError::InvalidOperation("this vault has no owner member row".into()).into(),
            );
        };
        if old_member_id == new_owner_id {
            return Err(VaultError::InvalidOperation("you already own this vault".into()).into());
        }
        // Review F6: pre-flight the target row BEFORE the gate — a
        // nonexistent or tombstoned claimant would otherwise burn real
        // approvals on an ask that can never execute.
        let target = crate::vault::members::member_file_by_id(&self.path, new_owner_id)
            .ok_or_else(|| VaultError::InvalidOperation("that member row does not exist".into()))?;
        if target.reset.is_some() || target.removed.is_some() {
            return Err(VaultError::InvalidOperation(
                "that member row is gone; ownership cannot be claimed for it".into(),
            )
            .into());
        }
        self.quorum_gate(
            "ownership_claim",
            &serde_json::json!({
                "new_owner_id": new_owner_id,
                "old_owner_id": old_member_id,
            }),
        )?;
        crate::vault::members::commit_ownership_swap(&self.path, old_member_id, new_owner_id)?;
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::OwnershipClaimed,
            format!("ownership claimed from member {old_member_id}"),
        );
        Ok(())
    }

    /// S1a-8: stage a received introduction into the repo-backed join
    /// queue (meta/requests/). The admin received the intro code
    /// out-of-band; staging makes the handoff listable, deniable, and
    /// auditable. Admin-gated.
    pub fn join_queue_submit(&mut self, intro_code: &str) -> Result<uuid::Uuid, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let intro = crate::vault::members::Introduction::decode(intro_code)?;
        if intro.vault_id != self.vault_id {
            return Err(VaultError::InvalidOperation(
                "introduction is for a different vault".into(),
            )
            .into());
        }
        crate::vault::members::submit_request(&self.path, &intro)
    }

    /// S1a-8: list queued join requests. Returns the well-shaped
    /// requests (secret state included) plus a count of malformed files
    /// (skipped, inert until denied). Admin-gated.
    pub fn join_queue_list(
        &self,
    ) -> Result<(Vec<crate::vault::members::JoinRequest>, usize), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::members::list_requests(&self.path)
    }

    /// S1a-8: approve a queued request through the STANDARD approval
    /// path (all verification — secret, elevated-role dial gate,
    /// identity binding — happens there). The request file is consumed
    /// only on success: a refused approval stays queued for retry.
    pub fn approve_queued_join(&mut self, req_id: uuid::Uuid) -> Result<Uuid, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let intro = crate::vault::members::read_request(&self.path, req_id)?;
        let code = intro.encode()?;
        let member_id = self.approve_join(&code)?;
        crate::vault::members::consume_request(&self.path, req_id)?;
        Ok(member_id)
    }

    /// S1a-8: deny (drop) a queued request. Admin-gated.
    pub fn deny_queued_join(&mut self, req_id: uuid::Uuid) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        crate::vault::members::consume_request(&self.path, req_id)
    }

    /// S1a-2: approve a joiner's introduction (owner side, unlocked).
    /// Verifies the code against the repo-side pending invite, enrolls
    /// the joiner's device, wraps the Root Key to the joiner's device
    /// key (P3-style keywrap), and writes the member record + binding
    /// with the invite's role. The artifacts reach the joiner through
    /// the normal sync cycle; the joiner unlocks with their own password
    /// via their device-local member unlock material.
    pub fn approve_join(&mut self, intro_code: &str) -> Result<Uuid, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let intro = crate::vault::members::Introduction::decode(intro_code)?;
        // S1a-8 review: newline discipline applies at APPROVAL too, not
        // just staging — the display name lands in the member record and
        // later newline-delimited payloads.
        if intro.display_name.contains(['\n', '\r']) {
            return Err(VaultError::InvalidOperation(
                "introduction display name contains newlines".into(),
            )
            .into());
        }
        if intro.vault_id != self.vault_id {
            return Err(VaultError::InvalidOperation(
                "introduction is for a different vault".into(),
            )
            .into());
        }
        // Trust dial (S1a-3): peek the invite role BEFORE consuming — a
        // failed gate leaves the invite intact for retry after the code
        // check. Roles above Editor require the joiner's contact card to
        // be Verified in the address book (Level 2 code check);
        // Editor/Viewer invites need no card.
        let invite = crate::vault::members::read_pending_invite(&self.path, intro.invite_id)?;
        // S1a-7 review: Owner invites are unmintable — refuse any that
        // predate that rule (defense in depth at approval too).
        if invite.role == crate::vault::members::MemberRole::Owner {
            return Err(VaultError::InvalidOperation(
                "ownership cannot be invited; use transfer_ownership".into(),
            )
            .into());
        }
        // S1a-5: reset invites gate on the SUCCESSOR row's role, not the
        // invite's — a stale or tampered invite must not downgrade the
        // gate below what the admin-fixed row carries.
        let target_row_role = invite
            .target_member
            .and_then(|t| crate::vault::members::member_file_by_id(&self.path, t))
            .map(|row| row.role);
        let effective_role = target_row_role.unwrap_or(invite.role);
        // S2 IS-5: the pair policy also holds at approval — an invite
        // minted before the shape was set, or a second member binding
        // mid-ceremony, must not breach the cap here. Reset approvals
        // pass: the successor row is unbound, so the cap counts only
        // joined members.
        crate::vault::space::pair_gate(&self.path, effective_role)?;
        // S3-4 review: an invite's embedded grants are bounded at mint
        // (MAX_GRANTS_PER_TEMPLATE). More than that in a git-synced
        // invite file means tampering — and the approval loop would run
        // an unbounded number of encrypt+wrap operations under the
        // vault lock. Refuse BEFORE any mutation so the invite and the
        // queue entry stay intact.
        if let Some(template) = &invite.template {
            if template.grants.len() > crate::vault::templates::MAX_GRANTS_PER_TEMPLATE {
                return Err(
                    VaultError::InvalidOperation("This invite is not valid.".into()).into(),
                );
            }
        }
        // S1a-5: an invite whose role disagrees with the admin-fixed
        // successor row is stale or tampered — refuse BEFORE consuming
        // so the invite survives for the admin to correct.
        if let Some(row_role) = target_row_role {
            if invite.role != row_role {
                return Err(VaultError::InvalidOperation(
                    "reset invite role does not match the successor row".into(),
                )
                .into());
            }
        }
        // S1a-8 review: ALL read-only validation happens in the peek
        // phase — the successor row's health (a reset invite whose
        // target vanished, is tombstoned, or is already joined must not
        // burn the invite) and the introduced key hex (parse failures
        // must not strand a half-approval). Mutations start at consume.
        if let Some(target) = invite.target_member {
            let row =
                crate::vault::members::member_file_by_id(&self.path, target).ok_or_else(|| {
                    VaultError::InvalidOperation(
                        "reset invite names a successor row that does not exist".into(),
                    )
                })?;
            if row.reset.is_some() || row.removed.is_some() {
                return Err(VaultError::InvalidOperation(
                    "reset invite names a tombstoned row".into(),
                )
                .into());
            }
            if row.identity_signing_pubkey.is_some() {
                return Err(VaultError::InvalidOperation(
                    "successor row already joined; issue a new reset".into(),
                )
                .into());
            }
        }
        let enc_bytes: [u8; 32] = hex::decode(&intro.encryption_public_key)
            .map_err(|_| VaultError::Corrupt("intro encryption key".into()))?
            .try_into()
            .map_err(|_| VaultError::Corrupt("intro encryption key length".into()))?;
        let sig_bytes: [u8; 32] = hex::decode(&intro.signing_public_key)
            .map_err(|_| VaultError::Corrupt("intro signing key".into()))?
            .try_into()
            .map_err(|_| VaultError::Corrupt("intro signing key length".into()))?;
        let elevated = matches!(
            effective_role,
            crate::vault::members::MemberRole::Admin | crate::vault::members::MemberRole::Owner
        );
        if elevated {
            let Some(card) = intro.contact_card.as_ref() else {
                return Err(VaultError::InvalidOperation(
                    "elevated roles require the joiner's contact card".into(),
                )
                .into());
            };
            card.verify()?;
            // The card alone proves nothing about the DEVICE claiming the
            // role: the introduction must be signed by the card's
            // identity key over the device-key payload, binding the two.
            let Some(identity_sig) = intro.identity_signature.as_ref() else {
                return Err(VaultError::InvalidOperation(
                    "elevated roles require an identity-signed introduction".into(),
                )
                .into());
            };
            let payload = crate::vault::members::Introduction::identity_sign_payload(
                intro.invite_id,
                intro.device_id,
                &intro.encryption_public_key,
                &intro.signing_public_key,
                &card.card.identity_signing_pubkey,
            );
            let vk_bytes: [u8; 32] = hex::decode(&card.card.identity_signing_pubkey)
                .map_err(|_| VaultError::Corrupt("contact pubkey hex".into()))?
                .try_into()
                .map_err(|_| VaultError::Corrupt("contact pubkey length".into()))?;
            let vk = signature::verifying_key_from_bytes(&vk_bytes)
                .map_err(|_| VaultError::Corrupt("contact pubkey invalid".into()))?;
            let sig_bytes = hex::decode(identity_sig)
                .map_err(|_| VaultError::Corrupt("identity signature hex".into()))?;
            let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
                .map_err(|_| VaultError::Corrupt("identity signature length".into()))?;
            signature::verify(&vk, &payload, &sig).map_err(|_| {
                VaultError::InvalidOperation(
                    "introduction identity signature does not match the contact card".into(),
                )
            })?;
            let key = self.contacts_key()?;
            match crate::vault::contacts::contact_trust(
                &self.path,
                &key,
                &card.card.identity_signing_pubkey,
            ) {
                Some(crate::vault::contacts::ContactTrust::Verified) => {}
                _ => {
                    return Err(VaultError::InvalidOperation(
                        "elevated roles require a verified contact (run the Level 2 code check first)"
                            .into(),
                    )
                    .into());
                }
            }
        }
        let invite = crate::vault::members::consume_pending_invite(
            &self.path,
            intro.invite_id,
            &intro.secret,
        )?;

        // Enroll the joiner's device: the registry gates signatures, the
        // member record gates roles. (Key hex was parsed in the peek
        // phase — S1a-8 review.)
        self.device_manager.registry.enroll_with_id(
            intro.device_id,
            intro.display_name.clone(),
            enc_bytes,
            sig_bytes,
            Some(self.device_id),
        )?;
        self.sync_registry_from_device_manager();
        self.device_manager.auto_save_result()?;

        // Wrap the Root Key to the joiner's device key (their transport
        // seat: read until the approval ships this keywrap).
        // S3-7b: skipped for non-admin joiners on team-shape vaults —
        // their unlock path is identity seed + space.wrap (minted
        // below); the Root Key must never reach a member device.
        // F9: an elevated joiner (Owner/Admin) on a flipped vault takes
        // the admin unlock path, so they DO get the keywrap — the flip
        // keeps keys from members, not from admins. The keywrap and the
        // member row ship in the same approval commit, so a crash before
        // the commit strands nothing (the intro stays pending).
        let flipped = crate::vault::space_meta::shape_flipped(&self.path);
        if !flipped || elevated {
            let root = self.unlocked().root()?;
            let recipient = x25519_dalek::PublicKey::from(enc_bytes);
            let (eph, ct, tag) =
                hpke_wrap::wrap_key(root.as_bytes(), &recipient, "root-key-keywrap")?;
            let keywrap = serde_json::json!({
                "device_id": intro.device_id.to_string(),
                "ephemeral_public": hex::encode(eph),
                "encrypted_key": hex::encode(ct),
                "tag": hex::encode(tag),
            });
            super::write_vault_file(
                &self
                    .path
                    .join(format!("meta/keywrap/{}.json", intro.device_id)),
                serde_json::to_string_pretty(&keywrap).unwrap().as_bytes(),
            )?;
        }

        // Member record + binding, admin-authored, role from the invite.
        // Approval IS the trust act (Level 3 replaces the code check).
        // The joiner's contact card pubkey is recorded as their identity
        // signing key (S1a-4: rotation visibility keys off this field).
        // S1a-5 reset invites bind the EXISTING successor row: display
        // name and role are admin-fixed at reset time (the introduction
        // cannot rename the member), the fresh identity comes from the
        // introduction's card, and trust stays at Channel — the reset
        // dial state until re-verification (elevated roles re-verified
        // at the gate above).
        let identity_pub = intro
            .contact_card
            .as_ref()
            .map(|c| c.card.identity_signing_pubkey.clone());
        // P1: the X25519 wrap pubkey rides the signed v2 card payload.
        // Verify the card before recording either key — a forged card
        // must not seed the member's wrap identity (fail-closed).
        let identity_wrap = match intro.contact_card.as_ref() {
            Some(card) => {
                card.verify()?;
                let wrap = card.card.identity_wrap_pubkey.trim();
                if wrap.is_empty() {
                    None
                } else {
                    // A malformed wrap pubkey would brick every later
                    // collection re-key; refuse the card here.
                    crate::vault::collections::wrap_pubkey_bytes(wrap)?;
                    Some(wrap.to_string())
                }
            }
            None => None,
        };
        let member = if let Some(target) = invite.target_member {
            // Successor-row health was validated in the peek phase
            // (S1a-8 review) — refusal there leaves the invite
            // retryable. Here: only the writes.
            let mut row =
                crate::vault::members::member_file_by_id(&self.path, target).ok_or_else(|| {
                    VaultError::InvalidOperation(
                        "reset invite names a successor row that does not exist".into(),
                    )
                })?;
            if elevated {
                row.trust = crate::vault::members::TrustLevel::Verified;
            }
            row.identity_signing_pubkey = identity_pub;
            row.identity_signing_pubkey_previous = None;
            row.identity_rotation_signature = None;
            row.identity_rotated_at = None;
            row.identity_wrap_pubkey = identity_wrap;
            let path = self
                .path
                .join(crate::vault::members::MEMBERS_DIR)
                .join(format!("{}.json", row.id));
            super::write_vault_file(
                &path,
                serde_json::to_string_pretty(&row).unwrap().as_bytes(),
            )
            .map_err(|e| {
                BaluardError::from(VaultError::Metadata(format!("write successor: {e}")))
            })?;
            row
        } else {
            let member = crate::vault::members::MemberFile {
                id: uuid::Uuid::new_v4(),
                display_name: intro.display_name.clone(),
                email: intro.email.clone(),
                role: invite.role,
                trust: crate::vault::members::TrustLevel::Verified,
                identity_signing_pubkey: identity_pub,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                // P8c: the seat rides the record so offboarding can strike
                // it without asking anyone.
                transport_username: invite.transport_username.clone(),
                identity_wrap_pubkey: identity_wrap,
            };
            crate::vault::members::write_member(&self.path, &member)?;
            member
        };
        crate::vault::members::write_device_binding(
            &self.path,
            &crate::vault::members::DeviceBinding {
                device_id: intro.device_id,
                member_id: member.id,
            },
        )?;
        // S3-7a: mint the member's space meta wrap when an SMK store
        // already exists (best-effort: prepare re-runs close any gap, so
        // a store failure must not fail the approval).
        if let Some(wrap_hex) = member.identity_wrap_pubkey.as_deref() {
            if let Ok(smk) =
                crate::vault::space_meta::open_store(&self.path, self.unlocked().root()?)
            {
                // Best-effort by design: the store exists but a wrap
                // write failing must not fail the approval. status()
                // counts the gap and prepare closes it.
                let _ = crate::vault::space_meta::write_space_wrap(
                    &self.path, &member.id, wrap_hex, &smk,
                );
            }
        }
        // S3-4: apply the invite's embedded template grants. The invite
        // is the contract (resolved at mint time), so a template
        // deleted after minting changes nothing here. A collection that
        // no longer exists is skipped inert — a grant must fail toward
        // no access, never wedge the approval. Grants are applied AFTER
        // the member row landed, so each grant mints the per-member
        // key wrap (P1 groundwork) for the new member immediately.
        if let Some(template) = &invite.template {
            for spec in &template.grants {
                let collection_id = spec.collection_id;
                let expires_at = spec
                    .expires_in_days
                    .map(|days| crate::vault::templates::now_secs() + u64::from(days) * 86_400);
                let grant = crate::vault::collections::CollectionGrant {
                    target: crate::vault::collections::GrantTarget::Member { id: member.id },
                    access: spec.access,
                    expires_at,
                };
                if let Err(e) = crate::vault::collections::upsert_grant(
                    &self.path,
                    self.unlocked().sgk()?,
                    &collection_id,
                    grant,
                ) {
                    eprintln!("warning: template grant skipped: {e}");
                }
            }
        }
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::MemberJoined,
            format!(
                "member \"{}\" joined as {}",
                member.display_name,
                match member.role {
                    crate::vault::members::MemberRole::Owner => "owner",
                    crate::vault::members::MemberRole::Admin => "admin",
                    crate::vault::members::MemberRole::Editor => "editor",
                    crate::vault::members::MemberRole::Viewer => "viewer",
                }
            ),
        );
        Ok(member.id)
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<(), BaluardError> {
        // Step 0: Rate limit check
        self.check_attempt_rate_limit()?;

        // S1a-2: member devices unlock with their own password material
        // (device-local meta/member-unlock.json); the vault-level KDF
        // params and kek-canary belong to the founding device's password.
        if let Some(member) = crate::vault::members::load_member_unlock(&self.path, self.device_id)?
        {
            let kek = kdf::derive_kek(master_password, &member.kdf_params)?;
            let canary = hex::decode(&member.kek_canary)
                .map_err(|_| VaultError::Corrupt("member canary".into()))?;
            let devkey_seal_m = Zeroizing::new(hkdf_derive::derive_devkey_seal_key(&kek)?);
            // Failed attempts record against the same counter as the
            // master-password path: brute-force protection applies to
            // member passwords too.
            let result = self.unlock_with_member_canary(&kek, canary);
            if result.is_ok() {
                self.clear_failed_attempts()?;
                // S1a-4: member devices can rotate their identity too —
                // expose the wrap key to rotate_identity.
                if let VaultState::Unlocked(u) = &mut self.state {
                    u.identity_wrap_key = Some(devkey_seal_m.clone());
                }
                // S1a-3: open the member's own identity (sealed under
                // their devkey seal) into the unlocked state so
                // contact-card signing works on member devices too.
                if let Some(sealed_hex) = member.identity_seed_sealed.as_deref() {
                    if let Ok(sealed) = hex::decode(sealed_hex) {
                        match crate::vault::identity::open_identity(&devkey_seal_m, &sealed) {
                            Ok(keys) => self.unlocked_mut().identity = Some(keys),
                            // Non-fatal: unlock succeeds; contact-card
                            // signing is unavailable until the identity
                            // is restored.
                            Err(e) => eprintln!("warning: could not restore member identity: {e}"),
                        }
                    }
                }
                return Ok(());
            }
            let _ = self.record_failed_attempt();
            return Err(result.err().unwrap());
        }

        // Step 1: Derive KEK (expensive Argon2id)
        let kek = kdf::derive_kek(master_password, &self.kdf_params)?;

        // Steps 2-8: shared unlock tail. For the master-password path a
        // failed canary/keywrap verification MUST record a failed attempt so
        // the on-disk attempt counter advances (brute-force protection).
        match self.unlock_with_kek(&kek) {
            Ok(()) => {
                self.clear_failed_attempts()?;
                // P1a: the master password is available only on THIS path —
                // use it for the warned passphrase-fallback identity seal
                // (keystore mode already cached inside unlock_with_kek).
                self.load_identity_cache(Some(master_password));
                Ok(())
            }
            Err(e) => {
                let _ = self.record_failed_attempt();
                Err(e)
            }
        }
    }

    /// P1a: load the cached identity from `meta/identity.enc`.
    ///
    /// Sealing-key resolution by mode (from `meta/identity-meta.json`):
    /// - keystore: the wrapping key lives in the OS keystore — loads with or
    ///   without a password.
    /// - passphrase: Argon2id over the master password with the dedicated
    ///   identity salt — requires `master_password` (None on the PIN/quick
    ///   unlock path: identity stays sealed until a full unlock; WARNED
    ///   downgrade mode, see the module docs in vault/identity.rs).
    ///
    /// Failures are logged, never fatal: the identity is optional for every
    /// pre-Space feature, and a corrupt identity must not block vault use.
    fn load_identity_cache(&mut self, master_password: Option<&str>) {
        let meta_path = self.path.join("meta/identity-meta.json");
        let Ok(data) = std::fs::read_to_string(&meta_path) else {
            return; // pre-P1a vault: no identity
        };
        let Ok(meta) = serde_json::from_str::<serde_json::Value>(&data) else {
            eprintln!("warning: meta/identity-meta.json is corrupt; identity unavailable");
            return;
        };
        let mode = meta["mode"].as_str().unwrap_or("");

        let wrap_key: Option<zeroize::Zeroizing<[u8; 32]>> = match mode {
            "keystore" => {
                let key_name = meta["keystore_key"].as_str().unwrap_or("");
                let keystore = crate::vault::creation::get_global_keystore();
                let bytes = keystore.and_then(|ks| ks.get_secret(key_name).ok());
                bytes
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .map(zeroize::Zeroizing::new)
            }
            "passphrase" => {
                let Some(pw) = master_password else {
                    return; // quick-unlock path: identity stays sealed
                };
                let salt = meta["salt_hex"]
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .unwrap_or_default();
                let params = crate::types::KdfParams {
                    profile: crate::types::KdfProfile::MobileLow,
                    memory_kib: meta["memory_kib"].as_u64().unwrap_or(8192) as u32,
                    time_cost: meta["time_cost"].as_u64().unwrap_or(3) as u32,
                    parallelism: 1,
                    salt,
                };
                kdf::derive_kek(pw, &params)
                    .ok()
                    .map(zeroize::Zeroizing::new)
            }
            _ => None,
        };
        let Some(wrap_key) = wrap_key else {
            return;
        };

        // S1a-4: prefer the member-scoped sealed identity when this device
        // is a bound member — identity rotation writes there; the legacy
        // meta/identity.enc path remains for founder/legacy vaults.
        let sealed = match crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .map(|m| {
                self.path
                    .join(crate::vault::members::MEMBERS_DIR)
                    .join(m.to_string())
                    .join("identity.enc")
            }) {
            Some(p) if p.exists() => std::fs::read(&p).ok(),
            _ => std::fs::read(self.path.join("meta/identity.enc")).ok(),
        };
        let Some(sealed) = sealed else {
            return;
        };
        match crate::vault::identity::open_identity(&wrap_key, &sealed) {
            Ok(keys) => {
                if let VaultState::Unlocked(u) = &mut self.state {
                    u.identity = Some(keys);
                    u.identity_wrap_key = Some(wrap_key);
                }
            }
            Err(e) => {
                eprintln!("warning: failed to open sealed identity: {e}");
            }
        }
    }

    /// P1a: the cached identity (`None` until loaded — see
    /// `load_identity_cache`). Consumers in S1a+ (contact cards, Space
    /// keywraps) treat `None` as "identity unavailable on this device".
    pub fn identity(&self) -> Option<&crate::vault::identity::IdentityKeys> {
        match &self.state {
            VaultState::Unlocked(u) => u.identity.as_ref(),
            VaultState::Locked => None,
        }
    }

    /// P1a routine identity rotation: generate a new keypair, re-seal under
    /// the same wrapping key, re-escrow under the recovery pubkey (read from
    /// `meta/identity-meta.json` — the phrase itself is not needed). The old
    /// keys drop (zeroized by their own Drop impls). Compromise-path
    /// rotation (admin re-wrap + Space notice) lands with S1a.
    pub fn rotate_identity(&mut self) -> Result<(), BaluardError> {
        let (wrap_key, recovery_pub_hex) = {
            let meta_path = self.path.join("meta/identity-meta.json");
            let data = std::fs::read_to_string(&meta_path)
                .map_err(|e| VaultError::Metadata(format!("reading identity meta: {e}")))?;
            let meta: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("parse identity meta: {e}")))?;
            let recovery_pub_hex = meta["recovery_pubkey_hex"]
                .as_str()
                .ok_or_else(|| {
                    VaultError::Metadata("identity meta missing recovery pubkey".into())
                })?
                .to_string();
            let wrap_key = match &self.state {
                VaultState::Unlocked(u) => u.identity_wrap_key.clone(),
                VaultState::Locked => None,
            }
            .ok_or_else(|| {
                VaultError::Metadata(
                    "identity wrap key unavailable; full master-password unlock required".into(),
                )
            })?;
            (wrap_key, recovery_pub_hex)
        };

        // S1a-4: member devices store identity artifacts member-scoped
        // (meta/members/<m>/), never in the synced meta/ root (meta/**
        // is admin-only and identity artifacts are per-member state).
        // Founder/legacy devices keep the meta/ paths.
        let member_scoped = crate::vault::members::member_id_for_device(&self.path, self.device_id);
        // S1a-5/S1a-6: a tombstoned member (reset OR removal) cannot
        // rotate — the row is dead (their commits are refused at
        // verification anyway).
        if let Some(m) = member_scoped {
            let tombstoned = crate::vault::members::member_file_by_id(&self.path, m)
                .map(|row| row.reset.is_some() || row.removed.is_some())
                .unwrap_or(false);
            if tombstoned {
                return Err(VaultError::InvalidOperation(
                    "this member row is tombstoned; re-join with the admin's new invite".into(),
                )
                .into());
            }
        }
        let identity_path = match member_scoped {
            Some(m) => self
                .path
                .join(crate::vault::members::MEMBERS_DIR)
                .join(m.to_string())
                .join("identity.enc"),
            None => self.path.join("meta/identity.enc"),
        };
        let escrow_path = match member_scoped {
            Some(m) => self
                .path
                .join(crate::vault::members::MEMBERS_DIR)
                .join(m.to_string())
                .join("identity-escrow.json"),
            None => self.path.join("meta/identity-escrow.json"),
        };

        let new_keys = crate::vault::identity::IdentityKeys::generate()?;
        // P1 invariant, now actually true: the wrap self-heal and its
        // refusal run BEFORE any identity byte is written. The refusal
        // path (identity lost in memory while wraps exist) must leave
        // zero state change — previously it fired after the sealed
        // seed, escrow, and member-unlock material had already been
        // overwritten with the new identity, orphaning every wrap.
        let new_wrap_hex = hex::encode(new_keys.wrapping_pub_bytes());
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| VaultError::InvalidOperation("device is not a vault member".into()))?;
        if let VaultState::Unlocked(u) = &self.state {
            match u.identity.as_ref() {
                Some(old_identity) => {
                    crate::vault::collections::rewrap_own_grant_wraps(
                        &self.path,
                        &member_id,
                        old_identity.wrapping_secret(),
                        &new_wrap_hex,
                    )?;
                    // S3-7a: the space meta wrap rides the same
                    // identity; same two-phase discipline.
                    crate::vault::space_meta::rewrap_own_space_wrap(
                        &self.path,
                        &member_id,
                        old_identity.wrapping_secret(),
                        &new_wrap_hex,
                    )?;
                    // S4-2: group key wraps ride the same identity too.
                    crate::vault::groups::rewrap_own_gkwraps(
                        &self.path,
                        &member_id,
                        old_identity.wrapping_secret(),
                        &new_wrap_hex,
                    )?;
                }
                None => {
                    // No old identity in memory: existing wraps would be
                    // orphaned by the rotation. Refuse while they exist.
                    if crate::vault::collections::has_grant_wraps(&self.path, &member_id)
                        || crate::vault::space_meta::has_space_wrap(&self.path, &member_id)
                        || crate::vault::groups::has_gkwraps(&self.path, &member_id)
                    {
                        return Err(VaultError::InvalidOperation(
                            "This device lost its identity key, so rotation is refused to keep the shared collection keys readable.".into(),
                        )
                        .into());
                    }
                }
            }
        }
        let sealed = crate::vault::identity::seal_identity(&wrap_key, &new_keys)?;
        super::write_vault_file(&identity_path, &sealed)?;

        // Re-escrow: HPKE-wrap the new seed to the recovery pubkey so phrase
        // recovery keeps restoring the CURRENT identity.
        let recovery_pub: [u8; 32] = hex::decode(&recovery_pub_hex)
            .map_err(|e| VaultError::Metadata(format!("recovery pubkey hex: {e}")))?
            .try_into()
            .map_err(|_| VaultError::Metadata("recovery pubkey wrong length".into()))?;
        let (eph, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            &new_keys.seed(),
            &x25519_dalek::PublicKey::from(recovery_pub),
            "identity-escrow",
        )?;
        let escrow = serde_json::json!({
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        super::write_vault_file(
            &escrow_path,
            serde_json::to_string_pretty(&escrow)
                .map_err(|e| VaultError::Metadata(format!("escrow serialization: {e}")))?
                .as_bytes(),
        )?;

        // S1a-4: member devices update their device-local sealed identity
        // seed so the rotation persists across lock/unlock.
        if member_scoped.is_some() {
            crate::vault::members::update_member_unlock_identity_seed(
                &self.path,
                &hex::encode(crate::vault::identity::seal_identity(&wrap_key, &new_keys)?),
            )?;
        }

        // Cache the new keys. S1a-4: identity rotation must be visible —
        // record the new identity pubkey + rotation timestamp in the
        // member record (self-service write; the commit ships it to every
        // client, whose contact reconciliation downgrades stale Verified
        // entries — the trust reset). No-op on legacy vaults without
        // member records.
        let vk_hex = hex::encode(new_keys.signing_key().verifying_key().as_bytes());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // S1a-4 review: sign the rotation payload with the NEW identity
        // key (proof of possession) and record the replaced key so the
        // structural rule can enforce previous-key continuity.
        // (The wrap self-heal + refusal ran ABOVE, before any identity
        // byte was written.)
        let previous_vk =
            crate::vault::members::identity_pubkey_for_device(&self.path, self.device_id);
        let rotation_payload = crate::vault::members::identity_rotation_payload(
            &member_id,
            &vk_hex,
            previous_vk.as_deref().unwrap_or(""),
        );
        use ed25519_dalek::Signer;
        let rotation_sig = hex::encode(new_keys.signing_key().sign(&rotation_payload).to_bytes());
        crate::vault::members::set_member_identity(
            &self.path,
            self.device_id,
            &vk_hex,
            previous_vk.as_deref(),
            &rotation_sig,
            now,
            Some(&new_wrap_hex),
        )?;
        if let VaultState::Unlocked(u) = &mut self.state {
            u.identity = Some(new_keys);
        }
        // S1b-1: activity log (best-effort).
        self.emit_share_event(
            crate::vault::events::ShareEventKind::IdentityRotated,
            "identity rotated; contacts re-verify with the new card",
        );
        Ok(())
    }

    /// Unlock the vault using a pre-derived KEK, skipping the expensive
    /// Argon2id derivation. Runs the shared unlock tail: derive session/sync
    /// keys, HPKE-unwrap the Root Key, verify both canaries, swap state.
    ///
    /// Used by session PIN Quick Unlock: the daemon retains the KEK in
    /// memory (mlocked, zeroized on drop) after the first master-password
    /// unlock, and a PIN gate re-unlocks without re-running Argon2id. The
    /// PIN path does NOT record on-disk failed attempts; the daemon's
    /// per-vault PIN counter owns attempt accounting and nukes the escrow
    /// after `MAX_PIN_FAILURES` tries (Bitwarden-equivalent policy).
    ///
    /// No key material crosses IPC. `kek` is zeroized by the caller when done.
    /// S3-7b: member unlock tail for flipped (team-shape) vaults. The
    /// member's KEK opened their device-local sealed identity seed; their
    /// identity wrapping secret opens the identity-keyed space.wrap; the
    /// SMK expands to the meta IKM. No Root Key, no group key.
    #[allow(clippy::too_many_arguments)]
    fn unlock_tail_member(
        &mut self,
        member: &crate::vault::members::MemberUnlock,
        session_key: [u8; 32],
        sync_key: [u8; 32],
        devkey_seal: [u8; 32],
    ) -> Result<(), BaluardError> {
        let sealed_hex = member.identity_seed_sealed.as_deref().ok_or_else(|| {
            VaultError::InvalidOperation(
                "this device has no sealed identity seed; re-approve this member".into(),
            )
        })?;
        let sealed = hex::decode(sealed_hex)
            .map_err(|_| VaultError::Corrupt("member identity seed".into()))?;
        let keys = crate::vault::identity::open_identity(&devkey_seal, &sealed).map_err(|e| {
            VaultError::InvalidOperation(format!(
                "this device's identity seed did not open; re-approve this member ({e})"
            ))
        })?;
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                VaultError::InvalidOperation(
                    "this device is not bound to a member record; re-approve this member".into(),
                )
            })?;
        let smk = crate::vault::space_meta::open_space_wrap(
            &self.path,
            &member_id,
            keys.wrapping_secret(),
        )
        .map_err(|e| {
            VaultError::InvalidOperation(format!(
                "no readable space meta wrap for this member yet; sync and retry ({e})"
            ))
        })?;
        let current_epoch = self.determine_current_epoch();
        // The devkey seal doubles as the identity sealing wrap key on the
        // member path (the seed is sealed under it), so identity rotation
        // works after PIN/KEK unlocks too.
        let identity_wrap_key = Zeroizing::new(devkey_seal);

        self.state = VaultState::Unlocked(UnlockedState {
            root_key: None,
            space_group_key: None,
            smk: Some(smk),
            session_key,
            sync_key,
            devkey_seal,
            item_keys: HashMap::new(),
            current_epoch,
            identity: Some(keys),
            identity_wrap_key: Some(identity_wrap_key),
        });
        // C1: legacy plaintext re-seal + registry sync, same as the admin
        // tail. The admin-only metadata migration is skipped on member
        // devices (they cannot write meta/** tracked files).
        {
            let path = self.path.join("meta/device-privkey.json");
            let _ = crate::vault::device_privkey::reseal_if_legacy(
                &path,
                &self.unlocked().devkey_seal,
                Some(self.device_id),
            );
            let _ = crate::vault::device_privkey::write_device_id(&self.path, self.device_id);
        }
        self.sync_registry_to_device_manager();
        Ok(())
    }

    /// S3-7b: admin-side convergence after the flip. A crash between the
    /// marker write and the flip's re-encryption leaves files sealed under
    /// the Root-Key-derived meta keys; read each with those keys (by
    /// temporarily pointing the meta IKM back at the Root Key) and re-save
    /// through the standard savers (meta-IKM-keyed). Best-effort per file:
    /// every admin unlock re-converges until the vault is clean.
    fn converge_meta_after_flip(&mut self) {
        // Temporarily drop the SMK so the standard loaders read the
        // old-keyed files with the live Root Key derivation.
        let saved_smk = match &mut self.state {
            VaultState::Unlocked(u) => u.smk.take(),
            VaultState::Locked => None,
        };
        let folders = self.list_folders().ok();
        let tags = self.list_tags().ok();
        let profile = self.load_profile().ok();
        let settings = self.get_settings().ok();
        let contacts = self.load_contacts().ok();
        // The avatar read must happen INSIDE the dropped-SMK window:
        // post-marker crash bytes are root-domain, which neither the
        // SMK key nor the legacy SGK fallback can open once the SMK is
        // restored.
        let avatar_path = self.path.join("meta/avatar.enc");
        let avatar_bytes = avatar_path
            .exists()
            .then(|| std::fs::read(&avatar_path).ok())
            .flatten()
            .and_then(|blob| self.decrypt_avatar_blob(&blob).ok());
        if let VaultState::Unlocked(u) = &mut self.state {
            u.smk = saved_smk;
        }
        if let Some(f) = folders {
            let _ = self.save_folders(&f);
        }
        if let Some(names) = tags {
            let index = crate::vault::manifest::TagIndex {
                tags: names,
                updated_at: crate::vault::templates::now_secs(),
            };
            let _ = self.save_tags_enc(&index);
        }
        if let Some(p) = profile {
            let _ = self.save_profile(&p);
        }
        if let Some(s) = settings {
            let _ = self.save_settings(&s);
        }
        if let Some(c) = contacts {
            let _ = self.save_contacts(&c);
        }
        // The avatar rides the same member-visible domain; migrate the
        // bytes snapshotted under the pre-flip key (best-effort, like
        // the five above).
        if let Some(bytes) = avatar_bytes {
            if let Ok(key) = self.derive_avatar_key() {
                if let Ok(new_blob) =
                    crate::vault::avatar::encrypt_avatar(&zeroize::Zeroizing::new(key), &bytes)
                {
                    let _ = super::write_vault_file(&avatar_path, &new_blob);
                }
            }
        }
        // A crash between the flip's marker write and its keywrap strip
        // leaves member Root Key wraps on disk; convergence removes them.
        self.strip_member_keywraps();
    }

    /// Re-seal the member-visible meta artifacts under a freshly rotated
    /// SMK and adopt that SMK in memory. The load pass runs while the
    /// OUTGOING SMK is still in `u.smk` (the files are old-keyed); the
    /// save pass runs after the swap, so everything re-seals under the
    /// new key. Returns false when any re-save failed — the caller keeps
    /// the pending marker so the next admin unlock retries the heal.
    fn reseal_meta_after_smk_rotate(&mut self, new_smk: zeroize::Zeroizing<[u8; 32]>) -> bool {
        let folders = self.list_folders().ok();
        let tags = self.list_tags().ok();
        let profile = self.load_profile().ok();
        let settings = self.get_settings().ok();
        let contacts = self.load_contacts().ok();
        let avatar_path = self.path.join("meta/avatar.enc");
        let avatar_bytes = avatar_path
            .exists()
            .then(|| std::fs::read(&avatar_path).ok())
            .flatten()
            .and_then(|blob| self.decrypt_avatar_blob(&blob).ok());
        if let VaultState::Unlocked(u) = &mut self.state {
            u.smk = Some(new_smk);
        }
        let mut ok = true;
        if let Some(f) = folders {
            ok &= self.save_folders(&f).is_ok();
        }
        if let Some(names) = tags {
            let index = crate::vault::manifest::TagIndex {
                tags: names,
                updated_at: crate::vault::templates::now_secs(),
            };
            ok &= self.save_tags_enc(&index).is_ok();
        }
        if let Some(p) = profile {
            ok &= self.save_profile(&p).is_ok();
        }
        if let Some(s) = settings {
            ok &= self.save_settings(&s).is_ok();
        }
        if let Some(c) = contacts {
            ok &= self.save_contacts(&c).is_ok();
        }
        if let Some(bytes) = avatar_bytes {
            if let Ok(key) = self.derive_avatar_key() {
                if let Ok(new_blob) =
                    crate::vault::avatar::encrypt_avatar(&zeroize::Zeroizing::new(key), &bytes)
                {
                    ok &= super::write_vault_file(&avatar_path, &new_blob).is_ok();
                }
            }
        }
        ok
    }

    /// Unlock-tail heal for a removal's interrupted SMK rotation: the
    /// pending marker carries the OUTGOING SMK, so the old-keyed meta
    /// files load under it and re-seal under the current one. Any load
    /// or save failure keeps the marker for the next attempt.
    fn heal_smk_pending_after_unlock(&mut self) {
        let Some(old_hex) = crate::vault::space_meta::read_smk_pending(&self.path) else {
            return;
        };
        let old = match hex::decode(&old_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        {
            Some(arr) => zeroize::Zeroizing::new(arr),
            None => {
                crate::vault::space_meta::clear_smk_pending(&self.path);
                return;
            }
        };
        let saved = match &mut self.state {
            VaultState::Unlocked(u) => u.smk.replace(old),
            VaultState::Locked => return,
        };
        let folders = self.list_folders().ok();
        let tags = self.list_tags().ok();
        let profile = self.load_profile().ok();
        let settings = self.get_settings().ok();
        let contacts = self.load_contacts().ok();
        let avatar_path = self.path.join("meta/avatar.enc");
        let avatar_bytes = avatar_path
            .exists()
            .then(|| std::fs::read(&avatar_path).ok())
            .flatten()
            .and_then(|blob| self.decrypt_avatar_blob(&blob).ok());
        if let VaultState::Unlocked(u) = &mut self.state {
            u.smk = saved;
        }
        let mut ok = folders.is_some()
            || tags.is_some()
            || profile.is_some()
            || settings.is_some()
            || contacts.is_some();
        if let Some(f) = folders {
            ok &= self.save_folders(&f).is_ok();
        }
        if let Some(names) = tags {
            let index = crate::vault::manifest::TagIndex {
                tags: names,
                updated_at: crate::vault::templates::now_secs(),
            };
            ok &= self.save_tags_enc(&index).is_ok();
        }
        if let Some(p) = profile {
            ok &= self.save_profile(&p).is_ok();
        }
        if let Some(s) = settings {
            ok &= self.save_settings(&s).is_ok();
        }
        if let Some(c) = contacts {
            ok &= self.save_contacts(&c).is_ok();
        }
        if let Some(bytes) = avatar_bytes {
            if let Ok(key) = self.derive_avatar_key() {
                if let Ok(new_blob) =
                    crate::vault::avatar::encrypt_avatar(&zeroize::Zeroizing::new(key), &bytes)
                {
                    ok &= super::write_vault_file(&avatar_path, &new_blob).is_ok();
                }
            }
        }
        if ok {
            crate::vault::space_meta::clear_smk_pending(&self.path);
        }
    }

    pub fn unlock_with_kek(&mut self, kek: &[u8; 32]) -> Result<(), BaluardError> {
        self.unlock_tail(kek, None)
    }

    /// S1a-2: member unlock tail — the KEK-canary check runs against the
    /// member's own canary (device-local member-unlock.json) instead of
    /// the founding device's vault-level canary.
    pub fn unlock_with_member_canary(
        &mut self,
        kek: &[u8; 32],
        member_canary: Vec<u8>,
    ) -> Result<(), BaluardError> {
        self.unlock_tail(kek, Some(member_canary))
    }

    fn unlock_tail(
        &mut self,
        kek: &[u8; 32],
        canary_override: Option<Vec<u8>>,
    ) -> Result<(), BaluardError> {
        // Step 2: Derive session + sync keys, plus the device-privkey seal
        // subkey (C1). The subkey, never the KEK, is retained post-unlock.
        let session_key = hkdf_derive::derive_session_key(kek)?;
        let sync_key = hkdf_derive::derive_sync_key(kek)?;
        let devkey_seal = hkdf_derive::derive_devkey_seal_key(kek)?;

        // Step 3: Verify KEK is correct by decrypting the KEK canary
        // Canary plaintext MUST equal b"baluard-kek-ok" — this catches wrong passwords
        // even when AES-GCM doesn't fail (cosmically unlikely but defense-in-depth).
        // Member devices (S1a-2) verify their own device-local canary.
        let canary_data = match canary_override {
            Some(canary) => canary,
            None => match crate::vault::members::load_member_unlock(&self.path, self.device_id)? {
                Some(member) => hex::decode(&member.kek_canary)
                    .map_err(|_| VaultError::Corrupt("member canary".into()))?,
                None => {
                    if self.path.join("meta/kek-canary.enc").exists() {
                        std::fs::read(self.path.join("meta/kek-canary.enc"))
                            .map_err(|e| VaultError::Metadata(format!("reading kek canary: {e}")))?
                    } else {
                        Vec::new()
                    }
                }
            },
        };
        if !canary_data.is_empty() {
            super::canary::verify_kek_canary(&session_key, &canary_data)?;
        }

        // S3-7b: team-shape member devices hold no Root Key. Their unlock
        // path is identity seed (device-local, KEK-sealed) → identity keys
        // → the identity-keyed space.wrap → SMK → meta IKM. No keywrap
        // unwrap, no SGK, no Root Key ever enters memory.
        // F9: an ELEVATED member (Owner/Admin) whose keywrap has landed
        // takes the admin path below instead — their password is still
        // their own (the member canary verified above), but their powers
        // need the Root Key. The keywrap-existence conjunct keeps the
        // legacy no-binding fallback fail-closed: a device with no member
        // row has no keywrap file, so it can never ride the admin path.
        // Before the approval commit is pulled the keywrap is absent and
        // the member tail refuses with sync-and-retry, as for every
        // member.
        let flipped = crate::vault::space_meta::shape_flipped(&self.path);
        if flipped {
            if let Some(member) =
                crate::vault::members::load_member_unlock(&self.path, self.device_id)?
            {
                let elevated_member = self.device_maps_to_admin(self.device_id)
                    && self
                        .path
                        .join(format!("meta/keywrap/{}.json", self.device_id))
                        .exists();
                if !elevated_member {
                    return self.unlock_tail_member(&member, session_key, sync_key, devkey_seal);
                }
            }
            // Founding/admin device — or an elevated member with their
            // keywrap on disk: the Root Key path below still runs; the SMK
            // comes from the sealed store so meta keys match the members'
            // HKDF(SMK) derivation.
        }

        // Step 4 (cont.): admin/founding path — HPKE-decapsulate Root Key
        // using device private key (keyring or file).
        // If unwrap fails on a fast-path resolved device_id, fall back through other
        // enrolled candidates to provide self-healing recovery against corrupted or
        // spoofed meta/device-id entries (F1 self-healing fix).
        let (root_key, _matched_device_id) = {
            let attempt_unwrap = |dev_id: Uuid| -> Result<RootKey, BaluardError> {
                let kw_path = self.path.join(format!("meta/keywrap/{dev_id}.json"));
                if !kw_path.exists() {
                    return Err(VaultError::NotFound(format!("keywrap for {dev_id}")).into());
                }
                let kw_json = std::fs::read_to_string(&kw_path)
                    .map_err(|e| VaultError::Metadata(format!("reading keywrap: {e}")))?;
                let parsed_kw = super::keywrap::parse_keywrap_json(&kw_json)?;
                let privs = load_device_privkeys(&self.path, dev_id, Some(&devkey_seal))?;
                // A keystore that opens but does not match any keywrap is a
                // stale/reinstalled device, not a wrong password: label it
                // so surfaces can offer re-pairing instead of retrying the
                // password field.
                let unwrapped = hpke_wrap::unwrap_key(
                    &parsed_kw.ephemeral_public,
                    &parsed_kw.encrypted_key,
                    &parsed_kw.tag,
                    &privs.x25519,
                    "root-key-keywrap",
                )
                .map_err(|_| {
                    VaultError::DeviceUnpaired(format!(
                        "the connection key for device {dev_id} does not match this vault"
                    ))
                })?;
                let rk_bytes: [u8; 64] = unwrapped
                    .try_into()
                    .map_err(|_| VaultError::Corrupt("unwrapped root key not 64 bytes".into()))?;
                let rk = RootKey::from_bytes(rk_bytes);
                self.verify_root_key(&rk)?;
                Ok(rk)
            };

            match attempt_unwrap(self.device_id) {
                Ok(rk) => (rk, self.device_id),
                Err(primary_err) => {
                    // P3: prefer this device's fresh wrap from the committed
                    // rekey transaction (its own keywrap file is stale or
                    // missing after a rotation by another device) BEFORE the
                    // F1 cross-device heal: a survivor must not silently
                    // adopt another device's identity while its own wrap is
                    // recoverable.
                    if let Some(rk) = self.adopt_rekey_txn_root(&devkey_seal) {
                        (rk, self.device_id)
                    } else {
                        let keywrap_dir = self.path.join("meta/keywrap");
                        let mut healed = None;
                        if keywrap_dir.exists() {
                            if let Ok(entries) = std::fs::read_dir(&keywrap_dir) {
                                for entry in entries.flatten() {
                                    let name = entry.file_name().to_string_lossy().to_string();
                                    if let Some(id_str) = name.strip_suffix(".json") {
                                        if let Ok(candidate_id) = Uuid::parse_str(id_str) {
                                            if candidate_id != self.device_id {
                                                if let Ok(rk) = attempt_unwrap(candidate_id) {
                                                    healed = Some((rk, candidate_id));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if let Some((rk, healed_id)) = healed {
                            self.device_id = healed_id;
                            let _ = crate::vault::device_privkey::write_device_id(
                                &self.path, healed_id,
                            );
                            (rk, healed_id)
                        } else {
                            return Err(primary_err);
                        }
                    }
                }
            }
        };

        // Step 7: Determine current epoch from any existing cipher or RK canary
        let current_epoch = self.determine_current_epoch();

        // S3-7b: post-flip, the seven member-visible meta derivations take
        // HKDF(SMK); the admin opens the SMK from the sealed store. Pre-flip
        // the meta IKM derives from the live Root Key (identical behavior).
        let smk = if flipped {
            Some(crate::vault::space_meta::open_store(&self.path, &root_key)?)
        } else {
            None
        };

        self.state = VaultState::Unlocked(UnlockedState {
            root_key: Some(root_key.clone()),
            space_group_key: Some(crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                &root_key,
                current_epoch,
            )),
            smk,
            session_key,
            sync_key,
            devkey_seal,
            item_keys: HashMap::new(),
            current_epoch,
            identity: None,
            identity_wrap_key: None,
        });

        if flipped {
            // Convergence: a crash between the flip's marker write and its
            // file re-encryption leaves old-keyed files behind. Heal them
            // now (read with the Root Key derivation, re-save under the
            // new one), so the post-unlock session never sees a mix.
            // A removal's interrupted SMK rotation heals before the flip
            // convergence (the marker's outgoing key opens the stranded
            // meta; both then re-seal under the live key).
            self.heal_smk_pending_after_unlock();
            self.converge_meta_after_flip();
        }

        // P1a: cache the identity when its sealing key is device-local (OS
        // keystore mode). Passphrase-fallback mode caches in unlock() where
        // the master password is still in scope.
        self.load_identity_cache(None);

        // C1: lazily re-seal a legacy plaintext device-privkey file now that
        // the KEK is proven correct. Best-effort — a failure must not fail
        // the unlock; the next unlock retries.
        {
            let path = self.path.join("meta/device-privkey.json");
            let _ = crate::vault::device_privkey::reseal_if_legacy(
                &path,
                &devkey_seal,
                Some(self.device_id),
            );
            let _ = crate::vault::device_privkey::write_device_id(&self.path, self.device_id);
        }

        // M6 fix: ensure registries stay in sync after unlock
        self.sync_registry_to_device_manager();

        // Migrate plaintext metadata to encrypted format
        self.migrate_plaintext_metadata();

        Ok(())
    }

    /// Change the master password. Requires unlocked vault.
    ///
    /// H1 fix: Re-derives KEK, re-wraps the Root Key, re-encrypts the KEK canary,
    /// updates KDF params, and disables stale biometric secrets.
    ///
    /// **Security note**: The master password gates the KEK canary (password verification)
    /// and the keywrap (encrypted via device X25519 key). The device private key
    /// (from OS keyring or `meta/device-privkey.json`) independently controls Root Key
    /// access. Password change alone does NOT protect against an attacker who holds
    /// the device private key. For post-compromise remediation, call `rotate_root_key()`
    /// or `revoke_device_and_rekey()` after changing the password.
    /// Replace the vault's recovery phrase with a fresh one. The current
    /// Root Key is re-wrapped under the new phrase, so the old phrase can
    /// no longer unwrap anything the moment this write lands. Gated on the
    /// current master password, never the old phrase: the owner holds the
    /// password, a phrase thief holds only the phrase, and rotation must
    /// be the owner's move (the change_master_password canary pattern).
    /// The new phrase is returned exactly once for immediate storage.
    pub fn rotate_recovery_phrase(&mut self, old_password: &str) -> Result<String, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        // Step 1: the password proves the caller is the owner (same canary
        // check change_master_password runs before touching anything).
        // Fail closed when the canary is absent: unlock guarantees a canary
        // somewhere, so a missing one means this device cannot verify the
        // password at all (review F2 — the old exists()-skip copied from
        // change_master_password would let a deleted canary wave any
        // string through).
        let old_kek = kdf::derive_kek(old_password, &self.kdf_params)?;
        let old_session_key = hkdf_derive::derive_session_key(&old_kek)?;
        let canary_path = self.path.join("meta/kek-canary.enc");
        if !canary_path.exists() {
            return Err(VaultError::Corrupt(
                "this device cannot verify the master password (password canary missing); unlock again on the device that created the vault".into(),
            )
            .into());
        }
        let canary_data = std::fs::read(&canary_path)?;
        super::canary::verify_kek_canary(&old_session_key, &canary_data)
            .map_err(|_| VaultError::Corrupt("old master password incorrect".into()))?;

        // A flipped (team) Space recovers with its Space Recovery Kit, not
        // a personal phrase; the destructive personal recovery would reset
        // the device roster here (review F6/F4).
        if crate::vault::space_meta::shape_flipped(&self.path) {
            return Err(VaultError::Metadata(
                "This Space recovers with its Space Recovery Kit, not a personal phrase.".into(),
            )
            .into());
        }

        // Step 2: fresh phrase, fresh wrap key (creation Step 7 shape).
        let phrase = crate::recovery::RecoveryPhrase::generate()?;
        let seed = phrase.derive_key();
        let recovery_x25519_secret = Zeroizing::new(x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(&seed[..32])
                .map_err(|_| VaultError::Corrupt("recovery key too short".into()))?,
        ));
        // PublicKey::from resolves a trait bound on &StaticSecret, so the
        // Zeroizing wrapper needs an explicit deref here (plain reference
        // coercion does not apply to trait-bound arguments).
        let recovery_x25519_public = x25519_dalek::PublicKey::from(&*recovery_x25519_secret);

        // Step 3: re-wrap the LIVE Root Key for the new phrase.
        let root_key = match &self.state {
            VaultState::Unlocked(u) => u.root()?.clone(),
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let (eph_pub, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            root_key.as_bytes(),
            &recovery_x25519_public,
            "recovery-keywrap",
        )?;

        // Step 4: overwrite the escrow; the old phrase is dead here.
        let recovery_data = serde_json::json!({
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
            "recovery_x25519_pubkey": hex::encode(recovery_x25519_public.as_bytes()),
            "rotated_at": crate::vault::collections::now_secs_pub(),
        });
        super::write_vault_file(
            &self.path.join("meta/recovery.json"),
            serde_json::to_string_pretty(&recovery_data)
                .unwrap()
                .as_bytes(),
        )?;

        Ok(phrase.phrase())
    }

    pub fn change_master_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        // Step 1: Verify old password
        let old_kek = kdf::derive_kek(old_password, &self.kdf_params)?;
        let old_session_key = hkdf_derive::derive_session_key(&old_kek)?;
        let old_devkey_seal = hkdf_derive::derive_devkey_seal_key(&old_kek)?;
        if self.path.join("meta/kek-canary.enc").exists() {
            let canary_data = std::fs::read(self.path.join("meta/kek-canary.enc"))?;
            super::canary::verify_kek_canary(&old_session_key, &canary_data)
                .map_err(|_| VaultError::Corrupt("old master password incorrect".into()))?;
        }

        // C1 pre-check: a sealed devkey file must open under the OLD seal
        // key BEFORE we rotate anything, otherwise a later failure would
        // leave a file the next unlock cannot open (lockout). Fail here,
        // before any write.
        let devkey_path = self.path.join("meta/device-privkey.json");
        if crate::vault::device_privkey::file_kind(&devkey_path)
            == crate::vault::device_privkey::PrivkeyFileKind::Sealed
        {
            let file = std::fs::read_to_string(&devkey_path)?;
            crate::vault::device_privkey::open_bytes(&old_devkey_seal, file.as_bytes())?;
        }

        // Step 2: Derive new KEK with existing KDF params
        // (could optionally re-calibrate, but keep it simple for now)
        let new_kek = kdf::derive_kek(new_password, &self.kdf_params)?;
        let new_session_key = hkdf_derive::derive_session_key(&new_kek)?;

        // Step 3: Get current root key from unlocked state
        let root_key = match &self.state {
            VaultState::Unlocked(u) => u.root()?.clone(),
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // Step 4: Load device private key for HPKE re-wrap
        let privkeys = load_device_privkeys(&self.path, self.device_id, Some(&old_devkey_seal))?;
        let x25519_public = x25519_dalek::PublicKey::from(&privkeys.x25519);

        // Step 5: HPKE re-wrap Root Key with new session key
        let (eph_pub, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            root_key.as_bytes(),
            &x25519_public,
            "root-key-keywrap",
        )?;
        let keywrap_data = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        let keywrap_json = serde_json::to_string_pretty(&keywrap_data).unwrap();
        super::write_vault_file(&keywrap_path, keywrap_json.as_bytes())?;

        // Step 6: Re-encrypt KEK canary with new session key
        if self.path.join("meta/kek-canary.enc").exists() {
            let canary_bytes = super::canary::create_kek_canary(&new_session_key, self.vault_id)?;
            let canary_path = self.path.join("meta/kek-canary.enc");
            super::write_vault_file(&canary_path, &canary_bytes)?;
        }

        // Step 7: Update in-memory session key and rotate the devkey seal
        // (C1): the KEK changed, so the seal subkey changed with it. The
        // upfront pre-check validated the old seal opens the file, so this
        // write cannot strand the vault.
        let new_devkey_seal = hkdf_derive::derive_devkey_seal_key(&new_kek)?;
        crate::vault::device_privkey::rotate_seal_key(
            &devkey_path,
            &old_devkey_seal,
            &new_devkey_seal,
            Some(self.device_id),
        )?;
        let _ = crate::vault::device_privkey::write_device_id(&self.path, self.device_id);
        if let VaultState::Unlocked(ref mut u) = self.state {
            u.session_key = new_session_key;
            u.devkey_seal = new_devkey_seal;
        }

        // Step 8: Disable old biometric secret (it stores the old password)
        // Caller should re-enable biometric with the new password after this.
        // Scoped to this vault's vault_id so other vaults' Quick Unlock is
        // untouched. Log on failure: stale secret will cause canary mismatch
        // on next biometric unlock, which is self-correcting (user falls
        // back to manual password entry).
        if let Err(e) = crate::biometric::disable(&self.vault_id.to_string()) {
            eprintln!("warning: failed to disable biometric after password change: {e}");
        }

        Ok(())
    }

    /// Migrate plaintext metadata files to encrypted format.
    /// Called after successful unlock. Best-effort: logs errors but does not fail unlock.
    fn migrate_plaintext_metadata(&self) {
        // S3-7b: the profile and activity legs write git-tracked meta/**
        // files that only admins may commit. On team-member devices
        // (no Root Key) the write would wedge the member's next push.
        let may_commit_meta = match &self.state {
            VaultState::Unlocked(u) => u.holds_root(),
            VaultState::Locked => false,
        };

        // Migrate folders.json -> folders.enc
        let folders_json = self.path.join("meta/folders.json");
        let folders_enc = self.path.join("meta/folders.enc");
        if folders_json.exists() && !folders_enc.exists() {
            if let Ok(data) = std::fs::read_to_string(&folders_json) {
                if let Ok(folders) =
                    serde_json::from_str::<Vec<crate::vault::manifest::Folder>>(&data)
                {
                    if self.save_folders(&folders).is_ok() {
                        let _ = std::fs::remove_file(&folders_json);
                    }
                }
            }
        }

        // Migrate tag_index.json -> tags.enc
        let tags_json = self.path.join("meta/tag_index.json");
        let tags_enc = self.path.join("meta/tags.enc");
        if tags_json.exists() && !tags_enc.exists() {
            if let Ok(data) = std::fs::read_to_string(&tags_json) {
                if let Ok(index) = serde_json::from_str::<crate::vault::manifest::TagIndex>(&data) {
                    if self.save_tags_enc(&index).is_ok() {
                        let _ = std::fs::remove_file(&tags_json);
                    }
                }
            }
        }

        // Migrate settings.json identity fields -> profile.enc (admin
        // commit surface: meta/profile.enc + meta/settings-pub.json are
        // Admin rows — same wedge class as the activity leg).
        let profile_enc = self.path.join("meta/profile.enc");
        if may_commit_meta && !profile_enc.exists() {
            if let Ok(settings) = self.get_settings() {
                let has_identity = settings.display_name.is_some()
                    || settings.subtitle.is_some()
                    || settings.avatar_ext.is_some();
                if has_identity {
                    let profile = crate::vault::manifest::UserProfile {
                        display_name: settings.display_name,
                        subtitle: settings.subtitle,
                        avatar_ext: settings.avatar_ext,
                    };
                    let _ = self.save_profile_and_strip_settings(&profile);
                }
            }
        }

        // Migrate device_activity.json -> activity.enc (admin commit
        // surface only — see the guard above).
        if may_commit_meta {
            let activity_enc = self.path.join("meta/activity.enc");
            if !activity_enc.exists() {
                let plaintext = crate::device_manager::DeviceActivityIndex::read(&self.path);
                if !plaintext.devices.is_empty() {
                    let _ = self.save_activity_enc(&plaintext);
                }
            }
        }
    }

    /// Lock the vault: zeroize all key material.
    /// File timestamp normalization runs in a background thread to avoid
    /// blocking the lock operation on large vaults.
    pub fn lock(&mut self) {
        self.state = VaultState::Locked;
        let path_clone = self.path.clone();
        let creation_ts = self
            .registry
            .devices
            .values()
            .map(|d| d.enrolled_at)
            .min()
            .unwrap_or(0);
        std::thread::spawn(move || {
            Self::normalize_timestamps_bg(&path_clone, creation_ts);
        });
    }

    /// Background timestamp normalization (static, no &self).
    fn normalize_timestamps_bg(vault_path: &std::path::Path, creation_ts: u64) {
        use filetime::{FileTime, set_file_mtime};
        let target = FileTime::from_unix_time(creation_ts as i64, 0);

        fn normalize_dir(dir: &std::path::Path, target: FileTime) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = set_file_mtime(&path, target);
                    } else if path.is_dir() {
                        normalize_dir(&path, target);
                    }
                }
            }
        }

        let dirs = ["ciphers", "trash", "meta"];
        for dir_name in &dirs {
            normalize_dir(&vault_path.join(dir_name), target);
        }
        if let Ok(entries) = std::fs::read_dir(vault_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "enc") {
                    let _ = set_file_mtime(&path, target);
                }
            }
        }
    }

    /// Check if vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultState::Unlocked(_))
    }

    /// Whether the unlocked session holds the Root Key (admin surface).
    /// Locked handles report false.
    pub fn holds_root(&self) -> bool {
        matches!(&self.state, VaultState::Unlocked(u) if u.holds_root())
    }

    /// Device-privkey seal subkey (C1). `Some` only while unlocked: the
    /// subkey lives in `UnlockedState` and is dropped on lock, exactly like
    /// the session key. Consumers: daemon sync signing (autosync), direct
    /// CLI sync after an in-process unlock.
    pub fn devkey_seal(&self) -> Option<[u8; 32]> {
        match &self.state {
            VaultState::Unlocked(u) => Some(u.devkey_seal),
            VaultState::Locked => None,
        }
    }

    /// Helper: get vault path as &Path for observer hooks.
    fn vault_path_as_ref(&self) -> Option<&Path> {
        Some(&self.path)
    }

    /// M6 fix: sync VaultHandle.registry with device_manager.registry.
    /// Call after loading or mutating either registry.
    fn sync_registry_to_device_manager(&mut self) {
        self.device_manager.registry = self.registry.clone();
    }

    /// Sync VaultHandle.registry with device_manager.registry.
    /// Call after operations that mutate device_manager's registry.
    fn sync_registry_from_device_manager(&mut self) {
        self.registry = self.device_manager.registry.clone();
    }

    /// Get a reference to the unlocked state (panics if locked).
    pub fn unlocked(&self) -> &UnlockedState {
        match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => panic!("vault is locked"),
        }
    }

    /// Get a mutable reference to the unlocked state (panics if locked).
    pub fn unlocked_mut(&mut self) -> &mut UnlockedState {
        match &mut self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => panic!("vault is locked"),
        }
    }

    /// Derive the avatar encryption key from the member-visible meta
    /// domain (raw root bytes pre-flip, HKDF-expanded SMK post-flip).
    /// Domain-separated from the legacy epoch-bound SGK derivation; on
    /// member devices this works wherever the profile does.
    pub fn derive_avatar_key(&self) -> Result<[u8; 32], BaluardError> {
        crate::crypto::hkdf_derive::derive_avatar_key(&self.unlocked().meta_ikm())
            .map_err(BaluardError::from)
    }

    /// Decrypt an avatar blob, trying the meta-domain key first and
    /// falling back to the legacy epoch-bound SGK derivation for blobs
    /// written before the re-home. Convergent: any rewrite migrates the
    /// blob; a rotation migrates the rest.
    pub fn decrypt_avatar_blob(&self, blob: &[u8]) -> Result<Vec<u8>, BaluardError> {
        match crate::vault::avatar::decrypt_avatar(&self.derive_avatar_key()?, blob) {
            Ok(bytes) => Ok(bytes),
            Err(_) => match self.unlocked().sgk() {
                Ok(sgk) => {
                    crate::vault::avatar::decrypt_avatar(&sgk.derive_avatar_key(sgk.epoch()), blob)
                        .map_err(BaluardError::from)
                }
                Err(_) => Err(VaultError::Metadata("avatar could not be decrypted".into()).into()),
            },
        }
    }

    /// Encrypt metadata JSON and write to disk atomically.
    /// Shared by save_folders, save_tags_enc, save_profile.
    /// Caller must ensure vault is unlocked and derive the key.
    fn encrypt_and_write_meta(
        &self,
        key: &[u8; 32],
        json: &[u8],
        enc_path: &std::path::Path,
        epoch: u64,
    ) -> Result<(), BaluardError> {
        let nonce = crate::crypto::aead::build_random_nonce();
        // Header stores only a u64 `nonce_counter`; derive it from the first
        // 8 bytes of the 96-bit random nonce so the field stays populated
        // (metadata-only — decrypt reads the full 12-byte nonce from the
        // envelope, not this field). A-1 fix: previously build_nonce(counter,
        // Uuid::nil()) zeroed the shard tail, leaving only 64 random bits.
        let nonce_counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());
        let aad = crate::crypto::aead::build_aad(
            self.vault_id,
            crate::types::ObjectType::Meta,
            Uuid::nil(),
            None,
            crate::ALG_AES_256_GCM,
            epoch,
            1,
        );
        let header = crate::types::EnvelopeHeader {
            version: crate::BALUARD_VERSION,
            alg_id: crate::ALG_AES_256_GCM,
            key_epoch: epoch,
            nonce_counter,
            update_seq: 1,
            tier: None,
        };
        let envelope = crate::crypto::aead::encrypt(key, json, &aad, &nonce, header)?;
        let envelope_bytes = crate::vault::envelope::serialize(&envelope)?;
        super::write_vault_file(enc_path, &envelope_bytes)?;
        Ok(())
    }

    /// Get vault settings (reads from disk).
    pub fn get_settings(&self) -> Result<crate::vault::manifest::VaultSettings, BaluardError> {
        // Split storage (2026-06-26): display prefs in plaintext settings-pub.json,
        // the rest encrypted under the root key in settings.enc. Legacy
        // settings.json is migrated on first unlock.
        //
        // Public (pre-unlock) fields: theme + lang.
        // Encrypted (post-unlock) fields: vault_timeout, default_uri_match,
        // fetch_favicons, slug, enrollment_policy. slug confirmed to have no
        // pre-unlock consumer (authoritative source is the .baluard marker +
        // registry); the rest are post-unlock only.
        let pub_path = self.path.join("meta/settings-pub.json");
        let enc_path = self.path.join("meta/settings.enc");
        let legacy_path = self.path.join("meta/settings.json");

        // 1. Plaintext public prefs (theme + lang). Fall back to legacy
        //    meta/locale for lang during migration.
        let (theme, lang) = if pub_path.exists() {
            let data = std::fs::read_to_string(&pub_path)?;
            let v: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("settings-pub parse: {e}")))?;
            (
                v.get("theme")
                    .and_then(|t| serde_json::from_value(t.clone()).ok()),
                v.get("lang").and_then(|l| l.as_str()).map(String::from),
            )
        } else {
            // Legacy: no settings-pub.json yet. lang lived in meta/locale or
            // settings.json; theme only in settings.json. The migration below
            // (or the legacy fallback path) fills these in.
            let lang = self.load_locale().or_else(|| {
                std::fs::read_to_string(&legacy_path).ok().and_then(|d| {
                    serde_json::from_str::<serde_json::Value>(&d)
                        .ok()
                        .and_then(|v| v["lang"].as_str().map(String::from))
                })
            });
            let theme = std::fs::read_to_string(&legacy_path).ok().and_then(|d| {
                serde_json::from_str::<serde_json::Value>(&d)
                    .ok()
                    .and_then(|v| serde_json::from_value(v["theme"].clone()).ok())
            });
            (theme, lang)
        };

        // 2. Encrypted settings. Requires unlocked vault.
        let encrypted = match &self.state {
            VaultState::Unlocked(unlocked) => {
                if enc_path.exists() {
                    let key =
                        hkdf_derive::derive_settings_key(&unlocked.meta_ikm()).map_err(|e| {
                            VaultError::Metadata(format!("settings key derivation: {e}"))
                        })?;
                    let data = std::fs::read(&enc_path)?;
                    let envelope = crate::vault::envelope::deserialize(&data)?;
                    let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
                    Some(
                        serde_json::from_slice::<crate::vault::manifest::EncryptedSettings>(
                            &decrypted,
                        )
                        .map_err(|e| VaultError::Metadata(format!("settings.enc parse: {e}")))?,
                    )
                } else {
                    None
                }
            }
            VaultState::Locked => None,
        };

        // 3. Legacy migration: if settings.enc is absent but settings.json
        //    exists, read the encrypted fields from it. The next save_settings
        //    (or an explicit migrate) writes settings.enc and settings-pub.json,
        //    deprecating settings.json.
        let (enc_fields, migrated_lang) = match encrypted {
            Some(e) => (Some(e), None),
            None => {
                if legacy_path.exists() {
                    let data = std::fs::read_to_string(&legacy_path)?;
                    let v: serde_json::Value = serde_json::from_str(&data)
                        .map_err(|e| VaultError::Metadata(format!("settings parse: {e}")))?;
                    let enc = crate::vault::manifest::EncryptedSettings {
                        vault_timeout: serde_json::from_value(v["vault_timeout"].clone())
                            .unwrap_or_else(|_| {
                                crate::vault::manifest::VaultTimeout::default_for_new()
                            }),
                        default_uri_match: serde_json::from_value(v["default_uri_match"].clone())
                            .ok(),
                        fetch_favicons: v["fetch_favicons"].as_bool(),
                        slug: v["slug"].as_str().map(String::from),
                        device_names: None,
                        enrollment_policy: serde_json::from_value(v["enrollment_policy"].clone())
                            .unwrap_or(crate::vault::manifest::EnrollmentPolicy::Strict),
                        // Space policy post-dates the legacy split: legacy
                        // files never carry it, so defaults apply.
                        space_invite_authority: Default::default(),
                        allow_viewer_export: false,
                        guest_enabled: None,
                        trash_policy: Default::default(),
                        restore_policy: Default::default(),
                        join_approval: Default::default(),
                        quorum_admin_ops: None,
                        collection_create_authority: Default::default(),
                        // These post-date the legacy settings.json split: a
                        // legacy file never carries them.
                        custom_equivalent_domains: None,
                        suggest_app_logins: None,
                        trusted_app_packages: None,
                        rejected_app_packages: None,
                    };
                    let legacy_lang = v["lang"].as_str().map(String::from);
                    (Some(enc), legacy_lang)
                } else {
                    (None, None)
                }
            }
        };

        // 4. Assemble. Effective lang prefers the explicit pub value, then the
        //    legacy-file value discovered during migration.
        let lang = lang.or(migrated_lang);
        Ok(crate::vault::manifest::VaultSettings {
            vault_timeout: enc_fields
                .as_ref()
                .map(|e| e.vault_timeout)
                .unwrap_or_else(crate::vault::manifest::VaultTimeout::default_for_new),
            theme,
            lang,
            default_uri_match: enc_fields.as_ref().and_then(|e| e.default_uri_match),
            fetch_favicons: enc_fields.as_ref().and_then(|e| e.fetch_favicons),
            slug: enc_fields.as_ref().and_then(|e| e.slug.clone()),
            // Identity fields live in profile.enc now; kept for struct compat.
            display_name: None,
            subtitle: None,
            avatar_ext: None,
            custom_equivalent_domains: enc_fields
                .as_ref()
                .and_then(|e| e.custom_equivalent_domains.clone()),
            suggest_app_logins: enc_fields.as_ref().and_then(|e| e.suggest_app_logins),
            trusted_app_packages: enc_fields
                .as_ref()
                .and_then(|e| e.trusted_app_packages.clone()),
            rejected_app_packages: enc_fields
                .as_ref()
                .and_then(|e| e.rejected_app_packages.clone()),
            enrollment_policy: enc_fields.as_ref().map(|e| e.enrollment_policy).unwrap_or(
                // No encrypted settings and no legacy file (step 3 already
                // handled the legacy case above, Strict for field-less old
                // files): a fresh vault pre-first-save. New vaults are
                // Personal (product intent); the old unconditional Strict
                // fallback poisoned creation — save_settings persisted
                // Strict, clones inherited it, and every phrase enrollment
                // then correctly rejected (multi-device e2e spike,
                // 2026-10-03). Creation now always saves settings, so this
                // branch only serves pre-save reads.
                crate::vault::manifest::EnrollmentPolicy::Personal,
            ),
            space_invite_authority: enc_fields
                .as_ref()
                .map(|e| e.space_invite_authority)
                .unwrap_or_default(),
            allow_viewer_export: enc_fields
                .as_ref()
                .map(|e| e.allow_viewer_export)
                .unwrap_or(false),
            guest_enabled: enc_fields.as_ref().and_then(|e| e.guest_enabled),
            trash_policy: enc_fields
                .as_ref()
                .map(|e| e.trash_policy)
                .unwrap_or_default(),
            restore_policy: enc_fields
                .as_ref()
                .map(|e| e.restore_policy)
                .unwrap_or_default(),
            join_approval: enc_fields
                .as_ref()
                .map(|e| e.join_approval)
                .unwrap_or_default(),
            quorum_admin_ops: enc_fields.as_ref().and_then(|e| e.quorum_admin_ops),
            collection_create_authority: enc_fields
                .as_ref()
                .map(|e| e.collection_create_authority)
                .unwrap_or_default(),
        })
    }

    /// Save vault settings using the split layout: theme+lang to plaintext
    /// settings-pub.json, everything else to encrypted settings.enc. Performs
    /// a one-time migration from legacy settings.json if it still exists.
    pub fn save_settings(
        &self,
        settings: &crate::vault::manifest::VaultSettings,
    ) -> Result<(), BaluardError> {
        let pub_path = self.path.join("meta/settings-pub.json");
        let enc_path = self.path.join("meta/settings.enc");

        // Public prefs (plaintext, pre-unlock). Merge with the existing
        // file so keys owned by other writers (the S2 space shape flag)
        // survive a settings save.
        let mut pub_json: serde_json::Value = std::fs::read_to_string(&pub_path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        pub_json["theme"] = serde_json::json!(settings.theme);
        pub_json["lang"] = serde_json::json!(settings.lang);
        let pub_str = serde_json::to_string_pretty(&pub_json)
            .map_err(|e| VaultError::Metadata(format!("settings-pub serialization: {e}")))?;
        super::write_vault_file(&pub_path, pub_str.as_bytes())?;

        // Encrypted settings (post-unlock only).
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => {
                // Locked save: only the public prefs can be persisted. This is
                // rare (settings.set is token-gated), but be safe.
                return Ok(());
            }
        };
        let enc_settings = crate::vault::manifest::EncryptedSettings {
            vault_timeout: settings.vault_timeout,
            default_uri_match: settings.default_uri_match,
            fetch_favicons: settings.fetch_favicons,
            slug: settings.slug.clone(),
            // C5: preserve the encrypted device-name map across rewrites —
            // VaultSettings does not carry it, so carry the stored value.
            device_names: {
                let names = self.device_display_names();
                if names.is_empty() { None } else { Some(names) }
            },
            enrollment_policy: settings.enrollment_policy,
            space_invite_authority: settings.space_invite_authority,
            allow_viewer_export: settings.allow_viewer_export,
            guest_enabled: settings.guest_enabled,
            trash_policy: settings.trash_policy,
            restore_policy: settings.restore_policy,
            join_approval: settings.join_approval,
            quorum_admin_ops: settings.quorum_admin_ops,
            collection_create_authority: settings.collection_create_authority,
            custom_equivalent_domains: settings.custom_equivalent_domains.clone(),
            suggest_app_logins: settings.suggest_app_logins,
            trusted_app_packages: settings.trusted_app_packages.clone(),
            rejected_app_packages: settings.rejected_app_packages.clone(),
        };
        let key = hkdf_derive::derive_settings_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("settings key derivation: {e}")))?;
        let json = serde_json::to_vec(&enc_settings)
            .map_err(|e| VaultError::Metadata(format!("settings.enc serialization: {e}")))?;
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;

        // One-time migration: drop the legacy plaintext settings.json now that
        // the split files are written. Identity fields already live in
        // profile.enc; nothing else remains here.
        let legacy = self.path.join("meta/settings.json");
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
        }
        Ok(())
    }

    /// Device display names from the encrypted settings map (audit C5).
    /// Empty map when the vault is locked or the file is absent. The
    /// registry file may briefly hold names pre-migration; this accessor is
    /// the post-unlock source of truth.
    pub fn device_display_names(&self) -> std::collections::HashMap<String, String> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return std::collections::HashMap::new(),
        };
        let enc_path = self.path.join("meta/settings.enc");
        if !enc_path.exists() {
            return std::collections::HashMap::new();
        }
        let Ok(key) = hkdf_derive::derive_settings_key(&unlocked.meta_ikm()) else {
            return std::collections::HashMap::new();
        };
        let Ok(data) = std::fs::read(&enc_path) else {
            return std::collections::HashMap::new();
        };
        let Ok(envelope) = crate::vault::envelope::deserialize(&data) else {
            return std::collections::HashMap::new();
        };
        let Ok(decrypted) = crate::crypto::aead::decrypt(&key, &envelope) else {
            return std::collections::HashMap::new();
        };
        serde_json::from_slice::<crate::vault::manifest::EncryptedSettings>(&decrypted)
            .ok()
            .and_then(|e| e.device_names)
            .unwrap_or_default()
    }

    /// Fold plaintext device display names from meta/devices.json into the
    /// encrypted settings map and strip them from the registry file
    /// (audit C5: devices.json is git-tracked; names are PII). Idempotent —
    /// re-runs re-fold names reintroduced by a legacy remote's registry
    /// during sync and then no-op. Best-effort callers may log and continue.
    pub fn migrate_device_names_into_settings(&self) -> Result<(), BaluardError> {
        // Requires the root key (settings.enc encryption). Pre-unlock is a
        // no-op; the next unlock retries.
        if !self.is_unlocked() {
            return Ok(());
        }
        let reg_path = self.path.join("meta/devices.json");
        let Some(reg_json) = std::fs::read_to_string(&reg_path).ok() else {
            return Ok(());
        };
        let Ok(mut reg) = serde_json::from_str::<crate::devices::DeviceRegistry>(&reg_json) else {
            // Corrupt registry: leave untouched; sync surfaces it elsewhere.
            return Ok(());
        };

        // Fold every non-empty name into the encrypted map and blank it.
        let mut names = self.device_display_names();
        let mut folded = false;
        for (id, entry) in reg.devices.iter_mut() {
            if !entry.name.is_empty() {
                names.insert(id.to_string(), std::mem::take(&mut entry.name));
                folded = true;
            }
        }
        if !folded {
            return Ok(()); // already clean: the common path after first run
        }

        // Persist the map first, then the stripped registry. A crash between
        // the two only causes a redundant re-fold on the next unlock.
        let settings = self.get_settings()?;
        let enc = crate::vault::manifest::EncryptedSettings {
            vault_timeout: settings.vault_timeout,
            default_uri_match: settings.default_uri_match,
            fetch_favicons: settings.fetch_favicons,
            slug: settings.slug.clone(),
            device_names: Some(names),
            enrollment_policy: settings.enrollment_policy,
            // The fold rewrite must carry every encrypted field or the
            // migration would silently wipe them (settings.enc is the
            // only store for these).
            space_invite_authority: settings.space_invite_authority,
            allow_viewer_export: settings.allow_viewer_export,
            guest_enabled: settings.guest_enabled,
            trash_policy: settings.trash_policy,
            restore_policy: settings.restore_policy,
            join_approval: settings.join_approval,
            quorum_admin_ops: settings.quorum_admin_ops,
            collection_create_authority: settings.collection_create_authority,
            custom_equivalent_domains: settings.custom_equivalent_domains.clone(),
            suggest_app_logins: settings.suggest_app_logins,
            trusted_app_packages: settings.trusted_app_packages.clone(),
            rejected_app_packages: settings.rejected_app_packages.clone(),
        };
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Ok(()),
        };
        let key = hkdf_derive::derive_settings_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("settings key derivation: {e}")))?;
        let json = serde_json::to_vec(&enc)
            .map_err(|e| VaultError::Metadata(format!("settings.enc serialization: {e}")))?;
        let enc_path = self.path.join("meta/settings.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;

        let stripped = reg
            .to_deterministic_json()
            .map_err(|e| VaultError::Metadata(format!("devices serialization: {e}")))?;
        super::write_vault_file(&reg_path, stripped.as_bytes())?;
        Ok(())
    }

    /// Load encrypted user profile from meta/profile.enc.
    /// Returns default (empty) profile if file doesn't exist yet.
    /// Falls back to reading identity fields from plaintext settings.json (legacy).
    pub fn load_profile(&self) -> Result<crate::vault::manifest::UserProfile, BaluardError> {
        let enc_path = self.path.join("meta/profile.enc");
        if enc_path.exists() {
            let unlocked = match &self.state {
                VaultState::Unlocked(u) => u,
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let key = hkdf_derive::derive_profile_key(&unlocked.meta_ikm())
                .map_err(|e| VaultError::Metadata(format!("profile key derivation: {e}")))?;
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let profile: crate::vault::manifest::UserProfile =
                serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("profile decrypt parse: {e}")))?;
            // Cleanup: strip stale identity fields from plaintext settings.json
            // (crash window: profile.enc written but settings.json not yet stripped)
            if let Ok(mut settings) = self.get_settings() {
                if settings.display_name.is_some()
                    || settings.subtitle.is_some()
                    || settings.avatar_ext.is_some()
                {
                    settings.display_name = None;
                    settings.subtitle = None;
                    settings.avatar_ext = None;
                    let _ = self.save_settings(&settings);
                }
            }
            return Ok(profile);
        }

        // Legacy fallback: extract identity fields from plaintext settings.json
        if let Ok(settings) = self.get_settings() {
            return Ok(crate::vault::manifest::UserProfile {
                display_name: settings.display_name,
                subtitle: settings.subtitle,
                avatar_ext: settings.avatar_ext,
            });
        }

        Ok(crate::vault::manifest::UserProfile {
            display_name: None,
            subtitle: None,
            avatar_ext: None,
        })
    }

    /// Save encrypted user profile to meta/profile.enc (atomic write).
    /// Does NOT modify settings.json. Caller is responsible for stripping
    /// identity fields from plaintext settings if needed.
    pub fn save_profile(
        &self,
        profile: &crate::vault::manifest::UserProfile,
    ) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_profile_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("profile key derivation: {e}")))?;
        let json = serde_json::to_vec(profile)
            .map_err(|e| VaultError::Metadata(format!("profile serialization: {e}")))?;
        let enc_path = self.path.join("meta/profile.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        Ok(())
    }

    /// Save profile AND strip identity fields from plaintext settings.json.
    /// Used by migration and crash-window cleanup where caller owns the settings state.
    pub fn save_profile_and_strip_settings(
        &self,
        profile: &crate::vault::manifest::UserProfile,
    ) -> Result<(), BaluardError> {
        self.save_profile(profile)?;
        let mut settings = self.get_settings().unwrap_or_default();
        settings.display_name = None;
        settings.subtitle = None;
        settings.avatar_ext = None;
        self.save_settings(&settings)?;
        Ok(())
    }

    // ── Locale ──

    /// Save plaintext locale to meta/locale.
    /// This file is readable before vault unlock (login screen needs language).
    /// Save the language pref to the plaintext settings-pub.json (the pre-unlock
    /// display-prefs file). Merges with any existing theme value so we don't
    /// clobber it. Replaces the old meta/locale sidecar (2026-06-26).
    pub fn save_locale(&self, lang: &str) -> Result<(), BaluardError> {
        let path = self.path.join("meta/settings-pub.json");
        // Merge with the existing pub prefs (theme, the S2 space shape
        // flag) instead of rebuilding the object.
        let mut json: serde_json::Value = std::fs::read_to_string(&path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        json["lang"] = serde_json::json!(lang);
        let body = serde_json::to_string_pretty(&json)
            .map_err(|e| VaultError::Metadata(format!("settings-pub serialization: {e}")))?;
        super::write_vault_file(&path, body.as_bytes())?;
        Ok(())
    }

    /// Load the language pref. Reads from settings-pub.json; falls back to the
    /// legacy meta/locale sidecar during migration.
    pub fn load_locale(&self) -> Option<String> {
        let pub_path = self.path.join("meta/settings-pub.json");
        if let Ok(data) = std::fs::read_to_string(&pub_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(s) = v.get("lang").and_then(|l| l.as_str()) {
                    return Some(s.trim().to_string());
                }
            }
        }
        // Legacy fallback.
        let legacy = self.path.join("meta/locale");
        std::fs::read_to_string(legacy)
            .ok()
            .map(|s| s.trim().to_string())
    }

    // ── Device Activity ──

    /// S1b-1: emit a share event (best-effort — never fails the parent
    /// operation).
    /// Member-email wave: the admin corrects a member's self-declared
    /// email. The field is delta-frozen after approval, so this admin
    /// route is the ONLY writer; the email stays strictly decorative.
    pub fn members_set_email(
        &mut self,
        member_id: Uuid,
        email: Option<&str>,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        self.assert_can_manage_members()?;
        let email = crate::vault::members::normalize_email(email)?;
        let mut row =
            crate::vault::members::member_file_by_id(&self.path, member_id).ok_or_else(|| {
                BaluardError::from(VaultError::NotFound(
                    "that member row does not exist".into(),
                ))
            })?;
        if row.email == email {
            return Ok(());
        }
        row.email = email;
        let path = self
            .path
            .join(crate::vault::members::MEMBERS_DIR)
            .join(format!("{}.json", row.id));
        crate::vault::write_vault_file(
            &path,
            serde_json::to_string_pretty(&row).unwrap().as_bytes(),
        )?;
        self.emit_share_event(
            crate::vault::events::ShareEventKind::MemberEmailChanged,
            format!("{}'s email was updated", row.display_name),
        );
        Ok(())
    }

    fn emit_share_event(
        &self,
        kind: crate::vault::events::ShareEventKind,
        detail: impl Into<String>,
    ) {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return,
        };
        let _ = crate::vault::events::append(
            &self.path,
            self.vault_id,
            &unlocked.meta_ikm(),
            unlocked.current_epoch,
            kind,
            detail,
        );
    }

    /// S1b-1: the Activity surface — up to `limit` most recent sharing
    /// events in CHRONOLOGICAL order (oldest first at index 0). Errors
    /// propagate (corrupt log = tamper, fail closed).
    pub fn share_events(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::vault::events::ShareEvent>, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let unlocked = self.unlocked();
        let mut events =
            crate::vault::events::load(&self.path, self.vault_id, &unlocked.meta_ikm())?;
        if events.len() > limit {
            let drop = events.len() - limit;
            events.drain(..drop);
        }
        Ok(events)
    }

    /// S1b-1: this device's local refusal log — human lines recording
    /// commits THIS client refused during verification (policy or
    /// roster layer). Local-only by design: each client records what it
    /// saw. Chronological order (oldest first), capped like the log
    /// itself.
    pub fn refusal_log(&self, limit: usize) -> Vec<String> {
        let path = self.path.join("meta/refusals.log");
        let Ok(data) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let mut lines: Vec<String> = data.lines().map(|l| l.to_string()).collect();
        if lines.len() > limit {
            let drop = lines.len() - limit;
            lines.drain(..drop);
        }
        lines
    }

    /// Load encrypted device activity index from meta/activity.enc.
    /// Falls back to plaintext meta/device_activity.json (legacy).
    pub fn load_activity_enc(
        &self,
    ) -> Result<crate::device_manager::DeviceActivityIndex, BaluardError> {
        // Sync engine writes plaintext device_activity.json after every commit.
        // If it exists, re-encrypt it (fresh data) before reading .enc.
        let json_path = self.path.join("meta/device_activity.json");
        if json_path.exists() {
            let fresh = crate::device_manager::DeviceActivityIndex::read(&self.path);
            if !fresh.devices.is_empty() {
                let _ = self.save_activity_enc(&fresh);
            }
            return Ok(fresh);
        }

        let enc_path = self.path.join("meta/activity.enc");
        if enc_path.exists() {
            let unlocked = match &self.state {
                VaultState::Unlocked(u) => u,
                VaultState::Locked => return Err(VaultError::Locked.into()),
            };
            let key = hkdf_derive::derive_activity_key(unlocked.root()?.as_bytes())
                .map_err(|e| VaultError::Metadata(format!("activity key derivation: {e}")))?;
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let index: crate::device_manager::DeviceActivityIndex =
                serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("activity decrypt parse: {e}")))?;
            return Ok(index);
        }
        // No data at all
        Ok(crate::device_manager::DeviceActivityIndex::new())
    }

    /// Save encrypted device activity index to meta/activity.enc (atomic write).
    /// Does NOT modify plaintext device_activity.json (sync engine may still write it).
    fn save_activity_enc(
        &self,
        index: &crate::device_manager::DeviceActivityIndex,
    ) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_activity_key(unlocked.root()?.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("activity key derivation: {e}")))?;
        let json = serde_json::to_vec(index)
            .map_err(|e| VaultError::Metadata(format!("activity serialization: {e}")))?;
        let enc_path = self.path.join("meta/activity.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        // Remove legacy plaintext
        let json_path = self.path.join("meta/device_activity.json");
        if json_path.exists() {
            let _ = std::fs::remove_file(&json_path);
        }
        Ok(())
    }

    // ── Generator History ──

    /// Maximum stored entries (FIFO cap).
    const MAX_GENERATOR_HISTORY: usize = 100;
    /// Maximum entries returned to UI.
    const DISPLAY_GENERATOR_HISTORY: usize = 67;

    /// Load encrypted generator history from meta/generator-history.enc.
    /// Returns empty vec if file doesn't exist yet.
    pub fn load_generator_history(
        &self,
    ) -> Result<Vec<crate::types::GeneratorHistoryEntry>, BaluardError> {
        let enc_path = self.path.join("meta/generator-history.enc");
        if !enc_path.exists() {
            return Ok(vec![]);
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_generator_history_key(unlocked.root()?.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("generator history key derivation: {e}")))?;
        let data = std::fs::read(&enc_path)?;
        let envelope = crate::vault::envelope::deserialize(&data)?;
        let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
        let entries: Vec<crate::types::GeneratorHistoryEntry> = serde_json::from_slice(&decrypted)
            .map_err(|e| VaultError::Metadata(format!("generator history decrypt parse: {e}")))?;
        Ok(entries)
    }

    /// Append a generator history entry, enforce FIFO cap, persist.
    /// Returns the updated list (capped to DISPLAY_GENERATOR_HISTORY).
    pub fn add_generator_history_entry(
        &self,
        entry: crate::types::GeneratorHistoryEntry,
    ) -> Result<Vec<crate::types::GeneratorHistoryEntry>, BaluardError> {
        let mut history = self.load_generator_history()?;
        history.push(entry);
        // FIFO cap: trim oldest
        if history.len() > Self::MAX_GENERATOR_HISTORY {
            history.drain(0..history.len() - Self::MAX_GENERATOR_HISTORY);
        }
        self.save_generator_history(&history)?;
        // Return display-capped slice (latest first)
        let display = Self::display_slice(&history);
        Ok(display)
    }

    /// Clear all generator history (deletes the encrypted file).
    pub fn clear_generator_history(&self) -> Result<(), BaluardError> {
        let enc_path = self.path.join("meta/generator-history.enc");
        if enc_path.exists() {
            std::fs::remove_file(&enc_path)?;
        }
        Ok(())
    }

    /// Get latest DISPLAY_GENERATOR_HISTORY entries (newest first).
    pub fn list_generator_history_display(
        &self,
    ) -> Result<Vec<crate::types::GeneratorHistoryEntry>, BaluardError> {
        let history = self.load_generator_history()?;
        Ok(Self::display_slice(&history))
    }

    /// Merge histories from two sync sides by timestamp, dedupe, cap at MAX.
    /// Returns merged list sorted newest-first.
    ///
    /// **Not yet wired into the sync engine.** Currently, `generator-history.enc`
    /// is treated as an opaque AEAD blob by git merge (last-writer-wins on
    /// binary conflict). This function is kept as a utility for when the sync
    /// engine gains a decrypt-merge-reencrypt path for vault metadata files.
    pub fn merge_generator_history(
        local: &[crate::types::GeneratorHistoryEntry],
        remote: &[crate::types::GeneratorHistoryEntry],
    ) -> Vec<crate::types::GeneratorHistoryEntry> {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        let mut merged: Vec<crate::types::GeneratorHistoryEntry> = Vec::new();
        // Interleave newest-first
        let mut all: Vec<&crate::types::GeneratorHistoryEntry> =
            local.iter().chain(remote.iter()).collect();
        all.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        for entry in all {
            let key = (entry.value.clone(), entry.created_at);
            if seen.insert(key) {
                merged.push(entry.clone());
            }
            if merged.len() >= Self::MAX_GENERATOR_HISTORY {
                break;
            }
        }
        merged
    }

    /// Save generator history to meta/generator-history.enc (atomic write).
    fn save_generator_history(
        &self,
        entries: &[crate::types::GeneratorHistoryEntry],
    ) -> Result<(), BaluardError> {
        if entries.is_empty() {
            return self.clear_generator_history();
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_generator_history_key(unlocked.root()?.as_bytes())
            .map_err(|e| VaultError::Metadata(format!("generator history key derivation: {e}")))?;
        let json = serde_json::to_vec(entries)
            .map_err(|e| VaultError::Metadata(format!("generator history serialization: {e}")))?;
        let enc_path = self.path.join("meta/generator-history.enc");
        self.encrypt_and_write_meta(&key, &json, &enc_path, unlocked.current_epoch)?;
        Ok(())
    }

    /// Return the display-capped slice of history (newest first).
    fn display_slice(
        history: &[crate::types::GeneratorHistoryEntry],
    ) -> Vec<crate::types::GeneratorHistoryEntry> {
        let start = history
            .len()
            .saturating_sub(Self::DISPLAY_GENERATOR_HISTORY);
        let mut slice: Vec<_> = history[start..].to_vec();
        slice.reverse(); // newest first
        slice
    }

    // ── Folder CRUD ──

    /// List all folders. P5b per-fact layout: one encrypted file per folder
    /// (`meta/folders/<uuid>.enc`). Falls back to the legacy single-envelope
    /// `meta/folders.enc`, then plaintext `folders.json` (migration on next
    /// save).
    pub fn list_folders(&self) -> Result<Vec<crate::vault::manifest::Folder>, BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_folders_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("folders key derivation: {e}")))?;

        // Per-fact layout: one file per folder, sorted by id for stable order.
        // Foreign entries (temp files, dotfiles, junk) are skipped with a
        // warning; reads NEVER delete anything — legacy migration happens on
        // write only. An empty/invalid per-fact dir falls through to the
        // legacy file rather than wiping it.
        let dir = self.path.join("meta/folders");
        if dir.exists() {
            let mut folders = Vec::new();
            let mut saw_valid_file = false;
            for entry in std::fs::read_dir(&dir)
                .map_err(|e| VaultError::Metadata(format!("folders listing: {e}")))?
            {
                let entry =
                    entry.map_err(|e| VaultError::Metadata(format!("folders read: {e}")))?;
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.') || !entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                {
                    continue;
                }
                if path.extension().map(|e| e != "enc").unwrap_or(true) {
                    continue;
                }
                let stem_ok = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<Uuid>().ok())
                    .is_some();
                if !stem_ok {
                    continue;
                }
                saw_valid_file = true;
                let data = std::fs::read(&path)?;
                let envelope = crate::vault::envelope::deserialize(&data)?;
                let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
                let folder: crate::vault::manifest::Folder = serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("folder decrypt parse: {e}")))?;
                folders.push(folder);
            }
            if saw_valid_file {
                folders.sort_by_key(|f| f.id);
                return Ok(folders);
            }
            // Zero valid files → treat as no per-fact layout; legacy below.
        }

        // Legacy single-envelope fallback.
        let enc_path = self.path.join("meta/folders.enc");
        if enc_path.exists() {
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let folders: Vec<crate::vault::manifest::Folder> =
                serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("folders decrypt parse: {e}")))?;
            // Cleanup stale plaintext if encrypted version decrypts cleanly
            let _ = std::fs::remove_file(self.path.join("meta/folders.json"));
            return Ok(folders);
        }
        // Legacy fallback: plaintext folders.json
        let json_path = self.path.join("meta/folders.json");
        if json_path.exists() {
            let data = std::fs::read_to_string(&json_path)?;
            let folders: Vec<crate::vault::manifest::Folder> = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("folders parse: {e}")))?;
            return Ok(folders);
        }
        Ok(Vec::new())
    }

    /// Save folders to disk (P5b per-fact layout: one encrypted file per
    /// folder). Skip-if-unchanged: an identical folder entry is NOT rewritten
    /// (random nonces would otherwise churn every file on every mutation —
    /// the multi-writer conflict pattern P5 exists to kill). Orphaned files
    /// from deleted folders are pruned. The legacy single-envelope and
    /// plaintext files are removed once per-fact files exist.
    fn save_folders(&self, folders: &[crate::vault::manifest::Folder]) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_folders_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("folders key derivation: {e}")))?;
        let dir = self.path.join("meta/folders");
        std::fs::create_dir_all(&dir)?;

        for folder in folders {
            let json = serde_json::to_vec(folder)
                .map_err(|e| VaultError::Metadata(format!("folder serialization: {e}")))?;
            let path = dir.join(format!("{}.enc", folder.id));
            let changed = match std::fs::read(&path) {
                Ok(bytes) => match crate::vault::envelope::deserialize(&bytes)
                    .map_err(BaluardError::from)
                    .and_then(|envelope| {
                        crate::crypto::aead::decrypt(&key, &envelope).map_err(BaluardError::from)
                    }) {
                    Ok(existing) => existing != json,
                    Err(_) => true, // corrupt — rewrite
                },
                Err(_) => true, // new folder
            };
            if changed {
                self.encrypt_and_write_meta(&key, &json, &path, unlocked.current_epoch)?;
            }
        }

        // Prune files whose folder no longer exists.
        let keep: std::collections::HashSet<Uuid> = folders.iter().map(|f| f.id).collect();
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| VaultError::Metadata(format!("folders prune listing: {e}")))?
        {
            let entry = entry.map_err(|e| VaultError::Metadata(format!("folders prune: {e}")))?;
            let stem = entry
                .path()
                .file_stem()
                .map(|s| s.to_string_lossy().to_string());
            if let Ok(id) = stem.as_deref().unwrap_or("").parse::<Uuid>() {
                if !keep.contains(&id) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        // Migration: the per-fact dir is authoritative now; drop the legacy
        // single-envelope and any stale plaintext.
        let _ = std::fs::remove_file(self.path.join("meta/folders.enc"));
        let _ = std::fs::remove_file(self.path.join("meta/folders.json"));
        Ok(())
    }

    /// Create a new folder.
    pub fn create_folder(&mut self, name: &str) -> Result<Uuid, BaluardError> {
        self.create_folder_with_parent(name, None)
    }

    /// Maximum folder nesting depth.
    const MAX_FOLDER_DEPTH: usize = 16;

    /// Create a new folder with optional parent.
    pub fn create_folder_with_parent(
        &mut self,
        name: &str,
        parent_id: Option<Uuid>,
    ) -> Result<Uuid, BaluardError> {
        if name.trim().is_empty() {
            return Err(
                crate::error::VaultError::Metadata("folder name cannot be empty".into()).into(),
            );
        }
        let trimmed = name.trim();
        let mut folders = self.list_folders()?;
        // Check for duplicate name within the same parent
        if folders
            .iter()
            .any(|f| f.name == trimmed && f.parent_id == parent_id)
        {
            return Err(crate::error::VaultError::Metadata(format!(
                "folder '{trimmed}' already exists"
            ))
            .into());
        }
        // Validate parent exists and check depth
        if let Some(pid) = parent_id {
            if !folders.iter().any(|f| f.id == pid) {
                return Err(
                    crate::error::VaultError::Metadata("parent folder not found".into()).into(),
                );
            }
            // Walk parent chain to check depth
            let mut depth = 1;
            let mut current = pid;
            while let Some(parent) = folders.iter().find(|f| f.id == current) {
                match parent.parent_id {
                    Some(gp) => {
                        depth += 1;
                        current = gp;
                    }
                    None => break,
                }
                if depth >= Self::MAX_FOLDER_DEPTH {
                    return Err(crate::error::VaultError::Metadata(format!(
                        "folder nesting too deep (max {})",
                        Self::MAX_FOLDER_DEPTH
                    ))
                    .into());
                }
            }
        }
        let id = Uuid::new_v4();
        folders.push(crate::vault::manifest::Folder {
            id,
            name: trimmed.to_string(),
            parent_id,
            icon: None,
        });
        self.save_folders(&folders)?;
        Ok(id)
    }

    /// Rename a folder by ID.
    pub fn rename_folder(&mut self, folder_id: Uuid, new_name: &str) -> Result<(), BaluardError> {
        if new_name.trim().is_empty() {
            return Err(
                crate::error::VaultError::Metadata("folder name cannot be empty".into()).into(),
            );
        }
        let mut folders = self.list_folders()?;
        let folder = folders
            .iter_mut()
            .find(|f| f.id == folder_id)
            .ok_or_else(|| {
                BaluardError::from(crate::error::VaultError::NotFound(format!(
                    "folder {folder_id}"
                )))
            })?;
        folder.name = new_name.trim().to_string();
        self.save_folders(&folders)?;
        Ok(())
    }

    /// Delete a folder by ID. Cascades to child folders.
    /// All ciphers with this folder_id (or any child's) become unassigned.
    pub fn delete_folder(&mut self, folder_id: Uuid) -> Result<(), BaluardError> {
        // Collect this folder + all descendants
        let all_folders = self.list_folders()?;
        let ids_to_delete = collect_descendant_ids(folder_id, &all_folders);

        if !all_folders.iter().any(|f| f.id == folder_id) {
            return Err(BaluardError::from(crate::error::VaultError::NotFound(
                format!("folder {folder_id}"),
            )));
        }

        // Remove all collected folders (persist only after cipher unassignment succeeds)
        let mut folders = all_folders;
        folders.retain(|f| !ids_to_delete.contains(&f.id));

        // Unassign all ciphers in any of the deleted folders
        let cipher_ids = self.list_cipher_ids()?;
        for cipher_id in cipher_ids {
            let file_path = self.path.join(format!("ciphers/{cipher_id}.enc"));
            if !file_path.exists() {
                continue;
            }
            let existing_bytes = std::fs::read(&file_path)?;
            let existing_file = cipher::CipherFile {
                id: cipher_id,
                envelope_bytes: existing_bytes,
            };
            let _existing_envelope =
                crate::vault::envelope::deserialize(&existing_file.envelope_bytes)?;
            let existing_cipher = {
                let unlocked = match &self.state {
                    VaultState::Unlocked(u) => u,
                    VaultState::Locked => return Err(VaultError::Locked.into()),
                };
                // S3-7c: skip ciphers this device cannot resolve (a member
                // device cannot read personal-flat ciphers; the owning
                // device converges the folder unassignment for those).
                match self.try_decrypt_cipher_at(unlocked, &file_path, &existing_file) {
                    Ok(c) => c,
                    Err(_) => continue,
                }
            };

            if existing_cipher
                .folder_id
                .is_some_and(|fid| ids_to_delete.contains(&fid))
            {
                // Reuse update_cipher to maintain all invariants (history, timestamps, etc.)
                let input = CipherInput {
                    name: existing_cipher.name.clone(),
                    folder_id: None, // unassign
                    collection_id: None,
                    kind: existing_cipher.kind.clone(),
                    favorite: existing_cipher.favorite,
                    reprompt: existing_cipher.reprompt,
                    notes: existing_cipher.notes.clone(),
                    custom_fields: existing_cipher.custom_fields.clone(),
                    created_at: Some(existing_cipher.created_at),
                    password_history: existing_cipher.password_history.clone(),
                    attachments: existing_cipher.attachments.clone(),
                    archived: existing_cipher.archived,
                    tags: existing_cipher.tags.clone(),
                };
                self.update_cipher(cipher_id, &input)?;
            }
        }

        // NOW remove folder from index (after all ciphers unassigned successfully)
        self.save_folders(&folders)?;

        Ok(())
    }

    /// List cipher IDs from filenames in ciphers/ directory.
    /// The on-disk path for an active cipher file: the personal flat
    /// path, or the collection-scoped directory when the entry was
    /// assigned to a salted collection (plan P5). Trash is not probed
    /// here; callers handle trash separately.
    pub fn cipher_file_path(&self, cipher_id: Uuid) -> Option<std::path::PathBuf> {
        let flat = self.path.join(format!("ciphers/{cipher_id}.enc"));
        if flat.exists() {
            return Some(flat);
        }
        let dirs = crate::vault::collections::load_dir_map(&self.path);
        for (d, _) in &dirs {
            let p = self.path.join(format!("ciphers/{d}/{cipher_id}.enc"));
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// Assign (or unassign) a live cipher to a collection by MOVING its
    /// file to the collection's scoped directory (plan P5: the path is
    /// the on-disk source of truth for membership, so the policy table
    /// can bind writes to collections). Trash is not assignable.
    pub fn assign_cipher_to_collection(
        &mut self,
        cipher_id: Uuid,
        collection_id: Option<Uuid>,
    ) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        // S3-7c review F7: resolve the target from the plaintext dir map —
        // no SGK needed, so granted members can move ciphers between
        // collections. A flat target stays admin-surface.
        let target_rel = match collection_id {
            Some(cid) => {
                let dirs = crate::vault::collections::load_dir_map(&self.path);
                let dir_name = dirs
                    .iter()
                    .find(|(_, id)| *id == cid)
                    .map(|(d, _)| d.clone())
                    .ok_or_else(|| {
                        VaultError::InvalidOperation("That collection no longer exists.".into())
                    })?;
                format!("ciphers/{dir_name}/{cipher_id}.enc")
            }
            None => format!("ciphers/{cipher_id}.enc"),
        };
        let Some(current) = self.cipher_file_path(cipher_id) else {
            // A trashed (or unknown) cipher cannot move.
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        };
        // Write-scope gate (plan §4.4): a commit the local device cannot
        // authorize would be refused at pull time on every peer and wedge
        // the vault's sync, so the move is refused here, before any
        // commit exists. Owner/Admin bypass (structural access); a move
        // out of a collection needs write scope on the SOURCE collection
        // too — membership changes are collection writes in both
        // directions.
        // S3-7c review F7: one shared gate for both ends — a move is a
        // collection write on the SOURCE and the TARGET (membership
        // changes are collection writes in both directions). The gate
        // reads plaintext grant rows, so member devices run it too.
        let is_admin = matches!(
            crate::vault::members::member_role_for_device(&self.path, self.device_id),
            Some(crate::vault::members::MemberRole::Owner)
                | Some(crate::vault::members::MemberRole::Admin)
        );
        if !is_admin {
            // Source-side: a nested path means the cipher currently lives
            // in a collection dir; a flat source is the admin surface and
            // the target-key derivation refuses members anyway.
            let source_cid = current
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|d| d.to_str())
                .and_then(|d| {
                    crate::vault::collections::load_dir_map(&self.path)
                        .into_iter()
                        .find(|(name, _)| name == d)
                        .map(|(_, id)| id)
                });
            if let Some(src) = source_cid {
                self.assert_collection_write(&src)?;
            }
            if let Some(dst) = collection_id {
                self.assert_collection_write(&dst)?;
            }
        }
        let target = self.path.join(target_rel);
        if current == target {
            return Ok(());
        }
        // S3-7c: the path IS the key domain. A cross-domain move must
        // re-encrypt under the target domain's item key (same envelope
        // epoch, seq bumped): SGK-keyed bytes dropped into a collection
        // dir would be unreadable for everyone but admins, and
        // CK-keyed bytes restored to flat would be unreadable at all.
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&current)?,
        };
        let existing = self.try_decrypt_cipher_at(unlocked, &current, &existing_file)?;
        let existing_envelope = crate::vault::envelope::deserialize(&existing_file.envelope_bytes)?;
        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            collection_id: None,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: Some(existing.created_at),
            password_history: existing.password_history,
            attachments: existing.attachments,
            archived: existing.archived,
            tags: existing.tags.clone(),
        };
        let target_item_key = self.resolve_item_key(
            unlocked,
            &target,
            cipher_id,
            existing_envelope.header.key_epoch,
        )?;
        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input,
            &target_item_key,
            existing_envelope.header.key_epoch,
            existing_envelope.header.update_seq + 1,
        )?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        super::write_vault_file(&target, &file.envelope_bytes)?;
        std::fs::remove_file(&current)?;
        self.rebuild_index()?;
        self.record_integrity(
            &cipher_id.to_string(),
            existing_envelope.header.update_seq + 1,
        );
        Ok(())
    }

    /// Cipher ids this device can actually resolve: everything for an
    /// admin (or pre-flip) device; only wrap-covered collection ciphers
    /// for a flipped member. Review F4: the heal/rebuild scan set MUST
    /// equal the staleness scan set, or every list re-heals forever.
    fn scannable_cipher_ids(&self, unlocked: &UnlockedState) -> Result<Vec<Uuid>, BaluardError> {
        if unlocked.holds_root() {
            return self.list_cipher_ids();
        }
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id);
        let mut ids = Vec::new();
        for (dir, cid) in crate::vault::collections::load_dir_map(&self.path) {
            let wrap_covers = member_id.is_some_and(|m| {
                crate::vault::collections::grant_wrap_path(&self.path, &cid, &m).exists()
            });
            if wrap_covers {
                ids.extend(self.list_cipher_ids_in_dir(&dir)?);
            }
        }
        Ok(ids)
    }

    /// S3-7c / 4.8: fill each meta's collection id from the on-disk
    /// path (index contents can predate the field). Review F6: one
    /// dir-map parse per list and one stat per unresolved meta — never
    /// per-cipher directory scans. Flat ciphers stay None (correct:
    /// they have no collection).
    fn fill_collection_ids(&self, metas: &mut [crate::types::CipherMeta]) {
        let dirs = crate::vault::collections::load_dir_map(&self.path);
        if dirs.is_empty() {
            return;
        }
        for meta in metas.iter_mut() {
            if meta.collection_id.is_some() {
                continue;
            }
            for (dir, cid) in &dirs {
                if self
                    .path
                    .join(format!("ciphers/{dir}/{}.enc", meta.id))
                    .exists()
                {
                    meta.collection_id = Some(*cid);
                    break;
                }
            }
        }
    }

    /// Cipher ids inside one collection directory (`ciphers/<dir>/`).
    pub fn list_cipher_ids_in_dir(&self, dir: &str) -> Result<Vec<Uuid>, BaluardError> {
        let dir_path = self.path.join("ciphers").join(dir);
        if !dir_path.is_dir() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for inner in std::fs::read_dir(&dir_path)?.flatten() {
            if let Some(id_str) = inner.file_name().to_string_lossy().strip_suffix(".enc") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    pub fn list_cipher_ids(&self) -> Result<Vec<Uuid>, BaluardError> {
        let ciphers_dir = self.path.join("ciphers");
        if !ciphers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut ids = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let push = |ids: &mut Vec<Uuid>, seen: &mut std::collections::HashSet<Uuid>, raw: &str| {
            if let Some(id_str) = raw.strip_suffix(".enc") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    // The same UUID can exist both flat and in a
                    // collection dir (a grantee can plant a copy); the
                    // index must list it once.
                    if seen.insert(id) {
                        ids.push(id);
                    }
                }
            }
        };
        for entry in std::fs::read_dir(&ciphers_dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.path().is_dir() {
                // Collection-scoped directory: recurse one level.
                for inner in std::fs::read_dir(entry.path())?.flatten() {
                    let inner_name = inner.file_name().to_string_lossy().to_string();
                    push(&mut ids, &mut seen, &inner_name);
                }
                continue;
            }
            push(&mut ids, &mut seen, &name);
        }
        Ok(ids)
    }

    /// List cipher metadata (requires unlocked vault for full CipherMeta).
    /// Decrypts from index.enc if available, otherwise auto-heals by scanning directory.
    /// List cipher metadata (non-archived only). Requires unlocked vault.
    /// Decrypts from index.enc if available, otherwise auto-heals.
    pub fn list_cipher_meta(&self) -> Result<Vec<crate::types::CipherMeta>, BaluardError> {
        Ok(self
            .list_cipher_meta_full()?
            .into_iter()
            .filter(|m| !m.archived)
            .collect())
    }

    /// List ALL cipher metadata (including archived). Exposed for export, health, and sync.
    pub fn list_cipher_meta_full(&self) -> Result<Vec<crate::types::CipherMeta>, BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // S3-7c: member devices list only what they can resolve — ciphers
        // inside collections they hold a wrap for. The staleness scan and
        // the heal both use that scope; personal-flat ciphers are invisible.
        let scan_ids = self.scannable_cipher_ids(unlocked)?;
        let member_scope: Option<std::collections::HashSet<Uuid>> = if unlocked.holds_root() {
            None
        } else {
            Some(scan_ids.iter().copied().collect())
        };

        // Try reading from the (possibly sharded) index. Missing or corrupt
        // shards → None → auto-heal rebuild below.
        if let Ok(index_key) = crate::crypto::hkdf_derive::derive_index_key(&unlocked.meta_ikm()) {
            if let Some((ciphers, skipped)) =
                index::read_sharded(self.vault_id, &self.path.join("meta"), &index_key)
            {
                // P5b staleness guard: the index is local-only, and pulled
                // ciphers land on disk without touching it. A cheap directory
                // scan detects disk/index divergence — SET equality, not just
                // counts (an add+delete swap keeps counts equal). On mismatch
                // fall through to the auto-heal rebuild instead of showing a
                // stale list. S3-7c: a member compares against its own
                // readable scope, not the whole disk.
                let scan: Result<Vec<Uuid>, BaluardError> = match &member_scope {
                    Some(set) => Ok(set.iter().copied().collect()),
                    None => self.list_cipher_ids(),
                };
                match scan {
                    Ok(mut disk_ids) => {
                        let mut indexed: Vec<uuid::Uuid> = ciphers
                            .iter()
                            .map(|m| m.id)
                            .chain(skipped.iter().copied())
                            .collect();
                        disk_ids.sort_unstable();
                        indexed.sort_unstable();
                        if disk_ids == indexed {
                            let mut metas = ciphers;
                            self.fill_collection_ids(&mut metas);
                            return Ok(metas);
                        }
                    }
                    // Cannot scan — trust the index rather than showing nothing.
                    Err(_) => {
                        let mut metas = ciphers;
                        self.fill_collection_ids(&mut metas);
                        return Ok(metas);
                    }
                }
            }
        }
        // Review F4: scan the SAME id set the staleness guard compared
        // against, so the rebuilt index matches on the next read.
        let ids = if unlocked.holds_root() {
            self.list_cipher_ids()?
        } else {
            scan_ids.clone()
        };
        let dirs = crate::vault::collections::load_dir_map(&self.path);
        let mut metas = Vec::with_capacity(ids.len());
        let mut skipped: Vec<uuid::Uuid> = Vec::new();

        for id in ids {
            let Some(file_path) = self.cipher_file_path(id) else {
                continue;
            };
            let file_dir = file_path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(|n| n.to_string());
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile { id, envelope_bytes };

            let c = match self.try_decrypt_cipher_at(unlocked, &file_path, &file) {
                Ok(c) => c,
                Err(crate::error::BaluardError::Vault(crate::error::VaultError::CrossEpoch {
                    envelope_epoch,
                    held_epoch,
                })) => {
                    // Cipher at a key epoch the held RootKey/SGK cannot reach.
                    // Previously this was silently `continue`d, which made the
                    // entry vanish from vault.list with no signal. Surface it
                    // so the user knows a re-sync / device refresh is needed
                    // (B-2 fix). Still skip rather than fail the whole list —
                    // a vault with one stray remote blob should still render.
                    eprintln!(
                        "warning: cipher {id} at epoch {envelope_epoch} cannot be decrypted with held epoch {held_epoch}; skipping from index",
                    );
                    skipped.push(id);
                    continue;
                }
                Err(e) => {
                    // Genuine corrupt envelope / IO error: log and skip rather
                    // than abort the whole index (graceful degradation), but
                    // keep this path noisy so it does not hide silent loss.
                    eprintln!("warning: cipher {id} skipped during index build: {e}");
                    skipped.push(id);
                    continue;
                }
            };

            let username = match &c.kind {
                crate::types::CipherKind::Login(data) => data.username.clone(),
                _ => None,
            };

            metas.push(crate::types::CipherMeta {
                id: c.id,
                name: c.name,
                folder_id: c.folder_id,
                cipher_type: c.kind.cipher_type(),
                favorite: c.favorite,
                reprompt: c.reprompt,
                username,
                tier: c.tier,
                key_epoch: c.key_epoch,
                update_seq: c.update_seq,
                updated_at: c.updated_at,
                archived: c.archived,
                tags: c.tags.clone(),
                collection_id: dirs
                    .iter()
                    .find(|(name, _)| Some(name) == file_dir.as_ref())
                    .map(|(_, id)| *id),
            });
        }

        // Save healed index (P5b: sharded, like rebuild_index)
        if let Ok(index_key) = crate::crypto::hkdf_derive::derive_index_key(&unlocked.meta_ikm()) {
            let index_dir = self.path.join("meta");
            let _ = index::write_sharded(
                self.vault_id,
                &metas,
                &index_key,
                unlocked.current_epoch,
                &index_dir,
                &skipped,
            );
        }

        Ok(metas)
    }

    /// P3: adopt this device's fresh Root Key wrap from the committed rekey
    /// transaction for the CURRENT epoch (`meta/rekey/<epoch>.txn`).
    ///
    /// A survivor of a rotation committed by another device holds a stale
    /// (revocation flow) keywrap; the transaction distributed with the
    /// rotation carries an HPKE wrap of the new Root Key for every remaining
    /// enrolled device. Adoption is epoch-bound (file name == transaction
    /// epoch == current canary epoch) and fail-closed: any mismatch returns
    /// None and the original unlock error stands.
    fn adopt_rekey_txn_root(&self, devkey_seal: &[u8; 32]) -> Option<RootKey> {
        let epoch = self.determine_current_epoch();
        if epoch == 0 {
            return None;
        }
        // S3-7b: on a team-shape vault a member device must never adopt
        // Root Key material, even from a stale pre-flip transaction.
        if crate::vault::space_meta::shape_flipped(&self.path)
            && !self.device_maps_to_admin(self.device_id)
        {
            return None;
        }
        let txn_path = self.path.join(format!("meta/rekey/{epoch}.txn"));
        let txn_json = std::fs::read_to_string(&txn_path).ok()?;
        let tx: crate::keys::rotation::RekeyTransaction = serde_json::from_str(&txn_json).ok()?;
        if tx.new_epoch != epoch {
            return None;
        }
        let entry = tx
            .wrapped_root_keys
            .iter()
            .find(|e| e.device_id == self.device_id)?;
        let privs = load_device_privkeys(&self.path, self.device_id, Some(devkey_seal)).ok()?;
        let unwrapped = hpke_wrap::unwrap_key(
            &entry.ephemeral_public,
            &entry.encrypted_key,
            &entry.tag,
            &privs.x25519,
            &format!("keywrap:rotation:{epoch}"),
        )
        .ok()?;
        let rk_bytes: [u8; 64] = unwrapped.try_into().ok()?;
        let rk = RootKey::from_bytes(rk_bytes);
        self.verify_root_key(&rk).ok()?;

        // Persist the adopted wrap so the next unlock takes the fast path.
        // Re-wrap the root key under "root-key-keywrap" so attempt_unwrap
        // can decrypt it without requiring meta/rekey/<epoch>.txn.
        let pub_x25519 = x25519_dalek::PublicKey::from(&privs.x25519);
        let (eph_pub, ct, tag) =
            hpke_wrap::wrap_key(rk.as_bytes(), &pub_x25519, "root-key-keywrap").ok()?;
        let kw = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        super::write_vault_file(
            &self
                .path
                .join(format!("meta/keywrap/{}.json", self.device_id)),
            serde_json::to_string_pretty(&kw).unwrap().as_bytes(),
        )
        .ok()?;
        Some(rk)
    }

    /// Verify root key by decrypting the Root Key canary.
    /// The canary is stored at vault creation as AES-256-GCM("baluard-rk-ok")
    /// encrypted with a key derived from Root Key.
    fn verify_root_key(&self, root_key: &RootKey) -> Result<(), BaluardError> {
        let canary_path = self.path.join("meta/rk-canary.enc");
        if !canary_path.exists() {
            // No canary (legacy vault). Fall back to first-cipher check.
            return self.verify_root_key_fallback(root_key);
        }

        let canary_data = std::fs::read(&canary_path)
            .map_err(|e| VaultError::Metadata(format!("reading rk canary: {e}")))?;
        super::canary::verify_rk_canary(root_key, &canary_data)?;
        Ok(())
    }

    /// Fallback: verify root key by decrypting the first existing cipher.
    /// Only used for legacy vaults without `meta/rk-canary.enc`.
    fn verify_root_key_fallback(&self, root_key: &RootKey) -> Result<(), BaluardError> {
        let cipher_ids = self.list_cipher_ids()?;
        if cipher_ids.is_empty() {
            // Empty vault with no RK canary: cannot verify root key.
            // Refuse unlock rather than accept any key silently.
            return Err(VaultError::Corrupt(
                "vault has no ciphers and no root key canary. Re-initialize vault.".into(),
            )
            .into());
        }

        // S3-7c review F11: the Root Key verifies flat ciphers directly
        // and collection ciphers via the SGK unwrap of the collection's
        // content key. Scan until one canary decrypts; a wrong password
        // fails everything.
        let epoch = self.determine_current_epoch();
        let sgk = crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(root_key, epoch);
        for canary_id in &cipher_ids {
            let Some(file_path) = self.cipher_file_path(*canary_id) else {
                continue;
            };
            let Ok(envelope_bytes) = std::fs::read(&file_path) else {
                continue;
            };
            let file = crate::vault::cipher::CipherFile {
                id: *canary_id,
                envelope_bytes,
            };
            let item_key = match self.cipher_domain(&file_path) {
                CipherDomain::Collection(dir) => {
                    let Some(cid) = self.collection_id_for_dir(&dir) else {
                        continue;
                    };
                    let (collection, _) =
                        match crate::vault::collections::open_collection(&self.path, &sgk, &cid) {
                            Ok(pair) => pair,
                            Err(_) => continue,
                        };
                    let Ok(ck) = crate::vault::collections::unwrap_ck(&collection, &sgk) else {
                        continue;
                    };
                    let Ok(envelope) = crate::vault::envelope::deserialize(&file.envelope_bytes)
                    else {
                        continue;
                    };
                    crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
                        &ck,
                        *canary_id,
                        envelope.header.key_epoch,
                    )
                }
                _ => Self::derive_item_key_from_root(root_key, *canary_id, epoch),
            };
            if crate::vault::cipher::decrypt_cipher(self.vault_id, *canary_id, &file, &item_key)
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(
            VaultError::Corrupt("master password incorrect (root key verification failed)".into())
                .into(),
        )
    }

    /// Old and new item keys for one cipher across a root rotation,
    /// domain-aware (S3-7c). Flat ciphers re-key under the new Root Key's
    /// SGK; collection ciphers keep the SAME content key (CK values are
    /// rotation-invariant) and re-derive at the new epoch, so member
    /// grant wraps stay valid and the member's access survives rotation.
    #[allow(clippy::too_many_arguments)]
    fn rotation_item_keys(
        &self,
        unlocked: &UnlockedState,
        old_root: &RootKey,
        file_path: &Path,
        file: &cipher::CipherFile,
        old_epoch: u64,
        new_epoch: u64,
        new_root: &RootKey,
    ) -> Result<(ItemKey, ItemKey), BaluardError> {
        match self.cipher_domain(file_path) {
            CipherDomain::Flat | CipherDomain::TrashFlat => Ok((
                Self::derive_item_key_from_root(old_root, file.id, old_epoch),
                Self::derive_item_key_from_root(new_root, file.id, new_epoch),
            )),
            CipherDomain::Collection(dir) | CipherDomain::TrashCollection(dir) => {
                let Some(cid) = self.collection_id_for_dir(&dir) else {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "That entry's collection no longer exists.".into(),
                    )));
                };
                let ck = self.resolve_ck(unlocked, &cid)?;
                Ok((
                    crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
                        &ck, file.id, old_epoch,
                    ),
                    crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
                        &ck, file.id, new_epoch,
                    ),
                ))
            }
        }
    }

    /// Derive an item key from the cached Space Group Key in UnlockedState.
    /// DESIGN-3: Uses the SGK already held in UnlockedState, avoiding redundant derivation.
    ///
    /// Routes through the checked `try_derive_item_key` so a cipher at a key
    /// epoch the held SGK cannot reach surfaces as a typed `CrossEpoch` error
    /// instead of (a) panicking in debug builds or (b) silently deriving the
    /// wrong key in release builds and failing the downstream AEAD check,
    /// which the index rebuild then dropped with no signal (B-2 fix).
    fn derive_item_key_from_sgk(
        sgk: &crate::keys::hierarchy::SpaceGroupKey,
        cipher_id: Uuid,
        epoch: u64,
    ) -> Result<ItemKey, BaluardError> {
        sgk.try_derive_item_key(cipher_id, epoch).ok_or_else(|| {
            VaultError::CrossEpoch {
                envelope_epoch: epoch,
                held_epoch: sgk.epoch(),
            }
            .into()
        })
    }

    /// Fallback: derive item key from RootKey by first deriving an SGK.
    /// Used only when we have a RootKey but no cached SGK (e.g., verify_root_key).
    fn derive_item_key_from_root(root_key: &RootKey, cipher_id: Uuid, epoch: u64) -> ItemKey {
        let sgk = crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(root_key, epoch);
        sgk.derive_item_key(cipher_id, epoch)
    }

    // ── S3-7c: cipher key domain ────────────────────────────────────
    //
    // A cipher's item key follows its location: flat paths (personal
    // ciphers) are keyed by the SGK and stay an admin surface; ciphers
    // inside a collection directory are keyed by that collection's
    // content key, so granted members holding only their per-member CK
    // wrap can decrypt without any group or root key material. Trash
    // preserves the origin directory so restore is always same-domain.

    fn cipher_domain(&self, file_path: &Path) -> CipherDomain {
        let rel = file_path.strip_prefix(&self.path).unwrap_or(file_path);
        let segs: Vec<&str> = rel.iter().map(|s| s.to_str().unwrap_or("")).collect();
        match segs.as_slice() {
            ["ciphers", dir, _] => CipherDomain::Collection((*dir).to_string()),
            ["trash", dir, _] => CipherDomain::TrashCollection((*dir).to_string()),
            ["trash", _] => CipherDomain::TrashFlat,
            _ => CipherDomain::Flat,
        }
    }

    fn collection_id_for_dir(&self, dir: &str) -> Option<Uuid> {
        crate::vault::collections::load_dir_map(&self.path)
            .into_iter()
            .find(|(name, _)| name == dir)
            .map(|(_, id)| id)
    }

    /// The trash location for a cipher, mirroring its origin layout.
    /// Falls back to scanning trash/ subdirectories directly, so entries
    /// trashed from a since-deleted collection stay reachable (review
    /// F12) until purge removes them.
    fn trash_file_path(&self, cipher_id: Uuid) -> Option<std::path::PathBuf> {
        let flat = self.path.join(format!("trash/{cipher_id}.enc"));
        if flat.exists() {
            return Some(flat);
        }
        for (d, _) in crate::vault::collections::load_dir_map(&self.path) {
            let p = self.path.join(format!("trash/{d}/{cipher_id}.enc"));
            if p.exists() {
                return Some(p);
            }
        }
        // Ghost fallback: any trash subdirectory not backed by a live
        // collection def.
        let trash_dir = self.path.join("trash");
        for entry in std::fs::read_dir(&trash_dir).ok()?.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let p = entry.path().join(format!("{cipher_id}.enc"));
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// Resolve one collection's content key for THIS device: admins (and
    /// pre-flip members holding the SGK) unwrap it from the collection
    /// file; flipped members open their per-member grant wrap with their
    /// identity wrapping secret.
    fn resolve_ck(
        &self,
        unlocked: &UnlockedState,
        collection_id: &Uuid,
    ) -> Result<Zeroizing<[u8; 32]>, BaluardError> {
        if let Ok(sgk) = unlocked.sgk() {
            let (file, _) =
                crate::vault::collections::open_collection(&self.path, sgk, collection_id)?;
            return crate::vault::collections::unwrap_ck(&file, sgk);
        }
        let identity = unlocked.identity.as_ref().ok_or_else(|| {
            BaluardError::from(VaultError::InvalidOperation(
                "this entry's collection key is not available on this device".into(),
            ))
        })?;
        let member_id = crate::vault::members::member_id_for_device(&self.path, self.device_id)
            .ok_or_else(|| {
                BaluardError::from(VaultError::InvalidOperation(
                    "this device is not bound to a Space member".into(),
                ))
            })?;
        crate::vault::collections::open_grant_wrap(
            &self.path,
            collection_id,
            &member_id,
            identity.wrapping_secret(),
        )
        .or_else(|_| {
            // S4-2: no direct grant wrap — try the group chain (gkwrap →
            // GK → ckwrap) across every group that names this member and
            // holds a live ckwrap for the collection.
            for (gid, members) in crate::vault::collections::load_group_memberships(&self.path) {
                if !members.contains(&member_id) {
                    continue;
                }
                if let Ok(ck) = crate::vault::groups::open_ck_through_group(
                    &self.path,
                    &gid,
                    collection_id,
                    &member_id,
                    identity.wrapping_secret(),
                ) {
                    return Ok(ck);
                }
            }
            crate::vault::collections::open_grant_wrap(
                &self.path,
                collection_id,
                &member_id,
                identity.wrapping_secret(),
            )
        })
    }

    /// Derive the item key for a cipher at its on-disk location.
    fn resolve_item_key(
        &self,
        unlocked: &UnlockedState,
        file_path: &Path,
        cipher_id: Uuid,
        epoch: u64,
    ) -> Result<ItemKey, BaluardError> {
        match self.cipher_domain(file_path) {
            CipherDomain::Flat => {
                let sgk = unlocked.sgk()?;
                sgk.try_derive_item_key(cipher_id, epoch).ok_or_else(|| {
                    BaluardError::from(VaultError::CrossEpoch {
                        envelope_epoch: epoch,
                        held_epoch: sgk.epoch(),
                    })
                })
            }
            CipherDomain::Collection(dir) => {
                let Some(cid) = self.collection_id_for_dir(&dir) else {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "That entry's collection no longer exists.".into(),
                    )));
                };
                let ck = self.resolve_ck(unlocked, &cid)?;
                Ok(
                    crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
                        &ck, cipher_id, epoch,
                    ),
                )
            }
            CipherDomain::TrashCollection(dir) => {
                let Some(cid) = self.collection_id_for_dir(&dir) else {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "That entry's collection no longer exists.".into(),
                    )));
                };
                let ck = self.resolve_ck(unlocked, &cid)?;
                Ok(
                    crate::keys::hierarchy::SpaceGroupKey::derive_item_key_from_ck(
                        &ck, cipher_id, epoch,
                    ),
                )
            }
            CipherDomain::TrashFlat => {
                let sgk = unlocked.sgk()?;
                sgk.try_derive_item_key(cipher_id, epoch).ok_or_else(|| {
                    BaluardError::from(VaultError::CrossEpoch {
                        envelope_epoch: epoch,
                        held_epoch: sgk.epoch(),
                    })
                })
            }
        }
    }

    /// Decrypt a cipher file at its on-disk location (domain-aware).
    fn try_decrypt_cipher_at(
        &self,
        unlocked: &UnlockedState,
        file_path: &Path,
        file: &crate::vault::cipher::CipherFile,
    ) -> Result<Cipher, BaluardError> {
        let envelope = crate::vault::envelope::deserialize(&file.envelope_bytes)?;
        let item_key =
            self.resolve_item_key(unlocked, file_path, file.id, envelope.header.key_epoch)?;
        crate::vault::cipher::decrypt_cipher(self.vault_id, file.id, file, &item_key)
    }

    /// Derive item key for a cipher (requires unlocked vault).
    pub fn derive_item_key(
        &self,
        cipher_id: Uuid,
        key_epoch: u64,
    ) -> crate::keys::hierarchy::ItemKey {
        let sgk = match &self.state {
            VaultState::Unlocked(u) => u.space_group_key.as_ref().expect(
                "derive_item_key requires a managing device (team members use collection keys)",
            ),
            VaultState::Locked => panic!("derive_item_key called on locked vault"),
        };
        // Routed through the checked derive so a genuine held-epoch mismatch
        // (encrypt/re-encrypt path with the wrong key_epoch) panics with a
        // typed message instead of silently deriving the wrong key. Callers
        // on the encrypt path always pass the held current_epoch, so a
        // mismatch here is an invariant violation, not user data.
        Self::derive_item_key_from_sgk(sgk, cipher_id, key_epoch)
            .expect("derive_item_key: key_epoch does not match held SpaceGroupKey epoch")
    }

    /// The currently-held epoch (the RootKey/SGK this device has in memory).
    /// None when locked. Used by Phase 2b conflict merge to stamp re-encrypted
    /// merged ciphers with the merging device's actual current epoch (per the
    /// design review: an envelope's epoch must match held key material).
    pub fn current_epoch(&self) -> Option<u64> {
        match &self.state {
            VaultState::Unlocked(u) => Some(u.current_epoch),
            VaultState::Locked => None,
        }
    }

    /// Get a cipher (decrypts if unlocked, returns metadata only if locked).
    /// Looks up in both active ciphers and trash.
    pub fn get_cipher(&self, cipher_id: Uuid) -> Result<CipherRead, BaluardError> {
        let file_path = if let Some(p) = self.cipher_file_path(cipher_id) {
            p
        } else if let Some(p) = self.trash_file_path(cipher_id) {
            p
        } else {
            return Err(VaultError::CipherNotFound(cipher_id.to_string()).into());
        };

        let envelope_bytes = std::fs::read(&file_path)?;
        let file = crate::vault::cipher::CipherFile {
            id: cipher_id,
            envelope_bytes,
        };

        match &self.state {
            VaultState::Unlocked(unlocked) => {
                let cipher = self.try_decrypt_cipher_at(unlocked, &file_path, &file)?;
                Ok(CipherRead::Decrypted(Box::new(cipher)))
            }
            VaultState::Locked => {
                let envelope = crate::vault::envelope::deserialize(&file.envelope_bytes)?;
                Ok(CipherRead::Locked(LockedCipherInfo {
                    id: cipher_id,
                    key_epoch: envelope.header.key_epoch,
                    update_seq: envelope.header.update_seq,
                    tier: envelope.header.tier,
                    ciphertext_len: envelope.ciphertext.len(),
                }))
            }
        }
    }

    /// Decrypt a cipher from raw envelope bytes (e.g. read from a specific git
    /// commit via `SyncEngine::read_blob_from_commit`), rather than from the
    /// working tree. Used by Phase 2b field-level conflict merge to decrypt
    /// the base / local / remote versions of a conflicting cipher.
    ///
    /// The `key_epoch` is read from the envelope header (NOT supplied by the
    /// caller); the item key is derived for that epoch via
    /// [`derive_item_key`]. If the vault's held SpaceGroupKey cannot reach the
    /// envelope's epoch (cross-rotation: remote pre-rotation with destroyed
    /// old RootKey, or local behind post-rotation), decryption fails cleanly —
    /// callers MUST treat this as "cannot merge this side," not retry.
    ///
    /// AAD is recomputed from the envelope's own header fields (same invariant
    /// as `get_cipher`), so a blob swapped from a different cipher_id or vault
    /// fails closed.
    pub fn decrypt_cipher_bytes(
        &self,
        cipher_id: Uuid,
        envelope_bytes: &[u8],
    ) -> Result<crate::types::Cipher, BaluardError> {
        let envelope = crate::vault::envelope::deserialize(envelope_bytes)?;
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => {
                return Err(VaultError::Corrupt(
                    "decrypt_cipher_bytes called on locked vault".into(),
                )
                .into());
            }
        };
        let file = crate::vault::cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: envelope_bytes.to_vec(),
        };
        // S3-7c: when the cipher exists locally, its key domain follows the
        // on-disk location (collection ciphers are CK-keyed). A cipher with
        // no local file is treated flat — conflict resolution only runs for
        // ciphers that exist locally, and a new remote cipher lands on disk
        // before any merge decision.
        let item_key = match self.cipher_file_path(cipher_id) {
            Some(path) => {
                self.resolve_item_key(unlocked, &path, cipher_id, envelope.header.key_epoch)?
            }
            None => {
                // Cross-epoch safe path: the envelope may be at a foreign
                // epoch. try_derive_item_key returns None on epoch mismatch
                // instead of panicking; map None to a clean Err the caller
                // reports as `cross_epoch`.
                let sgk = unlocked.sgk()?;
                sgk.try_derive_item_key(cipher_id, envelope.header.key_epoch)
                    .ok_or_else(|| {
                        BaluardError::from(VaultError::Corrupt(format!(
                            "cross-epoch decrypt: envelope epoch {} != held SGK epoch {}",
                            envelope.header.key_epoch,
                            sgk.epoch()
                        )))
                    })?
            }
        };
        crate::vault::cipher::decrypt_cipher(self.vault_id, cipher_id, &file, &item_key)
    }

    /// Delete a cipher by ID. By default, moves it to trash.
    /// If it is already in trash, deletes it permanently.
    pub fn delete_cipher(&self, cipher_id: Uuid) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }

        // S3-7c: trash preserves the origin layout, so restore is always
        // same-domain (a collection cipher stays CK-keyed inside
        // trash/<dir>/; a personal cipher stays SGK-keyed at trash/ root).
        if let Some(active_path) = self.cipher_file_path(cipher_id) {
            // Review F6: personal-flat ciphers are the admin surface — a
            // member cannot trash what it cannot read (and trashing needs
            // no crypto, so the role gate is the only fence).
            let is_admin = matches!(
                crate::vault::members::member_role_for_device(&self.path, self.device_id),
                Some(crate::vault::members::MemberRole::Owner)
                    | Some(crate::vault::members::MemberRole::Admin)
            );
            match self.cipher_domain(&active_path) {
                CipherDomain::Collection(dir) => {
                    let Some(cid) = self.collection_id_for_dir(&dir) else {
                        return Err(BaluardError::from(VaultError::InvalidOperation(
                            "That entry's collection no longer exists.".into(),
                        )));
                    };
                    // §6.5 trash_policy: a Space can restrict trashing to
                    // admins. Default keeps write-scope trashing.
                    if self.get_settings()?.trash_policy
                        == crate::vault::manifest::TrashPolicy::AdminsOnly
                        && !is_admin
                    {
                        return Err(BaluardError::from(VaultError::InvalidOperation(
                            "Trashing is limited to admins in this space.".into(),
                        )));
                    }
                    self.assert_collection_write(&cid)?;
                }
                CipherDomain::Flat if !is_admin => {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "this operation requires a managing device (team members hold no group key)"
                            .into(),
                    )));
                }
                _ => {}
            }
            let mut trash_rel = std::path::PathBuf::from("trash");
            // Only collection-scoped ciphers keep a subdirectory; flat
            // ciphers trash at the root (trash/<id>.enc).
            if let CipherDomain::Collection(dir) | CipherDomain::TrashCollection(dir) =
                self.cipher_domain(&active_path)
            {
                trash_rel.push(dir);
            }
            trash_rel.push(format!("{cipher_id}.enc"));
            let trash_path = self.path.join(trash_rel);
            if let Some(parent) = trash_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let envelope_bytes = std::fs::read(&active_path)?;
            super::write_vault_file(&trash_path, &envelope_bytes)?;
            std::fs::remove_file(&active_path)?;
            self.remove_integrity(&cipher_id.to_string());
            self.rebuild_index()?;
            Ok(())
        } else if let Some(trash_path) = self.trash_file_path(cipher_id) {
            // §4.4 "restore/purge admin": permanent deletion of a trashed
            // entry is admin-surface — collection trash and flat trash
            // alike. A member purging flat trash would also wedge its own
            // sync (flat_admin_only refuses the commit at every peer).
            let is_admin = matches!(
                crate::vault::members::member_role_for_device(&self.path, self.device_id),
                Some(crate::vault::members::MemberRole::Owner)
                    | Some(crate::vault::members::MemberRole::Admin)
            );
            match self.cipher_domain(&trash_path) {
                CipherDomain::TrashCollection(dir) => {
                    if self.collection_id_for_dir(&dir).is_none() {
                        return Err(BaluardError::from(VaultError::InvalidOperation(
                            "That entry's collection no longer exists.".into(),
                        )));
                    }
                    if !is_admin {
                        return Err(BaluardError::from(VaultError::InvalidOperation(
                            "Purging entries is limited to admins in this space.".into(),
                        )));
                    }
                }
                CipherDomain::TrashFlat if !is_admin => {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "this operation requires a managing device (team members hold no group key)"
                            .into(),
                    )));
                }
                _ => {}
            }
            std::fs::remove_file(&trash_path)?;
            self.remove_integrity(&cipher_id.to_string());
            self.rebuild_index()?;
            Ok(())
        } else {
            Err(VaultError::CipherNotFound(cipher_id.to_string()).into())
        }
    }

    /// Local write-scope gate for one collection: admins (and legacy
    /// vaults without a member directory) pass; everyone else needs a
    /// live write-or-manage grant. Mirrors the assign gate so a refused
    /// move can never mint an unpushable commit.
    fn assert_collection_write(&self, collection_id: &Uuid) -> Result<(), BaluardError> {
        let is_admin = matches!(
            crate::vault::members::member_role_for_device(&self.path, self.device_id),
            Some(crate::vault::members::MemberRole::Owner)
                | Some(crate::vault::members::MemberRole::Admin)
        );
        if is_admin || !self.path.join("meta/members").is_dir() {
            return Ok(());
        }
        // S3-5 review (restored, S3-7c F3): a demoted Viewer keeps a stale
        // write grant — peers apply the Editor floor, so a Viewer-authored
        // write would wedge sync. Refuse here, before any commit exists.
        if matches!(
            crate::vault::members::member_role_for_device(&self.path, self.device_id),
            Some(crate::vault::members::MemberRole::Viewer)
        ) {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "You do not have write access to that collection.".into(),
            )));
        }
        let Some(member_id) =
            crate::vault::members::member_id_for_device(&self.path, self.device_id)
        else {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "You do not have write access to that collection.".into(),
            )));
        };
        // S3-7c: read the collection file's plaintext grant rows directly
        // — no SGK needed, so member devices can run this gate.
        let file_path = crate::vault::collections::collections_file_path(&self.path, collection_id);
        let bytes = std::fs::read(&file_path).map_err(|_| {
            BaluardError::from(VaultError::InvalidOperation(
                "That collection no longer exists.".into(),
            ))
        })?;
        let file: crate::vault::collections::CollectionFile = serde_json::from_slice(&bytes)
            .map_err(|_| {
                BaluardError::from(VaultError::InvalidOperation(
                    "That collection's record is damaged.".into(),
                ))
            })?;
        let has_grant = file.id == *collection_id
            && crate::vault::groups::effective_access(
                &file.grants,
                member_id,
                &|gid| {
                    crate::vault::collections::load_group_memberships(&self.path)
                        .into_iter()
                        .find(|(id2, _)| *id2 == gid)
                        .map(|(_, ms)| ms)
                },
                crate::vault::collections::now_secs_pub(),
            )
            .is_some_and(|a| {
                matches!(
                    a,
                    crate::vault::collections::CollectionAccess::Write
                        | crate::vault::collections::CollectionAccess::Manage
                )
            });
        if !has_grant {
            return Err(BaluardError::from(VaultError::InvalidOperation(
                "You do not have write access to that collection.".into(),
            )));
        }
        Ok(())
    }

    /// List deleted cipher IDs in trash.
    pub fn list_trash_ids(&self) -> Result<Vec<Uuid>, BaluardError> {
        Ok(self
            .list_trash_entries()?
            .into_iter()
            .map(|(id, _)| id)
            .collect())
    }

    /// Trash rows with their origin collection, when the entry was
    /// trashed from a collection directory (§4.8-5). A row sitting
    /// under an unknown or vanished subdirectory maps to None; permanent
    /// purge still cleans it up.
    pub fn list_trash_entries(&self) -> Result<Vec<(Uuid, Option<Uuid>)>, BaluardError> {
        let trash_dir = self.path.join("trash");
        if !trash_dir.exists() {
            return Ok(Vec::new());
        }
        let dirs = crate::vault::collections::load_dir_map(&self.path);

        let mut rows = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Flat files first: matches trash_file_path resolution priority.
        for entry in std::fs::read_dir(&trash_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(id_str) = name.strip_suffix(".enc") {
                    if let Ok(id) = Uuid::parse_str(id_str) {
                        if seen.insert(id) {
                            rows.push((id, None));
                        }
                    }
                }
            }
        }

        for entry in std::fs::read_dir(&trash_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // S3-7c: collection ciphers trash into trash/<dir>/.
                let dir_name = entry.file_name().to_string_lossy().to_string();
                let cid = dirs
                    .iter()
                    .find(|(name, _)| *name == dir_name)
                    .map(|(_, id)| *id);
                for inner in std::fs::read_dir(&path)?.flatten() {
                    if let Some(id_str) = inner.file_name().to_string_lossy().strip_suffix(".enc") {
                        if let Ok(id) = Uuid::parse_str(id_str) {
                            // Review F10: the same uuid can sit at both
                            // trash shapes; keep the list deduplicated.
                            if seen.insert(id) {
                                rows.push((id, cid));
                            }
                        }
                    }
                }
            }
        }
        Ok(rows)
    }

    /// Restore a deleted cipher from trash back to active. S3-7c: trash
    /// preserves the origin layout, so restore is always same-domain —
    /// the bytes move back unchanged (a collection cipher returns to its
    /// collection dir, a personal cipher to the flat path). Collection
    /// restores need write scope (the path IS the membership).
    pub fn restore_cipher(&self, cipher_id: Uuid) -> Result<(), BaluardError> {
        let trash_path = self
            .trash_file_path(cipher_id)
            .ok_or_else(|| BaluardError::from(VaultError::CipherNotFound(cipher_id.to_string())))?;

        let rel = trash_path
            .strip_prefix(&self.path)
            .unwrap_or(&trash_path)
            .to_path_buf();
        let mut active_rel = std::path::PathBuf::from("ciphers");
        if let Some(parent_name) = rel.parent().and_then(|p| p.file_name()) {
            let parent_str = parent_name.to_string_lossy().to_string();
            if parent_str != "trash" {
                active_rel.push(&parent_str);
                let Some(_cid) = self.collection_id_for_dir(&parent_str) else {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "That entry's collection no longer exists.".into(),
                    )));
                };
                // §6.5 restore_policy: restoring is admin-only in v1 (the
                // §6.5 table lists no member-facing value; purge is admin
                // by the §4.4 row). A future write-scope variant must add
                // its arm here — the match stays exhaustive on purpose.
                match self.get_settings()?.restore_policy {
                    crate::vault::manifest::RestorePolicy::AdminsOnly => {
                        let is_admin = matches!(
                            crate::vault::members::member_role_for_device(
                                &self.path,
                                self.device_id
                            ),
                            Some(crate::vault::members::MemberRole::Owner)
                                | Some(crate::vault::members::MemberRole::Admin)
                        );
                        if !is_admin {
                            return Err(BaluardError::from(VaultError::InvalidOperation(
                                "Restoring is limited to admins in this space.".into(),
                            )));
                        }
                    }
                }
            } else {
                // Review F6: flat trash restores are admin-surface.
                let is_admin = matches!(
                    crate::vault::members::member_role_for_device(&self.path, self.device_id),
                    Some(crate::vault::members::MemberRole::Owner)
                        | Some(crate::vault::members::MemberRole::Admin)
                );
                if !is_admin {
                    return Err(BaluardError::from(VaultError::InvalidOperation(
                        "this operation requires a managing device (team members hold no group key)"
                            .into(),
                    )));
                }
            }
        }
        active_rel.push(format!("{cipher_id}.enc"));
        let active_path = self.path.join(active_rel);
        if let Some(parent) = active_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let envelope_bytes = std::fs::read(&trash_path)?;
        super::write_vault_file(&active_path, &envelope_bytes)?;
        std::fs::remove_file(&trash_path)?;
        self.rebuild_index()?;
        Ok(())
    }

    /// Purge deleted entries from trash that were deleted more than `days` ago.
    pub fn purge_old_trash(&self, days: u32) -> Result<usize, BaluardError> {
        // §4.4 "restore/purge admin": time-based purge is admin-surface on
        // team vaults. The daemon's best-effort unlock-time call swallows
        // the member refusal, so member devices simply no-op.
        if self.path.join("meta/members").is_dir() {
            let is_admin = matches!(
                crate::vault::members::member_role_for_device(&self.path, self.device_id),
                Some(crate::vault::members::MemberRole::Owner)
                    | Some(crate::vault::members::MemberRole::Admin)
            );
            if !is_admin {
                return Err(BaluardError::from(VaultError::InvalidOperation(
                    "Purging entries is limited to admins in this space.".into(),
                )));
            }
        }
        let trash_dir = self.path.join("trash");
        if !trash_dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        let limit =
            std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86400);

        for entry in std::fs::read_dir(&trash_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // S3-7c: collection trash subdirs — recurse one level.
                for inner in std::fs::read_dir(&path)?.flatten() {
                    let ipath = inner.path();
                    if let Ok(metadata) = std::fs::metadata(&ipath) {
                        if let Ok(modified) = metadata.modified() {
                            if modified < limit {
                                std::fs::remove_file(&ipath)?;
                                count += 1;
                            }
                        }
                    }
                }
                continue;
            }
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    if modified < limit {
                        std::fs::remove_file(&path)?;
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Add a cipher (requires unlocked vault).
    pub fn add_cipher(&mut self, input: &CipherInput) -> Result<Uuid, BaluardError> {
        self.add_cipher_in_collection(input, None)
    }

    /// Add a cipher, optionally inside a collection (S3-7c). A collection
    /// cipher is keyed by that collection's content key, so granted
    /// members can create entries without any group key material; a flat
    /// (personal) cipher stays SGK-keyed and is an admin surface.
    pub fn add_cipher_in_collection(
        &mut self,
        input: &CipherInput,
        collection_id: Option<Uuid>,
    ) -> Result<Uuid, BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let validated_tags = Self::validate_tags(&input.tags)?;
        let input = CipherInput {
            tags: validated_tags,
            ..input.clone()
        };
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let cipher_id = Uuid::new_v4();
        let file_path = match collection_id {
            None => self.path.join(format!("ciphers/{cipher_id}.enc")),
            Some(cid) => {
                self.assert_collection_write(&cid)?;
                // S3-7c: resolve the dir from the plaintext dir map — no
                // SGK needed, so members can create inside collections
                // they hold a write grant on.
                let dirs = crate::vault::collections::load_dir_map(&self.path);
                let dir_name = dirs
                    .iter()
                    .find(|(_, id)| *id == cid)
                    .map(|(d, _)| d.clone())
                    .ok_or_else(|| {
                        VaultError::InvalidOperation("That collection no longer exists.".into())
                    })?;
                self.path
                    .join(format!("ciphers/{dir_name}/{cipher_id}.enc"))
            }
        };
        let item_key =
            self.resolve_item_key(unlocked, &file_path, cipher_id, unlocked.current_epoch)?;

        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input,
            &item_key,
            unlocked.current_epoch, // epoch
            1,                      // update_seq
        )?;

        super::write_vault_file(&file_path, &file.envelope_bytes)?;
        self.rebuild_index()?;
        self.record_integrity(&cipher_id.to_string(), 1);

        Ok(cipher_id)
    }

    /// Update an existing cipher (requires unlocked vault).
    /// Re-encrypts with incremented update_seq.
    pub fn update_cipher(
        &mut self,
        cipher_id: Uuid,
        input: &CipherInput,
    ) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let validated_tags = Self::validate_tags(&input.tags)?;
        let input = CipherInput {
            tags: validated_tags,
            ..input.clone()
        };
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self
            .cipher_file_path(cipher_id)
            .ok_or_else(|| VaultError::NotFound(format!("cipher {cipher_id}")))?;

        // S3-7c review F2: a Read-grantee holds the CK wrap and could
        // re-encrypt an update locally, but peers refuse non-writable
        // cipher commits — the local gate must refuse first or the vault
        // wedges. Personal-flat ciphers stay an admin surface.
        if let CipherDomain::Collection(dir) = self.cipher_domain(&file_path) {
            let Some(cid) = self.collection_id_for_dir(&dir) else {
                return Err(BaluardError::from(VaultError::InvalidOperation(
                    "That entry's collection no longer exists.".into(),
                )));
            };
            self.assert_collection_write(&cid)?;
        }

        // Read existing envelope to get current update_seq and key_epoch
        let existing_bytes = std::fs::read(&file_path)?;
        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: existing_bytes,
        };
        let existing_envelope = crate::vault::envelope::deserialize(&existing_file.envelope_bytes)?;
        let new_update_seq = existing_envelope.header.update_seq + 1;
        let key_epoch = existing_envelope.header.key_epoch;

        // Read existing cipher to preserve created_at (S3-7c: domain-aware)
        let existing_cipher = self.try_decrypt_cipher_at(unlocked, &file_path, &existing_file)?;

        let mut input_owned = input.clone();
        input_owned.created_at = Some(existing_cipher.created_at);

        // Auto-append old password to history if password changed
        let old_password = match &existing_cipher.kind {
            crate::types::CipherKind::Login(data) => data.password.clone(),
            _ => None,
        };
        let new_password = match &input_owned.kind {
            crate::types::CipherKind::Login(data) => data.password.clone(),
            _ => None,
        };
        if let Some(ref old_pw) = old_password {
            if old_password != new_password {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut history = existing_cipher.password_history.clone();
                history.push(crate::types::PasswordHistoryEntry {
                    password: old_pw.clone(),
                    last_used_date: now,
                });
                // Cap history at 10 entries (BW parity default is 5, but 10 is more practical)
                const MAX_PASSWORD_HISTORY: usize = 10;
                if history.len() > MAX_PASSWORD_HISTORY {
                    history.drain(0..history.len() - MAX_PASSWORD_HISTORY);
                }
                input_owned.password_history = history;

                // Update password_revision_date on LoginData
                if let crate::types::CipherKind::Login(ref mut data) = input_owned.kind {
                    data.password_revision_date = Some(now);
                }
            }
        } else if input_owned.password_history.is_empty() {
            // Preserve existing history if caller didn't provide one and password didn't change.
            // History is append-only: passing password_history: vec![] preserves existing history.
            input_owned.password_history = existing_cipher.password_history.clone();
        }

        let item_key = self.resolve_item_key(unlocked, &file_path, cipher_id, key_epoch)?;

        let file = cipher::encrypt_cipher(
            self.vault_id,
            cipher_id,
            &input_owned,
            &item_key,
            key_epoch,
            new_update_seq,
        )?;

        super::write_vault_file(&file_path, &file.envelope_bytes)?;
        self.rebuild_index()?;
        self.record_integrity(&cipher_id.to_string(), new_update_seq);

        Ok(())
    }

    /// Clone a cipher: duplicate with new UUID, empty password history, reset update_seq.
    pub fn clone_cipher(&mut self, cipher_id: Uuid) -> Result<Uuid, BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self
            .cipher_file_path(cipher_id)
            .ok_or_else(|| VaultError::NotFound(format!("cipher {cipher_id}")))?;

        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&file_path)?,
        };
        let existing = self.try_decrypt_cipher_at(unlocked, &file_path, &existing_file)?;

        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            collection_id: None,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: None,         // fresh timestamp for the clone
            password_history: vec![], // empty history for clone
            attachments: existing.attachments.clone(),
            archived: existing.archived,
            tags: existing.tags.clone(),
        };

        // add_cipher handles new UUID + encryption.
        // S3-7c review F8: the clone lands in the SAME key domain as its
        // source — cloning a collection cipher into the flat personal
        // surface would silently move the copy out of the collection (and
        // a member clone would fail outright on the SGK path).
        let source_collection = match self.cipher_domain(&file_path) {
            CipherDomain::Collection(dir) => self.collection_id_for_dir(&dir),
            _ => None,
        };
        self.add_cipher_in_collection(&input, source_collection)
    }

    /// Archive a cipher: sets `archived: true`, hides from main list.
    /// Re-encrypts with updated flag.
    pub fn archive_cipher(&mut self, cipher_id: Uuid) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self
            .cipher_file_path(cipher_id)
            .ok_or_else(|| VaultError::CipherNotFound(cipher_id.to_string()))?;

        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&file_path)?,
        };
        let existing = self.try_decrypt_cipher_at(unlocked, &file_path, &existing_file)?;

        if existing.archived {
            return Ok(()); // Already archived, idempotent
        }

        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            collection_id: None,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: Some(existing.created_at),
            password_history: existing.password_history,
            attachments: existing.attachments,
            archived: true,
            tags: existing.tags.clone(),
        };
        self.update_cipher(cipher_id, &input)
    }

    /// Unarchive a cipher: sets `archived: false`, restores to main list.
    pub fn unarchive_cipher(&mut self, cipher_id: Uuid) -> Result<(), BaluardError> {
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt("vault is rotating, writes blocked".into()).into());
        }
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        let file_path = self
            .cipher_file_path(cipher_id)
            .ok_or_else(|| VaultError::CipherNotFound(cipher_id.to_string()))?;

        let existing_file = cipher::CipherFile {
            id: cipher_id,
            envelope_bytes: std::fs::read(&file_path)?,
        };
        let existing = self.try_decrypt_cipher_at(unlocked, &file_path, &existing_file)?;

        if !existing.archived {
            return Ok(()); // Already unarchived, idempotent
        }

        let input = CipherInput {
            name: existing.name,
            folder_id: existing.folder_id,
            collection_id: None,
            kind: existing.kind,
            favorite: existing.favorite,
            reprompt: existing.reprompt,
            notes: existing.notes,
            custom_fields: existing.custom_fields,
            created_at: Some(existing.created_at),
            password_history: existing.password_history,
            attachments: existing.attachments,
            archived: false,
            tags: existing.tags.clone(),
        };
        self.update_cipher(cipher_id, &input)
    }

    /// List archived cipher metadata (ciphers with `archived: true`).
    pub fn list_archived_meta(&self) -> Result<Vec<crate::types::CipherMeta>, BaluardError> {
        Ok(self
            .list_cipher_meta_full()?
            .into_iter()
            .filter(|m| m.archived)
            .collect())
    }

    // ── Tag operations ──

    /// Validate a single tag name: trim, reject empty/whitespace, max 64 chars, lowercase.
    pub fn validate_tag(name: &str) -> Result<String, BaluardError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(
                VaultError::Metadata("tag name cannot be empty or whitespace".into()).into(),
            );
        }
        if trimmed.chars().count() > 64 {
            return Err(VaultError::Metadata("tag name exceeds 64 characters".into()).into());
        }
        Ok(trimmed.to_lowercase())
    }

    /// Validate a slice of tags: each validated, case-insensitive dedup, max 20.
    pub fn validate_tags(tags: &[String]) -> Result<Vec<String>, BaluardError> {
        let mut validated = Vec::with_capacity(tags.len());
        let mut seen = std::collections::HashSet::new();
        for tag in tags {
            let normalized = Self::validate_tag(tag)?;
            if seen.insert(normalized.clone()) {
                validated.push(normalized);
            }
        }
        if validated.len() > 20 {
            return Err(VaultError::Metadata("cipher cannot have more than 20 tags".into()).into());
        }
        Ok(validated)
    }

    /// List all tags. P5b per-fact layout: one encrypted file per tag
    /// (`meta/tags/<sha256(name) prefix>.enc`, name stored inside — the
    /// filename is a digest, never user-controlled text). Falls back to the
    /// legacy single-envelope `meta/tags.enc`, then plaintext
    /// `tag_index.json`.
    pub fn list_tags(&self) -> Result<Vec<String>, BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_tags_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("tags key derivation: {e}")))?;

        // Per-fact layout. Foreign entries (temp files, dotfiles, junk) are
        // skipped; reads NEVER delete anything — legacy migration happens on
        // write only. An empty/invalid per-fact dir falls through to the
        // legacy file rather than wiping it.
        let dir = self.path.join("meta/tags");
        if dir.exists() {
            let mut tags = Vec::new();
            let mut saw_valid_file = false;
            for entry in std::fs::read_dir(&dir)
                .map_err(|e| VaultError::Metadata(format!("tags listing: {e}")))?
            {
                let entry = entry.map_err(|e| VaultError::Metadata(format!("tags read: {e}")))?;
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.') || !entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                {
                    continue;
                }
                if path.extension().map(|e| e != "enc").unwrap_or(true) {
                    continue;
                }
                // Filenames are "<32-hex>.enc" (sha256(name) prefix).
                let stem_ok = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    .unwrap_or(false);
                if !stem_ok {
                    continue;
                }
                saw_valid_file = true;
                let data = std::fs::read(&path)?;
                let envelope = crate::vault::envelope::deserialize(&data)?;
                let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
                let name: String = serde_json::from_slice(&decrypted)
                    .map_err(|e| VaultError::Metadata(format!("tag decrypt parse: {e}")))?;
                tags.push(name);
            }
            if saw_valid_file {
                tags.sort();
                tags.dedup();
                return Ok(tags);
            }
            // Zero valid files → treat as no per-fact layout; legacy below.
        }

        // Legacy single-envelope fallback.
        let enc_path = self.path.join("meta/tags.enc");
        if enc_path.exists() {
            let data = std::fs::read(&enc_path)?;
            let envelope = crate::vault::envelope::deserialize(&data)?;
            let decrypted = crate::crypto::aead::decrypt(&key, &envelope)?;
            let index: crate::vault::manifest::TagIndex = serde_json::from_slice(&decrypted)
                .map_err(|e| VaultError::Metadata(format!("tags decrypt parse: {e}")))?;
            // Cleanup stale plaintext if encrypted version decrypts cleanly
            let _ = std::fs::remove_file(self.path.join("meta/tag_index.json"));
            return Ok(index.tags);
        }
        // Legacy fallback: plaintext tag_index.json
        let json_path = self.path.join("meta/tag_index.json");
        if json_path.exists() {
            let data = std::fs::read_to_string(&json_path)?;
            let index: crate::vault::manifest::TagIndex = serde_json::from_str(&data)
                .map_err(|e| VaultError::Metadata(format!("tag index deserialization: {e}")))?;
            return Ok(index.tags);
        }
        Ok(vec![])
    }

    /// Rebuild tag index from all decrypted cipher metas (encrypted).
    pub fn rebuild_tag_index(&self) -> Result<(), BaluardError> {
        let metas = self.list_cipher_meta_full()?;
        let mut tag_set = std::collections::HashSet::new();
        for meta in &metas {
            for tag in &meta.tags {
                tag_set.insert(tag.clone());
            }
        }
        let mut tags: Vec<String> = tag_set.into_iter().collect();
        tags.sort();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let index = crate::vault::manifest::TagIndex {
            tags,
            updated_at: now,
        };

        self.save_tags_enc(&index)?;
        Ok(())
    }

    /// Create a new tag in the index (without assigning to any cipher).
    pub fn create_tag(&mut self, name: &str) -> Result<(), BaluardError> {
        let normalized = Self::validate_tag(name)?;
        let mut tags = self.list_tags()?;
        // Case-insensitive check
        if tags.iter().any(|t| t.eq_ignore_ascii_case(&normalized)) {
            return Ok(()); // idempotent
        }
        tags.push(normalized);
        tags.sort();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let index = crate::vault::manifest::TagIndex {
            tags,
            updated_at: now,
        };

        self.save_tags_enc(&index)?;
        Ok(())
    }

    /// Save tag index (P5b per-fact layout: one encrypted file per tag,
    /// filename = sha256(name) prefix — never user-controlled text; the name
    /// is stored inside). Skip-if-unchanged kills the rewrite churn; removed
    /// tags are pruned. Legacy single-envelope and plaintext files are
    /// removed once per-fact files exist.
    fn save_tags_enc(&self, index: &crate::vault::manifest::TagIndex) -> Result<(), BaluardError> {
        use sha2::{Digest, Sha256};
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let key = hkdf_derive::derive_tags_key(&unlocked.meta_ikm())
            .map_err(|e| VaultError::Metadata(format!("tags key derivation: {e}")))?;
        let dir = self.path.join("meta/tags");
        std::fs::create_dir_all(&dir)?;

        let mut keep: std::collections::HashSet<String> = std::collections::HashSet::new();
        for tag in &index.tags {
            let digest = Sha256::digest(tag.as_bytes());
            let file_name = format!("{}.enc", hex::encode(&digest[..16]));
            keep.insert(file_name.clone());
            let path = dir.join(&file_name);
            let json = serde_json::to_vec(tag)
                .map_err(|e| VaultError::Metadata(format!("tag serialization: {e}")))?;
            let changed = match std::fs::read(&path) {
                Ok(bytes) => match crate::vault::envelope::deserialize(&bytes)
                    .map_err(BaluardError::from)
                    .and_then(|envelope| {
                        crate::crypto::aead::decrypt(&key, &envelope).map_err(BaluardError::from)
                    }) {
                    Ok(existing) => existing != json,
                    Err(_) => true,
                },
                Err(_) => true,
            };
            if changed {
                self.encrypt_and_write_meta(&key, &json, &path, unlocked.current_epoch)?;
            }
        }

        // Prune tags removed since the last save.
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| VaultError::Metadata(format!("tags prune listing: {e}")))?
        {
            let entry = entry.map_err(|e| VaultError::Metadata(format!("tags prune: {e}")))?;
            let name = entry.file_name();
            if !keep.contains(&name.to_string_lossy().to_string()) {
                let _ = std::fs::remove_file(entry.path());
            }
        }

        // Migration: per-fact dir is authoritative now.
        let _ = std::fs::remove_file(self.path.join("meta/tags.enc"));
        let _ = std::fs::remove_file(self.path.join("meta/tag_index.json"));
        Ok(())
    }

    /// Rename a tag across all ciphers. Returns count of affected ciphers.
    pub fn rename_tag(&mut self, old: &str, new: &str) -> Result<usize, BaluardError> {
        let old_normalized = Self::validate_tag(old)?;
        let new_normalized = Self::validate_tag(new)?;
        if old_normalized == new_normalized {
            return Ok(0);
        }

        let metas = self.list_cipher_meta_full()?;
        let mut affected = 0usize;

        for meta in &metas {
            if meta
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&old_normalized))
            {
                // Decrypt full cipher
                let cipher = self.get_cipher(meta.id)?;
                let cipher = match cipher {
                    CipherRead::Decrypted(c) => c,
                    _ => continue,
                };

                let mut updated_tags: Vec<String> = cipher
                    .tags
                    .iter()
                    .map(|t| {
                        if t.eq_ignore_ascii_case(&old_normalized) {
                            new_normalized.clone()
                        } else {
                            t.clone()
                        }
                    })
                    .collect();
                updated_tags.sort();
                updated_tags.dedup();

                let input = CipherInput {
                    name: cipher.name,
                    folder_id: cipher.folder_id,
                    collection_id: None,
                    kind: cipher.kind,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    notes: cipher.notes,
                    custom_fields: cipher.custom_fields,
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history,
                    attachments: cipher.attachments,
                    archived: cipher.archived,
                    tags: updated_tags,
                };
                self.update_cipher(meta.id, &input)?;
                affected += 1;
            }
        }

        self.rebuild_tag_index()?;
        Ok(affected)
    }

    /// Delete a tag from all ciphers. Returns count of affected ciphers.
    pub fn delete_tag(&mut self, name: &str) -> Result<usize, BaluardError> {
        let normalized = Self::validate_tag(name)?;

        let metas = self.list_cipher_meta_full()?;
        let mut affected = 0usize;

        for meta in &metas {
            if meta
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&normalized))
            {
                let cipher = self.get_cipher(meta.id)?;
                let cipher = match cipher {
                    CipherRead::Decrypted(c) => c,
                    _ => continue,
                };

                let updated_tags: Vec<String> = cipher
                    .tags
                    .iter()
                    .filter(|t| !t.eq_ignore_ascii_case(&normalized))
                    .cloned()
                    .collect();

                let input = CipherInput {
                    name: cipher.name,
                    folder_id: cipher.folder_id,
                    collection_id: None,
                    kind: cipher.kind,
                    favorite: cipher.favorite,
                    reprompt: cipher.reprompt,
                    notes: cipher.notes,
                    custom_fields: cipher.custom_fields,
                    created_at: Some(cipher.created_at),
                    password_history: cipher.password_history,
                    attachments: cipher.attachments,
                    archived: cipher.archived,
                    tags: updated_tags,
                };
                self.update_cipher(meta.id, &input)?;
                affected += 1;
            }
        }

        self.rebuild_tag_index()?;
        Ok(affected)
    }

    fn find_device_id(path: &Path) -> Result<Uuid, BaluardError> {
        let keywrap_dir = path.join("meta/keywrap");
        if !keywrap_dir.exists() {
            return Err(VaultError::NotInitialized.into());
        }

        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(&keywrap_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_suffix(".json") {
                if let Ok(id) = Uuid::parse_str(id_str) {
                    candidates.push(id);
                }
            }
        }

        if candidates.is_empty() {
            return Err(VaultError::NotFound("no keywrap files found".into()).into());
        }

        // 1. Direct local device identity from meta/device-id or device-privkey.json
        if let Some(local_id) = crate::vault::device_privkey::read_device_id(path) {
            if candidates.contains(&local_id) {
                return Ok(local_id);
            }
            // S1a-2: a pending member device (introduced, awaiting the
            // approval keywrap) records a local identity that is not yet
            // in the keywrap directory. Keep it — the approval commit
            // ships the keywrap and unlock proceeds then. Never adopt
            // another device's id over a recorded local identity.
            return Ok(local_id);
        }

        // F1 fix: match local device public key against devices.json registry per device
        let registry_path = path.join("meta/devices.json");
        let registry: Option<DeviceRegistry> = if registry_path.exists() {
            std::fs::read_to_string(&registry_path)
                .ok()
                .and_then(|json| serde_json::from_str(&json).ok())
        } else {
            None
        };

        for candidate in &candidates {
            // C1: discovery runs pre-unlock (no seal key); the sealed file
            // arm fails closed, so only keyring-backed candidates can be
            // confirmed here. Single-keywrap fallback below still covers
            // keystore-less vaults.
            if let Ok(privkeys) = load_device_privkeys(path, *candidate, None) {
                let pub_key = x25519_dalek::PublicKey::from(&privkeys.x25519);
                let local_pub_hex = hex::encode(pub_key.as_bytes());
                if let Some(ref reg) = registry {
                    if let Some(device_rec) = reg.devices.get(candidate) {
                        if device_rec.encryption_public_key == local_pub_hex {
                            let _ = crate::vault::device_privkey::write_device_id(path, *candidate);
                            return Ok(*candidate);
                        }
                    }
                } else if candidates.len() == 1 {
                    let _ = crate::vault::device_privkey::write_device_id(path, *candidate);
                    return Ok(*candidate);
                }
            }
        }

        // Fallback: candidate where load_device_privkeys succeeds
        for candidate in &candidates {
            if load_device_privkeys(path, *candidate, None).is_ok() {
                let _ = crate::vault::device_privkey::write_device_id(path, *candidate);
                return Ok(*candidate);
            }
        }

        // Fallback for single keywrap file
        if candidates.len() == 1 {
            let _ = crate::vault::device_privkey::write_device_id(path, candidates[0]);
            return Ok(candidates[0]);
        }

        Err(VaultError::NotFound("matching device keywrap not found for this device".into()).into())
    }

    pub fn derive_vault_id(kdf_params: &KdfParams) -> Uuid {
        // Derive a stable UUID from the KDF salt
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"baluard-vault-id-v1");
        hasher.update(&kdf_params.salt);
        let hash = hasher.finalize();
        Uuid::from_bytes(hash[..16].try_into().unwrap())
    }

    /// Derive the vault_id from on-disk KDF params without fully opening
    /// the vault. Used by callers (e.g. daemon biometric status, which runs
    /// while the vault is locked) that need a stable per-vault identity to
    /// namespace per-vault keychain entries.
    pub fn vault_id_for_path(path: &Path) -> Result<Uuid, BaluardError> {
        let kdf_path = path.join("meta/kdf-params.json");
        let kdf_json = std::fs::read_to_string(&kdf_path)
            .map_err(|e| VaultError::Metadata(format!("reading kdf params: {e}")))?;
        let kdf_params: KdfParams = serde_json::from_str(&kdf_json)
            .map_err(|e| VaultError::Corrupt(format!("kdf params: {e}")))?;
        Ok(Self::derive_vault_id(&kdf_params))
    }

    // ── Rate limiting ──

    /// Check if too many failed unlock attempts have occurred.
    /// Exponential backoff: after N failures, wait 2^(N-5) seconds.
    /// First 5 attempts: no delay. After that: 1s, 2s, 4s, 8s, ...
    ///
    /// **Note**: This is a soft deterrent, not hard brute-force protection.
    /// The counter is stored in `meta/kdf-attempts.json` which can be deleted
    /// by any process with write access. Argon2id provides the real defense.
    fn check_attempt_rate_limit(&self) -> Result<(), BaluardError> {
        let path = self.path.join("meta/kdf-attempts.json");
        if !path.exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(&path)
            .map_err(|e| VaultError::Metadata(format!("reading attempts: {e}")))?;
        let info: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| VaultError::Corrupt(format!("attempts json: {e}")))?;
        let count = info["failed_count"].as_u64().unwrap_or(0);
        let last_ts = info["last_failed_at"].as_u64().unwrap_or(0);

        if count > 5 {
            let delay_secs = 1u64 << (count - 5).min(10); // cap at 2^10 = 1024s
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now.saturating_sub(last_ts) < delay_secs {
                return Err(VaultError::Corrupt(format!(
                    "too many failed attempts, wait {} seconds",
                    delay_secs - (now - last_ts)
                ))
                .into());
            }
        }
        Ok(())
    }

    fn record_failed_attempt(&self) -> Result<(), BaluardError> {
        let path = self.path.join("meta/kdf-attempts.json");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (count, _) = if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| VaultError::Metadata(format!("reading attempts: {e}")))?;
            let info: serde_json::Value = serde_json::from_str(&data).unwrap_or_default();
            (info["failed_count"].as_u64().unwrap_or(0), 0u64)
        } else {
            (0, 0)
        };

        let record = serde_json::json!({
            "failed_count": count + 1,
            "last_failed_at": now,
        });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record)
                .map_err(|e| VaultError::Corrupt(format!("attempts serialize: {e}")))?
                .as_bytes(),
        )?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn clear_failed_attempts(&self) -> Result<(), BaluardError> {
        let path = self.path.join("meta/kdf-attempts.json");
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Determine the current key epoch from existing vault data.
    fn determine_current_epoch(&self) -> u64 {
        // Try RK canary first (has key_epoch)
        let rk_path = self.path.join("meta/rk-canary.enc");
        if rk_path.exists() {
            if let Ok(data) = std::fs::read(&rk_path) {
                if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                    return envelope.header.key_epoch;
                }
            }
        }
        // Try first cipher envelope
        if let Ok(ids) = self.list_cipher_ids() {
            if let Some(first_id) = ids.first() {
                if let Some(file_path) = self.cipher_file_path(*first_id) {
                    if let Ok(data) = std::fs::read(&file_path) {
                        if let Ok(envelope) = crate::vault::envelope::deserialize(&data) {
                            return envelope.header.key_epoch;
                        }
                    }
                }
            }
        }
        // Default: epoch 1
        1
    }

    // ── Key Rotation (MISS-1 + MISS-2) ──

    /// Full root key rotation for single-device vaults.
    ///
    /// Atomic rotation with staged writes:
    /// 1. Generate new Root Key
    /// 2. Re-encrypt all ciphers (active + trash) to .tmp files
    /// 3. Update RK canary with new Root Key
    /// 4. Write new keywrap files for every enrolled device
    /// 5. Rename all .tmp -> final (single pass)
    /// 6. Transition epoch via DeviceManager lifecycle
    /// 7. Zeroize old Root Key
    ///
    /// After this, the old Root Key cannot decrypt any cipher.
    /// Forward secrecy is achieved.
    ///
    /// Requires unlocked vault.
    pub fn rotate_root_key(&mut self) -> Result<(), BaluardError> {
        self.quorum_gate("rotate_root_key", &serde_json::json!({}))?;
        self.rotate_root_key_internal()
    }

    /// The un-gated rotation worker. Internal callers that run under a
    /// DIFFERENT op's already-approved quorum (member removal's
    /// offboarding rotation) call this directly — re-entering the gate
    /// here would demand a second, unrelated approval mid-offboarding.
    pub(crate) fn rotate_root_key_internal(&mut self) -> Result<(), BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        if !self.device_manager.writes_allowed() {
            return Err(VaultError::Corrupt(
                "rotation in progress, use finalize_rotation()".into(),
            )
            .into());
        }

        let old_epoch = match &self.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let new_epoch = old_epoch + 1;
        let new_root_key = RootKey::generate();

        // Collect both active and trash cipher IDs
        let active_ids = self.list_cipher_ids()?;
        let trash_ids = self.list_trash_ids()?;
        let all_ids: Vec<(Uuid, bool)> = active_ids
            .iter()
            .map(|id| (*id, false))
            .chain(trash_ids.iter().map(|id| (*id, true)))
            .collect();

        // Write rotation-pending marker for crash recovery
        let pending_marker = self.path.join("meta/.rotation-pending");
        let pending_data = serde_json::json!({
            "old_epoch": old_epoch,
            "new_epoch": new_epoch,
        });
        std::fs::write(
            &pending_marker,
            serde_json::to_string_pretty(&pending_data).unwrap(),
        )?;
        let _ = std::fs::set_permissions(&pending_marker, std::fs::Permissions::from_mode(0o600));
        // B-1 fix: arm the RAII guard so a panic or early-return mid-rotation
        // sweeps staged .tmp files (ciphers, canary, keywrap) and leaves the
        // marker in place for VaultHandle::open to reconcile. Without this, a
        // crash mid-rename-loop left a mixed-epoch vault with no recovery.
        let mut _guard = RotationGuard::new(&self.path);

        // Phase 1: Re-encrypt all ciphers to .tmp files (staged).
        // S3-7c: domain-aware — the flat-only path build silently skipped
        // every collection-scoped cipher (they stayed at the old epoch).
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let old_root = unlocked.root()?.clone();
        let mut staged_renames: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (cipher_id, is_trash) in &all_ids {
            let file_path = if *is_trash {
                self.trash_file_path(*cipher_id)
            } else {
                self.cipher_file_path(*cipher_id)
            };
            let Some(file_path) = file_path else {
                continue;
            };
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile {
                id: *cipher_id,
                envelope_bytes,
            };

            let (old_item_key, new_item_key) = self.rotation_item_keys(
                unlocked,
                &old_root,
                &file_path,
                &file,
                old_epoch,
                new_epoch,
                &new_root_key,
            )?;
            // A corrupt entry must not abort the rotation mid-offboarding:
            // after the tombstone there is no retry, so the damaged file is
            // named loudly and left behind instead (2026-10-01 review).
            let mut existing = match self.try_decrypt_cipher_at(unlocked, &file_path, &file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "rotation: could not decrypt {} ({e}); the entry is left behind at the old key",
                        file_path.display()
                    );
                    continue;
                }
            };

            // P4: re-encrypt attachment blobs with the new item key (mirrors
            // revoke_device_and_rekey). Attachments live outside the cipher
            // envelope; skipping them strands every blob at the old epoch.
            for attach_meta in &existing.attachments {
                let attach_dir = self
                    .path
                    .join("entries")
                    .join(cipher_id.to_string())
                    .join("attachments");
                let attach_path = attach_dir.join(format!("{}.enc", attach_meta.id));
                if !attach_path.exists() {
                    continue;
                }
                let enc_blob = std::fs::read(&attach_path)?;
                let attach_uuid: Uuid = attach_meta
                    .id
                    .parse()
                    .map_err(|e| VaultError::Corrupt(format!("attachment id not a uuid: {e}")))?;
                let mut plaintext = crate::vault::attachment::decrypt_attachment(
                    self.vault_id,
                    *cipher_id,
                    attach_uuid,
                    old_item_key.as_bytes(),
                    &enc_blob,
                )?;
                let new_enc = crate::vault::attachment::encrypt_attachment(
                    self.vault_id,
                    *cipher_id,
                    attach_uuid,
                    new_item_key.as_bytes(),
                    &plaintext,
                    new_epoch,
                    existing.update_seq,
                )?;
                plaintext.zeroize();
                let attach_tmp = attach_path.with_extension("enc.tmp");
                std::fs::write(&attach_tmp, &new_enc)?;
                staged_renames.push((attach_tmp, attach_path));
            }

            let input = CipherInput {
                name: existing.name.clone(),
                folder_id: existing.folder_id,
                collection_id: None,
                kind: existing.kind.clone(),
                favorite: existing.favorite,
                reprompt: existing.reprompt,
                notes: existing.notes.clone(),
                custom_fields: existing.custom_fields.clone(),
                created_at: Some(existing.created_at),
                password_history: existing.password_history.clone(),
                attachments: existing.attachments.clone(),
                archived: existing.archived,
                tags: existing.tags.clone(),
            };

            let new_file = cipher::encrypt_cipher(
                self.vault_id,
                *cipher_id,
                &input,
                &new_item_key,
                new_epoch,
                existing.update_seq,
            )?;

            // Zeroize decrypted plaintext after re-encrypt (B-5: rotate_root_key
            // previously skipped this, leaving every secret in freed heap
            // after a routine non-revocation rotation).
            Self::zeroize_decrypted_cipher(&mut existing);

            // Write to .tmp path (staged)
            let tmp_path = file_path.with_extension("enc.tmp");
            std::fs::write(&tmp_path, &new_file.envelope_bytes)?;
            staged_renames.push((tmp_path, file_path));
        }

        // P4 remainder: re-encrypt the avatar. Post-flip the avatar
        // rides the SMK, which rotation does not touch — nothing to
        // re-key. Pre-flip it migrates from the outgoing root domain to
        // the incoming one (decrypt_avatar_blob falls back to the
        // legacy SGK derivation for blobs written before the re-home).
        let avatar_path = self.path.join("meta/avatar.enc");
        if avatar_path.exists() && self.unlocked().smk.is_none() {
            let blob = std::fs::read(&avatar_path)?;
            let mut plaintext = self.decrypt_avatar_blob(&blob)?;
            let new_avatar_key = zeroize::Zeroizing::new(
                crate::crypto::hkdf_derive::derive_avatar_key(new_root_key.as_bytes())?,
            );
            let new_blob = crate::vault::avatar::encrypt_avatar(&new_avatar_key, &plaintext)?;
            plaintext.zeroize();
            let avatar_tmp = avatar_path.with_extension("enc.tmp");
            std::fs::write(&avatar_tmp, &new_blob)?;
            staged_renames.push((avatar_tmp, avatar_path));
        }
        drop(old_root);

        // Phase 2: Update RK canary (staged)
        let rk_canary = super::canary::create_rk_canary(&new_root_key, self.vault_id, new_epoch)?;
        let canary_path = self.path.join("meta/rk-canary.enc");
        let canary_tmp = canary_path.with_extension("enc.tmp");
        std::fs::write(&canary_tmp, &rk_canary)?;
        let canary_rename = (canary_tmp.clone(), canary_path.clone());

        // Phase 3: Write new keywrap file (staged)
        let seal_key = self.devkey_seal();
        let privkeys = match load_device_privkeys(&self.path, self.device_id, seal_key.as_ref()) {
            Ok(k) => k,
            Err(_) => {
                // Cleanup staged files on error
                for (tmp, _) in &staged_renames {
                    let _ = std::fs::remove_file(tmp);
                }
                let _ = std::fs::remove_file(&canary_tmp);
                return Err(VaultError::NotFound(
                    "device private key not found for keywrap".into(),
                )
                .into());
            }
        };
        let x25519_public = x25519_dalek::PublicKey::from(&privkeys.x25519);
        let (eph_pub, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            new_root_key.as_bytes(),
            &x25519_public,
            "root-key-keywrap",
        )?;
        let keywrap_data = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        let keywrap_tmp = keywrap_path.with_extension("json.tmp");
        std::fs::write(
            &keywrap_tmp,
            serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )?;

        // P3: wrap the new Root Key for every OTHER enrolled ADMIN device
        // so survivors unlock on next pull. S3-7b: team members are
        // deliberately skipped — handing them the Root Key would silently
        // revert the flip's core property. Their unlocks ride the SMK
        // wrap, which the rotation does not touch (the SMK is
        // root-rotation-invariant and their wraps are identity-keyed).
        for (dev_id, dev_pub) in self
            .device_manager
            .registry
            .encryption_public_keys()
            .into_iter()
            .filter(|(dev_id, _)| {
                // S3-7b: pre-flip every device still holds the Root Key, so
                // rotation must keep refreshing their wraps (the original
                // P3 brick fix). Post-flip, team members are deliberately
                // skipped: handing them the Root Key would silently revert
                // the flip's core property. Their unlocks ride the SMK
                // wrap, which the rotation does not touch.
                let flipped = crate::vault::space_meta::shape_flipped(&self.path);
                *dev_id == self.device_id || !flipped || self.device_maps_to_admin(*dev_id)
            })
        {
            if dev_id == self.device_id {
                continue;
            }
            let (dev_eph, dev_ct, dev_tag) = crate::crypto::hpke_wrap::wrap_key(
                new_root_key.as_bytes(),
                &x25519_dalek::PublicKey::from(dev_pub),
                "root-key-keywrap",
            )?;
            let dev_data = serde_json::json!({
                "device_id": dev_id.to_string(),
                "ephemeral_public": hex::encode(dev_eph),
                "encrypted_key": hex::encode(dev_ct),
                "tag": hex::encode(dev_tag),
            });
            let dev_path = self.path.join(format!("meta/keywrap/{dev_id}.json"));
            let dev_tmp = dev_path.with_extension("json.tmp");
            std::fs::write(&dev_tmp, serde_json::to_string_pretty(&dev_data).unwrap())?;
            staged_renames.push((dev_tmp, dev_path));
        }

        // Phase 4: Atomic commit - rename all .tmp -> final
        // Order matters for crash safety: ciphers first, canary second, keywrap last.
        // If crash occurs mid-way, .rotation-pending marker enables recovery.
        // 1. Commit all cipher files first (the bulk of the data)
        for (tmp, final_path) in &staged_renames {
            std::fs::rename(tmp, final_path)?;
        }
        // 2. Commit RK canary (signals new root key is active)
        std::fs::rename(&canary_rename.0, &canary_rename.1)?;
        // 3. Commit keywrap last (point of no return)
        std::fs::rename(&keywrap_tmp, &keywrap_path)?;

        // Read folders/tags/profile/settings/generator history with OLD root
        // key before swap (P4: settings and generator history joined the
        // coverage set — both are root-key-derived and unreadable after the
        // swap without an explicit re-encrypt).
        // P4: these reads PROPAGATE failures -- `.ok()` silently skipped an
        // artifact whose read failed, stranding it at the old epoch after the
        // swap with no error reported. Missing files already return
        // Ok(empty) inside the readers; `.ok()` is not needed.
        let old_folders = self.list_folders()?;
        let old_tags = self.list_tags()?;
        let old_profile = self.load_profile()?;
        let old_activity = self.load_activity_enc()?;
        let old_settings = self.get_settings()?;
        let old_generator = self.load_generator_history()?;
        // S1a-3: the address book is RootKey-derived — read pre-swap.
        let old_contacts = self.load_contacts()?;
        // S2 IS-4b: the outbox registries are RootKey-derived — read
        // pre-swap, re-encrypt under the new outbox key post-swap.
        let old_outboxes = self.outbox_list()?;
        let old_links = self.outbox_links()?;
        let old_templates = self.templates_list()?;
        // S3-1 rotation coverage: decrypt collection content keys with the
        // outgoing SGK before the swap (rewrapped post-swap).
        let old_collection_keys =
            crate::vault::collections::collect_content_keys(&self.path, self.unlocked().sgk()?)?;
        // S3-7a: open the SMK with the OUTGOING root (the store is sealed
        // under it). Any failure means no usable SMK rides this rotation:
        // unprepared (NotFound) or already-dead (damaged by a previous
        // crashed rotation). Neither may wedge the rotation itself:
        // prepare re-mints and re-wraps everyone, so skipping is the
        // convergent choice.
        let old_space_smk =
            crate::vault::space_meta::open_store(&self.path, self.unlocked().root()?).ok();
        // S1b-1: the activity log rides the meta IKM — read pre-swap.
        // Local-only per-device file: an unreadable log (key-source
        // transition) reads as empty; the post-swap save re-seals it.
        let old_events =
            crate::vault::events::load(&self.path, self.vault_id, &self.unlocked().meta_ikm())
                .unwrap_or_default();
        // S4-2 rotation coverage: group keys ride the same pre-swap read
        // (gk_wrapped is SGK-epoch-sealed; gkwraps and ckwraps are
        // identity/GK-keyed and rotation-invariant).
        let old_group_keys =
            crate::vault::groups::collect_group_keys(&self.path, self.unlocked().sgk()?)?;

        // Phase 5: Swap Root Key and update epoch via DeviceManager lifecycle
        match &mut self.state {
            VaultState::Unlocked(u) => {
                if let Some(mut k) = u.root_key.take() {
                    k.zeroize();
                }
                u.root_key = Some(new_root_key.clone());
                if let Some(mut k) = u.space_group_key.take() {
                    k.zeroize();
                }
                u.space_group_key =
                    Some(crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                        &new_root_key,
                        new_epoch,
                    ));
                u.current_epoch = new_epoch;
                u.item_keys.clear();
            }
            VaultState::Locked => return Err(VaultError::Locked.into()),
        }

        // H4 fix: proper epoch lifecycle through DeviceManager
        // Clean transition: old ACTIVE -> new ACTIVE (single-device shortcut)
        self.device_manager
            .single_device_commit_rotation(new_epoch)?;

        // Fire observer hook
        if let Some(vp) = self.vault_path_as_ref() {
            self.device_manager.notify_rotation_committed(new_epoch, vp);
        }

        // Re-encrypt folders/tags/profile/settings/generator history with the
        // NEW root key. P4: failures PROPAGATE — a silent failure here
        // stranded the artifact at the old epoch, unreadable after the swap.
        // On failure the .rotation-pending marker is intentionally left in
        // place (the guard is not disarmed on error paths below): the vault
        // stays flagged incomplete until finalize_rotation reconciles.
        self.save_folders(&old_folders)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let index = crate::vault::manifest::TagIndex {
            tags: old_tags,
            updated_at: now,
        };
        self.save_tags_enc(&index)?;
        self.save_profile(&old_profile)?;
        self.save_activity_enc(&old_activity)?;
        self.save_settings(&old_settings)?;
        self.save_generator_history(&old_generator)?;
        // S1a-3: address book re-encrypted under the new contacts key.
        self.save_contacts(&old_contacts)?;
        // S2 IS-4b: outbox registries re-encrypted under the new key.
        crate::vault::outbox::save_owner_registry(&self.path, &self.outbox_key()?, &old_outboxes)?;
        crate::vault::outbox::save_links(&self.path, &self.outbox_key()?, &old_links)?;
        crate::vault::templates::save_templates(
            &self.path,
            self.unlocked().root()?.as_bytes(),
            &old_templates,
        )?;
        crate::vault::collections::rewrap_from_plaintexts(
            &self.path,
            self.unlocked().sgk()?,
            &old_collection_keys,
        )?;
        // S3-7a: re-seal the space store under the new root. P4 rule:
        // failures propagate (a skipped reseal orphans the SMK).
        if let Some(smk) = &old_space_smk {
            crate::vault::space_meta::reseal_store(&self.path, self.unlocked().root()?, smk)?;
        }
        // S4-2: re-seal every group key under the NEW SGK epoch.
        crate::vault::groups::rewrap_group_keys(
            &self.path,
            self.unlocked().sgk()?,
            &old_group_keys,
        )?;
        // S1b-1: activity log re-encrypted under the new events key.
        crate::vault::events::save(
            &self.path,
            self.vault_id,
            &self.unlocked().meta_ikm(),
            self.unlocked().current_epoch,
            &old_events,
        )?;

        // P4: re-wrap the emergency escrow to the NEW root key. The old
        // escrow hands emergency recovery a stale key whose canary check
        // fails — silently breaking emergency access after any rotation.
        // Skipped when emergency access is not configured or is revoked.
        // This runs BEFORE the rotation state is cleared: any failure here
        // propagates with the .rotation-pending marker still on disk, so the
        // next open warns that the rotation did not complete cleanly.
        if let Some(mut config) = crate::emergency::load_emergency_config(&self.path)? {
            if !matches!(config.status, crate::emergency::EmergencyStatus::Revoked) {
                let contact_bytes: [u8; 32] = config
                    .trusted_contact_pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                    VaultError::Corrupt("invalid emergency contact pubkey length".into())
                })?;
                let contact = x25519_dalek::PublicKey::from(contact_bytes);
                config.wrapped_root_key = crate::orgs::wrap_to_bundle(
                    new_root_key.as_bytes(),
                    &contact,
                    "emergency-escrow",
                )?;
                let seal = self.devkey_seal();
                let privkeys = load_device_privkeys(&self.path, self.device_id, seal.as_ref())?;
                crate::emergency::sign_status(
                    &mut config,
                    &privkeys.ed25519,
                    &self.vault_id.to_string(),
                )?;
                crate::emergency::save_emergency_config(&self.path, &config)?;
            }
        }

        // H4 fix: re-wrap recovery key with new Root Key (propagate error)
        Self::rewrap_recovery_key(&self.path, &new_root_key)?;
        // S4-7: the Space Recovery Kit's phrase must keep working after
        // a rotation — rewrap to the NEW root (absent kit is a no-op).
        crate::vault::recovery_kit::rewrap_kit(&self.path, &new_root_key)?;

        // Success: only now clear the rotation state. Every fallible step
        // above propagated its error while the guard was still armed, so a
        // failure leaves the marker on disk and the next open warns that the
        // rotation did not complete cleanly.
        _guard.disarm();
        std::fs::remove_file(self.path.join("meta/.rotation-pending"))?;

        Ok(())
    }

    /// Zeroize sensitive plaintext fields of a decrypted cipher in place.
    ///
    /// Shared by `rotate_root_key` and `revoke_device_and_rekey` so the
    /// per-kind zeroize logic cannot drift between them (B-5: rotate_root_key
    /// previously skipped this entirely, leaving every secret in the vault
    /// lingering in freed heap after a routine non-revocation rotation).
    ///
    /// Mirrors the field set in [`crate::sync::conflict::ConflictInfo::drop`].
    /// Notes, custom-field hidden values, and the kind-specific secret fields
    /// (Login password/TOTP/passkey keys, Card number/code, SshKey private
    /// key) are zeroized. Public/non-secret fields (names, URIs, etc.) are
    /// left for the caller to drop normally.
    fn zeroize_decrypted_cipher(existing: &mut crate::types::Cipher) {
        use zeroize::Zeroize;
        if let Some(n) = existing.notes.as_mut() {
            n.zeroize();
        }
        for cf in existing.custom_fields.iter_mut() {
            if matches!(cf.field_type, crate::types::CustomFieldType::Hidden) {
                cf.value.zeroize();
            }
        }
        match &mut existing.kind {
            crate::types::CipherKind::Login(d) => {
                if let Some(p) = d.password.as_mut() {
                    p.zeroize();
                }
                if let Some(u) = d.username.as_mut() {
                    u.zeroize();
                }
                if let Some(t) = d.totp_uri.as_mut() {
                    t.zeroize();
                }
                if let Some(ref mut fido2_list) = d.fido2_credentials {
                    for pk in fido2_list.iter_mut() {
                        if let Some(k) = pk.private_key.as_mut() {
                            k.zeroize();
                        }
                        if let Some(k) = pk.prf_key.as_mut() {
                            k.zeroize();
                        }
                    }
                }
            }
            crate::types::CipherKind::Card(d) => {
                if let Some(n) = d.number.as_mut() {
                    n.zeroize();
                }
                if let Some(c) = d.code.as_mut() {
                    c.zeroize();
                }
            }
            crate::types::CipherKind::SshKey(d) => {
                if let Some(k) = d.private_key.as_mut() {
                    k.zeroize();
                }
            }
            crate::types::CipherKind::Identity(_)
            | crate::types::CipherKind::BankAccount(_)
            | crate::types::CipherKind::DriversLicense(_)
            | crate::types::CipherKind::Passport(_)
            | crate::types::CipherKind::SecureNote => {}
        }
    }

    /// Re-wrap the Root Key in meta/recovery.json after rotation.
    /// Reads the stored recovery X25519 public key and HPKE-wraps the new Root Key.
    /// If recovery.json doesn't exist or lacks the pubkey field, silently skips.
    fn rewrap_recovery_key(vault_path: &Path, new_root_key: &RootKey) -> Result<(), BaluardError> {
        let recovery_path = vault_path.join("meta/recovery.json");
        if !recovery_path.exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(&recovery_path)
            .map_err(|e| VaultError::Metadata(format!("read recovery.json: {e}")))?;
        let mut json: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| VaultError::Corrupt(format!("parse recovery.json: {e}")))?;

        let pubkey_hex = match json["recovery_x25519_pubkey"].as_str() {
            Some(h) => h,
            None => {
                // Legacy vault without pubkey field — cannot re-wrap.
                // Recovery phrase will unwrap the OLD Root Key, which is stale after rotation.
                // Log loudly; user should re-create vault or re-enroll via recovery phrase.
                eprintln!(
                    "WARNING: recovery.json lacks recovery_x25519_pubkey; recovery re-wrap skipped. \
                     Recovery phrase will NOT work after this rotation. \
                     Re-enroll via recovery phrase to fix."
                );
                return Ok(());
            }
        };

        let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex)
            .map_err(|e| VaultError::Corrupt(format!("recovery pubkey hex: {e}")))?
            .try_into()
            .map_err(|_| VaultError::Corrupt("recovery pubkey wrong length".into()))?;

        let pubkey = x25519_dalek::PublicKey::from(pubkey_bytes);
        let (eph_pub, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            new_root_key.as_bytes(),
            &pubkey,
            "recovery-keywrap",
        )?;

        // Update the JSON in-place
        json["ephemeral_public"] = serde_json::Value::String(hex::encode(eph_pub));
        json["encrypted_key"] = serde_json::Value::String(hex::encode(ct));
        json["tag"] = serde_json::Value::String(hex::encode(tag));

        let tmp = recovery_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&json).unwrap())?;
        // H4 fix: enforce 0600 on file holding HPKE-wrapped Root Key
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        std::fs::rename(&tmp, &recovery_path)?;

        Ok(())
    }
    ///
    /// Generates a new Root Key, wraps it for all enrolled devices,
    /// and transitions the epoch to ROTATING.
    ///
    /// After calling this, the caller should:
    /// Revoke a device and perform full root key rotation.
    ///
    /// This is the correct entry point for device revocation. It:
    /// 1. Validates all preconditions (unlocked, not self, privkey readable)
    /// 2. Writes crash-recovery marker
    /// 3. Removes the target device from the registry and generates new Root Key
    /// 4. Re-encrypts all ciphers (active + trash) and attachments with the new key
    /// 5. Updates the RK canary
    /// 6. Writes a new keywrap file for this device
    /// 7. Updates in-memory state
    /// 8. Cleans up the revoked device's keywrap
    ///
    /// Cannot revoke self. Use force-evict from another device for that.
    /// Requires unlocked vault.
    pub fn revoke_device_and_rekey(
        &mut self,
        target_device_id: Uuid,
    ) -> Result<crate::device_manager::RevokeDeviceResult, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        // Same quorum class as removal: revoking a device rotates the
        // Root Key, so it must not become the threshold bypass.
        self.quorum_gate(
            "device_revoke",
            &serde_json::json!({ "device_id": target_device_id }),
        )?;
        if target_device_id == self.device_id {
            return Err(VaultError::InvalidOperation(
                "cannot revoke the current device. Use force-evict from another device.".into(),
            )
            .into());
        }

        let old_epoch = match &self.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // ── Precheck: validate privkey accessible BEFORE any irreversible change ──
        let seal_key = self.devkey_seal();
        let privkeys = load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())?;

        // ── Write crash-recovery marker and setup cleanup guard ──
        let pending_marker = self.path.join("meta/.rotation-pending");
        let pending_data = serde_json::json!({
            "old_epoch": old_epoch,
            "new_epoch": old_epoch + 1,
        });
        std::fs::write(
            &pending_marker,
            serde_json::to_string_pretty(&pending_data).unwrap(),
        )?;
        let _ = std::fs::set_permissions(&pending_marker, std::fs::Permissions::from_mode(0o600));
        let mut _guard = RotationGuard::new(&self.path);

        // ── Commit: revoke in registry and get new root key ──
        let mut result = self
            .device_manager
            .revoke_device_and_rotate(target_device_id, self.device_id)?;
        let new_root_key = result
            .new_root_key
            .as_ref()
            .ok_or_else(|| VaultError::Corrupt("revoke returned no new root key".into()))?
            .clone();
        let new_epoch = result.new_epoch;

        // ── Clone old root key once (borrow-safe for loop) ──
        let old_root = match &self.state {
            VaultState::Unlocked(u) => u.root()?.clone(),
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // ── Re-encrypt all ciphers (active + trash) and attachments to .tmp ──
        let active_ids = self.list_cipher_ids()?;
        let trash_ids = self.list_trash_ids()?;
        let all_ids: Vec<(Uuid, bool)> = active_ids
            .iter()
            .map(|id| (*id, false))
            .chain(trash_ids.iter().map(|id| (*id, true)))
            .collect();

        // S3-7c: domain-aware (mirrors rotate_root_key — the flat-only
        // path build skipped collection-scoped ciphers).
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };
        let mut staged_renames: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (cipher_id, is_trash) in &all_ids {
            let file_path = if *is_trash {
                self.trash_file_path(*cipher_id)
            } else {
                self.cipher_file_path(*cipher_id)
            };
            let Some(file_path) = file_path else {
                continue;
            };
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile {
                id: *cipher_id,
                envelope_bytes,
            };

            let (old_item_key, new_item_key) = self.rotation_item_keys(
                unlocked,
                &old_root,
                &file_path,
                &file,
                old_epoch,
                new_epoch,
                &new_root_key,
            )?;
            // Same corrupt-entry skip as the twin loop above: one garbage
            // file must not brick a removal's rotation.
            let mut existing = match self.try_decrypt_cipher_at(unlocked, &file_path, &file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "rotation: could not decrypt {} ({e}); the entry is left behind at the old key",
                        file_path.display()
                    );
                    continue;
                }
            };
            for attach_meta in &existing.attachments {
                let attach_dir = self
                    .path
                    .join("entries")
                    .join(cipher_id.to_string())
                    .join("attachments");
                let attach_path = attach_dir.join(format!("{}.enc", attach_meta.id));
                if !attach_path.exists() {
                    continue;
                }
                let enc_blob = std::fs::read(&attach_path)?;
                let attach_uuid: Uuid = attach_meta
                    .id
                    .parse()
                    .map_err(|e| VaultError::Corrupt(format!("attachment id not a uuid: {e}")))?;
                let mut plaintext = crate::vault::attachment::decrypt_attachment(
                    self.vault_id,
                    *cipher_id,
                    attach_uuid,
                    old_item_key.as_bytes(),
                    &enc_blob,
                )?;
                let new_enc = crate::vault::attachment::encrypt_attachment(
                    self.vault_id,
                    *cipher_id,
                    attach_uuid,
                    new_item_key.as_bytes(),
                    &plaintext,
                    new_epoch,
                    existing.update_seq,
                )?;
                plaintext.zeroize();
                let attach_tmp = attach_path.with_extension("enc.tmp");
                std::fs::write(&attach_tmp, &new_enc)?;
                staged_renames.push((attach_tmp, attach_path));
            }

            let input = CipherInput {
                name: existing.name.clone(),
                folder_id: existing.folder_id,
                collection_id: None,
                kind: existing.kind.clone(),
                favorite: existing.favorite,
                reprompt: existing.reprompt,
                notes: existing.notes.clone(),
                custom_fields: existing.custom_fields.clone(),
                created_at: Some(existing.created_at),
                password_history: existing.password_history.clone(),
                attachments: existing.attachments.clone(),
                archived: existing.archived,
                tags: existing.tags.clone(),
            };

            let new_file = cipher::encrypt_cipher(
                self.vault_id,
                *cipher_id,
                &input,
                &new_item_key,
                new_epoch,
                existing.update_seq,
            )?;

            // Zeroize decrypted plaintext after use (B-5: shared helper so
            // rotate_root_key and revoke_device_and_rekey cannot drift).
            Self::zeroize_decrypted_cipher(&mut existing);

            let tmp_path = file_path.with_extension("enc.tmp");
            std::fs::write(&tmp_path, &new_file.envelope_bytes)?;
            staged_renames.push((tmp_path, file_path));
        }
        drop(old_root);

        // P4 remainder: re-encrypt the avatar. Post-flip the avatar
        // rides the SMK, which rotation does not touch — nothing to
        // re-key. Pre-flip it migrates from the outgoing root domain to
        // the incoming one (decrypt_avatar_blob falls back to the
        // legacy SGK derivation for blobs written before the re-home).
        let avatar_path = self.path.join("meta/avatar.enc");
        if avatar_path.exists() && self.unlocked().smk.is_none() {
            let blob = std::fs::read(&avatar_path)?;
            let mut plaintext = self.decrypt_avatar_blob(&blob)?;
            let new_avatar_key = zeroize::Zeroizing::new(
                crate::crypto::hkdf_derive::derive_avatar_key(new_root_key.as_bytes())?,
            );
            let new_blob = crate::vault::avatar::encrypt_avatar(&new_avatar_key, &plaintext)?;
            plaintext.zeroize();
            let avatar_tmp = avatar_path.with_extension("enc.tmp");
            std::fs::write(&avatar_tmp, &new_blob)?;
            staged_renames.push((avatar_tmp, avatar_path));
        }

        // ── Update RK canary (staged) ──
        let rk_canary = super::canary::create_rk_canary(&new_root_key, self.vault_id, new_epoch)?;
        let canary_path = self.path.join("meta/rk-canary.enc");
        let canary_tmp = canary_path.with_extension("enc.tmp");
        std::fs::write(&canary_tmp, &rk_canary)?;

        // ── Write keywrap for current device (staged) ──
        let x25519_public = x25519_dalek::PublicKey::from(&privkeys.x25519);
        let (eph_pub, ct, tag) =
            hpke_wrap::wrap_key(new_root_key.as_bytes(), &x25519_public, "root-key-keywrap")?;
        let keywrap_data = serde_json::json!({
            "device_id": self.device_id.to_string(),
            "ephemeral_public": hex::encode(eph_pub),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        let keywrap_path = self
            .path
            .join(format!("meta/keywrap/{}.json", self.device_id));
        let keywrap_tmp = keywrap_path.with_extension("json.tmp");
        std::fs::write(
            &keywrap_tmp,
            serde_json::to_string_pretty(&keywrap_data).unwrap(),
        )?;

        // ── Atomic commit: rename all .tmp -> final ──
        for (tmp, final_path) in &staged_renames {
            std::fs::rename(tmp, final_path)?;
        }
        std::fs::rename(&canary_tmp, &canary_path)?;
        std::fs::rename(&keywrap_tmp, &keywrap_path)?;

        // ── Remove revoked device's keywrap file ──
        let revoked_keywrap = self
            .path
            .join(format!("meta/keywrap/{target_device_id}.json"));
        let _ = std::fs::remove_file(&revoked_keywrap);

        // Read folders/tags/profile/settings/generator history with OLD root
        // key before swap (P4: settings and generator history joined the
        // coverage set — both are root-key-derived and unreadable after the
        // swap without an explicit re-encrypt).
        // P4: these reads PROPAGATE failures -- `.ok()` silently skipped an
        // artifact whose read failed, stranding it at the old epoch after the
        // swap with no error reported. Missing files already return
        // Ok(empty) inside the readers; `.ok()` is not needed.
        let old_folders = self.list_folders()?;
        let old_tags = self.list_tags()?;
        let old_profile = self.load_profile()?;
        let old_activity = self.load_activity_enc()?;
        let old_settings = self.get_settings()?;
        let old_generator = self.load_generator_history()?;
        // S1a-3: the address book is RootKey-derived — read pre-swap.
        let old_contacts = self.load_contacts()?;
        // S2 IS-4b: the outbox registries are RootKey-derived — read
        // pre-swap, re-encrypt under the new outbox key post-swap.
        let old_outboxes = self.outbox_list()?;
        let old_links = self.outbox_links()?;
        let old_templates = self.templates_list()?;
        // S3-1 rotation coverage: decrypt collection content keys with the
        // outgoing SGK before the swap (rewrapped post-swap).
        let old_collection_keys =
            crate::vault::collections::collect_content_keys(&self.path, self.unlocked().sgk()?)?;
        // S3-7a: open the SMK with the OUTGOING root (the store is sealed
        // under it). Any failure means no usable SMK rides this rotation:
        // unprepared (NotFound) or already-dead (damaged by a previous
        // crashed rotation). Neither may wedge the rotation itself:
        // prepare re-mints and re-wraps everyone, so skipping is the
        // convergent choice.
        let old_space_smk =
            crate::vault::space_meta::open_store(&self.path, self.unlocked().root()?).ok();
        // S1b-1: the activity log rides the meta IKM — read pre-swap.
        // Local-only per-device file: an unreadable log (key-source
        // transition) reads as empty; the post-swap save re-seals it.
        let old_events =
            crate::vault::events::load(&self.path, self.vault_id, &self.unlocked().meta_ikm())
                .unwrap_or_default();
        // S4-2 rotation coverage: group keys ride the same pre-swap read
        // (gk_wrapped is SGK-epoch-sealed; gkwraps and ckwraps are
        // identity/GK-keyed and rotation-invariant).
        let old_group_keys =
            crate::vault::groups::collect_group_keys(&self.path, self.unlocked().sgk()?)?;

        // ── Update in-memory state ──
        match &mut self.state {
            VaultState::Unlocked(u) => {
                if let Some(mut k) = u.root_key.take() {
                    k.zeroize();
                }
                u.root_key = Some(new_root_key.clone());
                if let Some(mut k) = u.space_group_key.take() {
                    k.zeroize();
                }
                u.space_group_key =
                    Some(crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(
                        &new_root_key,
                        new_epoch,
                    ));
                u.current_epoch = new_epoch;
                u.item_keys.clear();
            }
            VaultState::Locked => return Err(VaultError::Locked.into()),
        }

        // Zeroize new root key in result (callers only need metadata)
        result.new_root_key = None;

        self.sync_registry_from_device_manager();

        if let Some(vp) = self.vault_path_as_ref() {
            self.device_manager.notify_rotation_committed(new_epoch, vp);
        }

        // Re-encrypt folders/tags/profile/settings/generator history with the
        // NEW root key. P4: failures PROPAGATE — a silent failure here
        // stranded the artifact at the old epoch, unreadable after the swap.
        // On failure the .rotation-pending marker is intentionally left in
        // place (the guard is not disarmed on error paths below): the vault
        // stays flagged incomplete until finalize_rotation reconciles.
        self.save_folders(&old_folders)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let index = crate::vault::manifest::TagIndex {
            tags: old_tags,
            updated_at: now,
        };
        self.save_tags_enc(&index)?;
        self.save_profile(&old_profile)?;
        self.save_activity_enc(&old_activity)?;
        self.save_settings(&old_settings)?;
        self.save_generator_history(&old_generator)?;
        // S1a-3: address book re-encrypted under the new contacts key.
        self.save_contacts(&old_contacts)?;
        // S2 IS-4b: outbox registries re-encrypted under the new key.
        crate::vault::outbox::save_owner_registry(&self.path, &self.outbox_key()?, &old_outboxes)?;
        crate::vault::outbox::save_links(&self.path, &self.outbox_key()?, &old_links)?;
        crate::vault::templates::save_templates(
            &self.path,
            self.unlocked().root()?.as_bytes(),
            &old_templates,
        )?;
        crate::vault::collections::rewrap_from_plaintexts(
            &self.path,
            self.unlocked().sgk()?,
            &old_collection_keys,
        )?;
        // S3-7a: re-seal the space store under the new root. P4 rule:
        // failures propagate (a skipped reseal orphans the SMK).
        if let Some(smk) = &old_space_smk {
            crate::vault::space_meta::reseal_store(&self.path, self.unlocked().root()?, smk)?;
        }
        // S4-2: re-seal every group key under the NEW SGK epoch.
        crate::vault::groups::rewrap_group_keys(
            &self.path,
            self.unlocked().sgk()?,
            &old_group_keys,
        )?;
        // S1b-1: activity log re-encrypted under the new events key.
        crate::vault::events::save(
            &self.path,
            self.vault_id,
            &self.unlocked().meta_ikm(),
            self.unlocked().current_epoch,
            &old_events,
        )?;

        // P4: re-wrap the emergency escrow to the NEW root key. The old
        // escrow hands emergency recovery a stale key whose canary check
        // fails — silently breaking emergency access after any rotation.
        // Skipped when emergency access is not configured or is revoked.
        // Runs BEFORE the rotation state is cleared: any failure here
        // propagates with the .rotation-pending marker still on disk.
        if let Some(mut config) = crate::emergency::load_emergency_config(&self.path)? {
            if !matches!(config.status, crate::emergency::EmergencyStatus::Revoked) {
                let contact_bytes: [u8; 32] = config
                    .trusted_contact_pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                    VaultError::Corrupt("invalid emergency contact pubkey length".into())
                })?;
                let contact = x25519_dalek::PublicKey::from(contact_bytes);
                config.wrapped_root_key = crate::orgs::wrap_to_bundle(
                    new_root_key.as_bytes(),
                    &contact,
                    "emergency-escrow",
                )?;
                let seal = self.devkey_seal();
                let privkeys = load_device_privkeys(&self.path, self.device_id, seal.as_ref())?;
                crate::emergency::sign_status(
                    &mut config,
                    &privkeys.ed25519,
                    &self.vault_id.to_string(),
                )?;
                crate::emergency::save_emergency_config(&self.path, &config)?;
            }
        }

        // H4 fix: re-wrap recovery key with new Root Key (propagate error)
        Self::rewrap_recovery_key(&self.path, &new_root_key)?;
        // S4-7: the Space Recovery Kit's phrase must keep working after
        // a rotation — rewrap to the NEW root (absent kit is a no-op).
        crate::vault::recovery_kit::rewrap_kit(&self.path, &new_root_key)?;

        // Success: only now clear the rotation state (same ordering rationale
        // as rotate_root_key — the marker must survive any failure).
        _guard.disarm();
        std::fs::remove_file(&pending_marker)?;

        Ok(result)
    }

    /// 1. If multi-device: git push the .txn file
    /// 2. If single-device: call `finalize_rotation()` immediately
    ///
    /// Requires unlocked vault.
    pub fn initiate_key_rotation(&mut self) -> Result<RootKey, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        let (new_root, _tx) = self.device_manager.initiate_rotation(self.device_id)?;
        Ok(new_root)
    }

    /// Check if there is a pending rotation that needs processing.
    pub fn has_pending_rotation(&self) -> bool {
        self.device_manager.epoch_state() == crate::keys::epoch::EpochState::Rotating
    }

    /// Get the current epoch state from DeviceManager.
    pub fn epoch_state(&self) -> crate::keys::epoch::EpochState {
        self.device_manager.epoch_state()
    }

    /// Finalize a rotation after quorum is reached (or single-device self-ack).
    ///
    /// This method:
    /// 1. Records a self-ack for single-device scenarios
    /// 2. Commits the rotation if quorum is reached
    ///
    /// Returns true if the rotation was committed.
    pub fn finalize_rotation(&mut self) -> Result<bool, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }

        let _epoch = self.device_manager.current_epoch();
        let tx_ref = self.device_manager.pending_transaction();
        let tx = match tx_ref {
            Some(tx) => tx,
            None => return Err(VaultError::Corrupt("no pending rotation".into()).into()),
        };

        // Build self-ack: sign with this device's Ed25519 key
        let txn_hash = crate::device_manager::compute_txn_hash(tx);

        let sign_input =
            crate::device_manager::build_ack_sign_input(tx.new_epoch, &self.device_id, &txn_hash);

        // Load signing key
        let seal_key = self.devkey_seal();
        let privkeys = load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())?;

        use crate::crypto::signature;
        let ack_sig = signature::sign(&privkeys.ed25519, &sign_input)?;

        let ack = crate::device_manager::RotationAck {
            epoch: tx.new_epoch,
            device_id: self.device_id,
            txn_hash: txn_hash.clone(),
            signature: ack_sig.to_bytes().to_vec(),
        };

        self.device_manager.record_ack(ack)
    }

    /// Emergency force evict: removes all other devices, initiates rotation.
    /// For single-device vaults, commits immediately.
    ///
    /// Returns the result of the eviction.
    pub fn force_evict_and_rotate(
        &mut self,
    ) -> Result<crate::device_manager::ForceEvictResult, BaluardError> {
        if !self.is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let result = self.device_manager.force_evict_and_rotate(self.device_id)?;
        // M6 fix: sync registry after eviction
        self.sync_registry_from_device_manager();
        Ok(result)
    }

    /// Recover vault from BIP-39 recovery phrase.
    /// Resets the device registry and enrolls this device as sole survivor.
    ///
    /// Returns the recovered Root Key and new device entry.
    pub fn recover_from_phrase(
        &mut self,
        phrase: &str,
        device_name: &str,
    ) -> Result<crate::device_manager::RecoveryResult, BaluardError> {
        let result = self
            .device_manager
            .recover_from_phrase(phrase, device_name)?;
        // M6 fix: sync registry after recovery
        self.sync_registry_from_device_manager();
        Ok(result)
    }

    /// Rebuild index.enc from active ciphers on disk.
    pub fn rebuild_index(&self) -> Result<(), BaluardError> {
        let unlocked = match &self.state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked.into()),
        };

        // Review F4: scan the SAME id set a member staleness guard would
        // compare against, so the rebuilt index matches on the next read.
        let ids = self.scannable_cipher_ids(unlocked)?;
        let dirs = crate::vault::collections::load_dir_map(&self.path);
        let mut metas = Vec::with_capacity(ids.len());
        let mut skipped: Vec<uuid::Uuid> = Vec::new();

        for id in ids {
            let Some(file_path) = self.cipher_file_path(id) else {
                continue;
            };
            let file_dir = file_path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(|n| n.to_string());
            let envelope_bytes = std::fs::read(&file_path)?;
            let file = cipher::CipherFile { id, envelope_bytes };

            let c = match self.try_decrypt_cipher_at(unlocked, &file_path, &file) {
                Ok(c) => c,
                Err(crate::error::BaluardError::Vault(crate::error::VaultError::CrossEpoch {
                    envelope_epoch,
                    held_epoch,
                })) => {
                    // Cipher at a key epoch the held RootKey/SGK cannot reach.
                    // Previously this was silently `continue`d, which made the
                    // entry vanish from vault.list with no signal. Surface it
                    // so the user knows a re-sync / device refresh is needed
                    // (B-2 fix). Still skip rather than fail the whole list —
                    // a vault with one stray remote blob should still render.
                    eprintln!(
                        "warning: cipher {id} at epoch {envelope_epoch} cannot be decrypted with held epoch {held_epoch}; skipping from index",
                    );
                    skipped.push(id);
                    continue;
                }
                Err(e) => {
                    // Genuine corrupt envelope / IO error: log and skip rather
                    // than abort the whole index (graceful degradation), but
                    // keep this path noisy so it does not hide silent loss.
                    eprintln!("warning: cipher {id} skipped during index build: {e}");
                    skipped.push(id);
                    continue;
                }
            };

            let username = match &c.kind {
                crate::types::CipherKind::Login(data) => data.username.clone(),
                _ => None,
            };

            metas.push(crate::types::CipherMeta {
                id: c.id,
                name: c.name,
                folder_id: c.folder_id,
                cipher_type: c.kind.cipher_type(),
                favorite: c.favorite,
                reprompt: c.reprompt,
                username,
                tier: c.tier,
                key_epoch: c.key_epoch,
                update_seq: c.update_seq,
                updated_at: c.updated_at,
                archived: c.archived,
                tags: c.tags.clone(),
                collection_id: dirs
                    .iter()
                    .find(|(name, _)| Some(name) == file_dir.as_ref())
                    .map(|(_, id)| *id),
            });
        }

        let index_key = hkdf_derive::derive_index_key(&unlocked.meta_ikm())?;
        let index_dir = self.path.join("meta");
        std::fs::create_dir_all(&index_dir)?;
        // P5b: sharded write — deterministic shard boundaries, orphaned
        // higher shards pruned, single-shard vaults byte-compatible with the
        // legacy index.enc layout. `skipped` rides shard 0 so the reader's
        // staleness check can compare like-for-like counts.
        index::write_sharded(
            self.vault_id,
            &metas,
            &index_key,
            unlocked.current_epoch,
            &index_dir,
            &skipped,
        )?;

        Ok(())
    }

    /// H3 fix: Record integrity checkpoint after cipher writes.
    /// Best-effort: loads manifest, records checkpoint signed with device Ed25519 key,
    /// saves. Failures are logged, not propagated (integrity is defense-in-depth, not gating).
    fn record_integrity(&self, object_id: &str, seq: u64) {
        let Ok(mut manifest) = crate::integrity::IntegrityManifest::load(&self.path) else {
            return;
        };
        let seal_key = self.devkey_seal();
        let Ok(privkeys) = load_device_privkeys(&self.path, self.device_id, seal_key.as_ref())
        else {
            return;
        };
        let signing_key = privkeys.ed25519;
        if manifest
            .record(object_id, seq, &self.device_id.to_string(), &signing_key)
            .is_err()
        {
            return;
        }
        if manifest.save(&self.path).is_err() {
            // intentionally ignored: this is the last step, fall through
        }
    }
    /// H3 fix: Remove integrity checkpoint on cipher delete.
    /// Prevents false rollback alarms for legitimately deleted entries.
    fn remove_integrity(&self, object_id: &str) {
        let Ok(mut manifest) = crate::integrity::IntegrityManifest::load(&self.path) else {
            return;
        };
        manifest.checkpoints.remove(object_id);
        let _ = manifest.save(&self.path);
    }
}

/// RAII guard: on drop (still armed — i.e. the rotation failed or panicked),
/// sweeps all .tmp files in the vault dirs but KEEPS the rotation-pending
/// marker so `VaultHandle::open` warns that a rotation did not complete.
/// Disarm with `disarm()` only after a successful commit, then remove the
/// marker explicitly.
struct RotationGuard {
    vault_path: PathBuf,
    armed: bool,
}

impl RotationGuard {
    fn new(vault_path: &Path) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RotationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // NOTE: the pending marker is deliberately KEPT — an armed drop means
        // the rotation failed or panicked, and the next open must warn that
        // the vault may be in a mixed-epoch state (P4: an incomplete rotation
        // must never look complete).
        // Sweep meta/ and meta/keywrap/
        remove_tmp_files(&self.vault_path.join("meta"));
        remove_tmp_files(&self.vault_path.join("meta/keywrap"));
        // S3-7c review F9: ciphers and trash now hold collection
        // subdirectories — sweep their .tmp files recursively.
        remove_tmp_files_recursive(&self.vault_path.join("ciphers"));
        remove_tmp_files_recursive(&self.vault_path.join("trash"));
    }
}

/// Remove .tmp files in a single directory (non-recursive).
fn remove_tmp_files(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "tmp") {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// Remove .tmp files in a directory tree recursively.
fn remove_tmp_files_recursive(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                remove_tmp_files_recursive(&p);
            } else if p.extension().is_some_and(|e| e == "tmp") {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// Result of reading a cipher: either decrypted content or locked metadata.
pub enum CipherRead {
    Decrypted(Box<Cipher>),
    Locked(LockedCipherInfo),
}

/// Cipher metadata available when vault is locked.
pub struct LockedCipherInfo {
    pub id: Uuid,
    pub key_epoch: u64,
    pub update_seq: u64,
    pub tier: Option<Tier>,
    pub ciphertext_len: usize,
}

// ── Keyring-backed device private key storage ──

/// Device private key material (X25519 + Ed25519).
struct DevicePrivKeys {
    x25519: x25519_dalek::StaticSecret,
    ed25519: ed25519_dalek::SigningKey,
}

/// Load device private keys: injected keystore first (mobile), then the
/// sealed device-privkey file. The file is the durable source of truth.
/// The OS keyring is deliberately NOT consulted on this path: a locked
/// Secret Service collection answers with an interactive prompt, and a
/// headless daemon or autostarted unlock would block forever inside a
/// dbus poll — the old code ignored keyring errors but not freezes.
fn load_device_privkeys(
    vault_path: &Path,
    device_id: Uuid,
    seal_key: Option<&[u8; 32]>,
) -> Result<DevicePrivKeys, BaluardError> {
    // 0. Consult SecureKeystore (global or injected)
    if let Some(keystore) = crate::vault::creation::get_global_keystore() {
        if let Ok(bytes) = keystore
            .get_secret(&device_id.to_string())
            .or_else(|_| keystore.get_secret(&format!("device:{device_id}")))
            .or_else(|_| keystore.get_secret("device_x25519_secret"))
        {
            if let Ok(json) = String::from_utf8(bytes) {
                if let Ok(keys) = parse_privkey_json(&json) {
                    return Ok(keys);
                }
            }
        }
    }

    // 1. The device-privkey file. Since the C1 fix the file is an
    // AES-256-GCM envelope sealed under a KEK-derived subkey; legacy
    // plaintext (phrase-flow writes, pre-seal vaults) is still readable
    // here and gets re-sealed lazily on the next successful unlock.
    let privkey_path = vault_path.join("meta/device-privkey.json");
    if privkey_path.exists() {
        let json = crate::vault::device_privkey::read_privkey_file(&privkey_path, seal_key)?;
        return parse_privkey_json(&json);
    }

    Err(VaultError::NotFound("device private key not found".into()).into())
}

/// Parse device private keys from JSON string.
fn parse_privkey_json(json: &str) -> Result<DevicePrivKeys, BaluardError> {
    let data: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| VaultError::Corrupt(format!("privkey json: {e}")))?;

    let x_bytes = hex::decode(data["x25519_private"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("x25519 hex: {e}")))?;
    let x_arr: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| VaultError::Corrupt("invalid x25519 key length".into()))?;

    let ed_bytes = hex::decode(data["ed25519_private"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("ed25519 hex: {e}")))?;
    let ed_arr: [u8; 32] = ed_bytes
        .try_into()
        .map_err(|_| VaultError::Corrupt("invalid ed25519 key length".into()))?;

    Ok(DevicePrivKeys {
        x25519: x25519_dalek::StaticSecret::from(x_arr),
        ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_arr),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KdfProfile;
    use crate::vault::creation;

    #[test]
    fn approve_join_records_wrap_pubkey_from_intro_card() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.approve_join(&intro_code).unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        let expected = intro
            .contact_card
            .as_ref()
            .unwrap()
            .card
            .identity_wrap_pubkey
            .clone();
        assert!(!expected.is_empty());
        let member_id =
            crate::vault::members::member_id_for_device(&owner_path, intro.device_id).unwrap();
        let row = crate::vault::members::member_file_by_id(&owner_path, member_id).unwrap();
        assert_eq!(row.identity_wrap_pubkey.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn invite_template_applies_grants_at_approval() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let sgk = handle.unlocked().sgk().expect("sgk in test").clone();
        let work = crate::vault::collections::create_collection(&owner_path, &sgk, "Work").unwrap();
        let template = handle
            .template_create(
                "Contractor",
                crate::vault::members::MemberRole::Viewer,
                vec![crate::vault::templates::TemplateGrant {
                    collection_id: work.id,
                    access: crate::vault::collections::CollectionAccess::Read,
                    expires_in_days: Some(30),
                }],
            )
            .unwrap();
        // Role divergence refuses (fail closed): the admin picked a
        // Viewer template, an Editor role must not ride it.
        assert!(
            handle
                .invite_create_with_template(
                    crate::vault::members::MemberRole::Editor,
                    None,
                    template.id
                )
                .is_err()
        );
        let code = handle
            .invite_create_with_template(
                crate::vault::members::MemberRole::Viewer,
                None,
                template.id,
            )
            .unwrap();
        // Deleting the template now must NOT change the pending invite:
        // the invite is the contract.
        handle.template_delete(template.id).unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.approve_join(&intro_code).unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        let member_id =
            crate::vault::members::member_id_for_device(&owner_path, intro.device_id).unwrap();
        let row = crate::vault::members::member_file_by_id(&owner_path, member_id).unwrap();
        assert_eq!(row.role, crate::vault::members::MemberRole::Viewer);
        // The grant landed from the embedded copy with a ~30-day window.
        let now = crate::vault::templates::now_secs();
        let grants = handle
            .collections_list()
            .unwrap()
            .into_iter()
            .find(|(id, _, _)| *id == work.id)
            .map(|(_, _, grants)| grants)
            .unwrap();
        let grant = grants
            .iter()
            .find(|g| g.target.member_id() == Some(member_id))
            .unwrap();
        assert_eq!(
            grant.access,
            crate::vault::collections::CollectionAccess::Read
        );
        let expires_at = grant.expires_at.expect("window");
        assert!(expires_at > now + 29 * 86_400);
        assert!(expires_at < now + 31 * 86_400);
        // The per-member key wrap minted at approval (P1 groundwork).
        assert!(
            crate::vault::collections::grant_wrap_path(&owner_path, &work.id, &member_id).exists()
        );
    }

    #[test]
    fn templates_survive_root_key_rotation() {
        let (dir, password) = create_test_vault();
        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&password).unwrap();
        let t = h
            .template_create("Auditor", crate::vault::members::MemberRole::Viewer, vec![])
            .unwrap();
        h.rotate_root_key().unwrap();
        let listed = h.templates_list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, t.id);
        assert_eq!(listed[0].name, "Auditor");
        // Still usable after rotation (the store re-sealed under the
        // new key).
        h.template_delete(t.id).unwrap();
        assert!(h.templates_list().unwrap().is_empty());
    }

    #[test]
    fn identity_rotation_rewraps_own_grant_wraps() {
        let (dir, password) = create_test_vault();
        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&password).unwrap();
        let member_id =
            crate::vault::members::member_id_for_device(dir.path(), h.device_id).unwrap();
        let card = h.contact_card_signed().unwrap();
        let mut row = crate::vault::members::member_file_by_id(dir.path(), member_id).unwrap();
        row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(dir.path(), &row).unwrap();
        let sgk = h.unlocked().sgk().expect("sgk in test").clone();
        let file =
            crate::vault::collections::create_collection(dir.path(), &sgk, "Shared").unwrap();
        crate::vault::collections::upsert_grant(
            dir.path(),
            &sgk,
            &file.id,
            crate::vault::collections::CollectionGrant {
                target: crate::vault::collections::GrantTarget::Member { id: member_id },
                access: crate::vault::collections::CollectionAccess::Write,
                expires_at: None,
            },
        )
        .unwrap();
        let old_keys = crate::vault::identity::IdentityKeys::from_seed(
            &h.unlocked().identity.as_ref().unwrap().seed(),
        );
        h.rotate_identity().unwrap();
        // The row carries the NEW wrap pubkey; the new identity opens
        // the re-wrapped CK, the old one is dead.
        let row2 = crate::vault::members::member_file_by_id(dir.path(), member_id).unwrap();
        assert_ne!(
            row2.identity_wrap_pubkey.as_deref(),
            Some(card.card.identity_wrap_pubkey.as_str())
        );
        let new_keys = h.unlocked().identity.as_ref().unwrap();
        crate::vault::collections::open_grant_wrap(
            dir.path(),
            &file.id,
            &member_id,
            new_keys.wrapping_secret(),
        )
        .unwrap();
        assert!(
            crate::vault::collections::open_grant_wrap(
                dir.path(),
                &file.id,
                &member_id,
                old_keys.wrapping_secret()
            )
            .is_err()
        );
    }

    #[cfg(feature = "git-sync")]
    #[test]
    fn timeline_derives_structural_history_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let password = "test-timeline-password";
        let (handle, _secrets) = creation::VaultCreator::new(dir.path(), password, "test-device")
            .kdf_profile(KdfProfile::MobileLow)
            .execute()
            .unwrap();
        drop(handle);

        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(password).unwrap();
        let seal = h.devkey_seal();
        let device = h.device_id.to_string();

        // A live member row to grant to (12-field literal, house test
        // convention).
        let member_id = uuid::Uuid::new_v4();
        let row = crate::vault::members::MemberFile {
            id: member_id,
            display_name: "Ada".into(),
            email: None,
            role: crate::vault::members::MemberRole::Editor,
            trust: crate::vault::members::TrustLevel::Channel,
            identity_signing_pubkey: Some(hex::encode([1u8; 32])),
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        crate::vault::members::write_member(dir.path(), &row).unwrap();

        let engine = crate::sync::engine::SyncEngine::new(dir.path(), &device, seal.as_ref());
        let repo = engine.open_repo().unwrap();
        engine.commit_all(&repo, "member row").unwrap();

        let cid = h.collection_create("Work").unwrap();
        h.lock();
        drop(h);
        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(password).unwrap();
        engine.commit_all(&repo, "collection").unwrap();

        h.collection_grant(
            cid,
            crate::vault::collections::GrantTarget::Member { id: member_id },
            crate::vault::collections::CollectionAccess::Write,
            None,
        )
        .unwrap();
        drop(h);
        engine.commit_all(&repo, "grant").unwrap();

        let feed = crate::sync::engine::SyncEngine::derive_timeline(&repo, 100).unwrap();
        let kinds: Vec<&str> = feed.iter().map(|e| e.kind.as_str()).collect();
        // Newest-first: the grant is the most recent fact, the vault's
        // birth the oldest.
        assert_eq!(kinds.first().copied(), Some("grant-added"));
        assert!(kinds.contains(&"collection-created"), "kinds: {kinds:?}");
        assert!(kinds.contains(&"member-added"), "kinds: {kinds:?}");
        assert_eq!(kinds.last().copied(), Some("vault-created"));
        // Positional order: grant before collection before birth.
        let grant_at = kinds.iter().position(|k| *k == "grant-added").unwrap();
        let coll_at = kinds
            .iter()
            .position(|k| *k == "collection-created")
            .unwrap();
        let born_at = kinds.iter().position(|k| *k == "vault-created").unwrap();
        assert!(grant_at < coll_at && coll_at < born_at);
        // Genesis attribution falls back to the creator label; the
        // grant commit's actor resolves to the creator's display name
        // (the only member row at that point).
        assert_eq!(feed.last().unwrap().actor, "the space's creator");
        assert!(!feed[0].actor.is_empty());
        assert_eq!(
            feed[0].detail,
            format!("member {}: write", &member_id.to_string()[..8])
        );
    }

    fn create_test_vault() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let password = "test-password-unlock-flow";

        let (handle, _secrets) = creation::VaultCreator::new(dir.path(), password, "test-device")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .execute()
            .unwrap();
        drop(handle); // Release locks so tests can re-open

        (dir, password.to_string())
    }

    #[test]
    fn mismatched_keystore_reports_unpaired_not_wrong_password() {
        // A keystore that opens but does not match the vault's keywrap is a
        // stale/reinstalled device: the error must say so instead of
        // collapsing into the generic wrong-password surface.
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        handle.lock();

        // Overwrite the keystore with a foreign legacy-plaintext key: the
        // file loader accepts it, the keywrap HPKE open cannot.
        use rand::RngCore;
        let mut x = [0u8; 32];
        let mut e = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x);
        rand::rngs::OsRng.fill_bytes(&mut e);
        let foreign = serde_json::json!({
            "x25519_private": hex::encode(x),
            "ed25519_private": hex::encode(e),
        });
        std::fs::write(
            dir.path().join("meta/device-privkey.json"),
            foreign.to_string(),
        )
        .unwrap();

        let mut handle = VaultHandle::open(dir.path()).unwrap();
        let err = handle.unlock(&password).unwrap_err();
        assert!(
            err.to_string().contains("no longer paired"),
            "expected the unpaired-device error, got: {err}"
        );
    }

    #[test]
    fn open_and_unlock_roundtrip() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        assert!(!handle.is_unlocked());

        handle.unlock(&password).unwrap();
        assert!(handle.is_unlocked());

        handle.lock();
        assert!(!handle.is_unlocked());
    }

    #[test]
    fn wrong_password_fails() {
        let (dir, _password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        assert!(handle.unlock("wrong-password").is_err());
    }

    /// S2 IS-5 review fix: settings-pub.json writers merge instead of
    /// rebuild, so the pair-space shape flag survives a settings save
    /// or a locale change.
    #[test]
    fn settings_writers_preserve_space_flag() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        crate::vault::space::set_space_flag(dir.path(), true).unwrap();

        handle
            .save_settings(&crate::vault::manifest::VaultSettings::default())
            .unwrap();
        handle.save_locale("es").unwrap();

        let pub_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("meta/settings-pub.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(pub_json["space"], serde_json::json!(true));
        assert_eq!(pub_json["lang"], serde_json::json!("es"));
    }

    /// S2 IS-3: one-shot item package end-to-end. B shares their card
    /// with A, A wraps an item to it, B imports the package as a fresh
    /// entry (new id, B's keys, sender name from the verified card).
    #[test]
    fn item_package_two_vault_roundtrip() {
        let (dir_a, pw_a) = create_test_vault();
        let (dir_b, pw_b) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();
        let mut b = VaultHandle::open(dir_b.path()).unwrap();
        b.unlock(&pw_b).unwrap();

        let kind: crate::types::CipherKind = serde_json::from_str(
            r#"{"type":"login","data":{"username":"u","password":"p","fido2_credentials":[{"credential_id":"abc","key_type":"public-key","key_algorithm":"ES256","key_curve":"P-256","key_value":"aa","rp_id":"bank.example","counter":0,"aaguid":"00000000-0000-0000-0000-000000000000","creation_date":1700000000,"private_key_missing":true}]}}"#,
        )
        .unwrap();
        let foreign_folder = Uuid::new_v4();
        let source_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Bank".into(),
                folder_id: Some(foreign_folder),
                collection_id: None,
                kind,
                archived: true,
                created_at: Some(1_600_000_000),
                ..Default::default()
            })
            .unwrap();

        // B's card lands in A's address book at Channel — the only
        // trust level a package needs (inert copy).
        let card_code = b.contact_card_create().unwrap();
        a.contacts_import_card(&card_code).unwrap();
        let contact_card = a.contacts_list().unwrap()[0].card.clone();

        let bytes = a.export_item_package(source_id, &contact_card).unwrap();
        let (new_id, sender) = b.import_item_package(&bytes).unwrap();
        assert_ne!(new_id, source_id, "import must be a fresh copy");
        assert_eq!(sender, a.contacts_list().unwrap()[0].card.display_name);

        match b.get_cipher(new_id).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "Bank");
                assert!(matches!(c.kind, crate::types::CipherKind::Login(_)));
                assert!(c.password_history.is_empty(), "history never travels");
                assert!(c.attachments.is_empty(), "attachments never travel");
                assert_eq!(c.folder_id, None, "foreign folder_id must be stripped");
                assert!(!c.archived, "archived flag must not travel");
                assert_ne!(
                    c.created_at, 1_600_000_000,
                    "creation timestamp must be reset"
                );
                // Sharing-posture symmetry with the outbox: passkeys are
                // live credentials and never travel in a one-shot package.
                if let crate::types::CipherKind::Login(login) = &c.kind {
                    assert!(login.fido2_credentials.is_none(), "passkeys never travel");
                }
            }
            CipherRead::Locked(_) => panic!("imported cipher must be readable"),
        }
    }

    /// S2 IS-3: a contact whose card predates the wrap pubkey (empty
    /// field, e.g. an address-book row stored before card v2) refuses
    /// export with the re-share guidance instead of failing cryptically.
    #[test]
    fn item_package_refuses_card_without_wrap_key() {
        let (dir_a, pw_a) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();

        let kind: crate::types::CipherKind =
            serde_json::from_str(r#"{"type":"login","data":{"username":"u","password":"p"}}"#)
                .unwrap();
        let source_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Bank".into(),
                kind,
                ..Default::default()
            })
            .unwrap();

        let legacy = crate::vault::contacts::ContactCard {
            display_name: "Old Card".into(),
            email: None,
            identity_signing_pubkey: hex::encode([1u8; 32]),
            identity_wrap_pubkey: String::new(),
            created_at: 1,
        };
        let err = a
            .export_item_package(source_id, &legacy)
            .unwrap_err()
            .to_string();
        assert!(err.contains("share their card again"), "err: {err}");
    }

    /// S2 IS-4b: outbox live mirror end-to-end. A publishes an entry to
    /// an outbox folder addressed to B's card; B links and reads
    /// (view-only, nothing imported); A edits the cipher, resync
    /// re-publishes (digest changed → commit), B sees the new value; A
    /// deletes the source, resync unpublishes, B sees an empty list.
    #[test]
    fn outbox_live_mirror_two_vaults() {
        let (dir_a, pw_a) = create_test_vault();
        let (dir_b, pw_b) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();
        let mut b = VaultHandle::open(dir_b.path()).unwrap();
        b.unlock(&pw_b).unwrap();

        let passkey = crate::types::PasskeyData {
            credential_id: "abc".into(),
            key_type: "public-key".into(),
            key_algorithm: "ECDSA".into(),
            key_curve: "P-256".into(),
            key_value: "aa".into(),
            rp_id: "bank.example".into(),
            rp_name: Some("Bank".into()),
            user_handle: None,
            user_name: Some("u".into()),
            user_display_name: None,
            counter: 0,
            aaguid: uuid::Uuid::nil(),
            prf_key: Some(vec![9, 9, 9]),
            private_key: Some(vec![1, 2, 3]),
            private_key_missing: false,
            linked_login_id: None,
            creation_date: 1_700_000_000,
            name: Some("pk".into()),
        };
        let mut login_data = crate::types::LoginData {
            username: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        };
        login_data.fido2_credentials = Some(vec![passkey]);
        let kind = crate::types::CipherKind::Login(login_data);
        let source_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Bank".into(),
                kind,
                ..Default::default()
            })
            .unwrap();

        let card_code = b.contact_card_create().unwrap();
        a.contacts_import_card(&card_code).unwrap();
        let contact_card = a.contacts_list().unwrap()[0].card.clone();

        let ob_dir = tempfile::TempDir::new().unwrap();
        let outbox_dir = ob_dir.path().join("outbox-mirror");
        let report = a
            .outbox_publish(&outbox_dir, source_id, &contact_card)
            .unwrap();
        assert!(report.committed);

        // B links with their OWN identity (the keywrap is addressed to
        // them) and reads.
        let link = b.outbox_link(&outbox_dir).unwrap();
        let entries = b.outbox_list_entries(link.outbox_id).unwrap();
        assert_eq!(entries.len(), 1);
        // View-only mirror: no passkey material travels.
        let mirrored = serde_json::to_string(&entries[0].item).unwrap();
        assert!(!mirrored.contains("fido2"), "passkeys must not mirror");
        assert_eq!(
            entries[0].sender_name,
            a.contacts_list().unwrap()[0].card.display_name
        );

        // Edit → resync → the mirror serves the new value.
        let kind2: crate::types::CipherKind = serde_json::from_str(
            r#"{"type":"login","data":{"username":"u","password":"new-pass"}}"#,
        )
        .unwrap();
        a.update_cipher(
            source_id,
            &crate::types::CipherInput {
                name: "Bank".into(),
                kind: kind2,
                ..Default::default()
            },
        )
        .unwrap();
        let resync = a.outbox_resync_all().unwrap();
        assert!(
            resync
                .iter()
                .any(|(id, committed)| *id == source_id && *committed)
        );
        let entries = b.outbox_list_entries(link.outbox_id).unwrap();
        let crate::types::CipherKind::Login(login) = &entries[0].item.kind else {
            panic!("expected login");
        };
        assert_eq!(login.password.as_deref(), Some("new-pass"));

        // Source deleted → unpublish on the next resync.
        a.delete_cipher(source_id).unwrap();
        a.outbox_resync_all().unwrap();
        let entries = b.outbox_list_entries(link.outbox_id).unwrap();
        assert!(entries.is_empty(), "deleted source must unpublish");
    }

    /// S2 IS-4b review: a PURGED (hard-deleted) source errors in
    /// get_cipher; the resync must unpublish it, not abort (a purge
    /// would otherwise wedge every later resync on the outbox).
    /// S3-1: collection lifecycle end-to-end on the handle, plus rotation
    /// coverage (content keys re-wrapped under the new SGK epoch).
    #[test]
    fn cipher_collection_assignment_moves_files() {
        let (dir, pw) = create_test_vault();
        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&pw).unwrap();

        let mk_input = |name: &str, pw: &str| {
            let kind = crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("u".into()),
                password: Some(pw.into()),
                ..Default::default()
            });
            crate::types::CipherInput {
                name: name.into(),
                kind,
                ..Default::default()
            }
        };
        let id = h.add_cipher(&mk_input("In Collection", "p")).unwrap();

        let col = h.collection_create("Work").unwrap();
        let flat = dir.path().join(format!("ciphers/{id}.enc"));
        assert!(flat.exists());
        h.assign_cipher_to_collection(id, Some(col)).unwrap();
        assert!(!flat.exists());
        // The file now lives in the collection's scoped directory.
        let dirs = crate::vault::collections::load_dir_map(dir.path());
        assert_eq!(dirs.len(), 1);
        let scoped_path = dir.path().join(format!("ciphers/{}/{}.enc", dirs[0].0, id));
        assert!(scoped_path.exists());
        // Reads, updates, and trash flows work through the scoped path.
        assert!(matches!(h.get_cipher(id), Ok(CipherRead::Decrypted(_))));
        let upd = mk_input("In Collection", "new-pass");
        h.update_cipher(id, &upd).unwrap();
        // Unassign moves it back to the personal flat path.
        h.assign_cipher_to_collection(id, None).unwrap();
        assert!(flat.exists());
        assert!(!scoped_path.exists());
        // Assign to a missing collection fails closed.
        let ghost = Uuid::new_v4();
        h.assign_cipher_to_collection(id, Some(ghost)).unwrap_err();
        // Delete from the collection dir lands in trash PRESERVING the
        // collection subdir (S3-7c: same-domain restore); restore returns
        // it to the collection dir it came from.
        h.assign_cipher_to_collection(id, Some(col)).unwrap();
        h.delete_cipher(id).unwrap();
        let dir_name = scoped_path
            .parent()
            .and_then(|p| p.file_name())
            .unwrap()
            .to_string_lossy()
            .to_string();
        let mut trash_scoped = dir.path().join("trash");
        trash_scoped.push(dir_name);
        trash_scoped.push(format!("{id}.enc"));
        assert!(trash_scoped.exists());
        h.restore_cipher(id).unwrap();
        assert!(scoped_path.exists());
        assert!(!flat.exists());
    }

    #[test]
    fn cipher_assignment_requires_collection_write_grant() {
        // F1 review fix: a non-grantee session device must not be able
        // to mint a commit that peers would refuse (wedging the vault).
        let (dir, pw) = create_test_vault();
        let mut h = VaultHandle::open(dir.path()).unwrap();
        h.unlock(&pw).unwrap();
        let col = h.collection_create("Shared").unwrap();

        // Rebind the session device to a fresh Editor member row.
        let editor = uuid::Uuid::new_v4();
        std::fs::create_dir_all(dir.path().join("meta/members")).unwrap();
        crate::vault::members::write_member(
            dir.path(),
            &crate::vault::members::MemberFile {
                id: editor,
                display_name: "Editor".into(),
                email: None,
                role: crate::vault::members::MemberRole::Editor,
                trust: crate::vault::members::TrustLevel::Verified,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        // Strip the genesis owner binding first: a device bound in two
        // subtrees now fails closed (2026-10-01 review blocker), so the
        // planted Editor binding must be the only one.
        for entry in std::fs::read_dir(dir.path().join("meta/members"))
            .unwrap()
            .flatten()
        {
            let stale = entry
                .path()
                .join("devices")
                .join(format!("{}.json", h.device_id));
            if stale.exists() {
                std::fs::remove_file(stale).unwrap();
            }
        }
        crate::vault::members::write_device_binding(
            dir.path(),
            &crate::vault::members::DeviceBinding {
                device_id: h.device_id,
                member_id: editor,
            },
        )
        .unwrap();

        let kind = crate::types::CipherKind::Login(crate::types::LoginData {
            username: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        });
        let cid = h
            .add_cipher(&crate::types::CipherInput {
                name: "E".into(),
                kind,
                ..Default::default()
            })
            .unwrap();
        // No grant: refused before any commit can be created.
        h.assign_cipher_to_collection(cid, Some(col)).unwrap_err();
        // Grant write on the collection, directly on disk (the editor
        // session cannot call collection_grant).
        let sgk = h.unlocked().sgk().expect("sgk in test").clone();
        crate::vault::collections::upsert_grant(
            dir.path(),
            &sgk,
            &col,
            crate::vault::collections::CollectionGrant {
                target: crate::vault::collections::GrantTarget::Member { id: editor },
                access: crate::vault::collections::CollectionAccess::Write,
                expires_at: None,
            },
        )
        .unwrap();
        h.assign_cipher_to_collection(cid, Some(col)).unwrap();
        // Moving out also needs the write grant; revoke it first.
        crate::vault::collections::revoke_grant(
            dir.path(),
            &sgk,
            &col,
            &crate::vault::collections::GrantTarget::Member { id: editor },
        )
        .unwrap();
        h.assign_cipher_to_collection(cid, None).unwrap_err();
    }

    #[test]
    fn collections_lifecycle_rotation() {
        let (dir_a, pw_a) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();

        // Owner session: full lifecycle.
        let id = a.collection_create("Servers").unwrap();
        a.collection_rename(id, "Infra").unwrap();
        let rows = a.collections_list().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "Infra");

        // Grant to a live member; revoke.
        let member = uuid::Uuid::new_v4();
        std::fs::create_dir_all(dir_a.path().join("meta/members")).unwrap();
        crate::vault::members::write_member(
            dir_a.path(),
            &crate::vault::members::MemberFile {
                id: member,
                display_name: "Alicia".into(),
                email: None,
                role: crate::vault::members::MemberRole::Editor,
                trust: crate::vault::members::TrustLevel::Verified,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        a.collection_grant(
            id,
            crate::vault::collections::GrantTarget::Member { id: member },
            crate::vault::collections::CollectionAccess::Write,
            None,
        )
        .unwrap();
        assert_eq!(a.collections_list().unwrap()[0].2.len(), 1);
        a.collection_revoke(
            id,
            crate::vault::collections::GrantTarget::Member { id: member },
        )
        .unwrap();
        assert_eq!(a.collections_list().unwrap()[0].2.len(), 0);

        // Rotation: the content keys must re-wrap under the new SGK.
        a.rotate_root_key().unwrap();
        let names: Vec<String> = a
            .collections_list()
            .unwrap()
            .into_iter()
            .map(|(_, n, _)| n)
            .collect();
        assert_eq!(names, vec!["Infra".to_string()]);

        a.collection_delete(id).unwrap();
        assert!(a.collections_list().unwrap().is_empty());
    }

    /// S3-1: the admin gate refuses a session device bound to an Editor row
    /// (plan §10.2: editors do not create collections).
    #[test]
    fn collections_create_refused_for_editor_device() {
        let (dir_a, pw_a) = create_test_vault();
        let device_id = {
            let h = VaultHandle::open(dir_a.path()).unwrap();
            h.device_id
        };
        let member = uuid::Uuid::new_v4();
        std::fs::create_dir_all(dir_a.path().join("meta/members")).unwrap();
        crate::vault::members::write_member(
            dir_a.path(),
            &crate::vault::members::MemberFile {
                id: member,
                display_name: "Editor Person".into(),
                email: None,
                role: crate::vault::members::MemberRole::Editor,
                trust: crate::vault::members::TrustLevel::Verified,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            dir_a.path(),
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: member,
            },
        )
        .unwrap();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();
        assert!(a.collection_create("Nope").is_err());
        assert!(a.collections_list().is_ok());
        // The gate is per-op: rename/delete/grant/revoke all refuse for a
        // non-admin session device.
        let fake = uuid::Uuid::new_v4();
        assert!(a.collection_rename(fake, "X").is_err());
        assert!(a.collection_delete(fake).is_err());
        assert!(
            a.collection_grant(
                fake,
                crate::vault::collections::GrantTarget::Member { id: member },
                crate::vault::collections::CollectionAccess::Read,
                None
            )
            .is_err()
        );
        assert!(
            a.collection_revoke(
                fake,
                crate::vault::collections::GrantTarget::Member { id: member }
            )
            .is_err()
        );
    }
    #[test]
    fn delegated_manager_gates_follow_manage_grant() {
        let (dir_a, pw_a) = create_test_vault();
        let device_id = {
            let h = VaultHandle::open(dir_a.path()).unwrap();
            h.device_id
        };
        let mut owner = VaultHandle::open(dir_a.path()).unwrap();
        owner.unlock(&pw_a).unwrap();
        // The owner mints two collections and a manage grant for a new
        // Editor member BEFORE the session device rebinds to it.
        let c1 = owner.collection_create("Servers").unwrap();
        let c2 = owner.collection_create("Finance").unwrap();
        let member = uuid::Uuid::new_v4();
        std::fs::create_dir_all(dir_a.path().join("meta/members")).unwrap();
        crate::vault::members::write_member(
            dir_a.path(),
            &crate::vault::members::MemberFile {
                id: member,
                display_name: "Manager Person".into(),
                email: None,
                role: crate::vault::members::MemberRole::Editor,
                trust: crate::vault::members::TrustLevel::Verified,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        owner
            .collection_grant(
                c1,
                crate::vault::collections::GrantTarget::Member { id: member },
                crate::vault::collections::CollectionAccess::Manage,
                None,
            )
            .unwrap();
        // Rebind the session device to the Editor/manager member. Strip
        // the genesis binding first: duplicate device bindings fail closed
        // now (2026-10-01 review blocker).
        for entry in std::fs::read_dir(dir_a.path().join("meta/members"))
            .unwrap()
            .flatten()
        {
            let stale = entry
                .path()
                .join("devices")
                .join(format!("{device_id}.json"));
            if stale.exists() {
                std::fs::remove_file(stale).unwrap();
            }
        }
        crate::vault::members::write_device_binding(
            dir_a.path(),
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: member,
            },
        )
        .unwrap();
        let mut m = VaultHandle::open(dir_a.path()).unwrap();
        m.unlock(&pw_a).unwrap();
        let stranger = uuid::Uuid::new_v4();
        std::fs::create_dir_all(dir_a.path().join("meta/members")).unwrap();
        crate::vault::members::write_member(
            dir_a.path(),
            &crate::vault::members::MemberFile {
                id: stranger,
                display_name: "Stranger Person".into(),
                email: None,
                role: crate::vault::members::MemberRole::Viewer,
                trust: crate::vault::members::TrustLevel::Verified,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        // Manager powers on the managed collection: grant, rename,
        // revoke.
        m.collection_grant(
            c1,
            crate::vault::collections::GrantTarget::Member { id: stranger },
            crate::vault::collections::CollectionAccess::Read,
            None,
        )
        .unwrap();
        m.collection_rename(c1, "Servers Renamed").unwrap();
        m.collection_revoke(
            c1,
            crate::vault::collections::GrantTarget::Member { id: stranger },
        )
        .unwrap();
        // Outside the managed scope everything refuses: grants on the
        // other collection, and create/delete stay admin-only.
        assert!(
            m.collection_grant(
                c2,
                crate::vault::collections::GrantTarget::Member { id: stranger },
                crate::vault::collections::CollectionAccess::Read,
                None
            )
            .is_err()
        );
        assert!(
            m.collection_revoke(
                c2,
                crate::vault::collections::GrantTarget::Member { id: stranger }
            )
            .is_err()
        );
        assert!(m.collection_rename(c2, "Nope").is_err());
        assert!(m.collection_create("Nope").is_err());
        assert!(m.collection_delete(c1).is_err());
        assert!(m.collection_delete(c2).is_err());
    }
    #[test]
    fn outbox_resync_survives_purged_source() {
        let (dir_a, pw_a) = create_test_vault();
        let (dir_b, pw_b) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();
        let mut b = VaultHandle::open(dir_b.path()).unwrap();
        b.unlock(&pw_b).unwrap();

        let kind: crate::types::CipherKind =
            serde_json::from_str(r#"{"type":"login","data":{"username":"u","password":"p"}}"#)
                .unwrap();
        let source_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Bank".into(),
                kind,
                ..Default::default()
            })
            .unwrap();
        let card_code = b.contact_card_create().unwrap();
        a.contacts_import_card(&card_code).unwrap();
        let contact_card = a.contacts_list().unwrap()[0].card.clone();
        let ob_dir = tempfile::TempDir::new().unwrap();
        let outbox_dir = ob_dir.path().join("outbox-purge");
        a.outbox_publish(&outbox_dir, source_id, &contact_card)
            .unwrap();

        a.delete_cipher(source_id).unwrap();
        a.purge_old_trash(0).unwrap();
        // Purged: get_cipher now errors CipherNotFound. Resync must
        // still succeed and unpublish.
        let resync = a.outbox_resync_all().unwrap();
        assert!(resync.iter().any(|(id, _)| *id == source_id));
        let link = b.outbox_link(&outbox_dir).unwrap();
        let entries = b.outbox_list_entries(link.outbox_id).unwrap();
        assert!(entries.is_empty(), "purged source must unpublish");
    }

    /// S2 IS-4b: the outbox registries are RootKey-derived and must
    /// survive a rotation re-encrypted (the P4 coverage rule).
    #[test]
    fn rotation_reencrypts_outbox_registries() {
        let (dir_a, pw_a) = create_test_vault();
        let (dir_b, pw_b) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();
        let mut b = VaultHandle::open(dir_b.path()).unwrap();
        b.unlock(&pw_b).unwrap();

        let kind: crate::types::CipherKind =
            serde_json::from_str(r#"{"type":"login","data":{"username":"u","password":"p"}}"#)
                .unwrap();
        let source_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Bank".into(),
                kind,
                ..Default::default()
            })
            .unwrap();
        let card_code = b.contact_card_create().unwrap();
        a.contacts_import_card(&card_code).unwrap();
        let contact_card = a.contacts_list().unwrap()[0].card.clone();
        let ob_dir = tempfile::TempDir::new().unwrap();
        let outbox_dir = ob_dir.path().join("outbox-rot");
        a.outbox_publish(&outbox_dir, source_id, &contact_card)
            .unwrap();

        a.rotate_root_key().unwrap();
        let rows = a.outbox_list().unwrap();
        assert_eq!(rows.len(), 1, "registry must survive rotation");
        assert_eq!(rows[0].published.len(), 1);
    }

    /// S2 IS-6: both reveal flavors end-to-end from a real vault cipher.
    /// Contact flavor: B's card, B's identity opens it (TOTP opted in,
    /// code computed, seed never surfaces). Guest flavor: passphrase
    /// opens it (no TOTP unless opted in, no sender). Non-Login ciphers
    /// and past expiries refuse at export.
    #[test]
    fn reveal_flavors_roundtrip_and_guards() {
        let (dir_a, pw_a) = create_test_vault();
        let (dir_b, pw_b) = create_test_vault();
        let mut a = VaultHandle::open(dir_a.path()).unwrap();
        a.unlock(&pw_a).unwrap();
        let mut b = VaultHandle::open(dir_b.path()).unwrap();
        b.unlock(&pw_b).unwrap();

        // Guest sharing is opt-in (2026-10-03): this flavor test exercises
        // the reveal machinery, not the door, so vault a opts in up front.
        // The door itself is covered by space_settings_roundtrip_and_guest_gate.
        let mut settings = a.get_settings().unwrap();
        settings.guest_enabled = Some(true);
        a.save_settings(&settings).unwrap();

        let source_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Team login".into(),
                kind: serde_json::from_str(
                    r#"{"type":"login","data":{"username":"ada",
                        "password":"hunter2",
                        "uris":[{"uri":"https://app.example.com"}],
                        "totp_uri":"otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"}}"#,
                )
                .unwrap(),
                ..Default::default()
            })
            .unwrap();

        // B's card lands in A's book at Channel (Level 1 is enough).
        let card_code = b.contact_card_create().unwrap();
        a.contacts_import_card(&card_code).unwrap();
        let contact = a.contacts_list().unwrap()[0].card.clone();

        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86_400;

        // Contact flavor: TOTP opted in, recipient opens with identity.
        let bytes = a
            .export_contact_reveal(source_id, &contact, expires, true)
            .unwrap();
        let opened = b.open_contact_reveal(&bytes).unwrap();
        assert_eq!(opened.item_name, "Team login");
        assert_eq!(opened.url.as_deref(), Some("https://app.example.com"));
        assert_eq!(opened.username.as_deref(), Some("ada"));
        assert_eq!(opened.password.as_deref(), Some("hunter2"));
        let code = opened
            .totp_code
            .clone()
            .expect("totp code computed at open");
        assert_eq!(code.len(), 6, "6-digit TOTP code, got {code}");
        assert!(opened.totp_valid_until.unwrap() > expires - 86_400);
        assert_eq!(
            opened.sender_name.as_deref(),
            Some(contact.display_name.as_str())
        );
        // The seed never surfaces in the opened view.
        let opened_json = serde_json::to_string(&opened).unwrap();
        assert!(
            !opened_json.contains("JBSWY3DPEHPK3PXP"),
            "totp seed must not cross the boundary"
        );

        // Guest flavor: TOTP not opted in, no sender, passphrase opens.
        let (guest_bytes, passphrase) = a.export_guest_reveal(source_id, expires, false).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let guest =
            crate::vault::reveals::open_guest_reveal(&guest_bytes, &passphrase, now).unwrap();
        assert_eq!(guest.password.as_deref(), Some("hunter2"));
        assert_eq!(guest.totp_code, None, "totp is opt-in");
        assert_eq!(guest.sender_name, None);

        // Non-Login ciphers refuse.
        let note_id = a
            .add_cipher(&crate::types::CipherInput {
                name: "Note".into(),
                kind: serde_json::from_str(r#"{"type":"secureNote"}"#).unwrap(),
                ..Default::default()
            })
            .unwrap();
        let err = a
            .export_guest_reveal(note_id, expires, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Only logins"), "err: {err}");

        // Past expiry refuses at export.
        let err = a
            .export_guest_reveal(source_id, now - 60, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("future"), "err: {err}");
    }

    /// P4: rotate_root_key must re-encrypt EVERY root-key-derived artifact —
    /// settings, generator history, attachments, and the emergency escrow
    /// joined the pre-existing folders/tags/profile/activity coverage. After
    /// rotation, all of them must be readable at the new epoch, and the
    /// emergency escrow must unwrap to the NEW root key.
    /// S3-9 (§6.5): Space settings roundtrip through the encrypted store
    /// and the guest_enabled gate on new guest reveals. The flip is a
    /// policy door, not a revocation: a reveal created before the flip
    /// still opens (the file is self-contained, carried by the recipient).
    #[test]
    fn space_settings_roundtrip_and_guest_gate() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Defaults from the §6.5 table.
        let settings = handle.get_settings().unwrap();
        assert_eq!(
            settings.space_invite_authority,
            crate::vault::manifest::InviteAuthority::Admins
        );
        assert!(!settings.allow_viewer_export);
        // 2026-10-03: guests OFF by default — sharing is opt-in now.
        assert_ne!(settings.guest_enabled, Some(true));

        let source_id = handle
            .add_cipher(&crate::types::CipherInput {
                name: "Team login".into(),
                kind: serde_json::from_str(
                    r#"{"type":"login","data":{"username":"ada",
                        "password":"hunter2",
                        "uris":[{"uri":"https://app.example.com"}]}}"#,
                )
                .unwrap(),
                ..Default::default()
            })
            .unwrap();
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86_400;

        // Default: guests OFF — new reveals refuse in plain language.
        let err = handle
            .export_guest_reveal(source_id, expires, false)
            .unwrap_err();
        assert!(format!("{err}").contains("Guest sharing is turned off"));

        // Flip the door open; new reveals export.
        let mut settings = handle.get_settings().unwrap();
        settings.guest_enabled = Some(true);
        settings.space_invite_authority = crate::vault::manifest::InviteAuthority::Owners;
        settings.allow_viewer_export = true;
        handle.save_settings(&settings).unwrap();
        let (guest_bytes, _passphrase) = handle
            .export_guest_reveal(source_id, expires, false)
            .unwrap();

        // Close the door again: new reveals refuse.
        let mut settings = handle.get_settings().unwrap();
        settings.guest_enabled = Some(false);
        handle.save_settings(&settings).unwrap();
        let err = handle
            .export_guest_reveal(source_id, expires, false)
            .unwrap_err();
        assert!(format!("{err}").contains("Guest sharing is turned off"));

        // The door is a policy, not a revocation: the reveal created while
        // open still opens — the file is self-contained.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let opened =
            crate::vault::reveals::open_guest_reveal(&guest_bytes, &_passphrase, now).unwrap();
        assert_eq!(opened.item_name, "Team login");

        // The settings survive the save/load cycle (settings.enc), and a
        // solo vault's founder passes the Owners invite-authority gate.
        let reloaded = handle.get_settings().unwrap();
        assert_eq!(reloaded.guest_enabled, Some(false));
        assert_eq!(
            reloaded.space_invite_authority,
            crate::vault::manifest::InviteAuthority::Owners
        );
        assert!(reloaded.allow_viewer_export);
        assert_eq!(reloaded.guest_enabled, Some(false));
        handle
            .invite_create(crate::vault::members::MemberRole::Viewer, None)
            .expect("founder invites under owners-only");
    }

    /// §6.5 trash_policy + restore_policy: the knob matrix. An Editor
    /// with a live Write grant trashes under the default
    /// (write_scope_can_trash) but restore refuses (restore_policy is
    /// admin-only by default). Flipping trash_policy to admins_only
    /// refuses the member's trash; the owner trashes and restores
    /// throughout. Bindings are swapped on one device (the rebind
    /// pattern) so role resolution is deterministic.
    #[test]
    fn access_review_reports_exposure_and_grants() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let work = handle.collection_create("Work").unwrap();

        // Plant an Editor row and grant Write while live. The review
        // lists the grant under the collection.
        let member_id = uuid::Uuid::new_v4();
        let mk_row = |removed: Option<u64>| crate::vault::members::MemberFile {
            id: member_id,
            display_name: "Ed".into(),
            email: None,
            role: crate::vault::members::MemberRole::Editor,
            trust: crate::vault::members::TrustLevel::Channel,
            identity_signing_pubkey: Some(hex::encode([1u8; 32])),
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        crate::vault::members::write_member(dir.path(), &mk_row(None)).unwrap();
        handle
            .collection_grant(
                work,
                crate::vault::collections::GrantTarget::Member { id: member_id },
                crate::vault::collections::CollectionAccess::Write,
                None,
            )
            .unwrap();

        let report = handle.access_review().unwrap();
        assert_eq!(report["flipped"], serde_json::Value::Bool(false));
        let cols = report["collections"].as_array().unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0]["name"], "Work");
        assert_eq!(
            cols[0]["grants"].as_array().unwrap()[0]["id"]
                .as_str()
                .unwrap(),
            member_id.to_string()
        );
        assert_eq!(report["exposure"].as_array().unwrap().len(), 0);
        assert_eq!(
            report["pending"]["access_requests"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(report["outboxes"].as_array().unwrap().len(), 0);

        // Tombstone the row (the removal ceremonies prove the flow;
        // here only the report matters). The surviving grant row is
        // the S4-8 exposure: credentials to rotate.
        crate::vault::members::write_member(dir.path(), &mk_row(Some(1))).unwrap();
        let report = handle.access_review().unwrap();
        let exposure = report["exposure"].as_array().unwrap();
        assert_eq!(exposure.len(), 1);
        assert_eq!(
            exposure[0]["member_id"].as_str().unwrap(),
            member_id.to_string()
        );
        assert_eq!(exposure[0]["display_name"], "Ed");
        assert_eq!(exposure[0]["kind"], "removed");
        let hits = exposure[0]["collections"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["name"], "Work");
        assert_eq!(hits[0]["access"], "write");

        // Raw key material never enters the report.
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("content_key"));
        assert!(!text.contains("ck_wrapped"));
    }

    #[test]
    fn rotate_recovery_phrase_replaces_the_escrow() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Wrong password refuses before anything is written.
        let err = handle
            .rotate_recovery_phrase("not-the-password")
            .unwrap_err();
        assert!(format!("{err}").contains("old master password incorrect"));

        // A correct rotation returns 24 words and the escrow opens for it.
        let phrase1 = handle.rotate_recovery_phrase(&password).unwrap();
        assert_eq!(phrase1.split_whitespace().count(), 24);

        fn unwrap_root_with(vault_path: &std::path::Path, phrase: &str) -> Result<Vec<u8>, String> {
            let parsed =
                crate::recovery::RecoveryPhrase::from_phrase(phrase).map_err(|e| format!("{e}"))?;
            let seed = parsed.derive_key();
            let secret = Zeroizing::new(x25519_dalek::StaticSecret::from(
                <[u8; 32]>::try_from(&seed[..32]).map_err(|_| "short seed".to_string())?,
            ));
            let json: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(vault_path.join("meta/recovery.json"))
                    .map_err(|e| format!("{e}"))?,
            )
            .map_err(|e| format!("{e}"))?;
            let eph = hex::decode(json["ephemeral_public"].as_str().unwrap_or(""))
                .map_err(|e| format!("{e}"))?;
            let ct = hex::decode(json["encrypted_key"].as_str().unwrap_or(""))
                .map_err(|e| format!("{e}"))?;
            let tag =
                hex::decode(json["tag"].as_str().unwrap_or("")).map_err(|e| format!("{e}"))?;
            let tag: [u8; 16] = tag.try_into().map_err(|_| "tag length".to_string())?;
            crate::crypto::hpke_wrap::unwrap_key(&eph, &ct, &tag, &secret, "recovery-keywrap")
                .map(|k| k.to_vec())
                .map_err(|e| format!("{e}"))
        }

        let root_before = handle_root_key_for_test(&handle);
        let opened = unwrap_root_with(&handle.path, &phrase1).unwrap();
        assert_eq!(opened, root_before);

        // A second rotation invalidates the first phrase: the old words no
        // longer unwrap the escrow, the new words do.
        let phrase2 = handle.rotate_recovery_phrase(&password).unwrap();
        assert_ne!(phrase1, phrase2);
        assert!(unwrap_root_with(&handle.path, &phrase1).is_err());
        let opened2 = unwrap_root_with(&handle.path, &phrase2).unwrap();
        assert_eq!(opened2, handle_root_key_for_test(&handle));

        // A flipped (team) Space refuses: its recovery contract is the
        // Space Recovery Kit, and the personal recovery would reset the
        // roster (review F6/F4).
        crate::vault::space_meta::write_shape_marker(dir.path(), 1).unwrap();
        let err = handle.rotate_recovery_phrase(&password).unwrap_err();
        assert!(
            format!("{err}").contains("Space Recovery Kit"),
            "team refusal: {err}"
        );
    }

    #[test]
    fn kit_recovery_enrolls_on_a_fresh_clone_and_unlocks() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let phrase = handle.space_recovery_kit_enable().unwrap();
        drop(handle);

        // A "fresh install" clone: sibling tempdir (never inside the
        // source tree), full recursive copy, kit file rides along.
        fn copy_vault(src: &std::path::Path, dst: &std::path::Path) {
            for entry in std::fs::read_dir(src).unwrap().flatten() {
                let ty = entry.file_type().unwrap();
                let to = dst.join(entry.file_name());
                if ty.is_dir() {
                    std::fs::create_dir_all(&to).unwrap();
                    copy_vault(&entry.path(), &to);
                } else {
                    std::fs::copy(entry.path(), &to).unwrap();
                }
            }
        }
        let clone_dir = tempfile::tempdir().unwrap();
        let clone_path = clone_dir.path().join("clone");
        std::fs::create_dir_all(&clone_path).unwrap();
        copy_vault(dir.path(), &clone_path);
        // A real fresh clone carries none of the OLD device's local
        // state (gitignored device files); strip them like git would.
        for local in [
            "meta/device-privkey.json",
            "meta/device-id",
            "meta/member-unlock.json",
        ] {
            let p = clone_path.join(local);
            if p.exists() {
                std::fs::remove_file(p).unwrap();
            }
        }
        assert!(!clone_path.join("meta/device-privkey.json").exists());

        // Recover: phrase + master password + device name -> a device
        // bound to the live Owner row. Path-only: no handle open before
        // the ceremony (a multi-device clone cannot open()).
        let device_id =
            VaultHandle::recover_device_with_kit(&clone_path, &phrase, &password, "Recovered Mac")
                .expect("recovery on a fresh clone");
        assert_eq!(
            crate::vault::members::member_role_for_device(&clone_path, device_id),
            Some(crate::vault::members::MemberRole::Owner)
        );

        // The recovered device unlocks through the admin path.
        let mut clone = VaultHandle::open(&clone_path).unwrap();
        clone.unlock(&password).unwrap();
        assert!(clone.holds_root());

        // The brick guard: re-running on a device that already holds
        // keys refuses instead of clobbering the keystore.
        let err = VaultHandle::recover_device_with_kit(&clone_path, &phrase, &password, "again")
            .unwrap_err()
            .to_string();
        assert!(err.contains("already has its own keys"), "err: {err}");
        drop(clone);

        // Wrong phrase refuses (a keystore-less clone: the phrase check
        // fires before anything else).
        let clone2_path = clone_dir.path().join("clone2");
        std::fs::create_dir_all(&clone2_path).unwrap();
        copy_vault(dir.path(), &clone2_path);
        for local in [
            "meta/device-privkey.json",
            "meta/device-id",
            "meta/member-unlock.json",
        ] {
            let p = clone2_path.join(local);
            if p.exists() {
                std::fs::remove_file(p).unwrap();
            }
        }
        let wrong = VaultHandle::open(&clone2_path).unwrap();
        let wrong_phrase = crate::recovery::RecoveryPhrase::generate()
            .unwrap()
            .phrase();
        let err =
            VaultHandle::recover_device_with_kit(&clone2_path, &wrong_phrase, &password, "nope")
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("does not open this vault's recovery kit"),
            "err: {err}"
        );
        drop(wrong);

        // Wrong master password refuses at the KEK canary — a typo would
        // otherwise mint an un-unlockable keystore.
        let err =
            VaultHandle::recover_device_with_kit(&clone2_path, &phrase, "not-the-password", "nope")
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("master password does not open this vault"),
            "err: {err}"
        );
        assert!(!clone2_path.join("meta/device-privkey.json").exists());

        // No kit refuses in plain language (remove the kit from the
        // same keystore-less clone).
        std::fs::remove_file(clone2_path.join("meta/recovery-kit.json")).unwrap();
        let err = VaultHandle::recover_device_with_kit(&clone2_path, &phrase, &password, "third")
            .unwrap_err()
            .to_string();
        assert!(err.contains("No recovery kit"), "err: {err}");
    }

    #[test]
    fn recovery_kit_survives_rotation_and_refuses_members() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Enable: a 24-word phrase comes back exactly once.
        let phrase = handle.space_recovery_kit_enable().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(handle.space_recovery_kit_status().unwrap());

        // The phrase unwraps the live Root Key.
        let live_root = handle_root_key_for_test(&handle);
        let recovered =
            crate::vault::recovery_kit::recover_root_from_kit(dir.path(), handle.vault_id, &phrase)
                .unwrap();
        assert_eq!(recovered.as_bytes(), live_root.as_slice());

        // Rotation rewraps the kit: the SAME phrase recovers the NEW root.
        handle.rotate_root_key().unwrap();
        let new_root = handle_root_key_for_test(&handle);
        assert_ne!(new_root, live_root);
        let recovered =
            crate::vault::recovery_kit::recover_root_from_kit(dir.path(), handle.vault_id, &phrase)
                .unwrap();
        assert_eq!(recovered.as_bytes(), new_root.as_slice());

        // A bound Editor manages nothing kit-related.
        let device_id = handle.device_id;
        let members_dir = dir.path().join("meta/members");
        let mut owner_member_id = None;
        for entry in std::fs::read_dir(&members_dir).unwrap().flatten() {
            let binding = entry
                .path()
                .join("devices")
                .join(format!("{device_id}.json"));
            if binding.exists() {
                owner_member_id = Some(
                    entry
                        .path()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
                std::fs::remove_file(binding).unwrap();
            }
        }
        let owner_member_id =
            uuid::Uuid::parse_str(&owner_member_id.expect("genesis binding")).unwrap();
        let editor_id = uuid::Uuid::new_v4();
        crate::vault::members::write_member(
            dir.path(),
            &crate::vault::members::MemberFile {
                id: editor_id,
                display_name: "Ed".into(),
                email: None,
                role: crate::vault::members::MemberRole::Editor,
                trust: crate::vault::members::TrustLevel::Channel,
                identity_signing_pubkey: Some(hex::encode([1u8; 32])),
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            dir.path(),
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: editor_id,
            },
        )
        .unwrap();
        assert_eq!(
            crate::vault::members::member_role_for_device(dir.path(), device_id),
            Some(crate::vault::members::MemberRole::Editor)
        );
        let err = handle.space_recovery_kit_enable().unwrap_err().to_string();
        assert!(err.contains("Only the owner or an admin"), "err: {err}");
        let err = handle.space_recovery_kit_disable().unwrap_err().to_string();
        assert!(err.contains("Only the owner or an admin"), "err: {err}");

        // Rebind back to the owner row (the Editor binding must go first
        // so role resolution finds exactly one binding).
        std::fs::remove_file(
            dir.path()
                .join("meta/members")
                .join(editor_id.to_string())
                .join("devices")
                .join(format!("{device_id}.json")),
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            dir.path(),
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: owner_member_id,
            },
        )
        .unwrap();
        assert!(handle.space_recovery_kit_disable().unwrap());
        assert!(!handle.space_recovery_kit_status().unwrap());
    }

    #[test]
    fn trash_and_restore_policies_gate_members() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Defaults from the §6.5 table.
        let settings = handle.get_settings().unwrap();
        assert_eq!(
            settings.trash_policy,
            crate::vault::manifest::TrashPolicy::WriteScopeCanTrash
        );
        assert_eq!(
            settings.restore_policy,
            crate::vault::manifest::RestorePolicy::AdminsOnly
        );

        let work = handle.collection_create("Work").unwrap();
        let mk_login = |name: &str| crate::types::CipherInput {
            name: name.into(),
            kind: serde_json::from_str(
                r#"{"type":"login","data":{"username":"ada","password":"pw"}}"#,
            )
            .unwrap(),
            ..Default::default()
        };
        let t1 = handle
            .add_cipher_in_collection(&mk_login("One"), Some(work))
            .unwrap();
        let t2 = handle
            .add_cipher_in_collection(&mk_login("Two"), Some(work))
            .unwrap();

        // Plant the member row and grant Write while this device is
        // still the owner (the grant needs the SGK).
        let member_id = uuid::Uuid::new_v4();
        crate::vault::members::write_member(
            dir.path(),
            &crate::vault::members::MemberFile {
                id: member_id,
                display_name: "Ed".into(),
                email: None,
                role: crate::vault::members::MemberRole::Editor,
                trust: crate::vault::members::TrustLevel::Channel,
                identity_signing_pubkey: Some(hex::encode([1u8; 32])),
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();
        handle
            .collection_grant(
                work,
                crate::vault::collections::GrantTarget::Member { id: member_id },
                crate::vault::collections::CollectionAccess::Write,
                None,
            )
            .unwrap();

        // Rebind this device to the Editor row (strip the genesis
        // binding first so role resolution is deterministic).
        let device_id = handle.device_id;
        let members_dir = dir.path().join("meta/members");
        let mut owner_member_id = None;
        for entry in std::fs::read_dir(&members_dir).unwrap().flatten() {
            let devices = entry.path().join("devices");
            let binding = devices.join(format!("{device_id}.json"));
            if binding.exists() {
                owner_member_id = Some(
                    entry
                        .path()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
                std::fs::remove_file(binding).unwrap();
            }
        }
        let owner_member_id =
            uuid::Uuid::parse_str(&owner_member_id.expect("genesis binding for this device"))
                .unwrap();
        crate::vault::members::write_device_binding(
            dir.path(),
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id,
            },
        )
        .unwrap();
        assert_eq!(
            crate::vault::members::member_role_for_device(dir.path(), device_id),
            Some(crate::vault::members::MemberRole::Editor)
        );

        // Default trash_policy: an Editor with a live Write grant trashes.
        handle.delete_cipher(t1).unwrap();

        // Default restore_policy: the same member's restore refuses.
        let err = handle.restore_cipher(t1).unwrap_err().to_string();
        assert!(err.contains("Restoring is limited to admins"), "err: {err}");

        // Flip trash_policy to admins_only; the member's trash refuses.
        let mut settings = handle.get_settings().unwrap();
        settings.trash_policy = crate::vault::manifest::TrashPolicy::AdminsOnly;
        handle.save_settings(&settings).unwrap();
        let err = handle.delete_cipher(t2).unwrap_err().to_string();
        assert!(err.contains("Trashing is limited to admins"), "err: {err}");
        assert!(handle.restore_cipher(t1).is_err());
        // §4.4: permanent deletion of trashed entries is admin-surface —
        // the editor cannot purge t1 from trash either.
        let err = handle.delete_cipher(t1).unwrap_err().to_string();
        assert!(
            err.contains("Purging entries is limited to admins"),
            "err: {err}"
        );

        // Back to the owner: settings persist across the rebind, the
        // owner trashes under admins_only and restores (restore_policy).
        std::fs::remove_file(
            members_dir
                .join(member_id.to_string())
                .join("devices")
                .join(format!("{device_id}.json")),
        )
        .unwrap();
        crate::vault::members::write_device_binding(
            dir.path(),
            &crate::vault::members::DeviceBinding {
                device_id,
                member_id: owner_member_id,
            },
        )
        .unwrap();
        assert_eq!(
            handle.get_settings().unwrap().trash_policy,
            crate::vault::manifest::TrashPolicy::AdminsOnly
        );
        handle.delete_cipher(t2).unwrap();
        handle.restore_cipher(t1).unwrap();
        assert!(handle.get_cipher(t1).is_ok());
    }

    #[test]
    fn rotation_reseals_space_meta_store() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Prepare mints the SMK store (owner genesis carries a wrap
        // pubkey per D35; either way prepare succeeds).
        let report = handle.space_prepare().unwrap();
        assert!(report.smk_fresh);
        let pre_rotation_root = RootKey::from_bytes(
            handle_root_key_for_test(&handle)
                .try_into()
                .expect("root 64 bytes"),
        );
        let smk_before =
            crate::vault::space_meta::open_store(dir.path(), &pre_rotation_root).unwrap();

        // Rotation re-seals the store under the new root; the SMK is
        // unchanged (wraps keep opening to the same key).
        handle.rotate_root_key().unwrap();
        let new_root = RootKey::from_bytes(
            handle_root_key_for_test(&handle)
                .try_into()
                .expect("root 64 bytes"),
        );
        let smk_after = crate::vault::space_meta::open_store(dir.path(), &new_root).unwrap();
        assert_eq!(*smk_after, *smk_before);
        // The pre-rotation root no longer opens the re-sealed store
        // (review F7).
        assert!(crate::vault::space_meta::open_store(dir.path(), &pre_rotation_root).is_err());
        let st = handle.space_status().unwrap();
        assert!(st.prepared);
    }

    #[test]
    fn rotation_covers_all_artifacts() {
        use crate::emergency;
        use crate::types::{GeneratorHistoryEntry, GeneratorKind, GeneratorParams};
        use x25519_dalek::PublicKey;

        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let vault_id_str = handle.vault_id.to_string();
        let device_id = handle.device_id;
        let seal = handle.devkey_seal();
        let old_epoch = match &handle.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => panic!("locked"),
        };
        let old_root = handle_root_key_for_test(&handle);

        // Folder + tag + settings + generator history + profile.
        let _folder_id = handle.create_folder("folders-f").unwrap();
        handle.create_tag("art-tag").unwrap();
        let mut settings = handle.get_settings().unwrap();
        settings.lang = Some("es".to_string());
        handle.save_settings(&settings).unwrap();
        handle
            .add_generator_history_entry(GeneratorHistoryEntry {
                value: "gen-pw".into(),
                kind: GeneratorKind::Password,
                params: GeneratorParams {
                    length: 20,
                    upper: true,
                    numbers: true,
                    symbols: false,
                    separator: None,
                },
                created_at: 1_700_000_000,
            })
            .unwrap();
        handle
            .save_profile(&crate::vault::manifest::UserProfile {
                display_name: Some("P5c Tester".into()),
                subtitle: None,
                avatar_ext: None,
            })
            .unwrap();

        // Cipher with one attachment blob on disk.
        let attach_uuid = uuid::Uuid::new_v4();
        let cipher_id = handle
            .add_cipher(&crate::types::CipherInput {
                name: "with-attach".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
                favorite: false,
                reprompt: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![crate::vault::attachment::AttachmentMeta {
                    id: attach_uuid.to_string(),
                    filename: "secret.txt".into(),
                    size: 8,
                    encrypted_size: 0,
                    mime_type: "text/plain".into(),
                    created_at: 0,
                }],
                archived: false,
                tags: vec![],
            })
            .unwrap();
        let old_item_key = VaultHandle::derive_item_key_from_root(
            &crate::keys::hierarchy::RootKey::from_bytes(old_root.clone().try_into().unwrap()),
            cipher_id,
            old_epoch,
        );
        let attach_dir = dir
            .path()
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments");
        std::fs::create_dir_all(&attach_dir).unwrap();
        let attach_blob = crate::vault::attachment::encrypt_attachment(
            handle.vault_id,
            cipher_id,
            attach_uuid,
            old_item_key.as_bytes(),
            b"filedata",
            old_epoch,
            1,
        )
        .unwrap();
        std::fs::write(attach_dir.join(format!("{attach_uuid}.enc")), attach_blob).unwrap();

        // Emergency access armed with a contact key we hold the private half of.
        let mut contact_secret_bytes = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut contact_secret_bytes);
        let contact_secret = x25519_dalek::StaticSecret::from(contact_secret_bytes);
        let contact_pub = PublicKey::from(&contact_secret);
        emergency::setup_emergency_access(
            dir.path(),
            "trust@example.com",
            contact_pub.as_bytes(),
            0,
            &old_root.clone().try_into().unwrap(),
            &vault_id_str,
            &load_device_privkeys(dir.path(), device_id, seal.as_ref())
                .unwrap()
                .ed25519,
        )
        .unwrap();
        // Recovery requires owner-approved status (verify against pinned key).
        emergency::approve_emergency_request(
            dir.path(),
            &load_device_privkeys(dir.path(), device_id, seal.as_ref())
                .unwrap()
                .ed25519,
            &vault_id_str,
        )
        .unwrap();

        // ── Rotate ──
        handle.rotate_root_key().unwrap();

        let new_root = handle_root_key_for_test(&handle);
        assert_ne!(new_root, old_root);
        let new_epoch = match &handle.state {
            VaultState::Unlocked(u) => u.current_epoch,
            VaultState::Locked => panic!("locked"),
        };
        assert_eq!(new_epoch, old_epoch + 1);

        // Metadata artifacts readable at the new epoch.
        assert!(
            handle
                .list_folders()
                .unwrap()
                .iter()
                .any(|f| f.name == "folders-f")
        );
        assert!(handle.list_tags().unwrap().contains(&"art-tag".to_string()));
        assert_eq!(handle.get_settings().unwrap().lang, Some("es".to_string()));
        let history = handle.load_generator_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].value, "gen-pw");
        assert_eq!(
            handle.load_profile().unwrap().display_name,
            Some("P5c Tester".to_string())
        );

        // Attachment blob decrypts with the NEW item key.
        let new_item_key = VaultHandle::derive_item_key_from_root(
            &crate::keys::hierarchy::RootKey::from_bytes(new_root.clone().try_into().unwrap()),
            cipher_id,
            new_epoch,
        );
        let enc_blob = std::fs::read(attach_dir.join(format!("{attach_uuid}.enc"))).unwrap();
        let plaintext = crate::vault::attachment::decrypt_attachment(
            handle.vault_id,
            cipher_id,
            attach_uuid,
            new_item_key.as_bytes(),
            &enc_blob,
        )
        .unwrap();
        assert_eq!(plaintext.as_slice(), b"filedata");

        // Emergency escrow unwraps to the NEW root key.
        let owner_vk = load_device_privkeys(dir.path(), device_id, seal.as_ref())
            .unwrap()
            .ed25519
            .verifying_key();
        let recovered =
            emergency::recover_emergency_root_key(dir.path(), &contact_secret, &owner_vk).unwrap();
        assert_eq!(recovered.as_slice(), new_root.as_slice());
    }

    /// P1a: the identity is generated at creation, sealed in
    /// meta/identity.enc (passphrase fallback on keystore-less test envs),
    /// escrowed under the recovery pubkey, loads on unlock, and rotates
    /// (new seed, escrow re-wrapped, sealed file rewritten).
    #[test]
    fn identity_lifecycle_seal_load_rotate() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();

        // Locked: identity not cached yet.
        assert!(handle.identity().is_none());

        handle.unlock(&password).unwrap();

        // Creation wrote the sealed identity + escrow + meta.
        assert!(dir.path().join("meta/identity.enc").exists());
        assert!(dir.path().join("meta/identity-escrow.json").exists());
        assert!(dir.path().join("meta/identity-meta.json").exists());

        // Loaded on unlock (passphrase-fallback mode in the keystore-less
        // test environment).
        let first_seed = handle.identity().unwrap().seed();
        let seed_before = handle.identity().unwrap().seed();
        assert_eq!(seed_before, first_seed);

        // Rotate: new seed, escrow re-wrapped to the recovery pubkey.
        handle.rotate_identity().unwrap();
        let seed_after = handle.identity().unwrap().seed();
        assert_ne!(seed_before, seed_after, "rotation must replace the seed");

        // Locked + unlocked again: the NEW identity loads from disk.
        handle.lock();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        assert_eq!(
            handle.identity().unwrap().seed(),
            seed_after,
            "post-rotation identity must persist across lock/unlock"
        );
    }

    /// P1a: the identity sealing key is NEVER the vault KEK. The sealed
    /// identity does not open under the unlock-derived devkey seal subkey
    /// (the KEK-derived seal that device-privkey.json uses), proving seal
    /// independence.
    #[test]
    fn identity_seal_is_independent_of_kek_seal() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let kek_seal = handle
            .devkey_seal()
            .expect("unlocked handle must expose the devkey seal");
        let sealed = std::fs::read(dir.path().join("meta/identity.enc")).unwrap();
        assert!(
            crate::vault::identity::open_identity(&kek_seal, &sealed).is_err(),
            "identity must not be decryptable with the KEK-derived devkey seal"
        );
    }

    /// P5c/P4: a blocked per-fact path makes save_folders fail — and the
    /// failure PROPAGATES to every caller (P4 never swallows metadata save
    /// errors).
    #[test]
    fn save_folders_blocked_path_fails() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let folder_id = handle.create_folder("changed").unwrap();

        // Make the folder's per-fact FILE path a directory: any save that
        // must rewrite it fails (atomic rename onto a directory), and the
        // failure PROPAGATES out of save_folders (P4: never silently strand
        // an artifact at the old epoch).
        let folder_file = dir
            .path()
            .join("meta/folders")
            .join(format!("{folder_id}.enc"));
        std::fs::remove_file(&folder_file).unwrap();
        std::fs::create_dir_all(&folder_file).unwrap();

        let changed = crate::vault::manifest::Folder {
            id: folder_id,
            name: "changed-v2".into(),
            parent_id: None,
            icon: None,
        };
        let err = handle.save_folders(&[changed]).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("directory"),
            "expected the blocked-path save failure, got: {err}"
        );
    }

    /// P4: a pre-swap metadata READ failure aborts the rotation BEFORE the
    /// point of no return, with the .rotation-pending marker left on disk
    /// (the armed RotationGuard keeps it — an incomplete rotation must never
    /// look complete).
    #[test]
    fn rotation_propagates_metadata_failure() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let folder_id = handle.create_folder("doomed").unwrap();

        // Corrupt the folder's per-fact file: the pre-swap list_folders()
        // read propagates the decrypt failure, aborting the rotation before
        // the keywrap swap. (get_settings is error-tolerant by design, so
        // settings corruption would NOT abort — folders do.)
        let folder_file = dir
            .path()
            .join("meta/folders")
            .join(format!("{folder_id}.enc"));
        std::fs::write(&folder_file, b"not-a-valid-envelope").unwrap();

        let err = handle.rotate_root_key().unwrap_err();
        assert!(
            dir.path().join("meta/.rotation-pending").exists(),
            "aborted rotation must leave the pending marker"
        );
        assert!(!err.to_string().is_empty());
    }

    /// P5c: folders and tags live as per-fact encrypted files. Two commits
    /// touching different folders must not churn unrelated files (the
    /// multi-writer conflict pattern P5 kills), and legacy layouts stay
    /// readable.
    #[test]
    fn folders_tags_per_fact_layout_and_churn_skip() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Three folders -> three per-fact files, no legacy envelope.
        let f1 = handle.create_folder("alpha").unwrap();
        let _f2 = handle.create_folder("beta").unwrap();
        let _f3 = handle.create_folder("gamma").unwrap();
        let fdir = dir.path().join("meta/folders");
        assert_eq!(std::fs::read_dir(&fdir).unwrap().count(), 3);
        assert!(!dir.path().join("meta/folders.enc").exists());

        handle.rename_folder(f1, "alpha-renamed").unwrap();

        let names: Vec<String> = handle
            .list_folders()
            .unwrap()
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert!(names.contains(&"alpha-renamed".to_string()));

        // Tags: per-fact files under meta/tags, pruned when the tag goes
        // away via rebuild.
        handle.create_tag("solo").unwrap();
        let tdir = dir.path().join("meta/tags");
        assert_eq!(std::fs::read_dir(&tdir).unwrap().count(), 1);
        assert!(!dir.path().join("meta/tags.enc").exists());

        // rebuild_tag_index derives tags from ciphers; "solo" is on none, so
        // it prunes the per-fact file.
        handle.rebuild_tag_index().unwrap();
        assert_eq!(std::fs::read_dir(&tdir).unwrap().count(), 0);
        assert!(handle.list_tags().unwrap().is_empty());
    }

    /// P5a/P5c: folders and tags dirs are local-tracked state that must be
    /// committed (other devices need folder/tag lists), and the churn-skip
    /// must keep unrelated per-fact files byte-identical across commits.
    #[test]
    fn folder_rename_touches_only_its_own_file() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let f1 = handle.create_folder("one").unwrap();
        let f2 = handle.create_folder("two").unwrap();

        let fdir = dir.path().join("meta/folders");
        let file_for = |id: uuid::Uuid| fdir.join(format!("{id}.enc"));
        let f2_before = std::fs::read(file_for(f2)).unwrap();

        handle.rename_folder(f1, "one-renamed").unwrap();

        // f2's file is byte-identical (skip-if-unchanged), f1's changed.
        assert_eq!(
            std::fs::read(file_for(f2)).unwrap(),
            f2_before,
            "untouched folder file must be byte-identical"
        );
        let one_meta: crate::vault::manifest::Folder = serde_json::from_slice(&{
            let key = crate::crypto::hkdf_derive::derive_folders_key(
                &handle_root_key_for_test(&handle).try_into().unwrap(),
            )
            .unwrap();
            let envelope =
                crate::vault::envelope::deserialize(&std::fs::read(file_for(f1)).unwrap()).unwrap();
            crate::crypto::aead::decrypt(&key, &envelope).unwrap()
        })
        .unwrap();
        assert_eq!(one_meta.name, "one-renamed");
    }

    /// Helper for tests: read the current root key bytes from an unlocked
    /// handle.
    fn handle_root_key_for_test(handle: &VaultHandle) -> Vec<u8> {
        match &handle.state {
            VaultState::Unlocked(u) => u.root().expect("root in test").as_bytes().to_vec(),
            VaultState::Locked => panic!("test handle must be unlocked"),
        }
    }

    #[test]
    fn unlock_with_kek_roundtrip() {
        // unlock_with_kek must produce the same unlocked state as the
        // full master-password unlock (same KEK -> same root/session keys).
        // This is the contract the session-PIN path relies on.
        let (dir, password) = create_test_vault();

        // Derive the KEK the same way the daemon does for PIN escrow.
        let probe = VaultHandle::open(dir.path()).unwrap();
        let kek = crate::crypto::kdf::derive_kek(&password, &probe.kdf_params).unwrap();

        let mut handle = VaultHandle::open(dir.path()).unwrap();
        assert!(!handle.is_unlocked());
        handle.unlock_with_kek(&kek).expect("correct KEK unlocks");
        assert!(handle.is_unlocked(), "unlock_with_kek sets Unlocked state");
    }

    #[test]
    fn unlock_with_kek_wrong_kek_fails() {
        // A wrong KEK must fail closed (canary mismatch) without panicking.
        // The PIN path's rate limiter handles attempt accounting.
        let (dir, _password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        let wrong_kek = [0u8; 32];
        assert!(handle.unlock_with_kek(&wrong_kek).is_err());
        assert!(!handle.is_unlocked());
    }

    #[test]
    fn add_and_decrypt_cipher() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@example.com".into()),
                password: Some("s3cret!".into()),
                uris: vec![crate::types::LoginUri::new("https://github.com".into())],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                fido2_credentials: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };

        let cipher_id = handle.add_cipher(&input).unwrap();

        // Re-open and unlock to verify persistence
        let mut handle2 = VaultHandle::open(dir.path()).unwrap();
        handle2.unlock(&password).unwrap();

        let result = handle2.get_cipher(cipher_id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "GitHub");
                match &c.kind {
                    crate::types::CipherKind::Login(data) => {
                        assert_eq!(data.username.as_deref(), Some("user@example.com"));
                        assert_eq!(data.password.as_deref(), Some("s3cret!"));
                    }
                    _ => panic!("expected Login kind"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted cipher"),
        }
    }

    #[test]
    fn locked_vault_returns_metadata_only() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Test".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("pw".into()),
                uris: vec![],
                totp_uri: None,
                autofill_on_page_load: false,
                fido2_credentials: None,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };

        let cipher_id = handle.add_cipher(&input).unwrap();
        handle.lock();

        let result = handle.get_cipher(cipher_id).unwrap();
        match result {
            CipherRead::Locked(info) => {
                assert_eq!(info.id, cipher_id);
                assert_eq!(info.key_epoch, 1);
            }
            CipherRead::Decrypted(_) => panic!("expected locked metadata"),
        }
    }

    #[test]
    fn sweep_keeps_collection_entries_readable() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let cid = handle.collection_create("Expiry").unwrap();
        let mk_input = |name: &str| CipherInput {
            name: name.into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::SecureNote,
            favorite: false,
            notes: Some("carry me".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let live = handle
            .add_cipher_in_collection(&mk_input("InSweep"), Some(cid))
            .unwrap();
        let trashed = handle
            .add_cipher_in_collection(&mk_input("Trashed"), Some(cid))
            .unwrap();
        handle.delete_cipher(trashed).unwrap();

        // Plant a past-dated member grant at the file level (time passage,
        // not mint-expired). The grantee's wrap pubkey is synthetic: the
        // sweep only needs the grant row to expire.
        let gone = Uuid::new_v4();
        let mut row = crate::vault::members::MemberFile {
            id: gone,
            display_name: "Gone".into(),
            role: crate::vault::members::MemberRole::Viewer,
            trust: crate::vault::members::TrustLevel::Channel,
            ..serde_default_member_row()
        };
        row.identity_signing_pubkey = Some(hex::encode([9u8; 32]));
        crate::vault::members::write_member(dir.path(), &row).unwrap();
        {
            let sgk = handle.unlocked().sgk().unwrap().clone();
            let (mut seeded, _) =
                crate::vault::collections::open_collection(dir.path(), &sgk, &cid).unwrap();
            seeded
                .grants
                .push(crate::vault::collections::CollectionGrant {
                    target: crate::vault::collections::GrantTarget::Member { id: gone },
                    access: crate::vault::collections::CollectionAccess::Read,
                    expires_at: Some(1),
                });
            crate::vault::collections::save_collection(dir.path(), &seeded).unwrap();
        }

        let removed = handle.collections_sweep().unwrap();
        assert_eq!(removed.len(), 1);

        // Without the re-encryption pass both entries are sealed under
        // item keys derived from the dead CK and unreadable.
        match handle.get_cipher(live).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "InSweep");
                assert_eq!(c.notes.as_deref(), Some("carry me"));
            }
            CipherRead::Locked(_) => panic!("expected decrypted entry after sweep"),
        }
        match handle.get_cipher(trashed).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Trashed"),
            CipherRead::Locked(_) => panic!("expected decrypted trash after sweep"),
        }
    }

    fn serde_default_member_row() -> crate::vault::members::MemberFile {
        serde_json::from_str(
            r#"{"id":"00000000-0000-0000-0000-000000000000","display_name":"x","role":"viewer","trust":"channel"}"#,
        )
        .unwrap()
    }

    /// 2026-10-01 review: one corrupt entry must not abort a rotation
    /// mid-offboarding (after the tombstone there is no retry). The
    /// damaged file is skipped loudly; honest entries re-key normally.
    #[test]
    fn rotation_survives_a_corrupt_entry() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let cid = handle.collection_create("Work").unwrap();
        let mk = |name: &str| CipherInput {
            name: name.into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::SecureNote,
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let good = handle
            .add_cipher_in_collection(&mk("Good"), Some(cid))
            .unwrap();
        let bad = handle
            .add_cipher_in_collection(&mk("Bad"), Some(cid))
            .unwrap();
        let bad_path = handle.cipher_file_path(bad).unwrap();
        std::fs::write(&bad_path, b"garbage bytes").unwrap();

        handle.rotate_root_key().unwrap();

        match handle.get_cipher(good).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Good"),
            CipherRead::Locked(_) => panic!("expected the honest entry readable"),
        }
        assert!(handle.get_cipher(bad).is_err());
    }

    /// 2026-10-01 review: a removal on a flipped vault rotates the SMK;
    /// the member-visible meta must re-seal under the rotated key or the
    /// actor's next unlock reads empty folders/tags/profile.
    #[test]
    fn removal_on_flipped_vault_reseals_meta() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        handle.space_prepare().unwrap();
        handle.space_flip().unwrap();
        let folder = handle.create_folder("Keep").unwrap();
        let gone = uuid::Uuid::new_v4();
        std::fs::create_dir_all(dir.path().join("meta/members")).unwrap();
        crate::vault::members::write_member(
            dir.path(),
            &crate::vault::members::MemberFile {
                id: gone,
                display_name: "Gone".into(),
                email: None,
                role: crate::vault::members::MemberRole::Viewer,
                trust: crate::vault::members::TrustLevel::Channel,
                identity_signing_pubkey: None,
                identity_signing_pubkey_previous: None,
                identity_rotation_signature: None,
                identity_rotated_at: None,
                reset: None,
                removed: None,
                transport_username: None,
                identity_wrap_pubkey: None,
            },
        )
        .unwrap();

        handle.member_remove(&[gone]).unwrap();

        let folders = handle.list_folders().unwrap();
        assert!(folders.iter().any(|f| f.id == folder));
        assert!(handle.get_settings().is_ok());
    }

    #[test]
    fn trash_entries_carry_origin_collection() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let cid = handle.collection_create("Moves").unwrap();
        let scoped = handle
            .add_cipher_in_collection(
                &CipherInput {
                    name: "Scoped".into(),
                    folder_id: None,
                    collection_id: None,
                    kind: crate::types::CipherKind::SecureNote,
                    favorite: false,
                    notes: None,
                    custom_fields: vec![],
                    created_at: None,
                    password_history: vec![],
                    attachments: vec![],
                    archived: false,
                    tags: vec![],
                    reprompt: false,
                },
                Some(cid),
            )
            .unwrap();
        let flat = handle
            .add_cipher(&CipherInput {
                name: "Flat".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::SecureNote,
                favorite: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![],
                archived: false,
                tags: vec![],
                reprompt: false,
            })
            .unwrap();

        handle.delete_cipher(scoped).unwrap();
        handle.delete_cipher(flat).unwrap();

        let rows = handle.list_trash_entries().unwrap();
        assert_eq!(rows.len(), 2);
        let scoped_row = rows.iter().find(|(id, _)| *id == scoped).unwrap();
        assert_eq!(scoped_row.1, Some(cid));
        let flat_row = rows.iter().find(|(id, _)| *id == flat).unwrap();
        assert_eq!(flat_row.1, None);

        // Same-domain restore keeps working off the same walk.
        handle.restore_cipher(scoped).unwrap();
        let rows = handle.list_trash_entries().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, None);
    }

    #[test]
    fn trash_soft_delete_restore_purge() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Delete Me".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: None,
                password: Some("val".into()),
                uris: vec![],
                totp_uri: None,
                fido2_credentials: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };

        let id = handle.add_cipher(&input).unwrap();
        assert!(handle.list_cipher_ids().unwrap().contains(&id));
        assert!(handle.list_trash_ids().unwrap().is_empty());

        // Delete moves it to trash
        handle.delete_cipher(id).unwrap();
        assert!(!handle.list_cipher_ids().unwrap().contains(&id));
        assert!(handle.list_trash_ids().unwrap().contains(&id));

        // Restore moves it back
        handle.restore_cipher(id).unwrap();
        assert!(handle.list_cipher_ids().unwrap().contains(&id));
        assert!(handle.list_trash_ids().unwrap().is_empty());

        // Delete to trash again
        handle.delete_cipher(id).unwrap();
        assert!(handle.list_trash_ids().unwrap().contains(&id));

        // Purge (0 days removes it immediately)
        let count = handle.purge_old_trash(0).unwrap();
        assert_eq!(count, 1);
        assert!(handle.list_trash_ids().unwrap().is_empty());
    }

    #[test]
    fn list_cipher_meta_returns_type_and_favorite() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Add a login
        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@gh.com".into()),
                password: Some("s3cret".into()),
                uris: vec![],
                fido2_credentials: None,
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
                favicon: None,
            }),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.add_cipher(&input).unwrap();

        // Add a card
        let card_input = CipherInput {
            name: "Visa".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Card(crate::types::CardData {
                brand: Some("Visa".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.add_cipher(&card_input).unwrap();

        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 2);

        let login_meta = metas.iter().find(|m| m.name == "GitHub").unwrap();
        assert_eq!(login_meta.cipher_type, crate::types::CipherType::Login);
        assert!(login_meta.favorite);
        assert_eq!(login_meta.username.as_deref(), Some("user@gh.com"));

        let card_meta = metas.iter().find(|m| m.name == "Visa").unwrap();
        assert_eq!(card_meta.cipher_type, crate::types::CipherType::Card);
        assert!(!card_meta.favorite);
        assert!(card_meta.username.is_none());
    }

    #[test]
    fn update_cipher_changes_name() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Old Name".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        let updated = CipherInput {
            name: "New Name".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.update_cipher(id, &updated).unwrap();

        // Re-read to verify
        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "New Name");
                assert!(c.favorite);
                assert_eq!(c.update_seq, 2);
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn password_change_appends_history() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@gh.com".into()),
                password: Some("old-pass-1".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        // Change password 3 times
        for pw in ["old-pass-2", "old-pass-3", "new-pass"] {
            let updated = CipherInput {
                name: "GitHub".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData {
                    username: Some("user@gh.com".into()),
                    password: Some(pw.into()),
                    ..Default::default()
                }),
                favorite: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![],
                archived: false,
                tags: vec![],
                reprompt: false,
            };
            handle.update_cipher(id, &updated).unwrap();
        }

        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.password_history.len(), 3);
                assert_eq!(c.password_history[0].password, "old-pass-1");
                assert_eq!(c.password_history[1].password, "old-pass-2");
                assert_eq!(c.password_history[2].password, "old-pass-3");
                // Ascending timestamps
                assert!(
                    c.password_history[0].last_used_date <= c.password_history[1].last_used_date
                );
                assert!(
                    c.password_history[1].last_used_date <= c.password_history[2].last_used_date
                );
                // Current password is the new one
                match &c.kind {
                    crate::types::CipherKind::Login(data) => {
                        assert_eq!(data.password.as_deref(), Some("new-pass"));
                        // password_revision_date must be set after change
                        assert!(data.password_revision_date.is_some());
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn clone_has_empty_history_and_different_id() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Create entry with some password history
        let input = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass1".into()),
                ..Default::default()
            }),
            favorite: true,
            notes: Some("notes".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        // Change password to create history
        let updated = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass2".into()),
                ..Default::default()
            }),
            favorite: true,
            notes: Some("notes".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.update_cipher(id, &updated).unwrap();

        // Clone
        let cloned_id = handle.clone_cipher(id).unwrap();
        assert_ne!(cloned_id, id, "clone must have different UUID");

        // Verify clone
        let result = handle.get_cipher(cloned_id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "GitHub");
                assert!(c.favorite);
                assert!(
                    c.password_history.is_empty(),
                    "clone must have empty history"
                );
                match &c.kind {
                    crate::types::CipherKind::Login(data) => {
                        assert_eq!(data.password.as_deref(), Some("pass2"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Verify original still has history
        let original = handle.get_cipher(id).unwrap();
        match original {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.password_history.len(), 1);
                assert_eq!(c.password_history[0].password, "pass1");
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn password_history_capped_at_ten() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Test".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                password: Some("pw0".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id = handle.add_cipher(&input).unwrap();

        // Change password 15 times
        for i in 1..=15 {
            let updated = CipherInput {
                name: "Test".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData {
                    password: Some(format!("pw{i}")),
                    ..Default::default()
                }),
                favorite: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![],
                archived: false,
                tags: vec![],
                reprompt: false,
            };
            handle.update_cipher(id, &updated).unwrap();
        }

        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.password_history.len(), 10, "history must be capped at 10");
                // Oldest entries evicted: should have pw5..pw14 (10 most recent)
                assert_eq!(c.password_history[0].password, "pw5");
                assert_eq!(c.password_history[9].password, "pw14");
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn folder_create_list_rename_delete() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Initially empty
        let folders = handle.list_folders().unwrap();
        assert!(folders.is_empty());

        // Create
        let id1 = handle.create_folder("Work").unwrap();
        let id2 = handle.create_folder("Personal").unwrap();
        assert_ne!(id1, id2);

        // List
        let folders = handle.list_folders().unwrap();
        assert_eq!(folders.len(), 2);
        let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Work"));
        assert!(names.contains(&"Personal"));

        // Rename
        handle.rename_folder(id1, "Work - Renamed").unwrap();
        let folders = handle.list_folders().unwrap();
        let renamed = folders.iter().find(|f| f.id == id1).unwrap();
        assert_eq!(renamed.name, "Work - Renamed");

        // Delete
        handle.delete_folder(id2).unwrap();
        let folders = handle.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, id1);

        // Delete non-existent
        let result = handle.delete_folder(id2);
        assert!(result.is_err());
    }

    #[test]
    fn folder_delete_unassigns_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let folder_id = handle.create_folder("Social").unwrap();

        // Add cipher assigned to folder
        let input = CipherInput {
            name: "Twitter".into(),
            folder_id: Some(folder_id),
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Verify folder assignment
        let cipher = handle.get_cipher(cipher_id).unwrap();
        match cipher {
            CipherRead::Decrypted(c) => assert_eq!(c.folder_id, Some(folder_id)),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Delete folder
        handle.delete_folder(folder_id).unwrap();

        // Verify cipher is now unassigned
        let cipher = handle.get_cipher(cipher_id).unwrap();
        match cipher {
            CipherRead::Decrypted(c) => {
                assert_eq!(
                    c.folder_id, None,
                    "cipher should be unassigned after folder delete"
                );
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn folder_move_cipher_between_folders() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let folder_a = handle.create_folder("A").unwrap();
        let folder_b = handle.create_folder("B").unwrap();

        // Add cipher to folder A
        let input = CipherInput {
            name: "Test".into(),
            folder_id: Some(folder_a),
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Move to folder B via update_cipher
        let updated = CipherInput {
            name: "Test".into(),
            folder_id: Some(folder_b),
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        handle.update_cipher(cipher_id, &updated).unwrap();

        // Verify
        let cipher = handle.get_cipher(cipher_id).unwrap();
        match cipher {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.folder_id, Some(folder_b));
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    // MISS-1: rotate_root_key re-encrypts all ciphers
    // P4 remainder: the avatar envelope is SGK-epoch-bound; both rotation
    // flows must re-encrypt it, or avatar_get fails after rotation.
    fn write_test_avatar(
        handle: &VaultHandle,
        dir: &std::path::Path,
    ) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let plaintext = b"fake-png-image-bytes".to_vec();
        let old_key = handle.derive_avatar_key().expect("avatar key in test");
        let blob = crate::vault::avatar::encrypt_avatar(&old_key, &plaintext).unwrap();
        std::fs::write(dir.join("meta/avatar.enc"), &blob).unwrap();
        (plaintext, blob, old_key)
    }

    #[test]
    fn rotate_root_key_re_encrypts_avatar() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let (plaintext, old_blob, old_key) = write_test_avatar(&handle, dir.path());

        let old_epoch = handle.unlocked().current_epoch;
        handle.rotate_root_key().unwrap();
        assert_eq!(handle.unlocked().current_epoch, old_epoch + 1);

        let stored = std::fs::read(dir.path().join("meta/avatar.enc")).unwrap();
        assert_ne!(stored, old_blob, "avatar blob must be re-encrypted");
        let roundtrip =
            crate::vault::avatar::decrypt_avatar(&handle.derive_avatar_key().unwrap(), &stored)
                .unwrap();
        assert_eq!(roundtrip, plaintext);
        assert!(
            crate::vault::avatar::decrypt_avatar(&old_key, &stored).is_err(),
            "stale-epoch key must not decrypt the avatar"
        );
    }

    #[test]
    fn revoke_device_and_rekey_re_encrypts_avatar() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let _dev2_id = enroll_second_device(&mut handle, dir.path(), &password);
        let dev3_id = enroll_third_device(&mut handle, dir.path());
        let (plaintext, old_blob, old_key) = write_test_avatar(&handle, dir.path());

        handle.revoke_device_and_rekey(dev3_id).unwrap();

        let stored = std::fs::read(dir.path().join("meta/avatar.enc")).unwrap();
        assert_ne!(stored, old_blob, "avatar blob must be re-encrypted");
        let roundtrip =
            crate::vault::avatar::decrypt_avatar(&handle.derive_avatar_key().unwrap(), &stored)
                .unwrap();
        assert_eq!(roundtrip, plaintext);
        assert!(crate::vault::avatar::decrypt_avatar(&old_key, &stored).is_err());
    }

    #[test]
    fn avatar_reads_legacy_sgk_blobs() {
        // Pre-re-home vaults carry avatars encrypted under the legacy
        // SGK epoch-bound derivation; the flexible read must open them
        // until a rotation or avatar write migrates the blob.
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let sgk = handle.unlocked().sgk().expect("founder holds sgk").clone();
        let legacy_key = sgk.derive_avatar_key(sgk.epoch());
        let plaintext = b"legacy-avatar".to_vec();
        let blob = crate::vault::avatar::encrypt_avatar(&legacy_key, &plaintext).unwrap();
        std::fs::write(dir.path().join("meta/avatar.enc"), &blob).unwrap();
        let opened = handle.decrypt_avatar_blob(&blob).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn rotate_root_key_re_encrypts_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Add some ciphers
        let input1 = CipherInput {
            name: "GitHub".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user@gh.com".into()),
                password: Some("secret123".into()),
                ..Default::default()
            }),
            favorite: true,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id1 = handle.add_cipher(&input1).unwrap();

        let input2 = CipherInput {
            name: "AWS".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("admin".into()),
                password: Some("aws-key".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id2 = handle.add_cipher(&input2).unwrap();

        // Capture old epoch
        let old_epoch = handle.unlocked().current_epoch;

        // Rotate root key
        handle.rotate_root_key().unwrap();

        // Verify epoch incremented
        let new_epoch = handle.unlocked().current_epoch;
        assert_eq!(new_epoch, old_epoch + 1);

        // Verify both ciphers still decrypt correctly
        match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "GitHub");
                assert!(c.favorite);
                match &c.kind {
                    crate::types::CipherKind::Login(d) => {
                        assert_eq!(d.username.as_deref(), Some("user@gh.com"));
                        assert_eq!(d.password.as_deref(), Some("secret123"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "AWS");
                match &c.kind {
                    crate::types::CipherKind::Login(d) => {
                        assert_eq!(d.password.as_deref(), Some("aws-key"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Verify persistence: re-open vault and verify decryption still works
        let password2 = password.clone();
        let mut handle2 = VaultHandle::open(dir.path()).unwrap();
        handle2.unlock(&password2).unwrap();
        assert_eq!(handle2.unlocked().current_epoch, new_epoch);

        match handle2.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "GitHub"),
            CipherRead::Locked(_) => panic!("expected decrypted after re-open"),
        }
    }

    #[test]
    fn test_index_fast_lookup_and_auto_heal() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // 1. Initial empty index is created on unlock/load/add
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 0);

        // Verify index.enc exists
        let index_path = handle.path.join("meta/index.enc");
        assert!(index_path.exists());

        // 2. Add some ciphers - should automatically update index
        let _id1 = handle
            .add_cipher(&CipherInput {
                name: "GH1".into(),
                ..Default::default()
            })
            .unwrap();

        let _id2 = handle
            .add_cipher(&CipherInput {
                name: "AWS1".into(),
                ..Default::default()
            })
            .unwrap();

        // List metadata - should read from index.enc
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 2);
        assert!(metas.iter().any(|m| m.name == "GH1"));
        assert!(metas.iter().any(|m| m.name == "AWS1"));

        // 3. Test Auto-Heal: corrupt the index.enc by writing junk bytes to it
        std::fs::write(&index_path, b"corrupted-junk-bytes").unwrap();

        // List metadata should trigger decryption failure on index, then auto-heal,
        // scan ciphers folder, rebuild index, and return valid metadata
        let metas_healed = handle.list_cipher_meta().unwrap();
        assert_eq!(metas_healed.len(), 2);
        assert!(metas_healed.iter().any(|m| m.name == "GH1"));
        assert!(metas_healed.iter().any(|m| m.name == "AWS1"));

        // Verify that index.enc was automatically rewritten and is now healthy again
        let envelope_bytes = std::fs::read(&index_path).unwrap();
        let unlocked = handle.unlocked();
        let index_key = crate::crypto::hkdf_derive::derive_index_key(&unlocked.meta_ikm()).unwrap();
        let decoded = index::decrypt_index(handle.vault_id, &envelope_bytes, &index_key).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn archive_unarchive_roundtrip() {
        let (dir, password) = create_test_vault();
        let path = dir.path();
        let mut handle = VaultHandle::open(path).unwrap();
        handle.unlock(&password).unwrap();

        // Add a cipher
        let input = CipherInput {
            name: "ArchiveMe".into(),
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("arch@example.com".into()),
                password: Some("s3cret".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Verify it appears in list
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].id, cipher_id);
        assert!(!metas[0].archived);

        // Archive it
        handle.archive_cipher(cipher_id).unwrap();

        // Should NOT appear in normal list
        let metas = handle.list_cipher_meta().unwrap();
        assert!(
            metas.is_empty(),
            "archived cipher should not appear in list"
        );

        // Should appear in archived list
        let archived = handle.list_archived_meta().unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].id, cipher_id);
        assert!(archived[0].archived);

        // Verify cipher data still intact
        let cipher = match handle.get_cipher(cipher_id).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(cipher.name, "ArchiveMe");
        assert!(cipher.archived);

        // Unarchive
        handle.unarchive_cipher(cipher_id).unwrap();

        // Should reappear in normal list
        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 1);
        assert!(!metas[0].archived);

        // Archived list should be empty
        let archived = handle.list_archived_meta().unwrap();
        assert!(archived.is_empty());
    }

    #[test]
    fn archive_idempotent() {
        let (dir, password) = create_test_vault();
        let path = dir.path();
        let mut handle = VaultHandle::open(path).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "DoubleArchive".into(),
            ..Default::default()
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        // Archive twice should not error
        handle.archive_cipher(cipher_id).unwrap();
        handle.archive_cipher(cipher_id).unwrap();

        let archived = handle.list_archived_meta().unwrap();
        assert_eq!(archived.len(), 1);

        // Unarchive twice should not error
        handle.unarchive_cipher(cipher_id).unwrap();
        handle.unarchive_cipher(cipher_id).unwrap();

        let metas = handle.list_cipher_meta().unwrap();
        assert_eq!(metas.len(), 1);
    }

    // ── S1a-2: join ceremony tracer ──

    use crate::error::SyncError as TestSyncError;

    /// Thin end-to-end walking skeleton: invite → introduction →
    /// approval → sync → member unlock (own password) → member write →
    /// owner-side role verification. Every layer is real (git transport,
    /// member KDF material, role enforcement); the surface is
    /// intentionally CLI-thin.
    #[test]
    fn member_join_tracer_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();

        // Owner: invite an editor. The code travels out-of-band.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();

        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Ship the pending invite to the joiner (thin tracer: a normal
        // sync cycle instead of the provider grant of the full join
        // queue).
        engine_o.commit_all(&repo_o, "invite").unwrap();

        // Joiner: clone the vault, introduce with the code + own password.
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();

        // Pre-approval: the joiner can open the clone; the local device
        // identity survives and unlock fails clearly (no keywrap yet).
        let mut early = VaultHandle::open(&joiner_path).unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        assert_eq!(early.device_id, intro.device_id);
        assert!(early.unlock("member-pass").is_err());
        drop(early);

        // Owner: approve (enrolls the device, wraps the Root Key to it,
        // writes the member record + binding with the invite's role).
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // Joiner: pull the approval artifacts and unlock with their OWN
        // password.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        assert_ne!(joiner.device_id, handle.device_id);
        // Wrong password records a failed attempt (brute-force protection
        // covers member passwords too); the correct one still works.
        assert!(joiner.unlock("wrong-pass").is_err());
        assert!(
            joiner_path.join("meta/kdf-attempts.json").exists(),
            "failed member unlock attempts must record"
        );
        joiner.unlock("member-pass").unwrap();

        // Member writes a cipher; the owner pulls and the role-aware
        // verification admits the Editor's cipher write.
        let input = CipherInput {
            name: "FromMember".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("member".into()),
                password: Some("pw".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let cid = joiner.add_cipher(&input).unwrap();
        let joiner_seal = joiner.devkey_seal();
        let engine_j2 = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner.device_id.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j2.commit_all(&repo_j, "member cipher").unwrap();

        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        let merged_oid = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert!(
            engine_o
                .verify_commit_signatures(&repo_o, &[merged_oid])
                .is_ok(),
            "member editor cipher commit must verify"
        );

        // The member still reads what they wrote after the round trip.
        match joiner.get_cipher(cid).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "FromMember"),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Role refusal: the member's meta write is refused ON PULL
        // (meta catch-all is Admin) — the owner fetches the commit and
        // the verification walk rejects it before any merge/checkout.
        // Hostile-author bypass: the staged-path-set filter would leave
        // this write unstaged (pinned by
        // staged_path_set_filters_unwritable_member_writes); this test
        // pins the walk itself.
        std::fs::write(joiner_path.join("meta/epoch.json"), b"{\"epoch\":9}").unwrap();
        engine_j2
            .commit_all_unfiltered(&repo_j, "member meta")
            .unwrap();
        let head_before = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        let pulled_meta = engine_o.pull(&repo_o, "joiner");
        assert!(
            matches!(
                &pulled_meta,
                Err(BaluardError::Sync(TestSyncError::PolicyViolation { .. }))
            ),
            "member meta push must be refused on pull, got {pulled_meta:?}"
        );
        let head_after = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert_eq!(head_after, head_before, "refused pull must not move HEAD");
    }

    /// S1a-3: the trust dial bites at approval. An Admin invite is
    /// refused until the joiner's contact card is imported AND verified
    /// (Level 2 code check), and the introduction must carry an identity
    /// signature binding the device keys to the verified card. After the
    /// code check the approval succeeds and the Admin's meta writes are
    /// admitted (contrast with the Editor refusal in the S1a-2 tracer).
    #[test]
    fn member_join_trust_dial_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();

        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();

        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();

        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();

        // Gate 1: Admin role, card NOT imported yet → refused, invite
        // stays pending (retryable).
        let refused = handle.approve_join(&intro_code);
        assert!(
            refused.is_err(),
            "unverified admin join must be refused: {refused:?}"
        );

        // Owner imports the joiner's card (Level 1: Channel), runs the
        // code check (both sides derive the same code), marks Verified.
        let trust = handle.contacts_import_intro(&intro_code).unwrap();
        assert_eq!(
            trust,
            crate::vault::contacts::ContactTrust::Channel,
            "import lands at Channel"
        );
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        let card = intro.contact_card.as_ref().unwrap();
        let owner_view =
            crate::vault::contacts::load_contacts(&owner_path, &handle.contacts_key().unwrap())
                .unwrap();
        let imported = owner_view
            .iter()
            .find(|e| e.card.identity_signing_pubkey == card.card.identity_signing_pubkey)
            .unwrap();
        assert_eq!(
            imported.card.verification_code(),
            card.card.verification_code(),
            "code check must derive the same code on both sides"
        );
        handle
            .contacts_mark_verified(&card.card.identity_signing_pubkey)
            .unwrap();

        // Gate 2: verified contact → approval succeeds.
        let member_id = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // Joiner pulls, unlocks, and their ADMIN meta write is admitted
        // (contrast with the Editor refusal in member_roles_enforced).
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        std::fs::write(joiner_path.join("meta/epoch.json"), b"{\"epoch\":5}").unwrap();
        let joiner_seal = joiner.devkey_seal();
        let engine_j2 = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner.device_id.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j2.commit_all(&repo_j, "admin meta").unwrap();
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        let merged = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert!(
            engine_o
                .verify_commit_signatures(&repo_o, &[merged])
                .is_ok(),
            "admin meta write must verify"
        );

        // Member record carries the invite's role.
        let member_file = owner_path
            .join("meta/members")
            .join(format!("{member_id}.json"));
        let record: crate::vault::members::MemberFile =
            serde_json::from_str(&std::fs::read_to_string(&member_file).unwrap()).unwrap();
        assert_eq!(record.role, crate::vault::members::MemberRole::Admin);
    }

    /// S3-6: request-access JIT end-to-end across two devices. The joiner
    /// submits a sealed ask, the owner's inbox decrypts it, approval issues
    /// the grant + mints the per-member wrap + consumes the file, and a
    /// second ask dies by denial. Ship legs ride the real sync engine.
    // S3-7b: the full team-shape flip ceremony. Owner + Editor joiner
    // through the standard ceremony; prepare, flip, ship, pull, and both
    // unlock paths must land on the same meta keys with the joiner
    // holding no Root Key.
    #[test]
    fn space_migrate_moves_history_and_followers_adopt() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Origin = bare A; ship the initial state.
        let bare_a = tempfile::tempdir().unwrap();
        git2::Repository::init_bare(bare_a.path()).unwrap();
        repo_o
            .remote("origin", bare_a.path().to_str().unwrap())
            .unwrap();
        // First-ever push: the bare remote has nothing to pull, so the
        // canonical cycle's pull leg would fail — push directly.
        engine_o.push(&repo_o, "origin").unwrap();

        // A follower cloned from A before the migration.
        let follower_path = temp.path().join("follower");
        git2::Repository::clone(bare_a.path().to_str().unwrap(), &follower_path).unwrap();
        let engine_f = crate::sync::engine::SyncEngine::new(&follower_path, "follower", None);

        // Destination: bare B.
        let bare_b = tempfile::tempdir().unwrap();
        git2::Repository::init_bare(bare_b.path()).unwrap();
        let to_url = bare_b.path().to_str().unwrap().to_string();

        // Refusals first: same address, unsupported scheme, no origin.
        let err = engine_o
            .migrate_remote(&repo_o, bare_a.path().to_str().unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("already the sync address"));
        let err = engine_o.migrate_remote(&repo_o, "ftp://nope").unwrap_err();
        assert!(err.to_string().contains("unsupported URL scheme"));
        let bare_repo = git2::Repository::init_bare(temp.path().join("norepo")).unwrap();
        let err = engine_o.migrate_remote(&bare_repo, &to_url).unwrap_err();
        assert!(err.to_string().contains("no sync address"));

        // Migrate: announcement on A, history on B, origin re-pointed.
        let report = engine_o.migrate_remote(&repo_o, &to_url).unwrap();
        assert_eq!(report.to, to_url);
        let origin_url = repo_o
            .find_remote("origin")
            .unwrap()
            .url()
            .unwrap()
            .to_string();
        assert_eq!(origin_url, to_url);
        assert_eq!(
            crate::sync::engine::read_remote_announcement(&owner_path).as_deref(),
            Some(to_url.as_str())
        );

        // B carries the vault head; A carries the announcement commit.
        let vault_head = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        let bare_b_repo = git2::Repository::open_bare(bare_b.path()).unwrap();
        assert_eq!(
            bare_b_repo
                .find_reference("refs/heads/main")
                .unwrap()
                .peel_to_commit()
                .unwrap()
                .id(),
            vault_head
        );
        let bare_a_repo = git2::Repository::open_bare(bare_a.path()).unwrap();
        let a_head = bare_a_repo
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap();
        let a_tree = a_head.tree().unwrap();
        assert!(
            a_tree
                .get_path(std::path::Path::new("meta/remote.json"))
                .is_ok(),
            "announcement committed on the old remote"
        );

        // The follower adopts on its next two cycles: cycle 1 pulls the
        // announcement from A.
        let repo_f = engine_f.open_repo().unwrap();
        engine_f.run_sync_cycle(&repo_f).unwrap();

        // Post-migration write on B: owner creates an entry or commits a file
        // and pushes directly to B (the active origin). This commit exists
        // ONLY on B, never on A.
        std::fs::write(owner_path.join("meta/notice.txt"), b"only on B").unwrap();
        engine_o
            .commit_all(&repo_o, "post-migration commit on new remote")
            .unwrap();
        engine_o.push(&repo_o, "origin").unwrap();
        let new_head = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert_ne!(new_head, vault_head);

        // Cycle 2: follower re-points to B and pulls the post-migration commit.
        engine_f.run_sync_cycle(&repo_f).unwrap();
        let follower_origin = repo_f
            .find_remote("origin")
            .unwrap()
            .url()
            .unwrap()
            .to_string();
        assert_eq!(follower_origin, to_url, "follower re-pointed itself");
        assert_eq!(
            repo_f.head().unwrap().peel_to_commit().unwrap().id(),
            new_head,
            "follower converged on the new remote with new commit"
        );

        // Idempotent follow: a third cycle changes nothing.
        assert!(!engine_f.apply_remote_announcement(&repo_f).unwrap());

        // Rollback test: migrate to an un-pushable remote aborts cleanly,
        // leaving origin and HEAD on B untouched.
        let bad_remote = temp.path().join("nonexistent_bare.git");
        let pre_fail_head = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert!(
            engine_o
                .migrate_remote(&repo_o, bad_remote.to_str().unwrap())
                .is_err()
        );
        assert_eq!(
            repo_o.find_remote("origin").unwrap().url().unwrap(),
            to_url,
            "origin was rolled back after failed migration"
        );
        // No-reset rollback (review): the aborted attempt's pointer
        // commit stays local and unpushed — a reset --hard would
        // discard any user work commit_all had swept in. Re-running
        // migrate converges on top of it.
        assert_ne!(
            repo_o.head().unwrap().peel_to_commit().unwrap().id(),
            pre_fail_head,
            "aborted migration leaves its commit local, origin restored"
        );

        // Manual repoint override: setting origin does not get reverted by apply_remote_announcement.
        let bare_c = tempfile::tempdir().unwrap();
        git2::Repository::init_bare(bare_c.path()).unwrap();
        let c_url = bare_c.path().to_str().unwrap().to_string();
        repo_f.remote_set_url("origin", &c_url).unwrap();
        assert!(!engine_f.apply_remote_announcement(&repo_f).unwrap());
        assert_eq!(
            repo_f.find_remote("origin").unwrap().url().unwrap(),
            c_url,
            "manual repoint was not clobbered"
        );
    }

    #[test]
    fn quorum_two_admin_rotation_needs_distinct_approvers() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Standard join ceremony with an ADMIN member (the second
        // approver). The invite reaches the clone because it commits
        // before the clone.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        // S1a: elevated roles require a Verified contact — import the
        // joiner's card from the intro and run the Level 2 upgrade.
        handle.contacts_import_intro(&intro_code).unwrap();
        let contacts = handle.contacts_list().unwrap();
        let joiner_card = contacts
            .iter()
            .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
            .expect("imported joiner card");
        handle
            .contacts_mark_verified(&joiner_card.card.identity_signing_pubkey)
            .unwrap();
        handle.approve_join(&intro_code).unwrap();
        // Raise the threshold BEFORE the joiner's first pull so both
        // devices read the same setting.
        let mut settings = handle.get_settings().unwrap();
        settings.quorum_admin_ops = Some(2);
        handle.save_settings(&settings).unwrap();
        engine_o.commit_all(&repo_o, "approve + quorum").unwrap();

        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert_eq!(joiner.get_settings().unwrap().quorum_admin_ops, Some(2));
        let joiner_seal = joiner.devkey_seal();
        let joiner_device = joiner.device_id;

        // First admin raises the ask: refused, record on file.
        let err = handle
            .rotate_root_key()
            .expect_err("solo rotation must wait for quorum");
        assert!(err.to_string().contains("admin approvals"), "{err}");
        let pending = handle.pending_op_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, "rotate_root_key");
        assert_eq!(pending[0].required, 2);
        // Same admin again: cannot self-confirm.
        let err = handle.rotate_root_key().expect_err("self-confirm");
        assert!(err.to_string().contains("different admin"), "{err}");

        // The record rides git: ship it, the second admin pulls, and
        // their confirming call runs the rotation on their device.
        engine_o.commit_all(&repo_o, "pending ask").unwrap();
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        joiner.rotate_root_key().expect("second admin confirms");
        assert!(joiner.pending_op_approvals().is_empty());

        // The confirming rotation mutated the JOINER's clone; ship it
        // back so the two devices converge before anything else (the
        // owner must re-unlock: its handle holds the pre-rotation root).
        let engine_js = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        let repo_js = engine_js.open_repo().unwrap();
        engine_js.commit_all(&repo_js, "joiner rotation").unwrap();
        drop(repo_js);
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        drop(handle);
        let mut handle = VaultHandle::open(&owner_path).unwrap();
        handle.unlock("owner-pass").unwrap();

        // Threshold-2 member_remove end to end (the double-precheck and
        // internal-rotation regression legs): the extra Editor is the
        // removal target.
        let code_e = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite extra").unwrap();
        let extra_path = temp.path().join("extra");
        git2::Repository::clone(owner_path.to_str().unwrap(), &extra_path).unwrap();
        let intro_e = crate::vault::members::create_introduction(
            &extra_path,
            &code_e,
            "extra-pass",
            "ExtraDevice",
        )
        .unwrap();
        let extra_id = handle.approve_join(&intro_e).unwrap();
        engine_o.commit_all(&repo_o, "approve extra").unwrap();

        // Owner initiates the removal: refused, ask on file.
        let err = handle
            .member_remove(&[extra_id])
            .expect_err("solo removal must wait for quorum");
        assert!(err.to_string().contains("admin approvals"), "{err}");
        engine_o.commit_all(&repo_o, "pending removal ask").unwrap();

        // The second admin pulls and confirms: the removal completes —
        // the internal precheck re-validation must NOT re-enter the
        // gate, and the offboarding rotation must run ungated.
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        joiner.member_remove(&[extra_id]).expect("removal confirms");
        assert!(joiner.pending_op_approvals().is_empty());
        let extra_row = crate::vault::members::member_file_by_id(&joiner_path, extra_id).unwrap();
        assert!(extra_row.removed.is_some(), "target tombstoned");
    }

    // ── §13: owner recovery — ownership_claim + owner-targeted reset ──

    /// Default threshold (1): an admin claims ownership in one step —
    /// the family path. Roles swap between EXISTING rows, the demoted
    /// owner stays an admin, and the event log records the claim. The
    /// demoted owner (now admin) can then reset the new owner's row;
    /// the successor inherits the Owner role so the owner rejoins as
    /// self. The new owner cannot claim (only admins) nor self-reset.
    #[test]
    fn admin_claims_ownership_and_owner_reset_rejoins() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.contacts_import_intro(&intro_code).unwrap();
        let contacts = handle.contacts_list().unwrap();
        let joiner_card = contacts
            .iter()
            .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
            .expect("imported joiner card");
        handle
            .contacts_mark_verified(&joiner_card.card.identity_signing_pubkey)
            .unwrap();
        let joiner_member_id = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve").unwrap();

        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();

        let old_owner_member_id = crate::vault::members::owner_member_id(&owner_path).unwrap();
        joiner
            .ownership_claim(joiner_member_id)
            .expect("threshold-1 claim executes");

        // The swap mutated the JOINER's clone; ship it back so the
        // owner's disk carries the new roles (a role swap does not
        // rotate keys, so no re-unlock is needed).
        let joiner_device = joiner.device_id;
        let joiner_seal = joiner.devkey_seal();
        let engine_js = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        let repo_js = engine_js.open_repo().unwrap();
        engine_js.commit_all(&repo_js, "claim").unwrap();
        drop(repo_js);
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();

        assert_eq!(
            crate::vault::members::owner_member_id(&owner_path),
            Some(joiner_member_id),
            "claimant owns the vault"
        );
        let old_row =
            crate::vault::members::member_file_by_id(&owner_path, old_owner_member_id).unwrap();
        assert_eq!(old_row.role, crate::vault::members::MemberRole::Admin);
        assert!(joiner.pending_op_approvals().is_empty());
        assert_eq!(
            joiner.share_events(50).unwrap().last().unwrap().kind,
            crate::vault::events::ShareEventKind::OwnershipClaimed
        );

        // The new owner is not an admin: cannot claim (no-op for them).
        let err = joiner
            .ownership_claim(joiner_member_id)
            .expect_err("owner cannot claim");
        assert!(err.to_string().contains("only an admin"), "{err}");

        // The demoted owner (now admin) resets the new owner's row; the
        // successor inherits the Owner role, so the owner rejoins as self.
        let (successor_id, _reset_code) = handle
            .member_reset(joiner_member_id)
            .expect("admin resets an owner row per the family path");
        let successor =
            crate::vault::members::member_file_by_id(&owner_path, successor_id).unwrap();
        assert_eq!(successor.role, crate::vault::members::MemberRole::Owner);

        // The self-reset guard survives the owner-target lift.
        let joiner_member =
            crate::vault::members::member_id_for_device(&joiner_path, joiner.device_id);
        assert_eq!(joiner_member, Some(joiner_member_id));
        assert!(joiner.member_reset(joiner_member_id).is_err(), "self-reset");
    }

    /// Threshold 2: the claim becomes a two-admin ask. The ask binds
    /// BOTH member ids (a changed owner means a different digest, so a
    /// stale ask can never execute against a new owner), the owner
    /// cannot co-approve (not an admin — the one-admin stall is real
    /// and surfaced), and the second admin's confirming call executes
    /// the swap on their clone.
    #[test]
    fn ownership_claim_threshold_two_needs_distinct_admins() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Two admin joiners through the standard ceremony (Admin needs a
        // Verified contact); the threshold rises before any pull.
        let mut joiner_dirs = Vec::new();
        let mut joiner_members = Vec::new();
        for i in 0..2 {
            let code = handle
                .invite_create(crate::vault::members::MemberRole::Admin, None)
                .unwrap();
            engine_o.commit_all(&repo_o, "invite").unwrap();
            let joiner_path = temp.path().join(format!("joiner{i}")).into_boxed_path();
            git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
            let intro_code = crate::vault::members::create_introduction(
                &joiner_path,
                &code,
                "member-pass",
                &format!("MemberDevice{i}"),
            )
            .unwrap();
            handle.contacts_import_intro(&intro_code).unwrap();
            let contacts = handle.contacts_list().unwrap();
            let card = contacts
                .iter()
                .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
                .expect("imported joiner card");
            handle
                .contacts_mark_verified(&card.card.identity_signing_pubkey)
                .unwrap();
            joiner_members.push(handle.approve_join(&intro_code).unwrap());
            engine_o.commit_all(&repo_o, "approve").unwrap();
            joiner_dirs.push(joiner_path);
        }
        let mut settings = handle.get_settings().unwrap();
        settings.quorum_admin_ops = Some(2);
        handle.save_settings(&settings).unwrap();
        engine_o.commit_all(&repo_o, "quorum").unwrap();

        let mut joiner_handles = Vec::new();
        let mut joiner_engines = Vec::new();
        for (i, path) in joiner_dirs.iter().enumerate() {
            let engine = crate::sync::engine::SyncEngine::new(path, "pull-only", None);
            let repo = engine.open_repo().unwrap();
            engine.pull(&repo, "origin").unwrap();
            drop(repo);
            let mut h = VaultHandle::open(path).unwrap();
            h.unlock("member-pass").unwrap();
            assert_eq!(h.get_settings().unwrap().quorum_admin_ops, Some(2));
            let seal = h.devkey_seal();
            let device = h.device_id;
            joiner_engines.push(crate::sync::engine::SyncEngine::new(
                path,
                &device.to_string(),
                seal.as_ref(),
            ));
            joiner_handles.push(h);
            let _ = i;
        }
        let admin1 = joiner_handles.first_mut().expect("admin1");

        // Ask: refused solo, record on file at the live bar.
        let err = admin1
            .ownership_claim(joiner_members[0])
            .expect_err("solo claim must wait for quorum");
        assert!(err.to_string().contains("admin approvals"), "{err}");
        let pending = admin1.pending_op_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, "ownership_claim");
        assert_eq!(pending[0].required, 2);
        let err = admin1
            .ownership_claim(joiner_members[0])
            .expect_err("self-confirm");
        assert!(err.to_string().contains("different admin"), "{err}");

        // The owner is not an admin: cannot co-approve a claim. With a
        // single admin this vault would stall — the UI surfaces the
        // pending ask; the doctrine answers with "raise admins first".
        let err = handle
            .ownership_claim(joiner_members[0])
            .expect_err("owner cannot approve");
        assert!(err.to_string().contains("only an admin"), "{err}");

        // The digest binds BOTH ids: a changed owner is a different ask.
        let old_owner = crate::vault::members::owner_member_id(&owner_path).unwrap();
        let d_real = crate::vault::approvals::op_digest(
            "ownership_claim",
            &serde_json::json!({"new_owner_id": joiner_members[0], "old_owner_id": old_owner}),
        );
        let d_other = crate::vault::approvals::op_digest(
            "ownership_claim",
            &serde_json::json!({"new_owner_id": joiner_members[0], "old_owner_id": uuid::Uuid::new_v4()}),
        );
        assert_ne!(d_real, d_other, "stale asks cannot match a new owner");

        // Ship the ask: joiner1 commits, the owner pulls it in, and the
        // second admin fetches it from origin before confirming.
        let repo1 = joiner_engines[0].open_repo().unwrap();
        joiner_engines[0].commit_all(&repo1, "pending ask").unwrap();
        drop(repo1);
        repo_o
            .remote("joiner1", joiner_dirs[0].to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner1").unwrap();
        let repo2 = joiner_engines[1].open_repo().unwrap();
        joiner_engines[1].pull(&repo2, "origin").unwrap();
        drop(repo2);

        joiner_handles[1]
            .ownership_claim(joiner_members[0])
            .expect("second admin confirms the SAME ask");
        assert!(joiner_handles[1].pending_op_approvals().is_empty());
        // The ask names the CLAIMANT: the confirming admin executes
        // admin1's takeover, not their own.
        assert_eq!(
            crate::vault::members::owner_member_id(&joiner_dirs[1]),
            Some(joiner_members[0]),
            "the claimant owns the vault"
        );
        let old_row = crate::vault::members::member_file_by_id(&joiner_dirs[1], old_owner).unwrap();
        assert_eq!(old_row.role, crate::vault::members::MemberRole::Admin);
    }

    /// Threshold-2 transfer twin (review F4): only the OWNER initiates a
    /// voluntary transfer, but an ADMIN completes it — the house
    /// re-call-to-confirm pattern. Without the confirmer path the ask
    /// could never reach quorum (the owner self-confirm is refused and
    /// no second owner exists).
    #[test]
    fn transfer_threshold_two_admin_confirms_owner_ask() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // One admin joiner through the standard ceremony (Admin needs a
        // Verified contact); the threshold rises before the pull.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.contacts_import_intro(&intro_code).unwrap();
        let contacts = handle.contacts_list().unwrap();
        let card = contacts
            .iter()
            .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
            .expect("imported joiner card");
        handle
            .contacts_mark_verified(&card.card.identity_signing_pubkey)
            .unwrap();
        let admin1_member = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve").unwrap();
        let mut settings = handle.get_settings().unwrap();
        settings.quorum_admin_ops = Some(2);
        handle.save_settings(&settings).unwrap();
        engine_o.commit_all(&repo_o, "quorum").unwrap();

        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "pull-only", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut admin1 = VaultHandle::open(&joiner_path).unwrap();
        admin1.unlock("member-pass").unwrap();
        assert_eq!(admin1.get_settings().unwrap().quorum_admin_ops, Some(2));

        // An admin cannot START a voluntary transfer — the consent is
        // the owner's call.
        let err = admin1
            .transfer_ownership(admin1_member)
            .expect_err("admin cannot initiate");
        assert!(err.to_string().contains("no pending"), "{err}");

        // The transfer target: a planted third-party row, so the
        // admin actor stays intact for the confirm legs.
        let editor_id = uuid::Uuid::new_v4();
        let editor_json = serde_json::json!({
            "id": editor_id,
            "display_name": "Successor",
            "role": "editor",
            "trust": "channel",
        });
        std::fs::write(
            owner_path
                .join("meta/members")
                .join(format!("{editor_id}.json")),
            editor_json.to_string(),
        )
        .unwrap();

        // The owner initiates: at threshold 2 this records a pending ask
        // (the owner's own approval is one of the required two).
        handle
            .transfer_ownership(editor_id)
            .expect_err("ask waits for quorum");
        let pending = handle.pending_op_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, "transfer_ownership");
        assert_eq!(pending[0].required, 2);

        // F3: the ask's digest binds the owner of record — a swapped
        // owner makes the ask unmatchable, like the claim's rule.
        let owner_member = crate::vault::members::owner_member_id(&owner_path).unwrap();
        let d_bind = crate::vault::approvals::op_digest(
            "transfer_ownership",
            &serde_json::json!({"new_member_id": editor_id, "old_owner_id": owner_member}),
        );
        let d_swap = crate::vault::approvals::op_digest(
            "transfer_ownership",
            &serde_json::json!({"new_member_id": editor_id, "old_owner_id": uuid::Uuid::new_v4()}),
        );
        assert_ne!(d_bind, d_swap, "a stale ask cannot match a new owner");

        // F4: a fresh ask supersedes the owner's earlier transfer asks
        // (a new target invalidates the old one).
        let second_id = uuid::Uuid::new_v4();
        let second_json = serde_json::json!({
            "id": second_id,
            "display_name": "Third",
            "role": "editor",
            "trust": "channel",
        });
        std::fs::write(
            owner_path
                .join("meta/members")
                .join(format!("{second_id}.json")),
            second_json.to_string(),
        )
        .unwrap();
        handle
            .transfer_ownership(second_id)
            .expect_err("second ask waits for quorum");
        let pending = handle.pending_op_approvals();
        assert_eq!(pending.len(), 1, "the second ask superseded the first");
        assert_eq!(
            pending[0].params.as_ref().unwrap()["new_member_id"].as_str(),
            Some(second_id.to_string().as_str()),
        );
        handle
            .transfer_ownership(editor_id)
            .expect_err("re-ask waits for quorum");
        let pending = handle.pending_op_approvals();
        assert_eq!(pending.len(), 1, "the re-ask superseded the second ask");
        assert_eq!(
            pending[0].params.as_ref().unwrap()["new_member_id"].as_str(),
            Some(editor_id.to_string().as_str()),
        );

        // Ship the ask, then the admin's confirming call executes the
        // swap on their clone.
        engine_o.commit_all(&repo_o, "transfer ask").unwrap();
        let repo_j2 = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j2, "origin").unwrap();
        drop(repo_j2);

        // F2: a dead target refuses BEFORE the gate — the ask is not
        // consumed and no co-approval burns on it. The target row is
        // corrupted on the CONFIRMING device only.
        let row_path = joiner_path
            .join("meta/members")
            .join(format!("{editor_id}.json"));
        let row_bytes = std::fs::read(&row_path).unwrap();
        std::fs::write(&row_path, "not json").unwrap();
        let err = admin1
            .transfer_ownership(editor_id)
            .expect_err("dead target refuses");
        assert!(err.to_string().contains("does not exist"), "{err}");
        assert_eq!(
            admin1.pending_op_approvals().len(),
            1,
            "the ask survives a dead-target refusal"
        );
        std::fs::write(&row_path, row_bytes).unwrap();

        admin1
            .transfer_ownership(editor_id)
            .expect("admin confirms the owner's ask");
        assert!(admin1.pending_op_approvals().is_empty());
        assert_eq!(
            crate::vault::members::owner_member_id(&joiner_path),
            Some(editor_id),
            "the successor owns the vault"
        );
    }

    /// F10: deterministic transfer refusals precede the quorum gate —
    /// a self-transfer and a bogus target fail outright and record no
    /// pending ask (a doomed ask would burn a co-approval). Runs at
    /// threshold 2 so a recorded ask would be visible: under the old
    /// gate-first ordering both refusals stranded a PendingOp.
    #[test]
    fn transfer_deterministic_refusals_record_no_pending_ask() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let mut settings = handle.get_settings().unwrap();
        settings.quorum_admin_ops = Some(2);
        handle.save_settings(&settings).unwrap();
        let owner_id = crate::vault::members::owner_member_id(dir.path()).unwrap();

        // Self-transfer refuses before the gate.
        let err = handle.transfer_ownership(owner_id).unwrap_err().to_string();
        assert!(err.contains("you already own"), "err: {err}");
        // A bogus target refuses before the gate.
        let err = handle
            .transfer_ownership(uuid::Uuid::new_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "err: {err}");
        assert!(handle.pending_op_approvals().is_empty());
    }

    /// A hand-written approvals record cannot forge a second yes: the
    /// gate counts only entries whose signature verifies against the
    /// member row's identity key, and the record self-heals on touch.
    #[test]
    fn forged_approval_record_never_executes() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let mut settings = handle.get_settings().unwrap();
        settings.quorum_admin_ops = Some(2);
        handle.save_settings(&settings).unwrap();
        let owner_id = crate::vault::members::owner_member_id(dir.path()).unwrap();

        // Hand-written record: the owner's member id with a garbage
        // signature, format 2 so it parses.
        let digest = crate::vault::approvals::op_digest("rotate_root_key", &serde_json::json!({}));
        let forged = serde_json::json!({
            "format": 2,
            "kind": "rotate_root_key",
            "params_digest": digest,
            "initiated_by": owner_id,
            "initiated_at": 1,
            "required": 2,
            "approvals": [{"member": owner_id, "sig": "00"}],
            "params": {},
        });
        let rec = dir.path().join("meta/approvals").join(format!(
            "{}-{}.json",
            digest,
            &owner_id.simple().to_string()[..8]
        ));
        std::fs::create_dir_all(rec.parent().unwrap()).unwrap();
        std::fs::write(&rec, forged.to_string()).unwrap();

        // The owner's REAL call counts only its own signed entry: the
        // forged one drops, the ask stays pending, and the record
        // self-heals to the real signature.
        let err = handle.rotate_root_key().unwrap_err().to_string();
        assert!(err.contains("admin approvals"), "{err}");
        let pending = handle.pending_op_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].approvals.len(), 1);
        assert_ne!(pending[0].approvals[0].sig, "00");
    }

    #[test]
    fn team_shape_flip_two_devices() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Owner row carries the identity wrap pubkey (deterministic in
        // the keystore-less test environment).
        let owner_member =
            crate::vault::members::member_id_for_device(&owner_path, handle.device_id).unwrap();
        let mut owner_row =
            crate::vault::members::member_file_by_id(&owner_path, owner_member).unwrap();
        let card = handle.contact_card_signed().unwrap();
        owner_row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(&owner_path, &owner_row).unwrap();

        // Standard join ceremony: one Editor member.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // Joiner pulls, unlocks (pre-flip: Root Key path), and the admin
        // prepares the SMK. Ship the wrap + prepare state to the joiner.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert!(joiner.unlocked().holds_root(), "pre-flip member holds root");
        let joiner_device = joiner.device_id;
        drop(repo_j);
        drop(joiner);

        let prep = handle.space_prepare().unwrap();
        assert!(prep.smk_fresh);
        // Plant an avatar so the flip converges it into the
        // member-visible domain (files_reencrypted 5 -> 6).
        let mut prof = handle.load_profile().unwrap();
        prof.avatar_ext = Some("png".into());
        handle.save_profile(&prof).unwrap();
        let avatar_plain = b"fake-png-image-bytes".to_vec();
        let avatar_blob = crate::vault::avatar::encrypt_avatar(
            &zeroize::Zeroizing::new(handle.derive_avatar_key().unwrap()),
            &avatar_plain,
        )
        .unwrap();
        crate::vault::write_vault_file(&owner_path.join("meta/avatar.enc"), &avatar_blob).unwrap();
        engine_o.commit_all(&repo_o, "prepare").unwrap();
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);

        // Flip. The joiner's device keywrap must leave the vault.
        let joiner_kw = owner_path.join(format!("meta/keywrap/{joiner_device}.json"));
        assert!(joiner_kw.exists());
        let report = handle.space_flip().unwrap();
        assert!(!report.already_flipped);
        assert_eq!(report.files_reencrypted, 6);
        assert_eq!(report.keywraps_removed, 1);
        assert!(!joiner_kw.exists());
        assert!(crate::vault::space_meta::shape_flipped(&owner_path));
        // Idempotent re-run.
        let again = handle.space_flip().unwrap();
        assert!(again.already_flipped);

        // Admin: same meta keys via the sealed store; folders readable.
        assert!(handle.unlocked().holds_root());
        assert!(handle.unlocked().smk.is_some());
        assert!(handle.list_folders().is_ok());
        assert!(handle.get_settings().is_ok());
        engine_o.commit_all(&repo_o, "flip").unwrap();

        // Joiner pulls the flip and unlocks on the member path: no Root
        // Key, SMK in hand, meta readable.
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert!(
            !joiner.unlocked().holds_root(),
            "post-flip member holds no root"
        );
        assert!(joiner.unlocked().space_group_key.is_none());
        assert!(joiner.unlocked().smk.is_some());
        assert!(joiner.list_folders().is_ok());
        assert!(joiner.get_settings().is_ok());
        // The avatar rode the flip into the member-visible domain: a
        // rootless member device decrypts it with the SMK-derived key.
        let avatar_stored = std::fs::read(joiner_path.join("meta/avatar.enc")).unwrap();
        assert_eq!(
            joiner.decrypt_avatar_blob(&avatar_stored).unwrap(),
            avatar_plain
        );
        // Admin-only surfaces refuse cleanly on the member device.
        assert!(joiner.rotate_root_key().is_err());
        assert!(joiner.space_prepare().is_err());
        drop(joiner);

        // Post-flip rotation: the Root Key leaves to admins only, and the
        // SMK (plus every member's access) rides through unchanged.
        let smk_before =
            crate::vault::space_meta::open_store(&owner_path, handle.unlocked().root().unwrap())
                .unwrap();
        handle.rotate_root_key().unwrap();
        assert!(
            !joiner_kw.exists(),
            "rotation must not re-arm member keywraps"
        );
        let new_root = RootKey::from_bytes(
            handle_root_key_for_test(&handle)
                .try_into()
                .expect("root 64 bytes"),
        );
        let smk_after = crate::vault::space_meta::open_store(&owner_path, &new_root).unwrap();
        assert_eq!(*smk_after, *smk_before);
        assert!(handle.list_folders().is_ok());
        engine_o.commit_all(&repo_o, "post-flip rotation").unwrap();

        // Joiner pulls the rotation and still unlocks (rootless).
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert!(!joiner.unlocked().holds_root());
        assert!(joiner.list_folders().is_ok());
        // Review F2: the activity log survives the post-flip rotation on
        // the rotating device (read under the SMK derivation) and reads
        // clean (empty but valid) on the member.
        assert!(!handle.share_events(50).unwrap().is_empty());
        assert!(joiner.share_events(50).unwrap().is_empty());
        drop(joiner);

        // Review F1: a SECOND join ceremony on the flipped vault — the
        // approval ships no Root Key keywrap, yet join_status must
        // report approved and the new member must unlock.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Viewer, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite 2").unwrap();
        let joiner2_path = temp.path().join("joiner2");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner2_path).unwrap();
        let intro2 = crate::vault::members::create_introduction(
            &joiner2_path,
            &code,
            "member2-pass",
            "MemberDevice2",
        )
        .unwrap();
        handle.approve_join(&intro2).unwrap();
        engine_o.commit_all(&repo_o, "approve join 2").unwrap();
        let engine_j2 = crate::sync::engine::SyncEngine::new(&joiner2_path, "joiner2", None);
        let repo_j2 = engine_j2.open_repo().unwrap();
        engine_j2.pull(&repo_j2, "origin").unwrap();
        let (introduced, approved) = crate::vault::members::join_status(&joiner2_path);
        assert!(introduced);
        assert!(
            approved,
            "flipped-vault approval must not wait for a keywrap"
        );
        let mut joiner2 = VaultHandle::open(&joiner2_path).unwrap();
        joiner2.unlock("member2-pass").unwrap();
        assert!(!joiner2.unlocked().holds_root());
        assert!(joiner2.unlocked().smk.is_some());
    }

    // F9 (general-pass review): an ADMIN invited after the flip must get
    // the Root Key keywrap and take the admin unlock path — a second
    // admin with no admin keys cannot run a growing Space. The flip's
    // property is role-scoped: members hold nothing, admins keep keys.
    // Rotation already staged wraps for admin-mapped devices; this pins
    // invite + unlock to the same rule, and pins members still rootless.
    #[test]
    fn admin_invitee_post_flip_holds_full_powers() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Owner row carries the identity wrap pubkey (flip readiness).
        let owner_member =
            crate::vault::members::member_id_for_device(&owner_path, handle.device_id).unwrap();
        let mut owner_row =
            crate::vault::members::member_file_by_id(&owner_path, owner_member).unwrap();
        let card = handle.contact_card_signed().unwrap();
        owner_row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(&owner_path, &owner_row).unwrap();

        handle.space_prepare().unwrap();
        handle.space_flip().unwrap();

        // Invite an ADMIN on the flipped vault.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite admin").unwrap();

        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "admin2-pass",
            "Admin2Device",
        )
        .unwrap();

        // Before the approval commit is pulled the joiner has a member
        // unlock file but no binding and no keywrap: unlock refuses.
        {
            let mut probe = VaultHandle::open(&joiner_path).unwrap();
            assert!(probe.unlock("admin2-pass").is_err());
        }

        // Elevated approval needs a Verified contact.
        handle.contacts_import_intro(&intro_code).unwrap();
        let unverified = handle
            .contacts_list()
            .unwrap()
            .into_iter()
            .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
            .map(|c| c.card.identity_signing_pubkey)
            .unwrap();
        handle.contacts_mark_verified(&unverified).unwrap();
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve admin join").unwrap();

        // The approval commit carries the keywrap: the joiner takes the
        // ADMIN path with their own password and holds full powers.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("admin2-pass").unwrap();
        assert!(
            joiner.unlocked().holds_root(),
            "post-flip admin invitee must hold the Root Key"
        );
        assert!(joiner.unlocked().smk.is_some());
        // Full powers: collection creation needs can-manage + the SGK.
        // The admin commits it like a real device (signed engine) so the
        // Space converges before the rotation leg.
        let cid = joiner.collection_create("Admin-made").unwrap();
        let joiner_seal = joiner.devkey_seal();
        let engine_j_signed = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner.device_id.to_string(),
            joiner_seal.as_ref(),
        );
        let repo_j_signed = engine_j_signed.open_repo().unwrap();
        engine_j_signed
            .commit_all(&repo_j_signed, "add collection")
            .unwrap();
        drop(joiner);

        // The owner pulls the second admin's collection, THEN rotates:
        // the rotation re-keys the collection, so it survives with its
        // content key intact.
        let repo_o = {
            let repo = engine_o.open_repo().unwrap();
            if repo.find_remote("joiner").is_err() {
                repo.remote("joiner", joiner_path.to_str().unwrap())
                    .unwrap();
            }
            repo
        };
        engine_o.pull(&repo_o, "joiner").unwrap();

        // Rotation: rotation stages keywraps for admin-mapped devices, so
        // the second admin survives it.
        handle.rotate_root_key().unwrap();
        engine_o.commit_all(&repo_o, "rotate").unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("admin2-pass").unwrap();
        assert!(joiner.unlocked().holds_root(), "admin survives rotation");
        // Meta reads work under the new epoch: the collection they made
        // is still listed by name.
        assert!(
            joiner
                .collections_list()
                .unwrap()
                .iter()
                .any(|c| c.0 == cid)
        );
        drop(joiner);

        // An EDITOR invited on the same flipped vault (after rotation)
        // still takes the member path: rootless, member-only powers.
        let code2 = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite editor").unwrap();
        let joiner3_path = temp.path().join("joiner3");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner3_path).unwrap();
        let intro3 = crate::vault::members::create_introduction(
            &joiner3_path,
            &code2,
            "editor-pass",
            "EditorDevice",
        )
        .unwrap();
        handle.approve_join(&intro3).unwrap();
        engine_o.commit_all(&repo_o, "approve editor").unwrap();
        let engine_j3 = crate::sync::engine::SyncEngine::new(&joiner3_path, "joiner3", None);
        let repo_j3 = engine_j3.open_repo().unwrap();
        engine_j3.pull(&repo_j3, "origin").unwrap();
        let mut editor = VaultHandle::open(&joiner3_path).unwrap();
        editor.unlock("editor-pass").unwrap();
        assert!(!editor.unlocked().holds_root());
        assert!(editor.unlocked().smk.is_some());
    }

    // Review Blocker on the F9 commit: a RESET admin's old device must
    // stay locked out on a flipped vault. Reset tombstones the row but
    // deliberately keeps its role field and never rotates, so the admin
    // mapping had to become tombstone-aware — otherwise the old device
    // rode the new admin unlock path with its still-valid keywrap.
    #[test]
    fn reset_locks_out_elevated_member_on_flipped_vault() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        let owner_member =
            crate::vault::members::member_id_for_device(&owner_path, handle.device_id).unwrap();
        let mut owner_row =
            crate::vault::members::member_file_by_id(&owner_path, owner_member).unwrap();
        let card = handle.contact_card_signed().unwrap();
        owner_row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(&owner_path, &owner_row).unwrap();

        handle.space_prepare().unwrap();
        handle.space_flip().unwrap();

        // Admin joiner ceremony (verified contact required for the role).
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite admin").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "admin2-pass",
            "Admin2Device",
        )
        .unwrap();
        handle.contacts_import_intro(&intro_code).unwrap();
        let unverified = handle
            .contacts_list()
            .unwrap()
            .into_iter()
            .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
            .map(|c| c.card.identity_signing_pubkey)
            .unwrap();
        handle.contacts_mark_verified(&unverified).unwrap();
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve admin join").unwrap();
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("admin2-pass").unwrap();
        assert!(joiner.unlocked().holds_root());
        let joiner_device = joiner.device_id;
        drop(joiner);

        // The owner resets the admin's row (suspected device, say). The
        // row tombstones; the role field stays; the keywrap file stays;
        // the Root Key is deliberately not rotated.
        let admin_member =
            crate::vault::members::member_id_for_device(&owner_path, joiner_device).unwrap();
        handle.member_reset(admin_member).unwrap();
        engine_o.commit_all(&repo_o, "reset admin").unwrap();

        // The old device pulls the tombstone and must NOT unlock: the
        // admin mapping is dead, and the member tail's space.wrap was
        // removed by the reset.
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        assert!(
            joiner.unlock("admin2-pass").is_err(),
            "a reset admin's old device must stay locked out"
        );
    }

    // Debt: threshold-2 rotation was only exercised on unflipped
    // vaults. This pins the combination: the ask needs a second admin,
    // the confirming rotation runs on the confirming device, both
    // admins converge onto the new root, and the SMK is untouched
    // (rotation-invariant), so members keep their wraps.
    #[test]
    fn quorum_rotation_on_flipped_vault_two_admins() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Flip readiness, then flip: members hold nothing, admins keep
        // keys.
        let owner_member =
            crate::vault::members::member_id_for_device(&owner_path, handle.device_id).unwrap();
        let mut owner_row =
            crate::vault::members::member_file_by_id(&owner_path, owner_member).unwrap();
        let card = handle.contact_card_signed().unwrap();
        owner_row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(&owner_path, &owner_row).unwrap();
        handle.space_prepare().unwrap();
        handle.space_flip().unwrap();

        // Second admin through the standard verified-contact ceremony.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite admin").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "admin2-pass",
            "Admin2Device",
        )
        .unwrap();
        handle.contacts_import_intro(&intro_code).unwrap();
        let unverified = handle
            .contacts_list()
            .unwrap()
            .into_iter()
            .find(|c| c.trust == crate::vault::contacts::ContactTrust::Channel)
            .map(|c| c.card.identity_signing_pubkey)
            .unwrap();
        handle.contacts_mark_verified(&unverified).unwrap();
        handle.approve_join(&intro_code).unwrap();
        // Raise the threshold BEFORE the joiner's first pull so both
        // devices read the same setting from disk.
        let mut settings = handle.get_settings().unwrap();
        settings.quorum_admin_ops = Some(2);
        handle.save_settings(&settings).unwrap();
        engine_o.commit_all(&repo_o, "approve + quorum").unwrap();

        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("admin2-pass").unwrap();
        assert!(
            joiner.unlocked().holds_root(),
            "admin invitee holds the root"
        );
        let joiner_seal = joiner.devkey_seal();
        let joiner_device = joiner.device_id;

        let pre_rotation_root = RootKey::from_bytes(
            handle_root_key_for_test(&handle)
                .try_into()
                .expect("root 64 bytes"),
        );
        let pre_root_bytes = handle_root_key_for_test(&handle);
        let smk_before =
            crate::vault::space_meta::open_store(&owner_path, &pre_rotation_root).unwrap();

        // Owner raises the ask; a solo rotation must not run.
        let err = handle
            .rotate_root_key()
            .expect_err("solo rotation must wait for quorum");
        assert!(err.to_string().contains("admin approvals"), "{err}");
        let pending = handle.pending_op_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, "rotate_root_key");
        assert_eq!(pending[0].required, 2);

        // Ship the ask; the second admin's confirming call runs the
        // rotation on THEIR clone.
        engine_o.commit_all(&repo_o, "pending ask").unwrap();
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        joiner.rotate_root_key().expect("second admin confirms");
        assert!(joiner.pending_op_approvals().is_empty());
        let joiner_root_bytes = handle_root_key_for_test(&joiner);
        let new_root =
            RootKey::from_bytes(joiner_root_bytes.clone().try_into().expect("root 64 bytes"));
        assert_ne!(joiner_root_bytes, pre_root_bytes);
        // The SMK is rotation-invariant: same bytes under the new root.
        let smk_after = crate::vault::space_meta::open_store(&joiner_path, &new_root).unwrap();
        assert_eq!(*smk_after, *smk_before);

        // Converge: the rotation ships back, the owner re-unlocks and
        // adopts the new root through the P3 rekey wrap.
        let engine_js = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        let repo_js = engine_js.open_repo().unwrap();
        engine_js.commit_all(&repo_js, "joiner rotation").unwrap();
        drop(repo_js);
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        drop(handle);
        let mut handle = VaultHandle::open(&owner_path).unwrap();
        handle.unlock("owner-pass").unwrap();
        assert!(handle.unlocked().holds_root());
        let new_root_bytes = handle_root_key_for_test(&handle);
        assert_eq!(new_root_bytes, joiner_root_bytes);
        assert!(handle.pending_op_approvals().is_empty());
        // The old root no longer opens the resealed store.
        assert!(crate::vault::space_meta::open_store(&owner_path, &pre_rotation_root).is_err());
    }

    // S3-7b review F6: a live non-admin row with NO wrap pubkey but a
    // stale space.wrap file on disk must be BLOCKED by the flip gate —
    // the wrap file alone is not readiness.
    #[test]
    fn flip_refuses_member_with_stale_wrap_and_no_pubkey() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        handle.space_prepare().unwrap();

        // Hostile/stale row: Editor, no wrap pubkey, but a wrap FILE.
        let m = crate::vault::members::MemberFile {
            id: uuid::Uuid::new_v4(),
            display_name: "Stale".into(),
            email: None,
            role: crate::vault::members::MemberRole::Editor,
            trust: crate::vault::members::TrustLevel::Verified,
            identity_signing_pubkey: Some(hex::encode([1u8; 32])),
            identity_signing_pubkey_previous: None,
            identity_rotation_signature: None,
            identity_rotated_at: None,
            reset: None,
            removed: None,
            transport_username: None,
            identity_wrap_pubkey: None,
        };
        crate::vault::members::write_member(&owner_path, &m).unwrap();
        let wrap_file = owner_path
            .join("meta/members")
            .join(m.id.to_string())
            .join("space.wrap");
        std::fs::create_dir_all(wrap_file.parent().unwrap()).unwrap();
        std::fs::write(&wrap_file, b"stale").unwrap();

        let err = handle.space_flip().unwrap_err();
        assert!(
            err.to_string().contains(&m.id.to_string()),
            "flip must name the blocked member: {err}"
        );
        assert!(!crate::vault::space_meta::shape_flipped(&owner_path));
    }

    /// S3-7c wave centerpiece: after the flip, a granted member reads and
    /// P5 explicit staged path sets, the wedge-class regression: a
    /// member device with a stray dirty write to a git-tracked Admin-row
    /// file commits WITHOUT it (the filter leaves it unstaged), so the
    /// owner's pull of the member's legit change succeeds. Pre-filter,
    /// add_all swept the stray file into the commit and every peer's
    /// pull refused it — the unpushable-commit wedge.
    #[test]
    fn staged_path_set_filters_unwritable_member_writes() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        let probe = VaultHandle::open(&joiner_path).unwrap();
        let joiner_device = probe.device_id;
        drop(probe);
        let engine_j =
            crate::sync::engine::SyncEngine::new(&joiner_path, &joiner_device.to_string(), None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);

        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        let joiner_seal = joiner.devkey_seal();
        let joiner_member =
            crate::vault::members::member_id_for_device(&joiner_path, joiner_device).unwrap();
        drop(joiner);

        // The stray write: a git-tracked Admin-row file this Editor may
        // never author.
        let stray = joiner_path.join("meta/epoch.json");
        assert!(stray.exists(), "epoch.json must exist in the clone");
        let stray_original = std::fs::read(&stray).unwrap();
        std::fs::write(&stray, b"stray-member-write").unwrap();

        // The legitimate write: the member's own subtree (any-role row).
        let own_dir = joiner_path
            .join("meta/members")
            .join(joiner_member.to_string());
        std::fs::create_dir_all(&own_dir).unwrap();
        let probe_file = own_dir.join("probe.enc");
        std::fs::write(&probe_file, b"member-authored").unwrap();

        let engine_j = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        let repo_j = engine_j.open_repo().unwrap();
        let before = repo_j.head().unwrap().peel_to_commit().unwrap();
        let stray_before = before
            .tree()
            .unwrap()
            .get_path(std::path::Path::new("meta/epoch.json"))
            .unwrap()
            .id();
        let before_id = before.id();
        drop(before);
        engine_j.commit_all(&repo_j, "member change").unwrap();
        let after = repo_j.head().unwrap().peel_to_commit().unwrap();
        assert_ne!(before_id, after.id(), "the member commit must land");
        let tree_after = after.tree().unwrap();
        let stray_after = tree_after
            .get_path(std::path::Path::new("meta/epoch.json"))
            .unwrap()
            .id();
        let members_in_tree = tree_after
            .get_path(std::path::Path::new("meta/members"))
            .is_ok();
        drop(tree_after);
        drop(after);
        // The stray rewrite stayed out of the commit: epoch.json still
        // carries its pre-stray blob, the probe rides.
        assert_eq!(
            stray_after, stray_before,
            "the stray epoch.json rewrite must not ride the commit"
        );
        assert!(members_in_tree);
        // Review F4 hygiene: the skipped stray is REVERTED in the
        // worktree, not left dirty — a permanently-dirty file would
        // wedge the sync badge and push an empty commit on every
        // autosync tick.
        let stray_now = std::fs::read(&stray).unwrap();
        assert_eq!(
            stray_now, stray_original,
            "the skipped stray must be reverted to its committed content"
        );
        drop(repo_j);

        // The owner's pull SUCCEEDS — pre-filter this refused with a
        // PolicyViolation on meta/epoch.json.
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        assert!(
            owner_path
                .join("meta/members")
                .join(joiner_member.to_string())
                .join("probe.enc")
                .exists()
        );
        let owner_epoch = std::fs::read(owner_path.join("meta/epoch.json")).unwrap();
        assert_ne!(owner_epoch, b"stray-member-write");

        // Idempotence: the next member commit skips the stray again.
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.commit_all(&repo_j, "second change").unwrap();
        let tree = repo_j
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree()
            .unwrap();
        assert_eq!(
            tree.get_path(std::path::Path::new("meta/epoch.json"))
                .unwrap()
                .id(),
            stray_before,
        );
    }

    /// The S3-7c member-access ceremony: a flipped joiner (no Root Key,
    /// no SGK) reads and writes collection ciphers via grant wraps,
    /// personal-flat ciphers stay invisible, trash/restore is
    /// same-domain, and root rotation keeps member access alive.
    #[test]
    fn member_collection_access_two_devices() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        let owner_member =
            crate::vault::members::member_id_for_device(&owner_path, handle.device_id).unwrap();
        let mut owner_row =
            crate::vault::members::member_file_by_id(&owner_path, owner_member).unwrap();
        let card = handle.contact_card_signed().unwrap();
        owner_row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(&owner_path, &owner_row).unwrap();

        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // The joiner engine signs with the joiner's device id (the commit
        // signer string drives the member-of lookup at verification). Pull
        // the approval first: the device identity comes from the clone.
        let probe = VaultHandle::open(&joiner_path).unwrap();
        let joiner_device = probe.device_id;
        drop(probe);
        let engine_j =
            crate::sync::engine::SyncEngine::new(&joiner_path, &joiner_device.to_string(), None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);

        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        let joiner_seal = joiner.devkey_seal();
        drop(joiner);
        let engine_j = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);

        // Prepare + flip: the joiner becomes rootless.
        handle.space_prepare().unwrap();
        engine_o.commit_all(&repo_o, "prepare").unwrap();
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        handle.space_flip().unwrap();
        engine_o.commit_all(&repo_o, "flip").unwrap();

        let mk_login = |name: &str, pw: &str| {
            let kind = crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("u".into()),
                password: Some(pw.to_string()),
                ..Default::default()
            });
            crate::types::CipherInput {
                name: name.into(),
                kind,
                ..Default::default()
            }
        };

        // Owner grants the Editor WRITE on a new collection and seeds one
        // cipher into it; one personal cipher stays flat.
        let work = handle.collection_create("Work").unwrap();
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        drop(joiner);
        let joiner_member =
            crate::vault::members::member_id_for_device(&owner_path, joiner_device).unwrap();
        handle
            .collection_grant(
                work,
                crate::vault::collections::GrantTarget::Member { id: joiner_member },
                crate::vault::collections::CollectionAccess::Write,
                None,
            )
            .unwrap();
        let seed_id = handle
            .add_cipher_in_collection(&mk_login("Seeded", "seed-pass"), Some(work))
            .unwrap();
        let personal_id = handle.add_cipher(&mk_login("Personal", "pw")).unwrap();
        engine_o.commit_all(&repo_o, "seed").unwrap();

        // Joiner pulls: the collection cipher is readable via the grant
        // wrap; the personal cipher is invisible AND unreadable.
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert!(!joiner.unlocked().holds_root());
        let metas = joiner.list_cipher_meta().unwrap();
        assert!(
            metas.iter().any(|m| m.id == seed_id),
            "seeded cipher listed"
        );
        assert!(
            !metas.iter().any(|m| m.id == personal_id),
            "personal cipher invisible"
        );
        match joiner.get_cipher(seed_id).unwrap() {
            CipherRead::Decrypted(c) => {
                let crate::types::CipherKind::Login(l) = &c.kind else {
                    panic!("expected login")
                };
                assert_eq!(l.password.as_deref(), Some("seed-pass"));
            }
            _ => panic!("expected decrypted"),
        }
        assert!(joiner.get_cipher(personal_id).is_err());

        // Member writes: create inside the collection, update the seeded
        // cipher. A flat create refuses (no group key).
        let own_id = joiner
            .add_cipher_in_collection(&mk_login("Mine", "mine-pass"), Some(work))
            .unwrap();
        assert!(joiner.add_cipher(&mk_login("Flat", "x")).is_err());
        joiner
            .update_cipher(seed_id, &mk_login("Seeded", "rotated-pass"))
            .unwrap();

        // Member trash + restore: same-domain, back inside the dir.
        let dirs = crate::vault::collections::load_dir_map(&joiner_path);
        let work_dir = dirs.iter().find(|(_, id)| *id == work).unwrap().0.clone();
        joiner.delete_cipher(own_id).unwrap();
        assert!(
            joiner_path
                .join(format!("trash/{work_dir}/{own_id}.enc"))
                .exists()
        );
        // §6.5 restore_policy: restoring is admin-only by default — the
        // member's restore refuses even with a live Write grant (trash
        // itself stays write-scope under the default trash_policy).
        let err = joiner.restore_cipher(own_id).unwrap_err().to_string();
        assert!(err.contains("Restoring is limited to admins"), "err: {err}");
        drop(joiner);

        // Joiner commits its writes; the owner pulls from the joiner
        // (the owner repo is the origin — add it as a remote).
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.commit_all(&repo_j, "member writes").unwrap();
        drop(repo_j);
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .map_err(|e| e.message().to_string())
            .ok();
        engine_o.pull(&repo_o, "joiner").unwrap();
        // The member's restore was refused core-side; the owner (admin)
        // restores the entry from the pulled trash commit.
        handle.restore_cipher(own_id).unwrap();
        for (cid, want) in [(own_id, "mine-pass"), (seed_id, "rotated-pass")] {
            match handle.get_cipher(cid).unwrap() {
                CipherRead::Decrypted(c) => {
                    let crate::types::CipherKind::Login(l) = &c.kind else {
                        panic!("expected login")
                    };
                    assert_eq!(l.password.as_deref(), Some(want));
                }
                _ => panic!("expected decrypted"),
            }
        }
        engine_o.commit_all(&repo_o, "land member writes").unwrap();

        // Root rotation: CK values are rotation-invariant, collection
        // ciphers re-key at the new epoch, and the member's grant wrap
        // still opens — access survives.
        handle.rotate_root_key().unwrap();
        // The rotating admin must still read its own re-keyed ciphers.
        match handle.get_cipher(seed_id).unwrap() {
            CipherRead::Decrypted(c) => {
                let crate::types::CipherKind::Login(l) = &c.kind else {
                    panic!("expected login")
                };
                assert_eq!(l.password.as_deref(), Some("rotated-pass"));
            }
            _ => panic!("expected decrypted"),
        }
        engine_o.commit_all(&repo_o, "rotate").unwrap();
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        drop(repo_j);
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        match joiner.get_cipher(seed_id).unwrap() {
            CipherRead::Decrypted(c) => {
                let crate::types::CipherKind::Login(l) = &c.kind else {
                    panic!("expected login")
                };
                assert_eq!(l.password.as_deref(), Some("rotated-pass"));
            }
            _ => panic!("expected decrypted"),
        }
    }

    #[test]
    fn jit_access_request_roundtrip_two_devices() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // The owner row must carry the identity wrap pubkey so the
        // approver set is non-empty (deterministic regardless of genesis
        // ordering in the keystore-less test environment).
        let owner_member =
            crate::vault::members::member_id_for_device(&owner_path, handle.device_id).unwrap();
        let mut owner_row =
            crate::vault::members::member_file_by_id(&owner_path, owner_member).unwrap();
        let card = handle.contact_card_signed().unwrap();
        owner_row.identity_wrap_pubkey = Some(card.card.identity_wrap_pubkey.clone());
        crate::vault::members::write_member(&owner_path, &owner_row).unwrap();

        // Two collections: one gets granted, one gets denied.
        let sgk = handle.unlocked().sgk().expect("sgk in test").clone();
        let work = crate::vault::collections::create_collection(&owner_path, &sgk, "Work").unwrap();
        let finance =
            crate::vault::collections::create_collection(&owner_path, &sgk, "Finance").unwrap();

        // Standard join ceremony: the asker is a live Editor member.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        let joiner_member = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // Joiner pulls everything (collections + membership), unlocks,
        // and submits TWO sealed asks (Work to be granted, Finance to be
        // denied). One unlock, one ship commit: an unlock between commits
        // can dirty git-tracked files via the plaintext-activity
        // migration, and an Editor cannot commit those.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        let req_id = joiner
            .collection_access_request(
                work.id,
                crate::vault::collections::CollectionAccess::Read,
                "need the servers",
            )
            .unwrap();
        let req_denied = joiner
            .collection_access_request(
                finance.id,
                crate::vault::collections::CollectionAccess::Read,
                "",
            )
            .unwrap();
        assert_eq!(joiner.my_access_requests().unwrap().len(), 2);

        // Ship the ask; the owner pulls and reads the inbox.
        let joiner_seal = joiner.devkey_seal();
        let joiner_device = joiner.device_id;
        drop(joiner);
        let engine_j_signed = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j_signed
            .commit_all(&repo_j, "access requests")
            .unwrap();
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();

        let (rows, malformed) = handle.access_requests_inbox().unwrap();
        assert_eq!(malformed, 0);
        assert_eq!(rows.len(), 2);
        let work_ask = rows.iter().find(|r| r.request_id == req_id).unwrap();
        assert_eq!(work_ask.requester_member_id, joiner_member);
        assert_eq!(work_ask.collection_name.as_deref(), Some("Work"));
        assert_eq!(work_ask.note, "need the servers");
        assert!(
            rows.iter()
                .any(|r| r.request_id == req_denied
                    && r.collection_name.as_deref() == Some("Finance"))
        );

        // Approve with an access override (asked read, granted write).
        let granted = handle
            .approve_access_request(
                joiner_member,
                req_id,
                Some(crate::vault::collections::CollectionAccess::Write),
                None,
            )
            .unwrap();
        assert_eq!(granted.collection_name.as_deref(), Some("Work"));
        // The request is consumed: double-approve is a refusal.
        assert!(
            handle
                .approve_access_request(joiner_member, req_id, None, None)
                .is_err()
        );
        // The deny leg: the second ask dies by denial, no grant issued.
        handle
            .deny_access_request(joiner_member, req_denied)
            .unwrap();
        // Double-deny is a refusal (the file is consumed).
        assert!(
            handle
                .deny_access_request(joiner_member, req_denied)
                .is_err()
        );
        engine_o.commit_all(&repo_o, "decide requests").unwrap();

        // Joiner pulls the decisions: no pending asks, the grant visible
        // (write, the admin's override), the denied collection untouched,
        // and the approval minted their per-member CK wrap.
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert!(joiner.my_access_requests().unwrap().is_empty());
        let listed = joiner.collections_list().unwrap();
        let work_row = listed.iter().find(|(id, _, _)| *id == work.id).unwrap();
        assert!(work_row.2.iter().any(|g| {
            g.target.member_id() == Some(joiner_member)
                && g.access == crate::vault::collections::CollectionAccess::Write
        }));
        let finance_row = listed.iter().find(|(id, _, _)| *id == finance.id).unwrap();
        assert!(finance_row.2.is_empty());
        let via_wrap = crate::vault::collections::open_grant_wrap(
            &joiner_path,
            &work.id,
            &joiner_member,
            joiner.identity().unwrap().wrapping_secret(),
        )
        .unwrap();
        let cks = crate::vault::collections::collect_content_keys(
            &joiner_path,
            joiner.unlocked().sgk().expect("sgk"),
        )
        .unwrap();
        let (_, ck) = cks.iter().find(|(id, _)| *id == work.id).unwrap();
        assert_eq!(via_wrap.as_ref(), ck.as_ref());

        // Activity log: one grant, one denial, in order.
        let events = handle.share_events(50).unwrap();
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&crate::vault::events::ShareEventKind::AccessGranted));
        assert!(kinds.contains(&crate::vault::events::ShareEventKind::AccessDenied));
        let grant_idx = kinds
            .iter()
            .position(|k| *k == crate::vault::events::ShareEventKind::AccessGranted)
            .unwrap();
        let deny_idx = kinds
            .iter()
            .position(|k| *k == crate::vault::events::ShareEventKind::AccessDenied)
            .unwrap();
        assert!(grant_idx < deny_idx);
        assert!(events[grant_idx].detail.contains("MemberDevice"));
    }

    /// S1a-4: identity rotation is visible and triggers the trust reset.
    /// The joiner rotates their identity; the member record carries the
    /// new pubkey + rotation timestamp, and the owner's address book
    /// entry for the OLD identity downgrades to Channel on reconcile.
    #[test]
    fn member_identity_rotation_resets_trust() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();

        // Genesis: owner member record carries the creation identity vk.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();

        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        let joiner_old_identity = intro
            .contact_card
            .as_ref()
            .unwrap()
            .card
            .identity_signing_pubkey
            .clone();

        let trust = handle.contacts_import_intro(&intro_code).unwrap();
        assert_eq!(trust, crate::vault::contacts::ContactTrust::Channel);
        handle.contacts_mark_verified(&joiner_old_identity).unwrap();
        handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // Joiner pulls approval, unlocks, rotates their identity.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        let old_identity_vk = joiner.identity().unwrap().signing_key().verifying_key();
        assert_eq!(
            hex::encode(old_identity_vk.as_bytes()),
            joiner_old_identity,
            "member record identity must match the introduced card"
        );
        joiner.rotate_identity().unwrap();
        let new_identity_vk = hex::encode(
            joiner
                .identity()
                .unwrap()
                .signing_key()
                .verifying_key()
                .as_bytes(),
        );
        assert_ne!(new_identity_vk, joiner_old_identity);

        // Rotation ships via sync; the owner reconciles on next sync:
        // the joiner's stale Verified contact drops to Channel.
        let joiner_seal = joiner.devkey_seal();
        let joiner_device = joiner.device_id;
        drop(joiner);
        let engine_j_signed = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j_signed
            .commit_all(&repo_j, "identity rotation")
            .unwrap();
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        let downgraded = handle.reconcile_stale_member_contacts().unwrap();
        assert_eq!(
            downgraded,
            vec![joiner_old_identity],
            "stale Verified contact must downgrade to Channel"
        );

        // The member record carries the NEW identity pubkey.
        let mut found: Option<crate::vault::members::MemberFile> = None;
        for entry in std::fs::read_dir(owner_path.join("meta/members"))
            .unwrap()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<crate::vault::members::MemberFile>(
                &std::fs::read_to_string(entry.path()).unwrap(),
            ) {
                if record.identity_signing_pubkey.as_deref() == Some(new_identity_vk.as_str()) {
                    found = Some(record);
                    break;
                }
            }
        }
        let member_record = found.expect("member record must carry the rotated identity");
        assert!(member_record.identity_rotated_at.is_some());
    }

    // ── S1a-5: member reset (§5.F-8 / scenario L) ──

    /// "Tablet died AND the recovery phrase is gone": the admin
    /// tombstones the member row and mints a reset invite bound to a
    /// fresh successor row. The old device's stale-clone commits are
    /// refused at pull (sticky tombstone), the old contact entry drops
    /// to Channel, and the member rejoins through the normal ceremony
    /// into the successor row. Entries are preserved.
    #[test]
    fn member_reset_reissues_identity_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();

        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();

        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        let old_identity = intro
            .contact_card
            .as_ref()
            .unwrap()
            .card
            .identity_signing_pubkey
            .clone();
        handle.contacts_import_intro(&intro_code).unwrap();
        handle.contacts_mark_verified(&old_identity).unwrap();
        let old_member_id = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        // The member pulls the approval and unlocks: alive and working.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();

        // S1a-5 review: the manage-members gate must actually resolve
        // roles on strict vaults — an Editor cannot mint invites,
        // approve joins, or reset members.
        assert!(
            joiner
                .invite_create(crate::vault::members::MemberRole::Viewer, None)
                .is_err()
        );
        assert!(joiner.member_reset(old_member_id).is_err());

        // Gates: unknown reset and self reset refuse; the OWNER row is
        // now resettable by an admin (S13) but the owner resetting their
        // own row is still the self guard.
        assert!(handle.member_reset(uuid::Uuid::new_v4()).is_err());
        let (successor_id, reset_code) = handle.member_reset(old_member_id).unwrap();
        // Double reset refused.
        assert!(handle.member_reset(old_member_id).is_err());
        // S1b-1: the reset landed in the activity log.
        assert_eq!(
            handle.share_events(50).unwrap().last().unwrap().kind,
            crate::vault::events::ShareEventKind::MemberReset
        );

        // The tombstone ships: old row dead, successor row waiting.
        engine_o.commit_all(&repo_o, "member reset").unwrap();
        let old_row = crate::vault::members::member_file_by_id(&owner_path, old_member_id).unwrap();
        {
            let reset = old_row.reset.as_ref().unwrap();
            assert_eq!(reset.successor, successor_id);
            let successor =
                crate::vault::members::member_file_by_id(&owner_path, reset.successor).unwrap();
            assert_eq!(successor.display_name, old_row.display_name);
            assert_eq!(successor.role, old_row.role);
            assert_eq!(
                successor.trust,
                crate::vault::members::TrustLevel::Channel,
                "successor starts at Channel: re-verification required"
            );
            assert!(successor.identity_signing_pubkey.is_none());
            assert_eq!(
                old_row.identity_signing_pubkey, None,
                "tombstone clears the current identity"
            );
            assert_eq!(
                old_row.identity_signing_pubkey_previous.as_deref(),
                Some(old_identity.as_str()),
                "tombstone parks the dead key in previous so contacts reset"
            );
        }
        assert_ne!(successor_id, old_member_id);

        // The OLD device goes rogue: it edits a cipher from its stale
        // clone and pushes. Every honest client must refuse the pull —
        // the tombstone from local history sticks through the walk even
        // though the rogue commit's own ancestry predates the reset.
        joiner
            .add_cipher(&crate::types::CipherInput {
                name: "rogue-after-reset".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
                favorite: false,
                reprompt: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                archived: false,
                tags: vec![],
                attachments: vec![],
            })
            .unwrap();
        let joiner_seal = joiner.devkey_seal();
        let joiner_device = joiner.device_id;
        drop(joiner);
        let engine_j_signed = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j_signed
            .commit_all(&repo_j, "rogue edit after reset")
            .unwrap();
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        let head_before = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        let rogue_err = engine_o
            .pull(&repo_o, "joiner")
            .expect_err("the tombstoned member's rogue commit must be refused");
        assert!(
            rogue_err.to_string().to_lowercase().contains("policy"),
            "refusal must be the policy denial, got: {rogue_err}"
        );
        let head_after = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert_eq!(head_before, head_after, "HEAD must not move on refusal");

        // Trust reset: the dead identity's contact entry drops to Channel.
        let downgraded = handle.reconcile_stale_member_contacts().unwrap();
        assert_eq!(downgraded, vec![old_identity]);

        // Re-join: a fresh device uses the reset invite; the approval
        // binds the successor row (admin-fixed name/role, fresh identity).
        let joiner2_path = temp.path().join("joiner2");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner2_path).unwrap();
        let intro2_code = crate::vault::members::create_introduction(
            &joiner2_path,
            &reset_code,
            "member-pass2",
            "MemberDevice2",
        )
        .unwrap();
        let intro2 = crate::vault::members::Introduction::decode(&intro2_code).unwrap();
        let new_identity = intro2
            .contact_card
            .as_ref()
            .unwrap()
            .card
            .identity_signing_pubkey
            .clone();

        // S1a-5 review: an invite whose role disagrees with the
        // admin-fixed successor row is refused (stale/tampered invite),
        // and the invite is consumed by the refusal.
        let invite_path = owner_path.join("meta/invites").join(format!(
            "{}.json",
            crate::vault::members::Introduction::decode(&intro2_code)
                .unwrap()
                .invite_id
        ));
        let invite_json = std::fs::read_to_string(&invite_path).unwrap();
        let mut invite_val: serde_json::Value = serde_json::from_str(&invite_json).unwrap();
        invite_val["role"] = serde_json::json!("viewer");
        std::fs::write(
            &invite_path,
            serde_json::to_string_pretty(&invite_val).unwrap(),
        )
        .unwrap();
        let mismatch = handle.approve_join(&intro2_code).unwrap_err();
        assert!(
            mismatch.to_string().contains("does not match"),
            "expected role-mismatch refusal, got: {mismatch}"
        );
        // The refusal ran pre-consume: restore the role and the invite
        // still works.
        invite_val["role"] = serde_json::json!("editor");
        std::fs::write(
            &invite_path,
            serde_json::to_string_pretty(&invite_val).unwrap(),
        )
        .unwrap();
        let bound = handle.approve_join(&intro2_code).unwrap();
        assert_eq!(bound, successor_id, "approval must bind the successor row");
        engine_o.commit_all(&repo_o, "approve reset join").unwrap();
        let successor_row =
            crate::vault::members::member_file_by_id(&owner_path, successor_id).unwrap();
        assert_eq!(
            successor_row.identity_signing_pubkey.as_deref(),
            Some(new_identity.as_str())
        );

        // The new device pulls the approval, unlocks with its OWN
        // password, edits a cipher, and the owner accepts the pull.
        let engine_j2 = crate::sync::engine::SyncEngine::new(&joiner2_path, "joiner2", None);
        let repo_j2 = engine_j2.open_repo().unwrap();
        engine_j2.pull(&repo_j2, "origin").unwrap();
        let mut joiner2 = VaultHandle::open(&joiner2_path).unwrap();
        joiner2.unlock("member-pass2").unwrap();
        joiner2
            .add_cipher(&crate::types::CipherInput {
                name: "after-reset-entry".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
                favorite: false,
                reprompt: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                archived: false,
                tags: vec![],
                attachments: vec![],
            })
            .unwrap();
        let j2_seal = joiner2.devkey_seal();
        let j2_device = joiner2.device_id;
        drop(joiner2);
        let engine_j2_signed = crate::sync::engine::SyncEngine::new(
            &joiner2_path,
            &j2_device.to_string(),
            j2_seal.as_ref(),
        );
        engine_j2_signed
            .commit_all(&repo_j2, "member rejoined")
            .unwrap();
        repo_o
            .remote("joiner2", joiner2_path.to_str().unwrap())
            .unwrap();
        engine_o
            .pull(&repo_o, "joiner2")
            .expect("the successor member's commits must be accepted");
    }

    // ── S1a-6: batch removal + offboarding (§4.2, scenario J) ──

    /// Departure/eviction: the admin removes a member in one batch call.
    /// The row is tombstoned (terminal), the device seat is struck from
    /// the registry, the keywrap is deleted, the Root Key rotates once
    /// (survivors re-keyed via P3 staging), the contact dial resets, the
    /// removed device can no longer unlock, and its stale commits are
    /// refused. Entries are preserved across the rotation.
    #[test]
    fn member_removal_offboards_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let owner_member_id = crate::vault::members::owner_member_id(&owner_path).unwrap();

        let cipher_id = {
            let input = crate::types::CipherInput {
                name: "pre-removal-entry".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
                favorite: false,
                reprompt: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                archived: false,
                tags: vec![],
                attachments: vec![],
            };
            handle.add_cipher(&input).unwrap()
        };

        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();

        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        let old_identity = intro
            .contact_card
            .as_ref()
            .unwrap()
            .card
            .identity_signing_pubkey
            .clone();
        handle.contacts_import_intro(&intro_code).unwrap();
        handle.contacts_mark_verified(&old_identity).unwrap();
        let old_member_id = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        let joiner_device = joiner.device_id;

        // Two more members: C joins the batch removal, D survives it
        // (proves survivor re-key adoption + unlock after the rotation).
        let mut members = vec![old_member_id];
        let mut identities = vec![old_identity.clone()];
        let mut member_devices = vec![joiner_device];
        for name in ["MemberC", "MemberD"] {
            let code_n = handle
                .invite_create(crate::vault::members::MemberRole::Editor, None)
                .unwrap();
            engine_o.commit_all(&repo_o, "invite").unwrap();
            let path_n = temp.path().join(name.to_lowercase());
            git2::Repository::clone(owner_path.to_str().unwrap(), &path_n).unwrap();
            let intro_n = crate::vault::members::create_introduction(
                &path_n,
                &code_n,
                &format!("pass-{name}"),
                name,
            )
            .unwrap();
            let decoded = crate::vault::members::Introduction::decode(&intro_n).unwrap();
            identities.push(
                decoded
                    .contact_card
                    .as_ref()
                    .unwrap()
                    .card
                    .identity_signing_pubkey
                    .clone(),
            );
            handle.contacts_import_intro(&intro_n).unwrap();
            handle
                .contacts_mark_verified(identities.last().unwrap())
                .unwrap();
            let id_n = handle.approve_join(&intro_n).unwrap();
            members.push(id_n);
            // The approval ships the keywrap: commit BEFORE the member
            // pulls, or their unlock finds no keywrap on their clone.
            engine_o.commit_all(&repo_o, "approve join").unwrap();
            let engine_n =
                crate::sync::engine::SyncEngine::new(&path_n, &name.to_lowercase(), None);
            let repo_n = engine_n.open_repo().unwrap();
            engine_n.pull(&repo_n, "origin").unwrap();
            let mut handle_n = VaultHandle::open(&path_n).unwrap();
            handle_n.unlock(&format!("pass-{name}")).unwrap();
            member_devices.push(handle_n.device_id);
        }
        let member_c = members[1];
        let d_path = temp.path().join("memberd");
        engine_o.commit_all(&repo_o, "members joined").unwrap();

        // Gates: Editor cannot remove; empty batch, owner row, unknown
        // member, duplicate entries all refused.
        assert!(joiner.member_remove(&[owner_member_id]).is_err());
        assert!(handle.member_remove(&[]).is_err());
        assert!(handle.member_remove(&[owner_member_id]).is_err());
        assert!(handle.member_remove(&[uuid::Uuid::new_v4()]).is_err());
        let unknown = uuid::Uuid::new_v4();
        assert!(handle.member_remove(&[unknown, unknown]).is_err());

        // Offboard A + C in one batch call.
        let report = handle.member_remove(&[old_member_id, member_c]).unwrap();
        assert_eq!(report.removed_members, vec![old_member_id, member_c]);
        // Double removal + re-removal refused.
        assert!(handle.member_remove(&[old_member_id]).is_err());
        assert!(handle.member_remove(&[unknown]).is_err());
        assert!(
            report.removed_devices.contains(&joiner_device)
                && report.removed_devices.contains(&member_devices[1]),
            "both removed members' device seats must be struck"
        );
        assert!(
            !report.removed_devices.contains(&member_devices[2]),
            "the survivor's seat must be untouched"
        );

        // Row tombstoned: terminal marker, identity cleared, dead key
        // parked in previous for the contact reset.
        let row = crate::vault::members::member_file_by_id(&owner_path, old_member_id).unwrap();
        assert!(row.removed.is_some());
        assert_eq!(row.identity_signing_pubkey, None);
        assert_eq!(
            row.identity_signing_pubkey_previous.as_deref(),
            Some(old_identity.as_str())
        );

        // Seat revoked everywhere: registry, keywrap.
        assert!(!handle.device_manager.registry.is_enrolled(&joiner_device));
        assert!(
            !owner_path
                .join(format!("meta/keywrap/{joiner_device}.json"))
                .exists()
        );

        // Entries preserved across the offboarding rotation.
        let read = handle.get_cipher(cipher_id).unwrap();
        match read {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "pre-removal-entry")
            }
            CipherRead::Locked(_) => {
                panic!("owner vault must stay unlocked through the rotation")
            }
        }

        engine_o.commit_all(&repo_o, "remove members").unwrap();

        // Contact dial reset for BOTH removed members (walk order is not
        // deterministic — compare as sets). The survivor's Channel entry
        // never downgrades.
        let mut downgraded = handle.reconcile_stale_member_contacts().unwrap();
        downgraded.sort();
        let mut expected = vec![identities[0].clone(), identities[1].clone()];
        expected.sort();
        assert_eq!(downgraded, expected, "both dead identities must reset");

        // The removed members' devices sync the removal (admin-signed)
        // and then can no longer unlock: keywrap gone, epoch moved.
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner_after = VaultHandle::open(&joiner_path).unwrap();
        assert!(joiner_after.unlock("member-pass").is_err());

        // The SURVIVOR's device pulls the removal and unlocks with its
        // own password: the P3 re-key staged its new keywrap before the
        // rotation committed, and its member canary is unaffected.
        let engine_d = crate::sync::engine::SyncEngine::new(&d_path, "memberd", None);
        let repo_d = engine_d.open_repo().unwrap();
        engine_d.pull(&repo_d, "origin").unwrap();
        let mut survivor = VaultHandle::open(&d_path).unwrap();
        survivor.unlock("pass-MemberD").unwrap();

        // Stale-clone rogue commit: refused at the honest client.
        let joiner_seal = joiner.devkey_seal();
        drop(joiner);
        let engine_j_signed = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j_signed
            .commit_all(&repo_j, "edit after removal")
            .unwrap();
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        let head_before = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        // Refusal layer note: removal strikes the device from the
        // REGISTRY, so the rogue commit usually dies at signature
        // attribution (signer not in roster) before the sticky tombstone
        // policy denial can fire. Either layer is a valid refusal; the
        // reset test covers the policy-denial layer with the registry
        // left intact.
        let rogue_err = engine_o
            .pull(&repo_o, "joiner")
            .expect_err("the removed member's commit must be refused");
        let rogue_err = rogue_err.to_string().to_lowercase();
        assert!(
            rogue_err.contains("policy") || rogue_err.contains("signature"),
            "refusal must be policy or roster-layer, got: {rogue_err}"
        );
        let head_after = repo_o.head().unwrap().peel_to_commit().unwrap().id();
        assert_eq!(head_before, head_after, "HEAD must not move on refusal");

        // Owner still healthy after the rotation: another cipher lands.
        handle
            .add_cipher(&crate::types::CipherInput {
                name: "post-removal-entry".into(),
                folder_id: None,
                collection_id: None,
                kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
                favorite: false,
                reprompt: false,
                notes: None,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                archived: false,
                tags: vec![],
                attachments: vec![],
            })
            .unwrap();
        engine_o.commit_all(&repo_o, "owner continues").unwrap();
    }

    // ── S1a-7: ownership transfer (§4.2, first-class action) ──

    /// Ownership transfer is a role change on TWO member records in one
    /// commit: the old owner is demoted (kept as Admin), the successor is
    /// promoted with SelfTrust, and exactly one Owner row exists before
    /// and after. Only the OWNER can transfer; a tombstoned successor is
    /// refused; the demoted old owner cannot transfer until ownership
    /// comes back.
    #[test]
    fn ownership_transfer_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let old_owner_id = crate::vault::members::owner_member_id(&owner_path).unwrap();

        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Join one successor (C) and one throwaway member (D, removed to
        // prove the tombstoned-target gate).
        let mut members = Vec::new();
        for (name, pass) in [("MemberC", "pass-C"), ("MemberD", "pass-D")] {
            let code_n = handle
                .invite_create(crate::vault::members::MemberRole::Editor, None)
                .unwrap();
            engine_o.commit_all(&repo_o, "invite").unwrap();
            let path_n = temp.path().join(name.to_lowercase());
            git2::Repository::clone(owner_path.to_str().unwrap(), &path_n).unwrap();
            let intro_n =
                crate::vault::members::create_introduction(&path_n, &code_n, pass, name).unwrap();
            let id_n = handle.approve_join(&intro_n).unwrap();
            members.push((id_n, path_n.clone(), pass));
            engine_o.commit_all(&repo_o, "approve join").unwrap();
            // Each member pulls their approval before unlocking: the
            // keywrap ships in the approve commit.
            let engine_n =
                crate::sync::engine::SyncEngine::new(&path_n, &name.to_lowercase(), None);
            let repo_n = engine_n.open_repo().unwrap();
            engine_n.pull(&repo_n, "origin").unwrap();
            let mut handle_n = VaultHandle::open(&path_n).unwrap();
            handle_n.unlock(pass).unwrap();
        }
        let (member_c_id, c_path, c_pass) = members[0].clone();
        let member_d_id = members[1].0;

        // Gates: unknown target, self-target, non-owner actor, tombstoned
        // target, locked handle, Owner-role invites unmintable.
        assert!(handle.transfer_ownership(uuid::Uuid::new_v4()).is_err());
        assert!(handle.transfer_ownership(old_owner_id).is_err());
        let mut c_handle = VaultHandle::open(&c_path).unwrap();
        c_handle.unlock(c_pass).unwrap();
        assert!(c_handle.transfer_ownership(old_owner_id).is_err());
        handle.member_remove(&[member_d_id]).unwrap();
        assert!(handle.transfer_ownership(member_d_id).is_err());
        let mut locked = VaultHandle::open(&owner_path).unwrap();
        assert!(locked.transfer_ownership(member_c_id).is_err());
        assert!(
            handle
                .invite_create(crate::vault::members::MemberRole::Owner, None)
                .is_err()
        );

        // The transfer: old owner demoted to Admin, successor promoted
        // with SelfTrust, exactly one Owner row.
        handle.transfer_ownership(member_c_id).unwrap();
        assert_eq!(
            crate::vault::members::owner_member_id(&owner_path),
            Some(member_c_id),
            "exactly one Owner row, and it is the successor"
        );
        let old_row = crate::vault::members::member_file_by_id(&owner_path, old_owner_id).unwrap();
        assert_eq!(old_row.role, crate::vault::members::MemberRole::Admin);
        let new_row = crate::vault::members::member_file_by_id(&owner_path, member_c_id).unwrap();
        assert_eq!(new_row.role, crate::vault::members::MemberRole::Owner);
        assert_eq!(new_row.trust, crate::vault::members::TrustLevel::SelfTrust);
        // S1b-1: the transfer landed in the activity log.
        assert_eq!(
            handle.share_events(50).unwrap().last().unwrap().kind,
            crate::vault::events::ShareEventKind::OwnershipTransferred
        );

        // The demoted old owner cannot transfer (disk-backed role), and
        // an Admin cannot remove the new Owner row.
        assert!(handle.transfer_ownership(member_c_id).is_err());
        assert!(handle.member_remove(&[member_c_id]).is_err());

        engine_o.commit_all(&repo_o, "transfer ownership").unwrap();

        // The new owner pulls, unlocks, and transfers back — the gate
        // follows the records, not the device. Commits from C's device
        // need the device signing key (per-engine signing, S1a-4 rule).
        let c_seal = c_handle.devkey_seal();
        let c_device = c_handle.device_id;
        let engine_c = crate::sync::engine::SyncEngine::new(&c_path, "memberc", None);
        let repo_c = engine_c.open_repo().unwrap();
        engine_c.pull(&repo_c, "origin").unwrap();
        drop(repo_c);
        // The pull carried the removal rotation: this handle's root is
        // stale until re-unlock (P3 adoption runs at unlock, exactly as
        // production devices re-lock and re-unlock).
        drop(c_handle);
        let mut c_handle = VaultHandle::open(&c_path).unwrap();
        c_handle.unlock(c_pass).unwrap();
        c_handle.transfer_ownership(old_owner_id).unwrap();
        assert_eq!(
            crate::vault::members::owner_member_id(&c_path),
            Some(old_owner_id),
            "flip-back restores the single Owner invariant"
        );
        drop(c_handle);
        let engine_c_signed =
            crate::sync::engine::SyncEngine::new(&c_path, &c_device.to_string(), c_seal.as_ref());
        let repo_c = engine_c_signed.open_repo().unwrap();
        engine_c_signed
            .commit_all(&repo_c, "transfer back")
            .unwrap();

        // The old owner pulls the flip-back and is Owner again.
        repo_o.remote("c", c_path.to_str().unwrap()).unwrap();
        engine_o.pull(&repo_o, "c").unwrap();
        assert_eq!(
            crate::vault::members::owner_member_id(&owner_path),
            Some(old_owner_id)
        );

        // A RESET-tombstoned row is also refused as a successor (D above
        // covered the removal tombstone).
        handle.member_reset(member_c_id).unwrap();
        assert!(handle.transfer_ownership(member_c_id).is_err());
    }

    // ── S1a-8: repo-backed join queue ──

    /// The intro handoff becomes repo state: the admin stages received
    /// introductions into meta/requests/, lists them (secret check,
    /// malformed skipped + counted), approves through the STANDARD
    /// verification path (request consumed only on success), denies the
    /// rest. Unbound devices are refused queue access; a wrong-secret
    /// request lists as suspect and fails approval without being
    /// consumed; an elevated-gate refusal also leaves the request
    /// queued for retry.
    #[test]
    fn join_queue_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Editor invite + introduction (the code travels out-of-band).
        let code1 = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro1 = crate::vault::members::create_introduction(
            &joiner_path,
            &code1,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();

        // Empty queue before staging.
        assert_eq!(handle.join_queue_list().unwrap(), (Vec::new(), 0));

        // Stage + verify the queue entry (secret matches the live
        // invite).
        let req1 = handle.join_queue_submit(&intro1).unwrap();
        let (queued, malformed) = handle.join_queue_list().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(malformed, 0);
        assert_eq!(queued[0].req_id, req1);
        assert!(queued[0].secret_ok);
        assert_eq!(queued[0].display_name, "MemberDevice");

        // Unbound devices have no queue access (fail-closed member gate).
        let joiner = VaultHandle::open(&joiner_path).unwrap();
        assert!(joiner.join_queue_list().is_err());

        // Malformed files in the requests dir are inert + counted. Non-
        // UUID stems and oversized blobs count too (review: non-UUID
        // stems used to collapse onto Uuid::nil() as unmanageable queue
        // entries; oversized blobs were read into memory unchecked).
        let req_dir = owner_path.join("meta/requests");
        std::fs::write(
            req_dir.join("deadbeef-0000-0000-0000-000000000000.json"),
            "{junk",
        )
        .unwrap();
        std::fs::write(req_dir.join("notauuid.json"), "{junk").unwrap();
        std::fs::write(
            req_dir.join(format!("{}.json", uuid::Uuid::new_v4())),
            "x".repeat(65_537),
        )
        .unwrap();
        let (_, malformed) = handle.join_queue_list().unwrap();
        assert_eq!(malformed, 3);

        // Newline display names are refused at APPROVAL too (the direct
        // path bypasses staging), before any mutation.
        let mut nl_intro = crate::vault::members::Introduction::decode(&intro1).unwrap();
        nl_intro.display_name = "bad\nname".into();
        assert!(handle.approve_join(&nl_intro.encode().unwrap()).is_err());

        // Approve through the queue: full standard verification, request
        // consumed on success.
        let member_id = handle.approve_queued_join(req1).unwrap();
        engine_o.commit_all(&repo_o, "approve queued join").unwrap();
        // The junk files stay (inert; purge-malformed is UI scope).
        assert_eq!(handle.join_queue_list().unwrap(), (Vec::new(), 3));

        // The approved member is a real member: pulls, unlocks.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        assert_eq!(
            crate::vault::members::member_id_for_device(&owner_path, joiner.device_id),
            Some(member_id)
        );

        // Wrong-secret request: lists as suspect, approval fails, request
        // stays queued.
        let mut bad = crate::vault::members::Introduction::decode(&intro1).unwrap();
        bad.secret = "deadbeef".into();
        let req_bad = handle.join_queue_submit(&bad.encode().unwrap()).unwrap();
        let (queued, _) = handle.join_queue_list().unwrap();
        let bad_entry = queued.iter().find(|q| q.req_id == req_bad).unwrap();
        assert!(!bad_entry.secret_ok, "tampered secret must flag suspect");
        assert!(handle.approve_queued_join(req_bad).is_err());
        assert!(
            !handle.join_queue_list().unwrap().0.is_empty(),
            "refused request stays queued"
        );
        handle.deny_queued_join(req_bad).unwrap();

        // Elevated gate through the queue: an Admin invite without a
        // verified card refuses, and the request stays queued for retry.
        let code3 = handle
            .invite_create(crate::vault::members::MemberRole::Admin, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite 3").unwrap();
        let joiner3_path = temp.path().join("joiner3");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner3_path).unwrap();
        let intro3 = crate::vault::members::create_introduction(
            &joiner3_path,
            &code3,
            "member-pass3",
            "MemberDevice3",
        )
        .unwrap();
        let req3 = handle.join_queue_submit(&intro3).unwrap();
        assert!(handle.approve_queued_join(req3).is_err());
        assert!(
            !handle.join_queue_list().unwrap().0.is_empty(),
            "elevated-gate refusal leaves the request queued"
        );
        handle.deny_queued_join(req3).unwrap();
        assert_eq!(handle.join_queue_list().unwrap(), (Vec::new(), 3));
    }

    // ── S1b-1: sharing activity log (detect + notify + viewer) ──

    /// Every member primitive emits a human-sentence event into the
    /// encrypted, rotation-covered log; the local refusal log records
    /// commits THIS client refused; the log survives the offboarding
    /// rotation (re-encrypted under the new events key).
    #[test]
    fn share_events_activity_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let owner_path = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner_path, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner_path,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();

        // Empty log at genesis.
        assert!(handle.share_events(50).unwrap().is_empty());

        // Join a member: MemberJoined lands.
        let code = handle
            .invite_create(crate::vault::members::MemberRole::Editor, None)
            .unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();
        let joiner_path = temp.path().join("joiner");
        git2::Repository::clone(owner_path.to_str().unwrap(), &joiner_path).unwrap();
        let intro_code = crate::vault::members::create_introduction(
            &joiner_path,
            &code,
            "member-pass",
            "MemberDevice",
        )
        .unwrap();
        handle.contacts_import_intro(&intro_code).unwrap();
        let intro = crate::vault::members::Introduction::decode(&intro_code).unwrap();
        handle
            .contacts_mark_verified(
                &intro
                    .contact_card
                    .as_ref()
                    .unwrap()
                    .card
                    .identity_signing_pubkey,
            )
            .unwrap();
        let old_member_id = handle.approve_join(&intro_code).unwrap();
        engine_o.commit_all(&repo_o, "approve join").unwrap();

        let events = handle.share_events(50).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].kind,
            crate::vault::events::ShareEventKind::MemberJoined
        );
        assert!(events[0].detail.contains("MemberDevice"));
        assert!(events[0].detail.contains("editor"));

        // The member pulls, unlocks, rotates: IdentityRotated lands on
        // the MEMBER device's local log.
        let engine_j = crate::sync::engine::SyncEngine::new(&joiner_path, "joiner", None);
        let repo_j = engine_j.open_repo().unwrap();
        engine_j.pull(&repo_j, "origin").unwrap();
        let mut joiner = VaultHandle::open(&joiner_path).unwrap();
        joiner.unlock("member-pass").unwrap();
        joiner.rotate_identity().unwrap();
        let joiner_events = joiner.share_events(50).unwrap();
        assert_eq!(
            joiner_events.last().unwrap().kind,
            crate::vault::events::ShareEventKind::IdentityRotated
        );

        // Owner pulls the rotation, reconciles: ContactTrustReset lands.
        let joiner_seal = joiner.devkey_seal();
        let joiner_device = joiner.device_id;
        drop(joiner);
        let engine_j_signed = crate::sync::engine::SyncEngine::new(
            &joiner_path,
            &joiner_device.to_string(),
            joiner_seal.as_ref(),
        );
        engine_j_signed
            .commit_all(&repo_j, "identity rotation")
            .unwrap();
        repo_o
            .remote("joiner", joiner_path.to_str().unwrap())
            .unwrap();
        engine_o.pull(&repo_o, "joiner").unwrap();
        let downgraded = handle.reconcile_stale_member_contacts().unwrap();
        assert_eq!(downgraded.len(), 1);
        let events = handle.share_events(50).unwrap();
        assert_eq!(
            events.last().unwrap().kind,
            crate::vault::events::ShareEventKind::ContactTrustReset
        );

        // Removal: MemberRemoved + the offboarding rotation. The log
        // must stay readable under the NEW events key (rotation
        // coverage), and seq stays monotonic across the swap.
        handle.member_remove(&[old_member_id]).unwrap();
        engine_o.commit_all(&repo_o, "remove member").unwrap();
        let events = handle.share_events(50).unwrap();
        let removed = events.last().unwrap();
        assert_eq!(
            removed.kind,
            crate::vault::events::ShareEventKind::MemberRemoved
        );
        assert!(removed.seq > events.first().unwrap().seq);

        // Rogue commit from the removed member's stale clone: refused at
        // pull, and the LOCAL refusal log records this client's
        // detection (detect + notify, S1b-1).
        engine_j_signed
            .commit_all(&repo_j, "edit after removal")
            .unwrap();
        assert!(engine_o.pull(&repo_o, "joiner").is_err());
        let refusals = handle.refusal_log(50);
        assert!(
            refusals.iter().any(|l| l.contains("refused commit")),
            "the refusal must be recorded locally, got: {refusals:?}"
        );
    }

    /// Compaction: the log folds its oldest entries beyond the cap.
    #[test]
    fn share_events_compaction_cap() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("v");
        std::fs::create_dir_all(&vault).unwrap();
        let root = [9u8; 64];
        let vault_id = uuid::Uuid::new_v4();
        for i in 0..(crate::vault::events::MAX_SHARE_EVENTS + 5) {
            crate::vault::events::append(
                &vault,
                vault_id,
                &root,
                1,
                crate::vault::events::ShareEventKind::MemberJoined,
                format!("event {i}"),
            )
            .unwrap();
        }
        let events = crate::vault::events::load(&vault, vault_id, &root).unwrap();
        assert_eq!(events.len(), crate::vault::events::MAX_SHARE_EVENTS);
        assert_eq!(events.first().unwrap().seq, 6, "oldest five folded away");
        assert_eq!(
            events.last().unwrap().seq,
            crate::vault::events::MAX_SHARE_EVENTS as u64 + 5
        );

        // S1b-1 review: a log transplanted from another vault fails the
        // AAD binding check (fail closed) instead of decrypting garbage.
        let other_root = [8u8; 64];
        let other_dir = temp.path().join("other");
        std::fs::create_dir_all(other_dir.join("meta")).unwrap();
        let other_vault_id = uuid::Uuid::new_v4();
        crate::vault::events::append(
            &other_dir,
            other_vault_id,
            &other_root,
            1,
            crate::vault::events::ShareEventKind::MemberJoined,
            "foreign",
        )
        .unwrap();
        std::fs::copy(
            other_dir.join("meta/share-events.enc"),
            vault.join("meta/share-events.enc"),
        )
        .unwrap();
        let err = crate::vault::events::load(&vault, vault_id, &root)
            .expect_err("transplanted log must fail closed");
        assert!(
            err.to_string().contains("does not belong"),
            "expected the AAD binding refusal, got: {err}"
        );
    }

    // ── P3: keywrap distribution + rekey-txn adoption ──

    /// Enroll a second device the way a real two-device vault looks:
    /// registry entry, current-epoch keywrap file, and dev2's own local
    /// state (sealed private keys + local device-id file) so the vault
    /// can be re-opened AS dev2.
    fn enroll_second_device(
        handle: &mut VaultHandle,
        dir: &std::path::Path,
        password: &str,
    ) -> (uuid::Uuid, x25519_dalek::StaticSecret) {
        let dev2_id = uuid::Uuid::new_v4();
        let dev2_ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dev2_x = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dev2_x_pub = x25519_dalek::PublicKey::from(&dev2_x);
        handle
            .device_manager
            .registry
            .enroll_with_id(
                dev2_id,
                "device-2".into(),
                dev2_x_pub.to_bytes(),
                dev2_ed.verifying_key().to_bytes(),
                Some(handle.device_id),
            )
            .unwrap();
        handle.sync_registry_from_device_manager();

        let root = handle.unlocked().root().expect("root in test").clone();
        let (eph, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(root.as_bytes(), &dev2_x_pub, "root-key-keywrap")
                .unwrap();
        let kw = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            dir.join(format!("meta/keywrap/{dev2_id}.json")),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();

        let kek = kdf::derive_kek(password, &handle.kdf_params).unwrap();
        let seal = hkdf_derive::derive_devkey_seal_key(&kek).unwrap();
        let inner = serde_json::json!({
            "x25519_private": hex::encode(dev2_x.to_bytes()),
            "ed25519_private": hex::encode(dev2_ed.to_bytes()),
        })
        .to_string();
        crate::vault::device_privkey::seal_file(
            &dir.join("meta/device-privkey.json"),
            &inner,
            &seal,
            Some(dev2_id),
        )
        .unwrap();
        crate::vault::device_privkey::write_device_id(dir, dev2_id).unwrap();
        (dev2_id, dev2_x)
    }

    /// Enroll a bare third device (registry + keywrap file only). It never
    /// unlocks in-process; it exists so a revocation leaves a survivor
    /// behind (revoking the second device would leave none).
    fn enroll_third_device(handle: &mut VaultHandle, dir: &std::path::Path) -> uuid::Uuid {
        let dev3_id = uuid::Uuid::new_v4();
        let dev3_ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dev3_x = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dev3_x_pub = x25519_dalek::PublicKey::from(&dev3_x);
        handle
            .device_manager
            .registry
            .enroll_with_id(
                dev3_id,
                "device-3".into(),
                dev3_x_pub.to_bytes(),
                dev3_ed.verifying_key().to_bytes(),
                Some(handle.device_id),
            )
            .unwrap();
        handle.sync_registry_from_device_manager();
        let root = handle.unlocked().root().expect("root in test").clone();
        let (eph, ct, tag) =
            crate::crypto::hpke_wrap::wrap_key(root.as_bytes(), &dev3_x_pub, "root-key-keywrap")
                .unwrap();
        let kw = serde_json::json!({
            "device_id": dev3_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            dir.join(format!("meta/keywrap/{dev3_id}.json")),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();
        dev3_id
    }

    // A survivor that pulls a repo rotated by another device must unlock
    // via the committed rekey transaction, keeping its OWN device id.
    // Pre-fix, the transaction had no consumer: the survivor's stale
    // keywrap failed the canary check and unlock either bricked (real
    // machines) or silently adopted another device's identity via the F1
    // heal (this shared-dir simulation).
    #[test]
    fn rekey_txn_adopted_on_survivor_unlock() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let (dev2_id, _dev2_x) = enroll_second_device(&mut handle, dir.path(), &password);
        let dev3_id = enroll_third_device(&mut handle, dir.path());

        let input = CipherInput {
            name: "Secret".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass123".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let cipher_id = handle.add_cipher(&input).unwrap();

        let old_epoch = handle.unlocked().current_epoch;
        let result = handle.revoke_device_and_rekey(dev3_id).unwrap();
        let new_epoch = result.new_epoch;
        assert_ne!(new_epoch, old_epoch);

        // Revocation removed the target's keywrap; the survivor's is now
        // stale (still wraps the retired root key).
        assert!(
            !dir.path()
                .join(format!("meta/keywrap/{dev3_id}.json"))
                .exists()
        );
        assert!(
            dir.path()
                .join(format!("meta/keywrap/{dev2_id}.json"))
                .exists()
        );

        // The committed transaction carries a fresh wrap for the survivor.
        let txn_path = dir.path().join(format!("meta/rekey/{new_epoch}.txn"));
        assert!(
            txn_path.exists(),
            "rekey txn must be committed for survivors"
        );
        let tx: crate::keys::rotation::RekeyTransaction =
            serde_json::from_str(&std::fs::read_to_string(&txn_path).unwrap()).unwrap();
        assert_eq!(tx.new_epoch, new_epoch);
        assert!(tx.wrapped_root_keys.iter().any(|e| e.device_id == dev2_id));

        // Simulate the survivor pulling the rotated repo and unlocking.
        drop(handle);
        let mut survivor = VaultHandle::open(dir.path()).unwrap();
        assert_eq!(survivor.device_id, dev2_id);
        survivor.unlock(&password).unwrap();
        // Adoption must keep the survivor's OWN identity (pre-fix, the F1
        // heal silently re-targeted the unlock at the actor's device).
        assert_eq!(
            survivor.device_id, dev2_id,
            "unlock must not adopt another device's identity"
        );
        assert_eq!(survivor.unlocked().current_epoch, new_epoch);
        // Adoption persisted the survivor's keywrap for the fast path.
        assert!(
            dir.path()
                .join(format!("meta/keywrap/{dev2_id}.json"))
                .exists()
        );
        match survivor.get_cipher(cipher_id).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Secret"),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Fast path: subsequent unlock must succeed using the persisted
        // keywrap even if the rekey transaction file is removed.
        drop(survivor);
        std::fs::remove_file(&txn_path).unwrap();
        let mut survivor2 = VaultHandle::open(dir.path()).unwrap();
        assert_eq!(survivor2.device_id, dev2_id);
        survivor2.unlock(&password).unwrap();
        assert_eq!(survivor2.unlocked().current_epoch, new_epoch);
        match survivor2.get_cipher(cipher_id).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Secret"),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    // Routine rotation distributes fresh keywraps to every enrolled
    // device, not just the actor. Without this, a plain rotate_root_key
    // bricks every other device on next pull.
    #[test]
    fn rotate_root_key_distributes_keywraps_to_all_devices() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let (dev2_id, dev2_x) = enroll_second_device(&mut handle, dir.path(), &password);

        let old_epoch = handle.unlocked().current_epoch;
        handle.rotate_root_key().unwrap();
        let new_epoch = handle.unlocked().current_epoch;
        assert_eq!(new_epoch, old_epoch + 1);

        let kw_path = dir.path().join(format!("meta/keywrap/{dev2_id}.json"));
        assert!(
            kw_path.exists(),
            "rotation must write a keywrap for every enrolled device"
        );
        let parsed =
            crate::vault::keywrap::parse_keywrap_json(&std::fs::read_to_string(&kw_path).unwrap())
                .unwrap();
        let unwrapped = crate::crypto::hpke_wrap::unwrap_key(
            &parsed.ephemeral_public,
            &parsed.encrypted_key,
            &parsed.tag,
            &dev2_x,
            "root-key-keywrap",
        )
        .unwrap();
        let expected = handle.unlocked().root().expect("root in test").as_bytes();
        assert_eq!(&unwrapped[..], &expected[..]);
    }

    // Adoption is fail-closed: no committed txn for the current epoch, or
    // a txn whose content does not match its epoch binding, must never
    // unlock the vault.
    #[test]
    fn rekey_txn_adoption_fails_closed() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();
        let (dev2_id, _) = enroll_second_device(&mut handle, dir.path(), &password);
        let dev3_id = enroll_third_device(&mut handle, dir.path());
        let actor_id = handle.device_id;
        let result = handle.revoke_device_and_rekey(dev3_id).unwrap();
        let new_epoch = result.new_epoch;
        let txn_path = dir.path().join(format!("meta/rekey/{new_epoch}.txn"));
        let txn_json = std::fs::read_to_string(&txn_path).unwrap();
        drop(handle);

        // Keep the F1 heal from impersonating the actor: a real survivor
        // cannot unwrap another device's keywrap, so the actor's keywrap
        // file must not offer a heal path in this shared-dir simulation.
        std::fs::remove_file(dir.path().join(format!("meta/keywrap/{actor_id}.json"))).unwrap();

        // Case 1: txn missing (never synced) -> survivor stays locked out.
        std::fs::remove_file(&txn_path).unwrap();
        let mut survivor = VaultHandle::open(dir.path()).unwrap();
        assert_eq!(survivor.device_id, dev2_id);
        assert!(survivor.unlock(&password).is_err());
        drop(survivor);

        // Case 2: txn present but content does not match its file name
        // (tampered or partially synced) -> fail closed.
        let mut tx: crate::keys::rotation::RekeyTransaction =
            serde_json::from_str(&txn_json).unwrap();
        tx.new_epoch += 1;
        std::fs::write(&txn_path, serde_json::to_string_pretty(&tx).unwrap()).unwrap();
        let mut survivor = VaultHandle::open(dir.path()).unwrap();
        assert!(survivor.unlock(&password).is_err());
    }

    #[test]
    fn revoke_device_and_rekey_re_encrypts_and_persists() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Enroll a second device directly in the registry
        let dev2_id = uuid::Uuid::new_v4();
        let dev2_ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dev2_x = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dev2_x_pub = x25519_dalek::PublicKey::from(&dev2_x);

        handle
            .device_manager
            .registry
            .enroll_with_id(
                dev2_id,
                "device-2".into(),
                dev2_x_pub.to_bytes(),
                dev2_ed.verifying_key().to_bytes(),
                Some(handle.device_id),
            )
            .unwrap();
        handle.sync_registry_from_device_manager();

        // Write keywrap for dev2
        let unlocked = handle.unlocked();
        let (eph, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            unlocked.root().expect("root in test").as_bytes(),
            &dev2_x_pub,
            "root-key-keywrap",
        )
        .unwrap();
        let _ = unlocked;
        let kw = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            dir.path().join(format!("meta/keywrap/{dev2_id}.json")),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();

        // Add a cipher
        let input = CipherInput {
            name: "Secret".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass123".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: Some("sensitive note".into()),
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id1 = handle.add_cipher(&input).unwrap();

        let old_epoch = handle.unlocked().current_epoch;

        // Revoke dev2
        let result = handle.revoke_device_and_rekey(dev2_id).unwrap();
        assert_eq!(result.revoked_device_id, dev2_id);
        assert_eq!(result.revoked_name, "device-2");
        assert_ne!(result.new_epoch, old_epoch);
        assert!(result.new_root_key.is_none()); // zeroized after use

        // Epoch changed in memory
        assert_ne!(handle.unlocked().current_epoch, old_epoch);

        // Dev2's keywrap removed, self keywrap present
        assert!(
            !dir.path()
                .join(format!("meta/keywrap/{dev2_id}.json"))
                .exists()
        );
        assert!(
            dir.path()
                .join(format!("meta/keywrap/{}.json", handle.device_id))
                .exists()
        );

        // No rotation-pending marker left
        assert!(!dir.path().join("meta/.rotation-pending").exists());

        // Cipher still decrypts correctly after re-encryption
        match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.name, "Secret");
                match &c.kind {
                    crate::types::CipherKind::Login(d) => {
                        assert_eq!(d.password.as_deref(), Some("pass123"));
                    }
                    _ => panic!("expected login"),
                }
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Re-open vault and verify persistence with new keywrap
        let mut handle2 = VaultHandle::open(dir.path()).unwrap();
        handle2.unlock(&password).unwrap();
        assert_eq!(handle2.unlocked().current_epoch, result.new_epoch);
        match handle2.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Secret"),
            CipherRead::Locked(_) => panic!("expected decrypted after re-open"),
        }
    }

    #[test]
    fn revoke_device_cannot_revoke_self() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let self_id = handle.device_id;
        let result = handle.revoke_device_and_rekey(self_id);
        assert!(result.is_err());
        match result {
            Err(BaluardError::Vault(VaultError::InvalidOperation(msg))) => {
                assert!(msg.contains("cannot revoke the current device"));
            }
            _other => panic!("expected InvalidOperation"),
        }
    }

    #[test]
    fn revoke_device_re_encrypts_attachments_and_trash() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Enroll a second device
        let dev2_id = uuid::Uuid::new_v4();
        let dev2_ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dev2_x = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dev2_x_pub = x25519_dalek::PublicKey::from(&dev2_x);
        handle
            .device_manager
            .registry
            .enroll_with_id(
                dev2_id,
                "device-2".into(),
                dev2_x_pub.to_bytes(),
                dev2_ed.verifying_key().to_bytes(),
                Some(handle.device_id),
            )
            .unwrap();
        handle.sync_registry_from_device_manager();

        // Write keywrap for dev2
        let unlocked = handle.unlocked();
        let (eph, ct, tag) = crate::crypto::hpke_wrap::wrap_key(
            unlocked.root().expect("root in test").as_bytes(),
            &dev2_x_pub,
            "root-key-keywrap",
        )
        .unwrap();
        let _ = unlocked;
        let kw = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "ephemeral_public": hex::encode(eph),
            "encrypted_key": hex::encode(ct),
            "tag": hex::encode(tag),
        });
        std::fs::write(
            dir.path().join(format!("meta/keywrap/{dev2_id}.json")),
            serde_json::to_string_pretty(&kw).unwrap(),
        )
        .unwrap();

        // Add a cipher with an attachment
        let attach_id = uuid::Uuid::new_v4();
        let input = CipherInput {
            name: "WithAttachment".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("user".into()),
                password: Some("pass".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![crate::vault::attachment::AttachmentMeta {
                id: attach_id.to_string(),
                filename: "secret.txt".into(),
                size: 12,
                encrypted_size: 0, // informational only (C4: blobs are tier-padded)
                mime_type: "text/plain".into(),
                created_at: 1000,
            }],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id1 = handle.add_cipher(&input).unwrap();

        // Write the encrypted attachment file
        let attach_dir = dir
            .path()
            .join("entries")
            .join(id1.to_string())
            .join("attachments");
        std::fs::create_dir_all(&attach_dir).unwrap();
        let item_key_epoch = handle.unlocked().current_epoch;
        let item_key = handle.derive_item_key(id1, item_key_epoch);
        let enc_blob = crate::vault::attachment::encrypt_attachment(
            handle.vault_id,
            id1,
            attach_id,
            item_key.as_bytes(),
            b"hello world",
            item_key_epoch,
            1,
        )
        .unwrap();
        std::fs::write(attach_dir.join(format!("{attach_id}.enc")), &enc_blob).unwrap();

        // Add a cipher, then move it to trash
        let trash_input = CipherInput {
            name: "Trashed".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData {
                username: Some("trash".into()),
                password: Some("trashed-pass".into()),
                ..Default::default()
            }),
            favorite: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec![],
            reprompt: false,
        };
        let id2 = handle.add_cipher(&trash_input).unwrap();
        handle.delete_cipher(id2).unwrap(); // moves to trash

        // Revoke dev2
        let result = handle.revoke_device_and_rekey(dev2_id).unwrap();
        assert_eq!(result.revoked_device_id, dev2_id);

        // Verify attachment was re-encrypted (file still exists and is readable)
        let attach_path = attach_dir.join(format!("{attach_id}.enc"));
        assert!(
            attach_path.exists(),
            "attachment file should exist after rekey"
        );
        let new_enc_blob = std::fs::read(&attach_path).unwrap();
        let new_item_key = handle.derive_item_key(id1, handle.unlocked().current_epoch);
        let decrypted = crate::vault::attachment::decrypt_attachment(
            handle.vault_id,
            id1,
            attach_id,
            new_item_key.as_bytes(),
            &new_enc_blob,
        )
        .unwrap();
        assert_eq!(decrypted, b"hello world");

        // Verify trashed cipher still decrypts
        match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => assert_eq!(c.name, "Trashed"),
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }

        // Verify no .tmp files remain anywhere
        fn check_no_tmp(dir: &Path) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        check_no_tmp(&p);
                    } else {
                        assert!(
                            p.extension().is_none_or(|e| e != "tmp"),
                            "leftover .tmp file: {}",
                            p.display()
                        );
                    }
                }
            }
        }
        check_no_tmp(dir.path());
    }

    // ── Tag tests ──

    #[test]
    fn tag_validation_rejects_empty() {
        assert!(VaultHandle::validate_tag("").is_err());
        assert!(VaultHandle::validate_tag("   ").is_err());
        assert!(VaultHandle::validate_tag("\t\n").is_err());
        assert!(VaultHandle::validate_tag("valid").is_ok());
    }

    #[test]
    fn tag_validation_max_length() {
        let long_tag = "a".repeat(65);
        assert!(VaultHandle::validate_tag(&long_tag).is_err());
        let exact_tag = "a".repeat(64);
        assert!(VaultHandle::validate_tag(&exact_tag).is_ok());
    }

    #[test]
    fn tag_validation_normalizes_case() {
        let result = VaultHandle::validate_tag("Work").unwrap();
        assert_eq!(result, "work");
    }

    #[test]
    fn create_cipher_with_tags() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input = CipherInput {
            name: "Tagged".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["work".into(), "email".into()],
        };
        let id = handle.add_cipher(&input).unwrap();

        let result = handle.get_cipher(id).unwrap();
        match result {
            CipherRead::Decrypted(c) => {
                assert_eq!(c.tags, vec!["work".to_string(), "email".to_string()]);
            }
            CipherRead::Locked(_) => panic!("expected decrypted"),
        }
    }

    #[test]
    fn rebuild_tag_index() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Create ciphers with various tags
        let input1 = CipherInput {
            name: "A".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["work".into(), "email".into()],
        };
        let input2 = CipherInput {
            name: "B".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["personal".into(), "email".into()],
        };
        handle.add_cipher(&input1).unwrap();
        handle.add_cipher(&input2).unwrap();

        handle.rebuild_tag_index().unwrap();
        let tags = handle.list_tags().unwrap();
        assert_eq!(
            tags,
            vec![
                "email".to_string(),
                "personal".to_string(),
                "work".to_string()
            ]
        );
    }

    #[test]
    fn create_tag_to_index() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        handle.create_tag("Work").unwrap();
        let tags = handle.list_tags().unwrap();
        assert_eq!(tags, vec!["work".to_string()]);

        // Idempotent
        handle.create_tag("WORK").unwrap();
        let tags2 = handle.list_tags().unwrap();
        assert_eq!(tags2, vec!["work".to_string()]);
    }

    #[test]
    fn rename_tag_updates_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input1 = CipherInput {
            name: "A".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["old-tag".into()],
        };
        let input2 = CipherInput {
            name: "B".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["old-tag".into(), "keep".into()],
        };
        let id1 = handle.add_cipher(&input1).unwrap();
        let id2 = handle.add_cipher(&input2).unwrap();

        let count = handle.rename_tag("old-tag", "new-tag").unwrap();
        assert_eq!(count, 2);

        // Verify cipher 1
        let c1 = match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(c1.tags, vec!["new-tag".to_string()]);

        // Verify cipher 2
        let c2 = match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert!(c2.tags.contains(&"new-tag".to_string()));
        assert!(c2.tags.contains(&"keep".to_string()));

        // Index updated
        let tags = handle.list_tags().unwrap();
        assert!(!tags.contains(&"old-tag".to_string()));
        assert!(tags.contains(&"new-tag".to_string()));
    }

    #[test]
    fn delete_tag_removes_from_ciphers() {
        let (dir, password) = create_test_vault();
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let input1 = CipherInput {
            name: "A".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["delete-me".into(), "keep".into()],
        };
        let input2 = CipherInput {
            name: "B".into(),
            folder_id: None,
            collection_id: None,
            kind: crate::types::CipherKind::Login(crate::types::LoginData::default()),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            tags: vec!["keep".into()],
        };
        let id1 = handle.add_cipher(&input1).unwrap();
        let id2 = handle.add_cipher(&input2).unwrap();

        let count = handle.delete_tag("delete-me").unwrap();
        assert_eq!(count, 1);

        // Verify cipher 1 no longer has delete-me
        let c1 = match handle.get_cipher(id1).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(c1.tags, vec!["keep".to_string()]);

        // Verify cipher 2 untouched
        let c2 = match handle.get_cipher(id2).unwrap() {
            CipherRead::Decrypted(c) => c,
            _ => panic!("expected decrypted"),
        };
        assert_eq!(c2.tags, vec!["keep".to_string()]);

        // Index updated
        let tags = handle.list_tags().unwrap();
        assert!(!tags.contains(&"delete-me".to_string()));
        assert!(tags.contains(&"keep".to_string()));
    }

    /// Regression for the settings split (2026-06-26): display prefs (theme,
    /// lang) must live in plaintext settings-pub.json; the rest must be
    /// encrypted under the root key in settings.enc. slug confirmed to have no
    /// pre-unlock consumer, so it lives in the encrypted half.
    #[test]
    fn settings_split_roundtrip_and_encryption() {
        let (dir, password) = create_test_vault();

        // Open + unlock, save settings across both halves.
        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        let settings = crate::vault::manifest::VaultSettings {
            vault_timeout: crate::vault::manifest::VaultTimeout::Minutes(15),
            theme: Some(crate::types::ThemeMode::Dark),
            lang: Some("es".into()),
            default_uri_match: Some(crate::types::UriMatchStrategy::Exact),
            fetch_favicons: Some(false),
            slug: Some("leaky-slug".into()),
            display_name: None,
            subtitle: None,
            avatar_ext: None,
            custom_equivalent_domains: None,
            suggest_app_logins: None,
            trusted_app_packages: None,
            rejected_app_packages: None,
            enrollment_policy: crate::vault::manifest::EnrollmentPolicy::Personal,
            space_invite_authority: Default::default(),
            allow_viewer_export: false,
            guest_enabled: None,
            trash_policy: Default::default(),
            restore_policy: Default::default(),
            join_approval: Default::default(),
            quorum_admin_ops: None,
            collection_create_authority: Default::default(),
        };
        handle.save_settings(&settings).unwrap();

        // Public file is plaintext and contains only theme + lang.
        let pub_str = std::fs::read_to_string(dir.path().join("meta/settings-pub.json")).unwrap();
        assert!(
            pub_str.contains("\"theme\""),
            "public file must contain theme"
        );
        assert!(
            pub_str.contains("\"lang\""),
            "public file must contain lang"
        );
        assert!(
            !pub_str.contains("slug"),
            "slug must NOT be in plaintext public file"
        );
        assert!(!pub_str.contains("enrollment_policy"));
        assert!(!pub_str.contains("fetch_favicons"));

        // Encrypted file is NOT plaintext JSON of those fields.
        let enc_bytes = std::fs::read(dir.path().join("meta/settings.enc")).unwrap();
        let enc_str = String::from_utf8_lossy(&enc_bytes);
        assert!(
            !enc_str.contains("leaky-slug"),
            "slug must be encrypted, not plaintext"
        );
        assert!(!enc_str.contains("enrollment_policy"));

        // Legacy settings.json must be removed after migration.
        assert!(!dir.path().join("meta/settings.json").exists());

        // Re-open and read back: all fields round-trip.
        let read_back = handle.get_settings().unwrap();
        assert_eq!(read_back.theme, Some(crate::types::ThemeMode::Dark));
        assert_eq!(read_back.lang.as_deref(), Some("es"));
        assert_eq!(read_back.slug.as_deref(), Some("leaky-slug"));
        assert_eq!(read_back.fetch_favicons, Some(false));
        assert_eq!(
            read_back.enrollment_policy,
            crate::vault::manifest::EnrollmentPolicy::Personal
        );
    }

    /// Regression: a vault with a legacy plaintext settings.json must migrate
    /// transparently on first get_settings (post-unlock). Nothing lost.
    #[test]
    fn settings_legacy_json_migrates_on_read() {
        let (dir, password) = create_test_vault();

        // Simulate a TRUE pre-split legacy vault: creation always writes the
        // split files now, so drop them — a real legacy vault predates both.
        std::fs::remove_file(dir.path().join("meta/settings.enc")).unwrap();
        std::fs::remove_file(dir.path().join("meta/settings-pub.json")).unwrap();

        // Write a legacy plaintext settings.json with mixed fields.
        let legacy = serde_json::json!({
            "vault_timeout": "OnRestart",
            "theme": "dark",
            "lang": "es",
            "default_uri_match": "exact",
            "fetch_favicons": false,
            "slug": "legacy-vault",
            "enrollment_policy": "Strict",
        });
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(
            dir.path().join("meta/settings.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let mut handle = VaultHandle::open(dir.path()).unwrap();
        handle.unlock(&password).unwrap();

        // Read picks up the legacy values via the fallback path.
        let s = handle.get_settings().unwrap();
        assert_eq!(s.slug.as_deref(), Some("legacy-vault"));
        assert_eq!(s.lang.as_deref(), Some("es"));
        assert_eq!(s.fetch_favicons, Some(false));

        // A save migrates: writes the split files and drops settings.json.
        handle.save_settings(&s).unwrap();
        assert!(dir.path().join("meta/settings-pub.json").exists());
        assert!(dir.path().join("meta/settings.enc").exists());
        assert!(!dir.path().join("meta/settings.json").exists());
    }

    /// Regression: a keystore-less vault with multiple devices and a sealed
    /// device-privkey file must open in locked state and resolve the local device_id.
    #[test]
    fn multi_device_locked_open_with_sealed_devkey_and_no_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let password = "test-password-123!";

        // 1. Create vault (device 1). Creation always persists settings
        // (Personal defaults), so the phrase enrollment below resolves the
        // real policy from settings.enc.
        let (_h, secrets) = creation::VaultCreator::new(path, password, "Desktop")
            .kdf_profile(crate::types::KdfProfile::MobileLow)
            .execute()
            .unwrap();

        // 2. Enroll device 2 with recovery phrase
        let (x25519_secret, x25519_public) = crate::crypto::hpke_wrap::generate_x25519_keypair();
        let (ed25519_signing, ed25519_verifying) =
            crate::crypto::signature::generate_ed25519_keypair();
        let dev2_id = Uuid::new_v4();
        let payload = crate::device_manager::EnrollmentPayload {
            device_id: dev2_id,
            encryption_public_key: hex::encode(x25519_public.to_bytes()),
            signing_public_key: hex::encode(crate::crypto::signature::verifying_key_bytes(
                &ed25519_verifying,
            )),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            nonce: hex::encode([1u8; 32]),
            name: "Mobile".into(),
            vault_id: None,
            epoch: None,
            registry_version: None,
        };

        let mut dm = DeviceManager::load_from_vault(path).unwrap();
        let res = dm
            .enroll_with_recovery_phrase(
                &payload,
                &secrets.recovery_phrase.phrase(),
                x25519_secret,
                ed25519_signing,
            )
            .unwrap();

        // Write device 2's device-privkey.json as sealed file with device 2's keys
        let kek =
            crate::crypto::kdf::derive_kek(password, &VaultHandle::open(path).unwrap().kdf_params)
                .unwrap();
        let devkey_seal = crate::crypto::hkdf_derive::derive_devkey_seal_key(&kek).unwrap();
        let privkey_json = serde_json::json!({
            "device_id": dev2_id.to_string(),
            "x25519_private": hex::encode(res.x25519_secret.to_bytes()),
            "ed25519_private": hex::encode(res.ed25519_signing.to_bytes()),
        });
        crate::vault::device_privkey::seal_file(
            &path.join("meta/device-privkey.json"),
            &privkey_json.to_string(),
            &devkey_seal,
            Some(dev2_id),
        )
        .unwrap();

        // Verify meta/keywrap has 2 files
        let kw_count = std::fs::read_dir(path.join("meta/keywrap"))
            .unwrap()
            .count();
        assert_eq!(kw_count, 2);

        // Verify file is sealed
        assert_eq!(
            crate::vault::device_privkey::file_kind(&path.join("meta/device-privkey.json")),
            crate::vault::device_privkey::PrivkeyFileKind::Sealed
        );

        // 3. Open locked vault — must find device 2 without password or keyring
        let mut handle = VaultHandle::open(path).unwrap();
        assert_eq!(handle.device_id, dev2_id);

        // 4. Unlock vault
        handle.unlock(password).unwrap();
        assert!(handle.is_unlocked());

        // 5. Test F1 self-healing: spoof meta/device-id with device 1's ID
        handle.lock();
        let dev1_id = secrets.device_id;
        crate::vault::device_privkey::write_device_id(path, dev1_id).unwrap();

        // Re-open: fast path selects dev1_id initially
        let mut handle2 = VaultHandle::open(path).unwrap();
        assert_eq!(handle2.device_id, dev1_id);

        // Unlock should heal and succeed by falling back to dev2_id
        handle2.unlock(password).unwrap();
        assert!(handle2.is_unlocked());
        assert_eq!(handle2.device_id, dev2_id);

        // Verify meta/device-id was corrected
        assert_eq!(
            crate::vault::device_privkey::read_device_id(path),
            Some(dev2_id)
        );
    }

    /// P8c-2: the invite's transport username rides the approval into the
    /// member record, so offboarding can strike the seat later.
    #[test]
    fn approve_join_records_transport_username() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().join("owner");
        let (mut handle, _secrets) =
            crate::vault::creation::VaultCreator::new(&owner, "owner-pass", "OwnerDevice")
                .kdf_profile(crate::types::KdfProfile::MobileLow)
                .initialize_git(true)
                .execute()
                .unwrap();
        handle.unlock("owner-pass").unwrap();
        let code = handle
            .invite_create(
                crate::vault::members::MemberRole::Editor,
                Some("gituser".into()),
            )
            .unwrap();
        // The invite record must be committed so the joiner's clone
        // carries it (same flow as the S1a-2 ceremony).
        let owner_seal = handle.devkey_seal();
        let engine_o = crate::sync::engine::SyncEngine::new(
            &owner,
            &handle.device_id.to_string(),
            owner_seal.as_ref(),
        );
        let repo_o = engine_o.open_repo().unwrap();
        engine_o.commit_all(&repo_o, "invite").unwrap();

        let joiner = temp.path().join("joiner");
        git2::Repository::clone(owner.to_str().unwrap(), &joiner).unwrap();
        let intro_code =
            crate::vault::members::create_introduction(&joiner, &code, "member-pass", "Joiner")
                .unwrap();
        let member_id = handle.approve_join(&intro_code).unwrap();
        let row = crate::vault::members::member_file_by_id(&owner, member_id).unwrap();
        assert_eq!(row.transport_username.as_deref(), Some("gituser"));
    }
}
