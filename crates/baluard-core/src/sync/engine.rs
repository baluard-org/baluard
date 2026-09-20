//! Git sync engine: real git2-rs operations for vault synchronization.
//!
//! Handles: repo init, commit, push, pull, clone, commit signing.
//! D9: Static "vault update" commit messages.
//! D12: Transactional 8-state machine.
//! D11: Shallow clone by default, auto-unshallow on conflict.

#[cfg(feature = "git-sync")]
use git2::build::RepoBuilder;
#[cfg(feature = "git-sync")]
use git2::{FetchOptions, Oid, PushOptions, Repository, Signature};

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use crate::error::{BaluardError, SyncError};
use crate::sync::commit::COMMIT_MESSAGE;
use crate::sync::credentials::CredentialConfig;
use crate::sync::state_machine::{SyncState, SyncStateMachine};

use base64::Engine;

/// Git sync engine wrapping git2-rs operations.
/// Device roster for one commit: device UUID → Ed25519 verifying key bytes.
type DeviceRoster = std::collections::BTreeMap<String, [u8; 32]>;
/// S1a: resolved member state per commit: device UUID -> role, plus
/// device UUID -> member id (drives {member} path segments).
#[derive(Debug, Clone)]
struct MemberSnapshot {
    roles: std::collections::BTreeMap<String, crate::sync::policy::CommitRole>,
    member_of: std::collections::BTreeMap<String, String>,
}
#[cfg(feature = "git-sync")]
pub struct SyncEngine {
    /// Path to the vault directory (= git workdir).
    pub vault_path: PathBuf,
    /// Local device UUID (string form). Used to find this device's registry
    /// entry for the pre-stage `last_seen_epoch` bump (C5: entries are keyed
    /// by id, never by display name — names are stripped from the
    /// git-tracked devices.json and live encrypted in settings.enc).
    /// Callers without a device id pass a placeholder; the bump is
    /// best-effort and silently no-ops on a non-UUID string.
    pub device_id: String,
    /// Whether this is a shallow clone.
    pub shallow: bool,
    /// Last-known remote HEAD OID (for pull verification).
    /// Stored in meta/sync-head.json outside the repo.
    pub last_remote_head: Option<String>,
    /// Credential configuration for SSH/HTTPS auth.
    pub credential_config: CredentialConfig,
    /// Transactional state machine (persisted to meta/sync-state.json).
    /// RefCell for interior mutability (pull/push take &self for git2 borrow reasons).
    pub state_machine: RefCell<SyncStateMachine>,
    /// Device Ed25519 signing key (loaded from meta/device-privkey.json).
    /// Used to sign all commits. None = signing disabled: on an enrolled
    /// vault (meta/devices.json present) commit creation fails closed
    /// (UnsignedCommitRefused); only pre-enrollment local vaults fall back
    /// to unsigned local commits.
    signing_key: Option<ed25519_dalek::SigningKey>,
}

/// Fetch progress for a clone operation, surfaced from git2's
/// `transfer_progress` callback. Cloned (cheap) into the daemon's job state
/// so the desktop can render a live progress bar.
#[derive(Clone, Copy, Debug, Default)]
pub struct CloneProgress {
    /// Objects received so far.
    pub objects_received: usize,
    /// Total objects the server announced (may grow during fetch).
    pub total_objects: usize,
    /// Raw bytes received.
    pub bytes_received: usize,
    /// Deltas indexed so far.
    pub indexed_deltas: usize,
    /// Total deltas to index.
    pub total_deltas: usize,
}

#[cfg(feature = "git-sync")]
impl SyncEngine {
    /// Create a new SyncEngine for a vault at the given path.
    /// Loads persisted state machine from disk if available.
    ///
    /// `devkey_seal` opens the sealed `meta/device-privkey.json` (C1) for
    /// commit signing. Pass the subkey from the unlocked handle when
    /// available; `None` falls back to the OS keyring (and legacy plaintext
    /// files) — a sealed file without a key means unsigned commits.
    /// Test/multi-device fixture helper: override the signing key loaded
    /// from the (single, per-vault) privkey file. Production devices each
    /// hold their own key material; a shared-directory simulation needs
    /// per-engine keys to sign as distinct devices.
    #[cfg(test)]
    pub(crate) fn with_signing_key(mut self, key: ed25519_dalek::SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    pub fn new(vault_path: &Path, device_id: &str, devkey_seal: Option<&[u8; 32]>) -> Self {
        let last_remote_head = Self::load_last_head(vault_path);
        let credential_config = CredentialConfig::load(vault_path);
        let state_machine = RefCell::new(SyncStateMachine::load_from_file(vault_path));
        // Load signing key — log warning on corrupt file but don't fail
        let signing_key = match Self::load_signing_key(vault_path, devkey_seal) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("warning: failed to load signing key: {e}");
                None
            }
        };
        if let Some(ref key) = signing_key {
            Self::warn_on_signing_key_mismatch(vault_path, device_id, key);
        }
        Self {
            vault_path: vault_path.to_path_buf(),
            device_id: device_id.to_string(),
            shallow: true,
            last_remote_head,
            credential_config,
            state_machine,
            signing_key,
        }
    }

    /// Transition the state machine to a new state and persist.
    fn transition_state(&self, target: SyncState) -> Result<(), BaluardError> {
        let mut sm = self.state_machine.borrow_mut();
        sm.transition(target).map_err(SyncError::StateMachine)?;
        sm.save_to_file(&self.vault_path)
            .map_err(SyncError::StateMachine)?;
        Ok(())
    }

    /// Check for stale state on startup and recover if needed.
    pub fn recover_state(&self) -> Result<(), BaluardError> {
        let mut sm = self.state_machine.borrow_mut();
        if sm.current == SyncState::Idle {
            return Ok(());
        }

        if sm.check_pending_timeout().is_some() {
            sm.evict_stale_pending();
        } else {
            sm.current = SyncState::Idle;
            sm.operation_id += 1;
            sm.pending_ciphers.clear();
            sm.pending_since = None;
        }

        sm.save_to_file(&self.vault_path)
            .map_err(SyncError::StateMachine)?;
        Ok(())
    }

    /// Initialize a git repo in the vault directory.
    /// Creates `.gitignore`, makes initial commit.
    pub fn init_repo(&self) -> Result<Repository, BaluardError> {
        let repo =
            Repository::init(&self.vault_path).map_err(|e| SyncError::Git(format!("init: {e}")))?;

        // Set generic git author to prevent identity correlation via git log
        let mut config = repo
            .config()
            .map_err(|e| SyncError::Git(format!("failed to open local git config: {e}")))?;
        if let Err(e) = config.set_str("user.name", "Baluard User") {
            return Err(BaluardError::Sync(SyncError::Git(format!(
                "failed to set local git user.name: {e}"
            ))));
        }
        if let Err(e) = config.set_str("user.email", "vault@baluard.local") {
            return Err(BaluardError::Sync(SyncError::Git(format!(
                "failed to set local git user.email: {e}"
            ))));
        }

        // Write .gitignore
        let gitignore = self.vault_path.join(".gitignore");
        if !gitignore.exists() {
            std::fs::write(&gitignore, GITIGNORE_CONTENT)
                .map_err(|e| SyncError::Git(format!("write .gitignore: {e}")))?;
        }

        // Initial commit
        self.commit_all(&repo, "initial vault setup")?;

        Ok(repo)
    }

    /// Open an existing repo at the vault path.
    pub fn open_repo(&self) -> Result<Repository, BaluardError> {
        let repo = Repository::open(&self.vault_path)
            .map_err(|e| BaluardError::Sync(SyncError::Git(format!("open: {e}"))))?;
        // Refresh .gitignore if it predates the sync-head/sync-state/.baluard
        // entries. status() filters these paths regardless, so this is cosmetic
        // (keeps `git status` on the CLI honest too) rather than load-bearing.
        self.refresh_gitignore();
        // P5b: the cipher index is local-only (gitignored, rebuilt from
        // ciphers on demand). Repos that still track meta/index.enc drop it
        // from the git index here — the disk file stays, history stays, but
        // the per-CRUD rewrite stops riding every commit and conflicting on
        // every concurrent multi-device sync. Best-effort: a failure here is
        // the pre-P5b behavior, not a break.
        let untrack = || -> Result<(), BaluardError> {
            let mut idx = repo
                .index()
                .map_err(|e| SyncError::Git(format!("index: {e}")))?;
            if idx
                .get_path(std::path::Path::new("meta/index.enc"), 0)
                .is_some()
            {
                idx.remove_path(std::path::Path::new("meta/index.enc"))
                    .map_err(|e| SyncError::Git(format!("untrack index: {e}")))?;
                idx.write()
                    .map_err(|e| SyncError::Git(format!("untrack index write: {e}")))?;
            }
            Ok(())
        };
        if let Err(e) = untrack() {
            eprintln!("warning: could not untrack meta/index.enc: {e}");
        }
        Ok(repo)
    }

    /// Rewrite .gitignore from the current const if any new entry is missing.
    /// Best-effort: logs a warning on failure.
    fn refresh_gitignore(&self) {
        let gitignore = self.vault_path.join(".gitignore");
        const NEW_ENTRIES: &[&str] = &[
            "meta/sync-head.json",
            "meta/sync-state.json",
            // S1a-2: per-member unlock material is device-local.
            "meta/member-unlock.json",
            // P5b: the cipher index is local-only bookkeeping.
            "meta/index.enc",
            "meta/index.enc.*",
            // P8b: local revocation verification tracker.
            "meta/revocations-verified.json",
        ];
        let needs_update = match std::fs::read_to_string(&gitignore) {
            Ok(existing) => NEW_ENTRIES.iter().any(|e| !existing.contains(e)),
            Err(_) => true,
        };
        if needs_update {
            if let Err(e) = std::fs::write(&gitignore, GITIGNORE_CONTENT) {
                eprintln!("warning: failed to refresh .gitignore: {e}");
            }
        }
    }

    /// Stage all changes and commit with static message (D9).
    /// Returns the new commit OID.
    pub fn commit_all(
        &self,
        repo: &Repository,
        _message_override: &str,
    ) -> Result<Oid, BaluardError> {
        // Bump this device's last_seen_epoch on `meta/devices.json` BEFORE
        // staging. devices.json is git-tracked, so rewriting it after the tree
        // is captured would leave the worktree dirty and the sync badge stuck
        // on "Changes pending" after every commit. Pre-stage lands it in the
        // commit and keeps the tree clean.
        self.bump_device_epoch();

        let mut index = repo
            .index()
            .map_err(|e| SyncError::Git(format!("index: {e}")))?;

        // Stage everything
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .map_err(|e| SyncError::Git(format!("add_all: {e}")))?;
        index
            .write()
            .map_err(|e| SyncError::Git(format!("index write: {e}")))?;

        let tree_id = index
            .write_tree()
            .map_err(|e| SyncError::Git(format!("write_tree: {e}")))?;
        let tree = repo
            .find_tree(tree_id)
            .map_err(|e| SyncError::Git(format!("find_tree: {e}")))?;

        let sig = Signature::now("Baluard User", "vault@baluard.local")
            .map_err(|e| SyncError::Git(format!("signature: {e}")))?;

        // Check for existing HEAD
        let parent_commits: Vec<_> = match repo.head() {
            Ok(head) => {
                let commit = head
                    .peel_to_commit()
                    .map_err(|e| SyncError::Git(format!("head commit: {e}")))?;
                vec![commit]
            }
            Err(_) => vec![], // Initial commit, no parent
        };

        let parents: Vec<_> = parent_commits.iter().collect();
        let commit_id = match self.create_signed_commit(repo, &sig, COMMIT_MESSAGE, &tree, &parents)
        {
            Ok(id) => id,
            Err(e) => {
                // Refusal/rollback path: restore the index to HEAD so the
                // staged residue can't poison the next pull's force-checkout
                // or a retry after the signing key becomes available.
                // reset_default with an empty pathspec is a no-op in git2-rs,
                // so read the HEAD tree back into the index instead.
                // Best-effort: the original error is what propagates.
                if let Ok(head) = repo.head() {
                    if let Ok(head_commit) = head.peel_to_commit() {
                        if let Ok(head_tree) = head_commit.tree() {
                            if let Ok(mut index) = repo.index() {
                                if index.read_tree(&head_tree).is_ok() {
                                    let _ = index.write();
                                }
                            }
                        }
                    }
                }
                return Err(e);
            }
        };
        // Record device activity (gitignored file) with the new commit sha.
        self.record_device_activity(&commit_id.to_string());
        // Update HEAD to point to the new commit
        let branch = Self::resolve_default_branch(repo);
        repo.reference(
            &format!("refs/heads/{branch}"),
            commit_id,
            true,
            "vault update",
        )
        .map_err(|e| SyncError::Git(format!("update HEAD: {e}")))?;
        repo.set_head(&format!("refs/heads/{branch}"))
            .map_err(|e| SyncError::Git(format!("set head: {e}")))?;

        Ok(commit_id)
    }

    /// Create a cover commit (no-op) to mask real usage patterns.
    ///
    /// Creates a commit with the same tree as HEAD (no file changes).
    /// Indistinguishable from a real vault update where nothing changed.
    /// Uses the same static message and signing as real commits.
    pub fn cover_commit(&self, repo: &Repository) -> Result<Oid, BaluardError> {
        // Same tree as current HEAD, creates an empty commit
        self.commit_all(repo, "")
    }

    /// Apply random jitter delay before a network operation.
    ///
    /// Defends against T3 timing analysis by git remote adversary.
    /// Delay is uniformly random in [0, max_delay_secs].
    /// Uses CSPRNG for delay selection.
    pub fn jitter_delay(max_delay_secs: u64) {
        if max_delay_secs == 0 {
            return;
        }
        // CSPRNG-backed uniform delay selection
        let rand_val: u64 = rand::random();
        let delay_ms = (rand_val % (max_delay_secs * 1000)) as u64;
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }

    /// Push with timing jitter to mask usage patterns.
    pub fn push_with_jitter(
        &self,
        repo: &Repository,
        remote_name: &str,
        max_delay_secs: u64,
    ) -> Result<(), BaluardError> {
        Self::jitter_delay(max_delay_secs);
        self.push(repo, remote_name)
    }

    /// Pull with timing jitter to mask usage patterns.
    pub fn pull_with_jitter(
        &self,
        repo: &Repository,
        remote_name: &str,
        max_delay_secs: u64,
    ) -> Result<PullResult, BaluardError> {
        Self::jitter_delay(max_delay_secs);
        self.pull(repo, remote_name)
    }

    /// Check if the working tree has uncommitted changes.
    pub fn status(&self, repo: &Repository) -> Result<WorkTreeStatus, BaluardError> {
        let statuses = repo
            .statuses(None)
            .map_err(|e| SyncError::Git(format!("statuses: {e}")))?;

        // Local-only engine bookkeeping that must never count as "dirty".
        // These are rewritten outside the commit cycle (push saves sync-head,
        // the state machine saves sync-state on every transition); even with
        // .gitignore + the open_repo untrack migration, an older vault may
        // still have them tracked in HEAD until the next commit lands the
        // removal. Filtering them here keeps the sync badge honest in the
        // window between migration and next sync.
        const LOCAL_ONLY: &[&str] = &[
            "meta/sync-head.json",
            "meta/sync-state.json",
            // P5b: untracking meta/index.enc on open shows a staged deletion
            // against HEAD until the next commit — filter it from the dirty
            // report like the other local-only bookkeeping. Shard files
            // (index.enc.sN) need prefix matching, not exact.
            "meta/index.enc",
            // P8b: local revocation verification tracker.
            "meta/revocations-verified.json",
        ];
        const LOCAL_ONLY_PREFIX: &str = "meta/index.enc.";

        let mut result = WorkTreeStatus::default();
        for entry in statuses.iter() {
            let path = std::str::from_utf8(entry.path_bytes()).unwrap_or("");
            if LOCAL_ONLY.contains(&path) || path.starts_with(LOCAL_ONLY_PREFIX) {
                continue;
            }
            let s = entry.status();
            if s.is_index_new() || s.is_index_modified() || s.is_index_deleted() {
                result.staged += 1;
            }
            if s.is_wt_new() || s.is_wt_modified() || s.is_wt_deleted() {
                result.unstaged += 1;
            }
        }
        Ok(result)
    }

    /// Get recent commit history (last N commits).
    pub fn log(&self, repo: &Repository, limit: usize) -> Result<Vec<CommitInfo>, BaluardError> {
        let head = repo
            .head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let start = head
            .peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel: {e}")))?;

        let mut commits = Vec::new();
        let mut current = Some(start);

        while let Some(c) = current.take() {
            if commits.len() >= limit {
                break;
            }
            commits.push(CommitInfo {
                id: c.id().to_string(),
                message: c.message().unwrap_or("").to_string(),
                author: c.author().name().unwrap_or("unknown").to_string(),
                time: c.time().seconds(),
            });
            current = c.parent(0).ok();
        }

        Ok(commits)
    }

    // ── Remote operations ──

    /// Add a remote URL.
    pub fn add_remote(
        &self,
        _repo: &Repository,
        name: &str,
        url: &str,
    ) -> Result<(), BaluardError> {
        validate_git_url(url)?;
        _repo
            .remote(name, url)
            .map_err(|e| SyncError::Git(format!("remote add: {e}")))?;
        Ok(())
    }

    /// Resolve the default branch name for the local repo.
    /// Tries HEAD symref first, falls back to "main".
    pub fn resolve_default_branch(repo: &Repository) -> String {
        // Check local HEAD first
        if let Ok(head) = repo.head() {
            if let Some(shorthand) = head.shorthand() {
                return shorthand.to_string();
            }
        }
        // Fallback: check refs/heads/main, then refs/heads/master
        if repo.find_reference("refs/heads/main").is_ok() {
            return "main".to_string();
        }
        if repo.find_reference("refs/heads/master").is_ok() {
            return "master".to_string();
        }
        // Default
        "main".to_string()
    }

    /// Enrolled-vault test for the unsigned-commit refusal: the registry
    /// must be present in the commit's first-parent tree (or in the new
    /// tree itself for the initial commit). The WORKTREE copy is deliberately
    /// ignored: it is mutable state a local process can delete.
    fn commit_line_is_enrolled(
        _repo: &Repository,
        tree: &git2::Tree<'_>,
        parents: &[&git2::Commit<'_>],
    ) -> bool {
        let has_registry = |t: &git2::Tree| {
            t.get_path(std::path::Path::new("meta/devices.json"))
                .is_ok()
        };
        // Enrolled if the registry is in the new tree (root or genesis
        // enrollment commit) OR in the first parent's tree (established
        // line). Mirrors roster_for_commit's genesis rule: an enrollment
        // commit must be signed even though its parent predates the
        // registry.
        if has_registry(tree) {
            return true;
        }
        if let Some(first) = parents.first() {
            if let Ok(parent_tree) = first.tree() {
                return has_registry(&parent_tree);
            }
        }
        false
    }

    /// Create a commit with Ed25519 signature embedded in the git object.
    /// Uses commit_create_buffer + commit_signed. On an enrolled vault
    /// (meta/devices.json present) a missing signing key is a hard error —
    /// unsigned commits are never created (P2). Pre-enrollment local vaults
    /// (no registry yet) keep the unsigned local path.
    fn create_signed_commit(
        &self,
        repo: &Repository,
        sig: &Signature<'_>,
        message: &str,
        tree: &git2::Tree<'_>,
        parents: &[&git2::Commit<'_>],
    ) -> Result<Oid, BaluardError> {
        if let Some(ref signing_key) = self.signing_key {
            let buf = repo
                .commit_create_buffer(sig, sig, message, tree, parents)
                .map_err(|e| SyncError::Git(format!("commit buffer: {e}")))?;
            let raw = buf
                .as_str()
                .ok_or_else(|| SyncError::Git("commit buffer not UTF-8".into()))?;
            let ed_sig = crate::crypto::signature::sign(signing_key, raw.as_bytes())
                .map_err(|e| SyncError::Git(format!("sign: {e}")))?;
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes());
            let sig_field = format!(
                "-----BEGIN BALUARD SIGNATURE-----\n{sig_b64}\n-----END BALUARD SIGNATURE-----"
            );
            let oid = repo
                .commit_signed(raw, &sig_field, None)
                .map_err(|e| SyncError::Git(format!("commit_signed: {e}")))?;
            Ok(oid)
        } else if Self::commit_line_is_enrolled(repo, tree, parents) {
            // Enrolled vault (registry in the parent tree, or in this tree
            // for the initial commit): refuse to create an unsigned commit —
            // checked against TREES, not the mutable worktree, so deleting
            // meta/devices.json locally cannot downgrade this vault to
            // unsigned commits (P2).
            Err(SyncError::UnsignedCommitRefused.into())
        } else {
            let oid = repo
                .commit(Some("HEAD"), sig, sig, message, tree, parents)
                .map_err(|e| SyncError::Git(format!("commit: {e}")))?;
            Ok(oid)
        }
    }
    /// Collect all commits between `ancestor` (exclusive) and `descendant`
    /// (inclusive) for signature verification. Walks ALL parents of merge
    /// commits (peer review fix for C2 residual: previously first-parent
    /// only, which let smuggled second-parent commits bypass verification).
    ///
    /// Termination is anchored to `local_oid` (local HEAD), not just the
    /// single `ancestor` OID. If a lineage walks back into any commit
    /// reachable from local HEAD, it's trusted and the BFS stops there.
    /// This prevents the regression where a side branch that forked
    /// *before* the merge base would walk to a root and return a
    /// misleading "shallow clone" error.
    ///
    /// Returns error if walk terminates before reaching any trusted
    /// commit (shallow clone gap).
    fn collect_commit_range(
        repo: &Repository,
        local_oid: Oid,
        ancestor: Oid,
        descendant: Oid,
    ) -> Result<Vec<Oid>, BaluardError> {
        use std::collections::HashSet;
        let mut oids = Vec::new();
        let mut visited: HashSet<Oid> = HashSet::new();
        // BFS frontier. Start with the descendant; we explore its parents
        // until we reach a trusted commit (local HEAD or any of its
        // ancestors, OR the explicit merge-base ancestor).
        let mut frontier: Vec<Oid> = vec![descendant];
        while let Some(current) = frontier.pop() {
            // Stop at the explicit merge base or any commit in local's
            // trusted history. The `ancestor` check is kept for the common
            // case where the merge base is on the first-parent lineage
            // (the fast-forward path); the `graph_descendant_of` check
            // covers side branches that reconverge into local history
            // before the merge base.
            if current == ancestor
                || repo
                    .graph_descendant_of(local_oid, current)
                    .unwrap_or(false)
            {
                continue;
            }
            if !visited.insert(current) {
                continue; // already explored
            }
            oids.push(current);
            let commit = repo
                .find_commit(current)
                .map_err(|e| SyncError::Git(format!("walk: {e}")))?;
            let parent_count = commit.parent_count();
            if parent_count == 0 {
                return Err(SyncError::Git(
                    "shallow clone prevents full signature verification: history truncated".into(),
                )
                .into());
            }
            // PR-60: propagate parent_id errors instead of silently
            // skipping. A skipped parent is a lineage that is never
            // signature-checked — a narrow bypass on corrupt/crafted
            // objects. The pre-fix code used .unwrap().
            for i in 0..parent_count {
                let p = commit
                    .parent_id(i)
                    .map_err(|e| SyncError::Git(format!("parent {i}: {e}")))?;
                if !visited.contains(&p) {
                    frontier.push(p);
                }
            }
        }
        Ok(oids)
    }

    /// Resolve the default branch name from a remote's HEAD symref.
    /// Must be called after fetch() so remote refs are available.
    pub fn resolve_remote_branch(repo: &Repository, remote_name: &str) -> String {
        // Try refs/remotes/{remote}/HEAD symbolic ref
        let symref_path = format!("refs/remotes/{remote_name}/HEAD");
        if let Ok(symref) = repo.find_reference(&symref_path) {
            if let Some(target) = symref.symbolic_target() {
                // target is like "refs/remotes/origin/main"
                if let Some(branch) = target.rsplit('/').next() {
                    return branch.to_string();
                }
            }
        }
        // Try common branch names on the remote
        for candidate in &["main", "master"] {
            let ref_path = format!("refs/remotes/{remote_name}/{candidate}");
            if repo.find_reference(&ref_path).is_ok() {
                return candidate.to_string();
            }
        }
        // Fallback
        "main".to_string()
    }

    /// Resolve this device's id + current epoch from the registry/epoch.json.
    /// Best-effort: returns None if the registry or epoch is unavailable.
    fn device_id_and_epoch(&self) -> Option<(uuid::Uuid, u64)> {
        let device_id = self.device_id.parse::<uuid::Uuid>().ok()?;
        let reg_path = self.vault_path.join("meta/devices.json");
        let reg = std::fs::read_to_string(&reg_path)
            .ok()
            .and_then(|data| serde_json::from_str::<crate::devices::DeviceRegistry>(&data).ok())?;
        if !reg.devices.contains_key(&device_id) {
            return None;
        }
        let epoch_path = self.vault_path.join("meta/epoch.json");
        let epoch = std::fs::read_to_string(&epoch_path)
            .ok()
            .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
            .and_then(|v| v["epoch"].as_u64())
            .unwrap_or(0);
        Some((device_id, epoch))
    }

    /// Bump `last_seen_epoch` on this device's registry entry.
    ///
    /// MUST run BEFORE staging (`add_all`) in `commit_all`: `meta/devices.json`
    /// is git-tracked, so rewriting it after the commit tree is snapshotted
    /// leaves the worktree dirty and the sync badge stuck on "Changes pending"
    /// immediately after every sync. Running it pre-stage lands the update in
    /// the same commit and leaves the tree clean. Best-effort: logs a warning
    /// on failure, does not fail the commit.
    fn bump_device_epoch(&self) {
        let Some((device_id, epoch)) = self.device_id_and_epoch() else {
            return;
        };
        let reg_path = self.vault_path.join("meta/devices.json");
        let Ok(data) = std::fs::read_to_string(&reg_path) else {
            return;
        };
        let Ok(mut reg) = serde_json::from_str::<crate::devices::DeviceRegistry>(&data) else {
            return;
        };
        if let Some(entry) = reg.devices.get_mut(&device_id) {
            entry.last_seen_epoch = epoch;
        }
        // P5a: deterministic serialization + skip-if-unchanged. devices.json
        // is git-tracked and shared by every device; rewriting it with
        // reordered (HashMap-serialized) or unchanged content churned the
        // file on every commit from a different process — a guaranteed
        // multi-writer conflict on the one file all devices touch. When the
        // bytes are identical the commit carries no devices.json delta.
        let Ok(json) = reg.to_deterministic_json() else {
            return;
        };
        if json == data {
            return;
        }
        let tmp_path = reg_path.with_file_name(format!(
            "{}.tmp",
            reg_path.file_name().unwrap_or_default().to_string_lossy()
        ));
        if std::fs::write(&tmp_path, &json).is_ok() {
            let _ = std::fs::rename(&tmp_path, &reg_path);
        }
    }

    /// Record this device's activity (last push timestamp + commit sha) in the
    /// activity index. `meta/device_activity.json` is gitignored, so writing it
    /// post-commit does NOT dirty the worktree. Best-effort.
    fn record_device_activity(&self, commit_sha: &str) {
        use crate::device_manager::DeviceActivityIndex;
        let Some((device_id, epoch)) = self.device_id_and_epoch() else {
            return;
        };
        if let Err(e) = DeviceActivityIndex::update(&self.vault_path, &device_id, commit_sha, epoch)
        {
            eprintln!("warning: failed to update activity index: {e}");
        }
    }

    /// Check for abort markers after pulling from another device.
    /// Returns the aborted epoch if a marker was found, None otherwise.
    /// Caller (daemon) should check this after pull and surface to user.
    pub fn check_abort_marker(&self) -> Option<u64> {
        // Read current epoch from epoch.json
        let epoch_path = self.vault_path.join("meta/epoch.json");
        let data = std::fs::read_to_string(&epoch_path).ok()?;
        let val: serde_json::Value = serde_json::from_str(&data).ok()?;
        let epoch = val["epoch"].as_u64()?;

        // Check if new_epoch (epoch + 1) has an abort marker
        let new_epoch = epoch + 1;
        let abort_path = self
            .vault_path
            .join(format!("meta/rekey/{new_epoch}.aborted"));
        if abort_path.exists() {
            return Some(new_epoch);
        }
        None
    }

    /// Get the remote URL (defaults to "origin").
    pub fn get_remote_url(&self, repo: &Repository, name: &str) -> Result<String, BaluardError> {
        let remote = repo
            .find_remote(name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;
        let url = remote
            .url()
            .ok_or_else(|| SyncError::Git("remote has no URL".into()))?;
        Ok(url.to_string())
    }

    /// True if the repo has a configured `origin` remote (i.e. sync is set up).
    /// Cheap existence check used by the auto-sync coordinator to decide
    /// whether to activate on unlock without running a full status.
    pub fn has_remote(repo: &Repository) -> Result<bool, BaluardError> {
        Ok(repo
            .find_remote("origin")
            .map(|r| r.url().is_some())
            .unwrap_or(false))
    }

    /// Remove a remote by name.
    pub fn remove_remote(&self, repo: &Repository, name: &str) -> Result<(), BaluardError> {
        repo.remote_delete(name)
            .map_err(|e| SyncError::Git(format!("remote delete '{name}': {e}")))?;
        Ok(())
    }

    /// True when the on-disk sync state machine is not Idle (a cycle is
    /// mid-flight from a previous process, or a conflict is paused).
    pub fn sync_state_busy(&self) -> bool {
        self.state_machine.borrow().current != SyncState::Idle
    }

    /// Locked background pull (mobile background sync, plan-mobile §3.5):
    /// fetch remote objects ONLY — no checkout, no merge, no commit, no state
    /// transition, no decryption. Safe with a locked vault: nothing decrypts
    /// or moves HEAD/worktree. The next unlock's pull (commit→pull→push cycle)
    /// finds the fetched objects locally and completes fast; conflicts are
    /// resolved by the normal foreground flow. Refuses when the state machine
    /// is not Idle (a paused conflict or mid-cycle state must not race a fetch).
    pub fn fetch_locked(&self, repo: &Repository, remote_name: &str) -> Result<bool, BaluardError> {
        if self.sync_state_busy() {
            return Err(BaluardError::Sync(SyncError::Git(
                "locked fetch refused: sync state machine not idle".into(),
            )));
        }
        let mut remote = repo
            .find_remote(remote_name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;
        let mut fetch_opts = FetchOptions::new();
        let callbacks = crate::sync::credentials::build_callbacks(&self.credential_config);
        fetch_opts.remote_callbacks(callbacks);
        let refspec = format!("refs/heads/*:refs/remotes/{remote_name}/*");
        remote
            .fetch(&[&refspec], Some(&mut fetch_opts), None)
            .map_err(|e| classify_remote_err("fetch", &e))?;

        // Up-to-date check on refs only (no graph walk of the worktree).
        let remote_branch = Self::resolve_remote_branch(repo, remote_name);
        let remote_head = repo
            .find_reference(&format!("refs/remotes/{remote_name}/HEAD"))
            .or_else(|_| {
                repo.find_reference(&format!("refs/remotes/{remote_name}/{remote_branch}"))
            })
            .map_err(|e| SyncError::Git(format!("find remote HEAD: {e}")))?;
        let r_oid = remote_head
            .peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel remote: {e}")))?
            .id();
        let l_oid = repo
            .head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?
            .peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel local: {e}")))?
            .id();
        Ok(r_oid != l_oid)
    }

    /// Push to remote. Uses "origin" by default.
    pub fn push(&self, repo: &Repository, remote_name: &str) -> Result<(), BaluardError> {
        let mut remote = repo
            .find_remote(remote_name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

        // Resolve local branch dynamically
        let branch = Self::resolve_default_branch(repo);
        let refname = format!("refs/heads/{branch}");

        // Push to matching branch name on remote
        let push_refspec = format!("{refname}:refs/heads/{branch}");

        let mut push_options = PushOptions::new();
        let callbacks = crate::sync::credentials::build_callbacks(&self.credential_config);
        push_options.remote_callbacks(callbacks);

        remote
            .push(&[&push_refspec], Some(&mut push_options))
            .map_err(|e| classify_remote_err("push", &e))?;

        // Track local HEAD OID for rollback detection
        let pushed_oid = repo
            .head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?
            .peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel: {e}")))?
            .id();
        self.save_last_head(&pushed_oid.to_string())?;

        Ok(())
    }

    /// Pull from remote: fetch + merge (with "ours" strategy for non-conflicting merges).
    /// Transitions state machine: Idle → Pulling → Merging → [Encrypting → Committing →] Idle.
    pub fn pull(&self, repo: &Repository, remote_name: &str) -> Result<PullResult, BaluardError> {
        // State: Idle → Pulling
        self.transition_state(SyncState::Pulling)?;

        let result = self.pull_inner(repo, remote_name);
        if result.is_err() {
            // Reset state machine on any error to avoid stuck non-Idle state
            let mut sm = self.state_machine.borrow_mut();
            sm.current = SyncState::Idle;
            sm.operation_id += 1;
            sm.pending_ciphers.clear();
            sm.pending_since = None;
            let _ = sm.save_to_file(&self.vault_path);
        }
        result
    }

    /// Inner pull implementation (state machine transitions for Merging/Idle done here).
    /// State machine must be in Pulling state. Does NOT take &mut self for transition_state.
    fn pull_inner(&self, repo: &Repository, remote_name: &str) -> Result<PullResult, BaluardError> {
        // Fetch (scoped to release credential borrow before state transitions)
        let (remote_oid, local_oid) = {
            let mut remote = repo
                .find_remote(remote_name)
                .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

            let mut fetch_opts = FetchOptions::new();
            let callbacks = crate::sync::credentials::build_callbacks(&self.credential_config);
            fetch_opts.remote_callbacks(callbacks);

            let refspec = format!("refs/heads/*:refs/remotes/{remote_name}/*");
            remote
                .fetch(&[&refspec], Some(&mut fetch_opts), None)
                .map_err(|e| classify_remote_err("fetch", &e))?;

            // Resolve remote branch dynamically
            let remote_branch = Self::resolve_remote_branch(repo, remote_name);

            // Get remote HEAD
            let remote_head = repo
                .find_reference(&format!("refs/remotes/{remote_name}/HEAD"))
                .or_else(|_| {
                    repo.find_reference(&format!("refs/remotes/{remote_name}/{remote_branch}"))
                })
                .map_err(|e| SyncError::Git(format!("find remote HEAD: {e}")))?;
            let r_oid = remote_head
                .peel_to_commit()
                .map_err(|e| SyncError::Git(format!("peel remote: {e}")))?
                .id();

            // Get local HEAD
            let l_oid = repo
                .head()
                .map_err(|e| SyncError::Git(format!("head: {e}")))?
                .peel_to_commit()
                .map_err(|e| SyncError::Git(format!("peel local: {e}")))?
                .id();

            (r_oid, l_oid)
        }; // fetch_opts dropped here, releasing credential borrow

        // Already up to date?
        if local_oid == remote_oid {
            // P8b: even with no new commits, an unapplied manifest (landed
            // during a conflicted pull that was resolved without a
            // subsequent successful pull, or a local manifest commit) may
            // still need its restore committed. Cheap when clean: one blob
            // read.
            let applied = self.apply_revocations(repo, &[])?;
            self.transition_state(SyncState::Idle)?;
            let _ = applied;
            return Ok(PullResult::AlreadyUpToDate);
        }

        // Check if fast-forward possible
        let _local_commit = repo
            .find_commit(local_oid)
            .map_err(|e| SyncError::Git(format!("find local commit: {e}")))?;
        let _remote_commit = repo
            .find_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("find remote commit: {e}")))?;

        if repo
            .graph_descendant_of(remote_oid, local_oid)
            .map_err(|e| SyncError::Git(format!("descendant check: {e}")))?
        {
            // Fast-forward
            let branch = Self::resolve_default_branch(repo);

            // D22: Verify commit signatures BEFORE updating any refs or working tree
            let new_oids = Self::collect_commit_range(repo, local_oid, local_oid, remote_oid)?;
            self.verify_commit_signatures(repo, &new_oids)?;

            repo.reference(
                &format!("refs/heads/{branch}"),
                remote_oid,
                true,
                "fast-forward merge",
            )
            .map_err(|e| SyncError::Git(format!("ff update ref: {e}")))?;
            repo.set_head(&format!("refs/heads/{branch}"))
                .map_err(|e| SyncError::Git(format!("set head: {e}")))?;

            // C1 fix: checkout_head(None) is GIT_CHECKOUT_NONE — a dry-run no-op
            // that advances HEAD but leaves the OLD working-tree files in place.
            // Callers (auto-sync, manual sync) that commit+push after this would
            // re-commit the stale tree and silently revert the just-pulled remote
            // changes. Force-checkout so the worktree matches the new HEAD.
            repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
                .map_err(|e| SyncError::Git(format!("checkout head: {e}")))?;

            // P8b: verify + apply revocations arriving in the pulled batch.
            let (_, restore_oid) = self.apply_revocations(repo, &new_oids)?;

            self.save_last_head(&restore_oid.unwrap_or(remote_oid).to_string())?;
            self.transition_state(SyncState::Idle)?;
            return Ok(PullResult::FastForward);
        }

        // State: Pulling → Merging
        self.transition_state(SyncState::Merging)?;

        // Non-fast-forward: need merge
        let merge_base = repo
            .merge_base(local_oid, remote_oid)
            .map_err(|e| SyncError::Git(format!("merge_base: {e}")))?;

        let _ancestor = repo
            .find_commit(merge_base)
            .map_err(|e| SyncError::Git(format!("find ancestor: {e}")))?;

        // D22: Verify commit signatures BEFORE merging remote commits.
        // Collect remote commits from merge_base to remote_oid and verify each.
        let remote_new_oids = Self::collect_commit_range(repo, local_oid, merge_base, remote_oid)?;
        self.verify_commit_signatures(repo, &remote_new_oids)?;

        // Perform merge
        let annotated = repo
            .find_annotated_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("annotated commit: {e}")))?;
        let mut merge_opts = git2::MergeOptions::new();
        repo.merge(&[&annotated], Some(&mut merge_opts), None)
            .map_err(|e| SyncError::Git(format!("merge: {e}")))?;

        // Check for conflicts
        let mut index = repo
            .index()
            .map_err(|e| SyncError::Git(format!("index: {e}")))?;

        // Check for conflicts
        if index.has_conflicts() {
            // Collect conflicting cipher file paths
            let mut conflicts = Vec::new();
            if let Ok(mut iter) = index.conflicts() {
                while let Some(Ok(entry)) = iter.next() {
                    if let Some(ours) = &entry.our {
                        let path_str = String::from_utf8_lossy(&ours.path).to_string();
                        conflicts.push(path_str);
                    }
                }
            }

            // P5a: a conflict confined to meta/devices.json is auto-resolved
            // by registry union (union of devices, max last_seen_epoch per
            // id, non-empty name preferred) instead of wedging the cycle in
            // NeedsDecision — the runtime field-merge only speaks cipher
            // files, and devices.json is plaintext so it needs no keys.
            // Union (not keep-local) so both sides converge to the same
            // superset instead of flapping. Membership correctness after a
            // revocation is enforced at the crypto/policy layer, not by this
            // file.
            if conflicts.len() == 1 && conflicts[0] == "meta/devices.json" {
                if self.union_merge_devices_conflict(repo, &mut index)? {
                    // Resolved in the index; fall through to the normal
                    // merge-commit path below.
                } else {
                    repo.cleanup_state()
                        .map_err(|e| SyncError::Git(format!("cleanup: {e}")))?;
                    return Ok(PullResult::Conflict {
                        files: conflicts,
                        local_oid,
                        remote_oid,
                    });
                }
            } else {
                repo.cleanup_state()
                    .map_err(|e| SyncError::Git(format!("cleanup: {e}")))?;
                // Leave the state machine in Merging (NOT Idle): a conflict means a
                // resolution commit must follow before the cycle can return to
                // Idle. Pre-fix this called transition_state(Idle), which made the
                // subsequent resolve_conflicts() -> transition_state(Idle) an
                // invalid Idle->Idle transition and silently broke both the
                // keep-local path and finalize_conflicts on any real conflict.
                // The resolver / finalize path transitions Merging -> Idle.
                return Ok(PullResult::Conflict {
                    files: conflicts,
                    local_oid,
                    remote_oid,
                });
            }
        }

        // Create merge commit
        let tree_id = index
            .write_tree()
            .map_err(|e| SyncError::Git(format!("write tree: {e}")))?;
        let tree = repo
            .find_tree(tree_id)
            .map_err(|e| SyncError::Git(format!("find tree: {e}")))?;

        let sig = Signature::now("Baluard User", "vault@baluard.local")
            .map_err(|e| SyncError::Git(format!("signature: {e}")))?;

        let local_parent = repo
            .find_commit(local_oid)
            .map_err(|e| SyncError::Git(format!("find local: {e}")))?;
        let remote_parent = repo
            .find_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

        let merge_oid = self.create_signed_commit(
            repo,
            &sig,
            COMMIT_MESSAGE,
            &tree,
            &[&local_parent, &remote_parent],
        )?;
        // Point HEAD at the merge commit
        let branch = Self::resolve_default_branch(repo);
        repo.reference(&format!("refs/heads/{branch}"), merge_oid, true, "merge")
            .map_err(|e| SyncError::Git(format!("update ref: {e}")))?;
        repo.set_head(&format!("refs/heads/{branch}"))
            .map_err(|e| SyncError::Git(format!("set head: {e}")))?;

        // C1 fix: ensure the working tree matches the merge commit we just
        // created. Without this the on-disk files can lag HEAD (repo.merge()
        // updates the index but does not guarantee a worktree checkout).
        repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .map_err(|e| SyncError::Git(format!("checkout after merge: {e}")))?;

        // P8b: verify + apply revocations arriving on the remote side of
        // the merge.
        let (_, restore_oid) = self.apply_revocations(repo, &remote_new_oids)?;

        // Track merge commit OID (not remote HEAD) for rollback detection
        self.save_last_head(&restore_oid.unwrap_or(merge_oid).to_string())?;
        repo.cleanup_state()
            .map_err(|e| SyncError::Git(format!("cleanup after merge: {e}")))?;
        self.transition_state(SyncState::Idle)?;
        Ok(PullResult::Merged)
    }

    /// Auto-resolve a meta/devices.json merge conflict by registry union:
    /// union of device entries, max `last_seen_epoch` per id (tie → ours),
    /// non-empty name preferred. Writes the merged file to the worktree and
    /// stages it, clearing the conflict. Returns false when the conflict
    /// cannot be parsed (caller falls back to the standard Conflict flow —
    /// fail visible, never fail silent).
    fn union_merge_devices_conflict(
        &self,
        repo: &Repository,
        index: &mut git2::Index,
    ) -> Result<bool, BaluardError> {
        const PATH: &str = "meta/devices.json";
        let mut ours_blob = None;
        let mut theirs_blob = None;
        if let Ok(mut iter) = index.conflicts() {
            while let Some(Ok(entry)) = iter.next() {
                let path = entry
                    .our
                    .as_ref()
                    .map(|e| String::from_utf8_lossy(&e.path).to_string())
                    .unwrap_or_default();
                if path == PATH {
                    ours_blob = entry.our.as_ref().map(|e| e.id);
                    theirs_blob = entry.their.as_ref().map(|e| e.id);
                    break;
                }
            }
        }
        let (Some(ours_id), Some(theirs_id)) = (ours_blob, theirs_blob) else {
            return Ok(false);
        };
        let parse_side = |id: git2::Oid| -> Option<crate::devices::DeviceRegistry> {
            let blob = repo.find_blob(id).ok()?;
            let data = std::str::from_utf8(blob.content()).ok()?;
            serde_json::from_str(data).ok()
        };
        let (Some(ours), Some(theirs)) = (parse_side(ours_id), parse_side(theirs_id)) else {
            return Ok(false);
        };

        // Union with deterministic preference rules.
        let mut merged: std::collections::BTreeMap<
            uuid::Uuid,
            crate::vault::manifest::DeviceEntry,
        > = std::collections::BTreeMap::new();
        for (id, entry) in &ours.devices {
            merged.insert(*id, entry.clone());
        }
        for (id, theirs_entry) in &theirs.devices {
            match merged.get_mut(id) {
                None => {
                    merged.insert(*id, theirs_entry.clone());
                }
                Some(ours_entry) => {
                    if theirs_entry.last_seen_epoch > ours_entry.last_seen_epoch {
                        *ours_entry = theirs_entry.clone();
                    } else if ours_entry.name.is_empty() && !theirs_entry.name.is_empty() {
                        ours_entry.name = theirs_entry.name.clone();
                    }
                }
            }
        }
        let mut out = crate::devices::DeviceRegistry::new();
        out.version = ours.version.max(theirs.version);
        out.devices = merged.into_iter().collect();

        // Worktree + stage; add_path replaces the conflict stages with a
        // stage-0 entry, marking the path resolved.
        let path = std::path::Path::new(PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(self.vault_path.join(parent))
                .map_err(|e| SyncError::Git(format!("create meta dir for devices union: {e}")))?;
        }
        let json = out
            .to_deterministic_json()
            .map_err(|e| SyncError::Git(format!("serialize devices union: {e}")))?;
        std::fs::write(self.vault_path.join(path), &json)
            .map_err(|e| SyncError::Git(format!("write devices union: {e}")))?;
        index
            .add_path(path)
            .map_err(|e| SyncError::Git(format!("stage devices union: {e}")))?;
        index
            .write()
            .map_err(|e| SyncError::Git(format!("index write: {e}")))?;
        Ok(true)
    }

    /// Delete the local-only index shards (best-effort). Called after any sync
    /// operation that wrote cipher files directly through the engine (pull,
    /// sync cycle) — those bypass the VaultHandle index-rebuild hooks, so the
    /// cached index may no longer match disk. Deleting the shards is keyless
    /// (no RootKey needed) and forces exactly one auto-heal rebuild at the next
    /// list. AlreadyUpToDate pulls must NOT call this.
    pub fn invalidate_local_index(vault_path: &std::path::Path) {
        let meta = vault_path.join("meta");
        let _ = std::fs::remove_file(meta.join("index.enc"));
        if let Ok(entries) = std::fs::read_dir(&meta) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("index.enc.s") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // P8b: revocation manifests (append-only, branch-protection-safe)
    // -------------------------------------------------------------------

    /// Manifest blob id in a tree (`None` when the file is absent).
    fn manifest_blob_id(tree: &git2::Tree<'_>) -> Option<Oid> {
        tree.get_path(std::path::Path::new(
            crate::sync::revocation::REVOCATIONS_PATH,
        ))
        .ok()
        .map(|e| e.id())
    }

    /// Parse the manifest out of a commit's tree (`None` when absent).
    /// Present-but-unparseable is a hard error (tamper, fail closed).
    fn manifest_from_tree(
        repo: &Repository,
        tree: &git2::Tree<'_>,
    ) -> Result<Option<crate::sync::revocation::RevocationManifest>, BaluardError> {
        let Some(blob_id) = Self::manifest_blob_id(tree) else {
            return Ok(None);
        };
        let blob = repo
            .find_blob(blob_id)
            .map_err(|e| SyncError::Git(format!("manifest blob: {e}")))?;
        crate::sync::revocation::RevocationManifest::parse(blob.content())
            .map(Some)
            .map_err(|e| SyncError::RevocationInvalid(e).into())
    }

    /// Verify NEW entries introduced by one manifest-blob transition
    /// against the roster snapshot in force at `commit` (first-parent
    /// rule, same as P2 commit verification). Only the entries absent
    /// from the parent manifest are checked: the file is append-only,
    /// so old entries were verified when their version arrived, and a
    /// later de-enrollment of their signer must never wedge pulls.
    /// Tampered old bytes would surface as a blob-id change (→ new
    /// transition → full re-verification).
    fn verify_manifest_transition(
        repo: &Repository,
        commit_oid: Oid,
        parent_manifest: Option<&crate::sync::revocation::RevocationManifest>,
        child: &crate::sync::revocation::RevocationManifest,
        roster_cache: &mut std::collections::HashMap<Oid, Option<DeviceRoster>>,
    ) -> Result<(), BaluardError> {
        use std::collections::HashSet;

        // Append-only containment: every parent entry must survive in
        // the child UNCHANGED (all signed fields byte-equal). Stripping
        // an entry OR rewriting its fields is tamper.
        if let Some(parent) = parent_manifest {
            for old in &parent.entries {
                let carried = child
                    .entries
                    .iter()
                    .any(|new| new.commit == old.commit && new == old);
                if !carried {
                    return Err(SyncError::RevocationInvalid(format!(
                        "manifest entry for commit {} was removed or altered — append-only violation",
                        old.commit
                    ))
                    .into());
                }
            }
        }

        let parent_commits: HashSet<&str> = parent_manifest
            .map(|p| p.entries.iter().map(|e| e.commit.as_str()).collect())
            .unwrap_or_default();
        let new_entries: Vec<&crate::sync::revocation::RevocationEntry> = child
            .entries
            .iter()
            .filter(|e| !parent_commits.contains(e.commit.as_str()))
            .collect();
        if new_entries.is_empty() {
            return Ok(());
        }

        let commit = repo
            .find_commit(commit_oid)
            .map_err(|e| SyncError::Git(format!("manifest commit: {e}")))?;
        let Some(roster) = Self::roster_for_commit(repo, &commit, roster_cache)? else {
            // Pre-enrollment line: no trust anchor, no shared threat.
            // Entries there cannot be verified; fail closed anyway — a
            // manifest version introduced before enrollment is tamper
            // by construction (the feature postdates enrollment).
            return Err(SyncError::RevocationInvalid(
                "manifest introduced on a pre-enrollment history line".into(),
            )
            .into());
        };
        for entry in new_entries {
            let Some(vk_bytes) = roster.get(&entry.device_id) else {
                return Err(SyncError::RevocationInvalid(format!(
                    "entry seq {}: device {} not in roster at introduction",
                    entry.seq, entry.device_id
                ))
                .into());
            };
            let vk = ed25519_dalek::VerifyingKey::from_bytes(vk_bytes)
                .map_err(|e| SyncError::RevocationInvalid(format!("roster key: {e}")))?;
            entry.verify_signature(&vk).map_err(|e| {
                SyncError::RevocationInvalid(format!("entry seq {}: {e}", entry.seq))
            })?;
        }
        Ok(())
    }

    /// Walk the full history from `head_oid` and verify EVERY manifest
    /// blob transition: append-only containment plus entry signatures
    /// at each introduction point. Runs whenever the locally-verified
    /// blob id does not match HEAD (arrival of a new version, cold
    /// start, conflict-resolution merge that skipped the hook), and is
    /// skipped entirely on the steady-state path (verified blob id
    /// unchanged — git content addressing makes this sound).
    fn walk_and_verify_manifest_history(
        repo: &Repository,
        head_oid: Oid,
    ) -> Result<(), BaluardError> {
        // Collect every commit reachable from HEAD (all parents).
        let mut oids = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![head_oid];
        while let Some(oid) = stack.pop() {
            if !visited.insert(oid) {
                continue;
            }
            let commit = repo
                .find_commit(oid)
                .map_err(|e| SyncError::Git(format!("manifest walk: {e}")))?;
            oids.push(oid);
            for i in 0..commit.parent_count() {
                let pid = commit
                    .parent_id(i)
                    .map_err(|e| SyncError::Git(format!("manifest walk parent: {e}")))?;
                stack.push(pid);
            }
        }
        let ordered = Self::topo_order_commits(repo, &oids)?;
        let mut roster_cache: std::collections::HashMap<Oid, Option<DeviceRoster>> =
            std::collections::HashMap::new();
        for oid in &ordered {
            let commit = repo
                .find_commit(*oid)
                .map_err(|e| SyncError::Git(format!("manifest walk: {e}")))?;
            let own_tree = commit
                .tree()
                .map_err(|e| SyncError::Git(format!("manifest walk tree: {e}")))?;
            let own_blob = Self::manifest_blob_id(&own_tree);
            if commit.parent_count() == 0 {
                if let Some(manifest) = Self::manifest_from_tree(repo, &own_tree)? {
                    Self::verify_manifest_transition(
                        repo,
                        *oid,
                        None,
                        &manifest,
                        &mut roster_cache,
                    )?;
                }
                continue;
            }
            let parent = commit
                .parent(0)
                .map_err(|e| SyncError::Git(format!("manifest walk parent: {e}")))?;
            let parent_tree = parent
                .tree()
                .map_err(|e| SyncError::Git(format!("manifest walk parent tree: {e}")))?;
            let parent_blob = Self::manifest_blob_id(&parent_tree);
            match (parent_blob, own_blob) {
                (Some(p), Some(o)) if p == o => continue, // no transition
                (Some(_), None) => {
                    return Err(SyncError::RevocationInvalid(
                        "revocation manifest deleted — append-only violation".into(),
                    )
                    .into());
                }
                (None, None) => continue, // no manifest on this line
                (parent_blob, Some(_)) => {
                    let child = Self::manifest_from_tree(repo, &own_tree)?.unwrap_or_default();
                    let parent_manifest = match parent_blob {
                        Some(blob_id) => {
                            let blob = repo
                                .find_blob(blob_id)
                                .map_err(|e| SyncError::Git(format!("manifest blob: {e}")))?;
                            Some(
                                crate::sync::revocation::RevocationManifest::parse(blob.content())
                                    .map_err(SyncError::RevocationInvalid)?,
                            )
                        }
                        None => None,
                    };
                    Self::verify_manifest_transition(
                        repo,
                        *oid,
                        parent_manifest.as_ref(),
                        &child,
                        &mut roster_cache,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Local revocation verification tracker (gitignored, keyless):
    /// the manifest blob id whose transitions were last verified plus
    /// the revoked commits already planned/applied. Steady-state pulls
    /// cost one file read instead of a history walk.
    fn revocation_tracker_path(&self) -> std::path::PathBuf {
        self.vault_path.join("meta/revocations-verified.json")
    }

    fn load_revocation_tracker(&self) -> RevocationTracker {
        std::fs::read(self.revocation_tracker_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save_revocation_tracker(&self, tracker: &RevocationTracker) -> Result<(), BaluardError> {
        let path = self.revocation_tracker_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| SyncError::Git(format!("tracker dir: {e}")))?;
        }
        let json = serde_json::to_vec(tracker)
            .map_err(|e| SyncError::Git(format!("tracker serialize: {e}")))?;
        std::fs::write(&path, json).map_err(|e| SyncError::Git(format!("tracker write: {e}")))?;
        Ok(())
    }

    /// Append a signed revocation entry for `commit_ref` and commit the
    /// updated manifest (standard signed-commit path, so the manifest
    /// commit itself is roster-verified at every peer). Refuses: unknown
    /// commit, duplicate revocation, unenrolled device, no signing key.
    /// Returns the new entry's sequence number.
    pub fn append_revocation(
        &self,
        repo: &Repository,
        commit_ref: &str,
        reason: &str,
    ) -> Result<u64, BaluardError> {
        let target = repo
            .revparse_single(commit_ref)
            .and_then(|obj| obj.peel_to_commit())
            .map_err(|e| {
                SyncError::RevocationInvalid(format!("unknown commit {commit_ref}: {e}"))
            })?;
        let commit_hex = target.id().to_string();

        let head_commit = repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let head_tree = head_commit
            .tree()
            .map_err(|e| SyncError::Git(format!("head tree: {e}")))?;
        let mut manifest = Self::manifest_from_tree(repo, &head_tree)?.unwrap_or_default();
        if manifest.contains_commit(&commit_hex) {
            return Err(SyncError::RevocationInvalid(format!(
                "commit {commit_hex} already revoked"
            ))
            .into());
        }

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(SyncError::UnsignedCommitRefused)?;

        // Roster from the HEAD TREE (not the worktree): an uncommitted
        // devices.json edit must not fabricate or mask enrollment. The
        // signer identity is the roster entry whose signing key matches
        // the loaded key — identity and signature cannot disagree.
        let roster_json: serde_json::Value = match head_tree
            .get_path(std::path::Path::new("meta/devices.json"))
            .ok()
            .map(|e| repo.find_blob(e.id()))
            .transpose()
            .map_err(|e| SyncError::Git(format!("roster blob: {e}")))?
        {
            Some(blob) => serde_json::from_slice(blob.content())
                .map_err(|e| SyncError::RevocationInvalid(format!("roster parse: {e}")))?,
            None => {
                return Err(SyncError::RevocationInvalid(
                    "no device roster at HEAD; cannot revoke".into(),
                )
                .into());
            }
        };
        use ed25519_dalek::Signer;
        let signing_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let device_id = roster_json["devices"]
            .as_object()
            .and_then(|devices| {
                devices.iter().find_map(|(id, entry)| {
                    (entry["signing_public_key"].as_str() == Some(signing_key_hex.as_str()))
                        .then(|| id.clone())
                })
            })
            .ok_or_else(|| {
                SyncError::RevocationInvalid(
                    "signing key not enrolled in the roster at HEAD; cannot revoke".into(),
                )
            })?;

        let mut entry = crate::sync::revocation::RevocationEntry {
            seq: manifest.next_seq(),
            commit: commit_hex,
            reason: reason.to_string(),
            revoked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            device_id,
            sig: String::new(),
        };
        entry.sig = base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(&entry.signed_payload()).to_bytes());
        manifest.entries.push(entry);

        let manifest_path = self
            .vault_path
            .join(crate::sync::revocation::REVOCATIONS_PATH);
        if let Some(dir) = manifest_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| SyncError::Git(format!("manifest dir: {e}")))?;
        }
        let json = manifest.to_json().map_err(SyncError::RevocationInvalid)?;
        std::fs::write(&manifest_path, json)
            .map_err(|e| SyncError::Git(format!("manifest write: {e}")))?;

        let oid = self.commit_all(repo, "")?;
        self.save_last_head(&oid.to_string())?;

        // Self-heal: the revoking device buries the bad content locally
        // too (the entry was written and signed by this device).
        self.apply_revocations(repo, &[])?;
        Ok(manifest.entries.last().map(|e| e.seq).unwrap_or(1))
    }

    /// Apply revocation manifests after a pull (any outcome).
    ///
    /// Verification is tracker-driven: the local tracker records the
    /// manifest blob id whose history transitions were last verified.
    /// On any mismatch (new version, cold start, a conflict-resolution
    /// merge that skipped the hook) the FULL history is walked and every
    /// manifest transition is checked — append-only containment plus
    /// entry signatures at each introduction point (fail closed). On
    /// the steady state (same blob id) this costs one file read; git
    /// content addressing makes the skip sound.
    ///
    /// Application: for each revoked commit still carrying its bad
    /// content at HEAD (head blob == revoked blob, and different from
    /// the first-parent blob), the affected paths are restored from the
    /// first-parent tree and committed with a targeted (path-scoped)
    /// signed commit — uncommitted worktree changes are never swept in.
    /// Paths already superseded by later commits are left alone:
    /// hash-based revocation cannot follow data flow (documented
    /// boundary — policy-layer content rules come later).
    ///
    /// Returns (restored path count, restore commit oid when created).
    pub fn apply_revocations(
        &self,
        repo: &Repository,
        new_oids: &[Oid],
    ) -> Result<(usize, Option<Oid>), BaluardError> {
        // Kept for signature compatibility; verification is tracker-driven
        // so it also covers up-to-date pulls after conflict resolutions.
        let _ = new_oids;

        let head_commit = repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let head_tree = head_commit
            .tree()
            .map_err(|e| SyncError::Git(format!("head tree: {e}")))?;
        let head_blob = Self::manifest_blob_id(&head_tree);
        let manifest = Self::manifest_from_tree(repo, &head_tree)?;

        // 1. Verification (skipped only when this exact blob version was
        // already verified locally). Runs even for an EMPTY or deleted
        // manifest when a verified version existed — stripping entries
        // or deleting the file is an append-only violation the walk
        // must catch.
        let mut tracker = self.load_revocation_tracker();
        let head_blob_str = head_blob.map(|o| o.to_string()).unwrap_or_default();
        if head_blob.is_none() && tracker.blob.is_empty() {
            return Ok((0, None)); // vault never had a manifest
        }
        if tracker.blob != head_blob_str {
            Self::walk_and_verify_manifest_history(repo, head_commit.id())?;
            tracker.blob = head_blob_str;
            self.save_revocation_tracker(&tracker)?;
        }
        let Some(manifest) = manifest else {
            return Ok((0, None));
        };

        // 2. Restore plan over not-yet-applied revocations.
        let mut plan: Vec<(String, Option<(Oid, i32)>)> = Vec::new();
        let mut newly_applied: Vec<String> = Vec::new();
        for entry in &manifest.entries {
            if tracker.applied.iter().any(|c| c == &entry.commit) {
                continue;
            }
            newly_applied.push(entry.commit.clone());
            let Ok(rev_oid) = Oid::from_str(&entry.commit) else {
                continue; // malformed hex cannot pass shape validation
            };
            let Ok(rc) = repo.find_commit(rev_oid) else {
                continue; // not in this repo's object store (other branch)
            };
            if rc.parent_count() == 0 {
                continue; // genesis commit: no clean parent to restore from
            }
            let parent_tree = rc
                .parent(0)
                .and_then(|p| p.tree())
                .map_err(|e| SyncError::Git(format!("revoked parent: {e}")))?;
            let revoked_tree = rc
                .tree()
                .map_err(|e| SyncError::Git(format!("revoked tree: {e}")))?;
            let diff = repo
                .diff_tree_to_tree(Some(&parent_tree), Some(&revoked_tree), None)
                .map_err(|e| SyncError::Git(format!("revocation diff: {e}")))?;
            for delta in diff.deltas() {
                let Some(path) = delta.new_file().path().or_else(|| delta.old_file().path()) else {
                    continue;
                };
                if !Self::repo_path_is_safe(path) {
                    return Err(SyncError::RevocationInvalid(format!(
                        "revoked commit touches unsafe path {}",
                        path.display()
                    ))
                    .into());
                }
                let path_str = path.to_string_lossy().to_string();
                if plan.iter().any(|(p, _)| p == &path_str) {
                    continue;
                }
                // Restore only paths where HEAD still carries exactly the
                // revoked content and it was not already neutralized.
                let parent_entry = parent_tree.get_path(path).ok();
                let revoked_entry = revoked_tree.get_path(path).ok();
                let head_entry = head_tree.get_path(path).ok();
                let ids_equal =
                    |a: &Option<git2::TreeEntry>, b: &Option<git2::TreeEntry>| match (a, b) {
                        (Some(x), Some(y)) => x.id() == y.id(),
                        (None, None) => true,
                        _ => false,
                    };
                if ids_equal(&head_entry, &parent_entry) {
                    continue; // already restored
                }
                if !ids_equal(&head_entry, &revoked_entry) {
                    continue; // superseded by later legitimate commits
                }
                plan.push((path_str, parent_entry.map(|e| (e.id(), e.filemode()))));
            }
        }
        if plan.is_empty() {
            if !newly_applied.is_empty() {
                tracker.applied.extend(newly_applied);
                self.save_revocation_tracker(&tracker)?;
            }
            return Ok((0, None));
        }

        // 3. Apply to the worktree (vault-rest permission invariant:
        // 0600, executables 0700).
        let restored = plan.len();
        for (path_str, clean) in &plan {
            let abs = self.vault_path.join(path_str);
            match clean {
                Some((blob_id, mode)) => {
                    let blob = repo
                        .find_blob(*blob_id)
                        .map_err(|e| SyncError::Git(format!("restore blob: {e}")))?;
                    if let Some(dir) = abs.parent() {
                        std::fs::create_dir_all(dir)
                            .map_err(|e| SyncError::Git(format!("restore dir: {e}")))?;
                    }
                    std::fs::write(&abs, blob.content())
                        .map_err(|e| SyncError::Git(format!("restore write: {e}")))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let perm = if *mode == 0o100755 { 0o700 } else { 0o600 };
                        let _ =
                            std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(perm));
                    }
                }
                None => {
                    let _ = std::fs::remove_file(&abs);
                }
            }
        }

        // 4. Targeted, signed restore commit — only the affected paths
        // are staged, so uncommitted worktree changes stay untouched.
        let plan_paths: Vec<String> = plan.iter().map(|(p, _)| p.clone()).collect();
        let restore_oid = self.commit_paths(repo, &plan_paths)?;

        tracker.applied.extend(newly_applied);
        self.save_revocation_tracker(&tracker)?;
        self.save_last_head(&restore_oid.to_string())?;
        // Restored cipher files bypassed the VaultHandle index hooks; the
        // keyless invalidation forces one rebuild so stale metadata (same
        // ids, old content) is never served after a restore.
        Self::invalidate_local_index(&self.vault_path);
        Ok((restored, Some(restore_oid)))
    }

    /// Vault-relative repo paths are safe when every component is a
    /// normal name: no absolute prefixes, no `..` traversal.
    fn repo_path_is_safe(rel: &std::path::Path) -> bool {
        if rel.is_absolute() {
            return false;
        }
        rel.components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    }

    /// Commit exactly `paths` (targeted staging) with the standard
    /// signed-commit path. Unlike commit_all this never sweeps unrelated
    /// worktree changes and never touches the device epoch.
    fn commit_paths(&self, repo: &Repository, paths: &[String]) -> Result<Oid, BaluardError> {
        let mut index = repo
            .index()
            .map_err(|e| SyncError::Git(format!("index: {e}")))?;
        for p in paths {
            let rel = std::path::Path::new(p);
            let abs = self.vault_path.join(p);
            if abs.exists() {
                index
                    .add_path(rel)
                    .map_err(|e| SyncError::Git(format!("add {}: {e}", p)))?;
            } else if index.get_path(rel, 0).is_some() {
                index
                    .remove_path(rel)
                    .map_err(|e| SyncError::Git(format!("remove {}: {e}", p)))?;
            }
        }
        index
            .write()
            .map_err(|e| SyncError::Git(format!("index write: {e}")))?;
        let tree_id = index
            .write_tree()
            .map_err(|e| SyncError::Git(format!("write_tree: {e}")))?;
        let tree = repo
            .find_tree(tree_id)
            .map_err(|e| SyncError::Git(format!("find_tree: {e}")))?;
        let sig = git2::Signature::now("Baluard User", "vault@baluard.local")
            .map_err(|e| SyncError::Git(format!("signature: {e}")))?;
        let parent = repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let oid = self.create_signed_commit(repo, &sig, COMMIT_MESSAGE, &tree, &[&parent])?;
        let branch = Self::resolve_default_branch(repo);
        repo.reference(&format!("refs/heads/{branch}"), oid, true, "vault update")
            .map_err(|e| SyncError::Git(format!("update HEAD: {e}")))?;
        repo.set_head(&format!("refs/heads/{branch}"))
            .map_err(|e| SyncError::Git(format!("set head: {e}")))?;
        self.record_device_activity(&oid.to_string());
        Ok(oid)
    }

    /// Read a file's content from a specific commit's tree.
    /// Used by conflict resolution to load base/local/remote versions.
    pub fn read_blob_from_commit(
        repo: &Repository,
        commit_oid: Oid,
        file_path: &str,
    ) -> Result<Vec<u8>, BaluardError> {
        let commit = repo
            .find_commit(commit_oid)
            .map_err(|e| SyncError::Git(format!("find commit: {e}")))?;
        let tree = commit
            .tree()
            .map_err(|e| SyncError::Git(format!("tree: {e}")))?;
        let entry = tree
            .get_path(Path::new(file_path))
            .map_err(|e| SyncError::Git(format!("path '{file_path}' not in tree: {e}")))?;
        let blob = repo
            .find_blob(entry.id())
            .map_err(|e| SyncError::Git(format!("blob: {e}")))?;
        Ok(blob.content().to_vec())
    }

    /// Write resolved file contents and create a merge commit.
    /// Call after conflict resolution with the merged/re-encrypted file contents.
    /// `resolved_files` maps file_path -> resolved content bytes.
    pub fn resolve_conflicts(
        &self,
        repo: &Repository,
        local_oid: Oid,
        remote_oid: Oid,
        resolved_files: &[(String, Vec<u8>)],
    ) -> Result<Oid, BaluardError> {
        // D22: Verify remote commits before resolving conflicts with their data.
        let merge_base = repo
            .merge_base(local_oid, remote_oid)
            .map_err(|e| SyncError::Git(format!("merge_base for conflict resolve: {e}")))?;
        let remote_new_oids = Self::collect_commit_range(repo, local_oid, merge_base, remote_oid)?;
        self.verify_commit_signatures(repo, &remote_new_oids)?;

        // Write resolved files to working directory (with path traversal protection)
        // Validate ALL paths before any filesystem side-effects.
        let canonical_vault = self
            .vault_path
            .canonicalize()
            .map_err(|e| SyncError::Git(format!("canonicalize vault path: {e}")))?;

        for (path, content) in resolved_files {
            let full_path = self.vault_path.join(path);

            // Canonicalize the parent (must already exist under vault).
            // Do NOT create dirs before validation — that creates side-effects
            // outside the vault on traversal paths.
            let parent = full_path.parent().unwrap_or(Path::new("."));
            let canonical_parent = parent.canonicalize().map_err(|e| {
                SyncError::Git(format!("path '{}' parent not under vault: {e}", path))
            })?;
            if !canonical_parent.starts_with(&canonical_vault) {
                return Err(SyncError::Git(format!(
                    "path traversal detected: '{}' escapes vault directory",
                    path
                ))
                .into());
            }
            let canonical_full = canonical_parent.join(full_path.file_name().unwrap_or_default());
            if !canonical_full.starts_with(&canonical_vault) {
                return Err(SyncError::Git(format!(
                    "path traversal detected: '{}' escapes vault directory",
                    path
                ))
                .into());
            }

            // Now safe to create dirs and write
            if let Some(p) = full_path.parent() {
                std::fs::create_dir_all(p)
                    .map_err(|e| SyncError::Git(format!("create dir: {e}")))?;
            }
            std::fs::write(&full_path, content)
                .map_err(|e| SyncError::Git(format!("write resolved: {e}")))?;
        }

        // Stage all and create merge commit
        let mut index = repo
            .index()
            .map_err(|e| SyncError::Git(format!("index: {e}")))?;
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .map_err(|e| SyncError::Git(format!("add_all: {e}")))?;
        index
            .write()
            .map_err(|e| SyncError::Git(format!("index write: {e}")))?;

        let tree_id = index
            .write_tree()
            .map_err(|e| SyncError::Git(format!("write_tree: {e}")))?;
        let tree = repo
            .find_tree(tree_id)
            .map_err(|e| SyncError::Git(format!("find_tree: {e}")))?;

        let sig = Signature::now("Baluard User", "vault@baluard.local")
            .map_err(|e| SyncError::Git(format!("signature: {e}")))?;

        let local_parent = repo
            .find_commit(local_oid)
            .map_err(|e| SyncError::Git(format!("find local: {e}")))?;
        let remote_parent = repo
            .find_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

        let merge_oid = self.create_signed_commit(
            repo,
            &sig,
            COMMIT_MESSAGE,
            &tree,
            &[&local_parent, &remote_parent],
        )?;
        // Point HEAD at the merge commit
        let branch = Self::resolve_default_branch(repo);
        repo.reference(
            &format!("refs/heads/{branch}"),
            merge_oid,
            true,
            "conflict resolution",
        )
        .map_err(|e| SyncError::Git(format!("update ref: {e}")))?;
        repo.set_head(&format!("refs/heads/{branch}"))
            .map_err(|e| SyncError::Git(format!("set head: {e}")))?;

        self.save_last_head(&merge_oid.to_string())?;
        repo.cleanup_state()
            .map_err(|e| SyncError::Git(format!("cleanup after merge: {e}")))?;
        self.transition_state(SyncState::Idle)?;
        Ok(merge_oid)
    }

    /// Resolve a pull conflict by keeping the LOCAL version of every
    /// conflicting file, producing a proper 2-parent merge commit on top of
    /// both local and remote. The next push is then fast-forwardable.
    ///
    /// This is the Phase 1 resolution policy ("keep local, surface to user").
    /// Phase 2 will decrypt + run [`crate::sync::conflict::merge_ciphers`] for
    /// field-level non-destructive merge before falling back to keep-local on
    /// true same-field conflicts. Local edits are never lost; remote edits that
    /// conflicted are in git history and can be reviewed.
    ///
    /// `files` is the conflicting file list from [`PullResult::Conflict`].
    pub fn resolve_conflict_keep_local(
        &self,
        repo: &Repository,
        local_oid: Oid,
        remote_oid: Oid,
        files: &[String],
    ) -> Result<Oid, BaluardError> {
        // For each conflicting file, take the local version's bytes.
        let mut resolved: Vec<(String, Vec<u8>)> = Vec::with_capacity(files.len());
        for f in files {
            let bytes = Self::read_blob_from_commit(repo, local_oid, f)?;
            resolved.push((f.clone(), bytes));
        }
        self.resolve_conflicts(repo, local_oid, remote_oid, &resolved)
    }

    /// Run one full sync cycle: commit local → pull → resolve conflicts → push.
    ///
    /// Backward-compatible entry point: on conflict, unconditionally keeps the
    /// local side via [`resolve_conflict_keep_local`] (Phase 1 policy). No
    /// field-level merge, no human-in-the-loop pause. See
    /// [`run_sync_cycle_with_resolver`] for the Phase 2 opt-in path.
    pub fn run_sync_cycle(&self, repo: &Repository) -> Result<SyncCycleOutcome, BaluardError> {
        self.run_sync_cycle_with_resolver(repo, &mut |_| ConflictResolution::KeepLocal)
    }

    /// Run one full sync cycle with an opt-in field-level conflict resolver.
    ///
    /// Same commit → pull → resolve → push order as [`run_sync_cycle`]. On a
    /// [`PullResult::Conflict`], instead of unconditionally keeping local,
    /// calls `resolver` with a [`PendingConflictState`]. The resolver returns:
    ///   - [`ConflictResolution::KeepLocal`] → fall back to the Phase 1 path
    ///     (`resolve_conflict_keep_local`), cycle completes as `Synced`.
    ///   - [`ConflictResolution::Pause`] → the caller will handle this conflict
    ///     out of band (decrypt + merge + decide). The cycle returns
    ///     [`SyncCycleOutcome::NeedsDecision`] WITHOUT writing a merge commit
    ///     or pushing. The caller resumes via [`finalize_conflicts`].
    ///
    /// Network failures still map to [`SyncCycleOutcome::Offline`].
    pub fn run_sync_cycle_with_resolver(
        &self,
        repo: &Repository,
        resolver: &mut impl FnMut(&PendingConflictState) -> ConflictResolution,
    ) -> Result<SyncCycleOutcome, BaluardError> {
        // 1. Commit pending local changes (clean worktree before pull).
        let status = self.status(repo)?;
        if status.is_dirty() {
            self.commit_all(repo, "")?;
        }

        // 2. Pull (fast-forward / merge / conflict). Track whether a conflict
        // was resolved so the caller can surface it to the user.
        let mut conflicts = 0u32;
        let mut pending: Vec<PendingConflictState> = Vec::new();
        match self.pull(repo, "origin") {
            Ok(PullResult::Conflict {
                files,
                local_oid,
                remote_oid,
            }) => {
                let state = PendingConflictState {
                    files,
                    local_oid,
                    remote_oid,
                };
                match resolver(&state) {
                    ConflictResolution::KeepLocal => {
                        // Phase 1 fallback: keep local, write 2-parent merge
                        // commit, complete the cycle.
                        self.resolve_conflict_keep_local(
                            repo,
                            state.local_oid,
                            state.remote_oid,
                            &state.files,
                        )?;
                        conflicts = 1;
                    }
                    ConflictResolution::Pause => {
                        // Caller opts in to field-level resolution. Pause the
                        // cycle: do NOT write a merge commit, do NOT push.
                        pending.push(state);
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if is_network_error(e) => return Ok(SyncCycleOutcome::Offline),
            Err(e) => return Err(e),
        }

        // 3. If the caller paused for a decision, return now — no push.
        if !pending.is_empty() {
            return Ok(SyncCycleOutcome::NeedsDecision { pending });
        }

        // 4. Push (local is committed + reconciled with remote → fast-forward).
        match self.push(repo, "origin") {
            Ok(_) => {}
            Err(ref e) if is_network_error(e) => return Ok(SyncCycleOutcome::Offline),
            Err(e) => return Err(e),
        }

        Ok(SyncCycleOutcome::Synced { conflicts })
    }

    /// Resume a paused cycle after the daemon has decided how to resolve each
    /// conflicting file. Writes the resolved blobs as a 2-parent merge commit
    /// (so the next push fast-forwards) and pushes.
    ///
    /// `resolved` is one `(path, bytes)` pair per file in `pending.files`,
    /// where `bytes` is the re-encrypted + re-padded cipher the daemon produced
    /// from `merge_ciphers` (auto-merged) or from the user's verdict
    /// (keep_local / keep_remote / keep_both). For `keep_both`, the caller is
    /// responsible for writing the SECOND entry under a new cipher id BEFORE
    /// calling this — `finalize_conflicts` only writes the files listed in
    /// `pending`.
    pub fn finalize_conflicts(
        &self,
        repo: &Repository,
        pending: &PendingConflictState,
        resolved: &[(String, Vec<u8>)],
    ) -> Result<u32, BaluardError> {
        // Re-entrancy / double-finalize guard: HEAD must still be at the local
        // tip captured in `pending`. A second finalize (retry after a spurious
        // error, or a UI double-submit before the daemon clears its pending
        // state) would otherwise build a SECOND 2-parent merge commit with the
        // same parents and, if the first already pushed, the second push is a
        // non-fast-forward that silently discards remote history. Reject early.
        let head_oid = repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .map(|c| c.id())
            .map_err(|e| SyncError::Git(format!("finalize_conflicts: read HEAD: {e}")))?;
        if head_oid != pending.local_oid {
            return Err(SyncError::Git(format!(
                "finalize_conflicts: HEAD ({}) is not the pending local tip ({}) — \
                 already finalized or moved; refusing double-resolve",
                head_oid, pending.local_oid
            ))
            .into());
        }
        self.resolve_conflicts(repo, pending.local_oid, pending.remote_oid, resolved)?;
        match self.push(repo, "origin") {
            Ok(_) => Ok(1),
            Err(ref e) if is_network_error(e) => {
                // Merge commit is already written; only the push failed. The
                // caller should treat this as Offline and retry the push on
                // the next cycle (the merge commit will fast-forward). Note:
                // unlike run_sync_cycle's Offline (Ok variant), this returns
                // Err(Network) so the caller can distinguish "merge landed,
                // push pending" from "nothing landed".
                Err(
                    SyncError::Network(format!("conflict finalized locally but push failed: {e}"))
                        .into(),
                )
            }
            Err(e) => Err(e),
        }
    }

    /// Clone a remote vault repo to a local directory.
    /// Only HTTPS and SSH URLs are allowed.
    pub fn clone(url: &str, target: &Path, _shallow: bool) -> Result<Repository, BaluardError> {
        validate_git_url(url)?;
        Self::clone_unchecked(url, target)
    }

    /// Clone without URL validation (for local testing/development).
    /// M5 fix: `pub(crate)` so external callers cannot bypass scheme validation.
    #[doc(hidden)]
    pub(crate) fn clone_unchecked(url: &str, target: &Path) -> Result<Repository, BaluardError> {
        crate::sync::tls::ensure_tls_roots();
        let mut builder = RepoBuilder::new();
        // Wire credential callbacks for clone operations
        let cred_config = CredentialConfig::load(target);
        let mut fetch_opts = FetchOptions::new();
        // Build inline callbacks to avoid lifetime issues
        let https_token = cred_config.expose_token();
        let mut callbacks = git2::RemoteCallbacks::new();
        callbacks.credentials(move |_url, username_from_url, allowed_types| {
            if allowed_types.contains(git2::CredentialType::SSH_KEY) {
                let user = username_from_url.unwrap_or("git");
                if let Ok(cred) = git2::Cred::ssh_key_from_agent(user) {
                    return Ok(cred);
                }
            }
            if allowed_types.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
                if let Some(ref token) = https_token {
                    let user = username_from_url.unwrap_or("git");
                    return git2::Cred::userpass_plaintext(user, token.as_str());
                }
            }
            if allowed_types.contains(git2::CredentialType::DEFAULT) {
                return git2::Cred::default();
            }
            Err(git2::Error::from_str("no credential source available"))
        });
        // M5 fix: enforce known_hosts for SSH (HTTPS passthrough).
        callbacks.certificate_check(|cert, host| {
            use git2::CertificateCheckStatus;
            use git2::cert::SshHostKeyType;
            if let Some(hostkey) = cert.as_hostkey() {
                let key_type = match hostkey.hostkey_type() {
                    Some(SshHostKeyType::Ed255219) => "ssh-ed25519",
                    Some(SshHostKeyType::Rsa) => "ssh-rsa",
                    Some(SshHostKeyType::Dss) => "ssh-dss",
                    Some(SshHostKeyType::Ecdsa256) => "ecdsa-sha2-nistp256",
                    Some(SshHostKeyType::Ecdsa384) => "ecdsa-sha2-nistp384",
                    Some(SshHostKeyType::Ecdsa521) => "ecdsa-sha2-nistp521",
                    _ => "",
                };
                let key = hostkey.hostkey().unwrap_or(&[]);
                match crate::sync::known_hosts::verify_host_key(host, key_type, key) {
                    crate::sync::known_hosts::HostKeyResult::Known => {
                        Ok(CertificateCheckStatus::CertificateOk)
                    }
                    _ => Err(git2::Error::from_str(&format!(
                        "SSH host key for {host} not in known_hosts"
                    ))),
                }
            } else {
                Ok(CertificateCheckStatus::CertificatePassthrough)
            }
        });
        fetch_opts.remote_callbacks(callbacks);
        builder.fetch_options(fetch_opts);
        let repo = builder.clone(url, target).map_err(|e| {
            SyncError::Git(crate::sync::credentials::scrub_git_error(&format!(
                "clone: {e}"
            )))
        })?;
        // P2: verify the fetched history before handing it out. Any failure
        // must not leave a checked-out unverified copy on disk.
        if let Err(e) = Self::verify_fetched_history(&repo) {
            let _ = std::fs::remove_dir_all(target);
            return Err(e);
        }
        Ok(repo)
    }

    /// Clone a remote vault repo with provider-specific credentials and
    /// progress reporting. Used by the daemon's `vault.clone_start` flow.
    ///
    /// Differs from [`clone`]/[`clone_unchecked`] in two ways:
    /// - uses `load_with_hint(target, provider)` so a multi-provider
    ///   install authenticates with the correct token rather than "first
    ///   connected provider" (avoids wrong-token 401s on clone). `None`
    ///   skips the provider hint: token fallbacks (any connected provider,
    ///   `BALUARD_GIT_TOKEN`, vault-stored file) still apply, and SSH
    ///   agent auth works for ssh:// URLs — private HTTPS repos with no
    ///   credential source fail closed.
    /// - wires git2's `transfer_progress` callback into `progress` so the
    ///   daemon can poll objects/bytes for a live progress bar.
    pub fn clone_remote(
        url: &str,
        target: &Path,
        provider: Option<crate::providers::types::Provider>,
        progress: std::sync::Arc<std::sync::Mutex<CloneProgress>>,
    ) -> Result<Repository, BaluardError> {
        Self::clone_remote_cancelable(url, target, provider, progress, None)
    }

    pub fn clone_remote_cancelable(
        url: &str,
        target: &Path,
        provider: Option<crate::providers::types::Provider>,
        progress: std::sync::Arc<std::sync::Mutex<CloneProgress>>,
        cancel_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<Repository, BaluardError> {
        validate_git_url(url)?;
        crate::sync::tls::ensure_tls_roots();
        let mut builder = RepoBuilder::new();
        let cred_config = CredentialConfig::load_with_hint(target, provider);
        let mut fetch_opts = FetchOptions::new();
        let https_token = cred_config.expose_token();
        let prog = progress.clone();
        let cancel = cancel_flag.clone();
        let mut callbacks = git2::RemoteCallbacks::new();
        callbacks.credentials(move |_url, username_from_url, allowed_types| {
            if allowed_types.contains(git2::CredentialType::SSH_KEY) {
                let user = username_from_url.unwrap_or("git");
                if let Ok(cred) = git2::Cred::ssh_key_from_agent(user) {
                    return Ok(cred);
                }
            }
            if allowed_types.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
                if let Some(ref token) = https_token {
                    let user = username_from_url.unwrap_or("git");
                    return git2::Cred::userpass_plaintext(user, token.as_str());
                }
            }
            if allowed_types.contains(git2::CredentialType::DEFAULT) {
                return git2::Cred::default();
            }
            Err(git2::Error::from_str("no credential source available"))
        });
        callbacks.certificate_check(|cert, host| {
            use git2::CertificateCheckStatus;
            use git2::cert::SshHostKeyType;
            if let Some(hostkey) = cert.as_hostkey() {
                let key_type = match hostkey.hostkey_type() {
                    Some(SshHostKeyType::Ed255219) => "ssh-ed25519",
                    Some(SshHostKeyType::Rsa) => "ssh-rsa",
                    Some(SshHostKeyType::Dss) => "ssh-dss",
                    Some(SshHostKeyType::Ecdsa256) => "ecdsa-sha2-nistp256",
                    Some(SshHostKeyType::Ecdsa384) => "ecdsa-sha2-nistp384",
                    Some(SshHostKeyType::Ecdsa521) => "ecdsa-sha2-nistp521",
                    _ => "",
                };
                let key = hostkey.hostkey().unwrap_or(&[]);
                match crate::sync::known_hosts::verify_host_key(host, key_type, key) {
                    crate::sync::known_hosts::HostKeyResult::Known => {
                        Ok(CertificateCheckStatus::CertificateOk)
                    }
                    _ => Err(git2::Error::from_str(&format!(
                        "SSH host key for {host} not in known_hosts"
                    ))),
                }
            } else {
                Ok(CertificateCheckStatus::CertificatePassthrough)
            }
        });
        callbacks.transfer_progress(move |p| {
            if let Some(ref flag) = cancel {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return false;
                }
            }
            if let Ok(mut g) = prog.lock() {
                g.objects_received = p.received_objects();
                g.total_objects = p.total_objects();
                g.bytes_received = p.received_bytes();
                g.indexed_deltas = p.indexed_deltas();
                g.total_deltas = p.total_deltas();
            }
            true
        });
        fetch_opts.remote_callbacks(callbacks);
        builder.fetch_options(fetch_opts);
        let repo = builder.clone(url, target).map_err(|e| {
            let mut msg = format!("clone: {e}");
            // Android TLS setup failures are silent by design; this is the
            // one place their reason reaches a user-visible surface.
            if let Some(diag) = crate::sync::tls::take_diag() {
                msg.push_str(&format!(" [tls: {diag}]"));
            }
            SyncError::Git(crate::sync::credentials::scrub_git_error(&msg))
        })?;
        // P2: verify the fetched history before handing it out.
        if let Err(e) = Self::verify_fetched_history(&repo) {
            let _ = std::fs::remove_dir_all(target);
            return Err(e);
        }
        Ok(repo)
    }
}

/// Local revocation verification tracker shape (gitignored, keyless).
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct RevocationTracker {
    /// Hex blob id of the last verified manifest version.
    #[serde(default)]
    blob: String,
    /// Revoked commit hexes already planned or applied locally.
    #[serde(default)]
    applied: Vec<String>,
}

/// Validate that a git URL uses an allowed scheme.
/// Permits: https://, ssh://, git@ (SSH shorthand).
/// In tests only: also permits file:// and absolute paths.
/// Rejects: git://, and all other schemes.
fn validate_git_url(url: &str) -> Result<(), BaluardError> {
    if url.starts_with("https://") || url.starts_with("ssh://") || url.starts_with("git@") {
        return Ok(());
    }
    #[cfg(test)]
    if url.starts_with("file://") || (url.starts_with('/') && !url.contains("://")) {
        return Ok(());
    }
    Err(SyncError::Git(format!(
        "unsupported URL scheme: {url}. Use https://, ssh://, or git@"
    ))
    .into())
}

impl SyncEngine {
    fn head_path(vault_path: &Path) -> PathBuf {
        vault_path.join("meta/sync-head.json")
    }

    fn load_last_head(vault_path: &Path) -> Option<String> {
        let path = Self::head_path(vault_path);
        let data = std::fs::read_to_string(&path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&data).ok()?;
        v["last_remote_head"].as_str().map(|s| s.to_string())
    }

    fn save_last_head(&self, oid: &str) -> Result<(), BaluardError> {
        let path = Self::head_path(&self.vault_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SyncError::Git(format!("create meta dir: {e}")))?;
        }
        let record = serde_json::json!({ "last_remote_head": oid });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record)
                .map_err(|e| SyncError::Git(format!("save head: {e}")))?,
        )?;
        Ok(())
    }

    /// Load Ed25519 signing key from OS keyring or meta/device-privkey.json.
    /// Returns None if no key found. Returns error if key is corrupt.
    fn load_signing_key(
        vault_path: &Path,
        devkey_seal: Option<&[u8; 32]>,
    ) -> Result<Option<ed25519_dalek::SigningKey>, BaluardError> {
        // Try OS keyring: read device IDs from devices.json and try each
        // (skipped in tests: unsigned binaries trigger keychain prompts; see
        // `crate::keyring_disabled`).
        if !crate::keyring_disabled() {
            let service = Self::keyring_service_for_vault(vault_path);
            if let Ok(devices_data) = std::fs::read_to_string(vault_path.join("meta/devices.json"))
            {
                if let Ok(devices) = serde_json::from_str::<serde_json::Value>(&devices_data) {
                    if let Some(device_map) = devices["devices"].as_object() {
                        for (device_id, _) in device_map {
                            if let Ok(entry) = keyring::Entry::new(&service, device_id) {
                                if let Ok(json) = entry.get_password() {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json)
                                    {
                                        if let Some(hex_str) = v["ed25519_private"].as_str() {
                                            if let Ok(bytes_vec) = hex::decode(hex_str) {
                                                let bytes: [u8; 32] =
                                                    bytes_vec.try_into().map_err(|_| {
                                                        SyncError::Git(
                                                            "privkey wrong length".into(),
                                                        )
                                                    })?;
                                                return Ok(Some(
                                                    ed25519_dalek::SigningKey::from_bytes(&bytes),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: sealed-or-legacy device-privkey file (C1). Sealed files
        // fail closed without the seal subkey.
        let path = vault_path.join("meta/device-privkey.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = crate::vault::device_privkey::read_privkey_file(&path, devkey_seal)
            .map_err(|e| SyncError::Git(format!("read privkey: {e}")))?;
        let v: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| SyncError::Git(format!("parse privkey: {e}")))?;
        let hex_str = v["ed25519_private"]
            .as_str()
            .ok_or_else(|| SyncError::Git("privkey missing ed25519_private field".into()))?;
        let mut bytes: [u8; 32] = hex::decode(hex_str)
            .map_err(|e| SyncError::Git(format!("decode privkey hex: {e}")))?
            .try_into()
            .map_err(|_| SyncError::Git("privkey wrong length".into()))?;
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        use zeroize::Zeroize;
        bytes.zeroize();
        Ok(Some(key))
    }

    /// Build keyring service name for a vault path (mirrors handle.rs keyring_service).
    fn keyring_service_for_vault(vault_path: &Path) -> String {
        let kdf_path = vault_path.join("meta/kdf-params.json");
        if let Ok(data) = std::fs::read_to_string(&kdf_path) {
            if let Ok(params) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(salt_hex) = params["salt"].as_str() {
                    if salt_hex.len() >= 16 {
                        return format!("baluard-{}", &salt_hex[..16]);
                    }
                }
            }
        }
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        vault_path.hash(&mut hasher);
        format!("baluard-fallback-{:016x}", hasher.finish())
    }

    /// Verify signatures for new commits pulled from remote.
    /// Uses git2's native extract_signature to get signature + signed data from commit object.
    /// The signature is embedded in the git commit object itself (gpgsig header).
    /// Returns number of verified commits. Returns error if any signature is invalid.
    /// Unsigned commits in the range cause an error (no backward compat for security).
    ///
    /// Roster-snapshot rule (P2): verifying keys are resolved per commit from
    /// THAT commit's first-parent tree (`meta/devices.json`, UUID-keyed
    /// DeviceRegistry), never from the worktree. A registry-rotation commit
    /// is verified with the parent's roster (routine rotation signs with the
    /// old key); commits after it use the new roster. Signatures bind to a
    /// device id; member/role resolution lands with membership v2 (P7).
    pub fn verify_commit_signatures(
        &self,
        repo: &Repository,
        new_oids: &[Oid],
    ) -> Result<usize, BaluardError> {
        if new_oids.is_empty() {
            return Ok(0);
        }

        let ordered = Self::topo_order_commits(repo, new_oids)?;

        // Roster-snapshot rule: each commit is verified against the registry
        // in its FIRST PARENT's tree (the pre-state). Genesis transition: a
        // commit whose parent line predates enrollment but which itself
        // introduces `meta/devices.json` verifies against its own tree (the
        // enroll commit carries the registry it signed under). Root commits:
        // own tree. Commits whose whole parent line predates enrollment are
        // grandfathered (skipped) — they can only enter a pull as ancient
        // merge second-parents. Rotation commits verify with the old key;
        // commits after them see the new registry.
        let mut roster_cache: std::collections::HashMap<git2::Oid, Option<DeviceRoster>> =
            std::collections::HashMap::new();
        for oid in &ordered {
            let commit = repo
                .find_commit(*oid)
                .map_err(|e| SyncError::Git(format!("walk: {e}")))?;
            if let Some(roster) = Self::roster_for_commit(repo, &commit, &mut roster_cache)? {
                let signer = self.verify_commit_against_roster(repo, *oid, &roster)?;
                Self::check_commit_paths(repo, &commit, &roster, &signer)?;
            }
        }

        Ok(ordered.len())
    }

    /// Verify an entire fetched history (clone path). Every commit is
    /// checked with the roster-snapshot rule: pre-enrollment commits (no
    /// registry on their parent line) are grandfathered; from the genesis
    /// enrollment commit onward every commit must carry a valid signature
    /// against the roster. A fully forged parallel history (registry
    /// stripped, signatures stripped) is accepted as "pre-enrollment" — an
    /// inherent TOFU limit at first clone, closed at pull time by head-anchored
    /// verification and later by P8 revocation manifests.
    fn verify_fetched_history(repo: &Repository) -> Result<(), BaluardError> {
        let head = repo
            .head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?
            .peel_to_commit()
            .map_err(|e| SyncError::Git(format!("head peel: {e}")))?;

        // Collect every commit root..HEAD (all parents — merge lines count).
        let mut oids = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![head.id()];
        while let Some(oid) = stack.pop() {
            if !visited.insert(oid) {
                continue;
            }
            let commit = repo
                .find_commit(oid)
                .map_err(|e| SyncError::Git(format!("walk: {e}")))?;
            oids.push(oid);
            for i in 0..commit.parent_count() {
                let pid = commit
                    .parent_id(i)
                    .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?;
                stack.push(pid);
            }
        }
        // Order parents-first so failures surface deterministically.
        let ordered = Self::topo_order_commits(repo, &oids)?;
        let mut roster_cache: std::collections::HashMap<git2::Oid, Option<DeviceRoster>> =
            std::collections::HashMap::new();
        for oid in &ordered {
            let commit = repo
                .find_commit(*oid)
                .map_err(|e| SyncError::Git(format!("walk: {e}")))?;
            if let Some(roster) = Self::roster_for_commit(repo, &commit, &mut roster_cache)? {
                let signer = Self::verify_commit_against_roster_static(repo, *oid, &roster)?;
                Self::check_commit_paths(repo, &commit, &roster, &signer)?;
            }
        }
        Ok(())
    }

    /// Roster in force for one commit, per the snapshot rule. `None` = the
    /// commit predates enrollment on its parent line (grandfathered).
    fn roster_for_commit(
        repo: &Repository,
        commit: &git2::Commit<'_>,
        cache: &mut std::collections::HashMap<git2::Oid, Option<DeviceRoster>>,
    ) -> Result<Option<DeviceRoster>, BaluardError> {
        let own = Self::roster_tree_lookup(repo, commit, cache)?;
        if commit.parent_count() == 0 {
            return Ok(own);
        }
        let parent = commit
            .parent(0)
            .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?;
        let parent_roster = Self::roster_tree_lookup(repo, &parent, cache)?;
        match (parent_roster, own) {
            (Some(r), _) => Ok(Some(r)),
            // Genesis enrollment transition: parent line predates the
            // registry, this commit introduces it.
            (None, Some(r)) => Ok(Some(r)),
            (None, None) => Ok(None),
        }
    }

    /// Parse `meta/devices.json` out of a commit's tree into a roster.
    /// Returns `None` when the file is absent (pre-enrollment tree).
    /// Present-but-unparseable is a hard error (tamper, fail closed).
    /// Results are cached per blob id — a pull batch re-parses each
    /// registry version once, not once per commit.
    fn roster_tree_lookup(
        repo: &Repository,
        commit: &git2::Commit<'_>,
        cache: &mut std::collections::HashMap<git2::Oid, Option<DeviceRoster>>,
    ) -> Result<Option<DeviceRoster>, BaluardError> {
        let tree = commit
            .tree()
            .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
        let entry = match tree.get_path(std::path::Path::new("meta/devices.json")) {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        let blob_id = entry.id();
        if let Some(cached) = cache.get(&blob_id) {
            return Ok(cached.clone());
        }
        let blob = repo
            .find_blob(blob_id)
            .map_err(|e| SyncError::Git(format!("read devices blob: {e}")))?;
        let data = std::str::from_utf8(blob.content())
            .map_err(|_| SyncError::Git("devices blob not UTF-8".into()))?;
        let parsed = match serde_json::from_str::<crate::devices::DeviceRegistry>(data) {
            Ok(reg) => {
                let mut roster = std::collections::BTreeMap::new();
                for (id, entry) in &reg.devices {
                    if let Ok(bytes) = hex::decode(&entry.signing_public_key) {
                        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                            roster.insert(id.to_string(), arr);
                        }
                    }
                }
                Some(roster)
            }
            Err(e) => {
                return Err(SyncError::Git(format!("parse devices blob: {e}")).into());
            }
        };
        cache.insert(blob_id, parsed.clone());
        Ok(parsed)
    }

    /// S1a: resolved member state for one commit: device UUID -> role,
    /// plus device UUID -> member id (for {member} path segments).
    /// `None` when the tree has no member directory (legacy vault,
    /// admin-equivalent). Present-but-unparseable or shape-violating
    /// files are a hard error (tamper, fail closed), mirroring the
    /// roster rule.
    fn members_tree_lookup(
        repo: &Repository,
        commit: &git2::Commit<'_>,
        cache: &mut std::collections::HashMap<git2::Oid, Option<MemberSnapshot>>,
    ) -> Result<Option<MemberSnapshot>, BaluardError> {
        let tree = commit
            .tree()
            .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
        let Ok(members_entry) =
            tree.get_path(std::path::Path::new(crate::vault::members::MEMBERS_DIR))
        else {
            return Ok(None);
        };
        // Cache by the SUBTREE id: the root tree id changes on every
        // commit, but the member subtree only changes when membership
        // does — a pull batch hits the cache for every unrelated commit.
        let subtree_id = members_entry.id();
        if let Some(cached) = cache.get(&subtree_id) {
            return Ok(cached.clone());
        }
        let members_prefix = format!("{}/", crate::vault::members::MEMBERS_DIR);
        let mut role_by_member: std::collections::BTreeMap<
            String,
            crate::sync::policy::CommitRole,
        > = std::collections::BTreeMap::new();
        let mut member_by_device: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut parse_err: Option<String> = None;
        tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
            if parse_err.is_some() {
                return -1;
            }
            if entry.kind() != Some(git2::ObjectType::Blob) {
                return 0;
            }
            let Some(name) = entry.name() else {
                return 0;
            };
            // String concat, never Path::join: the host separator must
            // not leak into POSIX git tree paths (Windows). git2 walk
            // roots are &str POSIX paths.
            let root_str = root;
            let path_str = if root_str.is_empty() {
                name.to_string()
            } else if let Some(stripped) = root_str.strip_suffix('/') {
                format!("{stripped}/{name}")
            } else {
                format!("{root_str}/{name}")
            };
            let Some(rel) = path_str.strip_prefix(&members_prefix) else {
                return 0;
            };
            if !rel.ends_with(".json") {
                // Non-member artifacts (e.g. .DS_Store) are inert: role
                // data comes only from validated .json files.
                return 0;
            }
            let Ok(obj) = entry.to_object(repo) else {
                parse_err = Some(format!("read {path_str}"));
                return -1;
            };
            let Ok(blob) = obj.into_blob() else {
                return 0;
            };
            let Ok(data) = std::str::from_utf8(blob.content()) else {
                parse_err = Some(format!("{path_str}: not UTF-8"));
                return -1;
            };
            let rel_parts: Vec<&str> = rel.split('/').collect();
            if rel_parts.len() == 1 {
                // Member file: <member_id>.json. The filename must agree
                // with the id inside, or the registry is tampered.
                let member_file: crate::vault::members::MemberFile =
                    match serde_json::from_str(data) {
                        Ok(m) => m,
                        Err(e) => {
                            parse_err = Some(format!("parse member {path_str}: {e}"));
                            return -1;
                        }
                    };
                let stem = rel_parts[0].strip_suffix(".json").unwrap_or(rel_parts[0]);
                if member_file.id.to_string() != stem {
                    parse_err = Some(format!(
                        "member file {path_str}: filename does not match id {}",
                        member_file.id
                    ));
                    return -1;
                }
                role_by_member.insert(
                    member_file.id.to_string(),
                    crate::sync::policy::CommitRole::from(member_file.role),
                );
            } else if rel_parts.len() == 3 && rel_parts[1] == "devices" {
                // Device binding: <member_id>/devices/<device_id>.json.
                // Directory and filename must agree with the payload, so
                // a binding cannot be forged into (or moved between)
                // someone else's member subtree.
                let binding: crate::vault::members::DeviceBinding = match serde_json::from_str(data)
                {
                    Ok(b) => b,
                    Err(e) => {
                        parse_err = Some(format!("parse binding {path_str}: {e}"));
                        return -1;
                    }
                };
                let member_dir = rel_parts[0];
                let device_stem = rel_parts[2].strip_suffix(".json").unwrap_or(rel_parts[2]);
                if binding.member_id.to_string() != member_dir
                    || binding.device_id.to_string() != device_stem
                {
                    parse_err = Some(format!(
                        "binding {path_str}: filename/dir do not match payload"
                    ));
                    return -1;
                }
                member_by_device
                    .insert(binding.device_id.to_string(), binding.member_id.to_string());
            } else {
                // Other artifacts in a member's own subtree (identity
                // escrow, requests) are not role data — skip them.
                return 0;
            }
            0
        })
        .map_err(|e| SyncError::Git(format!("member walk: {e}")))?;
        if let Some(e) = parse_err {
            return Err(SyncError::Git(format!("member directory: {e}")).into());
        }
        let mut roles: std::collections::BTreeMap<String, crate::sync::policy::CommitRole> =
            std::collections::BTreeMap::new();
        let mut member_of: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for (device, member) in &member_by_device {
            member_of.insert(device.clone(), member.clone());
            if let Some(role) = role_by_member.get(member) {
                roles.insert(device.clone(), *role);
            }
        }
        let snapshot = Some(MemberSnapshot { roles, member_of });
        cache.insert(subtree_id, snapshot.clone());
        Ok(snapshot)
    }

    /// S1a: member snapshot per commit, same snapshot rule as the
    /// roster: the FIRST parent's snapshot when present, else the
    /// commit's own (genesis, when this commit introduces the
    /// directory). `None` = no member directory on either side (legacy
    /// vault).
    fn member_table_for_commit(
        repo: &Repository,
        commit: &git2::Commit<'_>,
        cache: &mut std::collections::HashMap<git2::Oid, Option<MemberSnapshot>>,
    ) -> Result<Option<MemberSnapshot>, BaluardError> {
        let own = Self::members_tree_lookup(repo, commit, cache)?;
        if commit.parent_count() == 0 {
            return Ok(own);
        }
        let parent = commit
            .parent(0)
            .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?;
        let parent_table = Self::members_tree_lookup(repo, &parent, cache)?;
        match (parent_table, own) {
            (Some(m), _) => Ok(Some(m)),
            (None, Some(m)) => Ok(Some(m)),
            (None, None) => Ok(None),
        }
    }

    /// Order commits parents-first within the pulled batch so roster
    /// inheritance sees every parent before its children.
    fn topo_order_commits(repo: &Repository, oids: &[Oid]) -> Result<Vec<Oid>, BaluardError> {
        use std::collections::{HashMap, HashSet};
        let in_set: HashSet<Oid> = oids.iter().copied().collect();
        let mut order = Vec::with_capacity(oids.len());
        // 0 = unvisited, 1 = on stack (visiting), 2 = emitted.
        let mut marks: HashMap<Oid, u8> = HashMap::with_capacity(oids.len());
        // Iterative DFS: stack of (oid, next parent index to explore).
        let mut stack: Vec<(Oid, usize)> = Vec::new();
        for &start in oids {
            if marks.contains_key(&start) {
                continue;
            }
            marks.insert(start, 1);
            stack.push((start, 0));
            while let Some((oid, parent_idx)) = stack.pop() {
                let commit = repo
                    .find_commit(oid)
                    .map_err(|e| SyncError::Git(format!("walk: {e}")))?;
                let parent_count = commit.parent_count();
                let mut descended = false;
                let mut idx = parent_idx;
                while idx < parent_count {
                    let parent_oid = commit
                        .parent_id(idx)
                        .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?;
                    idx += 1;
                    if !in_set.contains(&parent_oid) {
                        continue;
                    }
                    match marks.get(&parent_oid) {
                        None => {
                            // Explore the child after this parent; park the
                            // child frame with its resume index first.
                            stack.push((oid, idx));
                            marks.insert(parent_oid, 1);
                            stack.push((parent_oid, 0));
                            descended = true;
                            break;
                        }
                        Some(1) => {
                            return Err(
                                SyncError::Git("commit cycle in pulled history".into()).into()
                            );
                        }
                        Some(_) => {} // parent already emitted
                    }
                }
                if descended {
                    continue;
                }
                marks.insert(oid, 2);
                order.push(oid);
            }
        }
        Ok(order)
    }

    /// Verify one commit's embedded signature against the roster in force.
    /// A match identifies the signing device, returned so the P7 net-diff
    /// check can resolve the signer's policy role; an empty roster or no
    /// match fails closed with InvalidCommitSignature.
    fn verify_commit_against_roster(
        &self,
        repo: &Repository,
        oid: Oid,
        roster: &DeviceRoster,
    ) -> Result<String, BaluardError> {
        Self::verify_commit_against_roster_static(repo, oid, roster)
    }

    /// P7 + P8a: every path a commit touches must be admitted by the
    /// signer's policy row (first-match table, deny by default). For a
    /// regular commit that is the first-parent diff (root commits diff
    /// against the empty tree). For a merge commit it is the RESIDUE: the
    /// difference between the actual tree and the recomputed merge of the
    /// two parents over their merge base — an honest merger's residue is
    /// empty; conflicted paths are attributed to the merger outright
    /// (a resolution is authored content). Octopus merges are never
    /// produced by this vault and are refused outright.
    fn check_commit_paths(
        repo: &Repository,
        commit: &git2::Commit<'_>,
        roster: &DeviceRoster,
        signer: &str,
    ) -> Result<(), BaluardError> {
        // S1a: resolve the signer's role from the member directory
        // snapshot (first-parent rule). Legacy vaults (no meta/members
        // subtree) stay admin-equivalent; strict vaults treat unbound
        // devices as pending joiners.
        let members =
            Self::member_table_for_commit(repo, commit, &mut std::collections::HashMap::new())?;
        let (role, member_id) = match members.as_ref() {
            Some(snapshot) => {
                let role = snapshot
                    .roles
                    .get(signer)
                    .copied()
                    .unwrap_or(crate::sync::policy::CommitRole::PendingJoiner);
                let member = snapshot.member_of.get(signer).map(String::as_str);
                (role, member)
            }
            None => (crate::sync::policy::CommitRole::Admin, None),
        };
        if commit.parent_count() > 2 {
            return Err(
                SyncError::Git("octopus merges are not produced by this vault".into()).into(),
            );
        }
        let tree = commit
            .tree()
            .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
        if commit.parent_count() <= 1 {
            // Regular commit: the first-parent diff is the author's edit
            // (root commits diff against the empty tree). NEVER applied to
            // merges: the other parent's clean content is not the
            // merger's authorship, and first-parent attribution would not
            // be parent-order invariant.
            let diff_parent = if commit.parent_count() == 1 {
                Some(
                    commit
                        .parent(0)
                        .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?,
                )
            } else {
                None
            };
            let parent_tree = match &diff_parent {
                Some(p) => Some(
                    p.tree()
                        .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?,
                ),
                None => None,
            };
            let diff = repo
                .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), None)
                .map_err(|e| SyncError::Git(format!("net diff: {e}")))?;
            for delta in diff.deltas() {
                Self::check_delta_path(repo, &delta, roster, signer, member_id, role)?;
            }
        }
        if commit.parent_count() == 2 {
            // P8a: recompute the expected merge from the parents over their
            // merge base; anything in the actual tree beyond it is the
            // merger's residue. Conflict resolutions are attributed to the
            // merger outright, so they are stripped from the expected index
            // and their paths pre-seeded into the residue set.
            let p1 = commit
                .parent(0)
                .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?;
            let p2 = commit
                .parent(1)
                .map_err(|e| SyncError::Git(format!("walk parent: {e}")))?;
            let base = repo
                .merge_base(p1.id(), p2.id())
                .map_err(|e| SyncError::Git(format!("merge base: {e}")))?;
            let base_tree = repo
                .find_commit(base)
                .map_err(|e| SyncError::Git(format!("walk base: {e}")))?
                .tree()
                .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
            let p1_tree = p1
                .tree()
                .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
            let p2_tree = p2
                .tree()
                .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
            let mut idx = repo
                .merge_trees(&base_tree, &p1_tree, &p2_tree, None)
                .map_err(|e| SyncError::Git(format!("recompute merge: {e}")))?;
            if idx.has_conflicts() {
                let mut conflicted: Vec<std::path::PathBuf> = Vec::new();
                for entry in idx
                    .conflicts()
                    .map_err(|e| SyncError::Git(format!("conflicts: {e}")))?
                    .filter_map(|r| r.ok())
                {
                    for e in [entry.our, entry.their, entry.ancestor]
                        .into_iter()
                        .flatten()
                    {
                        // IndexEntry.path is raw bytes. A non-UTF-8 path
                        // cannot be matched back onto the index: refuse
                        // with a clear error instead of a generic
                        // GIT_EUNMERGED at write_tree time.
                        conflicted.push(match String::from_utf8(e.path.clone()) {
                            Ok(s) => std::path::PathBuf::from(s),
                            Err(_) => {
                                return Err(
                                    SyncError::Git("conflicted path is not UTF-8".into()).into()
                                );
                            }
                        });
                    }
                }
                conflicted.sort();
                conflicted.dedup();
                for p in &conflicted {
                    // Exact removal: remove_all treats its argument as a
                    // glob/directory pathspec and would also strip
                    // non-conflicted entries under a conflicted directory.
                    // A conflicted path has no stage-0 entry to remove.
                    idx.conflict_remove(p.as_path())
                        .map_err(|e| SyncError::Git(format!("strip conflict: {e}")))?;
                }
                for p in &conflicted {
                    crate::sync::policy::authorize(signer, member_id, role, &p.to_string_lossy())
                        .map_err(BaluardError::from)?;
                }
            }
            let expected_oid = idx
                .write_tree_to(repo)
                .map_err(|e| SyncError::Git(format!("expected tree: {e}")))?;
            let expected = repo
                .find_tree(expected_oid)
                .map_err(|e| SyncError::Git(format!("walk tree: {e}")))?;
            let residue_diff = repo
                .diff_tree_to_tree(Some(&expected), Some(&tree), None)
                .map_err(|e| SyncError::Git(format!("merge residue diff: {e}")))?;
            for delta in residue_diff.deltas() {
                Self::check_delta_path(repo, &delta, roster, signer, member_id, role)?;
            }
        }
        Ok(())
    }

    /// One diff delta = one path's authorization. `meta/devices.json`
    /// gets a structural rule for non-admins: the only permitted delta is
    /// this device's own registry bump (last_seen_epoch on its own entry)
    /// — the per-commit epoch bump must not wedge lower roles, while
    /// adding, removing, or rekeying registry entries stays admin-only.
    fn check_delta_path(
        repo: &Repository,
        delta: &git2::DiffDelta,
        roster: &DeviceRoster,
        signer: &str,
        member: Option<&str>,
        role: crate::sync::policy::CommitRole,
    ) -> Result<(), BaluardError> {
        let Some(path) = delta.new_file().path().or_else(|| delta.old_file().path()) else {
            return Ok(());
        };
        let path = path.to_string_lossy().to_string();
        // S1a-4: member records (flat meta/members/<id>.json) written by a
        // non-admin signer: only the signer's OWN record, and only the
        // identity-rotation fields may change. Role, display name, and
        // trust are admin-owned; identity fields are self-service
        // (rotation visibility).
        if let Some(stem) = path
            .strip_prefix("meta/members/")
            .filter(|p| p.ends_with(".json") && !p[..p.len() - 5].contains('/'))
            .map(|p| &p[..p.len() - 5])
        {
            if role.rank() < crate::sync::policy::CommitRole::Admin.rank() {
                let own_member = member.and_then(|m| uuid::Uuid::parse_str(m).ok());
                let file_id = uuid::Uuid::parse_str(stem).ok();
                match (own_member, file_id) {
                    (Some(own), Some(file)) if own == file => {
                        return Self::check_member_record_identity_delta(
                            repo, delta, signer, member, role,
                        );
                    }
                    _ => {
                        return Err(SyncError::PolicyViolation {
                            device: signer.to_string(),
                            path: path.clone(),
                        }
                        .into());
                    }
                }
            }
        }
        // The integrity manifest rides every commit and is
        // self-authenticating: every checkpoint must verify against its
        // signing device's roster key. Role is irrelevant — a non-admin
        // updating their own signed checkpoints is legitimate, and a
        // forged or deleted manifest refuses.
        if path == "meta/integrity.json" {
            let deny = || {
                SyncError::PolicyViolation {
                    device: signer.to_string(),
                    path: path.clone(),
                }
                .into()
            };
            let new_id = delta.new_file().id();
            if new_id.is_zero() {
                return Err(deny());
            }
            let blob = repo.find_blob(new_id).map_err(|_| deny())?;
            let manifest: crate::integrity::IntegrityManifest =
                serde_json::from_slice(blob.content()).map_err(|_| deny())?;
            for (object_id, cp) in &manifest.checkpoints {
                let Some(vk) = roster.get(&cp.device_id) else {
                    return Err(deny());
                };
                manifest
                    .verify_checkpoint(object_id, vk)
                    .map_err(|_| deny())?;
            }
            // Containment: an honest update never drops or downgrades a
            // known checkpoint (an empty manifest would neuter rollback
            // detection).
            let old_id = delta.old_file().id();
            if !old_id.is_zero() {
                if let Ok(old_blob) = repo.find_blob(old_id) {
                    if let Ok(old_manifest) = serde_json::from_slice::<
                        crate::integrity::IntegrityManifest,
                    >(old_blob.content())
                    {
                        for (object_id, old_cp) in &old_manifest.checkpoints {
                            match manifest.checkpoints.get(object_id) {
                                Some(cp)
                                    if cp.device_id == old_cp.device_id && cp.seq >= old_cp.seq => {
                                }
                                _ => return Err(deny()),
                            }
                        }
                    }
                    // An unparseable OLD manifest: the new one is fully
                    // verified above on its own merits; keep going.
                }
            }
            return Ok(());
        }
        if path == "meta/devices.json"
            && role.rank() < crate::sync::policy::CommitRole::Admin.rank()
        {
            let blob_bytes = |oid: git2::Oid| -> Option<Vec<u8>> {
                if oid.is_zero() {
                    return None;
                }
                repo.find_blob(oid).ok().map(|b| b.content().to_vec())
            };
            let old = blob_bytes(delta.old_file().id());
            let new = blob_bytes(delta.new_file().id());
            if Self::registry_delta_is_own_bump(old.as_deref(), new.as_deref(), signer) {
                return Ok(());
            }
            return Err(SyncError::PolicyViolation {
                device: signer.to_string(),
                path,
            }
            .into());
        }
        crate::sync::policy::authorize(signer, member, role, &path).map_err(BaluardError::from)
    }

    /// S1a-4: a non-admin member's own record delta is allowed iff ONLY
    /// the identity-rotation fields changed (identity_signing_pubkey,
    /// identity_rotated_at). Role, display name, trust, and id are
    /// admin-owned. The new identity pubkey must be hex-32.
    #[allow(clippy::needless_pass_by_value)]
    fn check_member_record_identity_delta(
        repo: &Repository,
        delta: &git2::DiffDelta,
        signer: &str,
        member: Option<&str>,
        role: crate::sync::policy::CommitRole,
    ) -> Result<(), BaluardError> {
        debug_assert!(
            role.rank() < crate::sync::policy::CommitRole::Admin.rank(),
            "structural member-record rule is non-admin only"
        );
        let _ = role;
        let deny = || {
            SyncError::PolicyViolation {
                device: signer.to_string(),
                path: "meta/members".to_string(),
            }
            .into()
        };
        let blob = |oid: git2::Oid| -> Option<Vec<u8>> {
            if oid.is_zero() {
                return None;
            }
            repo.find_blob(oid).ok().map(|b| b.content().to_vec())
        };
        let (Some(old), Some(new)) = (blob(delta.old_file().id()), blob(delta.new_file().id()))
        else {
            return Err(deny());
        };
        let parse = |bytes: &[u8]| -> Option<crate::vault::members::MemberFile> {
            serde_json::from_str(std::str::from_utf8(bytes).ok()?).ok()
        };
        let (Some(old_member), Some(new_member)) = (parse(&old), parse(&new)) else {
            return Err(deny());
        };
        let own = member.and_then(|m| uuid::Uuid::parse_str(m).ok());
        if old_member.id != new_member.id
            || Some(new_member.id) != own
            || old_member.display_name != new_member.display_name
            || old_member.role != new_member.role
            || old_member.trust != new_member.trust
        {
            return Err(deny());
        }
        match new_member
            .identity_signing_pubkey
            .as_deref()
            .map(hex::decode)
        {
            Some(Ok(key)) if key.len() == 32 => {}
            _ => return Err(deny()),
        }
        Ok(())
    }

    /// S1a: registry deltas by a non-admin must be this device's own
    /// last_seen_epoch bump. Any addition, removal, key change, name
    /// change, or another device's bump refuses.
    fn registry_delta_is_own_bump(old: Option<&[u8]>, new: Option<&[u8]>, signer: &str) -> bool {
        let (Some(old), Some(new)) = (old, new) else {
            return false;
        };
        let (Ok(old_reg), Ok(new_reg)) = (
            serde_json::from_str::<crate::devices::DeviceRegistry>(
                std::str::from_utf8(old).unwrap_or(""),
            ),
            serde_json::from_str::<crate::devices::DeviceRegistry>(
                std::str::from_utf8(new).unwrap_or(""),
            ),
        ) else {
            return false;
        };
        let Ok(signer_id) = uuid::Uuid::parse_str(signer) else {
            return false;
        };
        if old_reg.version != new_reg.version {
            return false;
        }
        if old_reg.devices.len() != new_reg.devices.len() {
            return false;
        }
        for (id, old_entry) in &old_reg.devices {
            let Some(new_entry) = new_reg.devices.get(id) else {
                return false;
            };
            if old_entry.encryption_public_key != new_entry.encryption_public_key
                || old_entry.signing_public_key != new_entry.signing_public_key
                || old_entry.enrolled_by != new_entry.enrolled_by
                || old_entry.enrolled_at != new_entry.enrolled_at
            {
                return false;
            }
            if *id != signer_id && old_entry.last_seen_epoch != new_entry.last_seen_epoch {
                return false;
            }
        }
        new_reg.devices.contains_key(&signer_id)
    }

    /// Static variant used by the clone path (no engine instance needed —
    /// verification is a property of the fetched history, not of the local
    /// signing key).
    fn verify_commit_against_roster_static(
        repo: &Repository,
        oid: Oid,
        roster: &DeviceRoster,
    ) -> Result<String, BaluardError> {
        // Extract signature and signed data from the commit object
        let (sig_buf, content_buf) = repo
            .extract_signature(&oid, None)
            .map_err(|_| SyncError::InvalidCommitSignature)?;

        let sig_str = sig_buf.as_str().ok_or(SyncError::InvalidCommitSignature)?;
        let signed_data = content_buf
            .as_str()
            .ok_or(SyncError::InvalidCommitSignature)?;

        // Parse the signature: extract base64 between header/footer
        let sig_b64 = Self::extract_b64_from_sig_field(sig_str)?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|_| SyncError::InvalidCommitSignature)?;

        // Find the roster key that validates this signature. The matching
        // entry IS the signing device binding; the P7 net-diff check
        // resolves the signer's policy row from it.
        for (device_id, vk_bytes) in roster {
            if crate::sync::commit::verify_commit_signature(
                vk_bytes,
                signed_data.as_bytes(),
                &sig_bytes,
            )
            .is_ok()
            {
                return Ok(device_id.clone());
            }
        }
        Err(SyncError::InvalidCommitSignature.into())
    }

    /// Extract base64 payload from the "-----BEGIN BALUARD SIGNATURE-----\n<b64>\n-----END BALUARD SIGNATURE-----" format.
    /// Strips git gpgsig continuation-line spaces (space-prefixed lines) from the raw field.
    fn extract_b64_from_sig_field(sig_str: &str) -> Result<String, SyncError> {
        // Strip leading spaces from continuation lines (git gpgsig format)
        let normalized: String = sig_str
            .lines()
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        let begin = "-----BEGIN BALUARD SIGNATURE-----\n";
        let end = "\n-----END BALUARD SIGNATURE-----";
        let start = normalized
            .find(begin)
            .ok_or(SyncError::InvalidCommitSignature)?
            + begin.len();
        let rest = &normalized[start..];
        let end_pos = rest.find(end).ok_or(SyncError::InvalidCommitSignature)?;
        Ok(rest[..end_pos].to_string())
    }

    /// Sanity-check the loaded signing key against this device's registry
    /// entry (P2). A mismatch is logged but NOT fatal: the commit signature
    /// carries no device claim, so binding is enforced pull-side by the
    /// roster (a key absent from the roster is rejected on pull). Hard-
    /// disabling here would wedge the legitimate rotation moment, where the
    /// old key legitimately signs while the registry already lists the new.
    fn warn_on_signing_key_mismatch(
        vault_path: &Path,
        device_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) {
        let Ok(id) = uuid::Uuid::parse_str(device_id) else {
            return;
        };
        let Ok(data) = std::fs::read_to_string(vault_path.join("meta/devices.json")) else {
            return;
        };
        let Ok(reg) = serde_json::from_str::<crate::devices::DeviceRegistry>(&data) else {
            return;
        };
        let Some(entry) = reg.devices.get(&id) else {
            return;
        };
        let Ok(enrolled) = hex::decode(&entry.signing_public_key) else {
            return;
        };
        if enrolled.as_slice() != key.verifying_key().as_bytes() {
            eprintln!(
                "warning: loaded signing key does not match enrolled device {id}; commits will still verify under the key's own roster entry"
            );
        }
    }
}

/// Working tree status summary.
#[derive(Debug, Default)]
pub struct WorkTreeStatus {
    pub staged: usize,
    pub unstaged: usize,
}

impl WorkTreeStatus {
    pub fn is_dirty(&self) -> bool {
        self.staged > 0 || self.unstaged > 0
    }
}

/// Simplified commit info for log display.
#[derive(Debug)]
pub struct CommitInfo {
    pub id: String,
    pub message: String,
    pub author: String,
    pub time: i64,
}

/// Result of a pull operation.
#[derive(Debug, PartialEq)]
pub enum PullResult {
    AlreadyUpToDate,
    FastForward,
    Merged,
    /// Merge conflict detected. Contains list of conflicting cipher file paths
    /// plus the local and remote OIDs needed for resolve_conflicts().
    /// Caller should decrypt base/local/remote versions, run 3-way merge via
    /// conflict::merge_ciphers, re-encrypt, and call resolve_conflicts().
    Conflict {
        files: Vec<String>,
        local_oid: Oid,
        remote_oid: Oid,
    },
}

/// Caller's decision for a pull conflict, returned from the resolver closure
/// passed to [`SyncEngine::run_sync_cycle_with_resolver`].
///
/// This is the seam between the crypto-agnostic engine and the daemon-side
/// field-level merger (Phase 2b). Today the only options are "fall back to the
/// Phase 1 keep-local path" and "pause for field-level resolution".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Keep the local side (Phase 1 behavior). The cycle writes a 2-parent
    /// merge commit and completes normally.
    KeepLocal,
    /// Pause the cycle and surface the conflict to the caller for field-level
    /// resolution. Returns [`SyncCycleOutcome::NeedsDecision`].
    Pause,
}

/// Outcome of one full commit → pull → resolve → push cycle.
///
/// Git2-free so callers (the daemon auto-sync coordinator) can consume it
/// without a direct git2 dependency. `conflicts` counts conflict resolutions
/// performed this cycle (0 = clean sync).
#[derive(Debug, PartialEq)]
pub enum SyncCycleOutcome {
    /// Local changes committed + pushed (and any remote changes pulled).
    Synced { conflicts: u32 },
    /// Remote unreachable (network/transport failure). Caller should retry.
    Offline,
    /// A pull conflict was detected and the caller opted in to field-level
    /// resolution via [`SyncEngine::run_sync_cycle_with_resolver`]. The cycle
    /// is PAUSED at commit→pull→conflict-detect: no merge commit has been
    /// written and no push has happened. The caller must decrypt the
    /// base/local/remote blobs for each file in `pending`, run
    /// [`conflict::merge_ciphers`], and either:
    ///   - write auto-merged blobs + call [`SyncEngine::finalize_conflicts`]
    ///     (resumes the push), or
    ///   - hold the state for a human verdict and call `finalize_conflicts`
    ///     once the user picks (keep_local / keep_remote / keep_both).
    ///
    /// Repo state on return: HEAD is UNCHANGED (still at the local tip). The
    /// index and working tree are left in git's unmerged-conflict state from
    /// `Repository::merge` (`cleanup_state()` cleared MERGE_HEAD/MERGE_MSG but
    /// the conflicted index entries + any conflict-marked working files
    /// persist). The state machine is in `Merging`. `finalize_conflicts` (or
    /// the keep-local fallback) writes the resolution commit and transitions
    /// back to `Idle`. If the caller drops `pending` without resolving, the
    /// next cycle's `commit_all` may trip on the dirty/conflicted index; the
    /// safe recovery is `resolve_conflict_keep_local` or an explicit reset, not
    /// a blind re-pull.
    NeedsDecision { pending: Vec<PendingConflictState> },
}

/// State carried across the daemon boundary while a field-level conflict is
/// paused for resolution. Built by the engine on `PullResult::Conflict`;
/// consumed by [`SyncEngine::finalize_conflicts`] once the daemon has decided.
///
/// Plain data (no git2 types, no secrets): the conflicting file paths plus
/// the local/remote OIDs needed to read base/local/remote blobs via
/// [`SyncEngine::read_blob_from_commit`] and to write the merge commit via
/// [`SyncEngine::resolve_conflicts`]. The file paths are not secret, but the
/// daemon stores this alongside its decrypted `ConflictInfo` and zeroizes the
/// whole holding struct on drop / lock for hygiene (the OIDs are cheap to
/// clear and it avoids a second Drop impl on the daemon side).
///
/// `NeedsDecision` carries a `Vec` of these for forward-compat with batched
/// multi-file conflicts; today a single `pull()` yields at most one
/// `PullResult::Conflict`, so the Vec holds 0 or 1 entries in practice.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingConflictState {
    /// Conflicting cipher file paths (relative to vault root), e.g.
    /// `ciphers/<cipher_id>.enc`.
    pub files: Vec<String>,
    /// Local tip OID at the moment of conflict (the side we committed).
    pub local_oid: Oid,
    /// Remote tip OID that conflicted (the side we pulled).
    pub remote_oid: Oid,
}

/// .gitignore content for vault repos.
const GITIGNORE_CONTENT: &str = "\
# Secrets and private keys (CLI mode)
meta/device-privkey.json
meta/device-id
meta/member-unlock.json
meta/kdf-attempts.json
meta/git-credentials.json

# Legacy plaintext metadata (now encrypted as folders.enc/tags.enc/activity.enc)
meta/folders.json
meta/tag_index.json
meta/device_activity.json

# Sync engine internals — local-only bookkeeping, never synced
meta/sync-head.json
meta/sync-state.json

# Cipher lookup index — local-only, rebuilt from ciphers on demand (P5b).
# Tracked copies caused constant multi-device conflicts: the index is
# rewritten on every cipher CRUD on every device.
meta/index.enc
meta/index.enc.*

# P8b: local revocation verification tracker (blob id + applied list).
meta/revocations-verified.json

# Build artifacts
target/
*.swp
*.swo
*~

# OS artifacts
.DS_Store
Thumbs.db

# Pi agent
.pi/
";

/// Classify a remote (push/fetch) git2 error by its error class. Transport
/// failures (network, HTTP, SSH, auth, proxy, SSL) map to
/// [`SyncError::Network`] so callers can distinguish "offline / retry" from a
/// real data error. Everything else stays a [`SyncError::Git`]. Credentials
/// are scrubbed before the message is stored.
///
/// H1 fix: previously all push/fetch failures (including connection refused,
/// DNS failure, timeouts) were wrapped as `SyncError::Git`, so the daemon's
/// offline detector (`SyncError::Network` match) never fired and offline edits
/// never retried.
fn classify_remote_err(context: &str, e: &git2::Error) -> BaluardError {
    use git2::ErrorClass;
    let scrubbed = crate::sync::credentials::scrub_git_error(&format!("{context}: {e}"));
    let is_transport = matches!(
        e.class(),
        ErrorClass::Net | ErrorClass::Http | ErrorClass::Ssh | ErrorClass::Ssl
    );
    if is_transport {
        BaluardError::Sync(SyncError::Network(scrubbed))
    } else {
        BaluardError::Sync(SyncError::Git(scrubbed))
    }
}

/// True for errors that look like network/transport failures. Used by callers
/// (auto-sync) to decide whether to enter a retry loop.
pub fn is_network_error(e: &BaluardError) -> bool {
    matches!(e, BaluardError::Sync(SyncError::Network(_)))
}

#[cfg(test)]
#[cfg(feature = "git-sync")]
mod tests {
    use super::*;

    fn make_test_repo() -> (tempfile::TempDir, SyncEngine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = SyncEngine::new(dir.path(), "test-device", None);
        (dir, engine)
    }

    /// fetch_locked (mobile background sync): fetches objects but never moves
    /// HEAD or the worktree, reports remote-ahead correctly, and refuses when
    /// the sync state machine is busy.
    #[test]
    fn fetch_locked_is_fetch_only() {
        // Source repo = the "remote".
        let (dir, engine) = make_test_repo();
        std::fs::write(dir.path().join("cipher.enc"), b"v1").unwrap();
        let _ = engine.init_repo().unwrap();

        // Clone it (file:// stands in for the provider remote).
        let clone_dir = tempfile::tempdir().unwrap();
        let progress = std::sync::Arc::new(std::sync::Mutex::new(CloneProgress::default()));
        SyncEngine::clone_remote(
            &format!("file://{}", dir.path().display()),
            clone_dir.path(),
            Some(crate::providers::types::Provider::GitHub),
            progress,
        )
        .unwrap();
        let clone_engine = SyncEngine::new(clone_dir.path(), "clone-device", None);

        // No remote change yet -> up to date (false).
        {
            let repo = clone_engine.open_repo().unwrap();
            assert!(!clone_engine.fetch_locked(&repo, "origin").unwrap());
        }

        // Advance the remote.
        std::fs::write(dir.path().join("cipher.enc"), b"v2").unwrap();
        engine
            .commit_all(&engine.open_repo().unwrap(), "advance")
            .unwrap();

        // fetch_locked reports remote-ahead WITHOUT moving HEAD or worktree.
        {
            let repo = clone_engine.open_repo().unwrap();
            assert!(clone_engine.fetch_locked(&repo, "origin").unwrap());
            let head = repo.head().unwrap().peel_to_commit().unwrap().id();
            std::fs::read(clone_dir.path().join("cipher.enc"))
                .expect("worktree file must still exist");
            // Same HEAD as before the fetch: objects only.
            let repo2 = clone_engine.open_repo().unwrap();
            assert_eq!(head, repo2.head().unwrap().peel_to_commit().unwrap().id());
        }

        // Busy state machine -> refused.
        {
            let mut sm = clone_engine.state_machine.borrow_mut();
            sm.current = SyncState::Merging;
        }
        let repo = clone_engine.open_repo().unwrap();
        assert!(clone_engine.fetch_locked(&repo, "origin").is_err());
    }

    /// Phase 4: clone_remote must surface fetch progress via the
    /// transfer_progress callback (the daemon polls it for the desktop bar)
    /// and clone from a provider-hinted source. file:// is permitted under
    /// #[cfg(test)], so a local repo stands in for a remote provider.
    #[test]
    fn clone_remote_updates_progress() {
        let (dir, engine) = make_test_repo();
        std::fs::write(dir.path().join("cipher.enc"), b"\x01\x02\x03").unwrap();
        let _ = engine.init_repo().unwrap();

        let clone_dir = tempfile::tempdir().unwrap();
        let progress = std::sync::Arc::new(std::sync::Mutex::new(CloneProgress::default()));
        let cloned = SyncEngine::clone_remote(
            &format!("file://{}", dir.path().display()),
            clone_dir.path(),
            Some(crate::providers::types::Provider::GitHub),
            progress.clone(),
        )
        .expect("clone_remote should succeed for a local file:// source");

        // Clone produced a working repo with the content.
        assert!(clone_dir.path().join("cipher.enc").exists());
        assert!(clone_dir.path().join(".git").exists());
        let _ = cloned;

        // Progress was surfaced by the transfer_progress callback. A
        // single-commit repo transfers at least one object.
        let p = progress.lock().unwrap();
        assert!(
            p.total_objects >= 1,
            "total_objects should be >= 1, got {}",
            p.total_objects
        );
        assert_eq!(p.objects_received, p.total_objects);
    }

    /// Phase 4: a bad source URL must surface an error (adversarial: the
    /// caller must not get a silent success on a non-existent remote).
    #[test]
    fn clone_remote_rejects_unreachable_source() {
        let clone_dir = tempfile::tempdir().unwrap();
        let progress = std::sync::Arc::new(std::sync::Mutex::new(CloneProgress::default()));
        let url = format!("file://{}/does-not-exist", clone_dir.path().display());
        let result = SyncEngine::clone_remote(
            &url,
            clone_dir.path(),
            Some(crate::providers::types::Provider::GitLab),
            progress,
        );
        assert!(result.is_err(), "cloning a non-existent source must fail");
    }

    /// clone-url support: a provider-less clone must work for sources
    /// needing no credentials (public repos, file://, ssh-agent), and the
    /// provider hint stays optional end to end.
    #[test]
    fn clone_remote_works_without_provider_hint() {
        let (dir, engine) = make_test_repo();
        std::fs::write(dir.path().join("cipher.enc"), b"\x01\x02\x03").unwrap();
        let _ = engine.init_repo().unwrap();

        let clone_dir = tempfile::tempdir().unwrap();
        let progress = std::sync::Arc::new(std::sync::Mutex::new(CloneProgress::default()));
        let cloned = SyncEngine::clone_remote(
            &format!("file://{}", dir.path().display()),
            clone_dir.path(),
            None,
            progress,
        )
        .expect("provider-less clone should succeed for a credential-free source");
        let _ = cloned;
        assert!(clone_dir.path().join("cipher.enc").exists());
    }

    #[test]
    fn init_and_commit() {
        let (dir, engine) = make_test_repo();

        // Create a test file
        std::fs::write(dir.path().join("test.txt"), "hello").unwrap();

        let repo = engine.init_repo().unwrap();
        assert!(dir.path().join(".git").exists());
        assert!(dir.path().join(".gitignore").exists());

        // Should have 1 commit
        let log = engine.log(&repo, 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].message, "vault update");
    }

    #[test]
    fn multiple_commits() {
        let (dir, engine) = make_test_repo();
        let repo = engine.init_repo().unwrap();

        // Second commit
        std::fs::write(dir.path().join("data.enc"), b"\x00\x01\x02").unwrap();
        engine.commit_all(&repo, "").unwrap();

        let log = engine.log(&repo, 10).unwrap();
        assert_eq!(log.len(), 2);
        // Both have static message
        for c in &log {
            assert_eq!(c.message, "vault update");
        }
    }

    #[test]
    fn status_detects_changes() {
        let (dir, engine) = make_test_repo();
        let repo = engine.init_repo().unwrap();

        // Clean
        let status = engine.status(&repo).unwrap();
        assert!(!status.is_dirty());

        // Add untracked file
        std::fs::write(dir.path().join("new.enc"), b"encrypted").unwrap();
        let status = engine.status(&repo).unwrap();
        assert!(status.is_dirty());
    }

    /// Regression: status() must never report local-only engine internals
    /// (sync-head.json, sync-state.json) as dirty. These are rewritten
    /// outside the commit cycle (push saves sync-head, transitions save
    /// sync-state), so without filtering the worktree stays dirty after every
    /// sync and the badge never clears. Covers both the untracked case (new
    /// vaults with gitignore) and the tracked case (older vaults that
    /// committed them before the gitignore entry existed).
    #[test]
    fn status_ignores_local_engine_internals() {
        let (dir, engine) = make_test_repo();
        let repo = engine.init_repo().unwrap();

        std::fs::create_dir_all(dir.path().join("meta")).unwrap();

        // Case 1: untracked + gitignored rewrite (new vault path).
        std::fs::write(dir.path().join("meta/sync-head.json"), b"{\"oid\":\"abc\"}").unwrap();
        let status = engine.status(&repo).unwrap();
        assert!(
            !status.is_dirty(),
            "untracked sync-head should not dirty tree"
        );

        // Case 2: force-add + commit so it's tracked in HEAD (old vault path),
        // then rewrite. commit_all's add_all respects gitignore, so commit
        // directly to bypass it.
        {
            use git2::Signature;
            let mut index = repo.index().unwrap();
            index
                .add_path(std::path::Path::new("meta/sync-head.json"))
                .unwrap();
            index.write().unwrap();
            let tree_id = repo.index().unwrap().write_tree().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();
            let head = repo.head().unwrap().peel_to_commit().unwrap();
            let sig = Signature::now("test", "test@test").unwrap();
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "force-add internal",
                &tree,
                &[&head],
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("meta/sync-head.json"), b"{\"oid\":\"def\"}").unwrap();
        let status = engine.status(&repo).unwrap();
        assert!(
            !status.is_dirty(),
            "tracked-then-rewritten sync-head should not dirty tree (the bug)"
        );

        // Sanity: a normal tracked file rewrite IS still detected.
        std::fs::write(dir.path().join(".gitignore"), b"overwritten\n").unwrap();
        let status = engine.status(&repo).unwrap();
        assert!(status.is_dirty(), "normal rewrite should still dirty tree");
    }

    /// Regression: commit_all must leave the worktree clean. Previously it
    /// rewrote the git-tracked `meta/devices.json` (last_seen_epoch bump)
    /// AFTER snapshotting the commit tree, so every commit immediately
    /// re-dirtied the tree and the sync badge stayed on "Changes pending".
    #[test]
    fn commit_all_leaves_tree_clean() {
        let (dir, engine) = make_test_repo();
        let repo = engine.init_repo().unwrap();

        // Seed a tracked file + a real enrolled registry (production shape:
        // an enrolled vault refuses unsigned commits) so bump_device_epoch
        // has a target to rewrite (the original bug source).
        std::fs::write(dir.path().join("data.enc"), b"\x00\x01\x02").unwrap();
        enroll_device(
            dir.path(),
            &uuid::Uuid::new_v4(),
            &crate::crypto::signature::generate_ed25519_keypair().0,
        );
        // Recreate the engine so it loads the key written by enrollment.
        let engine = SyncEngine::new(dir.path(), "test-device", None);

        engine.commit_all(&repo, "").unwrap();

        // The tree MUST be clean immediately after commit_all returns.
        let status = engine.status(&repo).unwrap();
        assert!(
            !status.is_dirty(),
            "commit_all left the worktree dirty (staged={}, unstaged={}) — \
             post-commit metadata write must not escape the commit",
            status.staged,
            status.unstaged
        );
    }

    /// P5a: once the registry bytes are stable, repeated commits from this
    /// device carry NO devices.json delta — the bump skips the write when
    /// the serialized bytes are unchanged. This kills the multi-writer
    /// conflict where every device churned the one shared tracked file on
    /// every commit.
    #[test]
    fn commit_does_not_churn_devices_json_when_epoch_unchanged() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let id = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id, &key);
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":7}").unwrap();
        std::fs::write(dir.path().join("a.enc"), b"\x01").unwrap();
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        let repo = engine.init_repo().unwrap();
        engine.commit_all(&repo, "first").unwrap();

        let before = std::fs::read(dir.path().join("meta/devices.json")).unwrap();

        // Second commit: only a data change, epoch untouched.
        std::fs::write(dir.path().join("b.enc"), b"\x02").unwrap();
        let second = engine.commit_all(&repo, "second").unwrap();

        let after = std::fs::read(dir.path().join("meta/devices.json")).unwrap();
        assert_eq!(before, after, "bump must not rewrite an unchanged registry");

        // Tree-level: the second commit must not touch meta/devices.json.
        let parent = repo
            .find_commit(second)
            .unwrap()
            .parent(0)
            .unwrap()
            .tree()
            .unwrap();
        let tree = repo.find_commit(second).unwrap().tree().unwrap();
        let diff = repo
            .diff_tree_to_tree(Some(&parent), Some(&tree), None)
            .unwrap();
        for delta in diff.deltas() {
            let path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            assert_ne!(
                path, "meta/devices.json",
                "commit churned devices.json with no epoch change"
            );
        }

        // And when the epoch DOES change, the bump must land in the commit.
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":8}").unwrap();
        let third = engine.commit_all(&repo, "epoch change").unwrap();
        let parent = repo
            .find_commit(third)
            .unwrap()
            .parent(0)
            .unwrap()
            .tree()
            .unwrap();
        let tree = repo.find_commit(third).unwrap().tree().unwrap();
        let diff = repo
            .diff_tree_to_tree(Some(&parent), Some(&tree), None)
            .unwrap();
        let touched: Vec<String> = diff
            .deltas()
            .filter_map(|d| d.new_file().path().map(|p| p.to_string_lossy().to_string()))
            .collect();
        assert!(
            touched.iter().any(|p| p == "meta/devices.json"),
            "epoch change must land the devices.json bump, touched: {touched:?}"
        );
    }

    // ── P8a: merge-residue rule ──

    /// Build a tree from an optional base plus flat (name, bytes) entries.
    fn tree_with<'r>(
        repo: &'r git2::Repository,
        base: Option<&git2::Tree<'_>>,
        files: &[(&str, &[u8])],
    ) -> Result<git2::Tree<'r>, BaluardError> {
        let mut tb = repo
            .treebuilder(base)
            .map_err(|e| SyncError::Git(format!("treebuilder: {e}")))?;
        for (name, content) in files {
            let blob = repo
                .blob(content)
                .map_err(|e| SyncError::Git(format!("blob: {e}")))?;
            tb.insert(name, blob, 0o100644)
                .map_err(|e| SyncError::Git(format!("insert {name}: {e}")))?;
        }
        let oid = tb
            .write()
            .map_err(|e| SyncError::Git(format!("treebuilder write: {e}")))?;
        let tree = repo
            .find_tree(oid)
            .map_err(|e| SyncError::Git(format!("find tree: {e}")));
        Ok(tree?)
    }

    /// Fixture: enrolled repo with divergent lines from a shared base
    /// ({a.enc: base}). Line 1 always adds b.enc; line 2 always adds
    /// c.enc. `line1_a`/`line2_a` rewrite a.enc on that line (v1 / v2):
    /// both true = a real 3-way conflict on a.enc; both false = clean
    /// disjoint merge. Returns (dir, engine, repo, c1, c2).
    fn divergent_repo(
        line1_a: bool,
        line2_a: bool,
    ) -> Result<
        (
            tempfile::TempDir,
            SyncEngine,
            git2::Repository,
            git2::Oid,
            git2::Oid,
        ),
        BaluardError,
    > {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let id = uuid::Uuid::new_v4();
        let (dir, _) = make_test_repo();
        enroll_device(dir.path(), &id, &key);
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        let repo = engine.init_repo().unwrap();
        std::fs::write(dir.path().join("a.enc"), b"base").unwrap();
        engine.commit_all(&repo, "base").unwrap();
        let c0 = repo.head().unwrap().peel_to_commit().unwrap().id();

        std::fs::write(dir.path().join("b.enc"), b"line1").unwrap();
        if line1_a {
            std::fs::write(dir.path().join("a.enc"), b"v1").unwrap();
        }
        engine.commit_all(&repo, "line1").unwrap();
        let c1 = repo.head().unwrap().peel_to_commit().unwrap().id();

        {
            let c0_commit = repo.find_commit(c0).unwrap();
            repo.reset(c0_commit.as_object(), git2::ResetType::Hard, None)
                .unwrap();
        }
        std::fs::write(dir.path().join("c.enc"), b"c2c").unwrap();
        if line2_a {
            std::fs::write(dir.path().join("a.enc"), b"v2").unwrap();
        }
        engine.commit_all(&repo, "line2").unwrap();
        let c2 = repo.head().unwrap().peel_to_commit().unwrap().id();
        Ok((dir, engine, repo, c1, c2))
    }

    /// P8a: an honest merge (content exactly equal to the recomputed
    /// merge of both parents) carries no residue and must verify.
    #[test]
    fn honest_merge_carries_no_residue() {
        let (_dir, engine, repo, c1, c2) = divergent_repo(true, true).unwrap();
        // Both lines rewrote a.enc -> merge_trees really conflicts; the
        // merge tree resolves it to v1 and keeps line 2's unique c.enc.
        let resolution = tree_with(
            &repo,
            Some(&repo.find_commit(c1).unwrap().tree().unwrap()),
            &[("c.enc", b"c2c")],
        )
        .unwrap();
        let sig = git2::Signature::now("t", "t@example.com").unwrap();
        let c1_commit = repo.find_commit(c1).unwrap();
        let c2_commit = repo.find_commit(c2).unwrap();
        let merge = engine
            .create_signed_commit(&repo, &sig, "merge", &resolution, &[&c1_commit, &c2_commit])
            .unwrap();
        let verified = engine.verify_commit_signatures(&repo, &[merge]);
        assert!(verified.is_ok(), "honest merge must verify: {verified:?}");
    }

    /// P8a: content beyond the recomputed merge is the merger's residue
    /// and a path no policy row covers must refuse the whole commit.
    #[test]
    fn smuggled_merge_residue_refused() {
        let (_dir, engine, repo, c1, c2) = divergent_repo(false, false).unwrap();
        // Non-conflicted lines (b.enc / c.enc): honest expected merge plus
        // a smuggled nested file that no policy row covers.
        let c1_commit = repo.find_commit(c1).unwrap();
        let c2_commit = repo.find_commit(c2).unwrap();
        let c_enc = c2_commit
            .tree()
            .unwrap()
            .get_path(std::path::Path::new("c.enc"))
            .unwrap()
            .id();
        let inner = tree_with(&repo, None, &[("smug.enc", b"\xff")]).unwrap();
        let mut tb = repo.treebuilder(Some(&c1_commit.tree().unwrap())).unwrap();
        tb.insert("c.enc", c_enc, 0o100644).unwrap();
        tb.insert("unknown", inner.id(), 0o040000).unwrap();
        let tree = repo.find_tree(tb.write().unwrap()).unwrap();
        let sig = git2::Signature::now("t", "t@example.com").unwrap();
        let merge = engine
            .create_signed_commit(&repo, &sig, "merge", &tree, &[&c1_commit, &c2_commit])
            .unwrap();
        let verified = engine.verify_commit_signatures(&repo, &[merge]);
        assert!(
            matches!(
                &verified,
                Err(BaluardError::Sync(SyncError::PolicyViolation { .. }))
            ),
            "smuggled merge residue must be refused, got {verified:?}"
        );
    }

    /// P8a: a merger's conflict resolution is residue attributed to the
    /// signer. An admitted resolution (editor-scope path, admin-equivalent
    /// roster) passes; smuggled extra content on the same merge refuses.
    #[test]
    fn conflicted_resolution_attributed_to_merger() {
        let (_dir, engine, repo, c1, c2) = divergent_repo(true, true).unwrap();
        // Both lines rewrote a.enc -> merge_trees really conflicts; the
        // merge tree resolves it to v1 and keeps line 2's unique c.enc.
        let honest = tree_with(
            &repo,
            Some(&repo.find_commit(c1).unwrap().tree().unwrap()),
            &[("c.enc", b"c2c")],
        )
        .unwrap();
        let sig = git2::Signature::now("t", "t@example.com").unwrap();
        let c1_commit = repo.find_commit(c1).unwrap();
        let c2_commit = repo.find_commit(c2).unwrap();
        let merge = engine
            .create_signed_commit(&repo, &sig, "merge", &honest, &[&c1_commit, &c2_commit])
            .unwrap();
        let verified = engine.verify_commit_signatures(&repo, &[merge]);
        assert!(
            verified.is_ok(),
            "resolved conflict must verify: {verified:?}"
        );

        // Same conflicted merge plus a smuggled uncovered file.
        let inner = tree_with(&repo, None, &[("smug.enc", b"\xff")]).unwrap();
        let mut tb = repo.treebuilder(Some(&honest)).unwrap();
        tb.insert("unknown", inner.id(), 0o040000).unwrap();
        let smug_tree = repo.find_tree(tb.write().unwrap()).unwrap();
        let merge2 = engine
            .create_signed_commit(&repo, &sig, "merge2", &smug_tree, &[&c1_commit, &c2_commit])
            .unwrap();
        let verified2 = engine.verify_commit_signatures(&repo, &[merge2]);
        assert!(
            matches!(
                &verified2,
                Err(BaluardError::Sync(SyncError::PolicyViolation { .. }))
            ),
            "smuggled content on a conflicted merge must refuse, got {verified2:?}"
        );
    }

    /// S1a: with a member directory present, roles bite. An editor-bound
    /// device may write ciphers/ but not meta/; the owner's meta writes
    /// pass. Written fail-first: pre-wiring the member directory was
    /// ignored and every write verified as admin-equivalent.
    #[test]
    fn member_roles_enforced_on_pull() {
        let key_owner = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_editor = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_owner = uuid::Uuid::new_v4();
        let id_editor = uuid::Uuid::new_v4();
        let member_owner = uuid::Uuid::new_v4();
        let member_editor = uuid::Uuid::new_v4();

        let (dir, _) = make_test_repo();
        enroll_device(dir.path(), &id_owner, &key_owner);
        enroll_device(dir.path(), &id_editor, &key_editor);

        let mf = |id: uuid::Uuid, name: &str, role: &str| {
            serde_json::json!({
                "id": id.to_string(),
                "display_name": name,
                "role": role,
                "trust": "self",
            })
        };
        std::fs::create_dir_all(dir.path().join("meta/members")).unwrap();
        std::fs::write(
            dir.path().join(format!("meta/members/{member_owner}.json")),
            mf(member_owner, "Owner", "owner").to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join(format!("meta/members/{member_editor}.json")),
            mf(member_editor, "Editor", "editor").to_string(),
        )
        .unwrap();
        for (m, d) in [(member_owner, id_owner), (member_editor, id_editor)] {
            let p = dir.path().join(format!("meta/members/{m}/devices"));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(
                p.join(format!("{d}.json")),
                serde_json::json!({
                    "device_id": d.to_string(),
                    "member_id": m.to_string(),
                })
                .to_string(),
            )
            .unwrap();
        }

        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":1}").unwrap();
        std::fs::create_dir_all(dir.path().join("ciphers")).unwrap();
        std::fs::write(dir.path().join("ciphers/seed.enc"), b"\x01").unwrap();
        let engine_owner =
            SyncEngine::new(dir.path(), &id_owner.to_string(), None).with_signing_key(key_owner);
        let repo = engine_owner.init_repo().unwrap();
        engine_owner.commit_all(&repo, "seed").unwrap();

        let engine_editor =
            SyncEngine::new(dir.path(), &id_editor.to_string(), None).with_signing_key(key_editor);

        // Editor writes a cipher: admitted (Editor write scope).
        std::fs::write(dir.path().join("ciphers/new.enc"), b"\x02").unwrap();
        engine_editor.commit_all(&repo, "editor cipher").unwrap();
        let oid_cipher = repo.head().unwrap().peel_to_commit().unwrap().id();
        let verified_cipher = engine_owner.verify_commit_signatures(&repo, &[oid_cipher]);
        assert!(
            verified_cipher.is_ok(),
            "editor cipher write must verify: {verified_cipher:?}"
        );

        // Editor writes meta/: refused (meta catch-all is Admin).
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":2}").unwrap();
        engine_editor.commit_all(&repo, "editor meta").unwrap();
        let oid_meta = repo.head().unwrap().peel_to_commit().unwrap().id();
        let verified = engine_owner.verify_commit_signatures(&repo, &[oid_meta]);
        assert!(
            matches!(
                &verified,
                Err(BaluardError::Sync(SyncError::PolicyViolation { .. }))
            ),
            "editor meta write must be refused, got {verified:?}"
        );

        // Owner writes meta/: admitted.
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":3}").unwrap();
        engine_owner.commit_all(&repo, "owner meta").unwrap();
        let oid_owner_meta = repo.head().unwrap().peel_to_commit().unwrap().id();
        let verified_owner = engine_owner.verify_commit_signatures(&repo, &[oid_owner_meta]);
        assert!(
            verified_owner.is_ok(),
            "owner meta write must verify: {verified_owner:?}"
        );
    }

    /// P7: a pulled commit touching a path no policy row covers is
    /// refused with deny-by-default semantics (same rejection class as a
    /// bad signature): the pull aborts and HEAD stays put.
    #[test]
    fn pull_refuses_commit_touching_uncovered_path() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let (dir, _engine_a) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":7}").unwrap();
        // Recreate the engine so it loads the key written by enrollment.
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();
        engine_a.commit_all(&repo_a, "seed").unwrap();

        let (_remote, clone_dir, _clone_engine, cloned) =
            make_clone(dir.path(), &engine_a, &repo_a);
        let head_before = cloned.head().unwrap().peel_to_commit().unwrap().id();

        // A second device so the clone can act as its own engine.
        let key_b = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_b = uuid::Uuid::new_v4();
        enroll_device(clone_dir.path(), &id_b, &key_b);
        let engine_b = SyncEngine::new(clone_dir.path(), &id_b.to_string(), None);

        // Device A commits a file in a directory no policy row covers.
        std::fs::create_dir_all(dir.path().join("unknown")).unwrap();
        std::fs::write(dir.path().join("unknown/x.enc"), b"\x01").unwrap();
        engine_a.commit_all(&repo_a, "smuggled path").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        let result = engine_b.pull(&cloned, "origin");
        assert!(
            matches!(
                &result,
                Err(BaluardError::Sync(SyncError::PolicyViolation { .. }))
            ),
            "expected policy violation, got {result:?}"
        );
        let head_after = cloned.head().unwrap().peel_to_commit().unwrap().id();
        assert_eq!(head_after, head_before, "refused pull must not move HEAD");
    }

    /// P5a: a merge conflict confined to meta/devices.json (here: the owner
    /// removed a device entry while that device bumped its own epoch entry)
    /// auto-resolves by registry union instead of wedging the sync cycle in
    /// NeedsDecision — the runtime field-merge cannot handle non-cipher
    /// files.
    #[test]
    fn devices_json_conflict_auto_resolves_by_union() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_b = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();

        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        enroll_device(dir.path(), &id_b, &key_b);
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":7}").unwrap();
        std::fs::write(dir.path().join("a.enc"), b"\x01").unwrap();
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();

        let (_remote, clone_dir, _clone_engine, cloned) =
            make_clone(dir.path(), &engine_a, &repo_a);

        // Owner removes device B's registry entry (revocation flow) and pushes.
        let mut reg: crate::devices::DeviceRegistry = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("meta/devices.json")).unwrap(),
        )
        .unwrap();
        reg.devices.remove(&id_b);
        std::fs::write(
            dir.path().join("meta/devices.json"),
            reg.to_deterministic_json().unwrap(),
        )
        .unwrap();
        engine_a.commit_all(&repo_a, "remove device B").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        // Device B (unaware) bumps its own epoch entry and commits. Same file
        // lines touched on both sides -> text conflict on pull. The clone
        // needs B's private key material (gitignored, never synced).
        enroll_device(clone_dir.path(), &id_b, &key_b);
        std::fs::create_dir_all(clone_dir.path().join("meta")).unwrap();
        std::fs::write(clone_dir.path().join("meta/epoch.json"), b"{\"epoch\":9}").unwrap();
        let engine_b = SyncEngine::new(clone_dir.path(), &id_b.to_string(), None);
        std::fs::write(clone_dir.path().join("b.enc"), b"\x02").unwrap();
        engine_b.commit_all(&cloned, "device B epoch bump").unwrap();

        // Pull must auto-resolve via union: Merged, both devices present,
        // B's bumped epoch intact, merge commit written.
        let result = engine_b.pull(&cloned, "origin").unwrap();
        assert!(matches!(result, PullResult::Merged), "got {result:?}");

        let reg_after: crate::devices::DeviceRegistry = serde_json::from_str(
            &std::fs::read_to_string(clone_dir.path().join("meta/devices.json")).unwrap(),
        )
        .unwrap();
        assert!(reg_after.devices.contains_key(&id_a), "owner entry kept");
        assert!(reg_after.devices.contains_key(&id_b), "union keeps B");
        assert_eq!(reg_after.devices[&id_b].last_seen_epoch, 9);

        let head = cloned.head().unwrap().peel_to_commit().unwrap();
        assert_eq!(
            head.parent_count(),
            2,
            "auto-resolve writes the merge commit"
        );

        // Worktree clean (C1 guard): the auto-resolve must not leave residue.
        let status = engine_b.status(&cloned).unwrap();
        assert!(!status.is_dirty(), "auto-resolve left the worktree dirty");
    }

    /// C5: bump_device_epoch finds this device's registry entry by UUID,
    /// never by display name (names are stripped from devices.json and live
    /// encrypted in settings.enc).
    #[test]
    fn bump_device_epoch_matches_by_id_not_name() {
        let (dir, _engine) = make_test_repo();
        let id = uuid::Uuid::new_v4();
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let mut reg = crate::devices::DeviceRegistry::new();
        reg.devices.insert(
            id,
            crate::vault::manifest::DeviceEntry {
                device_id: id,
                name: String::new(), // C5: stripped at rest
                encryption_public_key: "aa".into(),
                signing_public_key: hex::encode(ed25519_dalek::VerifyingKey::from(&key).to_bytes()),
                enrolled_at: 1,
                enrolled_by: None,
                last_seen_epoch: 0,
            },
        );
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":7}").unwrap();
        std::fs::write(
            dir.path().join("meta/devices.json"),
            serde_json::to_string(&reg).unwrap(),
        )
        .unwrap();
        // The device's private key (plaintext legacy form, as ceremony output)
        // so commits on this enrolled vault succeed.
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(key.to_bytes()),
        });
        std::fs::write(
            dir.path().join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )
        .unwrap();

        // Engine carrying the matching id bumps the entry to epoch 7.
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        let repo = engine.init_repo().unwrap();
        engine.commit_all(&repo, "").unwrap();
        let after: crate::devices::DeviceRegistry = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("meta/devices.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(after.devices[&id].last_seen_epoch, 7);

        // An engine with a different (or placeholder) id leaves the entry
        // alone; it shares the key material so its commits still sign.
        let other = SyncEngine::new(dir.path(), "baluard-daemon", None);
        let repo2 = other.open_repo().unwrap();
        std::fs::write(dir.path().join("meta/epoch.json"), b"{\"epoch\":9}").unwrap();
        other.commit_all(&repo2, "").unwrap();
        let after2: crate::devices::DeviceRegistry = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("meta/devices.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            after2.devices[&id].last_seen_epoch, 7,
            "placeholder id must not bump"
        );
    }

    #[test]
    fn clone_local_repo() {
        let (dir, engine) = make_test_repo();
        std::fs::write(dir.path().join("cipher.enc"), b"\x01\x02\x03").unwrap();
        let _repo = engine.init_repo().unwrap();

        // Clone to another directory
        let clone_dir = tempfile::tempdir().unwrap();
        let _cloned = SyncEngine::clone_unchecked(
            &format!("file://{}", dir.path().display()),
            clone_dir.path(),
        )
        .unwrap();

        assert!(clone_dir.path().join("cipher.enc").exists());
        assert!(clone_dir.path().join(".git").exists());
    }

    /// Helper: enroll a device in the production registry format
    /// (meta/devices.json, UUID-keyed DeviceRegistry) and write its
    /// plaintext private key (legacy format, as vault ceremony output).
    /// Mirrors what DeviceManager + handle.rs produce in production.
    fn enroll_device(
        dir: &std::path::Path,
        device_id: &uuid::Uuid,
        signing_key: &ed25519_dalek::SigningKey,
    ) {
        let verifying = ed25519_dalek::VerifyingKey::from(signing_key);
        let mut reg: crate::devices::DeviceRegistry = if dir.join("meta/devices.json").exists() {
            serde_json::from_str(&std::fs::read_to_string(dir.join("meta/devices.json")).unwrap())
                .unwrap()
        } else {
            crate::devices::DeviceRegistry::new()
        };
        reg.devices.insert(
            *device_id,
            crate::vault::manifest::DeviceEntry {
                device_id: *device_id,
                name: String::new(), // C5: names stripped at rest
                encryption_public_key: hex::encode([0u8; 32]),
                signing_public_key: hex::encode(verifying.to_bytes()),
                enrolled_at: 1,
                enrolled_by: None,
                last_seen_epoch: 0,
            },
        );
        std::fs::create_dir_all(dir.join("meta")).unwrap();
        std::fs::write(
            dir.join("meta/devices.json"),
            serde_json::to_string_pretty(&reg).unwrap(),
        )
        .unwrap();
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(signing_key.to_bytes()),
        });
        std::fs::write(
            dir.join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )
        .unwrap();
    }

    /// Compatibility shim for existing single-keypair tests: enroll the
    /// given keypair under two stable device UUIDs so both sides verify.
    fn setup_signing_keys_with(dir: &std::path::Path, signing_key: &ed25519_dalek::SigningKey) {
        enroll_device(
            dir,
            &uuid::Uuid::parse_str("00000000-0000-0000-0000-00000000000a").unwrap(),
            signing_key,
        );
    }

    #[test]
    fn push_pull_roundtrip() {
        let signing_key = crate::crypto::signature::generate_ed25519_keypair().0;

        let (dir, _engine) = make_test_repo();
        setup_signing_keys_with(dir.path(), &signing_key);
        let engine = SyncEngine::new(dir.path(), "test-device", None);

        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let repo = engine.init_repo().unwrap();

        // Create bare remote
        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();

        let remote_url = format!("file://{}", remote_path.display());
        engine.add_remote(&repo, "origin", &remote_url).unwrap();

        engine.push(&repo, "origin").unwrap();

        // Resolve the branch name that was pushed and set bare repo HEAD accordingly.
        let branch = SyncEngine::resolve_default_branch(&repo);
        let bare_repo = Repository::open(&remote_path).unwrap();
        bare_repo
            .reference_symbolic(
                "HEAD",
                &format!("refs/heads/{branch}"),
                true,
                "set default branch",
            )
            .unwrap();

        // Clone: init + remote + fetch + checkout
        let clone_dir = tempfile::tempdir().unwrap();
        setup_signing_keys_with(clone_dir.path(), &signing_key);
        let clone_engine = SyncEngine::new(clone_dir.path(), "clone-device", None);
        let cloned = Repository::init(clone_dir.path()).unwrap();
        clone_engine
            .add_remote(&cloned, "origin", &remote_url)
            .unwrap();
        let mut remote = cloned.find_remote("origin").unwrap();
        remote
            .fetch(
                &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                None,
                None,
            )
            .unwrap();
        let remote_commit = cloned
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap();
        cloned
            .reference(
                &format!("refs/heads/{branch}"),
                remote_commit.id(),
                false,
                "clone",
            )
            .unwrap();
        cloned.set_head(&format!("refs/heads/{branch}")).unwrap();
        cloned
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();

        assert!(
            clone_dir.path().join("a.enc").exists(),
            "a.enc not found in clone"
        );

        // Add cipher on clone, commit and push back
        std::fs::write(clone_dir.path().join("b.enc"), b"\xBB").unwrap();
        clone_engine.commit_all(&cloned, "").unwrap();
        clone_engine.push(&cloned, "origin").unwrap();

        // Pull on original
        let result = engine.pull(&repo, "origin").unwrap();

        // Force checkout to sync working tree with new HEAD
        let repo_after = engine.open_repo().unwrap();
        repo_after
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();

        assert!(matches!(
            result,
            PullResult::FastForward | PullResult::Merged
        ));
        assert!(
            dir.path().join("b.enc").exists(),
            "b.enc not found after pull"
        );
    }

    /// Clone `source` through a bare remote (file:// stands in for the
    /// provider). The clone picks up the registry from the fetched tree;
    /// no local enrollment is written before checkout.
    fn make_clone(
        _source_dir: &std::path::Path,
        source_engine: &SyncEngine,
        source_repo: &Repository,
    ) -> (tempfile::TempDir, tempfile::TempDir, SyncEngine, Repository) {
        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();
        let remote_url = format!("file://{}", remote_path.display());
        source_engine
            .add_remote(source_repo, "origin", &remote_url)
            .unwrap();
        source_engine.push(source_repo, "origin").unwrap();
        let branch = SyncEngine::resolve_default_branch(source_repo);
        let bare = Repository::open(&remote_path).unwrap();
        bare.reference_symbolic(
            "HEAD",
            &format!("refs/heads/{branch}"),
            true,
            "set default branch",
        )
        .unwrap();

        let clone_dir = tempfile::tempdir().unwrap();
        let clone_engine = SyncEngine::new(clone_dir.path(), "clone-device", None);
        let cloned = Repository::init(clone_dir.path()).unwrap();
        clone_engine
            .add_remote(&cloned, "origin", &remote_url)
            .unwrap();
        let mut remote = cloned.find_remote("origin").unwrap();
        remote
            .fetch(
                &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                None,
                None,
            )
            .unwrap();
        drop(remote);
        let remote_commit = cloned
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap();
        let tip = remote_commit.id();
        drop(remote_commit);
        cloned
            .reference(&format!("refs/heads/{branch}"), tip, false, "clone")
            .unwrap();
        cloned.set_head(&format!("refs/heads/{branch}")).unwrap();
        cloned
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();
        (remote_dir, clone_dir, clone_engine, cloned)
    }

    /// Re-point an enrolled device's registry entry at a new key
    /// (read-modify-write on meta/devices.json only). Simulates an approved
    /// enrollment or key rotation landing in the registry; the device's
    /// private key file is untouched.
    fn set_device_key(
        dir: &std::path::Path,
        device_id: &uuid::Uuid,
        key: &ed25519_dalek::SigningKey,
    ) {
        let verifying = ed25519_dalek::VerifyingKey::from(key);
        let mut reg: crate::devices::DeviceRegistry =
            serde_json::from_str(&std::fs::read_to_string(dir.join("meta/devices.json")).unwrap())
                .unwrap();
        if let Some(entry) = reg.devices.get_mut(device_id) {
            entry.signing_public_key = hex::encode(verifying.to_bytes());
        } else {
            reg.devices.insert(
                *device_id,
                crate::vault::manifest::DeviceEntry {
                    device_id: *device_id,
                    name: String::new(),
                    encryption_public_key: hex::encode([0u8; 32]),
                    signing_public_key: hex::encode(verifying.to_bytes()),
                    enrolled_at: 1,
                    enrolled_by: None,
                    last_seen_epoch: 0,
                },
            );
        }
        std::fs::write(
            dir.join("meta/devices.json"),
            serde_json::to_string_pretty(&reg).unwrap(),
        )
        .unwrap();
    }

    /// Production shape: two devices with DISTINCT keypairs. Device B joins
    /// via the approval flow (an existing device enrolls B and pushes the
    /// registry update before B's first commit), then both exchange
    /// commits; each side must verify the other's signer.
    #[test]
    fn multi_device_pull_verifies_each_signer() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_b = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();

        // Device A creates the vault, enrolled before first commit.
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();

        let (_remote, clone_dir, clone_engine, cloned) = make_clone(dir.path(), &engine_a, &repo_a);

        // Approval flow: A enrolls B (registry update, signed by A) and pushes.
        enroll_device(dir.path(), &id_b, &key_b); // merged read-modify-write
        engine_a.commit_all(&repo_a, "enroll device B").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        // B pulls the enrollment; verifies A's commit against the roster.
        clone_engine.pull(&cloned, "origin").unwrap();

        // B's approved enrollment lands in its registry view and its
        // private key is present; B commits under its own key.
        enroll_device(clone_dir.path(), &id_b, &key_b);
        let engine_b = SyncEngine::new(clone_dir.path(), &id_b.to_string(), None);
        std::fs::write(clone_dir.path().join("b.enc"), b"\xBB").unwrap();
        engine_b.commit_all(&cloned, "device B change").unwrap();
        engine_b.push(&cloned, "origin").unwrap();

        // A pulls B's commit; B's distinct key must verify.
        let result = engine_a.pull(&repo_a, "origin").unwrap();
        assert!(matches!(
            result,
            PullResult::FastForward | PullResult::Merged
        ));
        assert!(dir.path().join("b.enc").exists());
    }

    /// A commit signed by a key absent from the roster is rejected on pull,
    /// even when the pull's own history is otherwise healthy.
    #[test]
    fn pull_rejects_foreign_signed_commit() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();
        let (_remote, clone_dir, _clone_engine, cloned) =
            make_clone(dir.path(), &engine_a, &repo_a);

        // A forger with their own key commits into A's repo. The key is
        // loaded but NOT enrolled — the roster never learns it.
        let key_f = crate::crypto::signature::generate_ed25519_keypair().0;
        let forge_dir = tempfile::tempdir().unwrap();
        let privkey = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(key_f.to_bytes()),
        });
        std::fs::create_dir_all(forge_dir.path().join("meta")).unwrap();
        std::fs::write(
            forge_dir.path().join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey).unwrap(),
        )
        .unwrap();
        let forger = SyncEngine::new(forge_dir.path(), "forger", None);
        std::fs::write(dir.path().join("stolen.enc"), b"\xCC").unwrap();
        forger.commit_all(&repo_a, "forged").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        let err = SyncEngine::new(clone_dir.path(), "clone-device", None)
            .pull(&cloned, "origin")
            .unwrap_err();
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::InvalidCommitSignature)
        ));
    }

    /// A raw unsigned commit (provider-side or hand-crafted) is rejected on
    /// pull — no unsigned fallback anywhere in the pulled range.
    #[test]
    fn pull_rejects_unsigned_commit() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();
        let (_remote, clone_dir, _clone_engine, cloned) =
            make_clone(dir.path(), &engine_a, &repo_a);

        // Unsigned commit written straight through libgit2.
        std::fs::write(dir.path().join("unsigned.enc"), b"\xDD").unwrap();
        let mut index = repo_a.index().unwrap();
        index
            .add_path(std::path::Path::new("unsigned.enc"))
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo_a.find_tree(tree_id).unwrap();
        let sig = git2::Signature::now("unsigned", "u@b.local").unwrap();
        let parent = repo_a.head().unwrap().peel_to_commit().unwrap();
        repo_a
            .commit(Some("HEAD"), &sig, &sig, "unsigned", &tree, &[&parent])
            .unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        let err = SyncEngine::new(clone_dir.path(), "clone-device", None)
            .pull(&cloned, "origin")
            .unwrap_err();
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::InvalidCommitSignature)
        ));
    }

    /// On an enrolled vault, a missing signing key refuses commit creation
    /// (P2: no unsigned fallback). Pre-enrollment local vaults still commit.
    #[test]
    fn enrolled_vault_refuses_unsigned_commit_creation() {
        let id = uuid::Uuid::new_v4();
        let (dir, engine) = make_test_repo();
        // Enrolled (registry present) but no private key anywhere.
        enroll_device(
            dir.path(),
            &id,
            &crate::crypto::signature::generate_ed25519_keypair().0,
        );
        std::fs::remove_file(dir.path().join("meta/device-privkey.json")).unwrap();
        std::fs::write(dir.path().join("x.enc"), b"\xEE").unwrap();
        let err = match engine.init_repo() {
            Err(e) => e,
            Ok(_) => panic!("expected unsigned-commit refusal"),
        };
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::UnsignedCommitRefused)
        ));
    }

    /// Rotation: the registry re-point and the old-key commit coexist (the
    /// engine warns on the mismatch but keeps signing \u{2014} pull-side roster
    /// verification is the hard gate).
    #[test]
    fn signing_key_mismatch_warns_but_does_not_block() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_other = crate::crypto::signature::generate_ed25519_keypair().0;
        let id = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id, &key_a);
        // Swap the privkey file for a different key; registry still says key_a.
        let forged = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(key_other.to_bytes()),
        });
        std::fs::write(
            dir.path().join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&forged).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("x.enc"), b"\xEF").unwrap();
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        // Create-side: signing proceeds (mismatch warns only \u{2014} rotation needs
        // this). Pull-side: peers REJECT the commit, because the hard gate is
        // the roster and this key is not the enrolled one.
        let repo = engine.init_repo().unwrap();
        let oid = engine.commit_all(&repo, "mismatched key").unwrap();
        assert!(engine.verify_commit_signatures(&repo, &[oid]).is_err());
    }

    /// Registry rotation: the rotation commit itself is signed with the OLD
    /// key and verifies against the parent roster; a follow-up commit with
    /// the old key AFTER the rotation is rejected (key-reuse attack).
    #[test]
    fn rotation_commit_signed_with_old_key_verifies_then_old_key_rejected() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_b_old = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_b_new = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();

        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        enroll_device(dir.path(), &id_b, &key_b_old);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();
        let (_remote, clone_dir, clone_engine, cloned) = make_clone(dir.path(), &engine_a, &repo_a);

        // B rotates: registry points at the new key, commit signed with OLD
        // (the legitimate rotation moment: warn-only mismatch, still signs).
        enroll_device(clone_dir.path(), &id_b, &key_b_old);
        set_device_key(clone_dir.path(), &id_b, &key_b_new);
        let engine_b = SyncEngine::new(clone_dir.path(), &id_b.to_string(), None);
        std::fs::write(clone_dir.path().join("rot.enc"), b"\x01").unwrap();
        engine_b.commit_all(&cloned, "rotate device B key").unwrap();
        engine_b.push(&cloned, "origin").unwrap();

        // A verifies the rotation commit (old key via parent roster).
        engine_a.pull(&repo_a, "origin").unwrap();

        // Old key signs AGAIN after the rotation: rejected.
        std::fs::write(clone_dir.path().join("late.enc"), b"\x02").unwrap();
        engine_b.commit_all(&cloned, "stale key reuse").unwrap();
        engine_b.push(&cloned, "origin").unwrap();
        let err = engine_a.pull(&repo_a, "origin").unwrap_err();
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::InvalidCommitSignature)
        ));
        drop(clone_engine);
    }

    /// The old test-only fixture path (meta/device-registry.json, name-keyed
    /// array) must be dead: keys present ONLY in that file verify nothing.
    #[test]
    fn legacy_registry_fixture_is_not_trusted() {
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let id_a = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id_a, &key_a);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine_a = SyncEngine::new(dir.path(), &id_a.to_string(), None);
        let repo_a = engine_a.init_repo().unwrap();
        let (_remote, clone_dir, _clone_engine, cloned) =
            make_clone(dir.path(), &engine_a, &repo_a);

        // Attacker seeds the legacy fixture with their key in the victim clone.
        let key_f = crate::crypto::signature::generate_ed25519_keypair().0;
        let vk_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&key_f).to_bytes());
        let legacy = serde_json::json!({
            "devices": [ { "name": "attacker", "signing_public_key": vk_hex } ]
        });
        std::fs::write(
            clone_dir.path().join("meta/device-registry.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        // Forged commit signed with the legacy-only key.
        let forge_dir = tempfile::tempdir().unwrap();
        let privkey = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(key_f.to_bytes()),
        });
        std::fs::create_dir_all(forge_dir.path().join("meta")).unwrap();
        std::fs::write(
            forge_dir.path().join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey).unwrap(),
        )
        .unwrap();
        let forger = SyncEngine::new(forge_dir.path(), "forger", None);
        std::fs::write(dir.path().join("stolen.enc"), b"\xCC").unwrap();
        forger.commit_all(&repo_a, "forged").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        let err = SyncEngine::new(clone_dir.path(), "clone-device", None)
            .pull(&cloned, "origin")
            .unwrap_err();
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::InvalidCommitSignature)
        ));
    }

    /// A vault enrolled AFTER unsigned history: the commit introducing the
    /// registry verifies against its own tree (genesis transition), so the
    /// pre-P2 cohort can adopt signing without a format break.
    #[test]
    fn pull_accepts_enrollment_transition_commit() {
        let (dir, engine) = make_test_repo();
        // Two UNSIGNED commits, no registry anywhere (legacy era).
        std::fs::write(dir.path().join("old1.enc"), b"\x01").unwrap();
        let repo = engine.init_repo().unwrap();
        std::fs::write(dir.path().join("old2.enc"), b"\x02").unwrap();
        engine.commit_all(&repo, "legacy change").unwrap();

        let (_remote, clone_dir, _clone_engine, cloned) = make_clone(dir.path(), &engine, &repo);

        // Enrollment lands (registry + signed commit signed with the key).
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        enroll_device(dir.path(), &uuid::Uuid::new_v4(), &key);
        let engine = SyncEngine::new(dir.path(), "test-device", None);
        std::fs::write(dir.path().join("new.enc"), b"\x03").unwrap();
        engine.commit_all(&repo, "enroll + signed").unwrap();
        engine.push(&repo, "origin").unwrap();

        // Peer pulls the transition commit: must verify via the genesis rule.
        let result = SyncEngine::new(clone_dir.path(), "clone-device", None)
            .pull(&cloned, "origin")
            .unwrap();
        assert!(matches!(
            result,
            PullResult::FastForward | PullResult::Merged
        ));
    }

    /// Cloning a SIGNED-era vault whose remote history was tampered with
    /// (forged unsigned commit on top) must fail closed — the clone path is
    /// no longer a verification bypass.
    #[test]
    fn clone_rejects_forged_commit_on_signed_vault() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let id = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id, &key);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        let repo = engine.init_repo().unwrap();

        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();
        let remote_url = format!("file://{}", remote_path.display());
        engine.add_remote(&repo, "origin", &remote_url).unwrap();
        engine.push(&repo, "origin").unwrap();
        let branch = SyncEngine::resolve_default_branch(&repo);
        let bare = Repository::open(&remote_path).unwrap();
        bare.reference_symbolic("HEAD", &format!("refs/heads/{branch}"), true, "head")
            .unwrap();

        // Forge an unsigned commit straight through libgit2 and push it.
        std::fs::write(dir.path().join("forged.enc"), b"\xFF").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("forged.enc")).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = git2::Signature::now("forger", "f@b.local").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "forged", &tree, &[&parent])
            .unwrap();
        engine.push(&repo, "origin").unwrap();

        let clone_target = tempfile::tempdir().unwrap();
        let err = match SyncEngine::clone_unchecked(&remote_url, clone_target.path()) {
            Err(e) => e,
            Ok(_) => panic!("clone must reject forged history"),
        };
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::InvalidCommitSignature)
        ));
    }

    /// Deleting meta/devices.json from the WORKTREE cannot downgrade an
    /// enrolled vault to unsigned commits: the refusal consults the parent
    /// commit's tree, not mutable local files.
    #[test]
    fn unsigned_refusal_survives_worktree_tamper() {
        let key = crate::crypto::signature::generate_ed25519_keypair().0;
        let id = uuid::Uuid::new_v4();
        let (dir, _engine) = make_test_repo();
        enroll_device(dir.path(), &id, &key);
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        let repo = engine.init_repo().unwrap();

        // Local adversary: strip the key source and the worktree registry.
        std::fs::remove_file(dir.path().join("meta/device-privkey.json")).unwrap();
        std::fs::remove_file(dir.path().join("meta/devices.json")).unwrap();
        let engine = SyncEngine::new(dir.path(), &id.to_string(), None);
        std::fs::write(dir.path().join("b.enc"), b"\xBB").unwrap();
        let err = match engine.commit_all(&repo, "should refuse") {
            Err(e) => e,
            Ok(_) => panic!("expected unsigned-commit refusal despite worktree tamper"),
        };
        assert!(matches!(
            err,
            BaluardError::Sync(SyncError::UnsignedCommitRefused)
        ));

        // The refused commit left the index clean (no staged residue to
        // poison the next pull's force-checkout).
        let status = engine.status(&repo).unwrap();
        assert_eq!(
            status.staged, 0,
            "refused commit must not leave staged changes"
        );
    }

    #[test]
    fn commit_signing_with_privkey() {
        let (dir, _engine) = make_test_repo();

        // Create signing key file (simulating vault ceremony output)
        let (signing, verifying) = crate::crypto::signature::generate_ed25519_keypair();
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(signing.to_bytes()),
        });
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(
            dir.path().join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )
        .unwrap();

        // Recreate engine so it loads the signing key
        let engine = SyncEngine::new(dir.path(), "test-device", None);

        let repo = engine.init_repo().unwrap();
        std::fs::write(dir.path().join("data.enc"), b"test").unwrap();
        let oid = engine.commit_all(&repo, "").unwrap();

        // Verify signature is embedded in the commit object via gpgsig header
        let (sig_buf, content_buf) = repo.extract_signature(&oid, None).unwrap();
        let sig_str = sig_buf.as_str().unwrap();
        let signed_data = content_buf.as_str().unwrap();

        // Extract base64 signature
        let begin = "-----BEGIN BALUARD SIGNATURE-----\n";
        let end = "\n-----END BALUARD SIGNATURE-----";
        let start = sig_str.find(begin).unwrap() + begin.len();
        let rest = &sig_str[start..];
        let end_pos = rest.find(end).unwrap();
        let sig_b64 = &rest[..end_pos];
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();

        // Verify the signature with the verifying key
        crate::sync::commit::verify_commit_signature(
            &verifying.to_bytes(),
            signed_data.as_bytes(),
            &sig_bytes,
        )
        .unwrap();

        // Verify: tampered data should fail
        let mut tampered = signed_data.as_bytes().to_vec();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }
        assert!(
            crate::sync::commit::verify_commit_signature(
                &verifying.to_bytes(),
                &tampered,
                &sig_bytes,
            )
            .is_err()
        );
    }

    // ── C2 end-to-end tests (peer review fix) ──

    /// Build a small linear history: A -> B -> C. Returns (repo, a, b, c).
    fn build_linear_repo(
        dir: &std::path::Path,
    ) -> (git2::Repository, git2::Oid, git2::Oid, git2::Oid) {
        let repo = git2::Repository::init(dir).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        // Commit A
        std::fs::write(dir.join("a.txt"), "A").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("a.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let a = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "A",
                &repo.find_tree(tree_oid).unwrap(),
                &[],
            )
            .unwrap();

        // Commit B (child of A)
        std::fs::write(dir.join("b.txt"), "B").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("b.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let b = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "B",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(a).unwrap()],
            )
            .unwrap();

        // Commit C (child of B)
        std::fs::write(dir.join("c.txt"), "C").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("c.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let c = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "C",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(b).unwrap()],
            )
            .unwrap();

        (repo, a, b, c)
    }

    /// Build a diamond history: A -> B -> D, A -> C -> D (merge commit D).
    /// Returns (repo, a, b, c, d).
    fn build_diamond_repo(
        dir: &std::path::Path,
    ) -> (git2::Repository, git2::Oid, git2::Oid, git2::Oid, git2::Oid) {
        let repo = git2::Repository::init(dir).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        // Commit A (root, updates HEAD)
        std::fs::write(dir.join("a.txt"), "A").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("a.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let a = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "A",
                &repo.find_tree(tree_oid).unwrap(),
                &[],
            )
            .unwrap();

        // Commit B: A -> B (updates HEAD, first parent of future merge)
        std::fs::write(dir.join("b.txt"), "B").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("b.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let b = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "B",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(a).unwrap()],
            )
            .unwrap();

        // Reset HEAD to A so we can create C as a side branch.
        // `set_head_detached` on A's OID, then commit C with HEAD=A.
        repo.set_head_detached(a).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();
        std::fs::write(dir.join("c.txt"), "C").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("c.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let c = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "C",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(a).unwrap()],
            )
            .unwrap();

        // Reset HEAD back to B so the merge commit below has B as the
        // first parent (required by git's commit-when-HEAD-update rule).
        repo.set_head_detached(b).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();

        // Merge D: parents B (current HEAD) and C (second parent)
        std::fs::write(dir.join("d.txt"), "D").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("d.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let d = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "D",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(b).unwrap(), &repo.find_commit(c).unwrap()],
            )
            .unwrap();

        (repo, a, b, c, d)
    }

    #[test]
    fn collect_commit_range_linear_history() {
        // A -> B -> C, ancestor=A, descendant=C
        // Should return [C, B] in some order
        let dir = tempfile::tempdir().unwrap();
        let (repo, a, _b, c) = build_linear_repo(dir.path());
        let oids = SyncEngine::collect_commit_range(&repo, a, a, c).unwrap();
        let set: std::collections::HashSet<_> = oids.iter().copied().collect();
        assert_eq!(set.len(), 2);
        assert!(!set.contains(&a), "ancestor must NOT be in result");
        assert!(set.contains(&c), "descendant must be in result");
    }

    #[test]
    fn collect_commit_range_walks_all_merge_parents() {
        // Diamond: A -> B, A -> C, B+C -> D (merge)
        // Walk from D to A. Must include C (second parent lineage) as
        // well as B (first parent lineage). Pre-fix this would have only
        // walked B and missed C.
        let dir = tempfile::tempdir().unwrap();
        let (repo, a, b, c, d) = build_diamond_repo(dir.path());
        let oids = SyncEngine::collect_commit_range(&repo, a, a, d).unwrap();
        let set: std::collections::HashSet<_> = oids.iter().copied().collect();
        assert_eq!(set.len(), 3, "should find D, B, and C (not just D and B)");
        assert!(
            set.contains(&d),
            "descendant (merge commit) must be in result"
        );
        assert!(set.contains(&b), "first parent must be in result");
        assert!(set.contains(&c), "second parent must be in result (C2 fix)");
        assert!(!set.contains(&a), "ancestor must NOT be in result");
    }

    #[test]
    fn collect_commit_range_handles_octopus_merge() {
        // A -> B, A -> C, A -> E, then octopus merge D with parents B, C, E.
        // Walk must enumerate all three parent lineages.
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        let commit_on_head = |repo: &git2::Repository,
                              content: &str,
                              parents: &[git2::Oid],
                              msg: &str|
         -> git2::Oid {
            let dir = repo.workdir().unwrap();
            std::fs::write(dir.join(format!("{content}.txt")), content).unwrap();
            let mut index = repo.index().unwrap();
            index
                .add_path(std::path::Path::new(&format!("{content}.txt")))
                .unwrap();
            index.write().unwrap();
            let tree_oid = repo.index().unwrap().write_tree().unwrap();
            let parent_commits: Vec<_> = parents
                .iter()
                .map(|p| repo.find_commit(*p).unwrap())
                .collect();
            let parent_refs: Vec<&git2::Commit> = parent_commits.iter().collect();
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                msg,
                &repo.find_tree(tree_oid).unwrap(),
                &parent_refs,
            )
            .unwrap()
        };

        let a = commit_on_head(&repo, "a", &[], "A");
        let b = commit_on_head(&repo, "b", &[a], "B");

        // Side branches: reset HEAD to A, then create C and E.
        // After each side-branch commit, HEAD moves to the new commit,
        // so we must reset to A before creating the next side branch.
        repo.set_head_detached(a).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();
        let c = commit_on_head(&repo, "c", &[a], "C");

        // Reset back to A before creating E.
        repo.set_head_detached(a).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();
        let e = commit_on_head(&repo, "e", &[a], "E");

        // Reset HEAD to B so the merge below has B as first parent.
        repo.set_head_detached(b).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();

        // Create octopus merge D with parents B (HEAD), C, E.
        std::fs::write(dir.path().join("d.txt"), "D").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("d.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let d = {
            let b_commit = repo.find_commit(b).unwrap();
            let c_commit = repo.find_commit(c).unwrap();
            let e_commit = repo.find_commit(e).unwrap();
            let parents: Vec<&git2::Commit> = vec![&b_commit, &c_commit, &e_commit];
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "D",
                &repo.find_tree(tree_oid).unwrap(),
                &parents,
            )
            .unwrap()
        };

        let oids = SyncEngine::collect_commit_range(&repo, a, a, d).unwrap();
        let set: std::collections::HashSet<_> = oids.iter().copied().collect();
        assert_eq!(set.len(), 4, "should find D, B, C, E");
        assert!(set.contains(&d));
        assert!(set.contains(&b));
        assert!(set.contains(&c));
        assert!(set.contains(&e));
    }

    #[test]
    fn collect_commit_range_trivial_path_is_single_descendant() {
        // The "cyclic" test was mislabeled: git cannot construct actual
        // cycles (content-addressed parents must pre-exist). This test
        // actually exercises a trivial A->B path where ancestor==local_oid
        // and the walk should return just [B]. The visited-set cycle guard
        // IS exercised by the diamond and octopus reconvergence tests above.
        // Renamed to be honest about what it tests.
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        // Build A (root)
        std::fs::write(dir.path().join("a.txt"), "A").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("a.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let a_oid = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "A",
                &repo.find_tree(tree_oid).unwrap(),
                &[],
            )
            .unwrap();

        // B: A -> B
        std::fs::write(dir.path().join("b.txt"), "B").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("b.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let b_oid = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "B",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(a_oid).unwrap()],
            )
            .unwrap();

        // A is ancestor of B. Walk from B to A should return just [B].
        let oids = SyncEngine::collect_commit_range(&repo, a_oid, a_oid, b_oid).unwrap();
        assert_eq!(oids, vec![b_oid]);
    }

    #[test]
    fn collect_commit_range_terminates_at_local_trusted_history() {
        // peer review review: pre-fix BFS walked every lineage to a root,
        // not just to the merge base. A side branch that forked BEFORE
        // the merge base would walk to root and return "shallow clone"
        // error. Fix: BFS terminates when reaching any commit reachable
        // from local_oid (via graph_descendant_of).
        //
        // Topology: A (root) -> B -> C (side from A)
        //          M = merge(B, C), HEAD = M after reset
        //          D = child of M
        //          local_oid = M
        //
        // Walk D -> A (merge base). The second-parent lineage of M is
        // C -> A. Without local_oid anchor, BFS would walk C's parent
        // A (= merge base) and stop. With local_oid = M, BFS also
        // stops at M (M is its own ancestor trivially). Result: {D, M}.
        // C is NOT in result because M (= local_oid) is its ancestor.
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        // A (root)
        std::fs::write(dir.path().join("a.txt"), "A").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("a.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let a_oid = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "A",
                &repo.find_tree(tree_oid).unwrap(),
                &[],
            )
            .unwrap();

        // B: A -> B
        std::fs::write(dir.path().join("b.txt"), "B").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("b.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let b_oid = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "B",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(a_oid).unwrap()],
            )
            .unwrap();

        // C: side branch from A. Reset HEAD to A first.
        repo.set_head_detached(a_oid).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();
        std::fs::write(dir.path().join("c.txt"), "C").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("c.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = repo.index().unwrap().write_tree().unwrap();
        let c_oid = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "C",
                &repo.find_tree(tree_oid).unwrap(),
                &[&repo.find_commit(a_oid).unwrap()],
            )
            .unwrap();

        // M: merge of B and C. HEAD is at C, so use None to avoid
        // "current tip is not the first parent" error (B != C).
        let m_oid = {
            let b_commit = repo.find_commit(b_oid).unwrap();
            let c_commit = repo.find_commit(c_oid).unwrap();
            let parents: Vec<&git2::Commit> = vec![&b_commit, &c_commit];
            repo.commit(
                None,
                &sig,
                &sig,
                "M",
                &repo
                    .find_tree(repo.index().unwrap().write_tree().unwrap())
                    .unwrap(),
                &parents,
            )
            .unwrap()
        };

        // D: child of M. Use None for update_ref.
        let d_oid = {
            let m_commit = repo.find_commit(m_oid).unwrap();
            let parents: Vec<&git2::Commit> = vec![&m_commit];
            let tree_oid = repo.index().unwrap().write_tree().unwrap();
            repo.commit(
                None,
                &sig,
                &sig,
                "D",
                &repo.find_tree(tree_oid).unwrap(),
                &parents,
            )
            .unwrap()
        };

        // Walk D -> A (merge base), local_oid = M.
        // Expected: {D, M}. B and C are ancestors of M (= local_oid),
        // so BFS stops before collecting them.
        let oids = SyncEngine::collect_commit_range(&repo, m_oid, a_oid, d_oid).unwrap();
        let set: std::collections::HashSet<_> = oids.iter().copied().collect();
        assert!(set.contains(&d_oid), "D must be in result");
        assert!(set.contains(&m_oid), "M must be in result");
        assert!(
            !set.contains(&b_oid),
            "B (ancestor of local_oid) must NOT be in result"
        );
        assert!(
            !set.contains(&c_oid),
            "C (ancestor of local_oid) must NOT be in result"
        );
        assert!(
            !set.contains(&a_oid),
            "A (merge base) must NOT be in result"
        );
    }

    /// Phase 2a seam: on a real same-file pull conflict, the resolver closure
    /// is invoked, `Pause` returns `NeedsDecision` WITHOUT writing a merge
    /// commit, and `finalize_conflicts` then writes the merge + (attempts) a
    /// push. The backward-compat `run_sync_cycle` (KeepLocal closure) still
    /// completes as `Synced`.
    #[test]
    fn run_sync_cycle_with_resolver_pause_and_finalize() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        // Two repos sharing one remote, same signing keypair so commits verify.
        let (dir_a, _engine) = make_test_repo();
        setup_signing_keys_with(dir_a.path(), &signing_key);
        let engine_a = SyncEngine::new(dir_a.path(), "test-device", None);
        std::fs::create_dir_all(dir_a.path().join("ciphers")).unwrap();
        std::fs::write(
            dir_a
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000001.enc"),
            b"BASE",
        )
        .unwrap();
        let repo_a = engine_a.init_repo().unwrap();

        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();
        let remote_url = format!("file://{}", remote_path.display());
        engine_a.add_remote(&repo_a, "origin", &remote_url).unwrap();
        engine_a.push(&repo_a, "origin").unwrap();
        let branch = SyncEngine::resolve_default_branch(&repo_a);
        let bare_repo = Repository::open(&remote_path).unwrap();
        bare_repo
            .reference_symbolic("HEAD", &format!("refs/heads/{branch}"), true, "head")
            .unwrap();

        // Clone B (same shape as the existing clone test).
        let dir_b = tempfile::tempdir().unwrap();
        setup_signing_keys_with(dir_b.path(), &signing_key);
        let engine_b = SyncEngine::new(dir_b.path(), "clone-device", None);
        let repo_b = Repository::init(dir_b.path()).unwrap();
        engine_b.add_remote(&repo_b, "origin", &remote_url).unwrap();
        let mut remote_b = repo_b.find_remote("origin").unwrap();
        remote_b
            .fetch(
                &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                None,
                None,
            )
            .unwrap();
        let remote_commit = repo_b
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap();
        repo_b
            .reference(
                &format!("refs/heads/{branch}"),
                remote_commit.id(),
                false,
                "clone",
            )
            .unwrap();
        drop(remote_commit);
        repo_b.set_head(&format!("refs/heads/{branch}")).unwrap();
        repo_b
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();
        drop(remote_b);

        // TRUE divergence from a shared base. A pushes base, both edit the
        // same file from that base. A pushes A's edit. B commits B's edit, then
        // pulls → conflict detected on B's side (B is behind + diverged).
        std::fs::write(
            dir_a
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000001.enc"),
            b"FROM_A",
        )
        .unwrap();
        engine_a.commit_all(&repo_a, "").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        std::fs::write(
            dir_b
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000001.enc"),
            b"FROM_B",
        )
        .unwrap();
        engine_b.commit_all(&repo_b, "").unwrap();

        // B pulls → conflict (both sides changed cipher.enc from base).
        // With a Pause resolver the cycle returns NeedsDecision and does NOT
        // write a merge commit.
        let mut paused: Vec<PendingConflictState> = Vec::new();
        let outcome = engine_b
            .run_sync_cycle_with_resolver(&repo_b, &mut |state| {
                paused.push(state.clone());
                ConflictResolution::Pause
            })
            .unwrap();
        assert!(matches!(outcome, SyncCycleOutcome::NeedsDecision { .. }));
        assert_eq!(paused.len(), 1, "resolver must be invoked exactly once");
        assert_eq!(
            paused[0].files,
            vec!["ciphers/deadbeef-0000-0000-0000-000000000001.enc".to_string()]
        );

        // The merge commit was NOT written: HEAD still points at B's tip, not a
        // 2-parent merge. (If finalize never runs, the next cycle redetects.)
        let head_b = repo_b.head().unwrap();
        let head_commit = head_b.peel_to_commit().unwrap();
        assert_eq!(
            head_commit.parent_count(),
            1,
            "Pause must not write a merge commit"
        );

        // Daemon-side decision: keep local bytes (FROM_B). finalize_conflicts
        // writes the 2-parent merge commit and pushes. The Idle->Idle
        // state-machine bug that previously broke this (pull pre-transitioned
        // to Idle on conflict) is fixed above — pull now leaves Merging, so
        // resolve_conflicts' final Merging->Idle is valid. Full round-trip
        // exercised here; 2b adds the daemon decrypt/merge layer on top.
        let engine_b2 = SyncEngine::new(dir_b.path(), "clone-device", None);
        let repo_b2 = engine_b2.open_repo().unwrap();
        let resolved = paused
            .iter()
            .flat_map(|s| s.files.iter().map(move |f| (f.clone(), b"FROM_B".to_vec())))
            .collect::<Vec<_>>();
        let result = engine_b2.finalize_conflicts(&repo_b2, &paused[0], &resolved);
        assert!(
            result.is_ok(),
            "finalize_conflicts should succeed: {result:?}"
        );

        let head_after = repo_b2.head().unwrap().peel_to_commit().unwrap();
        assert_eq!(
            head_after.parent_count(),
            2,
            "finalize_conflicts must write a 2-parent merge commit"
        );

        // Double-finalize guard (review #3): a second call with the same
        // pending must be rejected because HEAD has moved off local_oid.
        let second = engine_b2.finalize_conflicts(&repo_b2, &paused[0], &resolved);
        assert!(
            second.is_err(),
            "double-finalize must be rejected by the HEAD guard"
        );
    }

    /// Phase 2a seam: the backward-compat `run_sync_cycle` delegates to
    /// KeepLocal and is identical in shape to the pre-2a behavior (returns
    /// Synced, writes a 2-parent merge commit). Uses a fresh conflict pair.
    #[test]
    fn run_sync_cycle_backward_compat_uses_keep_local() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let (dir_a, _engine) = make_test_repo();
        setup_signing_keys_with(dir_a.path(), &signing_key);
        let engine_a = SyncEngine::new(dir_a.path(), "test-device", None);
        std::fs::create_dir_all(dir_a.path().join("ciphers")).unwrap();
        std::fs::write(
            dir_a
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000001.enc"),
            b"BASE",
        )
        .unwrap();
        let repo_a = engine_a.init_repo().unwrap();

        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();
        let remote_url = format!("file://{}", remote_path.display());
        engine_a.add_remote(&repo_a, "origin", &remote_url).unwrap();
        engine_a.push(&repo_a, "origin").unwrap();
        let branch = SyncEngine::resolve_default_branch(&repo_a);
        let bare_repo = Repository::open(&remote_path).unwrap();
        bare_repo
            .reference_symbolic("HEAD", &format!("refs/heads/{branch}"), true, "head")
            .unwrap();

        let dir_b = tempfile::tempdir().unwrap();
        setup_signing_keys_with(dir_b.path(), &signing_key);
        let engine_b = SyncEngine::new(dir_b.path(), "clone-device", None);
        let repo_b = Repository::init(dir_b.path()).unwrap();
        engine_b.add_remote(&repo_b, "origin", &remote_url).unwrap();
        let mut remote_b = repo_b.find_remote("origin").unwrap();
        remote_b
            .fetch(
                &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                None,
                None,
            )
            .unwrap();
        let remote_commit = repo_b
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap();
        repo_b
            .reference(
                &format!("refs/heads/{branch}"),
                remote_commit.id(),
                false,
                "clone",
            )
            .unwrap();
        repo_b.set_head(&format!("refs/heads/{branch}")).unwrap();
        repo_b
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();

        std::fs::write(
            dir_a
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000001.enc"),
            b"FROM_A",
        )
        .unwrap();
        engine_a.commit_all(&repo_a, "").unwrap();
        engine_a.push(&repo_a, "origin").unwrap();

        std::fs::write(
            dir_b
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000001.enc"),
            b"FROM_B",
        )
        .unwrap();
        engine_b.commit_all(&repo_b, "").unwrap();

        // Backward-compat path: KeepLocal. B pulls → conflict → keep B's bytes,
        // completes as Synced. Verified above that the Pause path detects the
        // conflict; the KeepLocal fallback is the same pull, just with a
        // finalize. The full Synced round-trip (incl. push + state machine)
        // is covered by 2b integration tests; here we only assert the resolver
        // wiring: a KeepLocal closure must not pause.
        //
        // We reuse the same conflict setup but with a resolver that records the
        // call and returns KeepLocal, then assert the outcome is Synced (not
        // NeedsDecision) and the resolver saw the conflict.
        // Rebuild a fresh conflict pair since the Pause test above consumed B.
        let (dir_a2, _engine) = make_test_repo();
        setup_signing_keys_with(dir_a2.path(), &signing_key);
        let engine_a2 = SyncEngine::new(dir_a2.path(), "test-device", None);
        std::fs::create_dir_all(dir_a2.path().join("ciphers")).unwrap();
        std::fs::write(
            dir_a2
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000002.enc"),
            b"BASE",
        )
        .unwrap();
        let repo_a2 = engine_a2.init_repo().unwrap();
        let remote_dir2 = tempfile::tempdir().unwrap();
        let remote_path2 = remote_dir2.path().join("vault.git");
        Repository::init_bare(&remote_path2).unwrap();
        let remote_url2 = format!("file://{}", remote_path2.display());
        engine_a2
            .add_remote(&repo_a2, "origin", &remote_url2)
            .unwrap();
        engine_a2.push(&repo_a2, "origin").unwrap();
        let branch2 = SyncEngine::resolve_default_branch(&repo_a2);
        let bare_repo2 = Repository::open(&remote_path2).unwrap();
        bare_repo2
            .reference_symbolic("HEAD", &format!("refs/heads/{branch2}"), true, "head")
            .unwrap();

        let dir_c = tempfile::tempdir().unwrap();
        setup_signing_keys_with(dir_c.path(), &signing_key);
        let engine_c = SyncEngine::new(dir_c.path(), "clone-device", None);
        let repo_c = Repository::init(dir_c.path()).unwrap();
        engine_c
            .add_remote(&repo_c, "origin", &remote_url2)
            .unwrap();
        let mut remote_c = repo_c.find_remote("origin").unwrap();
        remote_c
            .fetch(
                &[&format!(
                    "refs/heads/{branch2}:refs/remotes/origin/{branch2}"
                )],
                None,
                None,
            )
            .unwrap();
        let rc = repo_c
            .find_reference(&format!("refs/remotes/origin/{branch2}"))
            .unwrap()
            .peel_to_commit()
            .unwrap();
        repo_c
            .reference(&format!("refs/heads/{branch2}"), rc.id(), false, "clone")
            .unwrap();
        repo_c.set_head(&format!("refs/heads/{branch2}")).unwrap();
        repo_c
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();

        std::fs::write(
            dir_a2
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000002.enc"),
            b"FROM_A",
        )
        .unwrap();
        engine_a2.commit_all(&repo_a2, "").unwrap();
        engine_a2.push(&repo_a2, "origin").unwrap();
        std::fs::write(
            dir_c
                .path()
                .join("ciphers/deadbeef-0000-0000-0000-000000000002.enc"),
            b"FROM_C",
        )
        .unwrap();
        engine_c.commit_all(&repo_c, "").unwrap();

        let mut saw_conflict = false;
        // Backward-compat path: run_sync_cycle delegates to
        // run_sync_cycle_with_resolver with a KeepLocal closure. With the
        // Idle->Idle fix, the full Synced round-trip now works on a real
        // conflict (previously latent bug — pull pre-transitioned to Idle on
        // conflict, making resolve_conflicts' final Idle->Idle invalid).
        let outcome = engine_c
            .run_sync_cycle_with_resolver(&repo_c, &mut |state| {
                saw_conflict = true;
                assert_eq!(
                    state.files,
                    vec!["ciphers/deadbeef-0000-0000-0000-000000000002.enc".to_string()]
                );
                ConflictResolution::KeepLocal
            })
            .unwrap();
        assert!(
            saw_conflict,
            "KeepLocal resolver must still be invoked on conflict"
        );
        assert_eq!(outcome, SyncCycleOutcome::Synced { conflicts: 1 });
    }

    // -------------------------------------------------------------------
    // P8b: revocation manifests
    // -------------------------------------------------------------------

    const TEST_DEVICE: &str = "00000000-0000-0000-0000-00000000000a";

    fn make_enrolled_repo() -> (tempfile::TempDir, SyncEngine, Repository) {
        let signing_key = crate::crypto::signature::generate_ed25519_keypair().0;
        let dir = tempfile::tempdir().unwrap();
        setup_signing_keys_with(dir.path(), &signing_key);
        let engine = SyncEngine::new(dir.path(), TEST_DEVICE, None);
        std::fs::write(dir.path().join("cipher.enc"), b"v1").unwrap();
        let repo = engine.init_repo().unwrap();
        (dir, engine, repo)
    }

    fn push_to_new_bare(engine: &SyncEngine, repo: &Repository) -> (tempfile::TempDir, String) {
        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();
        let remote_url = format!("file://{}", remote_path.display());
        engine.add_remote(repo, "origin", &remote_url).unwrap();
        engine.push(repo, "origin").unwrap();
        let branch = SyncEngine::resolve_default_branch(repo);
        let bare = Repository::open(&remote_path).unwrap();
        bare.reference_symbolic(
            "HEAD",
            &format!("refs/heads/{branch}"),
            true,
            "set default branch",
        )
        .unwrap();
        (remote_dir, remote_url)
    }

    #[test]
    fn revocation_append_and_refusals() {
        let (_dir, engine, repo) = make_enrolled_repo();
        std::fs::write(_dir.path().join("cipher.enc"), b"smuggled").unwrap();
        let smuggled = engine.commit_all(&repo, "").unwrap();

        // Unknown commit refused.
        let err = engine
            .append_revocation(&repo, &"f".repeat(40), "nope")
            .unwrap_err();
        assert!(err.to_string().contains("revocation manifest invalid"));

        // Happy path: seq 1, manifest committed.
        let seq = engine
            .append_revocation(&repo, &smuggled.to_string(), "smuggled content")
            .unwrap();
        assert_eq!(seq, 1);
        let manifest: crate::sync::revocation::RevocationManifest = serde_json::from_str(
            &std::fs::read_to_string(_dir.path().join(crate::sync::revocation::REVOCATIONS_PATH))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].commit, smuggled.to_string());

        // Duplicate refused.
        let err = engine
            .append_revocation(&repo, &smuggled.to_string(), "again")
            .unwrap_err();
        assert!(err.to_string().contains("already revoked"));
    }

    #[test]
    fn revocation_restores_smuggled_content_on_pull() {
        let (src_dir, engine, repo) = make_enrolled_repo();
        let (_remote_dir, remote_url) = push_to_new_bare(&engine, &repo);

        // Clone BEFORE the bad content arrives.
        let clone_dir = tempfile::tempdir().unwrap();
        setup_signing_keys_with(
            clone_dir.path(),
            &crate::crypto::signature::generate_ed25519_keypair().0,
        );
        let clone_engine = SyncEngine::new(clone_dir.path(), TEST_DEVICE, None);
        let cloned = Repository::init(clone_dir.path()).unwrap();
        clone_engine
            .add_remote(&cloned, "origin", &remote_url)
            .unwrap();
        let branch = SyncEngine::resolve_default_branch(&repo);
        {
            let mut remote = cloned.find_remote("origin").unwrap();
            remote
                .fetch(
                    &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                    None,
                    None,
                )
                .unwrap();
        }
        let tip = cloned
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id();
        cloned
            .reference(&format!("refs/heads/{branch}"), tip, false, "clone")
            .unwrap();
        cloned.set_head(&format!("refs/heads/{branch}")).unwrap();
        cloned
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();
        assert_eq!(
            std::fs::read(clone_dir.path().join("cipher.enc")).unwrap(),
            b"v1"
        );

        // Compromised device pushes smuggled content.
        std::fs::write(src_dir.path().join("cipher.enc"), b"smuggled").unwrap();
        std::fs::write(src_dir.path().join("contraband.enc"), b"bad").unwrap();
        let smuggled = engine.commit_all(&repo, "").unwrap();
        engine.push(&repo, "origin").unwrap();

        // Admin revokes it; manifest commit rides a normal push.
        let seq = engine
            .append_revocation(&repo, &smuggled.to_string(), "smuggled")
            .unwrap();
        assert_eq!(seq, 1);
        engine.push(&repo, "origin").unwrap();

        // Clone pulls: FF arrives with bad commit + manifest; restore fires.
        let result = clone_engine.pull(&cloned, "origin").unwrap();
        assert!(matches!(
            result,
            crate::sync::engine::PullResult::FastForward
        ));
        assert_eq!(
            std::fs::read(clone_dir.path().join("cipher.enc")).unwrap(),
            b"v1",
            "smuggled cipher content must be restored to the pre-commit state"
        );
        assert!(
            !clone_dir.path().join("contraband.enc").exists(),
            "file added by the revoked commit must be removed"
        );
        // The manifest itself survives (append-only, tracked).
        assert!(
            clone_dir
                .path()
                .join(crate::sync::revocation::REVOCATIONS_PATH)
                .exists()
        );

        // Source self-heals on an up-to-date pull too.
        let result = engine.pull(&repo, "origin").unwrap();
        assert!(matches!(
            result,
            crate::sync::engine::PullResult::AlreadyUpToDate
        ));
        assert!(!src_dir.path().join("contraband.enc").exists());
        assert_eq!(
            std::fs::read(src_dir.path().join("cipher.enc")).unwrap(),
            b"v1"
        );

        // Idempotent: after pushing the restore, another pull must not
        // create any further commit.
        engine.push(&repo, "origin").unwrap();
        let head_before = repo.head().unwrap().peel_to_commit().unwrap().id();
        engine.pull(&repo, "origin").unwrap();
        let head_after = repo.head().unwrap().peel_to_commit().unwrap().id();
        assert_eq!(head_before, head_after, "re-apply must be a no-op");

        // Restored files keep the vault-rest permission invariant. The
        // SOURCE's cipher.enc was written by the restore path; the clone's
        // copy arrived via a normal checkout of the pushed restore commit
        // (checkout perms are a pre-existing layer, not the restore's).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(src_dir.path().join("cipher.enc"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "restored cipher must be 0600");
        }
    }

    #[test]
    fn revocation_manifest_strip_attack_fails_pull() {
        let (src_dir, engine, repo) = make_enrolled_repo();
        let (_remote_dir, remote_url) = push_to_new_bare(&engine, &repo);

        std::fs::write(src_dir.path().join("cipher.enc"), b"smuggled").unwrap();
        let smuggled = engine.commit_all(&repo, "").unwrap();
        engine.push(&repo, "origin").unwrap();
        engine
            .append_revocation(&repo, &smuggled.to_string(), "smuggled")
            .unwrap();
        engine.push(&repo, "origin").unwrap();

        // Clone with a cold tracker, pull everything once (verified).
        let clone_dir = tempfile::tempdir().unwrap();
        setup_signing_keys_with(
            clone_dir.path(),
            &crate::crypto::signature::generate_ed25519_keypair().0,
        );
        let clone_engine = SyncEngine::new(clone_dir.path(), TEST_DEVICE, None);
        let cloned = Repository::init(clone_dir.path()).unwrap();
        clone_engine
            .add_remote(&cloned, "origin", &remote_url)
            .unwrap();
        let branch = SyncEngine::resolve_default_branch(&repo);
        {
            let mut remote = cloned.find_remote("origin").unwrap();
            remote
                .fetch(
                    &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                    None,
                    None,
                )
                .unwrap();
        }
        let tip = cloned
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id();
        cloned
            .reference(&format!("refs/heads/{branch}"), tip, false, "clone")
            .unwrap();
        cloned.set_head(&format!("refs/heads/{branch}")).unwrap();
        cloned
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();
        clone_engine.pull(&cloned, "origin").unwrap();

        // Attacker (enrolled device) strips the entry in a NEW commit
        // (valid commit signature, forged manifest version).
        let manifest_path = src_dir
            .path()
            .join(crate::sync::revocation::REVOCATIONS_PATH);
        let manifest: crate::sync::revocation::RevocationManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        let stripped = crate::sync::revocation::RevocationManifest { entries: vec![] };
        std::fs::write(&manifest_path, stripped.to_json().unwrap()).unwrap();
        engine.commit_all(&repo, "").unwrap();
        engine.push(&repo, "origin").unwrap();

        // The peer must refuse the pull: entries cannot disappear.
        let err = clone_engine.pull(&cloned, "origin").unwrap_err();
        assert!(err.to_string().contains("append-only violation"));
    }

    #[test]
    fn revocation_signer_identity_derived_from_key_not_argument() {
        // Two devices enrolled; the privkey FILE ends up holding the LAST
        // enrolled key (B). append_revocation must tag the entry with B's
        // roster id (the key's owner), never the engine's device id or
        // the lexically-first roster entry.
        let key_a = crate::crypto::signature::generate_ed25519_keypair().0;
        let key_b = crate::crypto::signature::generate_ed25519_keypair().0;
        let uuid_a = uuid::Uuid::parse_str("00000000-0000-0000-0000-00000000000a").unwrap();
        let uuid_b = uuid::Uuid::parse_str("00000000-0000-0000-0000-00000000000b").unwrap();
        let dir = tempfile::tempdir().unwrap();
        enroll_device(dir.path(), &uuid_a, &key_a);
        enroll_device(dir.path(), &uuid_b, &key_b);
        let engine = SyncEngine::new(dir.path(), TEST_DEVICE, None);
        std::fs::write(dir.path().join("cipher.enc"), b"v1").unwrap();
        let repo = engine.init_repo().unwrap();
        std::fs::write(dir.path().join("cipher.enc"), b"smuggled").unwrap();
        let smuggled = engine.commit_all(&repo, "").unwrap();

        let seq = engine
            .append_revocation(&repo, &smuggled.to_string(), "test")
            .unwrap();
        let manifest: crate::sync::revocation::RevocationManifest = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(crate::sync::revocation::REVOCATIONS_PATH))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(seq, 1);
        assert_eq!(manifest.entries[0].device_id, uuid_b.to_string());
    }

    #[test]
    fn revocation_tampered_entry_fails_pull() {
        let (src_dir, engine, repo) = make_enrolled_repo();
        let (_remote_dir, remote_url) = push_to_new_bare(&engine, &repo);

        std::fs::write(src_dir.path().join("cipher.enc"), b"smuggled").unwrap();
        let smuggled = engine.commit_all(&repo, "").unwrap();
        engine.push(&repo, "origin").unwrap();
        engine
            .append_revocation(&repo, &smuggled.to_string(), "original reason")
            .unwrap();
        engine.push(&repo, "origin").unwrap();

        // Clone setup (same shape as the roundtrip test).
        let clone_dir = tempfile::tempdir().unwrap();
        setup_signing_keys_with(
            clone_dir.path(),
            &crate::crypto::signature::generate_ed25519_keypair().0,
        );
        let clone_engine = SyncEngine::new(clone_dir.path(), TEST_DEVICE, None);
        let cloned = Repository::init(clone_dir.path()).unwrap();
        clone_engine
            .add_remote(&cloned, "origin", &remote_url)
            .unwrap();
        let branch = SyncEngine::resolve_default_branch(&repo);
        {
            let mut remote = cloned.find_remote("origin").unwrap();
            remote
                .fetch(
                    &[&format!("refs/heads/{branch}:refs/remotes/origin/{branch}")],
                    None,
                    None,
                )
                .unwrap();
        }
        let tip = cloned
            .find_reference(&format!("refs/remotes/origin/{branch}"))
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id();
        cloned
            .reference(&format!("refs/heads/{branch}"), tip, false, "clone")
            .unwrap();
        cloned.set_head(&format!("refs/heads/{branch}")).unwrap();
        cloned
            .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();
        // Clone fetched after every push, so local==remote: the up-to-date
        // path must still self-heal the smuggled content.
        let base_pull = clone_engine.pull(&cloned, "origin").unwrap();
        assert!(matches!(
            base_pull,
            crate::sync::engine::PullResult::AlreadyUpToDate
        ));
        // First pull already restored the content.
        assert_eq!(
            std::fs::read(clone_dir.path().join("cipher.enc")).unwrap(),
            b"v1"
        );

        // Retroactive tamper: rewrite an entry's reason in a NEW commit
        // (commit signature stays valid — the ENTRY signature breaks).
        let manifest_path = src_dir
            .path()
            .join(crate::sync::revocation::REVOCATIONS_PATH);
        let mut raw = std::fs::read_to_string(&manifest_path).unwrap();
        raw = raw.replace("original reason", "evil rewrite");
        std::fs::write(&manifest_path, raw).unwrap();
        engine.commit_all(&repo, "").unwrap();
        engine.push(&repo, "origin").unwrap();

        // Clone's next pull must fail closed on the unforgeable entry.
        let err = clone_engine.pull(&cloned, "origin").unwrap_err();
        assert!(err.to_string().contains("revocation manifest invalid"));
    }
}
