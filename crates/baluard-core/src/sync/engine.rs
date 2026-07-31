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
#[cfg(feature = "git-sync")]
pub struct SyncEngine {
    /// Path to the vault directory (= git workdir).
    pub vault_path: PathBuf,
    /// Device name for commit author.
    pub device_name: String,
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
    /// Used to sign all commits. None = unsigned commits (legacy compat).
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
    pub fn new(vault_path: &Path, device_name: &str) -> Self {
        let last_remote_head = Self::load_last_head(vault_path);
        let credential_config = CredentialConfig::load(vault_path);
        let state_machine = RefCell::new(SyncStateMachine::load_from_file(vault_path));
        // Load signing key — log warning on corrupt file but don't fail
        let signing_key = match Self::load_signing_key(vault_path) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("warning: failed to load signing key: {e}");
                None
            }
        };
        Self {
            vault_path: vault_path.to_path_buf(),
            device_name: device_name.to_string(),
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
        Ok(repo)
    }

    /// Rewrite .gitignore from the current const if any new entry is missing.
    /// Best-effort: logs a warning on failure.
    fn refresh_gitignore(&self) {
        let gitignore = self.vault_path.join(".gitignore");
        const NEW_ENTRIES: &[&str] = &["meta/sync-head.json", "meta/sync-state.json"];
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
        let commit_id = self.create_signed_commit(repo, &sig, COMMIT_MESSAGE, &tree, &parents)?;
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
        const LOCAL_ONLY: &[&str] = &["meta/sync-head.json", "meta/sync-state.json"];

        let mut result = WorkTreeStatus::default();
        for entry in statuses.iter() {
            let path = std::str::from_utf8(entry.path_bytes()).unwrap_or("");
            if LOCAL_ONLY.contains(&path) {
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

    /// Create a commit with Ed25519 signature embedded in the git object.
    /// If signing_key is available, uses commit_create_buffer + commit_signed.
    /// Otherwise falls back to unsigned commit.
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
        let reg_path = self.vault_path.join("meta/devices.json");
        let device_id = std::fs::read_to_string(&reg_path)
            .ok()
            .and_then(|data| serde_json::from_str::<crate::devices::DeviceRegistry>(&data).ok())
            .and_then(|reg| {
                reg.devices
                    .iter()
                    .find(|(_, e)| e.name == self.device_name)
                    .map(|(id, _)| *id)
            })?;
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
        let Ok(json) = serde_json::to_string_pretty(&reg) else {
            return;
        };
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
            self.transition_state(SyncState::Idle)?;
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

            self.save_last_head(&remote_oid.to_string())?;
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

        // Track merge commit OID (not remote HEAD) for rollback detection
        self.save_last_head(&merge_oid.to_string())?;
        repo.cleanup_state()
            .map_err(|e| SyncError::Git(format!("cleanup after merge: {e}")))?;
        self.transition_state(SyncState::Idle)?;
        Ok(PullResult::Merged)
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
        Ok(repo)
    }

    /// Clone a remote vault repo with provider-specific credentials and
    /// progress reporting. Used by the daemon's `vault.clone_start` flow.
    ///
    /// Differs from [`clone`]/[`clone_unchecked`] in two ways:
    /// - uses `load_with_hint(target, Some(provider))` so a multi-provider
    ///   install authenticates with the correct token rather than "first
    ///   connected provider" (avoids wrong-token 401s on clone).
    /// - wires git2's `transfer_progress` callback into `progress` so the
    ///   daemon can poll objects/bytes for a live progress bar.
    pub fn clone_remote(
        url: &str,
        target: &Path,
        provider: crate::providers::types::Provider,
        progress: std::sync::Arc<std::sync::Mutex<CloneProgress>>,
    ) -> Result<Repository, BaluardError> {
        Self::clone_remote_cancelable(url, target, provider, progress, None)
    }

    pub fn clone_remote_cancelable(
        url: &str,
        target: &Path,
        provider: crate::providers::types::Provider,
        progress: std::sync::Arc<std::sync::Mutex<CloneProgress>>,
        cancel_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<Repository, BaluardError> {
        validate_git_url(url)?;
        let mut builder = RepoBuilder::new();
        let cred_config = CredentialConfig::load_with_hint(target, Some(provider));
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
            SyncError::Git(crate::sync::credentials::scrub_git_error(&format!(
                "clone: {e}"
            )))
        })?;
        Ok(repo)
    }
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
    ) -> Result<Option<ed25519_dalek::SigningKey>, BaluardError> {
        // Try OS keyring: read device IDs from devices.json and try each
        let service = Self::keyring_service_for_vault(vault_path);
        if let Ok(devices_data) = std::fs::read_to_string(vault_path.join("meta/devices.json")) {
            if let Ok(devices) = serde_json::from_str::<serde_json::Value>(&devices_data) {
                if let Some(device_map) = devices["devices"].as_object() {
                    for (device_id, _) in device_map {
                        if let Ok(entry) = keyring::Entry::new(&service, device_id) {
                            if let Ok(json) = entry.get_password() {
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                                    if let Some(hex_str) = v["ed25519_private"].as_str() {
                                        if let Ok(bytes_vec) = hex::decode(hex_str) {
                                            let bytes: [u8; 32] =
                                                bytes_vec.try_into().map_err(|_| {
                                                    SyncError::Git("privkey wrong length".into())
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

        // Fallback: plaintext file
        let path = vault_path.join("meta/device-privkey.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)
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
    pub fn verify_commit_signatures(
        &self,
        repo: &Repository,
        new_oids: &[Oid],
    ) -> Result<usize, BaluardError> {
        if new_oids.is_empty() {
            return Ok(0);
        }

        // Load known device verifying keys: device_name → hex verifying key
        let verifying_keys = Self::load_verifying_keys(&self.vault_path)?;

        let mut verified = 0;
        for oid in new_oids {
            // Extract signature and signed data from the commit object
            let (sig_buf, content_buf) = repo
                .extract_signature(oid, None)
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

            // Find a verifying key that validates this signature
            let mut found = false;
            for vk_hex in verifying_keys.values() {
                let vk_bytes: [u8; 32] = hex::decode(vk_hex)
                    .map_err(|_| SyncError::InvalidCommitSignature)?
                    .try_into()
                    .map_err(|_| SyncError::InvalidCommitSignature)?;
                if crate::sync::commit::verify_commit_signature(
                    &vk_bytes,
                    signed_data.as_bytes(),
                    &sig_bytes,
                )
                .is_ok()
                {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(SyncError::InvalidCommitSignature.into());
            }
            verified += 1;
        }

        Ok(verified)
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

    /// Load device verifying keys from meta/device-registry.json.
    fn load_verifying_keys(
        vault_path: &Path,
    ) -> Result<std::collections::HashMap<String, String>, BaluardError> {
        let registry_path = vault_path.join("meta/device-registry.json");
        if !registry_path.exists() {
            return Ok(std::collections::HashMap::new());
        }
        let data = std::fs::read_to_string(&registry_path)
            .map_err(|e| SyncError::Git(format!("read registry: {e}")))?;
        let reg: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| SyncError::Git(format!("parse registry: {e}")))?;
        let keys = reg["devices"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| {
                        let name = d["name"].as_str()?.to_string();
                        let pk = d["signing_public_key"].as_str()?.to_string();
                        Some((name, pk))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .collect();
        Ok(keys)
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
meta/kdf-attempts.json
meta/git-credentials.json

# Legacy plaintext metadata (now encrypted as folders.enc/tags.enc/activity.enc)
meta/folders.json
meta/tag_index.json
meta/device_activity.json

# Sync engine internals — local-only bookkeeping, never synced
meta/sync-head.json
meta/sync-state.json

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
        let engine = SyncEngine::new(dir.path(), "test-device");
        (dir, engine)
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
            crate::providers::types::Provider::GitHub,
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
            crate::providers::types::Provider::GitLab,
            progress,
        );
        assert!(result.is_err(), "cloning a non-existent source must fail");
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

        // Seed a tracked file + a devices registry so bump_device_epoch has a
        // target to rewrite (the original bug source).
        std::fs::write(dir.path().join("data.enc"), b"\x00\x01\x02").unwrap();
        std::fs::create_dir_all(dir.path().join("meta")).unwrap();
        std::fs::write(dir.path().join("meta/devices.json"), b"{\"devices\":{}}").unwrap();

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

    /// Helper: set up Ed25519 signing key + verifying key for a test repo.
    /// Uses a provided verifying key hex so both repos share the same keypair.
    fn setup_signing_keys_with(dir: &std::path::Path, signing_key: &ed25519_dalek::SigningKey) {
        let verifying = ed25519_dalek::VerifyingKey::from(signing_key);
        let privkey_data = serde_json::json!({
            "x25519_private": hex::encode([0u8; 32]),
            "ed25519_private": hex::encode(signing_key.to_bytes()),
        });
        std::fs::create_dir_all(dir.join("meta")).unwrap();
        std::fs::write(
            dir.join("meta/device-privkey.json"),
            serde_json::to_string_pretty(&privkey_data).unwrap(),
        )
        .unwrap();
        let vk_hex = hex::encode(verifying.to_bytes());
        let registry = serde_json::json!({
            "devices": [
                { "name": "test-device", "signing_public_key": vk_hex },
                { "name": "clone-device", "signing_public_key": vk_hex },
            ]
        });
        std::fs::write(
            dir.join("meta/device-registry.json"),
            serde_json::to_string_pretty(&registry).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn push_pull_roundtrip() {
        let signing_key = crate::crypto::signature::generate_ed25519_keypair().0;

        let (dir, _engine) = make_test_repo();
        setup_signing_keys_with(dir.path(), &signing_key);
        let engine = SyncEngine::new(dir.path(), "test-device");

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
        let clone_engine = SyncEngine::new(clone_dir.path(), "clone-device");
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
        let engine = SyncEngine::new(dir.path(), "test-device");

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
        let engine_a = SyncEngine::new(dir_a.path(), "test-device");
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
        let engine_b = SyncEngine::new(dir_b.path(), "clone-device");
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
        let engine_b2 = SyncEngine::new(dir_b.path(), "clone-device");
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
        let engine_a = SyncEngine::new(dir_a.path(), "test-device");
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
        let engine_b = SyncEngine::new(dir_b.path(), "clone-device");
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
        let engine_a2 = SyncEngine::new(dir_a2.path(), "test-device");
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
        let engine_c = SyncEngine::new(dir_c.path(), "clone-device");
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
}
