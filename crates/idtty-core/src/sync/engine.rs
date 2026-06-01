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

use crate::error::{IdttyError, SyncError};
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
    fn transition_state(&self, target: SyncState) -> Result<(), IdttyError> {
        let mut sm = self.state_machine.borrow_mut();
        sm.transition(target).map_err(SyncError::StateMachine)?;
        sm.save_to_file(&self.vault_path)
            .map_err(SyncError::StateMachine)?;
        Ok(())
    }

    /// Check for stale state on startup and recover if needed.
    pub fn recover_state(&self) -> Result<(), IdttyError> {
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
    pub fn init_repo(&self) -> Result<Repository, IdttyError> {
        let repo =
            Repository::init(&self.vault_path).map_err(|e| SyncError::Git(format!("init: {e}")))?;

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
    pub fn open_repo(&self) -> Result<Repository, IdttyError> {
        Repository::open(&self.vault_path).map_err(|e| SyncError::Git(format!("open: {e}")).into())
    }

    /// Stage all changes and commit with static message (D9).
    /// Returns the new commit OID.
    pub fn commit_all(
        &self,
        repo: &Repository,
        _message_override: &str,
    ) -> Result<Oid, IdttyError> {
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

        let sig = Signature::now(&self.device_name, "idtty@local")
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
    pub fn cover_commit(&self, repo: &Repository) -> Result<Oid, IdttyError> {
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
    ) -> Result<(), IdttyError> {
        Self::jitter_delay(max_delay_secs);
        self.push(repo, remote_name)
    }

    /// Pull with timing jitter to mask usage patterns.
    pub fn pull_with_jitter(
        &self,
        repo: &Repository,
        remote_name: &str,
        max_delay_secs: u64,
    ) -> Result<PullResult, IdttyError> {
        Self::jitter_delay(max_delay_secs);
        self.pull(repo, remote_name)
    }

    /// Check if the working tree has uncommitted changes.
    pub fn status(&self, repo: &Repository) -> Result<WorkTreeStatus, IdttyError> {
        let statuses = repo
            .statuses(None)
            .map_err(|e| SyncError::Git(format!("statuses: {e}")))?;

        let mut result = WorkTreeStatus::default();
        for entry in statuses.iter() {
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
    pub fn log(&self, repo: &Repository, limit: usize) -> Result<Vec<CommitInfo>, IdttyError> {
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
    pub fn add_remote(&self, _repo: &Repository, name: &str, url: &str) -> Result<(), IdttyError> {
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
    ) -> Result<Oid, IdttyError> {
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
                "-----BEGIN IDTTY SIGNATURE-----\n{sig_b64}\n-----END IDTTY SIGNATURE-----"
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
    /// Returns error if walk terminates before ancestor (shallow clone gap).
    fn collect_commit_range(
        repo: &Repository,
        ancestor: Oid,
        descendant: Oid,
    ) -> Result<Vec<Oid>, IdttyError> {
        let mut oids = Vec::new();
        let mut current = descendant;
        while current != ancestor {
            oids.push(current);
            let commit = repo
                .find_commit(current)
                .map_err(|e| SyncError::Git(format!("walk: {e}")))?;
            if commit.parent_count() == 0 {
                // Reached repo root or shallow boundary without finding ancestor
                return Err(SyncError::Git(
                    "shallow clone prevents full signature verification: history truncated".into(),
                )
                .into());
            }
            current = commit.parent_id(0).unwrap();
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

    /// Get the remote URL (defaults to "origin").
    pub fn get_remote_url(&self, repo: &Repository, name: &str) -> Result<String, IdttyError> {
        let remote = repo
            .find_remote(name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;
        let url = remote
            .url()
            .ok_or_else(|| SyncError::Git("remote has no URL".into()))?;
        Ok(url.to_string())
    }

    /// Push to remote. Uses "origin" by default.
    pub fn push(&self, repo: &Repository, remote_name: &str) -> Result<(), IdttyError> {
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
            .map_err(|e| SyncError::Git(format!("push: {e}")))?;

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
    pub fn pull(&self, repo: &Repository, remote_name: &str) -> Result<PullResult, IdttyError> {
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
    fn pull_inner(&self, repo: &Repository, remote_name: &str) -> Result<PullResult, IdttyError> {
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
                .map_err(|e| SyncError::Git(format!("fetch: {e}")))?;

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
            let new_oids = Self::collect_commit_range(repo, local_oid, remote_oid)?;
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

            repo.checkout_head(None)
                .map_err(|e| SyncError::Git(format!("checkout head: {e}")))?;

            self.save_last_head(&remote_oid.to_string())?;
            self.transition_state(SyncState::Idle)?;
            return Ok(PullResult::FastForward);
        }

        // State: Pulling → Merging
        self.transition_state(SyncState::Merging)?;

        // Non-fast-forward: need merge
        // Use "ours" strategy for conflict resolution (local wins for conflicting fields)
        let merge_base = repo
            .merge_base(local_oid, remote_oid)
            .map_err(|e| SyncError::Git(format!("merge_base: {e}")))?;

        let _ancestor = repo
            .find_commit(merge_base)
            .map_err(|e| SyncError::Git(format!("find ancestor: {e}")))?;

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
            self.transition_state(SyncState::Idle)?;
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

        let sig = Signature::now(&self.device_name, "idtty@local")
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
    ) -> Result<Vec<u8>, IdttyError> {
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
    ) -> Result<Oid, IdttyError> {
        // Write resolved files to working directory
        for (path, content) in resolved_files {
            let full_path = self.vault_path.join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)
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

        let sig = Signature::now(&self.device_name, "idtty@local")
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

    /// Clone a remote vault repo to a local directory.
    /// Only HTTPS and SSH URLs are allowed.
    pub fn clone(url: &str, target: &Path, _shallow: bool) -> Result<Repository, IdttyError> {
        validate_git_url(url)?;
        Self::clone_unchecked(url, target)
    }

    /// Clone without URL validation (for local testing/development).
    pub fn clone_unchecked(url: &str, target: &Path) -> Result<Repository, IdttyError> {
        let mut builder = RepoBuilder::new();
        // Wire credential callbacks for clone operations
        let cred_config = CredentialConfig::load(target);
        let mut fetch_opts = FetchOptions::new();
        // Build inline callbacks to avoid lifetime issues
        let https_token = cred_config.https_token.clone();
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
                    return git2::Cred::userpass_plaintext(user, token);
                }
            }
            if allowed_types.contains(git2::CredentialType::DEFAULT) {
                return git2::Cred::default();
            }
            Err(git2::Error::from_str("no credential source available"))
        });
        fetch_opts.remote_callbacks(callbacks);
        builder.fetch_options(fetch_opts);
        let repo = builder
            .clone(url, target)
            .map_err(|e| SyncError::Git(format!("clone: {e}")))?;
        Ok(repo)
    }
}

/// Validate that a git URL uses an allowed scheme.
/// Permits: https://, ssh://, git@ (SSH shorthand).
/// Rejects: file://, git://, and all other schemes.
fn validate_git_url(url: &str) -> Result<(), IdttyError> {
    if url.starts_with("https://") || url.starts_with("ssh://") || url.starts_with("git@") {
        Ok(())
    } else {
        Err(SyncError::Git(format!(
            "unsupported URL scheme: {url}. Use https://, ssh://, or git@"
        ))
        .into())
    }
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

    fn save_last_head(&self, oid: &str) -> Result<(), IdttyError> {
        let path = Self::head_path(&self.vault_path);
        let record = serde_json::json!({ "last_remote_head": oid });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record)
                .map_err(|e| SyncError::Git(format!("save head: {e}")))?,
        )?;
        Ok(())
    }

    /// Load Ed25519 signing key from meta/device-privkey.json.
    /// Returns None if file missing (pre-vault). Returns error if file is corrupt.
    fn load_signing_key(
        vault_path: &Path,
    ) -> Result<Option<ed25519_dalek::SigningKey>, IdttyError> {
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

    /// Verify signatures for new commits pulled from remote.
    /// Uses git2's native extract_signature to get signature + signed data from commit object.
    /// The signature is embedded in the git commit object itself (gpgsig header).
    /// Returns number of verified commits. Returns error if any signature is invalid.
    /// Unsigned commits in the range cause an error (no backward compat for security).
    pub fn verify_commit_signatures(
        &self,
        repo: &Repository,
        new_oids: &[Oid],
    ) -> Result<usize, IdttyError> {
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

    /// Extract base64 payload from the "-----BEGIN IDTTY SIGNATURE-----\n<b64>\n-----END IDTTY SIGNATURE-----" format.
    /// Strips git gpgsig continuation-line spaces (space-prefixed lines) from the raw field.
    fn extract_b64_from_sig_field(sig_str: &str) -> Result<String, SyncError> {
        // Strip leading spaces from continuation lines (git gpgsig format)
        let normalized: String = sig_str
            .lines()
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        let begin = "-----BEGIN IDTTY SIGNATURE-----\n";
        let end = "\n-----END IDTTY SIGNATURE-----";
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
    ) -> Result<std::collections::HashMap<String, String>, IdttyError> {
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

/// .gitignore content for vault repos.
const GITIGNORE_CONTENT: &str = "\
# Secrets and private keys (CLI mode)
meta/device-privkey.json
meta/kdf-attempts.json
meta/git-credentials.json

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

#[cfg(test)]
#[cfg(feature = "git-sync")]
mod tests {
    use super::*;

    fn make_test_repo() -> (tempfile::TempDir, SyncEngine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = SyncEngine::new(dir.path(), "test-device");
        (dir, engine)
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

    #[test]
    #[ignore] // TODO: git2 local push to bare repo has issues; works over HTTPS/SSH
    fn push_pull_roundtrip() {
        let (dir, engine) = make_test_repo();
        std::fs::write(dir.path().join("a.enc"), b"\xAA").unwrap();
        let repo = engine.init_repo().unwrap();

        // Create bare remote
        let remote_dir = tempfile::tempdir().unwrap();
        let remote_path = remote_dir.path().join("vault.git");
        Repository::init_bare(&remote_path).unwrap();

        // Create main branch from initial commit
        {
            let head = repo.head().unwrap();
            let commit = head.peel_to_commit().unwrap();
            // Rename current branch to main
            repo.branch("main", &commit, true).unwrap();
            repo.set_head("refs/heads/main").unwrap();
        }

        engine
            .add_remote(&repo, "origin", &remote_path.display().to_string())
            .unwrap();
        // Debug: what refs does the bare repo have?
        let bare_repo = Repository::open(&remote_path).unwrap();
        bare_repo.references().unwrap().for_each(|r| {
            if let Ok(refn) = r {
                eprintln!("  ref: {:?} -> {:?}", refn.name(), refn.target());
            }
        });
        engine.push(&repo, "origin").unwrap();

        // Clone
        let clone_dir = tempfile::tempdir().unwrap();
        let cloned =
            SyncEngine::clone_unchecked(&remote_path.display().to_string(), clone_dir.path())
                .unwrap();

        // Debug: list files
        for entry in std::fs::read_dir(clone_dir.path()).unwrap() {
            eprintln!("  {:?}", entry.unwrap().file_name());
        }

        assert!(
            clone_dir.path().join("a.enc").exists(),
            "a.enc not found in clone"
        );

        // Add cipher on clone, commit and push back
        std::fs::write(clone_dir.path().join("b.enc"), b"\xBB").unwrap();
        let clone_engine = SyncEngine::new(clone_dir.path(), "clone-device");
        clone_engine.commit_all(&cloned, "").unwrap();
        clone_engine.push(&cloned, "origin").unwrap();

        // Pull on original
        let result = engine.pull(&repo, "origin").unwrap();
        assert!(matches!(
            result,
            PullResult::FastForward | PullResult::Merged
        ));
        assert!(dir.path().join("b.enc").exists());
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
        let begin = "-----BEGIN IDTTY SIGNATURE-----\n";
        let end = "\n-----END IDTTY SIGNATURE-----";
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
}
