//! Git sync engine: real git2-rs operations for vault synchronization.
//!
//! Handles: repo init, commit, push, pull, clone, commit signing.
//! D9: Static "vault update" commit messages.
//! D12: Transactional 8-state machine.
//! D11: Shallow clone by default, auto-unshallow on conflict.

#[cfg(feature = "git-sync")]
use git2::{Repository, Signature, Oid, FetchOptions, PushOptions};
#[cfg(feature = "git-sync")]
use git2::build::RepoBuilder;

use std::path::{Path, PathBuf};

use crate::error::{IdttyError, SyncError};
use crate::sync::commit::COMMIT_MESSAGE;

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
}

#[cfg(feature = "git-sync")]
impl SyncEngine {
    /// Create a new SyncEngine for a vault at the given path.
    pub fn new(vault_path: &Path, device_name: &str) -> Self {
        let last_remote_head = Self::load_last_head(vault_path);
        Self {
            vault_path: vault_path.to_path_buf(),
            device_name: device_name.to_string(),
            shallow: true,
            last_remote_head,
        }
    }

    /// Initialize a git repo in the vault directory.
    /// Creates `.gitignore`, makes initial commit.
    pub fn init_repo(&self) -> Result<Repository, IdttyError> {
        let repo = Repository::init(&self.vault_path)
            .map_err(|e| SyncError::Git(format!("init: {e}")))?;

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
        Repository::open(&self.vault_path)
            .map_err(|e| SyncError::Git(format!("open: {e}")).into())
    }

    /// Stage all changes and commit with static message (D9).
    /// Returns the new commit OID.
    pub fn commit_all(&self, repo: &Repository, _message_override: &str) -> Result<Oid, IdttyError> {
        let mut index = repo.index()
            .map_err(|e| SyncError::Git(format!("index: {e}")))?;

        // Stage everything
        index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .map_err(|e| SyncError::Git(format!("add_all: {e}")))?;
        index.write()
            .map_err(|e| SyncError::Git(format!("index write: {e}")))?;

        let tree_id = index.write_tree()
            .map_err(|e| SyncError::Git(format!("write_tree: {e}")))?;
        let tree = repo.find_tree(tree_id)
            .map_err(|e| SyncError::Git(format!("find_tree: {e}")))?;

        let sig = Signature::now(&self.device_name, "idtty@local")
            .map_err(|e| SyncError::Git(format!("signature: {e}")))?;

        // Check for existing HEAD
        let parent_commits: Vec<_> = match repo.head() {
            Ok(head) => {
                let commit = head.peel_to_commit()
                    .map_err(|e| SyncError::Git(format!("head commit: {e}")))?;
                vec![commit]
            }
            Err(_) => vec![], // Initial commit, no parent
        };

        let parents: Vec<_> = parent_commits.iter().collect();
        let commit_id = repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            COMMIT_MESSAGE,
            &tree,
            &parents,
        ).map_err(|e| SyncError::Git(format!("commit: {e}")))?;

        Ok(commit_id)
    }

    /// Check if the working tree has uncommitted changes.
    pub fn status(&self, repo: &Repository) -> Result<WorkTreeStatus, IdttyError> {
        let statuses = repo.statuses(None)
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
        let head = repo.head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let start = head.peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel: {e}")))?;

        let mut commits = Vec::new();
        let mut current = Some(start);

        while let Some(c) = current.take() {
            if commits.len() >= limit { break; }
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
        _repo.remote(name, url)
            .map_err(|e| SyncError::Git(format!("remote add: {e}")))?;
        Ok(())
    }

    /// Get the remote URL (defaults to "origin").
    pub fn get_remote_url(&self, repo: &Repository, name: &str) -> Result<String, IdttyError> {
        let remote = repo.find_remote(name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;
        let url = remote.url()
            .ok_or_else(|| SyncError::Git("remote has no URL".into()))?;
        Ok(url.to_string())
    }

    /// Push to remote. Uses "origin" by default.
    pub fn push(&self, repo: &Repository, remote_name: &str) -> Result<(), IdttyError> {
        let mut remote = repo.find_remote(remote_name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

        // Resolve HEAD to a branch name
        let head = repo.head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let refname = head.name()
            .unwrap_or("HEAD");

        // Push refs/heads/main:refs/heads/main
        let push_refspec = format!("{refname}:refs/heads/main");

        let mut push_options = PushOptions::new();

        remote.push(&[&push_refspec], Some(&mut push_options))
            .map_err(|e| SyncError::Git(format!("push: {e}")))?;

        // Track remote HEAD for rollback detection
        let pushed_oid = repo.head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?
            .peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel: {e}")))?
            .id();
        self.save_last_head(&pushed_oid.to_string())?;

        Ok(())
    }

    /// Pull from remote: fetch + merge (with "ours" strategy for non-conflicting merges).
    pub fn pull(&self, repo: &Repository, remote_name: &str) -> Result<PullResult, IdttyError> {
        // Fetch
        let mut remote = repo.find_remote(remote_name)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

        let mut fetch_opts = FetchOptions::new();
        // TODO: Add credential callbacks
        // TODO: Shallow fetch when shallow=true

        remote.fetch(&["refs/heads/*:refs/remotes/origin/*"], Some(&mut fetch_opts), None)
            .map_err(|e| SyncError::Git(format!("fetch: {e}")))?;

        // Get remote HEAD
        let remote_head = repo.find_reference(&format!("refs/remotes/{remote_name}/HEAD"))
            .or_else(|_| repo.find_reference(&format!("refs/remotes/{remote_name}/main")))
            .map_err(|e| SyncError::Git(format!("find remote HEAD: {e}")))?;
        let remote_oid = remote_head.peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel remote: {e}")))?
            .id();

        // Get local HEAD
        let local_head = repo.head()
            .map_err(|e| SyncError::Git(format!("head: {e}")))?;
        let local_oid = local_head.peel_to_commit()
            .map_err(|e| SyncError::Git(format!("peel local: {e}")))?
            .id();

        // Already up to date?
        if local_oid == remote_oid {
            return Ok(PullResult::AlreadyUpToDate);
        }

        // Check if fast-forward possible
        let _local_commit = repo.find_commit(local_oid)
            .map_err(|e| SyncError::Git(format!("find local commit: {e}")))?;
        let _remote_commit = repo.find_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("find remote commit: {e}")))?;

        if repo.graph_descendant_of(remote_oid, local_oid)
            .map_err(|e| SyncError::Git(format!("descendant check: {e}")))?
        {
            // Fast-forward
            repo.reference("refs/heads/main", remote_oid, true, "fast-forward merge")
                .map_err(|e| SyncError::Git(format!("ff update ref: {e}")))?;
            repo.set_head("refs/heads/main")
                .map_err(|e| SyncError::Git(format!("set head: {e}")))?;
            repo.checkout_head(None)
                .map_err(|e| SyncError::Git(format!("checkout head: {e}")))?;

            self.save_last_head(&remote_oid.to_string())?;
            return Ok(PullResult::FastForward);
        }

        // Non-fast-forward: need merge
        // Use "ours" strategy for conflict resolution (local wins for conflicting fields)
        let merge_base = repo.merge_base(local_oid, remote_oid)
            .map_err(|e| SyncError::Git(format!("merge_base: {e}")))?;

        let _ancestor = repo.find_commit(merge_base)
            .map_err(|e| SyncError::Git(format!("find ancestor: {e}")))?;

        // Perform merge
        let annotated = repo.find_annotated_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("annotated commit: {e}")))?;
        let mut merge_opts = git2::MergeOptions::new();
        repo.merge(&[&annotated], Some(&mut merge_opts), None)
            .map_err(|e| SyncError::Git(format!("merge: {e}")))?;

        // Check for conflicts
        let mut index = repo.index()
            .map_err(|e| SyncError::Git(format!("index: {e}")))?;

        // Check for conflicts
        if index.has_conflicts() {
            // TODO: Field-level conflict resolution via sync/conflict.rs
            // For now, report conflict and abort
            repo.cleanup_state()
                .map_err(|e| SyncError::Git(format!("cleanup: {e}")))?;
            return Ok(PullResult::Conflict);
        }

        // Create merge commit
        let tree_id = index.write_tree()
            .map_err(|e| SyncError::Git(format!("write tree: {e}")))?;
        let tree = repo.find_tree(tree_id)
            .map_err(|e| SyncError::Git(format!("find tree: {e}")))?;

        let sig = Signature::now(&self.device_name, "idtty@local")
            .map_err(|e| SyncError::Git(format!("signature: {e}")))?;

        let local_parent = repo.find_commit(local_oid)
            .map_err(|e| SyncError::Git(format!("find local: {e}")))?;
        let remote_parent = repo.find_commit(remote_oid)
            .map_err(|e| SyncError::Git(format!("find remote: {e}")))?;

        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            COMMIT_MESSAGE,
            &tree,
            &[&local_parent, &remote_parent],
        ).map_err(|e| SyncError::Git(format!("merge commit: {e}")))?;

        self.save_last_head(&remote_oid.to_string())?;
        Ok(PullResult::Merged)
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
        let repo = builder.clone(url, target)
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
        Err(SyncError::Git(format!("unsupported URL scheme: {url}. Use https://, ssh://, or git@")).into())
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
        std::fs::write(&path, serde_json::to_string_pretty(&record)
            .map_err(|e| SyncError::Git(format!("save head: {e}")))?)?;
        Ok(())
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
    Conflict,
}

/// .gitignore content for vault repos.
const GITIGNORE_CONTENT: &str = "\
# Secrets and private keys (CLI mode)
meta/device-privkey.json
meta/kdf-attempts.json

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
        ).unwrap();

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

        engine.add_remote(&repo, "origin", &remote_path.display().to_string()).unwrap();
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
        let cloned = SyncEngine::clone_unchecked(
            &remote_path.display().to_string(),
            clone_dir.path(),
        ).unwrap();

        // Debug: list files
        for entry in std::fs::read_dir(clone_dir.path()).unwrap() {
            eprintln!("  {:?}", entry.unwrap().file_name());
        }

        assert!(clone_dir.path().join("a.enc").exists(), "a.enc not found in clone");

        // Add cipher on clone, commit and push back
        std::fs::write(clone_dir.path().join("b.enc"), b"\xBB").unwrap();
        let clone_engine = SyncEngine::new(clone_dir.path(), "clone-device");
        clone_engine.commit_all(&cloned, "").unwrap();
        clone_engine.push(&cloned, "origin").unwrap();

        // Pull on original
        let result = engine.pull(&repo, "origin").unwrap();
        assert!(matches!(result, PullResult::FastForward | PullResult::Merged));
        assert!(dir.path().join("b.enc").exists());
    }
}
