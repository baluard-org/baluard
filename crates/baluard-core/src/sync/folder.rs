//! Local folder sync transport (ADR 0112): bare Git repo in a user-selected
//! folder (Dropbox, Drive, iCloud Drive, Syncthing) with cloud conflict-copy
//! quarantine and sidecar file locking.

use std::path::{Path, PathBuf};

use git2::{Repository, RepositoryInitOptions};

use crate::error::SyncError;

const QUARANTINE_DIR: &str = ".baluard-quarantine";

/// Resolve the bare repository directory inside `folder_path`.
/// If `folder_path` is already a bare Git repository, returns it directly;
/// otherwise returns `<folder_path>/<vault_slug>.git`.
pub fn folder_bare_repo_path(folder_path: &Path, vault_slug: &str) -> Result<PathBuf, SyncError> {
    if !folder_path.is_dir() {
        return Err(SyncError::Git(format!(
            "sync folder does not exist or is not a directory: {}",
            folder_path.display()
        )));
    }
    if vault_slug.is_empty()
        || vault_slug.contains('/')
        || vault_slug.contains('\\')
        || vault_slug.contains("..")
    {
        return Err(SyncError::Git(format!(
            "invalid vault slug for folder sync: {vault_slug}"
        )));
    }
    if folder_path.join("HEAD").is_file() && folder_path.join("objects").is_dir() {
        return Ok(folder_path.to_path_buf());
    }
    Ok(folder_path.join(format!("{vault_slug}.git")))
}

/// Initialize or open the bare repository for `vault_slug` inside `folder_path`.
/// Returns the canonicalized bare repository path.
pub fn init_or_open_folder_remote(
    folder_path: &Path,
    vault_slug: &str,
) -> Result<PathBuf, SyncError> {
    let bare_path = folder_bare_repo_path(folder_path, vault_slug)?;
    if bare_path.exists() {
        sanitize_folder_remote_conflicts(&bare_path)?;
        Repository::open_bare(&bare_path)
            .map_err(|e| SyncError::Git(format!("open folder bare repo: {e}")))?;
    } else {
        let mut opts = RepositoryInitOptions::new();
        opts.bare(true).initial_head("main");
        Repository::init_opts(&bare_path, &opts)
            .map_err(|e| SyncError::Git(format!("init folder bare repo: {e}")))?;
    }
    std::fs::canonicalize(&bare_path)
        .map_err(|e| SyncError::Git(format!("canonicalize folder repo: {e}")))
}

/// Convert a local bare repository path into a `file://` URL for `git2`.
pub fn folder_url_from_path(bare_path: &Path) -> Result<String, SyncError> {
    let raw = bare_path
        .to_str()
        .ok_or_else(|| SyncError::Git("folder path is not valid UTF-8".into()))?;
    if raw.chars().any(|c| c.is_control()) {
        return Err(SyncError::Git(
            "invalid folder path: control characters are not allowed".into(),
        ));
    }
    #[cfg(windows)]
    {
        let stripped = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        let fwd = stripped.replace('\\', "/");
        if fwd.starts_with('/') {
            Ok(format!("file://{fwd}"))
        } else {
            Ok(format!("file:///{fwd}"))
        }
    }
    #[cfg(not(windows))]
    {
        Ok(format!("file://{raw}"))
    }
}

/// Extract a local filesystem path from a `file://` remote URL.
pub fn path_from_file_url(url: &str) -> Option<PathBuf> {
    let rest = url.strip_prefix("file://")?;
    #[cfg(windows)]
    {
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        Some(PathBuf::from(rest.replace('/', "\\")))
    }
    #[cfg(not(windows))]
    {
        Some(PathBuf::from(rest))
    }
}

/// Run `f` while holding an exclusive advisory lock in the local temp dir
/// keyed by `bare_dir` so concurrent local writers (daemon + CLI) serialize
/// their `pull -> push` without syncing a lockfile into the cloud folder.
pub fn with_folder_lock<T>(
    bare_dir: &Path,
    f: impl FnOnce() -> Result<T, SyncError>,
) -> Result<T, SyncError> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bare_dir.hash(&mut h);
    let lock_path =
        std::env::temp_dir().join(format!("baluard-folder-sync-{:016x}.lock", h.finish()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| SyncError::Git(format!("open folder sync lock: {e}")))?;
    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock
        .write()
        .map_err(|e| SyncError::Git(format!("acquire folder sync lock: {e}")))?;
    f()
}

/// Quarantine cloud-syncer conflict copies inside `refs/` and `objects/` so
/// `git2` can read refs and objects cleanly, and fail with a clear message if
/// `.icloud` placeholder files are still downloading.
pub fn sanitize_folder_remote_conflicts(bare_dir: &Path) -> Result<usize, SyncError> {
    if !bare_dir.is_dir() {
        return Ok(0);
    }
    if has_icloud_placeholders(bare_dir) {
        return Err(SyncError::Git(
            "cloud folder has unfinished iCloud downloads; wait for sync to complete".into(),
        ));
    }
    let mut moved = 0usize;
    let quarantine = bare_dir.join(QUARANTINE_DIR);
    for sub in ["refs", "objects"] {
        let root = bare_dir.join(sub);
        if root.is_dir() {
            moved += quarantine_conflicts_in(&root, &quarantine)?;
        }
    }
    Ok(moved)
}

fn has_icloud_placeholders(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some(QUARANTINE_DIR) {
            continue;
        }
        if path.is_dir() {
            if has_icloud_placeholders(&path) {
                return true;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("icloud") {
            return true;
        }
    }
    false
}

fn is_cloud_conflict_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("conflicted copy")
        || lower.contains("sync-conflict")
        || (lower.contains("conflict") && (lower.contains('(') || lower.contains(' ')))
}

fn quarantine_conflicts_in(dir: &Path, quarantine: &Path) -> Result<usize, SyncError> {
    let mut moved = 0usize;
    let entries = std::fs::read_dir(dir)
        .map_err(|e| SyncError::Git(format!("scan folder repo {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if path.is_dir() {
            if is_cloud_conflict_name(name) {
                move_to_quarantine(&path, name, quarantine)?;
                moved += 1;
            } else {
                moved += quarantine_conflicts_in(&path, quarantine)?;
            }
        } else if is_cloud_conflict_name(name) {
            move_to_quarantine(&path, name, quarantine)?;
            moved += 1;
        }
    }
    Ok(moved)
}

fn move_to_quarantine(src: &Path, name: &str, quarantine: &Path) -> Result<(), SyncError> {
    std::fs::create_dir_all(quarantine)
        .map_err(|e| SyncError::Git(format!("create quarantine dir: {e}")))?;
    let mut dst = quarantine.join(name);
    let mut idx = 1u32;
    while dst.exists() {
        dst = quarantine.join(format!("{name}.{idx}"));
        idx += 1;
    }
    std::fs::rename(src, &dst)
        .map_err(|e| SyncError::Git(format!("quarantine conflict file {}: {e}", src.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_and_reopen_folder_remote_creates_bare_main() {
        let tmp = tempfile::tempdir().unwrap();
        let bare = init_or_open_folder_remote(tmp.path(), "my-vault").unwrap();
        assert!(bare.ends_with("my-vault.git"));
        assert!(bare.join("HEAD").is_file());
        let repo = Repository::open_bare(&bare).unwrap();
        assert!(repo.is_bare());

        // Reopening the same folder reuses the existing bare repo.
        let bare2 = init_or_open_folder_remote(tmp.path(), "my-vault").unwrap();
        assert_eq!(bare, bare2);
    }

    #[test]
    fn sanitize_quarantines_cloud_conflict_copies_and_rejects_icloud() {
        let tmp = tempfile::tempdir().unwrap();
        let bare = init_or_open_folder_remote(tmp.path(), "vault").unwrap();
        let conflict_ref = bare
            .join("refs/heads")
            .join("main (Alice's conflicted copy 2026-11-18)");
        std::fs::write(&conflict_ref, "deadbeef\n").unwrap();

        let moved = sanitize_folder_remote_conflicts(&bare).unwrap();
        assert_eq!(moved, 1);
        assert!(!conflict_ref.exists());
        assert!(bare.join(QUARANTINE_DIR).exists());

        let icloud = bare.join("objects/00/.abc.icloud");
        std::fs::create_dir_all(icloud.parent().unwrap()).unwrap();
        std::fs::write(&icloud, "").unwrap();
        let err = sanitize_folder_remote_conflicts(&bare).unwrap_err();
        assert!(err.to_string().contains("iCloud"));
    }

    #[test]
    fn rejects_invalid_slugs() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(folder_bare_repo_path(tmp.path(), "../escape").is_err());
        assert!(folder_bare_repo_path(tmp.path(), "a/b").is_err());
        assert!(folder_bare_repo_path(tmp.path(), "").is_err());
    }

    #[test]
    fn folder_sync_push_and_pull_round_trip() {
        let folder = tempfile::tempdir().unwrap();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let eng_a = crate::sync::engine::SyncEngine::new(dir_a.path(), "dev-a", None);
        let repo_a = eng_a.init_repo().unwrap();
        std::fs::write(dir_a.path().join("note.txt"), b"hello").unwrap();
        eng_a.commit_all(&repo_a, "init").unwrap();

        let url = eng_a
            .add_folder_remote(&repo_a, "origin", folder.path(), "vault-1")
            .unwrap();
        assert!(url.starts_with("file://"));
        eng_a.push(&repo_a, "origin").unwrap();

        let eng_b = crate::sync::engine::SyncEngine::new(dir_b.path(), "dev-b", None);
        let repo_b = eng_b.init_repo().unwrap();
        eng_b
            .add_folder_remote(&repo_b, "origin", folder.path(), "vault-1")
            .unwrap();
        let pulled = eng_b.pull(&repo_b, "origin").unwrap();
        assert!(matches!(
            pulled,
            crate::sync::engine::PullResult::FastForward
                | crate::sync::engine::PullResult::AlreadyUpToDate
                | crate::sync::engine::PullResult::Merged
        ));
    }
}
