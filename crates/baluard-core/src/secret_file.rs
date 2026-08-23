//! Single primitive for writing secret files: owner-only permissions from the first
//! byte, atomic replace, no symlink following.
//!
//! Every file whose contents are secret (vault data, provider tokens, CLI exports,
//! attachment ciphertext, session-token caches) must be written through
//! [`write_secret_file`] so no world-readable window or pre-planted-symlink write
//! exists anywhere in the codebase. Audit ref: C14, C17, C24, C25 in
//! `docs/SECURITY-AUDIT-20260823.md`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Atomically write `contents` to `path` with owner-only permissions.
///
/// * Writes to a sibling temp file (`.<name>.secret.tmp`), created with mode 0600 on
///   Unix via `O_EXCL` (`create_new`), then renamed over `path`. The rename replaces
///   a pre-planted symlink at `path` instead of following it.
/// * A stale temp file from a prior crash is removed first; if anything re-creates it
///   before our `create_new`, the call fails closed with `AlreadyExists`.
/// * On Windows: same atomic-rename flow, but no explicit DACL yet. TODO(DACL):
///   user-SID owner-only ACL before the Windows release (audit C24).
pub fn write_secret_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let tmp = secret_tmp_path(path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Remove stale temp from a prior crash (ignore absence). Anything re-created in
    // the gap makes create_new below fail closed.
    let _ = fs::remove_file(&tmp);

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;

    let write_result = file.write_all(contents);
    drop(file);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, path)
}

fn secret_tmp_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path must name a file"))?
        .to_string_lossy()
        .into_owned();
    Ok(path.with_file_name(format!(".{name}.secret.tmp")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_file_owner_only_unix() {
        let dir = std::env::temp_dir().join(format!("baluard-secret-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.bin");
        write_secret_file(&path, b"secret-bytes").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret-bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "file must be owner-only");
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn replaces_symlink_instead_of_following() {
        let dir =
            std::env::temp_dir().join(format!("baluard-secret-symlink-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"original").unwrap();
        let target = dir.join("real-secret.enc");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        #[cfg(not(unix))]
        let target = victim.clone(); // no symlink test on non-unix

        write_secret_file(&target, b"new-contents").unwrap();
        // Victim untouched; the symlink itself was replaced by a regular file.
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert_eq!(fs::read(&target).unwrap(), b"new-contents");
        let _ = fs::remove_file(&victim);
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn leaves_no_temp_behind_on_success() {
        let dir = std::env::temp_dir().join(format!("baluard-secret-notmp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.enc");
        write_secret_file(&path, b"x").unwrap();
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1, "only the final file remains");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
