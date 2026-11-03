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
    // Flush to platter before the rename: without sync_all a power loss
    // right after the rename can leave a zero-length canary/keywrap and
    // brick the vault. A failed fsync fails the write.
    let sync_result = if write_result.is_ok() {
        file.sync_all()
    } else {
        Ok(())
    };
    drop(file);
    let result = sync_result.and(write_result);
    if let Err(e) = result {
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

// ── Sealed secret blobs (M3) ──
// AES-256-GCM envelope around arbitrary secret file content, bound to a
// purpose string via AAD. Used by callers that hold a process-lifetime
// encryption key (Android: a Keystore-wrapped random key handed in through
// UniFFI at app start). File format mirrors the C1 device-privkey seal:
// `{"type":"<purpose>","envelope":"<base64>"}` — detectable against the
// legacy plaintext content it replaces.

pub(crate) const SECRET_BLOB_PREFIX: &str = "baluard-secret-";

/// Seal `plaintext` into the envelope file format for `purpose` (e.g.
/// `"token-file-v1"`; the stored marker is `baluard-secret-<purpose>`).
pub fn seal_secret_blob(
    key: &[u8; 32],
    plaintext: &[u8],
    purpose: &str,
) -> Result<Vec<u8>, crate::error::BaluardError> {
    use crate::types::EnvelopeHeader;
    let marker = format!("{SECRET_BLOB_PREFIX}{purpose}");
    let nonce = crate::crypto::aead::build_random_nonce();
    let header = EnvelopeHeader {
        version: crate::BALUARD_VERSION,
        alg_id: crate::ALG_AES_256_GCM,
        key_epoch: 0,
        update_seq: 0,
        tier: None,
    };
    let envelope = crate::crypto::aead::encrypt(key, plaintext, marker.as_bytes(), &nonce, header)?;
    let serialized = crate::vault::envelope::serialize(&envelope)?;
    use base64::Engine as _;
    let doc = serde_json::json!({
        "type": marker,
        "envelope": base64::engine::general_purpose::STANDARD.encode(serialized),
    });
    Ok(doc.to_string().into_bytes())
}

/// Open a sealed blob produced by [`seal_secret_blob`]. Fails if `data` is
/// not the envelope format or the key is wrong (GCM tag binds both).
pub fn open_secret_blob(
    key: &[u8; 32],
    data: &[u8],
    purpose: &str,
) -> Result<Vec<u8>, crate::error::BaluardError> {
    use base64::Engine as _;
    let marker = format!("{SECRET_BLOB_PREFIX}{purpose}");
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| crate::error::VaultError::Corrupt(format!("sealed blob json: {e}")))?;
    if v["type"].as_str() != Some(marker.as_str()) {
        return Err(
            crate::error::VaultError::Corrupt("not a sealed blob for this purpose".into()).into(),
        );
    }
    let enc = v["envelope"]
        .as_str()
        .ok_or_else(|| crate::error::VaultError::Corrupt("sealed blob missing envelope".into()))?;
    let serialized = base64::engine::general_purpose::STANDARD
        .decode(enc)
        .map_err(|e| crate::error::VaultError::Corrupt(format!("sealed blob base64: {e}")))?;
    let envelope = crate::vault::envelope::deserialize(&serialized)?;
    let pt = crate::crypto::aead::decrypt(key, &envelope)
        .map_err(|_| crate::error::VaultError::Corrupt("sealed blob key mismatch".into()))?;
    // The outer "type" field is unauthenticated JSON; the purpose lives
    // in the AEAD AAD, so compare against it (same check open_bytes_hw
    // makes) or a re-labeled blob opens under another purpose.
    if envelope.aad != marker.as_bytes() {
        return Err(crate::error::VaultError::Corrupt(
            "sealed blob was sealed for a different purpose".into(),
        )
        .into());
    }
    Ok(pt)
}

/// True when the file content is the sealed format for ANY purpose. A false
/// return means "legacy plaintext or absent" — callers decide policy.
pub fn is_sealed_secret_blob(data: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(data)
        .ok()
        .and_then(|v| v["type"].as_str().map(|t| t.to_string()))
        .map(|t| t.starts_with(SECRET_BLOB_PREFIX))
        .unwrap_or(false)
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
