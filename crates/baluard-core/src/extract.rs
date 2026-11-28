//! Offline migration extracts from vault backups.
//!
//! Decrypts a materialized vault folder (or a backup zip of one) with the
//! recovery phrase, optionally verifying the master password against the
//! KEK canary, and emits an interoperable JSON dump plus plaintext
//! attachment files. Strictly read-only on the vault: no device
//! enrollment, no git remote contact, no writes to the vault itself.

use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{BaluardError, VaultError};
use crate::keys::hierarchy::RootKey;
use crate::vault::handle::{CipherRead, VaultHandle};

/// Refuse zips whose total uncompressed size exceeds this; a crafted
/// backup must not turn into an extraction bomb.
const MAX_ZIP_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// One decrypted attachment, ready to be written out. The data is
/// plaintext by definition — the caller's output IS the secret.
#[derive(Debug)]
pub struct ExtractedAttachment {
    pub cipher_id: Uuid,
    pub attachment_id: Uuid,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
    pub data: Vec<u8>,
}

/// Result of a successful extract.
#[derive(Debug)]
pub struct ExtractReport {
    /// Interoperable JSON dump (Bitwarden-compatible import format).
    pub json: String,
    pub entries: usize,
    pub folders: usize,
    /// True when the master password was checked against a KEK canary.
    /// False when the backup carries no canary to verify against.
    pub password_verified: bool,
    pub attachments: Vec<ExtractedAttachment>,
}

/// Extract from a backup zip into `work_dir` (created by this call;
/// the caller owns cleanup). Handles both backup shapes: a zip of a
/// vault folder and a zip of a bare mirror.
pub fn extract_from_zip(
    zip_path: &Path,
    work_dir: &Path,
    phrase: &str,
    password: Option<&str>,
) -> Result<ExtractReport, BaluardError> {
    std::fs::create_dir_all(work_dir)
        .map_err(|e| VaultError::Metadata(format!("creating work dir: {e}")))?;
    let vault_dir = materialize_zip(zip_path, work_dir)?;
    extract_from_folder(&vault_dir, phrase, password)
}

/// HPKE-unwrap the Root Key from `meta/recovery.json` with a recovery
/// phrase. Mirrors the first steps of device disaster recovery, minus
/// every mutating step: nothing is enrolled, nothing is written.
pub fn root_key_from_phrase(vault_path: &Path, phrase: &str) -> Result<RootKey, BaluardError> {
    use crate::recovery::RecoveryPhrase;

    let parsed = RecoveryPhrase::from_phrase(phrase)
        .map_err(|e| VaultError::Corrupt(format!("invalid recovery phrase: {e}")))?;
    let mut recovery_key = parsed.derive_key();
    let secret_bytes: [u8; 32] = recovery_key[..32]
        .try_into()
        .map_err(|_| VaultError::Corrupt("recovery key too short".into()))?;
    let x25519_secret = x25519_dalek::StaticSecret::from(secret_bytes);
    recovery_key.zeroize();

    let recovery_json_path = vault_path.join("meta/recovery.json");
    let recovery_json_str =
        std::fs::read_to_string(&recovery_json_path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => VaultError::Corrupt(
                "this backup has no recovery kit; it cannot be opened with a recovery phrase"
                    .into(),
            ),
            _ => VaultError::Metadata(format!("reading recovery.json: {e}")),
        })?;
    let recovery_json: serde_json::Value = serde_json::from_str(&recovery_json_str)
        .map_err(|e| VaultError::Corrupt(format!("parsing recovery.json: {e}")))?;

    let eph_pub = hex::decode(recovery_json["ephemeral_public"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("recovery eph_public hex: {e}")))?;
    let ct = hex::decode(recovery_json["encrypted_key"].as_str().unwrap_or(""))
        .map_err(|e| VaultError::Corrupt(format!("recovery encrypted_key hex: {e}")))?;
    let tag_hex = recovery_json["tag"].as_str().unwrap_or("");
    let tag_bytes =
        hex::decode(tag_hex).map_err(|e| VaultError::Corrupt(format!("recovery tag hex: {e}")))?;
    let mut tag = [0u8; 16];
    if tag_bytes.len() != 16 {
        return Err(VaultError::Corrupt("invalid recovery tag length".into()).into());
    }
    tag.copy_from_slice(&tag_bytes);

    let mut root_key_bytes = crate::crypto::hpke_wrap::unwrap_key(
        &eph_pub,
        &ct,
        &tag,
        &x25519_secret,
        "recovery-keywrap",
    )?;
    let rk_arr: [u8; 64] = root_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Corrupt("unwrapped root key not 64 bytes".into()))?;
    root_key_bytes.zeroize();
    Ok(RootKey::from_bytes(rk_arr))
}

/// Extract everything from a vault folder that already sits on disk
/// (unzipped by the caller, or materialized from a bare mirror).
pub fn extract_from_folder(
    vault_path: &Path,
    phrase: &str,
    password: Option<&str>,
) -> Result<ExtractReport, BaluardError> {
    let root = root_key_from_phrase(vault_path, phrase)?;
    let handle = VaultHandle::open_with_root_key(vault_path, &root)?;

    let password_verified = match password {
        Some(p) => handle.verify_master_password(p)?,
        None => false,
    };

    let mut ciphers = Vec::new();
    for id in handle.list_cipher_ids()? {
        match handle.get_cipher(id)? {
            CipherRead::Decrypted(cipher) => ciphers.push(*cipher),
            CipherRead::Locked(_) => {
                return Err(VaultError::Corrupt(format!(
                    "entry {id} did not decrypt; the backup is incomplete"
                ))
                .into());
            }
        }
    }
    let folder_pairs: Vec<(Uuid, String)> = handle
        .list_folders()?
        .into_iter()
        .map(|f| (f.id, f.name))
        .collect();
    let json = crate::import::export::export_bw_json(&ciphers, &folder_pairs)
        .map_err(|e| VaultError::Corrupt(format!("export serialization failed: {e}")))?;

    let mut attachments = Vec::new();
    for cipher in &ciphers {
        for meta in &cipher.attachments {
            let Ok(attachment_id) = meta.id.parse::<Uuid>() else {
                continue;
            };
            let data = handle.read_attachment_plaintext(cipher.id, attachment_id)?;
            attachments.push(ExtractedAttachment {
                cipher_id: cipher.id,
                attachment_id,
                filename: meta.filename.clone(),
                mime_type: meta.mime_type.clone(),
                size_bytes: meta.size,
                sha256_hex: sha256_hex(&data),
                data,
            });
        }
    }

    Ok(ExtractReport {
        json,
        entries: ciphers.len(),
        folders: folder_pairs.len(),
        password_verified,
        attachments,
    })
}

/// Detect the zip shape and unpack it into `work_dir`, returning the
/// vault folder inside it. Vault-folder zips unpack directly; bare
/// mirror zips are cloned into a working tree with plain git (local
/// file operation, no remote contact).
pub fn materialize_zip(zip_path: &Path, work_dir: &Path) -> Result<PathBuf, BaluardError> {
    let file = std::fs::File::open(zip_path)
        .map_err(|e| VaultError::Metadata(format!("opening backup zip: {e}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| VaultError::Corrupt(format!("reading backup zip: {e}")))?;

    let mut is_mirror = false;
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| VaultError::Corrupt(format!("reading zip entry {i}: {e}")))?;
        total = total.saturating_add(entry.size());
        let name = entry.name().to_string();
        if name == "HEAD" || name.starts_with("objects/") {
            is_mirror = true;
        }
    }
    if total > MAX_ZIP_UNCOMPRESSED_BYTES {
        return Err(VaultError::Corrupt("backup zip is too large to extract safely".into()).into());
    }

    if is_mirror {
        let gitdir = work_dir.join("repo");
        std::fs::create_dir_all(&gitdir)
            .map_err(|e| VaultError::Metadata(format!("creating work dir: {e}")))?;
        extract_zip_entries(&mut archive, &gitdir)?;
        // The mirror holds the repo history; the working tree with the
        // vault files comes out of the checkout.
        materialize_worktree_from_gitdir(&gitdir, &work_dir.join("checkout"))
    } else {
        let dest = work_dir.join("vault");
        std::fs::create_dir_all(&dest)
            .map_err(|e| VaultError::Metadata(format!("creating work dir: {e}")))?;
        extract_zip_entries(&mut archive, &dest)?;
        Ok(dest)
    }
}

/// Extract every entry of an already-opened zip into `dest`, stripping a
/// shared leading folder and refusing path traversal (zip-slip).
fn extract_zip_entries<R>(archive: &mut zip::ZipArchive<R>, dest: &Path) -> Result<(), BaluardError>
where
    R: std::io::Read + std::io::Seek,
{
    let names: Vec<String> = (0..archive.len())
        .map(|i| {
            archive
                .by_index(i)
                .map(|e| e.name().to_string())
                .map_err(|e| VaultError::Corrupt(format!("reading zip entry {i}: {e}")))
        })
        .collect::<Result<_, _>>()?;

    // Strip a wrapper folder only when EVERY entry shares one first
    // component; any entry without it (or without a slash at all) kills it.
    let mut shared_root: Option<String> = None;
    for name in &names {
        let first = name.split('/').next().unwrap_or("");
        if name.contains('/') && !first.is_empty() {
            match &shared_root {
                None => shared_root = Some(first.to_string()),
                Some(r) if r != first => {
                    shared_root = None;
                    break;
                }
                _ => {}
            }
        } else {
            shared_root = None;
            break;
        }
    }

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| VaultError::Corrupt(format!("reading zip entry {i}: {e}")))?;
        let raw = entry.name().to_string();
        let rel = match shared_root.as_deref() {
            Some(root) => raw.strip_prefix(root).unwrap_or(&raw),
            None => raw.as_str(),
        };
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            continue;
        }
        let rel_path = Path::new(rel);
        if rel_path.is_absolute()
            || rel_path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(VaultError::Corrupt(format!("unsafe path in backup zip: {raw}")).into());
        }
        let out_path = dest.join(rel_path);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)
                .map_err(|e| VaultError::Metadata(format!("creating zip dir: {e}")))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| VaultError::Metadata(format!("creating zip parent: {e}")))?;
        }
        let mut out = std::fs::File::create(&out_path)
            .map_err(|e| VaultError::Metadata(format!("writing zip entry: {e}")))?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| VaultError::Metadata(format!("copying zip entry: {e}")))?;
    }
    Ok(())
}

/// Check out a working tree from a bare (or gitdir) repo with plain git.
/// Purely local: a file-path clone never touches a remote and never runs
/// Baluard's sync layer, so no device enrollment happens here.
fn materialize_worktree_from_gitdir(
    gitdir: &Path,
    worktree: &Path,
) -> Result<PathBuf, BaluardError> {
    let src = gitdir
        .to_str()
        .ok_or_else(|| VaultError::Corrupt("mirror path is not valid UTF-8".into()))?;
    git2::Repository::clone(src, worktree).map_err(|e| {
        VaultError::Corrupt(format!("this mirror backup could not be materialized: {e}"))
    })?;
    Ok(worktree.to_path_buf())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CipherInput, KdfProfile};
    use crate::vault::attachment::AttachmentMeta;
    use crate::vault::creation::{CeremonySecrets, VaultCreator};
    use crate::vault::handle::VaultState;

    const ATTACHMENT_PLAINTEXT: &[u8] = b"passport-scan-bytes";

    struct TestVault {
        dir: tempfile::TempDir,
        phrase: String,
        password: String,
    }

    fn create_vault_with_attachment() -> TestVault {
        let dir = tempfile::tempdir().unwrap();
        let password = "extract-test-master-pw".to_string();
        let (mut handle, secrets) = VaultCreator::new(dir.path(), &password, "extract-test-device")
            .kdf_profile(KdfProfile::MobileLow)
            .initialize_git(false)
            .execute()
            .unwrap();
        let CeremonySecrets {
            recovery_phrase,
            vault_id,
            ..
        } = &secrets;
        let phrase = recovery_phrase.phrase();

        let root = match &handle.state {
            VaultState::Unlocked(u) => {
                RootKey::from_bytes(*u.root_key.as_ref().unwrap().as_bytes())
            }
            _ => panic!("vault should be unlocked after creation"),
        };

        let attachment_id = uuid::Uuid::new_v4();
        let current_epoch = match &handle.state {
            VaultState::Unlocked(u) => u.current_epoch,
            _ => panic!("vault should be unlocked after creation"),
        };
        // CipherInput implements Drop (secret material): build in place
        // instead of moving fields through struct-update syntax.
        let mut input = CipherInput::default();
        input.name = "Bank login".to_string();
        input.attachments = vec![AttachmentMeta {
            id: attachment_id.to_string(),
            filename: "statement.pdf".to_string(),
            size: ATTACHMENT_PLAINTEXT.len() as u64,
            encrypted_size: 0,
            mime_type: "application/pdf".to_string(),
            created_at: 0,
            blob_sha256: String::new(),
        }];
        let cipher_id = handle.add_cipher(&input).unwrap();
        // Mirror the flat-cipher resolution: SGK from the root key at the
        // vault's current epoch.
        let sgk = crate::keys::hierarchy::SpaceGroupKey::derive_from_root_key(&root, current_epoch);
        let item_key = sgk
            .try_derive_item_key(cipher_id, current_epoch)
            .expect("item key must derive at the current epoch");
        let enc = crate::vault::attachment::encrypt_attachment(
            *vault_id,
            cipher_id,
            attachment_id,
            item_key.as_bytes(),
            ATTACHMENT_PLAINTEXT,
            current_epoch,
            1,
        )
        .unwrap();
        let attach_dir = dir
            .path()
            .join("entries")
            .join(cipher_id.to_string())
            .join("attachments");
        std::fs::create_dir_all(&attach_dir).unwrap();
        std::fs::write(attach_dir.join(format!("{attachment_id}.enc")), &enc).unwrap();
        drop(handle);
        drop(secrets);
        TestVault {
            dir,
            phrase,
            password,
        }
    }

    /// Commit everything so the vault has history a mirror can carry.
    fn commit_all(dir: &Path) {
        let repo = git2::Repository::init(dir).unwrap();
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = git2::Signature::now("test", "test@test.invalid").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "seed", &tree, &[])
            .unwrap();
    }

    fn zip_folder(src: &Path, dest: &Path) {
        let file = std::fs::File::create(dest).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        fn add_dir(
            mut zip: &mut zip::ZipWriter<std::fs::File>,
            options: &zip::write::SimpleFileOptions,
            base: &Path,
            dir: &Path,
        ) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let rel = path.strip_prefix(base).unwrap();
                if path.is_dir() {
                    zip.add_directory(format!("{}/", rel.to_string_lossy()), *options)
                        .unwrap();
                    add_dir(zip, options, base, &path);
                } else {
                    zip.start_file(rel.to_string_lossy(), *options).unwrap();
                    std::io::copy(&mut std::fs::File::open(&path).unwrap(), &mut zip).unwrap();
                }
            }
        }
        add_dir(&mut zip, &options, src, src);
        zip.finish().unwrap();
    }

    #[test]
    fn extract_from_zip_roundtrips_entries_and_attachments() {
        let tv = create_vault_with_attachment();
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("backup.zip");
        zip_folder(tv.dir.path(), &zip_path);

        let report = extract_from_zip(
            &zip_path,
            &work.path().join("unpacked"),
            &tv.phrase,
            Some(&tv.password),
        )
        .unwrap();

        assert!(
            report.password_verified,
            "master password must verify against the KEK canary"
        );
        assert_eq!(report.entries, 1);
        assert_eq!(report.attachments.len(), 1);
        let att = &report.attachments[0];
        assert_eq!(att.filename, "statement.pdf");
        assert_eq!(att.data.as_slice(), ATTACHMENT_PLAINTEXT);
        let parsed: serde_json::Value = serde_json::from_str(&report.json).unwrap();
        assert!(parsed.get("items").is_some());
    }

    #[test]
    fn extract_from_zip_accepts_a_bare_mirror() {
        let tv = create_vault_with_attachment();
        commit_all(tv.dir.path());
        // Zip ONLY the .git directory: the shape a mirror-format backup
        // produces.
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("mirror.zip");
        zip_folder(&tv.dir.path().join(".git"), &zip_path);

        let report = extract_from_zip(
            &zip_path,
            &work.path().join("unpacked"),
            &tv.phrase,
            Some(&tv.password),
        )
        .unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.attachments.len(), 1);
        assert_eq!(report.attachments[0].data.as_slice(), ATTACHMENT_PLAINTEXT);
    }

    #[test]
    fn wrong_phrase_is_rejected() {
        let tv = create_vault_with_attachment();
        let other = crate::recovery::RecoveryPhrase::generate()
            .unwrap()
            .phrase();
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("backup.zip");
        zip_folder(tv.dir.path(), &zip_path);
        let err = extract_from_zip(
            &zip_path,
            &work.path().join("u"),
            &other,
            Some(&tv.password),
        )
        .expect_err("wrong phrase must fail");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn wrong_password_is_rejected_when_canary_exists() {
        let tv = create_vault_with_attachment();
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("backup.zip");
        zip_folder(tv.dir.path(), &zip_path);
        let err = extract_from_zip(
            &zip_path,
            &work.path().join("u"),
            &tv.phrase,
            Some("definitely-wrong-password"),
        )
        .expect_err("wrong password must fail");
        assert!(!err.to_string().is_empty());
    }
}
