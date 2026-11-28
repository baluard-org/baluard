//! Offline migration extracts from vault backups.
//!
//! Decrypts a materialized vault folder (or a backup zip of one) with the
//! recovery phrase, optionally verifying the master password against the
//! KEK canary, and emits an interoperable JSON dump plus plaintext
//! attachment files. Strictly read-only on the vault: no device
//! enrollment, no git remote contact. The vault copy it opens is scratch
//! data: Baluard's open path may heal integrity state in place, so never
//! point this at a live vault.

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

/// Outcome of the optional master-password check against the backup's
/// KEK canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterPasswordCheck {
    Verified,
    /// Reported, not fatal: the recovery phrase is the extract's
    /// authority, and member-device backups carry no synced unlock wrap,
    /// so their password cannot match the founder canary.
    Mismatch,
    NoCanary,
}

/// Result of a successful extract.
#[derive(Debug)]
pub struct ExtractReport {
    /// Interoperable JSON dump (Bitwarden-compatible import format).
    pub json: String,
    pub entries: usize,
    pub folders: usize,
    /// None when no master password was supplied (check skipped).
    pub password_check: Option<MasterPasswordCheck>,
    /// Attachment ids that were not valid UUIDs and so were not extracted.
    pub skipped_attachments: usize,
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

    let password_check = match password {
        Some(p) => match handle.verify_master_password(p) {
            Ok(true) => Some(MasterPasswordCheck::Verified),
            Ok(false) => Some(MasterPasswordCheck::NoCanary),
            Err(BaluardError::Vault(VaultError::PasswordMismatch)) => {
                Some(MasterPasswordCheck::Mismatch)
            }
            Err(e) => return Err(e),
        },
        None => None,
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
    let mut skipped_attachments: usize = 0;
    for cipher in &ciphers {
        for meta in &cipher.attachments {
            let Ok(attachment_id) = meta.id.parse::<Uuid>() else {
                skipped_attachments += 1;
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
        password_check,
        skipped_attachments,
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

    let names: Vec<String> = (0..archive.len())
        .map(|i| {
            archive
                .by_index(i)
                .map(|e| e.name().to_string())
                .map_err(|e| VaultError::Corrupt(format!("reading zip entry {i}: {e}")))
        })
        .collect::<Result<_, _>>()?;
    let shared_root = shared_wrapper_root(&names);
    // Shape detection must run on STRIPPED names: a mirror zipped under
    // one wrapper folder (vault.git/HEAD) would otherwise read as a
    // plain vault folder.
    let is_mirror = names.iter().any(|n| {
        matches!(strip_shared(n, shared_root.as_deref()), "HEAD")
            || strip_shared(n, shared_root.as_deref()).starts_with("objects/")
    });
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| VaultError::Corrupt(format!("reading zip entry {i}: {e}")))?;
        total = total.saturating_add(entry.size());
    }
    if total > MAX_ZIP_UNCOMPRESSED_BYTES {
        return Err(VaultError::Corrupt("backup zip is too large to extract safely".into()).into());
    }

    if is_mirror {
        let gitdir = work_dir.join("repo");
        std::fs::create_dir_all(&gitdir)
            .map_err(|e| VaultError::Metadata(format!("creating work dir: {e}")))?;
        extract_zip_entries(&mut archive, &gitdir, shared_root.as_deref())?;
        // The mirror holds the repo history; the working tree with the
        // vault files comes out of the checkout.
        let checkout = work_dir.join("checkout");
        materialize_worktree_from_gitdir(&gitdir, &checkout)?;
        reject_symlinks(&checkout)?;
        Ok(checkout)
    } else {
        let dest = work_dir.join("vault");
        std::fs::create_dir_all(&dest)
            .map_err(|e| VaultError::Metadata(format!("creating work dir: {e}")))?;
        extract_zip_entries(&mut archive, &dest, shared_root.as_deref())?;
        Ok(dest)
    }
}

/// Strip a wrapper folder only when EVERY entry shares one first
/// component; any entry without it (or without a slash at all) kills it.
fn shared_wrapper_root(names: &[String]) -> Option<String> {
    let mut shared_root: Option<String> = None;
    for name in names {
        let first = name.split('/').next().unwrap_or("");
        // "." and ".." are never wrapper folders: treating them as one
        // would strip a traversal away before the path guard sees it.
        if name.contains('/') && !first.is_empty() && first != "." && first != ".." {
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
    shared_root
}

fn strip_shared<'a>(name: &'a str, shared_root: Option<&str>) -> &'a str {
    let s = match shared_root {
        Some(root) => name.strip_prefix(root).unwrap_or(name),
        None => name,
    };
    s.trim_start_matches('/')
}

/// git2 materializes symlinks stored in the repo; an extract must not
/// follow links out of the tree it just created.
fn reject_symlinks(dir: &Path) -> Result<(), BaluardError> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)
            .map_err(|e| VaultError::Metadata(format!("walking extracted tree: {e}")))?
        {
            let path = entry
                .map_err(|e| VaultError::Metadata(format!("walking extracted tree: {e}")))?
                .path();
            let md = std::fs::symlink_metadata(&path)
                .map_err(|e| VaultError::Metadata(format!("walking extracted tree: {e}")))?;
            if md.file_type().is_symlink() {
                return Err(VaultError::Corrupt(
                    "backup contains a symlink; refusing to extract it".into(),
                )
                .into());
            }
            if md.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Extract every entry of an already-opened zip into `dest`, stripping a
/// shared leading folder and refusing path traversal (zip-slip).
fn extract_zip_entries<R>(
    archive: &mut zip::ZipArchive<R>,
    dest: &Path,
    shared_root: Option<&str>,
) -> Result<(), BaluardError>
where
    R: std::io::Read + std::io::Seek,
{
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| VaultError::Corrupt(format!("reading zip entry {i}: {e}")))?;
        let raw = entry.name().to_string();
        let rel = strip_shared(&raw, shared_root);
        if rel.is_empty() {
            continue;
        }
        // Only plain name components survive: Prefix/RootDir/ParentDir
        // components would let a crafted zip escape `dest` (on Windows,
        // "C:evil" and "\evil" are neither absolute nor ParentDir).
        let rel_path = Path::new(rel);
        if !rel_path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
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
        // Enforce the cap on bytes actually written: a zip may lie about
        // entry.size(), which the pre-pass total trusts.
        let copied = std::io::copy(
            &mut std::io::Read::take(&mut entry, MAX_ZIP_UNCOMPRESSED_BYTES + 1),
            &mut out,
        )
        .map_err(|e| VaultError::Metadata(format!("copying zip entry: {e}")))?;
        if copied > MAX_ZIP_UNCOMPRESSED_BYTES {
            return Err(VaultError::Corrupt(format!("zip entry too large: {raw}")).into());
        }
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

        assert_eq!(
            report.password_check,
            Some(MasterPasswordCheck::Verified),
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
        // The failure must come from unwrapping the kit, not from a
        // missing one: distinguish shape errors from crypto errors.
        assert!(
            !err.to_string().contains("no recovery kit"),
            "unexpected failure: {err}"
        );
    }

    #[test]
    fn wrong_password_reports_mismatch_when_canary_exists() {
        let tv = create_vault_with_attachment();
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("backup.zip");
        zip_folder(tv.dir.path(), &zip_path);
        let report = extract_from_zip(
            &zip_path,
            &work.path().join("u"),
            &tv.phrase,
            Some("definitely-wrong"),
        )
        .unwrap();
        assert_eq!(
            report.password_check,
            Some(MasterPasswordCheck::Mismatch),
            "a canary-bearing backup must report the mismatch"
        );
    }

    #[test]
    fn skipped_password_reports_none() {
        let tv = create_vault_with_attachment();
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("backup.zip");
        zip_folder(tv.dir.path(), &zip_path);
        let report = extract_from_zip(&zip_path, &work.path().join("u"), &tv.phrase, None).unwrap();
        assert_eq!(report.password_check, None);
    }

    #[test]
    fn zip_slip_entries_are_rejected() {
        let tv = create_vault_with_attachment();
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("evil.zip");
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("../evil.txt", options).unwrap();
            std::io::Write::write_all(&mut zip, b"nope").unwrap();
            zip.finish().unwrap();
        }
        let err = extract_from_zip(&zip_path, &work.path().join("u"), &tv.phrase, None)
            .expect_err("zip-slip entry must be rejected");
        assert!(err.to_string().contains("unsafe path"), "{err}");
    }

    #[test]
    fn wrapped_mirror_zip_is_detected_as_mirror() {
        let tv = create_vault_with_attachment();
        commit_all(tv.dir.path());
        fn copy_tree(src: &Path, dst: &Path) {
            std::fs::create_dir_all(dst).unwrap();
            for entry in std::fs::read_dir(src).unwrap().flatten() {
                let target = dst.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy_tree(&entry.path(), &target);
                } else {
                    std::fs::copy(entry.path(), target).unwrap();
                }
            }
        }
        // Mirror-format backups wrap the bare repo in one folder.
        let stage = tempfile::tempdir().unwrap();
        copy_tree(&tv.dir.path().join(".git"), &stage.path().join("vault.git"));
        let work = tempfile::tempdir().unwrap();
        let zip_path = work.path().join("wrapped.zip");
        zip_folder(stage.path(), &zip_path);
        let report = extract_from_zip(&zip_path, &work.path().join("u"), &tv.phrase, None).unwrap();
        assert_eq!(
            report.entries, 1,
            "a wrapped mirror must materialize via git2, not fail as a folder"
        );
    }
}
