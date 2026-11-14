//! Off-main attachment blob line (design: docs/designs/attachment-storage.md).
//!
//! Attachment envelopes travel on the notes ref `refs/notes/baluard-attachments`
//! as an append-mostly line of signed commits whose tree carries each blob
//! content-addressed by its SHA-256 (`<hash>.enc`). The vault's main branch
//! stays lean (metadata only); new blobs never ride main. Line tips descend
//! from the vault's root commit, so the gossip relocation's root-of-history
//! classification applies unchanged: a tip rooted on a different vault is
//! foreign, ignored for seeding, and never adopted — only compaction
//! force-replaces, and only with a genesis it just built.
//!
//! Integrity is content-addressing, not admission: any push-accessible
//! device may append entries, and junk is inert (downloads fetch by the
//! hash pinned in main metadata and verify the bytes against it), so line
//! commit signatures are hygiene, not a security boundary. Deleted
//! attachments are tombstoned on main; a manual compaction reclaims their
//! bytes from the line (main is the existence authority).
//!
//! Sync-time writes never prune: every publish rebuilds from the freshly
//! fetched tip, which already prevents resurrection of compacted ids, and
//! a write-time prune to main references would race other devices'
//! in-flight uploads (a blob lands on the line before its metadata lands
//! on main).

use std::collections::HashSet;

use git2::Oid;

use crate::error::{BaluardError, SyncError};

/// The attachments channel: a ref under refs/notes, invisible to the
/// forge branch and tag lists, so the user's repository keeps exactly one
/// branch beside the gossip channel.
pub const ATTACHMENTS_REF: &str = "refs/notes/baluard-attachments";

/// Tracking-ref short name under refs/remotes/<remote>/.
pub const ATTACHMENTS_TRACKING: &str = "attachments";

/// The worktree path shape of an attachment envelope under a cipher's
/// entry directory. Line-bound transport never stages onto main, and a
/// tracked legacy blob's pull-time checkout must not be refused because a
/// NEW sibling blob sits untracked beside it.
pub fn is_blob_path(path: &str) -> bool {
    path.starts_with("entries/") && path.contains("/attachments/") && path.ends_with(".enc")
}

/// The line-tree entry name for a blob id: the content hash pin main
/// metadata carries. `None` for anything that is not a SHA-256 hex
/// digest — junk names cannot enter the tree through this module.
pub fn entry_name(pin: &str) -> Option<String> {
    let h = pin.trim();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{}.enc", h.to_ascii_lowercase()))
}

/// The blob id (hash pin) behind a line-tree entry name.
pub fn entry_pin(name: &str) -> Option<&str> {
    name.strip_suffix(".enc")
}

/// SHA-256 of the stored envelope bytes, hex-encoded — the same value
/// Phase 1 pins into `AttachmentMeta.blob_sha256`.
pub fn hash_blob(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(blob))
}

/// Content-address verification: the bytes must hash to the pin. This is
/// the download-path integrity gate — a tampered line entry, a forged
/// blob, or a stale pin all fail closed here.
pub fn verify_blob(blob: &[u8], pin: &str) -> bool {
    hash_blob(blob) == pin.trim().to_ascii_lowercase()
}

/// Raw blob entries (name, oid) of a line tree. The line tree is FLAT
/// (leaf names only — git2 rejects path separators in tree entry names),
/// so this never walks subdirectories; entries of the wrong object type
/// are skipped, but names are NOT validated here — a hostile junk name
/// must survive a union untouched (hash pinning makes it inert; only
/// compaction reclaims it).
pub fn raw_entries(tip: &git2::Tree<'_>) -> Vec<(String, Oid)> {
    let mut out = Vec::new();
    for entry in tip.iter() {
        if entry.kind() != Some(git2::ObjectType::Blob) {
            continue;
        }
        let Some(name) = entry.name() else { continue };
        out.push((name.to_string(), entry.id()));
    }
    out
}

/// What one compaction pass reclaimed from the line. `kept` counts the
/// encrypted files the vault still references; `reclaimed` counts line
/// entries dropped (deleted attachments, pre-rotation leftovers, hostile
/// junk names).
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CompactionReport {
    pub reclaimed: u64,
    pub reclaimed_bytes: u64,
    pub kept: u64,
}

/// Worktree blob files that are line transport rather than git content:
/// new uploads stay untracked (stage_admitted skips them), while legacy
/// pre-line blobs were checked out from main and carry index state.
/// Only the pure-WT_NEW shape is publishable — the same classification
/// the staging skip uses.
pub fn collect_untracked_blob_paths(repo: &git2::Repository) -> Vec<std::path::PathBuf> {
    let workdir = match repo.workdir() {
        Some(w) => w.to_path_buf(),
        None => return Vec::new(),
    };
    let Ok(ciphers) = std::fs::read_dir(workdir.join("entries")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for cipher in ciphers.flatten() {
        let Ok(att) = std::fs::read_dir(cipher.path().join("attachments")) else {
            continue;
        };
        for file in att.flatten() {
            let path = file.path();
            if path.extension().is_none_or(|e| e != "enc") {
                continue;
            }
            let Ok(rel) = path.strip_prefix(&workdir) else {
                continue;
            };
            let Ok(status) = repo.status_file(rel) else {
                continue;
            };
            let has_index = status.intersects(
                git2::Status::INDEX_NEW
                    | git2::Status::INDEX_MODIFIED
                    | git2::Status::INDEX_DELETED
                    | git2::Status::INDEX_RENAMED
                    | git2::Status::INDEX_TYPECHANGE,
            );
            if has_index || !status.contains(git2::Status::WT_NEW) {
                continue;
            }
            out.push(path);
        }
    }
    out
}

/// Flatten a line tip tree into (pin, blob oid) entries, dropping names
/// that are not SHA-256 pins (junk cannot masquerade as content). The
/// pruner and download path speak in pins; the merger preserves raw
/// names.
pub fn line_entries(tip: &git2::Tree<'_>) -> Vec<(String, Oid)> {
    raw_entries(tip)
        .into_iter()
        .filter(|(name, _)| entry_pin(name).is_some())
        .map(|(name, oid)| (entry_pin(&name).unwrap().to_string(), oid))
        .collect()
}

/// Union-merge line trees into one new tree: a set-union of entries.
/// Content-addressed names never carry conflicting content (same name =
/// same bytes by construction), so the merge cannot conflict — junk
/// entries ride along inert until compaction.
pub fn union_line_trees<'r>(
    repo: &'r git2::Repository,
    trees: &[&git2::Tree<'_>],
) -> Result<git2::Tree<'r>, BaluardError> {
    let mut tb = repo
        .treebuilder(None)
        .map_err(|e| SyncError::Git(format!("attachments treebuilder: {e}")))?;
    for tree in trees {
        // Raw names: junk survives the merge untouched (inert by
        // contract) — the pin gate filters at download and compaction,
        // never at merge time.
        for (name, oid) in raw_entries(tree) {
            tb.insert(&name, oid, git2::FileMode::Blob.into())
                .map_err(|e| SyncError::Git(format!("attachments insert: {e}")))?;
        }
    }
    let id = tb
        .write()
        .map_err(|e| SyncError::Git(format!("attachments tree write: {e}")))?;
    Ok(repo
        .find_tree(id)
        .map_err(|e| SyncError::Git(format!("attachments find tree: {e}")))?)
}

/// Rebuild a line tree keeping only `keep` pins. Compaction's pruner: the
/// live set arrives from the runtime because main metadata is encrypted
/// at the sync layer, so the core cannot derive it.
pub fn prune_line_tree<'r>(
    repo: &'r git2::Repository,
    tip: &git2::Tree<'_>,
    keep: &HashSet<String>,
) -> Result<git2::Tree<'r>, BaluardError> {
    let mut tb = repo
        .treebuilder(None)
        .map_err(|e| SyncError::Git(format!("attachments treebuilder: {e}")))?;
    for (pin, oid) in line_entries(tip) {
        if keep.contains(&pin) {
            let Some(name) = entry_name(&pin) else {
                continue;
            };
            tb.insert(&name, oid, git2::FileMode::Blob.into())
                .map_err(|e| SyncError::Git(format!("attachments insert: {e}")))?;
        }
    }
    let id = tb
        .write()
        .map_err(|e| SyncError::Git(format!("attachments tree write: {e}")))?;
    Ok(repo
        .find_tree(id)
        .map_err(|e| SyncError::Git(format!("attachments find tree: {e}")))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_repo() -> (tempfile::TempDir, git2::Repository) {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        (dir, repo)
    }

    fn tree_with<'a>(repo: &'a git2::Repository, pins: &[&str]) -> git2::Tree<'a> {
        let mut tb = repo.treebuilder(None).unwrap();
        for pin in pins {
            let blob = repo.blob(format!("payload-{pin}").as_bytes()).unwrap();
            tb.insert(entry_name(pin).unwrap(), blob, git2::FileMode::Blob.into())
                .unwrap();
        }
        repo.find_tree(tb.write().unwrap()).unwrap()
    }

    #[test]
    fn entry_name_accepts_only_sha256_hex() {
        let good = "a".repeat(64);
        assert_eq!(
            entry_name(&good).as_deref(),
            Some(format!("{good}.enc").as_str())
        );
        assert_eq!(
            entry_name(&good.to_uppercase()).as_deref(),
            Some(format!("{good}.enc").as_str()),
            "mixed case pins normalize to lowercase"
        );
        assert!(entry_name("short").is_none());
        assert!(entry_name(&"g".repeat(64)).is_none(), "g is not hex");
        assert!(entry_name(&"a".repeat(63)).is_none());
        assert!(entry_name("").is_none());
    }

    #[test]
    fn verify_blob_rejects_forged_bytes() {
        let blob = b"envelope-bytes".to_vec();
        let pin = hash_blob(&blob);
        assert!(verify_blob(&blob, &pin));
        assert!(!verify_blob(&blob, &"0".repeat(64)));
        let mut forged = blob.clone();
        forged[0] ^= 0xff;
        assert!(!verify_blob(&forged, &pin), "a flipped byte breaks the pin");
    }

    #[test]
    fn is_blob_path_matches_the_entry_attachments_shape() {
        assert!(is_blob_path("entries/abc/attachments/def.enc"));
        assert!(!is_blob_path("entries/abc/cipher.enc"));
        assert!(!is_blob_path("ciphers/abc.enc"));
        assert!(!is_blob_path("entries/abc/attachments/def.txt"));
    }

    #[test]
    fn union_merges_and_junk_tips_converge() {
        let (_dir, repo) = scratch_repo();
        let t1 = tree_with(&repo, &[&"a".repeat(64), &"b".repeat(64)]);
        // A junk tip: a non-hex entry name rides along (inserted directly,
        // bypassing entry_name's gate) and is preserved by the union —
        // hash pinning makes it inert, compaction reclaims it.
        let mut junk_tb = repo.treebuilder(None).unwrap();
        let blob = repo.blob(b"junk").unwrap();
        junk_tb
            .insert("not-a-hash.enc", blob, git2::FileMode::Blob.into())
            .unwrap();
        let junk_tree = repo.find_tree(junk_tb.write().unwrap()).unwrap();
        let merged = union_line_trees(&repo, &[&t1, &junk_tree]).unwrap();
        let mut names: Vec<String> = merged
            .iter()
            .map(|e| String::from_utf8_lossy(e.name_bytes()).to_string())
            .collect();
        names.sort();
        assert_eq!(names.len(), 3, "union keeps every entry: {names:?}");
        assert!(names.contains(&format!("{}.enc", "a".repeat(64))));
        assert!(names.contains(&"not-a-hash.enc".to_string()));
    }

    #[test]
    fn prune_removes_deleted_ids_and_keeps_the_live_set() {
        let (_dir, repo) = scratch_repo();
        let keep_a = "a".repeat(64);
        let dead = "c".repeat(64);
        let tip = tree_with(&repo, &[&keep_a, &"b".repeat(64), &dead]);
        let mut keep = HashSet::new();
        keep.insert(keep_a.clone());
        keep.insert("b".repeat(64));
        let pruned = prune_line_tree(&repo, &tip, &keep).unwrap();
        let names: Vec<String> = pruned
            .iter()
            .map(|e| String::from_utf8_lossy(e.name_bytes()).to_string())
            .collect();
        assert_eq!(names.len(), 2, "the dead id is gone: {names:?}");
        assert!(!names.contains(&format!("{dead}.enc")));
    }
}
