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

/// What the cleanup notice says about a verified compaction (ADR 0107
/// enrichment). `device_id` comes from the genesis signature verifying
/// against a roster key — the key match IS the device binding — while
/// the numbers come from the signed genesis tree's `compaction.json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CompactionNotice {
    pub device_id: String,
    pub at: u64,
    pub reclaimed: u64,
    pub reclaimed_bytes: u64,
    pub kept: u64,
}

/// Tree entry name of the compaction record inside a compaction genesis.
pub const COMPACTION_ENTRY: &str = "compaction.json";

/// Reader cap for the compaction record (the bus's size-limit posture):
/// a larger entry is hostile or corrupt and surfaces no details.
pub const COMPACTION_MAX_BYTES: usize = 16 * 1024;

/// The parsed shape of `compaction.json`. Numeric fields only, `v`-gated;
/// unknown additive fields are ignored so a future version can extend.
#[derive(serde::Deserialize)]
pub(crate) struct CompactionPayload {
    pub(crate) v: u64,
    pub(crate) at: u64,
    pub(crate) reclaimed: u64,
    pub(crate) reclaimed_bytes: u64,
    pub(crate) kept: u64,
}

/// Per-device view of the shared attachments line, for the cleanup
/// notice: whether the line was rewritten under this device (a
/// compaction on another device) and whether the current tip belongs to
/// this vault at all.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LineStatus {
    /// Hex tip of the freshly fetched line; `None` when no line exists.
    pub tip: Option<String>,
    /// A previous tip was acknowledged and the current tip is not a
    /// descendant of it — the line was rewritten (compaction, or a
    /// force push). Descent could not be proven when the old commit is
    /// no longer reachable locally, which also reads as rewritten.
    pub rewritten: bool,
    /// The current tip is rooted on a different vault (hostile force
    /// push, or a vault-history reset this device has not pulled yet).
    pub foreign: bool,
    /// Attribution for a rewrite, per ADR 0107: `Some(true)` when the
    /// tip's commit signature verifies against a roster key (a rostered
    /// device performed the cleanup), `Some(false)` when a signature is
    /// present but no roster key verifies it (unknown signer), `None`
    /// when the tip is unsigned or the state is not a rewrite. The
    /// roster comes from main's tip tree (plaintext metadata, readable
    /// without unlocking).
    pub rewrite_signed: Option<bool>,
    /// Cleanup details when the rewrite is a compaction whose genesis
    /// signature verifies against the roster; `None` otherwise (not a
    /// rewrite, unsigned or unknown-signer genesis, no record).
    pub compaction: Option<CompactionNotice>,
}

/// The attachments channel: a ref under refs/notes, invisible to the
/// forge branch and tag lists, so the user's repository keeps exactly one
/// branch beside the gossip channel.
pub const ATTACHMENTS_REF: &str = "refs/notes/baluard-attachments";

/// Tracking-ref short name under refs/remotes/<remote>/.
pub const ATTACHMENTS_TRACKING: &str = "attachments";

/// The worktree path shape of an attachment envelope under a cipher's
/// entry directory: `entries/<cipher_id>/attachments/<attachment_id>.enc`,
/// exactly four components — the shape the publisher walks. Line-bound
/// transport never stages onto main, and a tracked legacy blob's pull-time
/// checkout must not be refused because a NEW sibling blob sits untracked
/// beside it. A stray .enc at any other depth is not line transport and
/// stays a normal local change.
pub fn is_blob_path(path: &str) -> bool {
    let mut parts = path.split('/');
    parts.next() == Some("entries")
        && parts.next().is_some_and(|id| !id.is_empty())
        && parts.next() == Some("attachments")
        && parts.next().is_some_and(|file| {
            file.strip_suffix(".enc")
                .is_some_and(|stem| !stem.is_empty())
        })
        && parts.next().is_none()
}

/// Whether a worktree status entry is line-bound transport rather than
/// main content. Only the pure `WT_NEW` shape qualifies: a blob the index
/// already tracks or holds staged is main content.
pub fn is_untracked_blob(status: git2::Status, path: &str) -> bool {
    let in_index = status.intersects(
        git2::Status::INDEX_NEW
            | git2::Status::INDEX_MODIFIED
            | git2::Status::INDEX_DELETED
            | git2::Status::INDEX_RENAMED
            | git2::Status::INDEX_TYPECHANGE,
    );
    status.contains(git2::Status::WT_NEW) && !in_index && is_blob_path(path)
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
            // Windows yields backslashes; git paths are slash-separated.
            let git_path = rel.to_string_lossy().replace('\\', "/");
            if !is_untracked_blob(status, &git_path) {
                continue;
            }
            out.push(path);
        }
    }
    out
}

/// Untracked worktree envelopes the last-known remote attachment line
/// does not carry. Offline readiness signal: the only publisher writes
/// blobs best-effort before the main push and a failed publish never
/// blocks it, so without this the blob is invisible everywhere. Pins are
/// compared against `refs/remotes/<remote>/<ATTACHMENTS_TRACKING>` — a
/// push advances that tracking ref, so a successful publish clears the
/// count without a fetch. With no local knowledge of the remote line at
/// all, every collected envelope counts as unconfirmed.
pub fn count_unpublished_blobs(repo: &git2::Repository, remote_name: &str) -> usize {
    let paths = collect_untracked_blob_paths(repo);
    if paths.is_empty() {
        return 0;
    }
    let confirmed = |tip: &git2::Tree<'_>, path: &std::path::Path| -> bool {
        // An unreadable envelope can never be confirmed, so it counts.
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        let Some(name) = entry_name(&crate::vault::attachment::blob_sha256(&bytes)) else {
            return false;
        };
        tip.get_name(&name).is_some()
    };
    let tracking = format!("refs/remotes/{remote_name}/{ATTACHMENTS_TRACKING}");
    match repo
        .find_reference(&tracking)
        .ok()
        .and_then(|r| r.peel_to_commit().ok())
        .and_then(|c| c.tree().ok())
    {
        None => paths.len(),
        Some(tip) => paths.into_iter().filter(|p| !confirmed(&tip, p)).count(),
    }
}

/// Flatten a line tip tree into (pin, blob oid) entries, dropping names
/// that are not SHA-256 pins (junk cannot masquerade as content). The
/// pruner and download path speak in pins; the merger preserves raw
/// names.
pub fn line_entries(tip: &git2::Tree<'_>) -> Vec<(String, Oid)> {
    raw_entries(tip)
        .into_iter()
        .filter_map(|(name, oid)| entry_pin(&name).map(|pin| (pin.to_string(), oid)))
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
    fn count_unpublished_blobs_compares_pins_with_the_remote_tracking_ref() {
        let (dir, repo) = scratch_repo();
        let att = dir
            .path()
            .join("entries/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/attachments");
        std::fs::create_dir_all(&att).unwrap();
        let blob_path = att.join("one.enc");
        std::fs::write(&blob_path, b"envelope-bytes").unwrap();

        // No remote line knowledge: everything counts as unconfirmed.
        assert_eq!(count_unpublished_blobs(&repo, "origin"), 1);

        // Tracking ref carries the pin: published, not counted.
        let pin = crate::vault::attachment::blob_sha256(b"envelope-bytes");
        let sig = git2::Signature::now("t", "t@example.invalid").unwrap();
        let tree_id = tree_with(&repo, &[&pin]).id();
        repo.commit(
            Some("refs/remotes/origin/attachments"),
            &sig,
            &sig,
            "line",
            &repo.find_tree(tree_id).unwrap(),
            &[],
        )
        .unwrap();
        assert_eq!(count_unpublished_blobs(&repo, "origin"), 0);

        // A second envelope the tracking line lacks is the only one counted.
        std::fs::write(att.join("two.enc"), b"other-bytes").unwrap();
        assert_eq!(count_unpublished_blobs(&repo, "origin"), 1);

        // Rewriting the first envelope to new bytes makes it unpublished
        // again under its new pin.
        std::fs::write(&blob_path, b"replaced-bytes").unwrap();
        assert_eq!(count_unpublished_blobs(&repo, "origin"), 2);
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
        // Exactly four components: the publisher walks that depth only,
        // so an envelope at any other depth is not line transport.
        assert!(!is_blob_path("entries/attachments/def.enc"));
        assert!(!is_blob_path("entries/abc/extra/attachments/def.enc"));
        assert!(!is_blob_path("entries/abc/attachments/sub/def.enc"));
        assert!(!is_blob_path("entries/abc/attachments/.enc"));
        assert!(!is_blob_path("entries//attachments/def.enc"));
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
