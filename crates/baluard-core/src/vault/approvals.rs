//! Sensitive-op approvals (§6.5 `quorum_admin_ops`, decided 2026-09-27).
//!
//! The default threshold is 1: one admin acts alone and this module
//! never sees traffic. When the admin raises the threshold, a
//! sensitive operation must collect DISTINCT admin approvals before it
//! runs. A pending record at `meta/approvals/<id>.json` carries the op
//! kind, a digest of the op's parameters, the initiator, and the
//! approvals collected so far. The record is plaintext and rides the
//! `meta/**` Admin sync row: every peer's next pull sees the ask, and
//! any admin device can confirm it.
//!
//! The two-phase flow: the first admin's call on a sensitive op
//! creates (or refreshes) the record and REFUSES with a clear message.
//! Each further admin confirming the same change appends an approval;
//! once distinct approvals reach the threshold, the confirming call
//! consumes the record and the op executes. A record whose params
//! digest differs from the incoming ask is stale — the newest ask
//! replaces it, so a changed plan never inherits old approvals.
//!
//! Enforcement is local-only like every §6.5 knob: the threshold lives
//! in the encrypted settings, which the keyless sync walker cannot
//! read. The record itself carries `required`, so a peer can still
//! render the ask.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

/// Directory under the vault root holding pending records.
pub const APPROVALS_DIR: &str = "meta/approvals";

/// Cap on the serialized op parameters carried for the digest.
pub const MAX_PARAMS_BYTES: usize = 8 * 1024;

/// Walk cap so a flooded directory cannot stall listing.
const MAX_PENDING_RECORDS: usize = 64;

/// Highest settable threshold.
pub const MAX_QUORUM: u8 = 5;

/// A pending sensitive-op approval record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOp {
    pub format: u8,
    /// Op identifier, e.g. `rotate_root_key`.
    pub kind: String,
    /// sha256 over kind + canonical params; binds approvals to one ask.
    pub params_digest: String,
    /// Member id that raised the ask.
    pub initiated_by: Uuid,
    pub initiated_at: u64,
    /// Threshold copied from settings at ask time.
    pub required: u8,
    /// Member ids that approved, initiator included.
    pub approvals: Vec<Uuid>,
    /// The canonical params the ask was raised with (review F1: the
    /// co-approver repeats the SAME ask, so claim-type ops must expose
    /// the claimant id the ask names; legacy records predate this and
    /// read as None).
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// Outcome of presenting an op at the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Enough distinct approvals were on record (this call supplied the
    /// last one); the record was consumed — run the op.
    Approved,
    /// The ask is waiting for more admins.
    Pending,
    /// This admin already approved; a DIFFERENT admin must confirm.
    AlreadyApproved,
}

/// Stable digest binding an approval set to one concrete ask.
pub fn op_digest(kind: &str, params: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(params).unwrap_or_else(|_| params.to_string());
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\x00");
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    hex::encode(&out[..16])
}

fn approvals_dir(vault_path: &Path) -> std::path::PathBuf {
    vault_path.join(APPROVALS_DIR)
}

/// List pending records, oldest first. Malformed or foreign-shaped
/// files skip inert; the walk caps at [`MAX_PENDING_RECORDS`].
pub fn list_pending(vault_path: &Path) -> Vec<PendingOp> {
    let dir = approvals_dir(vault_path);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut rows: Vec<(std::path::PathBuf, PendingOp)> = Vec::new();
    for entry in entries.flatten() {
        if rows.len() >= MAX_PENDING_RECORDS {
            break;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > MAX_PARAMS_BYTES {
            continue;
        }
        let Ok(op) = serde_json::from_slice::<PendingOp>(&bytes) else {
            continue;
        };
        if op.format != 1 || op.kind.is_empty() || op.params_digest.is_empty() {
            continue;
        }
        rows.push((path, op));
    }
    rows.sort_by_key(|(_, op)| (op.initiated_at, op.kind.clone()));
    rows.into_iter().map(|(_, op)| op).collect()
}

fn record_path(vault_path: &Path, op: &PendingOp) -> std::path::PathBuf {
    // Per-initiator filename: two admins raising the same ask each
    // carry their own file, so neither's uncommitted local copy can
    // collide with the other's committed one at pull time.
    approvals_dir(vault_path).join(format!(
        "{}-{}.json",
        op.params_digest,
        &op.initiated_by.simple().to_string()[..8]
    ))
}

fn write_record(vault_path: &Path, op: &PendingOp) -> std::io::Result<()> {
    let dir = approvals_dir(vault_path);
    std::fs::create_dir_all(&dir)?;
    let bytes = serde_json::to_vec_pretty(op).unwrap_or_default();
    let path = record_path(vault_path, op);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)
}

/// Present a sensitive op at the gate. See the module docs for the
/// flow. `member_id` is the acting device's member row id; the caller
/// has already verified it belongs to an admin.
pub fn present(
    vault_path: &Path,
    kind: &str,
    params: &serde_json::Value,
    member_id: Uuid,
    required: u8,
    now: u64,
) -> ApprovalOutcome {
    let digest = op_digest(kind, params);
    // Same ask already on record? Append (or short-circuit).
    let existing = list_pending(vault_path)
        .into_iter()
        .find(|op| op.kind == kind && op.params_digest == digest);
    if let Some(mut op) = existing {
        if op.approvals.contains(&member_id) {
            return ApprovalOutcome::AlreadyApproved;
        }
        op.approvals.push(member_id);
        // The LIVE threshold always governs: a record minted under a
        // lower knob (or a tampered `required`) can never approve below
        // what the settings demand now.
        let effective = required.max(op.required);
        if op.approvals.len() >= effective as usize {
            let _ = std::fs::remove_file(record_path(vault_path, &op));
            return ApprovalOutcome::Approved;
        }
        op.required = effective;
        let _ = write_record(vault_path, &op);
        return ApprovalOutcome::Pending;
    }
    // Fresh ask (or a stale record of the same kind — the newest ask
    // replaces it because stale records carry a different digest and
    // simply stop matching; nothing inherits old approvals).
    let op = PendingOp {
        format: 1,
        kind: kind.to_string(),
        params_digest: digest,
        initiated_by: member_id,
        initiated_at: now,
        required: required.clamp(2, MAX_QUORUM),
        approvals: vec![member_id],
        params: Some(params.clone()),
    };
    let _ = write_record(vault_path, &op);
    ApprovalOutcome::Pending
}

/// Remove a pending record after the op ran through another path or
/// was superseded. Missing file = nothing to do.
pub fn consume_matching(vault_path: &Path, kind: &str, params: &serde_json::Value) {
    let digest = op_digest(kind, params);
    for op in list_pending(vault_path) {
        if op.kind == kind && op.params_digest == digest {
            let _ = std::fs::remove_file(record_path(vault_path, &op));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(n: u64) -> serde_json::Value {
        serde_json::json!({ "n": n })
    }

    #[test]
    fn two_phase_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Threshold 2: first admin raises the ask.
        assert_eq!(
            present(path, "op", &params(1), a, 2, 100),
            ApprovalOutcome::Pending
        );
        // Same admin again: cannot self-confirm.
        assert_eq!(
            present(path, "op", &params(1), a, 2, 101),
            ApprovalOutcome::AlreadyApproved
        );
        // Second admin confirms: approved, record consumed.
        assert_eq!(
            present(path, "op", &params(1), b, 2, 102),
            ApprovalOutcome::Approved
        );
        assert!(list_pending(path).is_empty());
    }

    #[test]
    fn changed_params_do_not_inherit_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(
            present(path, "op", &params(1), a, 2, 100),
            ApprovalOutcome::Pending
        );
        // A different ask of the same kind: fresh record, no carry-over.
        assert_eq!(
            present(path, "op", &params(2), b, 2, 101),
            ApprovalOutcome::Pending
        );
        // The original ask still stands with its one approval.
        let rows = list_pending(path);
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .any(|r| r.params_digest == op_digest("op", &params(1)) && r.approvals == vec![a])
        );
    }

    #[test]
    fn raised_threshold_demands_more_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Record minted under threshold 2: one real approval so far.
        assert_eq!(
            present(path, "op", &params(1), a, 2, 100),
            ApprovalOutcome::Pending
        );
        // Hostile on-disk edit lowers the record's `required` to 1.
        // The LIVE knob is 3, so b's single real signature must not
        // approve: the live threshold always governs.
        let rows = list_pending(path);
        assert_eq!(rows.len(), 1);
        let mut hostile = rows[0].clone();
        hostile.required = 1;
        let _ = std::fs::write(
            path.join(APPROVALS_DIR).join(format!(
                "{}-{}.json",
                hostile.params_digest,
                &hostile.initiated_by.simple().to_string()[..8]
            )),
            serde_json::to_vec(&hostile).unwrap(),
        );
        assert_eq!(
            present(path, "op", &params(1), b, 3, 101),
            ApprovalOutcome::Pending
        );
        // The record now carries the raised bar.
        assert_eq!(list_pending(path)[0].required, 3);
    }

    #[test]
    fn listing_skips_malformed_and_caps() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let dir = path.join(APPROVALS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("junk.json"), b"not json").unwrap();
        std::fs::write(dir.join("note.txt"), b"ignored").unwrap();
        assert_eq!(
            present(path, "op", &params(7), Uuid::new_v4(), 2, 100),
            ApprovalOutcome::Pending
        );
        let rows = list_pending(path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "op");
        consume_matching(path, "op", &params(7));
        assert!(list_pending(path).is_empty());
    }
}
