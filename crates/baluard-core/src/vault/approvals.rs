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
//! render the ask. Each approval entry carries the approver's member
//! identity signature over the ask (kind + digest), so a hand-written
//! record cannot forge a second admin's yes: the gate counts only
//! entries whose signature verifies against the member row's published
//! identity key.

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

/// One distinct approval on a pending record. The signature covers the
/// ask (kind, params digest, vault id, ask timestamp) and is made with
/// the approver's member identity key, so the gate can check it
/// against the member row's published identity key — a hand-written
/// record cannot forge it, and a signature harvested from git history
/// cannot be replayed onto a fresh ask (the ask timestamp is signed
/// and staleness-gated).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalEntry {
    pub member: Uuid,
    /// Hex Ed25519 signature over [`approval_message`].
    pub sig: String,
}

/// How long a pending ask stays confirmable. Stale asks are consumed;
/// a confirming admin past the window simply re-raises as the fresh
/// initiator. Matches the stale-invite window.
pub const APPROVAL_STALE_SECS: u64 = 7 * 24 * 3600;

/// The message every approval signature covers: the op kind, the
/// params digest, the vault it belongs to, the ask timestamp, and the
/// ask's random nonce — domain-separated and bound to one concrete
/// record in one vault. The nonce is what makes a consumed record's
/// harvested signatures useless on a fresh re-ask: fresh asks mint a
/// new nonce, so old entries never verify against the new record
/// (Ed25519 signatures are deterministic — without the nonce a
/// same-second re-ask would be byte-identical to the superseded ask).
pub fn approval_message(
    kind: &str,
    params_digest: &str,
    vault_id: Uuid,
    initiated_at: u64,
    nonce: &str,
) -> Vec<u8> {
    let mut msg = b"baluard-approval-v1/".to_vec();
    msg.extend_from_slice(kind.as_bytes());
    msg.push(b'/');
    msg.extend_from_slice(params_digest.as_bytes());
    msg.push(b'/');
    msg.extend_from_slice(vault_id.as_bytes());
    msg.push(b'/');
    msg.extend_from_slice(initiated_at.to_le_bytes().as_slice());
    msg.push(b'/');
    msg.extend_from_slice(nonce.as_bytes());
    msg
}

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
    /// Signed approvals collected so far, initiator included. Format 2:
    /// each entry carries its own identity signature.
    pub approvals: Vec<ApprovalEntry>,
    /// The canonical params the ask was raised with (review F1: the
    /// co-approver repeats the SAME ask, so claim-type ops must expose
    /// the claimant id the ask names; legacy records predate this and
    /// read as None).
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    /// Random per-ask nonce bound into every approval signature. Fresh
    /// asks mint one; it makes a consumed record's harvested signatures
    /// useless on a fresh re-ask (serde default: legacy format-2 records
    /// without a nonce parse and verify under the empty-nonce message).
    #[serde(default)]
    pub nonce: Option<String>,
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
    /// This exact ask (kind + digest + ask time) was already executed —
    /// the on-disk record is a git-history restoration, deleted on
    /// sight. Raise a fresh ask instead.
    Consumed,
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

/// Walk pending records with their discovered paths. Malformed or
/// foreign-shaped files skip inert; the walk caps at
/// [`MAX_PENDING_RECORDS`].
fn list_pending_paths(vault_path: &Path) -> Vec<(std::path::PathBuf, PendingOp)> {
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
        if op.format != 2 || op.kind.is_empty() || op.params_digest.is_empty() {
            continue;
        }
        rows.push((path, op));
    }
    rows.sort_by_key(|(_, op)| (op.initiated_at, op.kind.clone()));
    rows
}

/// List pending records, oldest first. Malformed or foreign-shaped
/// files skip inert; the walk caps at [`MAX_PENDING_RECORDS`].
pub fn list_pending(vault_path: &Path) -> Vec<PendingOp> {
    list_pending_paths(vault_path)
        .into_iter()
        .map(|(_, op)| op)
        .collect()
}

/// Remove every record file matching one ask, by its discovered path —
/// never by reconstructing the filename, so renamed or concurrently
/// raised duplicates cannot linger and replay their entries later.
/// Each removal leaves a `.consumed` tombstone: the records are
/// git-tracked, so deleting one does not erase it — a record restored
/// from history must hit the tombstone barrier and die on sight
/// (2026-10-01 review: a replayed ask could re-execute within the
/// staleness window). Tombstones are plaintext, carry no keys, and
/// ride the same Admin sync row.
fn remove_matching(vault_path: &Path, kind: &str, digest: &str) {
    let consumed_at = crate::vault::collections::now_secs_pub();
    for (path, op) in list_pending_paths(vault_path) {
        if op.kind == kind && op.params_digest == digest {
            // The barrier keys on (kind, digest, nonce): the nonce is
            // inside every approval signature, so tampering with it
            // invalidates the entries, while a verbatim restoration keeps
            // it and dies on sight. Fresh asks mint distinct nonces, so
            // legitimate re-asks never match (a raw-byte content hash was
            // malleable: serde ignores whitespace, so a trailing newline
            // changed the hash and slipped the barrier).
            let tomb = serde_json::json!({
                "format": 1,
                "kind": op.kind,
                "params_digest": op.params_digest,
                "nonce": op.nonce,
                "initiated_at": op.initiated_at,
                "initiated_by": op.initiated_by.to_string(),
                "consumed_at": consumed_at,
            });
            let tomb_path = path.with_extension("json.consumed");
            let _ = std::fs::write(&tomb_path, tomb.to_string().as_bytes());
            let _ = std::fs::remove_file(path);
        }
    }
}

/// True when a consumed tombstone matches this exact ask. The tombstone
/// keys on (kind, digest, nonce): restored records die on sight; fresh
/// re-asks mint a new nonce and pass.
fn tombstoned(vault_path: &Path, kind: &str, digest: &str, nonce: &str) -> bool {
    let dir = approvals_dir(vault_path);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("consumed") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if v["format"].as_u64() != Some(1) {
            continue;
        }
        if v["kind"].as_str() == Some(kind)
            && v["params_digest"].as_str() == Some(digest)
            && v["nonce"].as_str() == Some(nonce)
        {
            return true;
        }
    }
    false
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

/// The signature verifier + its ask's nonce, travelling together: the
/// nonce binds every counted entry to one concrete record, and the
/// same nonce is stored on the record a fresh ask mints.
pub struct EntryVerifier<'a> {
    pub nonce: String,
    pub verify: Box<dyn Fn(&ApprovalEntry) -> bool + 'a>,
}

/// Present a sensitive op at the gate. See the module docs for the
/// flow. `verify` carries the acting admin's pre-verified entry check
/// (the caller has already verified the member row is an admin and
/// signed with the member identity key over the ask's nonce) and the
/// ask's nonce; entries failing the check are dropped and never
/// counted, so a hand-written record cannot forge a yes.
pub fn present(
    vault_path: &Path,
    kind: &str,
    params: &serde_json::Value,
    entry: ApprovalEntry,
    required: u8,
    now: u64,
    verify: &EntryVerifier,
) -> ApprovalOutcome {
    let digest = op_digest(kind, params);
    // Same ask already on record? Append (or short-circuit).
    let existing = list_pending(vault_path)
        .into_iter()
        .find(|op| op.kind == kind && op.params_digest == digest);
    if let Some(mut op) = existing {
        // A consumed tombstone for this exact ask (kind + digest + nonce)
        // means the on-disk record is a git-history restoration (the
        // consumption deleted it once already): delete it again and
        // refuse.
        let record_nonce = op.nonce.clone().unwrap_or_default();
        if tombstoned(vault_path, kind, &digest, &record_nonce) {
            remove_matching(vault_path, kind, &digest);
            return ApprovalOutcome::Consumed;
        }
        // A stale ask is no longer confirmable: consume it and treat
        // this call as a fresh ask (the confirming admin re-raises).
        // The ask timestamp is inside the signed message, so a stale
        // signature harvested from git history cannot be replayed onto
        // a fresh ask either way.
        if now.saturating_sub(op.initiated_at) >= APPROVAL_STALE_SECS {
            remove_matching(vault_path, kind, &digest);
            return fresh_ask(
                vault_path,
                kind,
                params,
                entry,
                required,
                now,
                digest,
                &verify.nonce,
            );
        }
        // Drop entries whose signature does not verify (a forged or
        // torn record cannot approve anything), then dedupe by member:
        // duplicated valid entries count once.
        op.approvals.retain(|e| (verify.verify)(e));
        let mut seen = std::collections::HashSet::new();
        op.approvals.retain(|e| seen.insert(e.member));
        if op.approvals.iter().any(|e| e.member == entry.member) {
            return ApprovalOutcome::AlreadyApproved;
        }
        op.approvals.push(entry);
        // The LIVE threshold always governs: a record minted under a
        // different knob (or a tampered `required` on either side)
        // never approves below or above what the settings demand now.
        let effective = required;
        if op.approvals.len() >= effective as usize {
            remove_matching(vault_path, kind, &digest);
            return ApprovalOutcome::Approved;
        }
        op.required = effective;
        let _ = write_record(vault_path, &op);
        return ApprovalOutcome::Pending;
    }
    fresh_ask(
        vault_path,
        kind,
        params,
        entry,
        required,
        now,
        digest,
        &verify.nonce,
    )
}

/// Fresh ask (or a stale record of the same kind — the newest ask
/// replaces it because stale records carry a different digest and
/// simply stop matching; nothing inherits old approvals). The caller
/// minted `nonce` for this ask and signed its entry over it.
#[allow(clippy::too_many_arguments)]
fn fresh_ask(
    vault_path: &Path,
    kind: &str,
    params: &serde_json::Value,
    entry: ApprovalEntry,
    required: u8,
    now: u64,
    digest: String,
    nonce: &str,
) -> ApprovalOutcome {
    let op = PendingOp {
        format: 2,
        kind: kind.to_string(),
        params_digest: digest,
        initiated_by: entry.member,
        initiated_at: now,
        required: required.clamp(2, MAX_QUORUM),
        approvals: vec![entry],
        params: Some(params.clone()),
        nonce: Some(nonce.to_string()),
    };
    let _ = write_record(vault_path, &op);
    ApprovalOutcome::Pending
}

/// Remove a pending record after the op ran through another path or
/// was superseded. Missing file = nothing to do.
pub fn consume_matching(vault_path: &Path, kind: &str, params: &serde_json::Value) {
    let digest = op_digest(kind, params);
    remove_matching(vault_path, kind, &digest);
}

/// Remove every pending record of `kind` whose digest differs from
/// `keep_digest` — a fresh ask supersedes older asks of the same kind
/// (a new transfer target invalidates the old one).
pub fn consume_other_of_kind(vault_path: &Path, kind: &str, keep_digest: &str) {
    let consumed_at = crate::vault::collections::now_secs_pub();
    for (path, op) in list_pending_paths(vault_path) {
        if op.kind == kind && op.params_digest != keep_digest {
            // Same tombstone discipline as remove_matching: a superseded
            // ask restored from git history must die on sight too.
            let tomb = serde_json::json!({
                "format": 1,
                "kind": op.kind,
                "params_digest": op.params_digest,
                "nonce": op.nonce,
                "initiated_at": op.initiated_at,
                "initiated_by": op.initiated_by.to_string(),
                "consumed_at": consumed_at,
            });
            let tomb_path = path.with_extension("json.consumed");
            let _ = std::fs::write(&tomb_path, tomb.to_string().as_bytes());
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(n: u64) -> serde_json::Value {
        serde_json::json!({ "n": n })
    }

    /// A test member: member id plus the identity key that signs its
    /// approvals.
    fn member_key() -> (Uuid, ed25519_dalek::SigningKey) {
        (
            Uuid::new_v4(),
            crate::crypto::signature::generate_ed25519_keypair().0,
        )
    }

    /// Fixed vault id and ask timestamp for message construction: the
    /// store tests exercise signature binding, and both signer and
    /// verifier build the same message.
    const VAULT: Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000001");
    const TS: u64 = 1_700_000_000;
    /// The one test nonce: fresh asks and their confirmations must sign
    /// (and verify) the same ask's nonce, mirroring the gate's mint-and-
    /// resolve flow.
    const NONCE: &str = "test-nonce";

    fn signed_entry(
        key: &ed25519_dalek::SigningKey,
        member: Uuid,
        kind: &str,
        digest: &str,
    ) -> ApprovalEntry {
        let sig =
            crate::crypto::signature::sign(key, &approval_message(kind, digest, VAULT, TS, NONCE))
                .unwrap();
        ApprovalEntry {
            member,
            sig: hex::encode(sig.to_bytes()),
        }
    }

    /// Verifier over the given member keys for one concrete ask, as the
    /// context struct present consumes (nonce travels with the closure,
    /// mirroring the gate's construction).
    fn verifier<'a>(
        members: &'a [(Uuid, ed25519_dalek::SigningKey)],
        kind: &'static str,
        digest: &'a str,
    ) -> crate::vault::approvals::EntryVerifier<'a> {
        crate::vault::approvals::EntryVerifier {
            nonce: NONCE.to_string(),
            verify: Box::new(move |e| {
                let Some((_, key)) = members.iter().find(|(m, _)| *m == e.member) else {
                    return false;
                };
                let Ok(sig_bytes) = hex::decode(&e.sig) else {
                    return false;
                };
                let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
                    return false;
                };
                crate::crypto::signature::verify(
                    &key.verifying_key(),
                    &approval_message(kind, digest, VAULT, TS, NONCE),
                    &ed25519_dalek::Signature::from_bytes(&arr),
                )
                .is_ok()
            }),
        }
    }

    #[test]
    fn two_phase_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        let (b, b_key) = member_key();
        let members = vec![(a, a_key.clone()), (b, b_key.clone())];
        let digest = op_digest("op", &params(1));

        // Threshold 2: first admin raises the ask.
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        // Same admin again: cannot self-confirm.
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &digest),
                2,
                101,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::AlreadyApproved
        );
        // Second admin confirms: approved, record consumed.
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&b_key, b, "op", &digest),
                2,
                102,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Approved
        );
        assert!(list_pending(path).is_empty());
    }

    #[test]
    fn changed_params_do_not_inherit_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        let (b, b_key) = member_key();
        let d1 = op_digest("op", &params(1));
        let d2 = op_digest("op", &params(2));
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &d1),
                2,
                100,
                &verifier(&[(a, a_key.clone())], "op", &d1)
            ),
            ApprovalOutcome::Pending
        );
        // A different ask of the same kind: fresh record, no carry-over.
        assert_eq!(
            present(
                path,
                "op",
                &params(2),
                signed_entry(&b_key, b, "op", &d2),
                2,
                101,
                &verifier(&[(b, b_key)], "op", &d2)
            ),
            ApprovalOutcome::Pending
        );
        // The original ask still stands with its one approval.
        let rows = list_pending(path);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.params_digest == d1
            && r.approvals.len() == 1
            && r.approvals[0].member == a));
    }

    /// 2026-10-01 review: a consumed record restored from git history
    /// must hit the tombstone barrier and die on sight — never re-execute
    /// within the staleness window (quorum_lower would defeat the
    /// ratchet; rotate_root_key has empty params).
    #[test]
    fn consumed_ask_restored_from_history_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        let (b, b_key) = member_key();
        let (c, c_key) = member_key();
        let members = vec![(a, a_key.clone()), (b, b_key.clone()), (c, c_key.clone())];
        let digest = op_digest("op", &params(1));
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        let record_path = path.join(APPROVALS_DIR).join(format!(
            "{}-{}.json",
            digest,
            &a.simple().to_string()[..8]
        ));
        let record_bytes = std::fs::read(&record_path).unwrap();
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&b_key, b, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Approved
        );
        // Consumption deleted the record and left exactly one tombstone.
        let tombstones: Vec<_> = std::fs::read_dir(path.join(APPROVALS_DIR))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("consumed"))
            .collect();
        assert_eq!(tombstones.len(), 1);
        // Replay: restore the consumed record verbatim from "history".
        std::fs::write(&record_path, &record_bytes).unwrap();
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&c_key, c, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Consumed
        );
        // The restored record died again on sight.
        assert!(list_pending(path).is_empty());
        // A fresh ask with different params is unaffected.
        let d2 = op_digest("op", &params(2));
        assert_eq!(
            present(
                path,
                "op",
                &params(2),
                signed_entry(&a_key, a, "op", &d2),
                2,
                100,
                &verifier(&members, "op", &d2)
            ),
            ApprovalOutcome::Pending
        );
    }

    #[test]
    fn raised_threshold_demands_more_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        let (b, b_key) = member_key();
        let (c, c_key) = member_key();
        let members = vec![(a, a_key.clone()), (b, b_key.clone()), (c, c_key.clone())];
        let digest = op_digest("op", &params(1));
        let hostile_path = |rows: &[PendingOp]| {
            path.join(APPROVALS_DIR).join(format!(
                "{}-{}.json",
                rows[0].params_digest,
                &rows[0].initiated_by.simple().to_string()[..8]
            ))
        };
        // Record minted under threshold 2: one real approval so far.
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        // Hostile on-disk edit lowers the record's `required` to 1.
        // The LIVE knob is 3, so b's single real signature must not
        // approve: the live threshold always governs.
        let rows = list_pending(path);
        assert_eq!(rows.len(), 1);
        let mut hostile = rows[0].clone();
        hostile.required = 1;
        let _ = std::fs::write(hostile_path(&rows), serde_json::to_vec(&hostile).unwrap());
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&b_key, b, "op", &digest),
                3,
                101,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        // The record now carries the raised bar.
        assert_eq!(list_pending(path)[0].required, 3);
        // Tampering UP cannot brick the ask either: the live knob
        // governs exactly, so the ask completes at the configured bar.
        let rows = list_pending(path);
        let mut hostile = rows[0].clone();
        hostile.required = 255;
        let _ = std::fs::write(hostile_path(&rows), serde_json::to_vec(&hostile).unwrap());
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&c_key, c, "op", &digest),
                2,
                102,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Approved
        );
        assert!(list_pending(path).is_empty());
    }

    /// Duplicated valid entries count once: a hostile record repeating
    /// one admin's approval cannot inflate the count.
    #[test]
    fn duplicate_entries_count_once() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        let (b, b_key) = member_key();
        let members = vec![(a, a_key.clone()), (b, b_key.clone())];
        let digest = op_digest("op", &params(1));
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        // Hostile rewrite: the same valid entry three times.
        let rows = list_pending(path);
        let mut hostile = rows[0].clone();
        let entry = hostile.approvals[0].clone();
        hostile.approvals = vec![entry.clone(), entry.clone(), entry];
        let _ = std::fs::write(
            path.join(APPROVALS_DIR).join(format!(
                "{}-{}.json",
                hostile.params_digest,
                &hostile.initiated_by.simple().to_string()[..8]
            )),
            serde_json::to_vec(&hostile).unwrap(),
        );
        // b's real approval makes TWO distinct admins, not four: at
        // threshold 5 the ask stays pending, and the record on disk
        // carries the deduped set.
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&b_key, b, "op", &digest),
                5,
                101,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        let rows = list_pending(path);
        assert_eq!(rows[0].approvals.len(), 2);
        assert_eq!(rows[0].approvals[0].member, a);
        assert_eq!(rows[0].approvals[1].member, b);
    }

    /// A stale ask is no longer confirmable: the confirming call
    /// consumes it and re-raises as a fresh ask (a signature over the
    /// old ask timestamp cannot ride along).
    #[test]
    fn stale_ask_is_consumed_and_reraised_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &op_digest("op", &params(1))),
                2,
                TS,
                &verifier(&[(a, a_key.clone())], "op", &op_digest("op", &params(1)))
            ),
            ApprovalOutcome::Pending
        );
        let later = TS + APPROVAL_STALE_SECS;
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &op_digest("op", &params(1))),
                2,
                later,
                &verifier(&[(a, a_key)], "op", &op_digest("op", &params(1)))
            ),
            ApprovalOutcome::Pending
        );
        let rows = list_pending(path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].initiated_at, later, "the ask restarted fresh");
    }

    /// A hand-written record cannot forge a yes: an entry whose
    /// signature does not verify is dropped, never counted, and the
    /// record self-heals on the next touch.
    #[test]
    fn forged_signature_is_dropped_and_never_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let (a, a_key) = member_key();
        let (b, b_key) = member_key();
        let members = vec![(a, a_key.clone()), (b, b_key.clone())];
        let digest = op_digest("op", &params(1));
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&a_key, a, "op", &digest),
                2,
                100,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        // Hostile rewrite: keep the member ids, replace a's signature
        // with a valid-looking but wrong one (signed by b's key).
        let rows = list_pending(path);
        let mut hostile = rows[0].clone();
        hostile.approvals[0].sig = hex::encode(
            crate::crypto::signature::sign(
                &b_key,
                &approval_message("op", &digest, VAULT, TS, NONCE),
            )
            .unwrap()
            .to_bytes(),
        );
        let _ = std::fs::write(
            path.join(APPROVALS_DIR).join(format!(
                "{}-{}.json",
                hostile.params_digest,
                &hostile.initiated_by.simple().to_string()[..8]
            )),
            serde_json::to_vec(&hostile).unwrap(),
        );
        // b's real approval counts only itself: the forged entry drops.
        assert_eq!(
            present(
                path,
                "op",
                &params(1),
                signed_entry(&b_key, b, "op", &digest),
                2,
                101,
                &verifier(&members, "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        // The record self-healed: only b's real entry remains.
        let rows = list_pending(path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].approvals.len(), 1);
        assert_eq!(rows[0].approvals[0].member, b);
    }

    #[test]
    fn listing_skips_malformed_and_caps() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path();
        let dir = path.join(APPROVALS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("junk.json"), b"not json").unwrap();
        std::fs::write(dir.join("note.txt"), b"ignored").unwrap();
        let (m, m_key) = member_key();
        let digest = op_digest("op", &params(7));
        assert_eq!(
            present(
                path,
                "op",
                &params(7),
                signed_entry(&m_key, m, "op", &digest),
                2,
                100,
                &verifier(&[(m, m_key)], "op", &digest)
            ),
            ApprovalOutcome::Pending
        );
        let rows = list_pending(path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "op");
        consume_matching(path, "op", &params(7));
        assert!(list_pending(path).is_empty());
    }
}
