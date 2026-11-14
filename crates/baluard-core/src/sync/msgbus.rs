//! Advisory message bus on the notes ref `refs/notes/baluard-msgs`
//! (standard: ADR 0107; constants and activation record: ADR 0109).
//!
//! The board is a flat, append-mostly line of signed commits under a
//! third notes ref, deliberately separate from gossip (deny-only
//! security signals) and the attachments line (bulk content transport).
//! Tree layout is frozen for all versions: `msgs/<topic>/<at>-<id>.json`,
//! so any version can prune and cap by path alone without parsing
//! bodies. Entries carry a versioned envelope (`baluard-msgs/v1`) whose
//! `id` is the SHA-256 of the canonical envelope minus `id` and `sig`,
//! computed over the parsed generic document so unknown future fields
//! stay covered, and whose `sig` is a hygiene ed25519 signature by the
//! device's commit-signing key over a domain-separated digest of `id`.
//!
//! Advisory only. Entries never admit vault content, never unlock
//! anything, and never direct a device to do work; `main` stays the only
//! existence authority. Merge preserves the unknown (raw entries, no
//! validation); validation happens at consumption. Write-time prune is
//! by path only: non-conforming paths, out-of-window timestamps, then
//! the oldest above the per-topic and total caps. Board compaction is
//! the only force-replace: a commit parented on the vault root holding
//! the pruned union plus one `cleanup.board-compacted` message.

use sha2::{Digest, Sha256};

use super::engine::SyncEngine;
use crate::error::{BaluardError, SyncError};

/// The advisory channel: a ref under refs/notes, invisible to the forge
/// branch and tag lists.
pub const MSGS_REF: &str = "refs/notes/baluard-msgs";

/// Tracking-ref short name under refs/remotes/<remote>/.
pub const MSGS_TRACKING: &str = "msgs";

/// The only envelope version this reader understands. Unknown versions
/// are skipped; forward compatibility is new types, never new refs.
pub const ENVELOPE_V: u64 = 1;

/// Domain separation prefix for per-message signatures: a signature
/// over this context plus a zero byte plus the raw digest of `id` cannot
/// replay in any other context.
pub const SIGN_CONTEXT: &[u8] = b"baluard-msgs-v1";

/// Entries older than this are dropped by reader and pruner (ADR 0109).
pub const MSG_TTL_SECS: u64 = 30 * 24 * 3600;

/// Entries dated further in the future than this are dropped (ADR 0109).
pub const CLOCK_SKEW_SECS: u64 = 24 * 3600;

/// Write-time prune keeps at most this many entries per topic (ADR 0109).
pub const PER_TOPIC_CAP: usize = 50;

/// Write-time prune target; also the compaction low watermark, so a
/// compacted board plus one cleanup message cannot retrigger compaction
/// at rest (ADR 0109).
pub const CAP_TOTAL: usize = 200;

/// Reader ceiling and compaction trigger; greater than `cap_total` plus
/// one, per the standard (ADR 0109).
pub const HARD_CAP: usize = 256;

/// Compaction also triggers when the board's first-parent chain exceeds
/// this many commits (ADR 0109).
pub const MAX_CHAIN: u64 = 128;

/// Parse-time size limit per entry; larger blobs are skipped unread.
pub const MAX_MSG_BYTES: usize = 16 * 1024;

/// JSON nesting limit for a message body; deeper bodies are skipped.
pub const MAX_BODY_DEPTH: usize = 8;

/// A message a consumer wants to publish. The envelope (`v`, `from`,
/// `at`, `id`, `sig`) is filled by the module; the body must carry
/// numeric and enum fields only, never prose a UI would copy.
pub struct MsgOut {
    pub r#type: String,
    pub body: serde_json::Value,
}

/// The board's own self-describing compaction message (ADR 0107).
pub const BOARD_COMPACTED_TYPE: &str = "cleanup.board-compacted";

/// Dot-separated type's first segment: the topic. `None` when any
/// segment leaves `[a-z0-9-]` or is empty.
pub fn topic_of(msg_type: &str) -> Option<&str> {
    let first = msg_type.split('.').next()?;
    if first.is_empty() || msg_type.is_empty() {
        return None;
    }
    for seg in msg_type.split('.') {
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
    }
    Some(first)
}

/// Path conformance, checked without reading any body: exactly
/// `msgs/<topic>/<decimal at>-<64 hex id>.json`. Returns the parsed
/// `(topic, at, id)`.
pub fn path_is_conforming(path: &str) -> Option<(String, u64, String)> {
    let mut segs = path.split('/');
    let a = segs.next()?;
    let topic = segs.next()?;
    let file = segs.next()?;
    if segs.next().is_some() || a != "msgs" {
        return None;
    }
    if topic.is_empty()
        || !topic
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    let stem = file.strip_suffix(".json")?;
    let (at_s, id) = stem.split_once('-')?;
    let at: u64 = at_s.parse().ok()?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b.is_ascii_hexdigit())
    {
        return None;
    }
    Some((topic.to_string(), at, id.to_string()))
}

/// Canonical JSON per ADR 0107: UTF-8, keys sorted by byte order, no
/// insignificant whitespace, integers only within plus or minus 2^53
/// minus 1, no floats. serde_json's map preserves insertion order in
/// this build, so keys are sorted explicitly.
pub fn canonical(value: &serde_json::Value) -> Result<String, BaluardError> {
    let mut out = String::new();
    write_canonical(value, &mut out, 0)?;
    Ok(out)
}

fn write_canonical(
    value: &serde_json::Value,
    out: &mut String,
    depth: usize,
) -> Result<(), BaluardError> {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(SyncError::Git("message body carries a float".into()).into());
            }
            let as_f = n.as_f64().unwrap_or(f64::INFINITY);
            if as_f.abs() > 9_007_199_254_740_991.0 {
                return Err(
                    SyncError::Git("message integer exceeds the 2^53-1 envelope".into()).into(),
                );
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            let quoted = serde_json::to_string(s)
                .map_err(|e| SyncError::Git(format!("message string: {e}")))?;
            out.push_str(&quoted);
        }
        Value::Array(items) => {
            if depth >= MAX_BODY_DEPTH {
                return Err(SyncError::Git("message body nesting too deep".into()).into());
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            if depth >= MAX_BODY_DEPTH {
                return Err(SyncError::Git("message body nesting too deep".into()).into());
            }
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let quoted = serde_json::to_string(k)
                    .map_err(|e| SyncError::Git(format!("message key: {e}")))?;
                out.push_str(&quoted);
                out.push(':');
                write_canonical(&map[*k], out, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Max nesting depth of a parsed value (objects and arrays count).
pub fn value_depth(value: &serde_json::Value) -> usize {
    use serde_json::Value;
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 1,
        Value::Array(items) => 1 + items.iter().map(value_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(value_depth).max().unwrap_or(0),
    }
}

/// The id of an envelope: lowercase hex SHA-256 over the canonical form
/// of the parsed document with `id` and `sig` excluded. The hash covers
/// unknown top-level fields, so no one can strip them.
pub fn message_id(envelope: &serde_json::Value) -> Result<String, BaluardError> {
    let mut doc = envelope
        .as_object()
        .ok_or_else(|| SyncError::Git("envelope is not an object".into()))?
        .clone();
    doc.remove("id");
    doc.remove("sig");
    let digest = Sha256::digest(canonical(&serde_json::Value::Object(doc))?.as_bytes());
    Ok(hex::encode(digest))
}

/// Signature input: the context string, a zero byte, and the 32 raw
/// SHA-256 digest bytes of the id (ADR 0107 round three pins this
/// encoding explicitly).
pub fn signing_payload(id_hex: &str) -> Vec<u8> {
    let mut payload = SIGN_CONTEXT.to_vec();
    payload.push(0u8);
    payload.extend_from_slice(&Sha256::digest(id_hex.as_bytes()));
    payload
}

/// Verify a lowercase-hex ed25519 message signature against a roster.
/// Any rostered key may sign for any device; the deny-only advisory
/// contract is what keeps that safe.
pub fn verify_message_sig(
    roster: &std::collections::BTreeMap<String, [u8; 32]>,
    id_hex: &str,
    sig_hex: &str,
) -> bool {
    use crate::crypto::signature::verify;
    use ed25519_dalek::Signature;
    let Ok(raw) = hex::decode(sig_hex) else {
        return false;
    };
    let Some(raw32): Option<[u8; 64]> = raw.as_slice().try_into().ok() else {
        return false;
    };
    let sig = Signature::from_bytes(&raw32);
    let payload = signing_payload(id_hex);
    roster.values().any(|vk| {
        crate::crypto::signature::verifying_key_from_bytes(vk)
            .map(|vk| verify(&vk, &payload, &sig).is_ok())
            .unwrap_or(false)
    })
}

/// Build a complete v1 envelope (including `id` and `sig`) for one
/// outgoing message. Fails when the body carries floats or oversized
/// integers — bodies are numeric and enum fields only.
pub fn build_envelope(
    signing_key: &ed25519_dalek::SigningKey,
    from_device: &str,
    at: u64,
    out: &MsgOut,
) -> Result<serde_json::Value, BaluardError> {
    let Some(topic) = topic_of(&out.r#type) else {
        return Err(SyncError::Git(format!(
            "message type {:?} is not a dot-separated [a-z0-9-] form",
            out.r#type
        ))
        .into());
    };
    let _ = topic;
    use serde_json::Value;
    let mut envelope = serde_json::Map::new();
    envelope.insert("v".into(), Value::from(ENVELOPE_V));
    envelope.insert("type".into(), Value::from(out.r#type.clone()));
    envelope.insert("from".into(), Value::from(from_device.to_string()));
    envelope.insert("at".into(), Value::from(at));
    envelope.insert("body".into(), out.body.clone());
    let base = Value::Object(envelope);
    let id = message_id(&base)?;
    let sig = crate::crypto::signature::sign(signing_key, &signing_payload(&id))
        .map_err(|e| SyncError::Git(format!("message sign: {e}")))?;
    let mut full = base.as_object().expect("built from a map").clone();
    full.insert("id".into(), Value::from(id.clone()));
    full.insert("sig".into(), Value::from(hex::encode(sig.to_bytes())));
    Ok(Value::Object(full))
}

/// Write-time prune, by path only (ADR 0107): drop non-conforming
/// paths, drop entries outside the time window, then keep the newest
/// `PER_TOPIC_CAP` per topic and the newest `CAP_TOTAL` overall (ties
/// break on id; the sort is (at desc, id asc) so "newest" is
/// deterministic without reading any body).
pub fn prune_entries(entries: &[(String, git2::Oid)], now: u64) -> Vec<(String, git2::Oid)> {
    let mut kept: Vec<(String, u64, String, git2::Oid)> = Vec::new();
    for (path, oid) in entries {
        let Some((topic, at, id)) = path_is_conforming(path) else {
            continue;
        };
        if at + MSG_TTL_SECS < now || at > now.saturating_add(CLOCK_SKEW_SECS) {
            continue;
        }
        kept.push((topic, at, id, *oid));
    }
    // Newest first: at desc, then id asc for determinism.
    kept.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
    let mut per_topic: std::collections::HashMap<String, usize> = Default::default();
    let mut out = Vec::new();
    for (topic, at, id, oid) in kept {
        let n = per_topic.entry(topic.clone()).or_insert(0);
        if *n >= PER_TOPIC_CAP {
            continue;
        }
        *n += 1;
        out.push((format!("msgs/{topic}/{at}-{id}.json"), oid));
    }
    if out.len() > CAP_TOTAL {
        out.truncate(CAP_TOTAL);
    }
    out
}

/// A message that passed every validation gate at consumption time.
#[derive(Debug, Clone)]
pub struct ValidatedMsg {
    pub path: String,
    pub topic: String,
    pub at: u64,
    pub id: String,
    /// Unauthenticated claim; never rendered as identity.
    pub from: Option<String>,
    pub body: serde_json::Value,
}

/// What the reader concluded about the fetched board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardStatus {
    /// No board ref exists yet.
    Empty,
    /// The tip is rooted on a different vault; the board is ignored.
    Foreign,
    /// More conforming entries than `HARD_CAP`; the board is ignored
    /// whole and the consumer uses its non-message fallback.
    OverHardCap,
    /// Readable.
    Ready,
}

#[derive(Debug, Clone)]
pub struct Board {
    pub status: BoardStatus,
    pub tip: Option<String>,
    pub msgs: Vec<ValidatedMsg>,
}

/// Validate and read a fetched board tip against a roster. The
/// root-of-history check is the only history walk; the tip tree is the
/// only thing read.
pub fn read_board_tree<'r>(
    repo: &'r git2::Repository,
    vault_root_hex: &str,
    roster: &std::collections::BTreeMap<String, [u8; 32]>,
    tip: Option<&git2::Commit<'r>>,
    now: u64,
) -> Result<Board, BaluardError> {
    let Some(commit) = tip else {
        return Ok(Board {
            status: BoardStatus::Empty,
            tip: None,
            msgs: Vec::new(),
        });
    };
    let tip_hex = commit.id().to_string();
    let ours = SyncEngine::root_commit_oid_from(repo, commit.id())
        .map(|r| r == vault_root_hex)
        .unwrap_or(false);
    if !ours {
        return Ok(Board {
            status: BoardStatus::Foreign,
            tip: Some(tip_hex),
            msgs: Vec::new(),
        });
    }
    let tree = commit
        .tree()
        .map_err(|e| SyncError::Git(format!("board tree: {e}")))?;
    // Layout: msgs/<topic>/<at>-<id>.json — two levels of subtree under
    // the board root (git tree entries cannot nest in one level).
    let mut entries: Vec<(String, git2::Oid)> = Vec::new();
    if let Ok(sub_entry) = tree.get_path(std::path::Path::new("msgs")) {
        if sub_entry.kind() == Some(git2::ObjectType::Tree) {
            let sub = repo
                .find_tree(sub_entry.id())
                .map_err(|e| SyncError::Git(format!("board subtree: {e}")))?;
            for topic_entry in sub.iter() {
                let Some(topic_name) = topic_entry.name() else {
                    continue;
                };
                if topic_entry.kind() != Some(git2::ObjectType::Tree) {
                    // A blob directly under msgs/ cannot conform.
                    entries.push((format!("msgs/{topic_name}"), topic_entry.id()));
                    continue;
                }
                let topic_tree = repo
                    .find_tree(topic_entry.id())
                    .map_err(|e| SyncError::Git(format!("board topic tree: {e}")))?;
                for leaf in topic_tree.iter() {
                    if leaf.kind() != Some(git2::ObjectType::Blob) {
                        continue;
                    }
                    let Some(name) = leaf.name() else { continue };
                    entries.push((format!("msgs/{topic_name}/{name}"), leaf.id()));
                }
            }
        }
    }
    let conforming = entries
        .iter()
        .filter(|(p, _)| path_is_conforming(p).is_some())
        .count();
    if conforming > HARD_CAP {
        return Ok(Board {
            status: BoardStatus::OverHardCap,
            tip: Some(tip_hex),
            msgs: Vec::new(),
        });
    }
    let mut msgs = Vec::new();
    for (path, oid) in &entries {
        let Some((topic, at, path_id)) = path_is_conforming(path) else {
            continue;
        };
        if at + MSG_TTL_SECS < now || at > now.saturating_add(CLOCK_SKEW_SECS) {
            continue;
        }
        let Ok(blob) = repo.find_blob(*oid) else {
            continue;
        };
        let bytes = blob.content();
        if bytes.len() > MAX_MSG_BYTES {
            continue;
        }
        let Ok(doc) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            continue;
        };
        if value_depth(&doc) > MAX_BODY_DEPTH {
            continue;
        }
        let Some(obj) = doc.as_object() else { continue };
        if obj.get("v").and_then(|v| v.as_u64()) != Some(ENVELOPE_V) {
            continue;
        }
        if obj.contains_key("enc") {
            continue;
        }
        let Some(t) = obj.get("type").and_then(|t| t.as_str()) else {
            continue;
        };
        let Some(msg_topic) = topic_of(t) else {
            continue;
        };
        if msg_topic != topic {
            continue;
        }
        let Some(body_at) = obj.get("at").and_then(|a| a.as_u64()) else {
            continue;
        };
        if body_at != at {
            continue;
        }
        let recomputed = message_id(&doc).unwrap_or_default();
        if recomputed != path_id {
            continue;
        }
        let Some(sig_hex) = obj.get("sig").and_then(|s| s.as_str()) else {
            continue;
        };
        if !verify_message_sig(roster, &recomputed, sig_hex) {
            continue;
        }
        msgs.push(ValidatedMsg {
            path: path.to_string(),
            topic,
            at,
            id: recomputed,
            from: obj.get("from").and_then(|f| f.as_str()).map(String::from),
            body: obj.get("body").cloned().unwrap_or(serde_json::Value::Null),
        });
    }
    Ok(Board {
        status: BoardStatus::Ready,
        tip: Some(tip_hex),
        msgs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ed25519_dalek::SigningKey {
        crate::crypto::signature::generate_ed25519_keypair().0
    }

    fn roster_with(
        key: &ed25519_dalek::SigningKey,
    ) -> std::collections::BTreeMap<String, [u8; 32]> {
        let mut r = std::collections::BTreeMap::new();
        let vk = crate::crypto::signature::verifying_key_bytes(&key.verifying_key());
        r.insert("11111111-1111-1111-1111-111111111111".to_string(), vk);
        r
    }

    fn hex_id(n: u64) -> String {
        format!("{n:064x}")
    }

    fn mk_path(topic: &str, at: u64, id: &str) -> String {
        format!("msgs/{topic}/{at}-{id}.json")
    }

    #[test]
    fn path_conformance_gates() {
        let id = hex_id(0xaa);
        let (t, at, got) = path_is_conforming(&mk_path("cleanup", 1_700_000_000, &id)).unwrap();
        assert_eq!(
            (t.as_str(), at, got.as_str()),
            ("cleanup", 1_700_000_000, id.as_str())
        );
        // Wrong root segment.
        assert!(path_is_conforming(&format!("other/cleanup/1700000000-{id}.json")).is_none());
        // Four segments: path injection via a nested topic.
        assert!(path_is_conforming(&format!("msgs/cleanup/sub/1700000000-{id}.json")).is_none());
        // Topic charset: uppercase, dot, underscore, empty all fail.
        assert!(path_is_conforming(&mk_path("Cleanup", 1, &id)).is_none());
        assert!(path_is_conforming(&mk_path("clea.nup", 1, &id)).is_none());
        assert!(path_is_conforming(&mk_path("clea_nup", 1, &id)).is_none());
        assert!(path_is_conforming(&mk_path("", 1, &id)).is_none());
        // At parses as decimal; id must be 64 hex characters.
        assert!(path_is_conforming(&mk_path("cleanup", 0, &id)).is_some());
        assert!(path_is_conforming(&mk_path("cleanup", 1, &"a".repeat(63))).is_none());
        assert!(path_is_conforming(&mk_path("cleanup", 1, &"A".repeat(64))).is_none());
        assert!(path_is_conforming(&format!("msgs/cleanup/notanum-{id}.json")).is_none());
        // Missing .json suffix.
        assert!(path_is_conforming(&format!("msgs/cleanup/1700000000-{id}")).is_none());
    }

    #[test]
    fn envelope_id_covers_unknown_top_level_fields() {
        let k = key();
        let out = MsgOut {
            r#type: "cleanup.compacted".into(),
            body: serde_json::json!({"kept": 3}),
        };
        let env = build_envelope(&k, "device-a", 1_000, &out).unwrap();
        // The embedded id matches a recompute over the parsed generic
        // document (id and sig excluded), unknown fields included.
        let id = message_id(&env).unwrap();
        assert_eq!(env.get("id").and_then(|v| v.as_str()), Some(id.as_str()));
        // Adding an unknown field changes the id — and a reader that
        // hashes the parsed document still recomputes the same value,
        // so a v2-added field cannot silently break v1 verification.
        let mut extended = env.clone();
        extended
            .as_object_mut()
            .unwrap()
            .insert("future_ext".into(), serde_json::json!(1));
        assert_ne!(message_id(&extended).unwrap(), id);
        assert_eq!(
            env.get("sig").and_then(|v| v.as_str()).map(str::len),
            Some(128)
        );
    }

    #[test]
    fn canonical_form_is_sorted_and_rejects_floats() {
        let v = serde_json::json!({"b": 1, "a": 2, "c": [3, {"z": 4, "y": 5}]});
        assert_eq!(
            canonical(&v).unwrap(),
            r#"{"a":2,"b":1,"c":[3,{"y":5,"z":4}]}"#
        );
        let float = serde_json::json!({"x": 1.5});
        assert!(canonical(&float).is_err(), "floats are banned");
    }

    #[test]
    fn signature_binds_the_id_digest() {
        let k = key();
        let roster = roster_with(&k);
        let out = MsgOut {
            r#type: "cleanup.compacted".into(),
            body: serde_json::json!({"n": 1}),
        };
        let env = build_envelope(&k, "d", 5, &out).unwrap();
        let id = env.get("id").and_then(|v| v.as_str()).unwrap();
        let sig = env.get("sig").and_then(|v| v.as_str()).unwrap();
        assert!(verify_message_sig(&roster, id, sig));
        // A different id breaks the digest binding.
        assert!(!verify_message_sig(&roster, &hex_id(0x01), sig));
        // A key absent from the roster fails.
        assert!(!verify_message_sig(&Default::default(), id, sig));
    }

    #[test]
    fn prune_drops_window_violations_nonconforming_then_caps() {
        let now: u64 = 1_800_000_000;
        let z = git2::Oid::from_str(&"0".repeat(40)).unwrap();
        let mut entries: Vec<(String, git2::Oid)> = vec![
            (mk_path("x", now - 100, &hex_id(1)), z), // kept
            (mk_path("x", now - MSG_TTL_SECS - 1, &hex_id(2)), z), // expired
            (mk_path("x", now + CLOCK_SKEW_SECS + 1, &hex_id(3)), z), // future
            (mk_path("x", now - 50, &hex_id(4)), z),  // kept
            ("msgs/x/junk".to_string(), z),           // non-conforming
            (format!("other/y/{}-{}.json", now - 10, hex_id(5)), z), // wrong root
            (format!("msgs/y/deep/{}-{}.json", now - 10, hex_id(6)), z), // 4 segments
        ];
        // Per-topic cap: 51 in-window "y" entries, oldest dropped.
        for i in 0..51u64 {
            entries.push((mk_path("y", now - 1000 + i, &hex_id(10 + i)), z));
        }
        let kept = prune_entries(&entries, now);
        let paths: Vec<&str> = kept.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains(&hex_id(2))),
            "expired dropped"
        );
        assert!(
            !paths.iter().any(|p| p.contains(&hex_id(3))),
            "future dropped"
        );
        assert!(
            !paths.iter().any(|p| p.ends_with("junk")),
            "non-conforming dropped"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with("other/")),
            "wrong root dropped"
        );
        assert!(
            !paths.iter().any(|p| p.contains(&hex_id(6))),
            "deep path dropped"
        );
        let y_count = paths.iter().filter(|p| p.contains("/y/")).count();
        assert_eq!(y_count, PER_TOPIC_CAP, "per-topic cap holds: {y_count}");
        assert!(
            !paths.iter().any(|p| p.contains(&hex_id(10))),
            "oldest y dropped"
        );
        assert!(
            paths.iter().any(|p| p.contains(&hex_id(1))),
            "in-window kept"
        );
    }

    #[test]
    fn cap_total_truncates_to_the_newest() {
        let now: u64 = 1_800_000_000;
        let z = git2::Oid::from_str(&"0".repeat(40)).unwrap();
        let mut entries = Vec::new();
        // Five topics, none reaching the per-topic cap: the total cap is
        // what must truncate.
        for i in 0..(CAP_TOTAL + 10) as u64 {
            let topic = format!("t{}", i % 5);
            entries.push((mk_path(&topic, now - 5000 + i, &hex_id(i % 255)), z));
        }
        let kept = prune_entries(&entries, now);
        assert_eq!(kept.len(), CAP_TOTAL, "the total cap truncates");
        let newest = hex_id(((CAP_TOTAL + 9) % 255) as u64);
        assert!(
            kept.iter().any(|(p, _)| p.contains(&newest)),
            "the newest survive"
        );
    }

    fn scratch_board<'r>(repo: &'r git2::Repository, entries: &[(&str, &[u8])]) -> git2::Tree<'r> {
        // Callers pass `msgs/<topic>/<file>` or the rest after msgs/;
        // group by topic into subtrees (git tree entries cannot nest in
        // one level). Empty leaf names are skipped.
        let mut topics: std::collections::BTreeMap<&str, Vec<(&str, &[u8])>> = Default::default();
        for (path, body) in entries {
            let rest = path.strip_prefix("msgs/").unwrap_or(path);
            let (topic, file) = rest.split_once('/').unwrap_or((rest, ""));
            if file.is_empty() {
                continue;
            }
            topics.entry(topic).or_default().push((file, *body));
        }
        let mut msgs_tb = repo.treebuilder(None).unwrap();
        for (topic, leaves) in topics {
            let mut topic_tb = repo.treebuilder(None).unwrap();
            for (name, body) in leaves {
                let blob = repo.blob(body).unwrap();
                topic_tb
                    .insert(name, blob, git2::FileMode::Blob.into())
                    .unwrap();
            }
            let id = topic_tb.write().unwrap();
            msgs_tb
                .insert(topic, id, git2::FileMode::Tree.into())
                .unwrap();
        }
        let msgs_id = msgs_tb.write().unwrap();
        let mut root_tb = repo.treebuilder(None).unwrap();
        root_tb
            .insert("msgs", msgs_id, git2::FileMode::Tree.into())
            .unwrap();
        let tree_id = root_tb.write().unwrap();
        repo.find_tree(tree_id).unwrap()
    }

    fn tip_over<'r>(repo: &'r git2::Repository, tree: &git2::Tree<'r>) -> git2::Commit<'r> {
        let sig = git2::Signature::now("t", "t@t").unwrap();
        let oid = repo.commit(None, &sig, &sig, "board", tree, &[]).unwrap();
        repo.find_commit(oid).unwrap()
    }

    fn good_envelope(
        k: &ed25519_dalek::SigningKey,
        typ: &str,
        at: u64,
        n: u64,
    ) -> (String, Vec<u8>) {
        let out = MsgOut {
            r#type: typ.into(),
            body: serde_json::json!({"n": n}),
        };
        let env = build_envelope(k, "device-a", at, &out).unwrap();
        let id = message_id(&env).unwrap();
        let path = mk_path(topic_of(typ).unwrap(), at, &id);
        (path, serde_json::to_vec(&env).unwrap())
    }

    #[test]
    fn reader_skips_mismatched_and_forged_entries() {
        let k = key();
        let roster = roster_with(&k);
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let now: u64 = 1_800_000_000;

        let (good_path, good_bytes) = good_envelope(&k, "cleanup.compacted", now - 60, 1);
        // Topic mismatch: type says other.thing, path says cleanup.
        let (wrong_topic_path, wrong_topic_bytes) = good_envelope(&k, "other.thing", now - 61, 2);
        let wrong_topic_path = wrong_topic_path.replacen("/other/", "/cleanup/", 1);
        // At mismatch: body at disagrees with the path at.
        let (at_mismatch_path, at_mismatch_bytes) =
            good_envelope(&k, "cleanup.compacted", now - 62, 3);
        let at_mismatch_path = at_mismatch_path.replacen(
            &format!("msgs/cleanup/{}-", now - 62),
            &format!("msgs/cleanup/{}-", now - 63),
            1,
        );
        // Id mismatch: re-sign a clean envelope, then tamper the body so
        // the recomputed hash no longer matches the path id.
        let (tamper_path, tamper_bytes) = good_envelope(&k, "cleanup.compacted", now - 64, 4);
        let mut tampered: serde_json::Value = serde_json::from_slice(&tamper_bytes).unwrap();
        tampered.as_object_mut().unwrap()["body"]["n"] = serde_json::json!(999);
        let tamper_bytes = serde_json::to_vec(&tampered).unwrap();
        // v2 envelope: skipped.
        let mut v2 = serde_json::from_slice::<serde_json::Value>(&good_bytes).unwrap();
        v2.as_object_mut()
            .unwrap()
            .insert("v".into(), serde_json::json!(2));
        let (v2_path, _) = good_envelope(&k, "cleanup.compacted", now - 65, 5);
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        // Enc-boxed body: a v1 reader skips it.
        let mut enc = serde_json::from_slice::<serde_json::Value>(&good_bytes).unwrap();
        enc.as_object_mut()
            .unwrap()
            .insert("enc".into(), serde_json::json!("box"));
        let enc_bytes = serde_json::to_vec(&enc).unwrap();
        let (enc_path, _) = good_envelope(&k, "cleanup.compacted", now - 66, 6);
        // Oversized body.
        let (big_path, _) = good_envelope(&k, "cleanup.compacted", now - 67, 7);
        let big_bytes = vec![b'x'; MAX_MSG_BYTES + 1];
        // Deeply nested body.
        let mut deep = String::from("{\"n\":");
        for _ in 0..(MAX_BODY_DEPTH + 2) {
            deep.push('{');
        }
        deep.push('}');
        for _ in 0..(MAX_BODY_DEPTH + 2) {
            deep.push('}');
        }
        let (deep_path, _) = good_envelope(&k, "cleanup.compacted", now - 68, 8);
        let deep_bytes = deep.into_bytes();

        let tree = scratch_board(
            &repo,
            &[
                (good_path.trim_start_matches("msgs/"), &good_bytes),
                (
                    wrong_topic_path.trim_start_matches("msgs/"),
                    &wrong_topic_bytes,
                ),
                (
                    at_mismatch_path.trim_start_matches("msgs/"),
                    &at_mismatch_bytes,
                ),
                (tamper_path.trim_start_matches("msgs/"), &tamper_bytes),
                (v2_path.trim_start_matches("msgs/"), &v2_bytes),
                (enc_path.trim_start_matches("msgs/"), &enc_bytes),
                (big_path.trim_start_matches("msgs/"), &big_bytes),
                (deep_path.trim_start_matches("msgs/"), &deep_bytes),
            ],
        );
        let tip = tip_over(&repo, &tree);
        let root = SyncEngine::root_commit_oid_from(&repo, tip.id()).unwrap();
        let board = read_board_tree(&repo, &root, &roster, Some(&tip), now).unwrap();
        assert_eq!(board.status, BoardStatus::Ready);
        assert_eq!(
            board.msgs.len(),
            1,
            "only the well-formed entry survives: {:?}",
            board.msgs
        );
        assert_eq!(board.msgs[0].body, serde_json::json!({"n": 1}));
        assert_eq!(board.msgs[0].topic, "cleanup");
    }

    #[test]
    fn removed_roster_key_fails_verification() {
        let k = key();
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let now: u64 = 1_800_000_000;
        let (path, bytes) = good_envelope(&k, "cleanup.compacted", now - 60, 9);
        let tree = scratch_board(&repo, &[(path.trim_start_matches("msgs/"), &bytes)]);
        let tip = tip_over(&repo, &tree);
        let root = SyncEngine::root_commit_oid_from(&repo, tip.id()).unwrap();
        let board = read_board_tree(&repo, &root, &Default::default(), Some(&tip), now).unwrap();
        assert_eq!(board.status, BoardStatus::Ready);
        assert!(board.msgs.is_empty(), "a key removed from the roster fails");
    }

    #[test]
    fn reader_limit_holds_on_a_flooded_board() {
        let k = key();
        let roster = roster_with(&k);
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let now: u64 = 1_800_000_000;
        let mut entries = Vec::new();
        for i in 0..(HARD_CAP as u64 + 1) {
            let (p, b) = good_envelope(&k, "cleanup.compacted", now - 60 - i, i);
            entries.push((p.trim_start_matches("msgs/").to_string(), b));
        }
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(p, b)| (p.as_str(), b.as_slice()))
            .collect();
        let tree = scratch_board(&repo, &refs);
        let tip = tip_over(&repo, &tree);
        let root = SyncEngine::root_commit_oid_from(&repo, tip.id()).unwrap();
        let board = read_board_tree(&repo, &root, &roster, Some(&tip), now).unwrap();
        assert_eq!(board.status, BoardStatus::OverHardCap);
        assert!(
            board.msgs.is_empty(),
            "a board over hard_cap is ignored whole"
        );
    }
}
