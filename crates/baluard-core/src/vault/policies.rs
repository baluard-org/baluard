//! Advisory org policies (S4-6, plan-power-pack §5).
//!
//! A Space owner publishes RECOMMENDED settings as a plaintext
//! `meta/policies.json` riding the meta/** Admin row (same shape logic
//! as the S3-6 catalog: the file's existence is the setting, an empty
//! publish removes it as the opt-out). Advisory only — nothing here is
//! enforced; the shipped §6.5 knobs keep their own gates. Member
//! surfaces read the file keylessly and render a "recommended" hint
//! next to matching settings.
//!
//! Values are validated fail-closed against the known knob table so a
//! typo cannot ship a recommendation no surface can render, and so the
//! file can never smuggle an unknown knob name.

use crate::error::{BaluardError, VaultError};
use serde_json::{Map, Value, json};
use std::path::Path;

pub const POLICIES_PATH: &str = "meta/policies.json";
const MAX_POLICIES_BYTES: usize = 64 * 1024;
const POLICIES_PURPOSE: &str = "space-policies-v1";

/// Validate one knob value against the shipped §6.5 table. Canonical
/// (wire) spellings only — the same strings space_settings_get emits,
/// so surfaces can compare directly.
fn validate_value(key: &str, value: &Value) -> Result<(), BaluardError> {
    let bad = |msg: &str| BaluardError::from(VaultError::InvalidOperation(msg.into()));
    match key {
        "space_invite_authority" => match value.as_str() {
            Some("admins") | Some("owners") => Ok(()),
            _ => Err(bad("space_invite_authority must be admins or owners")),
        },
        "allow_viewer_export" | "guest_enabled" => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err(bad(&format!("{key} must be a boolean")))
            }
        }
        "trash_policy" => match value.as_str() {
            Some("write_scope_can_trash") | Some("admins_only") => Ok(()),
            _ => Err(bad(
                "trash_policy must be write_scope_can_trash or admins_only",
            )),
        },
        // Single-valued in v1, but a settings-output roundtrip (posting
        // what space.settings emits) must be publishable.
        "restore_policy" => match value.as_str() {
            Some("admins_only") => Ok(()),
            _ => Err(bad("restore_policy must be admins_only")),
        },
        "join_approval" => match value.as_str() {
            Some("manual") | Some("code") => Ok(()),
            _ => Err(bad("join_approval must be manual or code")),
        },
        "quorum_admin_ops" => match value.as_u64() {
            Some(n) if (1..=5).contains(&n) => Ok(()),
            _ => Err(bad("quorum_admin_ops must be between 1 and 5")),
        },
        "collection_create_authority" => match value.as_str() {
            Some("admins") | Some("editors") => Ok(()),
            _ => Err(bad("collection_create_authority must be admins or editors")),
        },
        _ => Err(bad(&format!(
            "'{key}' is not a policy this space recognizes"
        ))),
    }
}

/// Validate a whole policy map: known keys only, valid values only.
pub fn validate_policies(policies: &Map<String, Value>) -> Result<(), BaluardError> {
    for (key, value) in policies {
        validate_value(key, value)?;
    }
    Ok(())
}

/// The self-describing purpose marker inside the JSON document (the
/// hardened writer is purpose-agnostic; the field documents the file
/// to any future reader and keeps cross-writes visually obvious).
pub fn policies_purpose() -> &'static str {
    POLICIES_PURPOSE
}

/// Read the published policies. Missing, damaged, oversized, or
/// malformed files read as None (fail toward "no recommendation"),
/// mirroring the S3-6 catalog discipline.
pub fn read_policies(vault_path: &Path) -> Result<Option<Value>, BaluardError> {
    let path = vault_path.join(POLICIES_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("read policies: {e}"))))?;
    if bytes.len() > MAX_POLICIES_BYTES {
        return Ok(None);
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => {
            let has_policies = v.get("policies").map(|p| p.is_object()).unwrap_or(false);
            Ok(if has_policies { Some(v) } else { None })
        }
        Err(_) => Ok(None),
    }
}

/// Publish (or clear, on an empty map) the advisory policies. The file
/// is plaintext and rides the meta/** Admin sync row; the caller owns
/// the admin gate.
pub fn write_policies(vault_path: &Path, policies: Map<String, Value>) -> Result<(), BaluardError> {
    let path = vault_path.join(POLICIES_PATH);
    if policies.is_empty() {
        // Empty publish is the opt-out: remove the file if present.
        match std::fs::remove_file(&path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(BaluardError::from(VaultError::Metadata(format!(
                    "remove policies: {e}"
                ))));
            }
        }
    }
    validate_policies(&policies)?;
    let set_at = crate::vault::collections::now_secs_pub();
    let doc = json!({
        "format": 1,
        "purpose": POLICIES_PURPOSE,
        "set_at": set_at,
        "policies": Value::Object(policies),
    });
    let bytes = serde_json::to_vec_pretty(&doc)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("encode policies: {e}"))))?;
    if bytes.len() > MAX_POLICIES_BYTES {
        return Err(BaluardError::from(VaultError::InvalidOperation(
            "The policy set is too large.".into(),
        )));
    }
    crate::vault::write_vault_file(&path, &bytes)
        .map_err(|e| BaluardError::from(VaultError::Metadata(format!("write policies: {e}"))))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn policies_publish_read_roundtrip_and_opt_out() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path();

        // Missing file reads as None.
        assert!(read_policies(path).unwrap().is_none());

        // Publish a full recommendation set, read it back.
        write_policies(
            path,
            map(&[
                ("space_invite_authority", json!("owners")),
                ("allow_viewer_export", json!(false)),
                ("guest_enabled", json!(true)),
                ("trash_policy", json!("write_scope_can_trash")),
                ("join_approval", json!("code")),
                ("quorum_admin_ops", json!(2)),
                ("collection_create_authority", json!("editors")),
            ]),
        )
        .unwrap();
        let read = read_policies(path).unwrap().expect("published");
        assert_eq!(read["format"], 1);
        assert_eq!(read["policies"]["space_invite_authority"], "owners");
        assert_eq!(read["policies"]["quorum_admin_ops"], 2);
        assert!(read["set_at"].as_u64().unwrap() > 0);

        // Empty publish removes the file (the opt-out).
        write_policies(path, Map::new()).unwrap();
        assert!(read_policies(path).unwrap().is_none());
        assert!(!path.join(POLICIES_PATH).exists());
    }

    #[test]
    fn policies_validation_refuses_unknown_and_mistyped() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path();

        // Unknown knob name.
        assert!(write_policies(path, map(&[("theme", json!("dark"))])).is_err());
        // Known knob, bad value.
        assert!(
            write_policies(path, map(&[("space_invite_authority", json!("everyone"))])).is_err()
        );
        assert!(write_policies(path, map(&[("quorum_admin_ops", json!(9))])).is_err());
        assert!(write_policies(path, map(&[("allow_viewer_export", json!("yes"))])).is_err());
        // Nothing was written by any refused call.
        assert!(read_policies(path).unwrap().is_none());

        // A damaged file reads as None (inert), not an error.
        std::fs::create_dir_all(path.join("meta")).unwrap();
        std::fs::write(path.join(POLICIES_PATH), b"{not json").unwrap();
        assert!(read_policies(path).unwrap().is_none());
        // An oversize file reads as None too.
        std::fs::write(path.join(POLICIES_PATH), vec![b'x'; MAX_POLICIES_BYTES + 1]).unwrap();
        assert!(read_policies(path).unwrap().is_none());
    }
}
