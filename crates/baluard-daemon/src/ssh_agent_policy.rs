//! Device-local SSH agent policy.
//!
//! The master switch and the sign policy decide what THIS machine may do
//! with vault-stored SSH keys, so they never travel with the vault: a
//! synced switch would let another device turn on silent signing here.
//! The per-key opt-in stays in the cipher (it describes the key), while
//! these two live in a machine-local file, the same way the D80
//! permissive-mode policy does.

use std::path::PathBuf;

/// What this machine may do with vault SSH keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentPolicy {
    /// Master switch: serve opted-in keys at all.
    pub enabled: bool,
    /// Sign policy: true signs without asking, false asks every time.
    pub auto_approve: bool,
}

/// The policy file, next to the machine's other local state.
pub fn policy_path() -> PathBuf {
    baluard_core::paths::data_dir().join("agent-policy.json")
}

/// Read the policy. A missing or unreadable file means off: the agent
/// serves nothing until the user turns it on here.
pub fn load() -> AgentPolicy {
    load_from(&policy_path())
}

/// Read the policy from an explicit path.
pub fn load_from(path: &std::path::Path) -> AgentPolicy {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return AgentPolicy::default();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return AgentPolicy::default();
    };
    AgentPolicy {
        enabled: value.get("enabled").and_then(serde_json::Value::as_bool) == Some(true),
        auto_approve: value
            .get("auto_approve")
            .and_then(serde_json::Value::as_bool)
            == Some(true),
    }
}

/// Write the policy, owner-only. The file is small and local; the write
/// is atomic enough for a policy that only changes from a settings
/// screen (rename over the old file).
pub fn save(policy: &AgentPolicy) -> Result<(), String> {
    save_to(&policy_path(), policy)
}

/// Write the policy to an explicit path.
pub fn save_to(path: &std::path::Path, policy: &AgentPolicy) -> Result<(), String> {
    let path = path.to_path_buf();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("agent policy dir: {e}"))?;
    }
    let body = serde_json::json!({
        "enabled": policy.enabled,
        "auto_approve": policy.auto_approve,
    })
    .to_string();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body.as_bytes()).map_err(|e| format!("agent policy write: {e}"))?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("agent policy rename: {e}"))?;
    Ok(())
}

/// Owner-only on unix; the Windows build keeps the default ACL.
#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| format!("agent policy stat: {e}"))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| format!("agent policy chmod: {e}"))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy file is machine-local, so the tests write to a scratch
    /// path instead of the real one.
    fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-policy.json");
        (dir, path)
    }

    #[test]
    fn missing_policy_reads_as_off() {
        let (_dir, path) = scratch();
        let policy = load_from(&path);
        assert!(!policy.enabled);
        assert!(!policy.auto_approve);
    }

    #[test]
    fn policy_round_trips_through_the_file() {
        let (_dir, path) = scratch();
        save_to(
            &path,
            &AgentPolicy {
                enabled: true,
                auto_approve: false,
            },
        )
        .unwrap();
        let back = load_from(&path);
        assert!(back.enabled);
        assert!(!back.auto_approve);
        save_to(
            &path,
            &AgentPolicy {
                enabled: true,
                auto_approve: true,
            },
        )
        .unwrap();
        let back = load_from(&path);
        assert!(back.enabled);
        assert!(back.auto_approve);
    }

    #[cfg(unix)]
    #[test]
    fn saved_policy_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = scratch();
        save_to(&path, &AgentPolicy::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_policy_reads_as_off() {
        let (_dir, path) = scratch();
        std::fs::write(&path, b"{ not json").unwrap();
        let policy = load_from(&path);
        assert!(!policy.enabled);
        assert!(!policy.auto_approve);
    }
}
