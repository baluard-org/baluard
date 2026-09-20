//! P7: the path-glob -> role policy table (plan §4.4) and its matcher.
//!
//! The net-diff checker in `engine.rs` evaluates every path a regular
//! commit touches against this table; the first matching row decides and
//! an unmatched path is denied (deny by default). Merge commits are
//! exempt until P8a defines the merge-residue rule.
//!
//! Pre-S1a reality: `meta/devices.json` carries no roles, so every roster
//! device resolves to [`CommitRole::Admin`] (admin-equivalent). The table
//! and the checker land now; S1a only replaces the role resolver.
//!
//! Patterns are forward-slash segment lists. Segment syntax: a literal
//! segment, `*` (exactly one segment), `**` (only as the last segment;
//! matches any remainder, including empty), and `{self}` (exactly one
//! segment equal to the signer's device id).

use crate::error::SyncError;

/// Commit signer roles. Rank: Owner strongest, PendingJoiner weakest
/// (it satisfies only [`RequiredRole::Any`] rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRole {
    Owner,
    Admin,
    Editor,
    Viewer,
    PendingJoiner,
}

impl CommitRole {
    pub(crate) fn rank(self) -> u8 {
        match self {
            CommitRole::Owner => 4,
            CommitRole::Admin => 3,
            CommitRole::Editor => 2,
            CommitRole::Viewer => 1,
            CommitRole::PendingJoiner => 0,
        }
    }
}

impl From<crate::vault::members::MemberRole> for CommitRole {
    fn from(r: crate::vault::members::MemberRole) -> Self {
        match r {
            crate::vault::members::MemberRole::Owner => CommitRole::Owner,
            crate::vault::members::MemberRole::Admin => CommitRole::Admin,
            crate::vault::members::MemberRole::Editor => CommitRole::Editor,
            crate::vault::members::MemberRole::Viewer => CommitRole::Viewer,
        }
    }
}

/// The minimum role a policy row demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredRole {
    /// Any signer, including a pending joiner (self-service subtrees).
    Any,
    Viewer,
    Editor,
    Admin,
    Owner,
}

impl RequiredRole {
    fn admits(self, role: CommitRole) -> bool {
        let required = match self {
            RequiredRole::Any => return true,
            RequiredRole::Viewer => 1,
            RequiredRole::Editor => 2,
            RequiredRole::Admin => 3,
            RequiredRole::Owner => 4,
        };
        role.rank() >= required
    }
}

/// One row of the ordered policy table (plan §4.4).
struct PolicyRow {
    pattern: &'static str,
    required: RequiredRole,
}

/// Ordered table: the FIRST matching row decides. Rows run from the most
/// specific (self-service subtree) to the least (meta catch-all, root
/// files).
const TABLE: &[PolicyRow] = &[
    // Self-service: a member's own subtree (devices, pending, requests).
    PolicyRow {
        pattern: "meta/members/{self}/**",
        required: RequiredRole::Any,
    },
    // Someone else's member subtree, and Space-level settings.
    PolicyRow {
        pattern: "meta/members/**",
        required: RequiredRole::Admin,
    },
    PolicyRow {
        pattern: "meta/space.json",
        required: RequiredRole::Admin,
    },
    PolicyRow {
        pattern: "meta/collections/**",
        required: RequiredRole::Admin,
    },
    // Device/rotation admin surface.
    PolicyRow {
        pattern: "meta/devices.json",
        required: RequiredRole::Admin,
    },
    PolicyRow {
        pattern: "meta/epoch.json",
        required: RequiredRole::Admin,
    },
    PolicyRow {
        pattern: "meta/rekey/**",
        required: RequiredRole::Admin,
    },
    PolicyRow {
        pattern: "meta/keywrap/**",
        required: RequiredRole::Admin,
    },
    // Write scope: ciphers, folders, tags, trash move
    // (write_scope_can_trash), parent-item attachments.
    PolicyRow {
        pattern: "meta/folders/**",
        required: RequiredRole::Editor,
    },
    PolicyRow {
        pattern: "meta/tags/**",
        required: RequiredRole::Editor,
    },
    PolicyRow {
        pattern: "ciphers/**",
        required: RequiredRole::Editor,
    },
    PolicyRow {
        pattern: "trash/**",
        required: RequiredRole::Editor,
    },
    PolicyRow {
        pattern: "entries/**",
        required: RequiredRole::Editor,
    },
    // meta catch-all: canaries, settings, profile, kdf params, emergency,
    // avatar, revocation manifests, integrity state.
    PolicyRow {
        pattern: "meta/**",
        required: RequiredRole::Admin,
    },
    // Root-level loose files (vault marker, stray single files).
    PolicyRow {
        pattern: "*",
        required: RequiredRole::Admin,
    },
];

fn pattern_matches(pattern: &[&str], path: &[&str], signer: &str) -> bool {
    let mut pat = pattern;
    let mut segs = path;
    loop {
        match (pat.first(), segs.first()) {
            (None, None) => return true,
            (None, Some(_)) => return false,
            // `**` is only meaningful as the last segment; matches any
            // remainder (including the empty one).
            (Some(&"**"), _) => return pat.len() == 1,
            (Some(&"*"), Some(_)) => {
                pat = &pat[1..];
                segs = &segs[1..];
            }
            (Some(&"{self}"), Some(&seg)) if seg == signer => {
                pat = &pat[1..];
                segs = &segs[1..];
            }
            (Some(&p), Some(&seg)) if p == seg && p != "{self}" => {
                pat = &pat[1..];
                segs = &segs[1..];
            }
            _ => return false,
        }
    }
}

/// Evaluate the table for one written path. The first matching row
/// decides; an unmatched path is denied (deny by default).
pub fn authorize(signer: &str, role: CommitRole, path: &str) -> Result<(), SyncError> {
    let deny = || SyncError::PolicyViolation {
        device: signer.to_string(),
        path: path.to_string(),
    };
    let segs: Vec<&str> = path.split('/').collect();
    for row in TABLE {
        let pattern: Vec<&str> = row.pattern.split('/').collect();
        if pattern_matches(&pattern, &segs, signer) {
            return if row.required.admits(role) {
                Ok(())
            } else {
                Err(deny())
            };
        }
    }
    Err(deny())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-1111-1111-1111-111111111111";
    const B: &str = "22222222-2222-2222-2222-222222222222";

    #[test]
    fn self_member_subtree_any_role() {
        let own = format!("meta/members/{A}/devices/d.json");
        authorize(A, CommitRole::Viewer, &own).unwrap();
        authorize(A, CommitRole::PendingJoiner, &own).unwrap();

        // Another member's subtree needs Admin: Viewer denied, Admin ok.
        let other = format!("meta/members/{B}/devices/d.json");
        assert!(authorize(A, CommitRole::Viewer, &other).is_err());
        authorize(A, CommitRole::Admin, &other).unwrap();
    }

    #[test]
    fn pending_joiner_covered_only_by_any_rows() {
        let own = format!("meta/members/{A}/pending/join.json");
        authorize(A, CommitRole::PendingJoiner, &own).unwrap();
        assert!(authorize(A, CommitRole::PendingJoiner, "ciphers/x.enc").is_err());
        let other = format!("meta/members/{B}/pending/join.json");
        assert!(authorize(A, CommitRole::PendingJoiner, &other).is_err());
    }

    #[test]
    fn editor_write_scope_boundaries() {
        for path in [
            "ciphers/x.enc",
            "trash/x.enc",
            "meta/folders/f.enc",
            "meta/tags/t.enc",
            "entries/x/attachments/a.enc",
        ] {
            authorize(A, CommitRole::Editor, path).unwrap();
        }
        assert!(authorize(A, CommitRole::Editor, "meta/devices.json").is_err());
        assert!(authorize(A, CommitRole::Editor, "meta/settings.enc").is_err());
        assert!(authorize(A, CommitRole::Editor, "meta/rekey/2.txn").is_err());
    }

    #[test]
    fn admin_surface_and_meta_catch_all() {
        for path in [
            "meta/devices.json",
            "meta/epoch.json",
            "meta/settings.enc",
            "meta/avatar.enc",
            "meta/revocations.json",
        ] {
            authorize(A, CommitRole::Admin, path).unwrap();
        }
        // The meta catch-all stays Admin: an Editor cannot smuggle writes
        // into unlisted meta paths.
        assert!(authorize(A, CommitRole::Editor, "meta/revocations.json").is_err());
        authorize(A, CommitRole::Owner, "meta/nested/deeper").unwrap();
    }

    #[test]
    fn deny_by_default_unmatched_paths() {
        assert!(authorize(A, CommitRole::Owner, "unknown/x.enc").is_err());
        assert!(authorize(A, CommitRole::Owner, "a/b/c.enc").is_err());
    }

    #[test]
    fn glob_precision() {
        // {self} matches the exact signer segment only; the literal
        // "{self}" directory is nobody's subtree.
        authorize(A, CommitRole::Viewer, &format!("meta/members/{A}/x")).unwrap();
        assert!(authorize(A, CommitRole::Viewer, "meta/members/{self}/x").is_err());
        // Row isolation: the folders row must not swallow sibling names.
        assert!(authorize(A, CommitRole::Editor, "meta/foldersx/a.enc").is_err());
        authorize(A, CommitRole::Admin, "meta/foldersx/a.enc").unwrap();
        // `*` is exactly one segment.
        authorize(A, CommitRole::Admin, "loose.enc").unwrap();
        assert!(authorize(A, CommitRole::Admin, "loose.enc/inner").is_err());
        // `**` requires its prefix.
        assert!(authorize(A, CommitRole::Viewer, "trashf/x.enc").is_err());
    }
}
