//! P7 + P8a + S1a-1: the path-glob -> role policy table (plan §4.4) and
//! its matcher.
//!
//! The net-diff checker in `engine.rs` evaluates every path a commit
//! touches against this table; the first matching row decides and an
//! unmatched path is denied (deny by default). Regular commits check
//! their first-parent diff, merge commits check their residue against
//! the recomputed expected merge (P8a), and conflicted paths are
//! attributed to the merger outright.
//!
//! Role resolution (S1a-1): the device-to-member bindings and member
//! files in `meta/members/**` are parsed per commit with the
//! roster-snapshot rule; a commit tree without a member directory is a
//! legacy vault and stays admin-equivalent; a strict vault treats an
//! unbound device as a pending joiner.
//!
//! Patterns are forward-slash segment lists. Segment syntax: a literal
//! segment, `*` (exactly one segment), `**` (only as the last segment;
//! matches any remainder, including empty), and `{member}` (exactly one
//! segment equal to the signer's MEMBER id, resolved from the device
//! binding snapshot — never the raw device id, so a device can only
//! write inside its own member's devices subtree).

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
/// specific (self-service devices subtree) to the least (meta catch-all,
/// root files). Member FILES (role assignment) are admin-only — only the
/// devices subtree of a member is self-service (device lifecycle is
/// all-roles per §5.A).
const TABLE: &[PolicyRow] = &[
    // Self-service: a member's own subtree (device lifecycle, identity
    // rotation artifacts). §4.4 own_id/** any role; member RECORDS
    // (role/trust assignment) stay admin-only — the engine's structural
    // rule permits identity-field-only record updates.
    PolicyRow {
        pattern: "meta/members/{member}/**",
        required: RequiredRole::Any,
    },
    // Other members' records, and Space-level settings.
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
    // Rotation artifacts (rekey txns, acks) are admin surface.
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
    // avatar, revocation manifests, integrity state, epoch.
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

fn pattern_matches(pattern: &[&str], path: &[&str], member: Option<&str>) -> bool {
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
            (Some(&"{member}"), Some(&seg)) if member == Some(seg) => {
                pat = &pat[1..];
                segs = &segs[1..];
            }
            (Some(&p), Some(&seg)) if p == seg && p != "{member}" => {
                pat = &pat[1..];
                segs = &segs[1..];
            }
            _ => return false,
        }
    }
}

/// Evaluate the table for one written path. The first matching row
/// decides; an unmatched path is denied (deny by default). `member` is
/// the signer's member id from the binding snapshot (`None` = unbound
/// device, which can never satisfy a `{member}` segment).
pub fn authorize(
    signer: &str,
    member: Option<&str>,
    role: CommitRole,
    path: &str,
) -> Result<(), SyncError> {
    let deny = || SyncError::PolicyViolation {
        device: signer.to_string(),
        path: path.to_string(),
    };
    let segs: Vec<&str> = path.split('/').collect();
    for row in TABLE {
        let pattern: Vec<&str> = row.pattern.split('/').collect();
        if pattern_matches(&pattern, &segs, member) {
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

    const DA: &str = "11111111-1111-1111-1111-111111111111"; // device A
    const MA: &str = "33333333-3333-3333-3333-333333333333"; // DA's member
    const MB: &str = "44444444-4444-4444-4444-444444444444"; // another member

    #[test]
    fn own_member_devices_subtree_any_role() {
        let own = format!("meta/members/{MA}/devices/{DA}.json");
        authorize(DA, Some(MA), CommitRole::Viewer, &own).unwrap();
        authorize(DA, Some(MA), CommitRole::PendingJoiner, &own).unwrap();

        // Another member's subtree needs Admin — the {member} segment
        // only matches the signer's own member id.
        let other = format!("meta/members/{MB}/devices/{DA}.json");
        assert!(authorize(DA, Some(MA), CommitRole::Viewer, &other).is_err());
        authorize(DA, Some(MA), CommitRole::Admin, &other).unwrap();
    }

    #[test]
    fn unbound_device_writes_nothing() {
        // No binding (member = None): the {member} segment can never
        // match, so an unbound device is held to the PendingJoiner rank:
        // even its own-shaped subtree is denied, and nothing else is in
        // reach for a PendingJoiner anyway.
        let own = format!("meta/members/{MA}/devices/{DA}.json");
        assert!(authorize(DA, None, CommitRole::PendingJoiner, &own).is_err());
        assert!(authorize(DA, None, CommitRole::Viewer, &own).is_err());
    }

    #[test]
    fn member_files_are_admin_only() {
        // A member FILE (role assignment) is never self-service — the
        // {member} row only covers the devices subtree.
        let own_file = format!("meta/members/{MA}.json");
        assert!(authorize(DA, Some(MA), CommitRole::Viewer, &own_file).is_err());
        assert!(authorize(DA, Some(MA), CommitRole::Editor, &own_file).is_err());
        // A device-named member file is still a member file: writing it
        // as a non-admin is refused even though the segment equals the
        // device id (the escalation attempt from the review round).
        let escalate = format!("meta/members/{DA}.json");
        assert!(authorize(DA, Some(MA), CommitRole::Editor, &escalate).is_err());
        // Owners/admins manage members.
        authorize(DA, Some(MA), CommitRole::Admin, &own_file).unwrap();
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
            authorize(DA, Some(MA), CommitRole::Editor, path).unwrap();
        }
        assert!(authorize(DA, Some(MA), CommitRole::Editor, "meta/devices.json").is_err());
        assert!(authorize(DA, Some(MA), CommitRole::Editor, "meta/settings.enc").is_err());
        assert!(authorize(DA, Some(MA), CommitRole::Editor, "meta/rekey/2.txn").is_err());
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
            authorize(DA, Some(MA), CommitRole::Admin, path).unwrap();
        }
        // The meta catch-all stays Admin: an Editor cannot smuggle writes
        // into unlisted meta paths.
        assert!(authorize(DA, Some(MA), CommitRole::Editor, "meta/revocations.json").is_err());
        authorize(DA, Some(MA), CommitRole::Owner, "meta/nested/deeper").unwrap();
    }

    #[test]
    fn deny_by_default_unmatched_paths() {
        assert!(authorize(DA, Some(MA), CommitRole::Owner, "unknown/x.enc").is_err());
        assert!(authorize(DA, Some(MA), CommitRole::Owner, "a/b/c.enc").is_err());
    }

    #[test]
    fn glob_precision() {
        // {member} matches the signer's member segment only; the literal
        // "{member}" directory is nobody's subtree.
        authorize(
            DA,
            Some(MA),
            CommitRole::Viewer,
            &format!("meta/members/{MA}/devices/x"),
        )
        .unwrap();
        assert!(authorize(DA, Some(MA), CommitRole::Viewer, "meta/members/{member}/x").is_err());
        // Row isolation: the folders row must not swallow sibling names.
        assert!(authorize(DA, Some(MA), CommitRole::Editor, "meta/foldersx/a.enc").is_err());
        authorize(DA, Some(MA), CommitRole::Admin, "meta/foldersx/a.enc").unwrap();
        // `*` is exactly one segment.
        authorize(DA, Some(MA), CommitRole::Admin, "loose.enc").unwrap();
        assert!(authorize(DA, Some(MA), CommitRole::Admin, "loose.enc/inner").is_err());
        // `**` requires its prefix.
        assert!(authorize(DA, Some(MA), CommitRole::Viewer, "trashf/x.enc").is_err());
    }
}
