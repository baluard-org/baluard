//! S4-5: the derived activity timeline. Nothing here writes anything —
//! the timeline is synthesized from verified signed git history, so
//! reads leave no trace and no shared event file ever exists (the
//! resolved power-pack design; see 0087-power-pack.md section 4).
//!
//! The split: `engine.rs` owns the walk (verification, roster lookup,
//! and attribution are engine-private) and hands each commit's changed
//! paths to the pure classifiers here. Entry-level cipher churn is
//! deliberately excluded — the per-device share-events log covers it
//! locally; the timeline is the space story.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One timeline row. Order is NEWEST-FIRST (the walk runs HEAD toward
/// the root); `at` is the commit's committer time — display-only by
/// design, since git timestamps skew across devices (topological order
/// is the real ordering).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    #[serde(rename = "kind")]
    pub kind: TimelineKind,
    #[serde(rename = "at")]
    pub at: i64,
    /// Short commit id (first 8 hex) so an entry can point at its commit.
    #[serde(rename = "oid")]
    pub oid: String,
    /// Human actor: the member's display name when the signing device
    /// maps to a member row, else the device id prefix.
    #[serde(rename = "actor")]
    pub actor: String,
    #[serde(rename = "actor_member", skip_serializing_if = "Option::is_none")]
    pub actor_member: Option<Uuid>,
    /// Plain-language detail (already rendered; no client-side assembly).
    #[serde(rename = "detail")]
    pub detail: String,
}

/// Coarse event classes. Kebab-case on the wire so surfaces can render
/// labels from a fixed mapping, with unknown kinds falling back to the
/// raw string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimelineKind {
    /// The vault's genesis commit.
    VaultCreated,
    /// A member row appeared.
    MemberAdded,
    /// A member row was tombstoned (batch removal).
    MemberRemoved,
    /// A member row was reset (successor minted).
    MemberReset,
    /// A member rotated their identity keys in place.
    IdentityRotated,
    /// A single member's role changed.
    RoleChanged,
    /// Ownership moved between two existing rows (transfer or claim).
    OwnershipTransferred,
    /// A collection was created.
    CollectionCreated,
    /// A collection was deleted.
    CollectionDeleted,
    /// A grant was added to a collection.
    GrantAdded,
    /// A grant was removed from a collection (revoke, group delete
    /// prune, or the expiry sweep).
    GrantRevoked,
    /// A group was created.
    GroupCreated,
    /// A group was deleted.
    GroupDeleted,
    /// A group's member list changed.
    GroupMembershipChanged,
    /// The Root Key was rotated (a rekey transaction landed).
    KeyRotated,
    /// The Team-shape flip marker landed.
    TeamFlip,
    /// Space policy recommendations were published or cleared.
    PoliciesSet,
    /// The Space Recovery Kit was enabled or removed.
    RecoveryKitSet,
    /// The sync address moved (remote migration).
    RemoteMoved,
}

impl TimelineKind {
    /// The wire string (kebab), for surfaces that render unknown kinds
    /// verbatim.
    pub fn as_str(&self) -> &'static str {
        match self {
            TimelineKind::VaultCreated => "vault-created",
            TimelineKind::MemberAdded => "member-added",
            TimelineKind::MemberRemoved => "member-removed",
            TimelineKind::MemberReset => "member-reset",
            TimelineKind::IdentityRotated => "identity-rotated",
            TimelineKind::RoleChanged => "role-changed",
            TimelineKind::OwnershipTransferred => "ownership-transferred",
            TimelineKind::CollectionCreated => "collection-created",
            TimelineKind::CollectionDeleted => "collection-deleted",
            TimelineKind::GrantAdded => "grant-added",
            TimelineKind::GrantRevoked => "grant-revoked",
            TimelineKind::GroupCreated => "group-created",
            TimelineKind::GroupDeleted => "group-deleted",
            TimelineKind::GroupMembershipChanged => "group-membership-changed",
            TimelineKind::KeyRotated => "key-rotated",
            TimelineKind::TeamFlip => "team-flip",
            TimelineKind::PoliciesSet => "policies-set",
            TimelineKind::RecoveryKitSet => "recovery-kit-set",
            TimelineKind::RemoteMoved => "remote-moved",
        }
    }
}

/// A member row's identity-relevant fields for diffing (the slice of
/// `MemberFile` the timeline can speak about).
#[derive(Debug, Clone, PartialEq)]
pub struct MemberFacts {
    pub display_name: String,
    pub role: crate::vault::members::MemberRole,
    pub removed: bool,
    pub reset: bool,
    pub identity_signing_pubkey: Option<String>,
}

impl MemberFacts {
    /// Project the timeline-relevant facts out of a member row.
    pub fn from_row(row: &crate::vault::members::MemberFile) -> Self {
        Self {
            display_name: row.display_name.clone(),
            role: row.role,
            removed: row.removed.is_some(),
            reset: row.reset.is_some(),
            identity_signing_pubkey: row.identity_signing_pubkey.clone(),
        }
    }
}

/// Diff one member row's old and new facts into timeline events.
/// Tombstones dominate: a removed or reset row reports exactly that,
/// never the rotation that may ride the same rewrite.
pub fn classify_member_change(
    id: Uuid,
    old: Option<&MemberFacts>,
    new: Option<&MemberFacts>,
) -> Vec<(TimelineKind, String)> {
    let name_of = |f: Option<&MemberFacts>| -> String {
        f.map(|f| f.display_name.clone())
            .unwrap_or_else(|| short_id(&id))
    };
    match (old, new) {
        (None, Some(new)) => {
            vec![(TimelineKind::MemberAdded, name_of(Some(new)))]
        }
        (Some(_), None) => {
            vec![(TimelineKind::MemberRemoved, name_of(old))]
        }
        (Some(old), Some(new)) => {
            if !old.removed && new.removed {
                return vec![(TimelineKind::MemberRemoved, new.display_name.clone())];
            }
            if !old.reset && new.reset {
                return vec![(TimelineKind::MemberReset, new.display_name.clone())];
            }
            let mut events = Vec::new();
            if old.identity_signing_pubkey.is_some()
                && new.identity_signing_pubkey.is_some()
                && old.identity_signing_pubkey != new.identity_signing_pubkey
            {
                events.push((TimelineKind::IdentityRotated, new.display_name.clone()));
            }
            if old.role != new.role {
                events.push((
                    TimelineKind::RoleChanged,
                    format!("{} is now {}", new.display_name, role_label(new.role)),
                ));
            }
            events
        }
        (None, None) => Vec::new(),
    }
}

/// Diff a collection's grant list into grant events. A same-target
/// access change (Read → Write or back) is a revocation of the old
/// level plus a grant of the new one — two events, since the old
/// access genuinely stopped.
pub fn classify_grant_changes(
    old: &[crate::vault::collections::CollectionGrant],
    new: &[crate::vault::collections::CollectionGrant],
) -> Vec<(TimelineKind, String)> {
    let mut events = Vec::new();
    for g in new {
        let prev = old.iter().find(|o| o.target == g.target);
        match prev {
            None => events.push((TimelineKind::GrantAdded, grant_label(g))),
            Some(o) if o.access != g.access => {
                events.push((TimelineKind::GrantRevoked, grant_label(o)));
                events.push((TimelineKind::GrantAdded, grant_label(g)));
            }
            Some(_) => {}
        }
    }
    for g in old {
        if !new.iter().any(|n| n.target == g.target) {
            events.push((TimelineKind::GrantRevoked, grant_label(g)));
        }
    }
    events
}

/// Diff a group's member list into one membership event (added and
/// removed ids in a single detail line).
pub fn classify_group_change(
    old_members: &[Uuid],
    new_members: &[Uuid],
) -> Option<(TimelineKind, String)> {
    let added: Vec<String> = new_members
        .iter()
        .filter(|m| !old_members.contains(m))
        .map(short_id)
        .collect();
    let removed: Vec<String> = old_members
        .iter()
        .filter(|m| !new_members.contains(m))
        .map(short_id)
        .collect();
    if added.is_empty() && removed.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if !added.is_empty() {
        parts.push(format!("added {}", added.join(", ")));
    }
    if !removed.is_empty() {
        parts.push(format!("removed {}", removed.join(", ")));
    }
    Some((TimelineKind::GroupMembershipChanged, parts.join("; ")))
}

/// Collapse role flips into an ownership transfer when exactly two
/// members swapped the Owner role in one commit (transfer and claim
/// both land this way). `old_roles` carries the pre-commit roles of
/// every member whose row changed, so the member GAINING Owner is the
/// one whose id was NOT previously Owner. The two role events are
/// REPLACED in place; any other events (identity rotations riding the
/// same commit) survive.
pub fn coalesce_ownership(
    events: &[(TimelineKind, String, Option<Uuid>)],
    old_roles: &[(Uuid, crate::vault::members::MemberRole)],
) -> Vec<(TimelineKind, String, Option<Uuid>)> {
    let role_idx: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, (k, _, _))| *k == TimelineKind::RoleChanged)
        .map(|(i, _)| i)
        .collect();
    if role_idx.len() == 2 {
        let gained = role_idx.iter().find_map(|i| {
            let (_, _, id) = &events[*i];
            id.is_some_and(|id| {
                old_roles
                    .iter()
                    .any(|(oid, r)| *oid != id && *r == crate::vault::members::MemberRole::Owner)
            })
            .then_some(*i)
        });
        if let Some(at) = gained {
            let (label, who) = (events[at].1.clone(), events[at].2);
            let mut out: Vec<(TimelineKind, String, Option<Uuid>)> = events.to_vec();
            out[at] = (TimelineKind::OwnershipTransferred, label, who);
            out.remove(if at == role_idx[0] {
                role_idx[1]
            } else {
                role_idx[0]
            });
            return out;
        }
    }
    events.to_vec()
}

fn grant_label(g: &crate::vault::collections::CollectionGrant) -> String {
    let who = match &g.target {
        crate::vault::collections::GrantTarget::Member { id } => {
            format!("member {}", short_id(id))
        }
        crate::vault::collections::GrantTarget::Group { id } => {
            format!("group {}", short_id(id))
        }
    };
    let access = match g.access {
        crate::vault::collections::CollectionAccess::Read => "read",
        crate::vault::collections::CollectionAccess::Write => "write",
        crate::vault::collections::CollectionAccess::Manage => "manage",
    };
    format!("{who}: {access}")
}

fn role_label(role: crate::vault::members::MemberRole) -> &'static str {
    match role {
        crate::vault::members::MemberRole::Owner => "owner",
        crate::vault::members::MemberRole::Admin => "admin",
        crate::vault::members::MemberRole::Editor => "editor",
        crate::vault::members::MemberRole::Viewer => "viewer",
    }
}

/// First 8 hex of an id — the display shape for ids whose row is gone
/// (deleted groups) or that never had one.
pub fn short_id(id: &Uuid) -> String {
    id.to_string().chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(role: crate::vault::members::MemberRole, key: &str) -> MemberFacts {
        MemberFacts {
            display_name: "Ada".into(),
            role,
            removed: false,
            reset: false,
            identity_signing_pubkey: Some(key.into()),
        }
    }

    #[test]
    fn member_events_cover_join_leave_rotate_and_tombstones() {
        let id = Uuid::new_v4();
        let (k, d) = classify_member_change(
            id,
            None,
            Some(&row(crate::vault::members::MemberRole::Editor, "aa")),
        )[0]
        .clone();
        assert_eq!(k, TimelineKind::MemberAdded);
        assert_eq!(d, "Ada");
        let (k, _) = classify_member_change(
            id,
            Some(&row(crate::vault::members::MemberRole::Editor, "aa")),
            Some(&row(crate::vault::members::MemberRole::Editor, "bb")),
        )[0]
        .clone();
        assert_eq!(k, TimelineKind::IdentityRotated);
        let events = classify_member_change(
            id,
            Some(&row(crate::vault::members::MemberRole::Editor, "aa")),
            Some(&row(crate::vault::members::MemberRole::Admin, "bb")),
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].0, TimelineKind::RoleChanged);
        let mut gone = row(crate::vault::members::MemberRole::Editor, "bb");
        gone.removed = true;
        let events = classify_member_change(
            id,
            Some(&row(crate::vault::members::MemberRole::Editor, "aa")),
            Some(&gone),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, TimelineKind::MemberRemoved);
        let mut reset_row = row(crate::vault::members::MemberRole::Editor, "bb");
        reset_row.reset = true;
        let events = classify_member_change(
            id,
            Some(&row(crate::vault::members::MemberRole::Editor, "aa")),
            Some(&reset_row),
        );
        assert_eq!(events[0].0, TimelineKind::MemberReset);
        let events = classify_member_change(
            id,
            Some(&row(crate::vault::members::MemberRole::Editor, "aa")),
            None,
        );
        assert_eq!(events[0].0, TimelineKind::MemberRemoved);
    }

    #[test]
    fn grant_and_group_diffs_and_ownership_coalesce() {
        let cid = Uuid::new_v4();
        let m1 = Uuid::new_v4();
        let m2 = Uuid::new_v4();
        let grant = |id: Uuid| crate::vault::collections::CollectionGrant {
            target: crate::vault::collections::GrantTarget::Member { id },
            access: crate::vault::collections::CollectionAccess::Write,
            expires_at: None,
        };
        let events = classify_grant_changes(&[grant(m1)], &[grant(m1), grant(m2)]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, TimelineKind::GrantAdded);
        assert!(events[0].1.contains("write"));
        let events = classify_grant_changes(&[grant(m1), grant(m2)], &[grant(m1)]);
        assert_eq!(events[0].0, TimelineKind::GrantRevoked);

        // F1: a same-target access change is a revoke+grant pair.
        let read_grant = crate::vault::collections::CollectionGrant {
            target: crate::vault::collections::GrantTarget::Member { id: m1 },
            access: crate::vault::collections::CollectionAccess::Read,
            expires_at: None,
        };
        let events = classify_grant_changes(&[read_grant], &[grant(m1)]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, TimelineKind::GrantRevoked);
        assert!(events[0].1.contains("read"));
        assert_eq!(events[1].0, TimelineKind::GrantAdded);
        assert!(events[1].1.contains("write"));

        let (k, d) = classify_group_change(&[m1], &[m1, m2]).unwrap();
        assert_eq!(k, TimelineKind::GroupMembershipChanged);
        assert!(d.contains("added"));
        assert!(classify_group_change(&[m1], &[m1]).is_none());

        let events = vec![
            (
                TimelineKind::RoleChanged,
                "old is now admin".to_string(),
                Some(m1),
            ),
            (
                TimelineKind::RoleChanged,
                "new is now owner".to_string(),
                Some(m2),
            ),
        ];
        let old_roles = vec![(m1, crate::vault::members::MemberRole::Owner)];
        let coalesced = coalesce_ownership(&events, &old_roles);
        assert_eq!(coalesced.len(), 1);
        assert_eq!(coalesced[0].0, TimelineKind::OwnershipTransferred);
        assert_eq!(coalesced[0].2, Some(m2));
        // A rotation riding the same commit survives the coalesce.
        let mixed = vec![
            (
                TimelineKind::IdentityRotated,
                "rotated".to_string(),
                Some(m1),
            ),
            (
                TimelineKind::RoleChanged,
                "old is now admin".to_string(),
                Some(m1),
            ),
            (
                TimelineKind::RoleChanged,
                "new is now owner".to_string(),
                Some(m2),
            ),
        ];
        let out = coalesce_ownership(&mixed, &old_roles);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, TimelineKind::IdentityRotated);
        assert_eq!(out[1].0, TimelineKind::OwnershipTransferred);
        let one = vec![(TimelineKind::RoleChanged, "solo".to_string(), Some(m2))];
        let out = coalesce_ownership(&one, &old_roles);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, TimelineKind::RoleChanged);

        assert_eq!(short_id(&cid).len(), 8);
    }
}
