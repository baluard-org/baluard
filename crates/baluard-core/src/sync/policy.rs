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
use uuid::Uuid;

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
    // Family-spaces §5: the sealed minor record is Admin-only WRITE and
    // DELETE even inside the signer's own subtree — without this row
    // (and the first-match rule) a minor could overwrite or delete
    // their own flag from a validly signed commit. Admins writing
    // ANOTHER member's record fall through to the Admin-only
    // meta/members/** row below.
    PolicyRow {
        pattern: "meta/members/{member}/minor.enc",
        required: RequiredRole::Admin,
    },
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
    // Groups (S4-2): defs (membership, keys) are admin surface; a
    // member's own gkwrap carries a structural self-service rule below.
    PolicyRow {
        pattern: "meta/groups/**",
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

/// Collection write context for one verified commit (plan P5/S3): the
/// salted dir -> collection id map read from the commit tree's
/// `meta/collections/**`, and the collection ids the SIGNER holds a
/// write grant on (resolved from those same files plus the signer's
/// member id). An empty scope = every cipher path is personal-flat.
pub struct CollectionScope {
    pub dirs: Vec<(String, Uuid)>,
    pub writable: Vec<Uuid>,
    /// S3-7c review F5: set from the commit tree's space-shape marker.
    /// On a flipped (team-shape) vault the personal-flat cipher surface is
    /// Admin-only — member devices hold neither Root Key nor SGK and can
    /// never have authored flat content legitimately.
    pub flat_admin_only: bool,
    /// S3-5 delegated manage: collections whose def (grant list) the
    /// signer may edit — the ids holding a `manage` grant for the
    /// signer in the PARENT tree. Authority must pre-date the edit:
    /// reading the commit's own tree would let a member self-grant
    /// manage in the same commit.
    pub managed: Vec<Uuid>,
}

impl CollectionScope {
    pub fn none() -> CollectionScope {
        CollectionScope {
            dirs: Vec::new(),
            writable: Vec::new(),
            managed: Vec::new(),
            flat_admin_only: false,
        }
    }
}

/// Evaluate the table for one written path. The first matching row
/// decides; an unmatched path is denied (deny by default). `member` is
/// the signer's member id from the binding snapshot (`None` = unbound
/// device, which can never satisfy a `{member}` segment).
///
/// Collection-scoped rule (plan §4.4 row `ciphers/<collection_id>/**`):
/// a path at `ciphers/<dir>/...` (three or more segments) names a
/// collection directory. It is admitted only when the directory maps to
/// a known collection AND the signer holds write scope on that
/// collection — the member-role rows then apply on top, so a Viewer can
/// never write ciphers even with a grant.
pub fn authorize_scoped(
    signer: &str,
    member: Option<&str>,
    role: CommitRole,
    path: &str,
    scope: &CollectionScope,
    is_deletion: bool,
) -> Result<(), SyncError> {
    let deny = || SyncError::PolicyViolation {
        device: signer.to_string(),
        path: path.to_string(),
    };
    let segs: Vec<&str> = path.split('/').collect();
    if segs.first() == Some(&"ciphers") && segs.len() >= 3 {
        let dir = segs[1];
        let Some((_, cid)) = scope.dirs.iter().find(|(d, _)| d == dir) else {
            return Err(deny());
        };
        // S3-7c fix (latent S3-2 gap): Owner/Admin hold every known
        // collection structurally — the writable set lists GRANT holders
        // only, so an admin-authored collection cipher was refused at
        // every peer's pull. Unknown dirs still deny everyone (forged
        // directories stay out), and the role floor below still applies.
        if !matches!(role, CommitRole::Owner | CommitRole::Admin) && !scope.writable.contains(cid) {
            return Err(deny());
        }
        // Fall through: the member-role rows still gate the signer.
    }
    // S3-7c review F5: two path classes the table alone admits too
    // broadly on team vaults.
    //   1. trash/<dir>/**: collection-scoped trashes follow the SAME
    //      scope rules as the ciphers they came from (known dir +
    //      grant-or-admin); an Editor member cannot trash foreign
    //      collection entries.
    //   2. Personal-flat ciphers and root trash files: on a FLIPPED
    //      vault these are the admin surface — member devices hold
    //      neither Root Key nor SGK and never authored flat content
    //      legitimately, so the Editor table row must not admit their
    //      rewrites or deletions. Pre-flip vaults keep the legacy rows.
    if segs.first() == Some(&"trash") && segs.len() >= 3 {
        let dir = segs[1];
        let Some((_, cid)) = scope.dirs.iter().find(|(d, _)| *d == dir) else {
            return Err(deny());
        };
        if !matches!(role, CommitRole::Owner | CommitRole::Admin) && !scope.writable.contains(cid) {
            return Err(deny());
        }
        // Fall through: the member-role rows still gate the signer.
    }
    if scope.flat_admin_only {
        let flat_cipher = segs.first() == Some(&"ciphers") && segs.len() == 2;
        let flat_trash = segs.first() == Some(&"trash") && segs.len() == 2;
        if (flat_cipher || flat_trash) && role.rank() < CommitRole::Admin.rank() {
            return Err(deny());
        }
    }
    if segs.first() == Some(&"meta") && segs.get(1) == Some(&"collections") {
        // Own-wrap self-service (P1 groundwork, review S3-5): a member
        // rotating their identity rewrites their OWN per-member key
        // wrap. Structural rule at any role, like the members/devices
        // self-rule — without it every grantee's identity rotation
        // would wedge sync on the Admin meta/collections row.
        if segs.len() == 4
            && segs[3].ends_with(".wrap")
            && segs[3].strip_suffix(".wrap") == member
            && segs[2].parse::<Uuid>().is_ok()
        {
            return Ok(());
        }
        // S3-5 delegated manage: a signer holding a manage grant (from
        // the parent tree) may edit that collection's def and rewrite
        // or remove member wraps. Shapes are exact — the def is
        // meta/collections/<uuid>.json, wraps are one segment deeper —
        // so nothing can hide under loose subpaths. Def DELETION is
        // never delegated (it kills the collection's grant list; that
        // stays admin-only), wrap deletions are (revoke removes them).
        // The Editor floor still applies — a Viewer can never author
        // these commits. Everything else on meta/collections/** stays
        // Admin via the table below.
        if segs.len() == 3 && segs[2].ends_with(".json") && !is_deletion {
            if let Some(raw) = segs[2].strip_suffix(".json") {
                if let Ok(cid) = raw.parse::<Uuid>() {
                    if scope.managed.contains(&cid) && RequiredRole::Editor.admits(role) {
                        return Ok(());
                    }
                }
            }
        }
        if segs.len() == 4 && segs[3].ends_with(".wrap") {
            if let Ok(cid) = segs[2].parse::<Uuid>() {
                if scope.managed.contains(&cid) && RequiredRole::Editor.admits(role) {
                    return Ok(());
                }
            }
        }
    }
    if segs.first() == Some(&"meta") && segs.get(1) == Some(&"groups") {
        // Own-gkwrap self-service (S4-2): a member rotating their
        // identity rewrites their OWN group key wraps. Structural rule
        // at any role, mirroring the collections own-wrap rule above —
        // without it a grantee's identity rotation would wedge sync on
        // the Admin meta/groups row. The .gkwrap suffix keeps ckwraps
        // (admin surface) out of this rule.
        if segs.len() == 4
            && segs[3].ends_with(".gkwrap")
            && segs[3].strip_suffix(".gkwrap") == member
            && segs[2].parse::<Uuid>().is_ok()
        {
            return Ok(());
        }
    }
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

/// Personal-flat convenience wrapper (no collections in scope).
pub fn authorize(
    signer: &str,
    member: Option<&str>,
    role: CommitRole,
    path: &str,
) -> Result<(), SyncError> {
    authorize_scoped(signer, member, role, path, &CollectionScope::none(), false)
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

    // S3-7a: the space meta files ride existing rows — pin the routing
    // so a table reorder cannot expose the SMK.
    #[test]
    fn space_meta_files_routing() {
        // The sealed store: Admin only (meta/** row).
        authorize(DA, Some(MA), CommitRole::Admin, "meta/space.enc").unwrap();
        assert!(authorize(DA, Some(MA), CommitRole::Editor, "meta/space.enc").is_err());
        assert!(authorize(DA, Some(MA), CommitRole::Viewer, "meta/space.enc").is_err());

        // Own space.wrap: self-service at ANY role (identity-rotation
        // self-heal writes it).
        let own_wrap = format!("meta/members/{MA}/space.wrap");
        authorize(DA, Some(MA), CommitRole::Viewer, &own_wrap).unwrap();

        // Another member's space.wrap: Admin only (prepare wraps others;
        // a member transplanting a wrap must refuse at verification).
        let other_wrap = format!("meta/members/{MB}/space.wrap");
        assert!(authorize(DA, Some(MA), CommitRole::Editor, &other_wrap).is_err());
        authorize(DA, Some(MA), CommitRole::Admin, &other_wrap).unwrap();
    }

    fn scoped(dir: &str, cid: Uuid, writable: &[Uuid]) -> CollectionScope {
        CollectionScope {
            flat_admin_only: false,
            dirs: vec![(dir.to_string(), cid)],
            writable: writable.to_vec(),
            managed: Vec::new(),
        }
    }

    // Test-module wrappers binding the signer pair; `del` picks the
    // deletion variant of the policy check.
    fn allowed(path: &str, role: CommitRole, scope: &CollectionScope) -> Result<(), SyncError> {
        authorize_scoped(DA, Some(MA), role, path, scope, false)
    }

    fn allowed_del(path: &str, role: CommitRole, scope: &CollectionScope) -> Result<(), SyncError> {
        authorize_scoped(DA, Some(MA), role, path, scope, true)
    }

    #[test]
    fn collection_scoped_paths_follow_grants_and_role() {
        let cid = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let path = format!("ciphers/deadbeefdeadbeefdeadbeefdeadbeef/{MA}.enc");
        // Editor with a write grant: allowed.
        allowed(
            &path,
            CommitRole::Editor,
            &scoped("deadbeefdeadbeefdeadbeefdeadbeef", cid, &[cid]),
        )
        .unwrap();
        // Editor without a grant: denied.
        assert!(
            allowed(
                &path,
                CommitRole::Editor,
                &scoped("deadbeefdeadbeefdeadbeefdeadbeef", cid, &[])
            )
            .is_err()
        );
        // Unknown dir: denied even for an Owner (deny-by-default keeps
        // forged directories out) — the scope map has a different name.
        assert!(
            allowed(
                &path,
                CommitRole::Owner,
                &scoped("cafebabecafebabecafebabecafebabe", cid, &[cid])
            )
            .is_err()
        );
        // A grant does not lift the role floor: a Viewer with write
        // grant still cannot write ciphers.
        assert!(
            allowed(
                &path,
                CommitRole::Viewer,
                &scoped("deadbeefdeadbeefdeadbeefdeadbeef", cid, &[cid])
            )
            .is_err()
        );
        // A different collection's id in the writable set does not open
        // this dir.
        assert!(
            allowed(
                &path,
                CommitRole::Editor,
                &scoped("deadbeefdeadbeefdeadbeefdeadbeef", cid, &[other])
            )
            .is_err()
        );
        // Personal flat paths stay Editor-only, no scope needed.
        authorize(DA, Some(MA), CommitRole::Editor, "ciphers/x.enc").unwrap();
        // With CollectionScope::NONE (legacy/personal) an unexpected
        // 3-segment ciphers path is still denied: the empty scope has no
        // known dirs, so nothing can hide behind a nested path.
        assert!(
            allowed(
                "ciphers/x.enc/inner.enc",
                CommitRole::Editor,
                &CollectionScope::none()
            )
            .is_err()
        );
    }

    #[test]
    fn delegated_manage_admits_meta_collections_for_managers_only() {
        let cid = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let def = format!("meta/collections/{cid}.json");
        let wrap = format!("meta/collections/{cid}/{}.wrap", uuid::Uuid::new_v4());
        let mut scope = scoped("deadbeefdeadbeefdeadbeefdeadbeef", cid, &[cid]);
        // No manage grant: even an Owner hits the Admin table row...
        assert!(allowed(&def, CommitRole::Editor, &scope).is_err());
        // ...while an actual Admin passes via the table.
        allowed(&def, CommitRole::Admin, &scope).unwrap();

        // S3-5: a manager may edit the def and the per-member wraps of
        // the managed collection (Editor floor intact).
        scope.managed = vec![cid];
        allowed(&def, CommitRole::Editor, &scope).unwrap();
        allowed(&wrap, CommitRole::Editor, &scope).unwrap();
        // The Viewer floor is not lifted by manage (a Viewer can never
        // hold one anyway — the mint gate refuses — but the policy must
        // not rely on that).
        assert!(allowed(&def, CommitRole::Viewer, &scope).is_err());
        // A different collection's def stays out of reach.
        let other_def = format!("meta/collections/{other}.json");
        assert!(allowed(&other_def, CommitRole::Editor, &scope).is_err());
        // A non-UUID entry under meta/collections is not a collection
        // def: falls through to the Admin row and is denied.
        assert!(allowed("meta/collections/notes.txt", CommitRole::Editor, &scope).is_err());
        // Legacy/personal scope (empty) denies everything on the path.
        assert!(allowed(&def, CommitRole::Editor, &CollectionScope::none()).is_err());
    }

    #[test]
    fn manage_review_fixes_deletion_own_wrap_and_shapes() {
        let cid = uuid::Uuid::new_v4();
        let def = format!("meta/collections/{cid}.json");
        let wrap = format!("meta/collections/{cid}/{MA}.wrap");
        let mut scope = scoped("deadbeefdeadbeefdeadbeefdeadbeef", cid, &[cid]);
        scope.managed = vec![cid];

        // Review F2: def DELETION is never delegated — removing it kills
        // the collection's grant list. Wrap deletion stays within manage
        // authority (revoke removes wraps).
        assert!(allowed_del(&def, CommitRole::Editor, &scope).is_err());
        allowed_del(&wrap, CommitRole::Editor, &scope).unwrap();

        // Review F5: a member's OWN wrap is self-service at any role —
        // identity rotation rewrites it, and the Admin row would
        // otherwise wedge every grantee's rotation. No manage grant
        // needed (empty scope); someone else's wrap is not self-service.
        allowed(&wrap, CommitRole::Viewer, &CollectionScope::none()).unwrap();
        let other_wrap = format!("meta/collections/{cid}/{}.wrap", uuid::Uuid::new_v4());
        assert!(allowed(&other_wrap, CommitRole::Editor, &CollectionScope::none()).is_err());

        // Review F6: exact shapes only. Loose subpaths and extension
        // games fall through to the Admin row.
        let loose = format!("meta/collections/{cid}/sub/payload.enc");
        assert!(allowed(&loose, CommitRole::Editor, &scope).is_err());
        let deep_def = format!("meta/collections/{cid}.json/extra");
        assert!(allowed(&deep_def, CommitRole::Editor, &scope).is_err());
        let no_ext = format!("meta/collections/{cid}");
        assert!(allowed(&no_ext, CommitRole::Editor, &scope).is_err());
    }

    #[test]
    fn group_paths_are_admin_with_own_gkwrap_self_service() {
        let gid = uuid::Uuid::new_v4();
        let def = format!("meta/groups/{gid}.json");
        let own_gkwrap = format!("meta/groups/{gid}/{MA}.gkwrap");
        let other_gkwrap = format!("meta/groups/{gid}/{}.gkwrap", uuid::Uuid::new_v4());
        let ckwrap = format!("meta/groups/{gid}/{}.ckwrap", uuid::Uuid::new_v4());

        // S4-2: group defs, other members' gkwraps, and ckwraps are
        // Admin surface (membership changes rotate the group key).
        assert!(allowed(&def, CommitRole::Editor, &CollectionScope::none()).is_err());
        allowed(&def, CommitRole::Admin, &CollectionScope::none()).unwrap();
        assert!(allowed(&other_gkwrap, CommitRole::Editor, &CollectionScope::none()).is_err());
        assert!(allowed(&ckwrap, CommitRole::Editor, &CollectionScope::none()).is_err());

        // The member's OWN gkwrap is self-service at any role (identity
        // rotation), and the .gkwrap suffix is what admits it — a
        // ckwrap named like a wrap cannot ride this rule.
        allowed(&own_gkwrap, CommitRole::Viewer, &CollectionScope::none()).unwrap();
        allowed(&own_gkwrap, CommitRole::Editor, &CollectionScope::none()).unwrap();
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
