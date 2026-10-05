# Plan: Family Spaces

Status: In review (one external review round folded in)
Date: 2026-10-05
Author: Esteban
Related: docs/plan-sharing.md (closed design record), docs/plan-merged-search.md (G24), D59-D78 in docs/software-architecture-decisions.md

## 1. Problem

A family Space is not a small organization. Treating it like one makes the product wrong in both directions: it gives families the friction of an org (switch vaults to find the Wi-Fi password) and lacks the machinery families actually need, because families change in ways companies do not.

The events a family Space must survive, from the product owner: couples separating or divorcing while shared items outlive the relationship; members who no longer want to be part; children growing up, leaving, and founding their own family; a parent passing away with uninterrupted control for the survivor; adoption and new members arriving; and two main admins — both parents controlling the family vault as equals.

Breaking changes are explicitly permitted. Baluard is pre-release with a single dogfooder: vault format, markers, member files, the index, and the creation flow may all break.

## 2. Model: a purpose flag on the unflipped shape

A family Space is a vault that has NOT flipped to team shape, carrying a recorded purpose. The round-1 review caught the plan's deepest error here: a flipped team shape puts flat entries behind admin-only policy and takes the Root Key away from member devices entirely, so a kid could never read the Wi-Fi password and the G24 merge set would be nearly empty. The intended family default is the unflipped shape, where every member holds the Root Key and can decrypt everything — which is exactly what a family is.

Purpose lives in plaintext `meta/settings-pub.json` beside the existing `"space": true` pair flag (`space.rs:45`), not in the shape marker: it must be readable while locked (G24 chips classify without decrypting), it is admin-write enforced by the existing `meta/**` sync row, and the shape marker file does not exist before a flip. The field is `"purpose": "family" | "org"`. `"space": true` stays what it is today — the two-person couple cap (`space.rs:119` refuses a third member and Owner/Admin invites); a family vault is not a pair vault.

Purpose changes are Owner-initiated and quorum-gated — a purpose any admin could flip is a policy-downgrade path. The round-1 review corrected its own G24 advice: purpose is now justified to store because it has four consumers (merge defaults, minors, kit, departure), and `personal_merge` becomes an optional override whose absence follows the purpose. Changing purpose never rewrites an explicitly set knob.

## 3. Two main admins: the second parent at Admin rank

The plan dropped true co-ownership after pricing it. The single-owner invariant is load-bearing in six places the round-1 review verified: `remove_member` refuses Owner rows outright (`members.rs:324`, "the owner row cannot be removed"), two Owner rows are treated as a crash artifact (`transfer_ownership` heals them by demoting, `handle.rs:3079`), `commit_ownership_swap` is hard-wired to one old and one new row, kit recovery binds to the first live Owner row it finds (`handle.rs:733`), provider seat logic assumes the Owner row owns the repo (`state.rs:2851`), and there is no role-change route to mint a second seat with. Owner rank over Admin adds only: removal protection (weaker than it looks — `member_reset` accepts Owner targets and the successor inherits the role, D61), transfer initiation, the `space_invite_authority = owners` check, and the repo-owner assumption.

Admin rank already delivers "two main admins" in every way that matters: both parents manage members, the kit, root rotation, space settings, collections, migration, and quorum asks. So the family model is: the founding parent is Owner; the co-parent is invited as Admin (Admin invites exist today, `members_invite`); the D61 succession path — admin reset of the Owner row, successor inheriting the role — is the takeover story. The asymmetry that remains (only the Owner row initiates transfer) is acceptable until it bites; revisit then.

## 4. Quorum: default 1, opt-in 2 only after the contest window

The round-1 review killed the plan's quorum-2 default with the widow journey: `quorum_gate` reads the stored knob with no cap by live admins (`handle.rs:414`, `required = quorum_admin_ops.unwrap_or(1).max(1)`), so at 2 a dead parent's seat blocks every gated op — removal, reset, transfer, claim, rotation, revocation, even lowering the threshold itself — and the kit cannot rescue it because approvals are signed by the member identity key a recovered device does not hold. D61 recorded exactly this boundary and deferred the fix.

Family default: `quorum_admin_ops = 1`. A parent acts alone; the surviving-parent journey runs `member_reset` on the deceased's row at quorum 1 and inherits the seat. Raising the bar to 2 becomes available only once the D61 contest window ships (a raised ask notifies all target devices and executes after roughly 30 days unless vetoed — explicit action plus notice, not liveness tracking). Contest window: v1.1, with quorum 2 as the opt-in it unlocks.

## 5. Membership states: the minor flag

Member files gain `minor: bool` (default false; a breaking format change is fine). It is a guardian-controlled flag, never an age claim: no birthdates, no verification, ever.

A minor member cannot self-leave without an Admin confirming the request, cannot be promoted to Admin, cannot claim ownership, cannot use the kit, and cannot approve quorum asks. A minor can always file a leave request — it executes when a parent confirms, so a forgotten flag cannot trap an adult child. Joining rides the existing invite flow; `transport_username` is already optional, so a child without email joins by code alone. The G24 join notice about merged family items applies to minors too.

## 6. Departure: a leave record executed by an admin

There is no `members.leave` today, and the round-1 review showed the naive route cannot work: `member_remove` requires an Owner/Admin caller, refuses self-removal (`handle.rs:2936`), runs under the quorum role gate, and in flipped shapes a plain member holds no keys to rotate. If the leaver authored the rotation they would author the new keys — the remaining admins must run it.

Design: the departing member writes a signed leave record into their own member subtree (`meta/members/<id>/`, the policy row whose writer is `Any`), then their surfaces show "waiting for a parent to finish". Any admin device executes the standard removal on its next unlock or sync: provider seat strike, SGK rotation, tombstone with reason `left`. The D73 notice wording differs by reason: "you left" versus "you were removed". Minors file the same record; the admin confirmation is the parent's say. Enrollment proofs and old-epoch keys die at the rotation (D78 proofs are epoch-matched). Org Spaces keep admin-only removal.

## 7. Kit and repo rules

Two round-1 findings need rules because the kit bypasses quorum by design and the repo outlives people:

- The kit is permanent possession of whoever holds the phrase (D64), and kit enable-over-existing and kit disable are today only role-gated (`handle.rs:604-628`) — one parent could silently replace the family's only kit with a phrase only they know. Rule: kit disable and kit enable-over-existing require both parents' confirmation once a second admin exists (a quorum-style ask), and any parent's departure or death forces kit re-issue — a brand-new phrase, not a rewrap — so a leaver never retains a permanent backdoor.
- Provider seats and strikes act with the acting device's token, and the repo lives in someone's account. When the repo-owning parent departs or dies, the survivor runs `space.migrate` (exists, admin-gated) to move the Space to their own account; the departure checklist and the succession checklist both name it.

## 8. Lifecycle matrix

Arrival (a new spouse, an adopted child, a grandparent): the existing invite code, join queue, and `join_approval: manual|code` cover it unchanged. Minors join with the flag set by the inviting parent.

Growing up: a parent flips `minor` to false. No crypto event.

Founding their own family: create a new family Space, copy out what is yours (section 9), then file the leave record.

Separation or divorce: no automatic split — shared encrypted blobs do not divide, and pretending otherwise sells a false settlement. The leaving parent transfers ownership first if they are the Owner (`transfer_ownership` exists), then files the leave record; the rotation removes their access and the notice says "you left". Kids' shared logins live in a collection or a small kids Space granted to both parents, so custody of access is a grant question, not a membership question. A new partner after a death or a divorce is a normal invite; the ex's departure follows the same record.

Death of a parent: co-admin family — the survivor acts alone at quorum 1: `member_reset` on the deceased's row (the successor inherits the role, D61), kit re-issue, and `space.migrate` if the repo was the deceased's account. Sole-parent family — the kit is the answer, which is why family creation makes it mandatory: the 24-word phrase in the safe, shown once, surviving root rotation by rewrap (`recovery_kit.rs:151`). A relative holding the kit recovers a device bound to the deceased's Owner row, then transfers ownership to their own row (the grandparent journey, documented in the kit flow). Both parents gone: the kit phrase lives wherever the family's most important paper lives. Baluard makes the kit excellent; it does not detect death.

Stolen device (the most common real event, not a departure): `member_reset` for a lost member device, `device_revoke` for a lost admin device — both exist, both are quorum-gated, both run at quorum 1.

An invited co-parent who never joins: the quorum and admin-count assumptions rise only when the second admin actually joins, never at invite time; unclaimed invites expire.

Private items inside a family vault: not possible by construction — unflipped members all hold the Root Key. The creation flow says so plainly: what must stay private lives in the personal vault.

A personal vault never converts into a family Space: `space_flip` is refused for the personal vault (the round-1 review flagged the plan's earlier flip-row as converting private items into family items); the path is "create a Space and copy what you choose".

## 9. Taking your things

The departure UX (self-leave and admin removal dialogs) carries a checklist step: copy what is yours before you go. Family purpose defaults `allow_viewer_export` to true so a departing member can run the encrypted `.bldbak` export of what their keys reach; guest reveals remain available for one-off handovers (`guest_enabled` stays opt-in as shipped). After the rotation lands, copies are the leaver's and the family's items stop updating for them — stated in the dialog.

## 10. Creation flow

1. Name the Space and pick the purpose (family highlighted alongside org; the pair flag keeps its own two-person flow).
2. Invite the co-parent as Admin (code plus display name; skippable — a single parent runs the family alone, with the kit carrying the succession).
3. Recovery kit: mandatory for family purpose. Show 24 words once, require the saved acknowledgment.
4. Quorum stays 1; the settings row explains that 2 arrives with the contest window.
5. `personal_merge` follows the purpose default with the G24 join notice; every member sees it.
6. Members: children with the minor flag (Viewer or Editor), other adults as needed, each with the same join notice.

## 11. Non-goals

No death detection, inactivity triggers, or automatic succession — any liveness tracking is surveillance of family members; co-admin plus kit are the answers. No automatic asset division on divorce; the product provides departure, rotation, and copies, and stays out of the settlement. No age verification — `minor` is a parent-managed flag. No new cryptographic primitives: the key hierarchy, kit escrow, quorum asks, reset path, and removal rotation carry everything. No changes to org Spaces beyond what G24 already plans. No private items inside the family vault, stated rather than built.

## 12. Tests

Core: purpose flag roundtrip in `settings-pub.json` (and its relationship to `is_space_vault`); owner reset with successor inheritance on a family vault; kit re-issue forced by parent departure; kit disable/enable-over confirmation with a second admin; leave record written, executed by an admin, refused for a minor without confirmation; rotation after leave with reason `left` in the notice; minor gates (promotion, claim, kit, quorum); unflipped-shape merge set equals full member reads; `allow_viewer_export` purpose default; personal-vault flip refusal.

Route coverage: `members.leave` (record write), leave execution on admin unlock/sync, purpose in `space.status`, the kit confirmation ask, `space.migrate` on the succession checklist path.

E2E: the widow journey — survivor resets the deceased's seat at quorum 1, kit re-issued, family continues; the divorce journey — transfer ownership, leave record, admin executes, seat struck, "you left" notice on next pull; the growing-up journey — flag flip, leave request, confirmation, new family Space creation; the stolen-tablet journey — member reset by one parent alone.

## 13. Landing order

1. Purpose flag in `settings-pub.json` + member `minor` flag (format breaks, migration-free).
2. `members.leave` record route + admin-side execution + notice wording by reason.
3. Kit rules: confirmation ask, departure-forced re-issue, kit-mandatory creation step.
4. Family creation wizard (purpose question, Admin co-parent invite, kit, notices) + personal-vault flip refusal.
5. G24 wiring: purpose sets the `personal_merge` default and the family default export permission.
6. v1.1: the D61 contest window, unlocking quorum 2 as a family opt-in.
