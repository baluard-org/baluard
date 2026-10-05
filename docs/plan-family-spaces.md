# Plan: Family Spaces

Status: In review (two external review rounds folded in)
Date: 2026-10-05
Author: Esteban
Related: docs/plan-sharing.md (closed design record), docs/plan-merged-search.md (G24), D59-D78 in docs/software-architecture-decisions.md

## 1. Problem

A family Space is not a small organization. Treating it like one makes the product wrong in both directions: it gives families the friction of an org (switch vaults to find the Wi-Fi password) and lacks the machinery families actually need, because families change in ways companies do not.

The events a family Space must survive, from the product owner: couples separating or divorcing while shared items outlive the relationship; members who no longer want to be part; children growing up, leaving, and founding their own family; a parent passing away with uninterrupted control for the survivor; adoption and new members arriving; and two main admins — both parents controlling the family vault as equals.

Breaking changes are explicitly permitted. Baluard is pre-release with a single dogfooder: vault format, flags, member files, the pair gate, and the creation flow may all break.

## 2. Model: a purpose flag and a decoupled pair gate

A family Space is a vault that has NOT flipped to team shape, carrying a recorded purpose. Round-1 review established why the shape is unflipped: a flip takes the Root Key from member devices and hides flat entries behind admin-only policy, so a kid could never read the Wi-Fi password. Every family member holds the Root Key and can decrypt everything — which is what a family is, stated plainly: there is no cryptographic compartmentalization inside the family vault. Collections organize; they never conceal. Private items live in the personal vault, and custody boundaries that must be cryptographically real need separate Spaces.

Round-2 review caught the flag collision: the existing `"space": true` plaintext flag means the two-person couple (`pair_gate` caps live members at 2 and refuses Owner/Admin invites, `space.rs:119`), and `is_space_vault` drives registry metadata and transfer demotion (`host.rs:323`, `members.rs:418`). Reusing it for family is impossible; ignoring it makes the family vault invisible as a Space. The break: `"space": true` comes to mean any shared vault, the two-person cap moves under `purpose: "pair"`, and family and org set `purpose: "family" | "org"` in the same file. Purpose lives in plaintext `meta/settings-pub.json` because locked surfaces (G24 chips) must classify without decrypting.

Purpose is written by an Owner-only route — the round-2 review correctly rejected calling this quorum-gated, because `settings-pub.json` carries no approval envelope a quorum gate could check; the honest v1 enforcement is the route's role gate, with structural delta validation as future work. `personal_merge` (G24) stays the enforcement knob and remains an optional override: absent, it follows the purpose.

## 3. Two main admins: the second parent at Admin rank

The plan dropped true co-ownership after pricing it against the single-owner invariant, which round-1 review verified as load-bearing in six places: Owner rows refuse removal (`members.rs:324`), two Owner rows are healed as a crash artifact (`handle.rs:3079`), the ownership swap is hard-wired 1:1, kit recovery binds to the first live Owner row, provider seat logic equates the Owner row with the repo owner, and no role-change route exists. Admin rank already manages members, the kit, rotation, space settings, collections, migration, and quorum asks — both parents hold full practical control. Family purpose also maps `space_invite_authority = owners` to admit Admins, so the Admin co-parent can always invite the children.

Round-2 review corrected the succession mechanism, overturning round 1: `member_reset` is NOT takeover. It tombstones the target row and mints a successor row carrying the TARGET's role for the target to rejoin as themselves — the caller's role never changes (`members.rs:274`). Resetting a dead parent would leave a dangling unbound Owner invite. The real takeover is `ownership_claim(survivor_id)` (Admin-only, `handle.rs:3190`), which swaps the roles, after which the deceased's demoted row can be removed normally. The widow journey is: claim, remove, re-issue the kit, migrate the repo if needed.

One asymmetry is accepted and documented: at quorum 1 an Admin can claim ownership from a live Owner without consent, and an Owner can remove an Admin outright — in a hostile separation, whoever acts first wins. The round-2 mitigation (a notice window on claims against a live Owner) ships with the v1.1 contest window; until then the family purpose surfaces a plain warning on the claim screen, matching the honest-client posture recorded in D63.

## 4. Quorum: default 1, opt-in 2 only after the contest window

`quorum_gate` reads the stored knob with no cap by live admins (`handle.rs:414`), so a quorum-2 default deadlocks the widow journey at the plan's own settings — and the kit cannot rescue it, because round-2 review verified kit recovery demands the vault master password against the KEK canary. Family default: `quorum_admin_ops = 1`, and `space_settings_set` refuses values above 1 on a family Space until the contest window ships, so the deadlock cannot be configured today. Raising to 2 unlocks in v1.1 behind the contest window (an ask notifies all target devices and executes after roughly 30 days unless vetoed — explicit action plus notice, never liveness tracking).

## 5. Membership states: the minor flag

Member files gain `minor: bool` (default false; a breaking format change). It is a guardian-controlled flag, never an age claim: no birthdates, no verification, ever. A new Admin-only route `members.set_minor` flips it, and the sync member-record validator pins the flag (`minor` may not change during routine identity rotations) so no non-admin signer can self-clear it.

A minor member cannot be promoted, cannot claim ownership, cannot use the kit, cannot approve asks, and cannot transfer-own (the transfer route refuses minor targets — round-2 review caught the gap). Children join as Viewers by default; Editor is a deliberate parent choice, made with the knowledge that on an unflipped vault an Editor can modify and trash any family cipher. A minor files a leave request, but nothing executes without an Admin approving it (section 6).

Scoped child editors (planned): the product owner asked for children who can edit the entries they can see, with permissions. Today the cipher-write role floor blocks it - a Viewer with a write grant still cannot write ciphers (policy.rs:464 pins the rule), so the only choice is all-or-nothing Editor. Family purpose adds one policy rule: a write grant on a collection lifts the role floor for cipher writes inside that collection only. The child's own entries live in a Kids collection; a parent grants Write; the child edits there and nowhere else. Grants stay admin-minted, so no self-escalation exists, and the read side changes nothing - the child already sees everything on the unflipped shape, as every member does.

The orphan escape: possession of the kit phrase clears the minor flag. If both parents are gone, the adult child recovers a device with the safe-deposit phrase and the flag falls with it — a forgotten flag can never trap anyone who holds the phrase, and the phrase was already the family's root authority by D64's design.

## 6. Departure: an approved leave record

There is no self-leave today, and both review rounds converged on why the naive designs fail: `member_remove` requires an Owner/Admin caller and refuses self-removal; a leaver must never author the next epoch's keys; and round-2 review killed silent background execution — two admin devices auto-executing the same leave record would run competing root rotations (split-brain), and an offline unlock would hang on the 20-second seat strike.

Design: the departing member writes a signed leave record into their own member subtree (`meta/members/<id>/`, the Any-writer policy row). Every admin surface shows a pending-departure notification; an Admin explicitly approves, and that single execution runs the standard ceremony: seat strike, SGK rotation, tombstone with a coarse reason (`left` versus `removed` — reasons stay neutral by design; git history is forever). Until approval, the leaver sees "waiting for a parent to finish". Minors file the same record; the Admin approval is the parental say — one flow, no contradiction. `members.leave` refuses the Owner row until ownership is transferred, so an approval can never die on the "owner rows cannot be removed" guard. Org Spaces keep admin-only removal, which is the friction the product wants.

## 7. Kits and the repo

Round-2 review found the current kit recovery cannot serve the family as built: it derives the KEK from a typed master password and verifies the KEK canary before anything (`handle.rs:714-730`), so a grandparent holding only the safe-deposit phrase fails — and recovery binds to the first live Owner row, refusing when that row is gone (`handle.rs:735`). The family redesign: phrase-only recovery for family Spaces. The 24 words unwrap the Root Key (they already are the root authority, D64); the recovering device mints its own fresh master password and keystore, binds to any live Admin row (or, with none, takes the Owner seat as the personal-vault recovery path already does), and clears the minor flag per section 5. The KEK-canary check exists to catch a mistyped password before minting a keystore; phrase-only recovery replaces that gate with the phrase itself and is strictly for the family purpose.

Kit rules: enabling over an existing kit or disabling one requires confirmation from the other admin once a second admin exists, with confirmations counted over currently-live non-tombstoned rows only — the widow journey (claim, remove, re-issue) reduces the live-admin count to 1 before the re-issue, so no deadlock. Any parent's approved departure or the succession journey forces a kit re-issue with a brand-new phrase, so a leaver never retains a permanent backdoor.

The repo outlives people: seats and strikes act with the acting device's token, so when the repo-owning parent departs or dies, the survivor runs `space.migrate` (exists, admin-gated) to move the Space to their own account. Both the departure and succession checklists name it.

## 8. Lifecycle matrix

Arrival (a new spouse, an adopted child, a grandparent): the existing invite flow, join queue, and `join_approval: manual|code` unchanged. Minors join flagged by the inviting parent; the family purpose ensures the Admin co-parent can invite regardless of `space_invite_authority`.

Growing up: a parent flips `minor` off via `members.set_minor`. No crypto event.

Founding their own family: create a new family Space, copy out what is yours (section 9), file the leave record.

Separation or divorce: no automatic split — shared encrypted blobs do not divide, and the whole vault is visible to both parents by design, which the creation flow states. The leaving parent transfers ownership first if they hold it, files the leave record, and the other parent approves; rotation removes access and the notice says "you left". Both-stay co-parenting is the parents' call. Collections do not guard items from a member (section 2), so custody of kids' logins that must be cryptographically separated means a separate kids Space granted to both parents — a grant question across Spaces, never a membership flag inside one.

Death of a parent: the survivor claims ownership, removes the deceased row, re-issues the kit, and migrates the repo if the deceased owned it — all at quorum 1, all with keys the survivor already holds. Sole-parent family: the phrase-only kit recovery of section 7 is the path, and family creation makes the kit mandatory. A relative recovering binds to a live Admin row or takes the Owner seat, then may claim. Both parents gone: the kit phrase lives wherever the family's most important paper lives.

Stolen device: `member_reset` for a lost member device, `device_revoke` for a lost admin device — both quorum-gated, both fine at quorum 1.

An invited co-parent who never joins: admin-count and kit-confirm assumptions rise only when the second admin actually joins; unclaimed invites expire.

## 9. Taking your things

Round-2 review rejected the plan's export default: `.bldbak` and JSON export dump the entire vault, so `allow_viewer_export` must NOT default true for family — a departing member would walk away with the parents' banking logins. Departure offers instead: per-item handovers through guest reveals (opt-in as shipped), and a one-time admin-granted full export only with a prominent whole-vault warning. A selective "copy these items to my vault" flow is future work and the real answer; the checklist names it as such.

## 10. Creation flow

1. Name the Space and pick the purpose (family highlighted; org beside it; the couple keeps its two-person flow under `purpose: "pair"`).
2. Invite the co-parent as Admin (code plus display name; skippable for a single parent, with the kit carrying the succession).
3. Recovery kit: mandatory for family purpose. Show 24 words once, require the saved acknowledgment; the phrase-only recovery semantics of section 7 apply.
4. Quorum stays 1; the settings row explains that 2 arrives with the contest window.
5. `personal_merge` follows the purpose default with the G24 join notice for every member.
6. Members: children as Viewers with the minor flag; other adults as needed.

A personal vault never converts into a family Space: the flip is refused, and the path is "create a Space and copy what you choose".

## 11. Non-goals

No death detection, inactivity triggers, or automatic succession — any liveness tracking is surveillance of family members; co-admin plus kit are the answers. No automatic asset division on divorce. No age verification — `minor` is a parent-managed flag. No new cryptographic primitives: the key hierarchy, kit escrow, quorum asks, reset path, and removal rotation carry everything; the only cryptographic change is gating the D78 enrollment-proof fallback to genuine single-admin personal vaults (section 12). No private items inside the family vault, stated rather than built. No changes to org Spaces beyond what G24 already plans.

## 12. Sync and enrollment safety

Round-2 review caught a live hole the family model would have widened: the D78 enrollment-proof fallback admits a commit's paths wholesale once the proof authenticates against the Root Key (`engine.rs:3629`, the `bootstrap_key.is_some()` early return), and its pull-path guard checks only the shape, not the member count. On an unflipped five-member family vault, any Root-Key holder — a Viewer child included — could phrase-enroll a device and then write any path, bypassing the `meta/**` Admin row. Fix: the fallback requires an absent member directory (a genuine single-admin personal vault). Family and org Spaces fail closed to the ordinary role table; phrase enrollment of new devices on shared vaults runs through the explicit invite flow, which is what a family wants anyway.

## 13. Tests

Core: purpose flag roundtrip and the decoupled pair gate (family invites a third member; pair still caps at two); ownership-claim succession on a family vault (claim, demoted-row removal, kit re-issue with live-admin counting); phrase-only kit recovery binding to an Admin row and clearing the minor flag; kit enable-over/disable confirmation with live-admin counting; leave record write, explicit approval execution, minor leave requiring approval, Owner leave refused until transfer; minor gates (promotion, claim, kit, quorum, transfer); `members.set_minor` route auth and the member-record delta pin; enrollment fallback refused when a member directory exists; children-as-Viewer default; personal-vault flip refusal; `space_settings_set` refusing quorum > 1 on family.

Route coverage: `members.leave`, leave approval execution, `members.set_minor`, purpose in `space.status`, kit confirmation ask, `space.migrate` checklist path.

E2E: the widow journey (claim, remove, kit re-issue, migrate); the divorce journey (transfer, leave record, approval, "you left" notice); the growing-up journey (flag flip, leave request, approval, new family Space); the stolen-tablet journey (reset by one parent); the grandparent journey (phrase-only recovery with no prior vault password).

## 14. Landing order

1. Flags: purpose + minor + the decoupled pair gate; `members.set_minor`; the minor delta pin; enrollment-fallback gating (format breaks, migration-free).
2. `members.leave` record route + pending-departure surface + admin approval execution + reason-based notices.
3. Kit work: phrase-only family recovery, live-admin confirmations, departure-forced re-issue, kit-mandatory creation step.
4. Family creation wizard (purpose question, Admin co-parent invite, children as Viewers, kit, notices) + personal-vault flip refusal.
5. G24 wiring: purpose sets the `personal_merge` default; the plan-merged-search consent section amended to record purpose.
6. v1.1: the D61 contest window, unlocking quorum 2, the claim notice window against live Owners, the selective item-copy departure flow, and scoped child editors (collection write grants lifting the role floor on family purpose, with policy tests pinning the scope).
