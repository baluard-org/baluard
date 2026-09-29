# Baluard: Organization Power Pack (S4)

Rev 1.0 (2026-09-28). Owner: Esteban. Status: **open, S4-1 already shipped**.

The sharing plan (`docs/plan-sharing.md`) is closed as of 2026-09-28: everything
up to and including S4-1 ships. This document owns all remaining sharing
work: the org power pack (S4-2 onward) plus the deferred personal-space
and parked items moved here (section 11), so the closed sharing plan
carries nothing pending.

Foundations this builds on (all shipped, see D-records in
`docs/software-architecture-decisions.md`):

- S4-1 quorum gate: `quorum_admin_ops` (default 1, raisable to 5) puts
  removals, resets, transfers, rotation, and sync-address moves behind N
  distinct admin approvals via plaintext `meta/approvals` records (D59).
- `collection_create_authority` (admins default, editors on demand).
- §6.5 knobs with surfaces on desktop + mobile.
- SMK flip (S3-7b): flipped members hold neither Root Key nor SGK.
- Member collection access (S3-7c): read scope equals key scope.
- Per-device activity log + refusal log + notices (S1b), surfaced on both
  platforms.

## 0. Scope at a glance

| # | Item | Size | Depends on |
|---|---|---|---|
| S4-2 | Groups as a key layer | L | Q6a confirm, S4-3 decision |
| S4-3 | Dual control resolution | S | Esteban call |
| S4-4 | Access review report | M | nothing (ships alone) |
| S4-5 | Full Activity timeline | M/L | design call (see 5) |
| S4-6 | Advisory org policies | S | nothing |
| S4-7 | Emergency × org × identity doc | S | nothing |
| S4-8 | Synthesized neutralization (revisit) | ? | Esteban restatement |
| S4-9 | Mobile multi-Space host | L | nothing |

## 1. S4-2 Groups as a key layer

Goal: grant a collection to a department instead of person by person. A group
holds a key; members of the group can open what the group can open.

Exists today: nothing. Groups appear in the plan as a one-liner only.

Design questions (none answered yet):

1. Key tier: a random Group Key per group, wrapped under the SGK for admins
   and per member-group identity wraps for members (the collection pattern
   again), or derived from the SMK? The collection pattern reuses proven
   mechanics (wrap mint, identity-rotation self-heal, removal cleanup) and
   keeps the SMK out of the equation; leaning there.
2. Storage shape: `meta/groups/<id>.json` with sealed name + member list
   (the CollectionFile pattern), wraps at `meta/groups/<g>/<m>.wrap`.
3. CollectionAccess gains a target kind: grants name a member id today; a
   group grant needs either a separate row or a reserved id space. Sync
   policy rows for `meta/groups/**` must exist before any group commit
   syncs.
4. Rotation: member leaves a group -> group rekey (collection-style, CK
   values invariant so member wraps survive) vs full collection rotation.
   Churn is the same rotation-driven growth the sharing plan already
   priced.
5. JIT asks against groups (S3-6 pattern) and role templates (S3-4) over
   groups: defer or ship together?
6. Surfacing: sidebar shows granted collections; groups need a management
   surface (desktop Collections tab extension or a new Groups tab; mobile
   deferred?).

Acceptance shape: admin creates a group, adds members, grants a collection
to the group, every group member reads/writes per the grant, leaving the
group rotates the group key without touching collection content keys, and
the two-vault ceremony proves it across devices.

## 2. S4-3 Dual control resolution

> **RESOLVED 2026-09-28 (see section 10): option (b) with an intrinsic
> ratchet — lowering the threshold requires approvals under the current
> threshold. First build item together with the Q5 owner-reset fix.**

The plan's entire dual-control spec is one line: "Dual control 2-of-2 XOR
(S4)". S4-1's N-distinct-admin approvals already express 2-of-2 (threshold 2)
and N-of-M. Options:

1. Declare dual control superseded by S4-1 at threshold 2 and delete the
   one-liner (cheapest; the knob exists).
2. Keep a "locked" variant: an org pins threshold 2 and surfaces forbid
   lowering it (a policy lock on the knob).

Needed from Esteban: pick 1 or 2. Nothing else blocks. → RESOLVED: 2, with
the ratchet intrinsic (no lock knob).

## 3. S4-4 Access review report

> **SHIPPED (2026-09-29, tracer; see D61's sibling record D62):** the
> aggregated report is live end to end — core `access_review`, the
> `access.review` route, the People-tab card with per-member expandable
> rows and JSON export, and the S4-8 exposure summary (removed/reset
> members' surviving grants listed as the rotation list). Mobile bridge
> method deferred; contact-key grants and outbox links (other devices'
> local state) stay out.

Goal: an admin answers "who can see what" in one place.

Exists today: the data is all there (collection grants with expiry, member
roles and tombstones, group grants once S4-2 lands, outbox links, contact
trust). Nothing aggregates it.

Design questions:

1. Scope: collections + roles only, or also outbox mirrors and contact-key
   grants? The outbox is item-level transport; a review that skips it
   understates exposure.
2. Output: on-screen report (People tab card, per-member expandable rows)
   vs export (JSON/CSV) vs both. Screens-first matches every prior wave.
3. Freshness: computed on demand on the admin device from disk state;
   no new persistence.

Acceptance shape: open the report, see per member: roles, collections with
access + expiry, pending asks, outbox mirrors; tombstoned rows greyed with
"kept bytes" note.

## 4. S4-5 Full Activity timeline

> **RESOLVED 2026-09-28 (see section 10): derived-only v1 — synthesized
> from verified signed git history; no shared event files, no read
> tracking. Builds last.**

Goal: one space-wide feed of who did what, instead of per-device logs.

Exists today: `meta/share-events.enc` is deliberately per-device and
gitignored (S1b-1), refusals are local, notices aggregate only
filesystem-derived facts. No device can read another device's event log.

This is the hard design question of the pack: a space-wide timeline needs a
synced events ledger, which reintroduces exactly what S1b avoided (commit
timing as a metadata channel, T14; event volume in git history). Options:

1. Shared ledger: member-emitted events commit to a git-tracked
   `meta/events.enc` under policy rows; every device appends its own
   subtree. Reads the S1b-1 pattern but makes events shared. Costs:
   history growth, timing exposure, policy work.
2. Derived-only timeline: aggregate what git history already proves
   (commits by device, roster changes, grant changes from collection file
   history) and render that. No new writes, weaker story ("your manager
   changed a grant" shows; "member X viewed an entry" never will).
3. Hybrid: derived-only v1, shared ledger as a later add-on.

Needed from Esteban: which story does 1.0 tell. Option 3 is the safe → RESOLVED: option 3
(derived-only v1).
default.

## 5. S4-6 Advisory org policies

> **SHIPPED (2026-09-29, tracer; see D63):** plaintext
> `meta/policies.json` on the meta/** Admin row, fail-closed validation
> over the shipped §6.5 knob table, `policies.set`/`policies.list`
> routes, desktop Space-tab publish/clear with per-row recommended
> hints, mobile hints showing only recommendations that differ.
> Advisory only — no gate reads the file for decisions.

Goal: a Space owner publishes recommended settings ("use Viewers without
export", "invite authority: owners") and member surfaces show them.

Design: plaintext `meta/policies.json` riding the meta/** Admin row
(same shape logic as the S3-6 catalog: existence is the setting, empty
publish is opt-out), surfaces render a "recommended" hint next to matching
settings. Advisory only, never enforced (enforcement is the shipped knobs).
No new crypto, one route pair, one card per platform.

## 6. S4-7 Emergency × org × identity doc

> **SHIPPED (2026-09-29, tracer; D64 + D65):** the doc landed as
> `docs/emergency-org-identity.md`; the Space Recovery Kit core shipped
> (enable/disable/status + rotation rewrap in both paths + phrase
> unwrap, tested); the recovery ceremony shipped the same day —
> `recover_device_with_kit` (canary verified, registry entry, binding
> to the live Owner row, brick guard), host-level `vault.recover_kit`,
> admin-gated `space.kit_*` routes, the desktop Space settings kit
> section, and the CLI disaster path (`vaults recover-kit`). Deferred:
> login-screen recovery UI on desktop, any mobile recovery surface.

Goal: one design doc tying the three layers together.

Exists today: `emergency.rs` is core-wired (both rotation paths rewrap the
escrow through `orgs::wrap_to_bundle`) but has no routes, CLI, or UI; the
identity is keystore/recovery-sealed with rotation and trust resets (S1a).

The doc must answer: what does emergency recovery mean in a Space (a
recovered device lands as the owner device? as a member?), who approves
recovery in an org (owner incapacitation is the whole scenario), and how
the escrowed Root Key interacts with the flip (escrow wraps the Root Key;
flipped members never hold it; a recovered owner device unlocks as an
admin and converges). Doc-only deliverable; route decision deferred.

## 7. S4-8 Synthesized neutralization (revisit)

> **RESOLVED 2026-09-28 (see section 10): dropped as an independent
> item. Its operational purpose folds into S4-4 as the offboarding
> exposure summary (flag credentials a removed member could read for
> rotation).**

The plan carries this as a bare one-liner with no design, no scenario, and
no code reference anywhere. Needed from Esteban: restate what it meant → RESOLVED: dropped as a
crypto item; the purpose folds into S4-4 (see section 10).
(suspected origin: neutralizing a compromised member's knowledge via
rotation, "synthesized" from the recovery path), or drop the line.

## 8. S4-9 Mobile multi-Space host

Goal: the phone holds several vaults (personal + Spaces) like the desktop
VaultHost does since Phase 6.

Exists today: uniffi exposes per-vault lifecycle; the mobile app opens one
vault at a time. `VaultHost` (multi-vault map + active pointer, 30s
auto-lock walker) is desktop-side.

Design questions:

1. OOM: the Android `:autofill` process forbids master-password Argon2id
   (64-256 MB per unlock). A phone holding N unlocked Spaces must budget
   KDF work and resident keys (the mlock budget log exists desktop-side);
   likely rule: one Argon2id at a time, other vaults stay locked until
   switched.
2. Bridge shape: a `MobileVaultHost` uniffi object over the runtime
   `VaultHost`, or app-level coordination over existing per-vault exports?
3. UI: the vault switcher exists on the unlock screen; multi-unlock needs
   switch-without-lock vs lock-on-switch decisions.

Size L; independent of every other item; can go any time.

## 9. Cross-cutting debt (tracked here, small)

1. Desktop `VaultView` gates the ask button on a row-counting `myAccess`
   proxy; should read `is_admin_device` like mobile does (wave-29 fix).
2. Thin quorum-rotation test coverage on a flipped vault (threshold 2 +
   rotation + member unlock in one ceremony).
3. Mobile pending-approvals card: SHIPPED — wave-37 renders the pending
   list in mobile Settings beside the quorum knob (the `approvals_list()`
   bridge has a UI row); nothing pending.

## 10. Open questions (moved from sharing plan §10) — RESOLVED 2026-09-28

All five were resolved 2026-09-28 by an adversarial design review under
Esteban's directive: resolve them in the most secure way that stays easy
for end users; anything heavier exists but is disabled by default,
configured by the primary admin. Code claims in the review were verified
against source before adoption. Decisions:

1. **Q5 recovery — CONFIRMED with a fix.** The shipped reset/transfer
   flow stands, but the Owner lockout in `members.rs` ("the owner row
   cannot be reset") closes: an Admin can reset an incapacitated Owner
   and claim ownership, both riding the existing quorum gate (default 1
   = instant; threshold 2 = a second admin co-approves). Opt-in Space
   Recovery Kit: Root Key escrowed to an offline phrase for the physical
   safe, covering sole-admin total loss. Implementation design LOCKED
   (§13): reset serves owner-returns; a dedicated `ownership_claim` over
   a shared commit helper serves owner-gone; the transfer gate stays
   untouched.
2. **Q6a identity pivot — CONFIRMED permanent.** One personal vault per
   human holds the identity; Spaces carry zero master passwords. A
   departing member keeps personal data; company data locks.
3. **S4-3 dual control — RESOLVED (b), ratchet intrinsic.** Quorum
   threshold 2 IS dual control (shipped, S4-1/D59). Lowering the
   threshold requires approvals under the CURRENT threshold, so a rogue
   admin cannot drop 2 back to 1 alone. No separate lock knob: with
   quorum 1 the lock is meaningless and the knob would only add a state.
4. **S4-5 timeline — derived-only v1.** The space-wide feed synthesizes
   from verified signed git commit history (topological order primary,
   timestamps display-only). Zero new git-tracked event files, zero read
   tracking ("reads leave no trace" preserved). Audit export rides S4-4.
5. **S4-8 neutralization — DROPPED as a crypto item; folded into S4-4**
   as the offboarding exposure summary: after removal, admins see every
   credential the departing member could read, flagged for rotation.
   Read data cannot be un-read; the passwords themselves get changed.

**Default doctrine (the family preset decision)**: no new `family` vault
shape — the shape drives the unlock path and Root Key distribution, and a
third shape is invasive. A family is a Space created through a **Family
preset**: `join_approval` set to `code` at creation (invite code
auto-approves; nobody waits on a sofa; the serde default stays `manual`),
adults admin, kids editor/viewer, guests on, zero settings screens.
Organizations use today's shipped defaults (quorum 1, manual approval,
admins invite, admins create collections, viewer export off, editors
trash, admins restore) with zero configuration. The advanced tier
(quorum 2..5, owners-only invites, Recovery Kit) lives in Space settings,
off by default, flipped by the primary admin.

## 11. Deferred and parked (not org scope; tracked here so the closed plan carries nothing pending)

**S5, personal-space scope, deferred in full**: personal areas (a member's
private corner of a shared vault; today personal means admin-only flat
ciphers), per-item ACL exception (one item shared outside its collection),
IS-4 inline item keys (cut; revisit only if users ask by name), travel
mode, P2P send, provider discovery, per-member theme/language preferences.

**Parked scenario items (no phase)**: `space.export` / `space.sever`
(clean split of a Space into or out of a vault; sharing plan §5.F-2) and
the out-of-band adopt link + cold mirror (§5.F-7; the re-bind itself
shipped as S3-8 remote migration, what remains is the link-style UX and
the mirror).

**P5 plumbing remainder**: SHIPPED (2026-09-28, tracer; see D60 in
`docs/software-architecture-decisions.md`) — explicit staged path sets
landed: the writer stages only what its policy admits, admission context
resolves from the HEAD tree via the verification walks' own helpers,
merge commits stage the authenticated merge output (the P8a residue
check governs), skipped paths revert in the worktree, and genesis admits
all. This closes the last open P item; the sharing plan carries nothing
pending.

**Parked past 1.0 (tracked in progress.md, listed for completeness)**:
iOS Phase 7 + sharing parity, recovery-key export (TXT/MD/PDF), browser
extension Phase 2, 2FA tiers 2-5.

## 12. Suggested build order (updated for the 2026-09-28 resolutions)

1. **S4-3 ratchet + Q5 owner-reset fix** (S) — SHIPPED (2026-09-28,
   D61; spec: §13).
2. **S4-4 access review report** (M) — SHIPPED (2026-09-29, D62;
   carries the S4-8 exposure/rotation filter).
3. **S4-6 advisory org policies** (S) — SHIPPED (2026-09-29, D63).
4. **S4-7 emergency × org doc + Space Recovery Kit** (S) — SHIPPED (2026-09-29, kit core + doc; the enrollment ceremony is its own follow-up slice).
5. **S4-9 mobile multi-Space host** (L, parallelizable).
6. **S4-2 groups as a key layer** (L, the headline item; Q6a confirmed,
   design leans on the collection pattern).
7. **S4-5 derived timeline** (M/L) — last; the synthesis engine over
   commit history.

## 13. First-wave build spec: Q5 owner recovery + S4-3 ratchet (locked and SHIPPED 2026-09-28)

The reviewed design for §12 item 1, settled by a second adversarial
review round whose code claims were source-verified, then built as
specified (D61) with one review-driven amendment: the claimant id is an
explicit parameter that travels in the ask's params, so a co-approver
can repeat the SAME ask from the pending card. Two separate ops,
no widening of the voluntary transfer gate.

**Two ops, two scenarios.** `member_reset` gains Owner targets for admin actors (the owner-row refusal in `members.rs` lifts for Owner/Admin callers; the quorum gate is already on the op): the successor row inherits the Owner role, so an owner who returns rejoins as self — the family path. A NEW `ownership_claim` core op covers owner-gone-forever: ownership moves to the claiming admin's EXISTING row, old owner demoted. `transfer_ownership` stays untouched (Owner-actor-only, S1a-7 gate intact).

**Shared helper.** `commit_ownership_swap(vault_path, old_id, new_id)` is a pure record mutator with zero authorization inside: validate old ≠ new, old row is a live Owner, new row exists and is live; promote FIRST (role Owner + trust SelfTrust), demote SECOND (Editor on pair Spaces per S2 IS-5 — pair Spaces have no admins and a demoted Admin would wedge later resets; otherwise Admin; SelfTrust resets to Verified). Promote-first is load-bearing: a crash between the writes leaves two owners (recoverable by re-run), demote-first bricks the vault. The single-Owner invariant lives here only, tested once.

**ownership_claim ordering and params.** Unlocked → `assert_can_manage_members` → disk-backed actor check `Some(Admin)` ("only an admin can claim ownership") → `owner_member_id` present → refuse self-claim → `quorum_gate("ownership_claim", json!({"old_owner_id", "new_owner_id"}))` → helper → new `ShareEventKind::OwnershipClaimed`. The digest binds BOTH ids so an approval cannot replay across a changed owner. No provider seat work: Owner and Admin both map to Write, and no offboarding happens, so no strikes, no pre-flight.

**Surfaces and semantics.** Contextual single button per actor: an owner sees Transfer; an admin viewing the owner row sees Take Over Ownership; nobody sees both (desktop PeopleTab + mobile PeopleScreen, new `members.claim` route arm, state wrapper, allowlist, uniffi bridge for mobile parity). Threshold 1 means the claim is instant — the family floor; raising the knob is the org's dual control. A contest window (owner-device notice + cancel) is an ADVANCED opt-in for a later wave; no mandatory notice period in v1. Demoted-owner devices keep old keys: a theft-shaped displacement must be followed by `member_remove` (seat strike + rotation). Reset and claim stay fully separate ops.

**S4-3 ratchet (same wave).** Lowering `quorum_admin_ops` requires approvals under the CURRENT threshold; the ratchet is intrinsic to the knob, no separate lock knob. Threshold-1 lowering is the actor's own approval — the default floor unchanged.

**Test plan.** Helper unit tests (pair-Space Editor demotion, tombstone refusals, promote-before-demote invariant); a two-vault claim ceremony at threshold 2 (ask, co-approval, commit, peer pull, demoted-owner unlock); owner-reset rejoin-inherits-Owner; replay-digest refusal when the owner changed between ask and approval; route test for `members.claim` plus the owner-reset legs.
