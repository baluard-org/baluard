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

The plan's entire dual-control spec is one line: "Dual control 2-of-2 XOR
(S4)". S4-1's N-distinct-admin approvals already express 2-of-2 (threshold 2)
and N-of-M. Options:

1. Declare dual control superseded by S4-1 at threshold 2 and delete the
   one-liner (cheapest; the knob exists).
2. Keep a "locked" variant: an org pins threshold 2 and surfaces forbid
   lowering it (a policy lock on the knob).

Needed from Esteban: pick 1 or 2. Nothing else blocks.

## 3. S4-4 Access review report

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

Needed from Esteban: which story does 1.0 tell. Option 3 is the safe
default.

## 5. S4-6 Advisory org policies

Goal: a Space owner publishes recommended settings ("use Viewers without
export", "invite authority: owners") and member surfaces show them.

Design: plaintext `meta/policies.json` riding the meta/** Admin row
(same shape logic as the S3-6 catalog: existence is the setting, empty
publish is opt-out), surfaces render a "recommended" hint next to matching
settings. Advisory only, never enforced (enforcement is the shipped knobs).
No new crypto, one route pair, one card per platform.

## 6. S4-7 Emergency × org × identity doc

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

The plan carries this as a bare one-liner with no design, no scenario, and
no code reference anywhere. Needed from Esteban: restate what it meant
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
3. Mobile pending-approvals card: the uniffi `approvals_list()` bridge
   method shipped (wave-37); no UI row renders it.

## 10. Open questions (moved from sharing plan §10)

1. Q5: recovery, ownership transfer, member reset as designed: confirm.
2. Q6a: identity-rooted Spaces with the layered identity
   (keystore/recovery-sealed identity; emergency content-key split):
   confirm the pivot. Groups (S4-2) lean on member identity wraps either
   way; this confirms the framing.
3. S4-3 dual control fate (section 2).
4. S4-5 timeline story (section 4).
5. S4-8 neutralization meaning (section 7).

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

## 12. Suggested build order

1. S4-3 + S4-8 decisions, Q5/Q6a confirms (costs one conversation).
2. S4-4 access review (M, no new crypto, immediate admin value).
3. S4-6 advisory policies (S).
4. S4-7 emergency doc (S).
5. S4-9 mobile host (L, parallelizable).
6. S4-2 groups (L, the headline item; designs after Q6a).
7. S4-5 timeline (last; biggest open design call).
