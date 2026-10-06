# Plan: Family Spaces (v4)

Status: In review (v4 reviewed by external peer; findings folded)
Date: 2026-10-05
Author: Esteban
Related: docs/plan-sharing.md (closed design record), docs/plan-merged-search.md (G24), D59-D78 in docs/software-architecture-decisions.md

## 1. Problem and ruling

A family Space is not a small organization, but the product owner has ruled that scoping is a requirement: family members must be able to see only what is shared with them, and some items must stay hidden from some members. Earlier revisions (v2/v3) modeled the family as an unflipped vault where every member decrypts everything, with privacy living only in personal vaults and separate Spaces. That model is dropped. v3's umbrella of several family vaults is also dropped: there is exactly one family vault, `baluard-family`.

The v4 model is a single vault, born in team shape, with roles and collections as the access machinery. This is deliberately Bitwarden-shaped, and Baluard already ships every primitive it needs: roles, collection grants to members and groups, scoped key wraps, kit recovery, quorum asks. What gets designed here is the family ergonomics on top, so it never feels like an org console.

## 2. Model: team-shaped from birth

A family vault is created directly in team shape (the shape organizations use). Today nothing creates a team-shaped vault directly and `space_flip` does not refuse a personal vault (its only gates are unlocked, the manage gate, and member readiness, so a personal founder would pass), so the creation path is defined as create-then-flip inside one wizard transaction, with a new refusal: `space_flip` refuses every vault whose purpose is not `family` or `org` (personal vaults refuse, and pair Spaces refuse too: they carry the Space flag and would otherwise flip and break their two-person semantics). Consequences, all existing behavior:

- Parent devices (Owner/Admin) hold the Space Group Key and see every item, filed or not.
- Member devices (Editor/Viewer) hold neither the Root Key nor the SGK. They receive wrapped collection keys only for collections granted to them, so an ungranted collection is not filtered out of their view; it is cryptographically absent.
- The sync policy admits cipher writes for a member holding Editor rank plus a write grant on the item's collection, and refuses Viewer-rank writes regardless of grants (the role floor is pinned by test). A child who should edit joins as Editor, and the grants alone bound their reach.
- Collections carry `Read`, `Write`, and `manage` access with expiry dates, grantable to members or groups.

The `purpose` flag lives in plaintext `meta/settings-pub.json` beside the shape marker, written by an Owner-only route (no quorum claim: the file carries no approval envelope; structural delta validation is future work). `purpose: family` drives defaults: `personal_merge` on, minors available, family kit rules, join notices. `purpose: org` keeps the organization behavior unchanged. A personal vault never converts into a family vault; the create-then-copy path is the only one.

The flag split is load-bearing. Today `space.create` writes `"space": true`, and that flag caps the vault at two members, refuses Admin and Owner invites, and makes the ownership swap demote the old Owner to Editor, which would break the divorce journey. v4 therefore makes both consumers purpose-aware: `pair_gate` caps only `purpose: pair` (the couple stays a couple), and on `purpose: family` the swap keeps the old Owner at Admin so a departing parent can be removed after the claim. The family vault is a Space (`space: true`) with `purpose: family`, which is also what makes G24 classify it correctly; without the split, a family created through the plain vault path would be treated as a personal vault by the merge ceiling, and a family created through the Space path could never seat the second parent. Quorum stays at 1: `space_settings_set` refuses `quorum_admin_ops` above 1 on a family vault until the v1.1 contest window ships, so the dead-parent deadlock cannot be configured.

## 3. Roles and scopes

Roles stay `Owner/Admin/Editor/Viewer` and gate administration and rank exactly as organizations use them. Collections are the content boundary:

- `Shared`: created automatically with the vault and granted Read to every member at join. Wi-Fi, streaming, shared cards. This is what keeps the family vault from becoming a grants console: the common items need no thought.
- Group-restricted collections: a `Parents` group holds the collections children must never see (`Finances`, `Documents`). Granting a collection to the group is the whole act; membership in the group is the visibility rule. The group bounds members; it is not a boundary between the two Admin parents, who hold the SGK and unwrap every collection key regardless of group membership (section 9 states the same plainly). The group earns its keep for non-admin trusted adults, a grandparent for instance.
- Per-person collections: `Kids` holds the children's own entries, granted Write to the kids and Read to the parents (admins see everything regardless).
- Adding an item defaults to `Shared` **by cipher type**, and the default binds Admins only: Login and SecureNote go to `Shared`; Card, Identity, BankAccount, DriversLicense, and Passport go admin-only (unfiled) or to the `Parents` collection. Members cannot write unfiled ciphers on a team vault, so a child's own additions default to their granted writable collection (`Kids`); the alternative would fail closed with a permission error on every child-saved card. The reason for the admin-side split is that `Shared` is a leak by omission if a parent dumps the family card in it, and because moving an item out of `Shared` later is not a recall: member clones already hold the earlier ciphertext in git history and the collection key never changed. The UI states this plainly where items are moved out of shared collections.
- `Shared` is a protected system collection: its id is recorded in admin-written settings, deleting it is refused, and deleting any non-empty collection is refused (today `collection_delete` orphans its items and the policy then denies all writes into the unknown directory).
- Role-gated collection defaults ("visible to Admins and above automatically") are v1.1 sugar over groups; groups carry v1 completely.

Two boundaries are stated rather than hidden. First, scoping is confidentiality-only: an Editor child's writes to `entries/**` (attachments), `meta/folders/**`, and `meta/tags/**` are not grant-scoped (collection trash is grant-scoped, and flat trash is admin-only), so a child could damage attachments on a hidden item or rename family folders and tags; git history makes this recoverable, and the creation flow says so. Second, some metadata stays member-visible: which collections exist, their grant lists, item counts and size tiers (collection directory names are salted, but the definitions under `meta/collections/` expose names and grants), plus folders, tags, profile, settings, and contacts (re-sealed under the member key at flip). Parents are advised not to encode secrets in collection, folder, or tag names.

Self-escalation is impossible: grants are minted by Admins, `manage` delegation keeps grantees from editing the lists that delegate to them, and collection-creation authority follows `collection_create_authority` (admins by default for family purpose).

## 4. The concrete family

Two parents, two children, one vault:

| Member | Rank | Grants |
|---|---|---|
| Mom (Owner) | Owner | everything, admin surface |
| Dad (Admin) | Admin | everything, admin surface |
| Alex (12, Editor) | Editor | Read `Shared`, Read+Write `Kids` |
| Sam (7, Editor) | Editor | Read `Shared`, Read+Write `Kids` |

Alex opens search: personal vault, `Shared`, `Kids`, merged and badged (G24). `Finances` does not appear as locked or empty; Alex's device holds no key for it. Alex saves the new game account into `Kids` and edits it freely. Nobody ever configures a role matrix.

## 5. Membership states: the minor flag

Member files gain `minor: bool` (default false; a breaking format change). It is guardian-controlled, never an age claim: no birthdates, no verification, ever. A new Admin-only route `members.set_minor` flips it, and the sync member-record validator pins the flag (`minor` may not change during routine identity rotations) so no non-admin signer can self-clear it.

A minor cannot be promoted, cannot claim ownership, cannot use the kit, cannot approve asks, and cannot transfer-own (the transfer route refuses minor targets). A minor files a leave request, but nothing executes without an Admin approving it (section 6). The plumbing is wider than the flag: the member-record delta validator pins an enumerated field list today, so `minor` must join it, and the invite file, join approval, the reset successor, and every `MemberFile` construction site must carry the field.

Children join as Editors by default on family purpose, with their grants bounding what the rank can touch; Viewer remains available for read-only members, and the policy floor guarantees a Viewer cannot write even where granted. The orphan escape carries from v3: possession of the kit phrase clears the minor flag. If both parents are gone, the adult child recovers with the safe-deposit phrase and the flag falls with it.

## 6. Departure: an approved leave record

The v3 design carries unchanged: the departing member writes a signed leave record into their own member subtree, every admin surface shows a pending-departure notification, an Admin explicitly approves, and that single execution runs the standard ceremony (seat strike, SGK rotation, tombstone with a coarse `left` versus `removed` reason). The leaver sees "waiting for a parent to finish". Minors file the same record; the Admin approval is the parental say. `members.leave` refuses the Owner row until ownership is transferred. Org purpose keeps admin-only removal.

One property improves under team shape: a member's export contains only what they can decrypt, so a leaver walking away with an export takes their granted scope, not the vault. The export permission itself is Space-wide, not per member or one-time; family keeps `allow_viewer_export` off, an Admin may run an export themselves and hand it over, and flipping the knob for one departure is a deliberate, visible act. Per-item handovers ride guest reveals, which carry Login credentials only today; notes, cards, and identities move by direct sharing or an admin-run export. The selective "copy these items to my vault" flow remains v1.1.

Grant narrowing before an approval is advisory, not cryptographic: revoking a grant removes the row and the wrap but does not rotate the collection key (only the expiry sweep rotates, a recorded D67 boundary), and the old wrap file remains in git history, so a still-seated member could unwrap the unchanged key. The cryptographic cut for a departing member is the approval execution itself: the seat strike and the SGK rotation. A revoke-with-rotation (re-encrypting the collection's entries using the sweep's existing rotation machinery) is future hardening, not a v1 dependency.

## 7. Kits and the repo

Phrase-only family recovery carries from v3: the current kit recovery demands the vault master password and binds to the first live Owner row, which fails the grandparent-with-phrase-only journey. Family purpose redesigns recovery: the 24 words unwrap the Root Key (they are the root authority by D64), the recovering device mints its own fresh master password and keystore, and it always ends as a fresh member row: Owner when no live admin row exists, otherwise Admin alongside the survivor. Recovery clears the minor flag.

Kit rules carry: enabling over an existing kit or disabling one requires confirmation from the other admin once a second admin exists, counted over currently-live non-tombstoned rows only, so the widow journey (claim, remove, re-issue) reduces the live-admin count to 1 before the re-issue. Any parent's approved departure or the succession journey forces a kit re-issue with a new phrase.

The repo outlives people, as before: seats and strikes act with the acting device's token, so when the repo-owning parent departs or dies the survivor runs `space.migrate` to move the vault to their own account. Both checklists name it.

## 8. Lifecycle matrix

Arrival (new spouse, adopted child, grandparent): the invite flow, join queue, and `join_approval: manual|code` unchanged. New members receive Read on `Shared` at join plus whatever else the inviting parent grants. Minors join flagged.

Growing up: a parent flips `minor` off via `members.set_minor`. No crypto event; grants unchanged.

Founding their own family: create a new family vault, copy out what is yours (section 6), file the leave record.

Separation or divorce: no automatic split. The leaving parent transfers ownership first if they hold it (the purpose-aware swap keeps them Admin rather than demoting to Editor), files the leave record, the other parent approves; rotation kills their wraps and the notice says "you left". What a member could decrypt, they could always have copied; scoping bounds what was ever visible, not what memory retains. Grant narrowing before approval is advisory (section 6). Co-parenting after separation is the parents' arrangement; collections and grants already express it.

Death of a parent: the survivor claims ownership, removes the deceased row, re-issues the kit, migrates the repo if needed, all at quorum 1. Sole-parent family: the phrase-only kit recovery is the path, and family creation makes the kit mandatory. A relative recovering binds to a live Admin row or takes the Owner seat, then may claim. Both parents gone: the kit phrase lives wherever the family's most important paper lives.

Stolen device: a reset alone is not a theft response, and on a team vault neither is a root rotation alone. The parent does four things. `member_reset` kills the identity (it tombstones the row, prunes groups, and drops the space wrap, but performs no rotation and strikes no provider token). The stolen device is revoked, striking its seat and provider token. The collections the device could open get an explicit collection-key rotation (the expiry sweep's machinery: fresh key, survivors re-wrapped, entries re-encrypted), because re-keying alone re-encrypts under the same collection key a thief may already have extracted. The replacement invite carries the Shared template plus re-granted `Kids`, because a reset successor starts with no grants and no group memberships and the child would otherwise lose everything until a parent notices. A stolen Admin device is simpler: revoke-and-rekey rotates the Root Key and SGK, which is the whole game at admin scope.

An invited co-parent who never joins: admin-count and kit-confirm assumptions rise only when the second admin actually joins; unclaimed invites expire.

## 9. Non-goals

No death detection, inactivity triggers, or automatic succession; co-admin plus kit are the answers. No automatic asset division. No age verification. No new cryptographic primitives: scoping is the shipped team shape. The org model stays untouched for organizations. Hiding is real (absent keys) for content, never for metadata (section 3), and stated plainly in the creation flow: admins always see everything, so a child's privacy from parents is not a thing this vault provides; that is what personal vaults are. A sole parent dying leaves the children able to read `Shared` and `Kids` but nobody able to grant or rotate; the kit is the designed path out, and creation makes it mandatory.

## 10. Sync and enrollment safety

The D78 enrollment-proof fallback is already closed on team-shaped vaults: the pull path refuses the structural-only fallback without a Root-Key verifier, and members hold no Root Key. The v3 idea of additionally gating on an absent member directory is dropped: every vault created since S1a carries a member directory with an Owner row, so that gate would have broken personal multi-device sync while adding nothing. Members cannot self-grant: grant lists are admin-written, `manage` delegation cannot edit the lists that delegate, and the sync policy verifies collection-scoped writes against rank plus grant on every pull. One quorum-1 sharp edge is accepted and surfaced: at threshold 1 an Admin parent can claim ownership from a live Owner unilaterally, so v1 ships a notice to the Owner's devices when a claim against a live Owner is raised (the D61 contest window that makes claims contestable remains v1.1).

## 11. G24 wiring

`purpose: family` sets the `personal_merge` default on, and the family vault classifies as a Space for the merge ceiling once the flag split (section 2) lands. The merged set is bound to what the member can decrypt (the D71 scoped-key rule), so a child's merged search and autofill span their personal vault, `Shared`, and their granted collections, badged; nothing surfaces from `Finances` because nothing decrypts. Parents merging the family vault see their full view. Slug-scoped fetches, service-worker projection, and the ranking rules in docs/plan-merged-search.md apply unchanged; family purpose only pre-seeds the consent default.

## 12. Tests

Core: create-then-flip yields a team-shaped vault with `Shared` and the `Parents` group, and `space_flip` refuses vaults without family purpose or the Space flag; the pair gate caps only `purpose: pair` and the ownership swap keeps the old Owner at Admin on family purpose; purpose survives `settings-pub` merge saves; join grants `Shared` Read (via the role-template grants path); add-cipher defaults route by cipher type at the state layer; member devices decrypt only granted collections (structural: no wrap exists for ungranted collections); Editor-rank child writes inside a granted collection and cannot write into `Shared` with Read; Viewer rank refused writes even with grants; group grant and revoke flows; `Shared` deletion refused and non-empty collection deletion refused; grant revoke removes the wrap while the collection key survives (documented D67 boundary); `members.set_minor` auth and the minor delta pin (the new field joins the pinned list); leave record write, explicit approval execution, minor leave requiring approval, Owner leave refused until transfer; kit confirmations with live-admin counting; phrase-only recovery ending in a fresh Owner-or-Admin row and clearing the minor flag; the claim-against-live-Owner notice; reset successor receiving the Shared template with `Kids` re-granted; stolen-member-device eviction requiring an explicit collection-key rotation because re-key alone reuses the key; `space_settings_set` refusing quorum above 1 on family; export scoped to the member's decryptable set.

Route coverage: `members.leave`, leave approval, `members.set_minor`, purpose in `space.status`, kit confirmation ask, `space.migrate` path.

E2E: the widow journey (claim, remove, kit re-issue, migrate); the divorce journey (transfer, leave record, approval, "you left" notice, grant narrowing before approval); the growing-up journey (flag flip, leave request, approval); the stolen-tablet journey (reset by one parent); the grandparent journey (phrase-only recovery, no prior vault password); the scoping journey (child device never receives `Finances` keys, merged search shows `Shared` + `Kids` only).

## 13. Landing order

1. Flags, classification, and shape: `purpose` + `minor` (flag route, delta pin, invite file, join approval, reset successor, every `MemberFile` site); the pair-gate split and the purpose-aware swap; the `space_flip` refusal and the create-then-flip wizard transaction; `Shared` created at vault creation and protected as a system collection; non-empty collection deletion refused.
2. Shared ergonomics: join-time `Shared` Read via the invite role-template grants; add-cipher defaults routing by cipher type.
3. `members.leave` record route, pending-departure surface, admin approval execution, reason-based notices; the grant-narrowing-is-advisory wording in the UI.
4. Kit work: phrase-only family recovery ending in a fresh Owner-or-Admin row, live-admin confirmations, departure-forced re-issue.
5. Wizard and family flows: purpose question, Admin co-parent invite (the wizard mints the invite; the Verified contact card and identity-signed introduction complete during the co-parent's own join, since an elevated join cannot approve before contact verification), children as flagged Editors with grants, kit step, the claim-against-live-Owner notice, and the stolen-device flow (reset, revoke, collection-key rotation, re-grant with the Shared template).
6. G24 wiring: purpose sets the `personal_merge` default; plan-merged-search consent section records purpose; the Space-classification test.
7. v1.1: the D61 contest window, quorum 2, the selective item-copy departure flow, role-gated collection defaults as sugar over groups, and revoke-with-rotation for collections.
