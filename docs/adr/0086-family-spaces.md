# ADR 0086. Family Spaces

> Status: Accepted (2026-10-05). Implemented in eight landing steps on 2026-10-06 and 2026-10-07: flags and classification, collection key rotation and the kit verifier, shared ergonomics, departure, kit work, the wizard and family flows, the merge ceiling wiring, and the contest window with quorum 2 through 5 and the item-copy founding flow. Open items are listed at the end of Consequences. The plan began as a design in review after two external reviews and a fresh-session review.

## Context

Families need one shared vault with distinct visibility for shared household data, guardian-only data, and each child's data. Separate family vaults create unnecessary switching, while an unscoped shared vault exposes every entry to every member.

The product owner ruled that scoping is a requirement: family members must see only what is shared with them, and some items must stay hidden from some members. Two earlier models were dropped. The first modeled the family as an unflipped vault where every member decrypts everything, with privacy living only in personal vaults and separate Spaces. The second used an umbrella of several family vaults. There is exactly one family vault.

The shipped Space model already provides roles, collections, member and group grants, scoped key wraps, quorum asks, and recovery kits (ADR 0085 and ADR 0087). The design is deliberately shaped like Bitwarden's organization model, and the work is family ergonomics on top so the vault never feels like an organization console. Family behavior should use those mechanisms while setting safer defaults for a non-technical household.

Family membership does not encode legal relationships. An Admin acts as a guardian, so wards, step-families, and multi-generation households use the same model. The product records only an optional guardian-controlled minor flag, not age evidence.

The family design must preserve the existing pair-Space cap and organization defaults. A third vault shape would change unlock and RootKey distribution, so family is a purpose preset on the existing team-shaped Space model.

## Decision

### Shape, purpose, and classification

A family vault is a team-shaped Space created through an idempotent, resumable creation flow. Nothing creates a team-shaped vault directly, so creation is create-then-flip inside one wizard transaction. Its normalized slug is `baluard-space-family`.

`purpose` is an enum with absent, `pair`, `family`, and `org` states in plaintext `meta/settings-pub.json`, beside the shape marker. Absent with the Space flag means a legacy pair Space that keeps its two-person cap. Absent with a flipped shape means a legacy organization. Absent with neither means a personal vault. The `space.set_purpose` route accepts only `family` or `org`, requires an administrator, and writes once: a purpose already set cannot change in this version. The `pair` value is recognized but no route stamps it today: pair Spaces are identified by the legacy Space flag created with `space.create`. `family` is writable only at creation, on an empty vault (no ciphers, archived items, trash entries, or collections), so a populated personal vault can never become a family vault. `org` is writable from a personal vault because that is how organizations are made: create a plain vault, then flip it to team shape. `purpose: family` drives defaults (personal merge on, minors available, family kit rules, join notices) and `purpose: org` keeps organization behavior unchanged.

Space classification is the union of explicit purpose, flipped team shape, or the legacy `space` flag. Any consumer that checks only one signal misclassifies: organizations made through the flip path carry neither the flag nor a purpose, and would otherwise classify as personal and be silently merge-eligible. `space_flip` demands a `family` or `org` purpose and refuses everything else, including pair Spaces, which carry the Space flag and would otherwise flip and break their two-person semantics. The shipped organization flip surfaces call `space.flip` directly, so a purpose-less personal vault flipping stamps `org` at the flip surface itself, because that conversion is an organization conversion.

The creation flow asks for purpose before making the team-shaped vault, then creates the protected `Shared` collection, the `Guardians` group, and the Recovery Kit. If the process stops after the irreversible flip, the next run resumes the partially completed family setup and converges on the same `Shared` collection. A failure to persist purpose or the Space marker aborts instead of leaving an unclassified team vault. This is a hard failure, unlike the warn-and-continue used by plain Space creation, because the flag now gates quorum and merge.

The flag split is load-bearing. The legacy Space flag caps a vault at two members, refuses Admin and Owner invites, and makes ownership swaps demote the old Owner to Editor, which would break the divorce journey. The pair gate therefore caps only `purpose: pair` and legacy Space-flagged vaults without purpose. Family ownership transfer preserves the former Owner as Admin, so a departing guardian can be removed after succession. Organization and pair transfer semantics are unchanged.

### Roles and content scope

Admins hold the Space Group Key (SGK) and can decrypt every collection. Members hold neither RootKey nor SGK. They receive wrapped collection keys only for their grants, so an ungranted collection is not filtered from a member's view: it is cryptographically absent. The sync policy permits cipher writes only when the signer has Editor-or-higher rank and a Write grant on that collection, and refuses Viewer writes regardless of grants (the role floor is pinned by test). A child who should edit joins as Editor, and the grants alone bound their reach. Collections carry `Read`, `Write`, and `manage` access with expiry and are grantable to members or groups. Self-escalation is impossible: grants are minted by Admins, `manage` delegation cannot edit the lists that delegate to it, and collection creation follows `collection_create_authority`, which defaults to admins.

The concrete household shows the spread of the model:

| Member | Rank | Grants |
|---|---|---|
| Parent (Owner) | Owner | Everything, administration |
| Second parent, grandparent (Admin) | Admin | Everything, co-guardian |
| Uncle (Viewer) | Viewer | Read `Shared` only |
| Child (Editor) | Editor | Read `Shared`, Read and Write on the child's own collection |
| Ward without formal adoption (Editor, flagged minor) | Editor | Same as a child; the guardians are the household admins |

A third admin keeps every kit operation satisfiable through any single loss. The vault records no legal relationship and needs none.

Collections are the content boundary:

- `Shared` is created with the vault and granted Read to every member at join. Wi-Fi, streaming, and shared cards live there, which keeps the vault from becoming a grants console. It is a protected system collection: its identifier is recorded in admin-written settings, deleting it is refused, and deleting any non-empty collection is refused (previously deletion orphaned items and the policy then denied all writes into the unknown directory).
- One group (the `Guardians` group in the example) holds collections some members must never see, such as `Finances` and `Documents`. Granting a collection to the group is the whole act, and membership in the group is the visibility rule. Groups bound non-admin members only; they are not a boundary between admins, who unwrap every collection key through the SGK. A group earns its keep for a trusted adult without admin rank, such as an aunt or grandparent who may read `Shared` but never `Finances`.
- Each child gets a per-person collection with Write for that child and Read for the guardians. One shared `Kids` collection is avoided because a twelve-year-old could read and edit a seven-year-old's entries.
- Add defaults bind by cipher type and by actor. For admins, Login and SecureNote default to `Shared`, while Card, Identity, BankAccount, DriversLicense, and Passport stay admin-only (unfiled) or go to a guardian collection, because `Shared` is a leak by omission if a guardian files the family card there. A member cannot write unfiled ciphers on a team vault, so a member's new item defaults to the member's single writable collection, and zero or several writable collections require an explicit choice with a plain-language error; the alternative is a permission error on every child-saved card. A guardian-designated `default_add_collection` overrides the multi-writable refusal only while the member still holds a live Write grant.
- Moving an item out of `Shared` does not recall earlier ciphertext from member clones, and the collection key stays unchanged. The interface states this where items are moved.
- Collection names are unique per vault, compared case-insensitively.

Two boundaries are stated rather than hidden. First, scoping is confidentiality-only: an Editor child's writes to `entries/**` (attachments), `meta/folders/**`, and `meta/tags/**` are not grant-scoped (collection trash is grant-scoped, and flat trash is admin-only), so a child could damage attachments on a hidden item or rename family folders and tags. Signed history makes this recoverable, and the creation flow says so. Second, some metadata is member-visible: which collections exist, their grant lists, item counts and size tiers (directory names are salted, but the definitions under `meta/collections/` expose names and grants), folders, tags, profile, settings, and contacts. Guardians are advised not to encode secrets in collection, folder, or tag names. Family Spaces do not provide privacy from guardians; that is what personal vaults are for.

### The minor flag

Membership gains a guardian-controlled `minor` state. No birth date, verification, or legal status is ever recorded. Because member rows are plaintext on the forge, the flag does not join them. It lives in an admin-written sealed record at `meta/members/<id>/minor.enc`, so nothing about a child's status leaks to the remote, the sync delta validator needs no new pinned field, and no member file construction site changes. Only the Admin-only route `members.set_minor` changes it.

The sealed record has an explicit Admin-only row in the sync policy placed ahead of the general self-owned member subtree row, which admits any role. Without it, a minor could overwrite or delete their own flag from a validly signed commit. A minor cannot be promoted, claim ownership, use the kit, approve asks, or be a swap or claim target. The ownership swap and the claim route require a live, non-minor target everywhere and Admin rank on family purpose only; pair and org vaults keep their existing transfer semantics, and a pair Space has no Admin rank. Minor invitations mint only at Editor or Viewer rank, so a minor never arrives with power, and admins and owners cannot be flagged. Children join as Editors by default, with their grants bounding the rank.

Growing up clears the flag with no crypto event. There is deliberately no role-change route, so promoting a former minor to Admin runs the standard remove-and-reinvite path with a fresh member identifier and re-minted grants, and the wizard states it. Possession of the kit phrase also clears the flag, so an adult child can recover when every guardian is gone.

### Departure

Departure is an explicit signed leave record in the member's own subtree. Every admin surface shows a pending departure and an Admin approves it explicitly. Minors file the same record, and the Admin approval is the guardian's say. `members.leave` refuses the Owner row until ownership is transferred. Organization purpose keeps administrator-only removal.

Approval is one execution: it captures the collections the leaver could open before any mutation (for an Admin, every collection, because the SGK unwraps all keys, including grants that are expired but unswept), strikes provider access, tombstones the member with reason `left` or `removed`, rotates every captured collection key while pruning the leaver's rows, reissues the Recovery Kit with a new phrase returned exactly once, and pushes. It refuses while the leaver owns the repository, so `space.migrate` must run first. Rotation and kit failures surface in the response, and no successful leave is returned after a partial cryptographic cut. The leaver sees "waiting for a guardian to finish".

The SGK rotation is not the cryptographic cut. Rotation re-seals the same collection keys, because the CK value never changes (a recorded boundary), so an Admin leaver who unwrapped every collection key still holds working keys after any RootKey or SGK rotation. `collection_rotate_key` creates a fresh CK, rewraps it for surviving grantees, re-encrypts entries, trash, and attachments, and prunes the departed grant rows. The expiry sweep prunes only expired grants, and rewrapping alone would leave dead grant records behind.

Grant narrowing for a member target now rotates the collection key as well (revoke-with-rotation, 2026-10-12), because the removed member already held the old key and wrap deletion alone never cut access; the old wrap file remains in git history. Group revokes keep wrap-only semantics. Every rotate-shaped operation converges the shared `.sweep-pending` marker first.

A member's export contains only what that member can decrypt, so a leaver walking away with an export takes their granted scope and not the vault. The export gate blocks Viewer rank only, so an Editor child can always export their granted scope, which is acceptable because that scope is their own items plus `Shared`, and the export warning names it. Per-item handovers ride guest reveals, which carry Login credentials only. Notes, cards, and identities move by direct sharing, an administrator-run export, or the selective item-copy flow (`vaults.copy_items`, `baluard vaults copy-items`, which strips attachments and foreign folder identifiers and carries password history).

### Recovery Kit, verifier, and repository

Family kit recovery is phrase-only. The previous kit recovery demanded the vault master password and bound to the first live Owner row, which fails the grandparent-with-phrase-only journey. The 24 words unwrap the RootKey (they are the root authority), the recovering device mints its own fresh master password (8-character floor) and keystore with per-device member unlock, and it always ends as a fresh unflagged member row: Owner when no live Admin row exists, otherwise Admin. Legacy personal vaults refuse this path.

Publishing was the hard part. A recovered device is a fresh identity, so every peer resolves its first commit against the previous roster, which lacks it, and refuses. The enrollment-proof fallback (ADR 0081) never fires on a flipped vault, because a structural pass would let any remote writer forge admissions, recovery writes no enrollment proof, and members hold no RootKey to verify one anyway. The fix rides the kit file `meta/recovery-kit.json` (format 2, with a `root_check` seal under a RootKey-derived subkey over vault identifier, recipient key, and verifier key, so a git writer without the RootKey cannot rebind the kit). At kit creation the file carries the public half of an Ed25519 key derived from the same phrase. The recovered device signs its first commit with the private half, held in a sealed device-local `meta/recovery-signer.key` that clears on first push. Peers accept that commit under the parent tree's kit verifier plus the commit's exactly-one registry addition, adopt the updated roster from its tree, and verify everything afterward under the device key. The check rides both the pull walk and the clone walk, so a vault cloned after recovery verifies the same history the same way.

The recovering device must also be able to clone, which needs repository read access. The phrase plus repository access recovers the vault, and the phrase alone recovers it once someone with access invites the recovered device in. The kit checklist names this seat prerequisite.

Kit replacement (enable over an existing kit) and disable require confirmation at a fixed threshold of `min(2, live_admin_count)`, never the quorum knob and counted over live non-tombstoned rows, so a sole admin confirms alone and a two-admin household needs both. The enable-over ask is bound to the kit's creation time. First enable is ungated because family creation enables the kit (idempotently on resumed runs). Any guardian's approved departure and the succession journey force a reissue with a new phrase.

The repository outlives people. Seats and strikes act with the acting device's token, so when the repository-owning guardian departs or dies, a surviving admin runs `space.migrate` to move the vault to their own account, and both departure checklists name it. Peers learn the new address from the announcement pushed to the old remote, so if the old repository vanishes before members pull, each member re-adds the vault by the new address manually. A child usually cannot hold a forge account, so child devices use a guardian-owned read-write seat scoped to the family repository, labeled in the wizard as the guardian's forge identity, or stay local-only. A write seat means a child could force-push the family repository. Signed history supports recovery only when an Admin keeps a trustworthy clone, and the creation flow tells guardians to keep one.

### Ownership and quorum

Family quorum follows the organization knob (default 1, settable 2 through 5). At quorum 1, an Admin can claim ownership from a live Owner immediately, and the claim commit carries a notice naming the claimant to the Owner's devices (at quorum 1 there is no pending ask, so the notice rides the claim). A confirmed claim against a live Owner on a family vault also writes a synced contest record `meta/contests/ownership-claim.json`. The Owner may cancel it through `members.contest_cancel` for 30 days (status via `members.contest_status`), and the claim re-touch executes only after the window, with the elapsed record serving as the durable proof that the quorum gate was satisfied. Admins cannot cancel, and tombstoned owner rows refuse claims outright. The arming surfaces as success (`armed: true`) so the daemon covers and nudges the record to the Owner's devices.

The window is enforced on the executing device's clock, and peers admit admin-signed member commits as they always have, so quorum 2 remains the cryptographic two-key control. Death is not tracked: a deceased owner's row stays live, so succession waits out the window. The last-guardian deadlock of quorum 2 has a recorded escape: the kit phrase recovers a second admin device, and two admins can lower the bar.

### Merge ceiling

Family purpose sets `personal_merge` on by default (the user can change it), through `space::effective_personal_merge` (absent follows purpose, an explicit value overrides). Merged search and autofill include only content the member can decrypt, badged by collection, so a child's merged view spans the personal vault, `Shared`, and granted collections. Unavailable collections do not appear as locked or empty, because the device holds no key for them. A grandparent with `Shared`-only grants merges exactly that. Slug-scoped fetches and ranking rules follow ADR 0098, and family purpose only pre-seeds the consent default.

Eligibility is the device-local keyless predicate `VaultRegistry::merge_eligible`. Personal vaults are always eligible, Spaces need the `merge_ceiling_seen` cache refreshed at unlock and at settings save, explicit opt-out (`merge_opt_in`) wins, and a never-unlocked Space fails closed. Legacy flipped organizations and pair Spaces classify as Spaces and stay out of merge.

### Defaults and journeys

The family preset uses code-based join approval, adults as Admins, children as Editors or Viewers, and `Shared` Read grants. Organization defaults remain unchanged. Advanced controls (quorum, invite authority, kit settings) live in Space settings. A child invitation embeds `Shared` Read plus that child's collection Write grant. A reset successor starts with no grants and no group memberships, so replacement invitations carry the member's captured grants.

Arrival uses the existing invite flow, join queue, and `join_approval`, with `Shared` Read at join and minors flagged. Founding a new family means creating a new family vault and copying out the founder's items. Separation or divorce has no automatic split: the leaving guardian transfers ownership first if they hold it (the purpose-aware swap keeps them Admin), files the leave record, and another guardian approves, so the execution rotates keys, reissues the kit, migrates if the leaver owned the repository, and the notice says "you left". What a member could decrypt, they could always have copied, so scoping bounds what was visible and not what memory retains. A guardian's death runs through claim, removal, kit reissue, and migration. A household whose last admin is gone relies on phrase-only recovery, and the phrase lives wherever the family's most important paper lives.

A stolen device needs four steps, because a reset alone is not a theft response and on a team vault neither is a root rotation alone. `member_reset` kills the identity (tombstones the row, prunes groups, drops the space wrap) but rotates nothing and strikes no token. The stolen device is revoked, striking its seat and provider token. The collections the device could open get an explicit `collection_rotate_key`, because re-keying alone reuses the same collection key a thief may have extracted. The replacement invitation carries the `Shared` template plus the re-granted per-child collections. The single daemon operation `members.replace_device` performs these steps, capturing the member's real grant levels, resetting, optionally revoking and rekeying each bound device, and rotating the captured collections with failures surfaced. A stolen Admin device uses revoke-and-rekey for the RootKey and SGK, and collection rotation still applies to collections only admins could open. An invited co-guardian who never joins changes no admin-count or kit-confirm assumption until they join, and unclaimed invitations expire.

### Non-goals

No death detection, inactivity triggers, or automatic succession. No automatic asset division. No age verification. No legal-relationship modeling. No new cryptographic primitives. The organization model is untouched. Hiding is real for content and never for metadata, and the creation flow states plainly that admins see everything.

### Acceptance coverage

The core suite pins: create-then-flip yields a team-shaped vault with `Shared` and `Guardians`; `space_flip` refuses non-family, non-org purposes; the pair gate caps only pair and legacy flagged vaults; the swap keeps the old Owner at Admin on family purpose; minors are refused everywhere as swap or claim targets; family purpose is refused on a populated vault; add defaults route by type at the state layer; member devices decrypt only granted collections (structurally, no wrap exists); a Read-granted child cannot write into `Shared`; Viewer rank is refused even with grants; `Shared` and non-empty collection deletion are refused; revoking a member grant rotates the key; the Admin-only policy row blocks a minor from writing or deleting the record; approval execution rotates and reissues before push; kit confirmations follow `min(2, live admins)`; phrase-only recovery ends in a fresh Owner or Admin row and clears the minor flag; and the contest window arms, cancels, and executes through the gate-proof record. The end-to-end journeys are the widow, divorce, growing-up, stolen-tablet, grandparent (peers accept the recovered device's commits on pull and a fresh clone verifies the same history), and scoping (a child's device never receives `Finances` keys and merged search shows only `Shared` and the child's collection) journeys, plus the wizard half-complete state.

## Consequences

One vault supports guardians, children, and guests without requiring families to configure a role matrix. Collection keys enforce content confidentiality, while collection names, grant lists, item counts, size tiers, folders, tags, profile, settings, and contacts remain visible to members or repository collaborators as specified by the Space model.

Admin devices can see all family content. Family Spaces do not provide privacy from guardians. Member writes to attachments and shared folder or tag metadata are not fully collection-scoped, so a member may damage metadata or attachments outside their grant; signed history supports recovery.

Leaving members retain previously copied bytes. Child devices require repository access; a guardian-owned repository seat or local-only use may be necessary. Provider migration can require manual re-addition if the old repository is unavailable before peers receive its new address. A repository write seat lets its holder push changes, and recovery from a forced update needs an Admin with a trustworthy clone.

Family creation from an existing populated personal vault is not supported in-app by conversion. The founder exports and imports data or uses the selective item-copy flow. A family member's export contains only decryptable content, but Editors can export their granted scope.

The family model does not detect death, inactivity, or legal guardianship. A household whose last Admin is unavailable depends on the Recovery Kit phrase. If the phrase and every Admin device are lost, members may retain read access but cannot grant, rotate, or administer the Space.

Open items. The graphical wording for departure and grant narrowing is a separate design pass. The purpose flag has no structural delta validation in the sync walk, so it is protected by the Admin gate and write-once rule only. The 30-day contest window is enforced on the executing device and is not a peer-verified rule. Role-gated collection defaults (visible to Admins and above automatically) were deferred as sugar over groups and are not built; only `default_add_collection` landed. A notice on purpose change, designed against a co-guardian relabeling the vault, is not needed in the shipped model because the purpose cannot change once set.

## References

- ADR 0085 (`docs/adr/0085-sharing.md`), ADR 0087 (`docs/adr/0087-power-pack.md`), ADR 0098 (`docs/adr/0098-merged-search.md`), and ADR 0081 (`docs/adr/0081-the-proof-rides-the-commit.md`).
- Per-slice history: ADR 0062 through 0077 (`docs/adr/0064-two-keys-to-the-owner-s-chair.md` for the contest window, `docs/adr/0067-the-phrase-is-the-last-key.md` and `docs/adr/0068-recovery-is-a-fresh-clone-and-a-phrase.md` for the kit, `docs/adr/0070-the-department-holds-a-key.md` for groups, `docs/adr/0074-the-flip-keeps-keys-from-members-not-from-admins.md` for scoped keys).
- `docs/security/emergency-org-identity.md`.
- `crates/baluard-core/src/vault/family.rs`, `crates/baluard-core/src/vault/space.rs`, `crates/baluard-core/src/vault/collections.rs`, `crates/baluard-core/src/vault/recovery_kit.rs`, `crates/baluard-core/src/sync/policy.rs`, `crates/baluard-core/src/device_manager.rs`, `crates/baluard-runtime/src/state.rs`.
