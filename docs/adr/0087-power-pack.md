# ADR 0087. Space Administration Power Pack

> Status: Accepted (2026-09-28). Complete: all items shipped or resolved between 2026-09-28 and 2026-09-30, and the later hardening rounds are recorded in ADR 0078 through 0081. Deferred and parked sharing work is listed under Decision.

## Context

Shared Spaces need administrative controls for quorum, group-based access, review of membership exposure, recovery, and audit history. These controls must build on the identity-rooted Space and collection model of ADR 0085 without adding a server or recording individual reads.

The foundations were already shipped: the quorum gate `quorum_admin_ops` (default 1, raisable to 5) that puts removals, resets, transfers, rotation, and sync-address moves behind distinct administrator approvals (ADR 0062), the `collection_create_authority` setting, the Space settings knobs with surfaces on desktop and mobile, the Space Meta Key flip under which flipped members hold neither RootKey nor SGK, member collection access where read scope equals key scope, and the per-device activity log, refusal log, and notices.

The existing approval mechanism already supports distinct administrator approvals. Additional controls should reuse this primitive instead of introducing a separate dual-control state or policy lock.

Space state is signed and synchronized through Git. Any shared timeline must respect the rule that reads leave no trace and must not add predictable event-file churn that exposes activity timing (the T14 timing-fingerprint concern).

The pack was split into eight items. Four open design questions needed an owner decision, and an adversarial design review on 2026-09-28 resolved all of them under the directive to choose the most secure option that stays easy for end users, with anything heavier existing but disabled by default and configured by the primary administrator. Claims in that review were verified against source before adoption.

| Item | Outcome |
|---|---|
| Groups as a key layer | Shipped (ADR 0070) |
| Dual control | Resolved: threshold 2 is dual control, with an intrinsic ratchet (ADR 0064) |
| Access review report | Shipped, carrying the offboarding exposure summary (ADR 0065) |
| Full Activity timeline | Resolved as derived-only, shipped (ADR 0071) |
| Advisory organization policies | Shipped (ADR 0066) |
| Emergency, organization, and identity design | Shipped as a design document and the Space Recovery Kit (ADR 0067, ADR 0068) |
| Synthesized neutralization | Dropped as a cryptographic item, folded into the access review |
| Mobile multi-Space host | Shipped as app-level coordination (ADR 0069) |

## Decision

### Quorum and the ratchet

Sensitive administrative operations use `quorum_admin_ops`, an integer threshold defaulting to 1 and configurable up to 5. The gated operations are member removal, member reset, ownership transfer, ownership claim, device revocation, RootKey rotation, sync-address migration, and changes to the threshold itself. A requested operation is a record at `meta/approvals/<id>.json` carrying the operation kind, a digest of the parameters, the initiator, and the approvals collected so far. The record is plaintext, governed by the `meta/**` Admin sync policy row, so every peer's next pull sees the ask and any administrator device can confirm it. Collection creation authority is configured separately by `collection_create_authority`, defaulting to Admins with Editors optionally enabled.

The flow has two phases. The first administrator's call creates or refreshes the record and refuses with a clear message. Each further administrator confirming the same change appends an approval. Once distinct approvals reach the live threshold, the confirming call consumes the record and the operation executes. A record whose parameter digest differs from the incoming ask is stale and the newest ask replaces it, so a changed plan never inherits old approvals. Parameters are capped at 8 KiB, at most 64 pending records are walked, and an ask stays confirmable for seven days; a confirming administrator past the window simply raises a fresh ask.

Each approval entry carries the approver's member identity signature over the ask (operation kind, parameter digest, vault identifier, ask time, and the ask's random nonce, domain-separated). The gate counts only entries whose signature verifies against the member row's published identity key, so a hand-written record cannot forge a second administrator's approval. The nonce makes signatures harvested from a consumed record useless on a fresh ask, which matters because Ed25519 signatures are deterministic and a same-second re-ask would otherwise be byte-identical. The ask digest also folds in a fingerprint of the state the operation will mutate, so a restored record and deleted tombstone cannot re-approve an ask whose prestate has moved. Asks timestamped more than ten minutes in the future are stale. The gate's role check runs at every threshold, including 1 (ADR 0078).

The threshold lives in the encrypted settings, which the keyless sync walker cannot read, so enforcement is local to administrator devices like every other settings knob; the record carries the required count so a peer can still render the ask. The kit gate uses a fixed threshold instead of the knob (ADR 0086).

The ratchet is intrinsic: changing the threshold downward is itself an operation subject to the current value. No independent lock setting is stored, because with quorum 1 a lock is meaningless and a knob would only add a state. This prevents a single administrator from lowering a threshold of 2 to 1 without a second approval. At threshold 1, lowering is the actor's own approval and the default floor is unchanged.

### Groups

Groups are a key layer above collections. Each group has a random 256-bit Group Key (GK). The group file `meta/groups/<id>.json` holds a plaintext member list (live members only, removal deletes the row), the GK sealed under an SGK-derived wrap key (HKDF info `baluard-group-key-wrap-v1`, epoch-bound), and the group display name sealed under the GK. Each member holds the GK wrapped to their identity key at `meta/groups/<group>/<member>.gkwrap`, and each collection granted to the group stores its content key again under the GK at `meta/groups/<group>/<collection>.ckwrap`. The key chain is `gkwrap -> GK -> ckwrap -> CK -> names and item keys`. Caps are 64 groups per vault, 200 members per group, and 256 KiB per group file on read, because git-tracked files can arrive oversized.

A collection grant targets a member or a group through typed identities, and group access uses the same effective-access predicate as individual grants. That predicate is shared across the member, group, and scope walks, so a group grant cannot be interpreted differently by listing and by write authorization. Group grants are Admin-controlled; delegated managers grant people, not departments. The design leaned on the collection pattern (proven wrap minting, identity-rotation self-heal, removal cleanup) rather than deriving group keys from the SMK.

The indirection is the point. Removing a member from a group rotates only that group's GK and re-seals its ckwraps under the new GK. Collection content keys and every direct grantee stay untouched, where per-member CK wraps would force a full re-key of every collection the group can open. Offboarding removes member rows and rotates each affected group key. What a leaver memorized, an old CK, stays the accepted eventual-revocation boundary priced everywhere else, so a collection key must be rotated separately if a former grantee may already have extracted it. Group files ride the `meta/**` Admin policy row, and a member's own `.gkwrap` carries a structural own-wrap exception so identity rotation stays self-service. Group-targeted access requests and role templates over groups were open design questions at planning, and this ADR records no such extension.

The accepted shape was: an administrator creates a group, adds members, grants a collection to the group, every member reads and writes per the grant, leaving the group rotates the group key without touching collection content keys, and the two-vault ceremony proves it across devices.

### Access review

The access review answers who can see what in one place. It is computed on demand from current Space state on the administrator device, with no new persistence. It reports member roles, collection grants with expiry, pending asks, group access, and tombstoned members, and it is admin-gated. Tombstoned members' surviving grants appear as a rotation list: the offboarding exposure summary that replaces the dropped neutralization item. Read data cannot be unread, so the credentials a removed member could open must be changed; the report lists them and does not claim that deletion from current grants erased historical wraps or copied content.

The report omits contact-key grants and recipient outbox state that exists only on other devices, and administrators review those through the sharing surfaces. Desktop provides the People-tab card with expandable rows and a JSON export, and the mobile bridge method is deferred.

### Activity timeline

Three designs were considered. A shared ledger would commit member-emitted events to a tracked `meta/events.enc` under policy rows and give a full story, at the cost of history growth, commit-timing exposure, and policy work. A derived-only timeline aggregates what verified git history already proves and writes nothing, with a weaker story. A hybrid starts derived-only and adds a ledger later. The decision is derived-only for v1, with the ledger left as a later add-on.

The timeline is synthesized from verified, signed git history. The walk runs newest-first in topological order, and the engine owns it because roster resolution, verification, and attribution are file-private there. Pure classifiers in `sync/timeline.rs` turn each commit's changed paths into events. Topological order is the ordering authority because commit timestamps can be skewed or manipulated, and timestamps affect display only. The event kinds are vault creation, member added, removed, or reset, identity rotation, role change, ownership transfer, collection created or deleted, grant added or revoked, group created, deleted, or membership changed, key rotation, team flip, policies set, recovery kit set, and remote moved. Entry-level cipher churn is excluded because the per-device share-events log covers it locally. Unverifiable commits produce no event. The timeline writes no shared event ledger and records no reads, and it is admin-gated like the access review. The per-device `meta/share-events.enc` stays deliberately local and gitignored.

### Advisory policies

Organization policies are advisory plaintext in `meta/policies.json`, governed by the Admin policy row, with the same shape logic as the collection catalog: the file's existence is the setting and an empty publish removes it, which is the opt-out. `policies.set` and `policies.list` publish and read recommendations, validated fail-closed against the shipped knob table (canonical wire spellings only, 64 KiB cap, unknown knob names rejected). Clients show a recommended hint where it differs from the local setting. No authorization gate reads the file, and enforced settings remain the actual Space controls: invite authority, viewer export, guest access, trash, and restore rules.

### Recovery kit and ownership

The Space Recovery Kit escrows the RootKey to an offline BIP-39 phrase for the physical safe and supports enable, disable, status, and recovery. The kit file `meta/recovery-kit.json` is plaintext and git-tracked under the Admin row so it survives total machine loss. It carries only an HPKE wrap of the RootKey to a key derived from the phrase, bound to one vault, under HPKE context `space-recovery-kit`. Format 2 adds a `root_check` seal, and version 1 kits must be re-enabled. Domain separation keeps it apart from the personal vault's `recovery-keywrap` and the trusted-contact `emergency-escrow`. The kit holds no status machinery on purpose: whoever holds the phrase can unwrap while the file exists, because owner incapacitation cannot wait for an in-band approval, and removal of the file by an administrator is the only off switch. The phrase is shown exactly once, at enable time, and rotation rewraps the escrow in both paths.

The kit is an offline recovery authority for owner incapacity or total device loss. It does not grant repository access, which remains with the provider seat. The escrow wraps the RootKey, flipped members never hold that key, and a recovered owner device unlocks as an administrator and converges. The recovery ceremony verifies the canary, writes the device registry entry, and refuses a recovery that would brick the vault. As first designed it bound the device to the live Owner row; the shipped ceremony is phrase-only and ends in a fresh member row (ADR 0086). Surfaces are the host-level `vault.recover_kit`, administrator-gated `space.kit_*` routes, the desktop Space settings kit section, and the CLI path `baluard vaults recover-kit`. A login-screen recovery interface on desktop and any mobile recovery surface are deferred. The full analysis of emergency access, organizations, and identity is `docs/security/emergency-org-identity.md`.

Owner recovery uses two separate operations and leaves the voluntary transfer untouched. `member_reset` accepts Owner targets for Owner or Admin actors, with the quorum gate already on the operation, and the successor row inherits the Owner role, so a returning owner rejoins as themselves. A new `ownership_claim` covers an owner gone forever: ownership moves to the claiming Admin's existing row and the old owner is demoted. Voluntary `transfer_ownership` remains Owner-only.

Ownership changes use `commit_ownership_swap(vault_path, old_id, new_id)`, a pure record mutator with no authorization inside. It validates that the identifiers differ, that the old row is a live Owner, and that the new row exists and is live. It promotes the successor first (Owner role, self trust) and demotes the prior Owner second. Pair Spaces demote to Editor because they have no administrators and a demoted Admin would wedge later resets; other Spaces demote to Admin, and self trust resets to verified. The promotion-first order is load-bearing: an interrupted update leaves two Owners (recoverable by re-running) rather than none, which would brick the vault. The single-Owner invariant lives only in this helper and is tested once.

`ownership_claim` checks in order: vault unlocked, member-management authority, a disk-backed actor role of Admin, an existing owner row, and a claimant different from the owner. It then runs the quorum gate with parameters `old_owner_id` and `new_owner_id`. The digest binds both identifiers, so an approval cannot replay across a changed owner. The helper runs, and an `OwnershipClaimed` event is emitted. No provider seat work occurs, because Owner and Admin both map to Write and no offboarding happens. The surface is one contextual button per actor: an owner sees Transfer, an administrator viewing the owner row sees Take Over Ownership, and nobody sees both. At threshold 1 the claim is instant, which is the family floor, and raising the knob is the organization's dual control. A demoted owner's devices keep old keys, so a theft-shaped displacement must be followed by `member_remove`, which strikes the seat and rotates. Reset and claim stay fully separate operations. A contest window for claims was left as an advanced opt-in for a later wave, and it landed for family purpose only (ADR 0086).

### Mobile multi-vault

Mobile supports up to three unlocked vaults through `MultiVaultSession`. Switching uses the existing per-vault exports, and the least-recently-used vault is locked when the limit is exceeded. `ON_STOP` locks inactive sessions, and a per-session auto-lock poll enforces each vault's timer, replacing the desktop walker. The mobile app does not introduce a Rust multi-vault host, and no uniffi lifecycle API changed.

The limit exists because the Android `:autofill` process forbids master-password Argon2id (64 to 256 MB per unlock), so a phone holding several unlocked vaults must budget key derivation work and resident keys. The rule is one Argon2id at a time, with other vaults staying locked until switched. App-level coordination won over a `MobileVaultHost` object over the runtime host. The fast path lives in the switcher.

### Default doctrine

There is no new `family` vault shape, because the shape drives the unlock path and RootKey distribution and a third shape is invasive. A family is a Space created through a family preset: `join_approval` set to `code` at creation so the invite code auto-approves and nobody waits on a sofa (the stored default stays `manual`), adults as Admins, children as Editors or Viewers, and zero settings screens. The original plan listed guest reveals as on in the preset; a product decision on 2026-10-03 made guest reveals opt-in (off unless explicitly enabled) for every Space. Organizations use the shipped defaults: quorum 1, manual approval, admins invite, admins create collections, viewer export off, editors trash, and admins restore. The advanced tier (quorum 2 through 5, owners-only invitations, Recovery Kit) lives in Space settings, off by default, flipped by the primary administrator. One personal vault per human holds the identity and Spaces carry zero master passwords. That decision is permanent: a departing member keeps personal data while company data locks.

### Cross-cutting debt closed with the pack

Desktop admin gating uses the server-derived `vault.is_admin_device` marker (`holds_root`) through a context signal instead of counting rows. The marker is key state: a locked vault reports false, and a demoted but unlocked device keeps reporting administrator until it locks, a recorded boundary. A flipped-vault two-administrator test runs the threshold-2 rotation ceremony (ask ships via git, the confirming rotation executes on the confirmer's clone, both administrators converge through key adoption, the SMK is byte-invariant, and the old root is rejected). The mobile settings screen lists pending approvals beside the quorum knob.

### Deferred and parked sharing work

Personal-space scope (S5) is deferred in full: personal areas (a member's private corner of a shared vault, whereas today personal means admin-only flat ciphers), a per-item ACL exception (one item shared outside its collection), inline item keys, travel mode, peer-to-peer send, provider discovery, and per-member theme and language preferences. Parked scenario items with no phase are `space.export` and `space.sever` (clean split of a Space into or out of a vault) and the out-of-band adopt link plus cold mirror (the re-bind itself shipped as remote migration, ADR 0047). The explicit staged path sets for the multi-writer git layer shipped (ADR 0063). Parked past 1.0: iOS sharing parity, browser extension phase 2, and two-factor tiers 2 through 5. Recovery-key export as text or Markdown shipped inside the recovery-phrase rotation ceremony (ADR 0077), while PDF and print remain parked.

## Consequences

Organizations can require distinct administrators for sensitive operations and review effective access from local state. Group membership reduces repeated per-member grants without changing collection encryption.

The timeline proves structural events in verified history only. It cannot report reads, and unverified history contributes no narrative. The access review is not a global view of outbox links or contact-key grants.

Quorum is enforced on administrator devices only, because the threshold lives in encrypted settings. A peer cannot judge a commit against the knob, so quorum is a control among cooperating administrator clients and not a property that the sync walker verifies.

At quorum 1, an Admin may claim ownership without a second approver. A family contest window can provide a 30-day Owner cancellation period, but the default organization quorum remains 1. Recovery phrases require offline protection; loss of all Admin devices and the phrase remains unrecoverable. The kit phrase must be stored outside the devices and repositories it protects, and a stolen phrase can recover the RootKey; quorum controls do not protect against independent possession of the recovery authority. A demoted owner who held the old keys keeps them until a removal rotates.

Mobile holds at most three vault sessions unlocked. Additional vaults require locking an existing session, and the lifecycle is coordinated by the application rather than the Rust runtime host.

Quorum approval records and policy recommendations are visible in shared history. They reveal administrative intent and configuration changes even though they do not reveal individual credential reads.

Group rotation adds ciphertext and wrap churn as membership changes. Collection keys remain unchanged when only group membership changes, so users must rotate a collection key separately if a former grantee may already have extracted it.

The access review does not discover all outbox mirrors or local contact-key grants. Administrators must use the separate sharing surfaces to review those grants. A removed member's access review row is an exposure indicator, not evidence of whether the member retained plaintext, and no timeline can prove that a member read or copied a credential.

## References

- ADR 0085 (`docs/adr/0085-sharing.md`) and ADR 0086 (`docs/adr/0086-family-spaces.md`).
- Per-slice history: ADR 0062 (`docs/adr/0062-two-admins-two-signatures.md`), ADR 0064 (`docs/adr/0064-two-keys-to-the-owner-s-chair.md`), ADR 0065 (`docs/adr/0065-who-can-see-what-on-demand.md`), ADR 0066 (`docs/adr/0066-recommend-never-enforce.md`), ADR 0067 (`docs/adr/0067-the-phrase-is-the-last-key.md`), ADR 0068 (`docs/adr/0068-recovery-is-a-fresh-clone-and-a-phrase.md`), ADR 0069 (`docs/adr/0069-the-phone-keeps-its-spaces-open.md`), ADR 0070 (`docs/adr/0070-the-department-holds-a-key.md`), ADR 0071 (`docs/adr/0071-history-is-the-ledger.md`), and the hardening wave ADR 0078 (`docs/adr/0078-the-hardening-wave.md`).
- `docs/security/emergency-org-identity.md`.
- `crates/baluard-core/src/vault/approvals.rs`, `crates/baluard-core/src/vault/groups.rs`, `crates/baluard-core/src/vault/policies.rs`, `crates/baluard-core/src/vault/recovery_kit.rs`, `crates/baluard-core/src/sync/timeline.rs`, `crates/baluard-runtime/src/host.rs`, `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/auth/MultiVaultSession.kt`.
