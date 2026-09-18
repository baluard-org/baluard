# Plan: Sharing (Spaces, Roles, Collections, Item Sharing)

**Status**: Proposed. Not implemented beyond the primitives listed in §2.
**Rev 3**: integrates a peer review pass (high reasoning). Changes: scoped net-diff merge rule replaces the linear-history rule (D22 policy no longer fights the shipped conflict engine), provider ACL grant side added (§4.5, §4.1 step 0), mandatory code read-back in join approval, standalone item keys wired into Space rekey, lost-device self-service flow, owner incapacitation, device files split out of member files, quarantine protocol specified (neutralize-and-notify), bulk removal = one rotation, roadmap S2/S3 swapped (items before collections), minimal Activity viewer pulled into S1.
**Rev 2**: integrates a peer review pass (member/device split, directory metadata, inline item keys, join queue, offboarding pre-flight, cross-epoch offline merge).
**Scope**: Every scenario where more than one person touches the same data in Baluard, on the existing serverless architecture (git remote = transport, no backend).
**Companion docs**: `docs/software-architecture-decisions.md` § D9 / D17 / D19 / D22 / Domain 6, `docs/software-architecture.md` § 4.2 / 4.4, `docs/threat-model.md`.

---

## 0. TL;DR

| # | Scenario | Design (recommended) | Phase |
|---|----------|----------------------|-------|
| A | Whole vault shared, roles: owner / admin / editor / viewer | Directory membership (`meta/members/`) with member → devices split + role field + D22 signature-policy enforcement | S1 |
| B | Item shared between 2 users, equal power | Standalone random item key, wrapped per recipient, inline in the Space they share; cross-vault pairs use a visible 2-person Space; one-shots use encrypted package export | S2 |
| C | Item shared, owner keeps control, revocable | Same inline item keys, grant = viewer, item-key rotation on revoke | S2 |
| D | Org granularity: collections with per-grant role, admins see all, trash purge admin-only | Per-collection random keys (BW model), personal areas, trash signature policy | S3 |
| E | Parity gaps vs Bitwarden / 1Password | Matrix in §5.E; build activity log, org policies, guests; reject Send/SSO | S4 |

Key exchange: **bilateral QR scan** in person (families), **in-repo join queue** for orgs/remote — with a mandatory code read-back at approval and a provider-collaborator grant step before first clone. No server, ever.

Enforcement split, honest and explicit:

- **Read scope** = cryptography. You can read what you hold keys for. Nothing else. Guests and narrow members never receive the SGK.
- **Write integrity** = Ed25519 commit signatures (D22) + per-path signature policy on pull. Merge commits are judged by their net diff against the signer's scope (ordinary conflict resolution stays legal for editors; `meta/` and `trash/` stay admin-only).
- **Availability** = git provider ACLs (who can push at all). Granted and revoked through the same UI flow as membership (§4.5). Documented, not solved by us.

---

## 1. Scenarios

From Esteban, made testable:

- **A. Shared Space, roles.** One vault shared by 2+ people. Owners and admins have full control. Editors can create and edit entries. Viewers can read and use (copy, TOTP, autofill) but not modify. All roles can sync.
- **B. Item co-ownership.** Two Baluard users share a single entry with equal power: both edit, both can revoke the other.
- **C. Owner-controlled item share.** Same as B but one-sided: the owner keeps full power; the recipient can view and use only; the owner can revoke at any time.
- **D. Org granularity.** Owner and admins access everything. Other members access only assigned collections (categories / folder-like groups), each grant read-only or read-write. Trash purge and empty are owner/admin-only.
- **E. Parity.** Whatever Bitwarden and 1Password do for sharing that Baluard lacks, adapted to serverless reality. Listed, triaged, ranked in §5.E.
- **F. (derived) Personal area in a shared Space.** A member keeps private entries inside a shared Space, invisible to admins. 1Password "Private vault" parity. Configurable off.
- **G. (derived) Guest.** An outsider (family accountant, contractor) gets exactly one collection, read-only, no visibility into the rest; ideally with a natural end date. 1Password Guest parity + advisory expiry (§5.F-8).
- **H. (derived) Multi-device member.** Every member owns 2+ devices (phone + laptop). Adding a device must not involve the Space owner or any admin; losing one must not involve them either (§5.F-6).
- **I. (derived) Clean split.** A couple separates, or a spin-off team leaves a company: one party takes a copy of selected entries (or the whole Space) and severs the link. §5.F-2.
- **J. (derived) Departure with live provider access.** An employee leaves while their PAT / collaborator status on the git host is still active. Crypto revocation alone leaves repo tampering open. §5.F-3.
- **K. (derived) Owner incapacitation.** The only person with provider-account admin rights on the family Space dies or loses the account. §5.F-7.

"Everything ideally configurable" translates into an org settings block, §6.5.

---

## 2. Current state

What already exists and is reused:

| Piece | Where | Notes |
|---|---|---|
| Space Group Key hierarchy | `crates/baluard-core/src/keys/`, `vault/handle.rs` | RootKey → SGK → ItemKey (HKDF, epoch-bound). Zeroize. Single-user derivation today: `derive_from_root_key` |
| Org key wrapping | `crates/baluard-core/src/orgs.rs` | D17: X25519 + HPKE `WrappedKeyBundle`. `add_member`, `remove_member` (returns new group key, re-wraps survivors). `AccessList` at `meta/access_list.json`, atomic write, 0600 |
| Rekey on removal | `vault/handle.rs` `revoke_device_and_rekey()` | Full rotation: re-encrypt ciphers + attachments + keywrap, crash marker, `RotationGuard` |
| Commit signing + verification | `sync/engine.rs` D22 | Ed25519 signature embedded in commit object. `verify_commit_signatures` runs BEFORE refs/worktree update on every pull/merge, against known device keys (`meta/device-pks`) |
| Conflict resolution | `sync/engine.rs` `finalize_conflicts` | Writes **2-parent merge commits** signed by whichever device resolved (auto-merge, keep_local/remote, keep_both all route here). Any write-policy design must keep these legal for editors |
| Emergency access | `crates/baluard-core/src/emergency.rs` | Pre-wrapped Root Key, HPKE, advisory time gate. Reuses `WrappedKeyBundle` |
| Recovery | `crates/baluard-core/src/recovery.rs`, `device_manager.rs` | One BIP-39 phrase per vault, wraps the Root Key. `EnrollmentPolicy::ExistingDevice` (device-signed) or the recovery path (phrase-based device enrollment, bypasses device approval). Phrase is generated at Space creation, held by the creator |
| Multi-vault host | `baluard-runtime/src/host.rs`, `state.rs` | VaultHost map + active pointer. A shared Space is just another vault |
| Sync engine | `sync/engine.rs` | commit → pull (force-checkout) → resolve → push. Network classification, conflict merge (F1 auto / F2–F4 panel) |
| Devices | `device_manager.rs` | Enrollment (device-signed approval or phrase), quorum, force-evict, epochs. **Devices hold the keypairs, not users**. Rotation quorum = `ceil(N/2)` of all enrolled devices — must be decoupled for org scale (§4.4) |
| Trash | `vault/handle.rs` | `trash/<id>.enc` envelopes; delete = move, second delete = purge. No role gating today |
| Providers | `crates/baluard-core/src/providers/` | ForgeProvider trait + OAuth + `provider.create_repo`. **No collaborator add/remove/list yet — a gap this plan closes (§4.5)** |

What does not exist:

- No caller: zero CLI commands, daemon routes, or UI touching `orgs.rs`. It is a library island.
- No roles. `OrgMember` = `{email, device_id, x25519_public_key}`. D9 says "Admin"; nothing models it.
- No collections, no per-folder or per-category keys, no grants.
- No item-level keys. ItemKeys are HKDF-derived from SGK; a standalone, shareable item key does not exist.
- No key exchange. D9's "fetch invitee public key from the Git host by email" is not implementable as written.
- No signature policy. D22 verifies that a commit is signed by a known device, not that the signer was allowed to touch those paths.
- Plaintext emails in `access_list.json` leak member identities to the git remote.
- No cross-epoch re-encryption for authorized members with unpushed offline edits.
- No provider collaborator management (grant or audit).

---

## 3. Architectural constraints (non-negotiable context)

1. **No server.** The git remote is a dumb store. Every "who may do what" decision is made locally by clients, enforced cryptographically or via signatures, or not at all.
2. **Git commits are the event log.** Membership changes, grants, revocations: all are commits, all are signed, all are visible to every member. This is the audit trail for free (§5.E-7).
3. **Revocation is eventual.** A removed member keeps reading their local clone (old ciphertext, still decrypted in their memory/disk from before). New commits are invisible: encrypted under a key they lack. Inherent to serverless. The threat model documents this for devices; it holds for members.
4. **Integrity vs availability boundary.** Cryptography protects secrecy. Anyone with git push rights can delete files or push garbage. We cannot prevent it; we can detect (signatures), neutralize (§4.4), revert (git history), and the provider's collaborator settings remain the real access-control boundary. The product must say this plainly, once, in plain language.
5. **Symmetric keys do not separate read from write.** An AES key that decrypts also encrypts. "Read-only" is therefore never a data-layer property; it is enforced by (a) read-scope key distribution and (b) authorship verification via signatures. Any design claiming crypto-enforced read-only writes is wrong. §4.4 is built on this.
6. **Two authorities, one user.** Access to a shared Space = (a) crypto membership (`meta/members/`, keys) AND (b) provider ACL (clone/push rights on the repo). They are granted, audited, and revoked by different mechanisms and MUST be managed in one UI flow, in the right order (§4.5). Neither implies the other.
7. **Padded buckets.** 5-tier uniform sizes already hide per-entry metadata. Sharing adds metadata surface: membership files, grant lists, commit patterns. Keep opaque IDs in plaintext files; encrypt names and never store emails in plaintext.
8. **Pre-1.0.** Formats break freely. Replace `access_list.json` outright; no migration shims.
9. **First-release UX bar.** Non-technical users never see: HPKE, SGK, epochs, signature policy. They see "Share", "Invite", role pickers, and a fingerprint check the UI calls "Compare the codes".

---

## 4. Building blocks

### 4.1 Key exchange: how an invitee's public key reaches the admin

**KX-1. Bilateral QR scan (recommended base, in-person).**
Both devices run "Share": the inviter shows a QR encoding their contact block (member UUID, display name, X25519 wrapping key, Ed25519 signing key); the invitee scans with the camera, and both screens display a short verification code (SAS) derived from both key sets. Humans compare visually. One gesture, no files, no second app.

**KX-2. In-repo join queue (recommended base, orgs / remote).**
Steps, in order:

1. **Provider grant (step 0, mandatory):** the admin client calls the new `ForgeProvider::add_collaborator` (GitHub/GitLab/Codeberg) to invite the invitee's provider account to the private repo, and shows the deep link to the provider's invitation-acceptance page. The invitee accepts in the browser (one click from the provider's email). Without this, the invitee cannot clone; Baluard must never pretend otherwise (§4.5).
2. **Enrollment token:** the admin generates a one-time token (repo URL + token), shown as text/QR/link, handed over any channel.
3. **Self-introduction:** the invitee pastes it into Baluard; their client clones the Space, generates its identity, and pushes a signed self-introduction to `meta/pending/<device_uuid>.json`. Pending entries carry no keys.
4. **Approval with mandatory code read-back:** the admin gets "Ana wants to join" in-app. The approval screen shows a short verification code derived from the pending device's keys. The admin reads it back to the invitee over an independent channel (existing chat thread, phone call) and approves only on a match. The self-reported display name is NOT verification — a leaked token otherwise lets an attacker register under any name. The code comparison is mandatory, not optional.

**KX-3. Contact-card file (fallback, remote + no org).**
The KX-1 block exported as a `.baluard-contact` file / copy-paste text, transported over any channel, imported by the admin, SAS compared out-of-band. Kept for cases where neither party can host a queue and the invitee has no camera.

**KX-4. Provider discovery (sugar, later).**
Invite by git-host username; Baluard publishes the member's public keys as a GPG key on their provider account; admin client fetches and verifies. Still requires the SAS comparison. Fragile per-provider adapters. Build only if invite friction proves real.

**KX-5. Central key directory.** Rejected: a server. Violates the architecture and the promise.

**Decision**: KX-1 for families in person; KX-2 for companies and remote onboarding (in S1, with step 0 and mandatory read-back); KX-3 fallback; KX-4 optional.

Trust model note: all variants are TOFU + explicit verification. KX-1/3 verify via SAS comparison; KX-2 verifies via the code read-back at approval time (the admin's knowledge of the invitee is necessary but never sufficient). The UI makes the comparison a step, not a suggestion.

### 4.2 Membership v2: directory, member → devices

**Identity model.** Baluard's crypto is device-based: devices hold keypairs (D1, `device_manager.rs`). Users are humans. The membership model says both:

- A **member** is a human: one stable member UUID, display name, Space role. One file: `meta/members/<member_id>.json` — identity + role only.
- A member's **devices** are one file each: `meta/members/<member_id>/devices/<device_id>.json` (public keys, added_by).
- Key wraps are one file each: `meta/members/<member_id>/<device_id>.wrap` (HPKE-wrapped SGK for that device), `meta/collections/<collection_id>/<member_id>-<device_id>.wrap`.

```json
// meta/members/<member_id>.json
{
  "id": "<member_uuid>",
  "display_name": "Ana",
  "role": "editor",
  "email_enc": "<optional, encrypted under SGK>"
}
```

```json
// meta/members/<member_id>/devices/<device_id>.json
{
  "device_id": "<device_uuid>",
  "x25519_public_key": "<hex>",
  "ed25519_public_key": "<hex>",
  "added_by": "self"
}
```

```json
// meta/collections/<collection_id>.json
{
  "id": "<collection_uuid>",
  "name_enc": "<encrypted name>",
  "grants": [ { "member": "<member_uuid>", "access": "view|write|manage", "expires_at": null } ]
}
```

**Why per-file everywhere (no JSON content merges).** Every field bundle that two different writers may touch concurrently lives in its own file: role edits (admin) never share a file with device enrollment (member); wrap files are write-once per rotation. Git merges disjoint file adds/deletes trivially; no 3-way JSON resolver exists anywhere in this design.

**Rules:**

- Plaintext contains opaque UUIDs and display names only. No emails in plaintext (encrypted `email_enc` optional). Fixes the current leak in `access_list.json`.
- `role` is the Space-level role (A). `collections[].grants` is the D layer. Effective read = max(Space role, collection grant). Write additionally requires a signature the policy accepts (§4.4).
- `expires_at` on a grant is optional, advisory (§5.F-8).
- Every mutation is a signed commit. Policy maps `meta/members/<own_id>/**` to that member (device add/revoke, self-service), everything else in `meta/` to admins/owners.
- Pending queue: `meta/pending/<device_uuid>.json`, promoted by admin approval (KX-2 step 4).

### 4.3 Key model changes

| Key | Today | After |
|---|---|---|
| SGK | derived from RootKey, encrypts entries + index | same, for personal and fully-shared Spaces; wraps every collection key (admin/owner path) |
| Item key | HKDF(SGK, cipher_id, epoch), never materialized | unchanged for unshared items. When an item is shared (B/C): generate a random 256-bit key, re-encrypt that one envelope, store `entries/<cipher_id>.keys/` with the item key wrapped per authorized device. Envelope gains a `key_ref` marker |
| Collection key | does not exist | random per collection (§5.D); item keys for collection entries derive from it, epoch-bound like today |

**Rotation coverage — the complete list (nothing left unwrapped):**

| Trigger | What rotates |
|---|---|
| Item revoke (C, targeted) | that item's standalone key: one envelope re-encrypted + wraps |
| Member removed from one collection (D) | that collection key: its envelopes + wraps |
| Device lost by a surviving member (K scenario, §5.F-6) | no key rotation: delete that device's wrap files only (§5.F-6 explains why) |
| Member removed from the Space (A) | SGK (full rekey, existing machinery) + EVERY collection key + **EVERY standalone item key that member could reach** (enumerate from `entries/<id>.keys/` grants; covers passkey private keys inside `fido2_credentials`, which re-wrap with the item) |
| N members removed (bulk) | ONE rotation covering the union (batch `remove_members([…])`), never N sequential rekeys |

**Git-history bloat note.** Every full rekey rewrites every blob: a 200 MB vault adds ~200 MB of history per rekey. Mitigation shipped in S4: `baluard space migrate` creates a fresh remote, pushes a single squashed history of current state, updates the remote URL for members. No force-push tricks against provider policies.

### 4.4 Enforcement points (what makes "viewer" mean anything)

| Layer | Mechanism | Enforces |
|---|---|---|
| Read scope | Key distribution: viewers of collection X hold only X's key path; guests hold no SGK | Confidentiality. You cannot read what you cannot decrypt |
| Write policy | D22 extension. On pull, for each new commit: (a) signed by a known device (existing); (b) the signer's role must cover every path the commit's **net diff** touches. Net diff = `diff(first_parent, commit)` for every commit type, merges included. A merge commit is legal for any signer whose scope covers the changes the merge INTRODUCES — so ordinary conflict resolution by editors (`finalize_conflicts`, 2-parent commits) stays legal — and illegal the moment the net diff touches `meta/` or `trash/`, which are admin-only (except a member's own `meta/members/<own_id>/**` subtree) | Integrity: an editor resolving a content conflict syncs normally; an editor whose merge smuggles a grant change or a trash move is rejected by every honest client. Rejected content is neutralized, not merged (below) |
| Quarantine protocol | For a commit that fails (b): fetch proceeds, the commit stays in history as an ancestor (no force-push, remote keeps flowing), but the policy engine **restores the offending paths from the last known-good admin commit** before the worktree is loaded by the vault, records the bad content on a local audit ref, and notifies admins ("blocked changes from Ana — review"). The next admin commit overwrites the paths canonically; the bad payload is never decrypted into any vault state | Detect + neutralize + revert, without freezing sync. Honest about the limit: the bad commit exists at the provider; only its EFFECT on vaults is erased |
| Per-member subtree | `meta/members/<own_id>/**` writable by that member (any role): device add, lost-device wrap revocation (§5.F-6). All other `meta/` admin/owner; `entries/` per write scope; `trash/` per trash policy (§5.D) | Self-service without admin involvement |
| Soft policy | Client-side checks (hide buttons, block export) | UX only, stated as such |
| Availability | Provider collaborator settings (who may push), granted/revoked via §4.5 flows; org setup surfaces the provider's branch-protection checklist as an optional hardening step | The real outer fence |

**Rotation quorum decoupling.** Device-enrollment quorum (`ceil(N/2)` of all devices, Domain 6) cannot gate org-scale rotations: revoking one employee must not wait for 50 offline laptops. In shared Spaces, the rotation *commit* is authorized by `quorum_admin_ops` admin signatures (§6.5) and pushed unilaterally; the fleet-ack quorum keeps governing device ENROLLMENT only. Org Spaces should set enrollment approval to admin-signed as well.

Known, documented limits (not fixable serverlessly, said once, plainly):

- **Deletion by omission.** Git commits are tree snapshots; a push-authorized editor can craft a tree that simply lacks a file. Signatures prove authorship, not completeness. Git history preserves the data; admins restore from Activity.
- **Quarantine is not prevention.** The bad commit exists at the provider; only its effect on vault states is neutralized (§4.4 table).
- **Unlocked-device theft.** If a device is stolen while unlocked, the attacker holds decrypted keys until lock; wrap revocation cannot undo that. Full rekey is the response, as for any compromised device.

### 4.5 Provider ACL coupling (grant + revoke, one flow)

The crypto membership and the repo ACL are two authorities (§3-6). The plan manages both:

- **Grant (onboarding):** KX-2 step 0 (§4.1). New `ForgeProvider` methods: `add_collaborator(repo, account)`, `collaborator_status(repo, account)`, deep link to the invitation-acceptance page. GitHub/GitLab/Codeberg all support collaborator invites via API; the invitee's one-click acceptance happens in the provider's own UI. For in-person KX-1 (family, same couch), the same grant step runs in the background before first sync.
- **Revoke (offboarding):** §5.F-3 pre-flight. Removal runs `collaborator_status` first; if the departing member still holds access, the flow blocks with a checklist and deep link until resolved (or the admin overrides for offline orgs).
- **Hardening (org preset):** setup surfaces the provider's branch-protection checklist ("require reviews / restrict force-pushes") as an optional recommended step with a deep link. It is the only mechanism in the stack that PREVENTS rather than detects a rogue push; it costs nothing and stays optional because it is provider-native configuration, not Baluard state.

---

## 5. Scenario designs

### 5.A Whole-Space sharing with roles

**Roles and capability matrix** (Space level):

| Capability | Owner | Admin | Editor | Viewer |
|---|---|---|---|---|
| Read/use all entries | Y | Y | Y | Y |
| Create/edit entries | Y | Y | Y | N |
| Move to trash (write scope) | Y | Y | Y* | N |
| Restore / purge / empty trash | Y | Y | N | N |
| Invite / remove members | Y | Y | N | N |
| Change member roles | Y | Y (not owner) | N | N |
| Enroll own devices / revoke own lost device | Y | Y | Y | Y |
| Rotate keys / rekey | Y | Y | N | N |
| Delete Space | Y | N | N | N |
| Manage collections & grants (D) | Y | Y | N | N |
| Change Space settings | Y | Y | N | N |

*Y\* = per trash policy setting, default `write_scope_can_trash` (§5.D, §6.5).

- Multiple owners allowed; default: the creator. Removing the last owner requires transferring ownership first (checked in UI and policy: a commit leaving zero owners is invalid).
- Quorum for destructive admin ops: `quorum_admin_ops` admin signatures (§4.4, §6.5). Default 1.
- Invite flow: Share → "Invite someone" → pick role → QR scan (together) or join code (remote; includes the provider-invite step and the code read-back) → approve → done. The invitee's client pulls, finds its member file + device wrap, unwraps, shows "Ana added you as Editor".
- Accept flow: provider invite accept (browser, once) + join code. Nothing else to click.
- Device enrollment (H) and lost-device revocation (§5.F-6): fully self-service inside the member's own subtree.
- Remove flow (existing D19 path, wired at last, now batch-capable): admin selects one or many members → pre-flight (§5.F-3) → ONE rotation covering SGK + collections + reachable item keys (§4.3) → re-wrap survivors → push. Progress UI: "Updating encryption for 5 people…". The evicted member sees "Your access to Work was removed" on their next sync attempt (fail closed; message mirrors the stale-KEK PIN path).
- **Recovery phrase custody (shared Spaces).** The phrase wraps the Root Key: it is the OWNER credential, not a member credential. Members never receive it. Rules: (a) multi-member Spaces enforce `EnrollmentPolicy::ExistingDevice` (phrase-based enrollment off — a phrase is a root bypass, meaningless to hand to members); (b) ownership transfer includes phrase re-escrow for the new owner (the old owner's phrase stops working for enrollment: new keywrap under their master password, emergency-escrow style); (c) the setup UI shows "your recovery phrase restores YOUR owner access; members are managed in Share".
- Viewer restrictions beyond writes: vault export disabled (configurable `allow_viewer_export`), clipboard auto-clear already exists, TOTP/passkey use allowed (autofill needs read only).

**Alternatives for the roles model:** R-1 flat Space role (chosen) / R-2 per-member capability flags (reject: unusable UI) / R-3 Bitwarden custom roles (defer).

### 5.B Item co-ownership (equal power) & 5.C Owner-controlled share

B and C are one mechanism with different grants. The mechanism is **inline item keys**, not separate repositories.

**IS-4. Inline item-key sharing (primary).**
For any two users who already share a Space (family Space, org Space): "Share this entry" → the entry migrates to a standalone random item key (one envelope re-encrypted), the key is wrapped per authorized device into `entries/<id>.keys/`. Both editors (B) or owner + viewers (C). No new repos, no new sync loops, no provider API calls. Conflict merge: the field-level merge already runs per cipher; shared items use it unchanged. Space-level member removal rotates reachable item keys (§4.3) — the C guarantee holds no matter which revoke path fires.

**IS-5. Two-person shared Space (cross-vault, live sync).**
For two users who do NOT share any Space: the guided flow creates a small, **visible** Space ("Ana & Bob") — scenario A with a preset (both editors for B; owner + viewer for C) — and moves/shares the entries into it. Visible in the vault switcher on purpose: hidden vaults confuse sync status, auto-lock, and detach. One repo per pair-relationship, not per item.

**IS-3. Encrypted one-time package (one-shot, no ongoing sync).**
"Send a copy": owner encrypts the entry under the recipient's public key into a `.baluard-item` package, transferred by any messenger; the recipient imports it into a Space of their choice. No repo, no relationship, no revocation (the copy is theirs; share-time copy says so).

**Rejected:** IS-1 hidden micro-Space channels (repo/API/mobile explosion, hidden-state confusion); IS-2 cross-repo read grants (metadata leak, coupling).

**B semantics**: equal power = both editors; either can remove the other (that removal rotates the item key or, in IS-5, rekeys the Space). Either can delete the entry: deletion removes it for both. UI: "You'll both be able to edit and remove it."

**C semantics**: grant = viewer. Signature policy rejects viewer writes; the UI hides edit affordances anyway. Revoke: owner removes the viewer → item keys rotate (one envelope + wraps). Share-time copy: "They'll keep a copy of what they've already seen." (§3-3.)

### 5.D Org granularity: collections

**CO-1. Per-collection random keys (Bitwarden model, adapted). (Recommended)**

- A collection = a named bucket of entries inside one Space: `meta/collections/<id>.json` + grants. Rendered in the existing sidebar tree ("Collections"; folders stay personal).
- **Collections are available to ANY Space** — a family may segment "household finances" from "kids' subscriptions" exactly like a company segments teams. The presets (§6.5) differ in defaults only, never in capability.
- Every collection gets a random 256-bit key. Wrapped: (a) under SGK — the admin/owner master path; (b) per granted member's devices (`meta/collections/<id>/<member>-<device>.wrap`).
- Entries carry `collection_id` in envelope meta; item keys for collection entries derive from the collection key. Entries outside any collection: visible only to admins/owners (SGK) or inside the member's personal area (F).
- Grant levels: `view` / `write` / `manage`, optional advisory `expires_at`. `manage` = can edit the collection's name + grants (delegated admin).
- Member removed from a collection: rotate that collection key, re-encrypt its envelopes, re-wrap remaining grantees. Member removed from the Space: full coverage per §4.3.

**Trash policy (D requirement, as revised in Rev 2).**

- **Move to trash**: any member with `write` on the entry's scope (collection grant or Space role) may trash entries they can write — an editor who cannot delete accumulates stale credentials and keeps using expired passwords. Setting name: `write_scope_can_trash` (Renamed from Rev 2's misleading `editors_can_trash_own`: the scope is the write grant, not authorship — one editor can trash an entire collection they have write on).
- **Restore / purge / empty trash**: owner/admin only, enforced client-side AND by the signature policy on `trash/` writes.
- **Undo window**: client-side, pre-push: a just-trashed entry can be un-trashed locally by its trasher for 30 days or until the next sync pushes it — accidental deletes inside org Spaces never need an admin for a 5-second oops. The admin-gated restore remains the path once the trash has synced.
- Trash listing hidden from viewers. Honest limit (§4.4): a push-authorized editor can delete an `entries/` file outright; git history preserves it; Activity surfaces restorable deletions.

**Personal area (F).** A per-member collection `personal:<member_uuid>` whose key is wrapped only for that member's devices. Optional per Space (§6.5 with rationale). Admins cannot read it, by design; the settings screen says so.

**Guest (G).** A member with role `viewer` + a single collection grant, no SGK wrap, optional expiry (§5.F-8).

**Alternatives:** CO-2 keyed folders (rejected: folders are personal per-user views), CO-3 per-item ACLs only (rejected: members × entries wrap explosion), CO-4 folder-path grants (rejected: org structure must be shared state).

### 5.E Parity gaps vs Bitwarden / 1Password / Proton Pass

Triage: **Build** (this plan), **Defer** (post-1.0), **Reject** (architecture-incompatible).

| # | Feature (origin) | Baluard adaptation | Verdict | Phase |
|---|---|---|---|---|
| 1 | Organizations (BW) / Teams (1P) | Spaces + roles (A) + admin layer | Build | S1 |
| 2 | Item sharing (BW org item share / 1P) | Inline item keys + pair Space + package (IS-4/5/3) | Build | S2 |
| 3 | Collections (BW) / shared vaults (1P) | Keyed collections (D) — any Space, preset default | Build | S3 |
| 4 | Per-collection permissions (1P View/Edit/Manage) | Grant levels view/write/manage | Build | S3 |
| 5 | Guests (1P) | Viewer + single grant, no SGK | Build (falls out) | S3 |
| 6 | Private vault per member (1P) | Personal areas (F) | Build | S3 |
| 7 | Event logs / item audit (BW) | Git history IS the log: signed commits per action. Activity viewer (per-entry + per-Space timeline, plain-language rendering). Minimal read-only view ships in S1 — the detect-and-revert trust model needs a human-readable surface from day one | Build | S1 (min) / S4 (full) |
| 8 | Org policies (BW: password requirements, lock timeout, export ban) | Policy block in `settings-pub.json` + `settings.enc`; advisory client-side enforcement; admin sees a compliance report, never a guarantee | Build (advisory) | S4 |
| 9 | Admin password reset (BW) | Incompatible with zero-knowledge. Member recovery phrase; fully locked out → admin removes + re-invites (data survives in repo). Documented recovery path | Adapt | S4 |
| 10 | Send / temporary share links (BW) | Needs a relay. Serverless alternative = IS-3 package or C-style share. Reject links for 1.0; revisit P2P if demand | Reject (now) | — |
| 11 | SSO / SCIM / LDAP (BW enterprise) | Requires identity server. Org onboarding = join queue (KX-2) | Reject | S5? |
| 12 | Travel Mode (1P) | Serverless gap: local clone persists. Offline-only flag + full rekey on return. Honest and weak; defer | Defer | S5 |
| 13 | Groups of users (BW) | Extra key hierarchy layer. Defer until real orgs exceed ~20 members | Defer | S5 |
| 14 | Attachments in shared content | Ride the item key / collection key. Verify in tests | Build (verify) | S2 |
| 15 | Favorites / per-user metadata | Per-client state already. Verify sync excludes per-user flags from shared envelopes | Build (verify) | S3 |
| 16 | Browser extension + mobile for shared vaults | NMH bridge + uniffi expose collection-aware reads and roles: `vault.list_collections`, collection-filtered `match`/`get`, role-gated `save`. Each new route gets an explicit D21 allowlist decision (added routes in S1: read-only `match`/`get`/`list_collections`; invite/role routes stay daemon-only). Autofill works for viewer/guest from day one of each phase. Mobile ADMIN surfaces (invite/approve/roles) follow in S3, not desktop-forever | Build | S1 (reads) / S3 (collections + admin) |
| 17 | Emergency access (BW premium) | Exists. Document emergency × org Spaces (trustee = admin-level) and × provider ownership (§5.F-7) | Adapt doc | S4 |
| 18 | Per-item custom permissions (BW enterprise custom role) | Reject for 1.0 | Reject (now) | — |
| 19 | Shared passkey/TOTP caveats | Doc + UI: shared passkeys work with RPs that tolerate counter gaps (syncable passkeys commonly do); strict-RP passkeys carry a "shared use" warning tag. TOTP stays inside the username/password/TOTP atomic merge group | Build (doc + tag) | S2 |
| 20 | Repo ownership & quota | Space settings show repo owner + size; `baluard space migrate` for compaction/ownership (§4.3); free-tier guidance | Build | S4 |
| 21 | Temporary/expiring access | Optional `expires_at` on grants; advisory reminders to admins; consistent with "policies are advisory" (§5.F-8) | Build (advisory) | S3 |

Parity summary after S4: Bitwarden-tier sharing minus Send/SSO/groups, with a strictly better audit story (signed git history) and strictly weaker policy enforcement (no server). That trade is the architecture, stated once, plainly.

### 5.F Lifecycle and operations

1. **Multi-device member (H, add).** Self-service: the member's existing device wraps SGK + readable collection keys for the new device and pushes into `meta/members/<own_id>/`. No owner, no admin. Test: invite Bob once; Bob adds phone + tablet himself.
2. **Clean split (I).** (a) "Take my copy": batch-select entries → package export (IS-3) or move into a personal Space, then leave. (b) "Sever and keep": convert the local clone into an independent Space — fresh member set, fresh RootKey via existing rotation, new remote via `provider.create_repo`. The old Space is unaffected.
3. **Departure pre-flight (J).** Admin removal runs `collaborator_status` first (§4.5); if the departing member still holds push access, the flow blocks with a checklist and deep link until the provider ACL is resolved (override available for offline orgs). Removal side of the §4.5 two-authority rule.
4. **Offline member across a rekey (K).** Pull detects `epoch` advance. Still authorized: unwrap the new SGK, re-encrypt unpushed local commits' content into one fresh commit on top of the rekey HEAD, push; old-epoch commits go to a local audit ref. Was the evicted one: keywrap fails → fail closed → "Your access was removed".
5. **Repo owner & quota (L).** The repo lives under the creator's provider account; Space settings display owner + size; transfer = `baluard space migrate` to an owner-chosen remote.
6. **Lost device of a surviving member (H, lose).** Self-service from a healthy device: revoke the lost device → its wrap files are deleted (`meta/members/<own_id>/<device>.wrap`, collection + item wraps), a signed commit removes the device from the registry subtree. **No key rotation needed when the device was locked**: device private keys are hardware-protected (Keychain/Keystore/DPAPI), so a locked stolen device holds only ciphertext + unwrappable wraps; deleting the wraps stops all future decryption. If the device was stolen UNLOCKED, the member (or admin) triggers a full rekey instead — same response as any compromised device (§4.4 limit). Rate note: wrap revocation is O(wraps), cheap; abuse (repeated self-revocations) throttled like unlock attempts.
7. **Owner incapacitation (K scenario).** Setup warns when a shared Space has exactly one provider-account admin: "If you lose access to your GitHub account, nobody can manage the repo." Family preset nudges toward ≥2 provider-capable members at creation. Emergency access covers vault-key recovery; provider-account recovery is the provider's own flow (documented, linked). Plain language, no new machinery.
8. **Expiring access (G).** Optional `expires_at` on collection grants and memberships. Advisory only: client reminds the admin ("Ana's guest access ends Friday — remove or extend?"), the Activity view flags stale grants. Nothing is crypto-enforced at expiry — nothing can be, serverless — the reminder is the feature, consistent with §6.5's honesty.

---

## 6. Cross-cutting decisions (ranked)

### 6.1 Key exchange
1. KX-1 bilateral QR (in person) and KX-2 in-repo join queue with step-0 provider grant + mandatory code read-back (org/remote) — both base mechanisms
2. KX-3 contact-card file — remote fallback
3. KX-4 provider discovery — optional sugar
4. KX-5 key server — rejected

### 6.2 Write-role enforcement
1. D22 signature policy: per-path net-diff scope checks (merge commits judged by what they introduce) — recommended; the scoped rule is what makes it compatible with the shipped conflict engine
2. Read-scope key distribution — the confidentiality half (never sufficient for integrity: symmetric keys cannot be read-only)
3. Provider collaborator management (§4.5) — the availability fence, managed in-flow
4. Provider branch protection — surfaced as an optional org-setup hardening checklist (prevention, not detection)
5. Server-side enforcement — rejected (no server)

### 6.3 Item sharing
1. IS-4 inline item keys (inside any shared Space) — recommended
2. IS-5 visible two-person Space (cross-vault live sync) — one repo per pair, visible in switcher
3. IS-3 encrypted one-time package — one-shots, no relationship
4. IS-1 hidden micro-Space channels — rejected (repo/API/mobile explosion, hidden-state confusion)
5. IS-2 cross-repo read grants — rejected (metadata leak, coupling)

### 6.4 Org granularity
1. CO-1 keyed collections (available to any Space; presets set defaults) — recommended
2. CO-4 folder-path grants — rejected
3. CO-2 keyed folders — rejected
4. CO-3 per-item ACLs — rejected

### 6.5 Configurability surface (Space settings; settings-pub/enc)

| Setting | Type | Default |
|---|---|---|
| `personal_areas` | bool | org: true / family: false |
| `allow_viewer_export` | bool | false |
| `trash_policy` | `write_scope_can_trash` \| `admins_only` | `write_scope_can_trash` |
| `restore_policy` | `admins_only` (fixed in 1.0; client-side undo window aside) | `admins_only` |
| `invite_authority` | `owners` \| `admins` | `admins` |
| `join_approval` | `manual` \| `code` | `manual` |
| `quorum_admin_ops` | 1..n | 1 |
| `guest_enabled` | bool | true |
| `grant_expiry` | advisory on/off | on |

Rationale lines (defaults are decisions, not accidents): `personal_areas` on for orgs because the org Space is usually the only corporate vault (1P private-vault parity); off for families because every member already has a personal vault — personal storage is met outside the shared Space. `trash_policy` default favors editors because stale credentials are the worse failure. `quorum_admin_ops` = 1 because most Spaces have one admin; raise it the day a second admin exists. `grant_expiry` is advisory everywhere, forever.

Presets: **Family** (one shared Space, personal areas off, editors = adults) and **Company** (collections, personal areas on, quorum 2, provider hardening checklist at setup). Two cards at share-setup time; one engine underneath.

---

## 7. Roadmap

| Phase | Content | Depends on | Size |
|---|---|---|---|
| **S0 Foundation** | Directory membership (`meta/members/`, `meta/collections/`, per-device identity + wrap files), member/device split, contact-block core + QR generation, `ForgeProvider` collaborator methods (`add_collaborator`, `collaborator_status`), batch `remove_members`, daemon routes `member.list/invite/remove/role`, CLI `baluard space member …`. No UI | — | M |
| **S1 Scenario A** | Desktop share UI (invite/accept/role picker), KX-1 QR + KX-2 join queue (step-0 provider grant, code read-back, approval UI), **scoped net-diff signature policy** (design gate: reconcile with `finalize_conflicts` merge commits before any code), remove = full rekey wired (batch) + offboarding pre-flight, cross-epoch offline re-encrypt, self-service device enroll + lost-device revocation, quarantine neutralize-and-notify, viewer soft restrictions, **minimal read-only Activity viewer**, extension + mobile read scope (`match`/`get`/`list_collections` with explicit D21 allowlist decisions), recovery-phrase custody rules (EnrollmentPolicy flip), i18n (en/es/pt) | S0 | L |
| **S2 Scenarios B+C** | Standalone item keys (inline), pair-Space preset (IS-5), package export/import (IS-3), item revoke + rotation, Space-rekey coverage for item keys (incl. `fido2_credentials` re-wrap), shared passkey/TOTP caveat tags, attachment verification | S1 | M |
| **S3 Scenario D** | Collection keys + grants + rotation, org sidebar UI, trash policy + purge gating + undo window, personal areas (F), guests (G) + advisory expiry, org settings screen + presets, provider hardening checklist, collection-aware extension/mobile routes, mobile admin surfaces (invite/approve/roles) | S1 | L |
| **S4 Parity** | Full Activity viewer (timeline, plain-language), org policies (advisory), `baluard space migrate` (compaction/ownership), emergency × org × provider-ownership doc, recovery/re-invite flow (E-9), repo owner/size surfacing | S3 | M |
| **S5 Defer** | Groups, travel mode, P2P send, provider discovery (KX-4) if demand | — | — |

Ordering rationale (Rev 3): A unblocks everything and carries the operational hardening. **Items (S2) before collections (S3)**: co-ownership/revocable share is the single most common ask across BOTH segments ("share this one login with my partner", "give the accountant this one password"), and it is architecturally simpler — no grant model, no collection UI. Collections matter once a Space has internal structure, mostly at org scale. The design gate in S1 (policy vs `finalize_conflicts`) is blocking and listed first.

---

## 8. Test plan

- **Property tests** (`proptest`): wrap/unwrap cycles for members, devices, collections, item keys; revoke → verify unreadable; role matrix → policy verdicts exhaustive over (role × path × signer); per-device wrap independence.
- **Policy-vs-engine (S1 gate)**: editor resolves an ordinary content conflict → 2-parent merge commit → net diff within `entries/` → accepted everywhere. Editor's merge whose net diff touches `meta/members/`, `meta/collections/`, `trash/` → rejected/neutralized on every honest client, admins notified. Quarantine: bad commit as ancestor → subsequent pulls, edits, pushes all keep working; vault state matches admin-defined content.
- **Integration**: invite (QR and join-queue incl. provider-invite step + read-back) → accept → edit → sync both sides → remove (batch: 3 members, ONE rotation) → evicted clients fail closed with the right message. Self-service device enrollment during an admin's concurrent role edit (disjoint files, clean merge). Collection grant change mid-sync. Pair-Space create → both edit → F1 auto-merge → owner revoke (C). Package export → import → mutation independence.
- **IS-4 coverage**: Space-level removal rotates standalone item keys the member could reach — including a Login carrying `fido2_credentials` (nested passkey private key re-wraps, not just the envelope). Lost-device flow: wrap files deleted → lost device fails all future pulls; sibling devices unaffected; unlocked-theft variant → full rekey path.
- **Cross-epoch offline (§5.F-4)**: authorized member offline during rekey with unpushed edits → pull, re-encrypt, push succeeds; evicted member → fail closed with removal message.
- **Recovery custody**: multi-member Space enforces `ExistingDevice` enrollment; ownership transfer re-escrows the phrase; old phrase no longer enrolls devices.
- **Offboarding pre-flight**: mock provider reports member still collaborator → blocked with checklist; reports removed → rekey proceeds. Bulk removal pre-flight checks all.
- **Crash safety**: rekey interrupted mid-rotation → `RotationGuard` + crash-marker recovery, per existing tests.
- **Metadata hygiene**: CI scan of pushed trees — no emails, no role leakage in unencrypted files, plaintext limited to UUIDs + display names.
- **Bloat**: simulated 10-rekey org vault → `space migrate` output clone-size bounded by current-state size, not history.
- **UX**: invite flow completable by a non-technical tester without docs; QR+SAS and join-code flows each ≤ 3 steps + 1 provider-accept click; the code comparison is the only cryptographic moment, called "compare the codes".

---

## 9. Security notes and honest limitations

1. **Eventual revocation.** Removed members keep every byte they already had. Keys rotate; their old local copies do not. Say it in product copy, not just docs.
2. **Editors can damage.** With push rights, a rogue editor can delete files (restorable via history) or push junk (neutralized). Prevention lives at the provider collaborator list + optional branch protection. One-page admin guide covers it.
3. **Read-only is policy + scope, never crypto.** Symmetric keys decrypt and encrypt equally (§3-5). Viewer enforcement = read-scope distribution + signature policy + UI. A compromised viewer client can attempt writes; honest clients neutralize them.
4. **The recovery phrase is a root bypass, deliberately.** It is the owner's break-glass and never a member credential (§5.A custody rules). A member who obtained the owner's phrase holds the owner's power — the same is true of the owner's master password. Custody + transfer rules exist because shared Spaces change hands; the phrase itself does not become member-revocable.
5. **Metadata.** Bucket padding hides sizes; commit timing and membership structure remain visible to the git host and members. Opaque IDs, no emails (§4.2), plaintext limited to UUIDs + display names.
6. **Member keys are password-protected, not hardware-bound.** A member's X25519 key is as strong as their master password + KDF. Device keys are hardware-protected; member identity keys are not.
7. **Verification is TOFU-shaped.** QR/file verify by SAS comparison; the join queue verifies by mandatory code read-back at approval. Skip both and you trust whatever channel carried the invitation. UI makes verification a step, not a suggestion.
8. **Policies are advisory.** No server, no force. Admins see a compliance report, not a guarantee. Grant expiry is a reminder, not a lock.
9. **History bloat is real.** Rekeys rewrite all blobs; migrate/compact is the S4 answer. Free-tier quota guidance ships with it.
10. **Invariants untouched**: AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroize-on-drop, 0600 files, token-gated IPC, mlock. Sharing adds keys; it weakens none.

---

## 10. Open questions (Esteban)

1. Multi-owner default quorum: 1 (solo admin acts) or 2 (two-admin confirm for removals)? Plan assumes 1, configurable.
2. May editors create collections? Plan says no (admins manage structure; editors fill it). Debatable for families.
3. **Trash default (settled in Rev 2/3, confirm):** `write_scope_can_trash` — editors may move-to-trash entries in their write scope; restore/purge stays admin-only; client-side undo window covers oops moments. Revert to `admins_only` if the original stricter reading wins.
4. Viewers and passkeys: use-for-autofill yes, export/display of the credential no — confirm.
5. **Recovery phrase on ownership transfer:** plan re-escrows the phrase to the new owner (old phrase dead for enrollment). Alternative: per-owner phrases (bigger crypto change). Recommend re-escrow; confirm.
6. Expiring grants: advisory reminders only (recommended, consistent with serverless honesty) — confirm no stronger promise is expected.
