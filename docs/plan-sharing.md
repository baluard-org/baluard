# Plan: Sharing (Spaces, Roles, Collections, Item Sharing)

**Status**: Proposed. Not implemented beyond the primitives listed in §2.
**Rev 7**: integrates Opus round-3 self-critique. The identity keypair gets a full lifecycle (rotation flow, emergency scoping, quick-unlock warnings) — Rev 6 treated the crown jewel as set-and-forget. Outbox re-scoped to one repo per recipient (roster + history-shape leaks killed the consolidated design). §4.4 becomes a real policy table (requests/pending/folders/tags paths were outside the rules). Hardware-AES build flag decides the index debate. `baluard-personal` becomes the DEFAULT, not a forced rule (Opus retracted; §10.6b). `space.adopt` covers owner death and provider loss. Six screens. Shared-OS-account named as a non-boundary.
**Rev 6/6.1**: identity-rooted Spaces pivot (Opus round 2) + review refinements (consolidated outbox superseded per-recipient in Rev 7, incremental index, JIT caps, event compaction). **Rev 5**: Opus code-level review (phase P). **Rev 2–4**: independent peer reviews (identity split, graded trust, async invites).
**Scope**: Every scenario where more than one person touches the same data, on the serverless architecture (git remote = transport, no backend).
**Companion docs**: `docs/software-architecture-decisions.md` (D9; DOMAIN 5 commit signing; D4 conflict resolution), `docs/software-architecture.md` §4, `docs/threat-model.md`. D-numbers in the decisions doc have drifted; this plan cites decisions by name.

---

## 0. TL;DR

| # | Scenario | Design | Phase |
|---|----------|--------|-------|
| P | — | **Prerequisites**: identity-rooted Spaces **with a full identity lifecycle** (rotation, emergency scoping, quick-unlock warnings); signature-verification repair bound to device→member→role; keywrap distribution to identities; rotation coverage; multi-writer git layer (explicit staging, per-fact meta, gitignored+untracked index, hardware-AES flag); **policy table** (path glob → role, as data); default-deny IPC. No sharing code before P | P |
| A | Whole Space shared, roles | Directory membership; each member unlocks with their OWN master password and unwraps the Space key with their identity key; net-diff policy | S1a/b |
| B | Item co-ownership | Pair Space (visible 2-person Space, both editors) | S2 |
| C | Owner-controlled share | **Outbox repo per recipient** (read-only collaborator; transport-enforced one-way) or pair Space with viewer grant; revoke = unpublish + rotate | S2 |
| D | Org granularity | Collections + grants, role templates, delegated manage, request-access JIT (HPKE-sealed payloads), expiry-that-rotates, groups; trash purge admin-only | S3/S4 |
| E | Parity gaps | §5.E matrix | S4 |

Identity and trust: signed **contact cards** + **address book**; graded verification — **Level 0** passphrase reveal (no identity), **Level 1** channel trust (inert artifacts only: packages), **Level 2** code check (required for live shares and memberships), **Level 3** admin approval. Recorded per identity. All async. No server, ever.

Enforcement split: **read scope** = keys (+ locally rebuilt index); **write integrity** = signatures bound to device→member→role via the policy table; **one-way availability** = read-only provider collaboration; **everything else about pushing** = provider ACLs, managed in-flow.

---

## 1. Scenarios

- **A. Shared Space, roles.** 2+ people, each their own master password. Owner/admin full control; editors create/edit; viewers read/use. All sync.
- **B. Item co-ownership.** Two users, one entry, equal power; both can revoke the other.
- **C. Owner-controlled share.** Owner keeps power; recipient views/uses only; owner revokes any time.
- **D. Org granularity.** Admins see all; members only their collections, read or write; ladder in §4.7; trash purge admin-only.
- **E. Parity** (§5.E). **G. Guest**: one collection, read-only, end date. **H. Multi-device member**: device add/loss involves nobody else. **I. Clean split.** **J. Departure with live provider access.** **K. Owner incapacitation / provider loss.**

---

## 2. Current state (verified against source)

What exists and is reused:

| Piece | Where | Notes |
|---|---|---|
| Key hierarchy | `keys/`, `vault/handle.rs` | RootKey → SGK → ItemKey (HKDF, epoch-bound), zeroize. Index key: `derive_index_key(root_key)` — Spaces (no RootKey) will derive it from SGK (§4.3) |
| Org key wrapping (island) | `orgs.rs` | HPKE `WrappedKeyBundle`, add/remove member. Zero callers; `progress.md` "Orgs: Done" is wrong (fix separately). Becomes the Space-wrap engine in P1 |
| Rekey machinery | `handle.rs` | Rotation covers ciphers/trash/attachments/folders/tags/profile/activity/recovery-rewrap; misses `settings.enc`, `emergency.json`, avatar, index; writes keywrap only for the actor. `meta/rekey/<epoch>.txn` wraps for all devices — no consumer |
| Commit signing | `sync/engine.rs` | Ed25519-signed commits. **Verification dead in production** (reads test-only `meta/device-registry.json`); `load_signing_key` returns first keyring hit, not the acting device; `unlock_with_kek` can adopt another device's identity |
| Conflict resolution | `sync/engine.rs`, `runtime/state.rs` | Field-level cipher merge; 2-parent merges; single-file only; `add_all("*")` ×2; `commit_all` rewrites `meta/devices.json` per commit |
| Emergency access | `emergency.rs` | Personal-vault scoped today. **After P1 the personal vault contains the identity: emergency scoping becomes a P decision (§4.1)** |
| Recovery | `recovery.rs`, `device_manager.rs` | BIP-39 phrase wraps RootKey; `EnrollmentPolicy::{Personal, Strict}` |
| Multi-vault host | `baluard-runtime` | VaultHost map + active pointer + per-vault tokens. **`VaultState::lock` is public, called from 5+ sites, no host back-pointer; mobile has no VaultHost (uniffi wraps a single vault)** — P1/P5 work |
| Sync | `sync/engine.rs` | commit → pull (force-checkout) → resolve → push; shallow clones; index auto-heals by scanning |
| Devices | `device_manager.rs` | Enrollment (Personal/Strict), quorum, force-evict, epochs |
| Trash | `handle.rs` | `trash/<id>.enc`; active ciphers `ciphers/<id>.enc`; attachments under `entries/<id>/attachments/` (never touch the index build) |
| Providers | `providers/` | ForgeProvider + OAuth + `create_repo`. GitHub `repo` OK; GitLab `api` OK; Codeberg scopeless (collaborator admin + read-only enforcement gaps, UI-flagged) |
| Daemon gating | `handler.rs` | `TOKEN_REQUIRED_ACTIONS` allowlist; **`vaults.list/switch/close/detach/lock_all` are NOT gated** — and `vaults.list` cannot be token-gated (login screen, pre-token). Shared-OS-account reality, §9 |

Does not exist: callers of `orgs.rs`; member identities or any identity lifecycle (rotation!); per-member unlock; keywrap distribution; signature policy; key exchange; collections; an Activity data source (commit metadata is deliberately uniform, T14).

---

## 3. Architectural constraints

1. **No server.** Everything local, cryptographic, or signature-based.
2. **Git commits are storage, not a log** (uniform metadata, T14). Audit trail = signed event files, built.
3. **Revocation is eventual.** Removed members keep their bytes.
4. **Integrity vs availability.** Detect, notify, restore, migrate; provider ACLs fence.
5. **Symmetric keys do not separate read from write** — except at the transport (read-only collaborator, outbox).
6. **Two authorities, one user**: crypto membership AND provider ACL, one flow (§4.5).
7. **File modes do not survive git.**
8. **Padded buckets**: plaintext = opaque IDs + display names + trust. Padded sizes also multiply history (§5.F-5).
9. **Pre-1.0**: formats break freely.
10. **UX bar**: six screens total; users never see HPKE, SGK, epochs, policies.
11. **One credential per human, for life.** Second password prompts are forbidden, including between a user and their Spaces.
12. **A shared OS account is not a security boundary.** Same UID = shared socket, shared biometric enrollment, pre-token vault listing. One OS account per human, or existence/names are shared. Stated in-product, not solved in-code (§9).

---

## 4. Building blocks

### 4.0 Prerequisites (phase P)

| # | Blocker | Work |
|---|---|---|
| P1 | **Identity-rooted Spaces + identity lifecycle.** Personal vault stores the member identity keypair (X25519+Ed25519) as encrypted data — never HKDF-derived; re-encrypted in personal rotation; restored by the personal recovery phrase. A Space has no master password; its key is HPKE-wrapped to member identities (`WrappedKeyBundle`). **Lifecycle:** (a) `identity.rotate` with TWO paths — **routine** (old key still held: member self-wraps `space.wrap` to the new identity in their own subtree, signed by the old key; no admin, no lockout, no rekey) **with safeguards**: a Space notice fires on every member's client, trust levels verified against the old identity reset (cards must re-verify against the new key), and the old identity stays valid for a contest window — a thief holding a stolen key can use this path too, so rotation must be visible to be contestable; the bar is justified against `device_manager` quorum-gated enrollment (identity > device); **compromise** (old key NOT trusted): `identity.rotate` + every Space admin re-wraps AND the Space SGK rotates — re-wraps alone do nothing against an exfiltrated private key; non-admin members enter `AwaitingReWrap` per Space (UI: "waiting for admin in N Spaces"; rotation notice file in the member's own subtree, admin 1-click on sync); old identity marked compromised in address books; (b) **emergency scoping** — emergency escrow NEVER contains the identity keypair (contact gets personal ciphers only, Spaces excluded; org setting flags members with emergency grants); (c) quick-unlock on a personal vault requires explicit enable with the plain-language warning that any biometric enrolled on this OS account opens it; (d) **lock chokepoint** — `VaultState::lock` becomes host-private; all locking flows through `VaultHost::lock_slug`, which keeps a dependency graph (personal vault → dependent Spaces). **Cascade mechanism (revised per review):** host lock stays outermost and is RELEASED before per-vault locks (as today); cascade = bump the Space's auto-sync generation (existing primitive), invalidate session tokens, then `VaultState::lock()` per dependent slug — the RwLock drains in-flight handlers naturally. **Never await `cycle_lock` from a lock path**: it is held across a 60s network-bound `spawn_blocking`, its timeout does not cancel the blocking task, and the host's sequential lock loops would stall 60s × N (deadlock once autosync gains a host back-pointer). Switching/closing a personal vault reports and performs the cascade (`SwitchOutcome`, heartbeat token invalidation, `vaults.close` cascade) — the "switch = pointer flip only" invariant is amended for identity roots | |
| P2 | **Signature-verification repair.** `load_verifying_keys` → `meta/devices.json` (UUID map); bind signature → device → member → role; bind loaded signing key to `self.device_id`; disable identity adoption in multi-member vaults; delete the test fixture; production-shaped tests: legit verifies, foreign rejected. **Roster-snapshot rule (load-bearing):** verification walks new commits in topological order and resolves the signer's roles from each commit's FIRST-PARENT tree, advancing an in-memory roster as it goes — never the working tree (today `engine.rs` reads it), never the final tree. Without this, admin-add (C1) + member push (C2) fetched in one pull rejects C2 against a stale roster and the whole pull fails — the join queue cannot complete a single sync | |
| P3 | **Keywrap distribution to member identities.** Removal re-wraps the Space key for remaining members; survivors unlock on next pull | |
| P4 | **Rotation coverage.** `settings.enc`, `emergency.json` (encrypted contact), avatar, attachments, **identity keypair (personal rotation)**; index mooted by P5 | |
| P5 | **Multi-writer git layer.** Per-device split out of `devices.json`; explicit staged path sets replace `add_all("*")`; multi-file + non-cipher conflict strategies; `folders.enc`/`tags.enc` → per-fact files + tombstones **with a write-scope carve-out** (members manage their own folders/tags in Spaces — editors included); **`meta/index.enc` gitignored AND untracked** (add to `GITIGNORE_CONTENT`, `git rm --cached` via the existing `open_repo` refresh path, extend the defensive `status()` filter — tracked-but-modified otherwise wedges the sync badge); index first-build scans, later updates incremental by changed cipher ids, undecryptable entries surfaced by count; **enable hardware AES** (the `aes 0.8.4` fixslice default runs ~25–40 MB/s on mid-range Android; the flag divides crypto by ~20 — this, not index architecture, decides the cold-build question; drop segmented-fragment fallbacks); cover commits off in shared Spaces | |
| P6 | **Default-deny IPC.** Invert to `TOKEN_EXEMPT_ACTIONS` + coverage test. Honest limit: `vaults.list` stays pre-token (login screen) — shared-OS-account exposure of names/existence is a §9 limitation, not a P6 fix | |
| P7 | **Policy table as data.** §4.4's map becomes a constant (path glob → required role), consumed by the net-diff checker. Authoritative paths: `meta/members/<m>/**` (own: devices, pending, requests, space.wrap) — **never** top-level `meta/requests/**` or `meta/pending/**`; `meta/folders/**`, `meta/tags/**` (write scope); `meta/` rest (admin); `ciphers/` (write scope); `trash/` (policy); **pending-joiner row**: an unenrolled signer may write once to `meta/members/<m>/pending/<device>.json` only. Required tests: glob precision (`meta/members/<m>.json` is admin-owned while `meta/members/<m>/**` is self-service — one prefix-matching bug away from role self-escalation) and the pending-joiner row | |

Envelope format: unchanged. No v2 — inline item keys are cut (§4.6).

### 4.1 Identity and trust: cards, dial, lifecycle

Contact cards signed by the **identity** key; local encrypted **address book**; identity is a one-time cost per relationship.

| Level | Mechanism | Recorded as | Used for |
|---|---|---|---|
| 0. Passphrase | App-generated passphrase, Argon2id+AES-GCM, params+expiry in AAD; no identity involved | n/a | Guest reveals only |
| 1. Channel trust | Card arrived over a trusted channel | `trust: channel` | Packages (IS-3) — inert only |
| 2. Code check | Both apps show a code; compare over chat whenever, or QR in person | `trust: verified` | **Required** for live shares (pair Spaces, outbox setup) and Space invites |
| 3. Admin approval | Join link; approval vouches; code check recommended | `trust: admin` / `admin-unverified` | Org onboarding |

Join queue: provider grant step 0 (§4.5) → one-time token → signed self-introduction at `meta/members/<m>/pending/<device>.json` (own-subtree path, P7) → async admin approval → `active`. Identity compromise → `identity.rotate` (P1a): old cards invalidated, admins re-wrap. Emergency access: **personal ciphers only, never the identity** (P1b) — an emergency contact must never inherit every Space a person belongs to; org setting flags such members.

### 4.2 Membership v2

`meta/members/<member_id>.json` (id, display_name, role, trust, encrypted email optional); **per-provider account handle in the encrypted portion** (`providers: {github: "handle", gitlab: "handle"}`) — required by every §4.5 collaborator call, and it must NOT be plaintext (it links a pseudonymous member to a real-world provider account). Constraint, stated: **every member of a Space holds an account on that Space's provider** — cross-provider membership is impossible by architecture. `meta/members/<m>/devices/<d>.json`; `meta/members/<m>/space.wrap` (HPKE to the identity — one wrap per member, not per device; P3); `meta/collections/<id>.json` (encrypted name, grants `{member, access: view|write|manage, expires_at?}`); `meta/members/<m>/requests/<id>.json` (JIT asks, HPKE-sealed to the approver set — plaintext carries only the requester id, never the target item). Per-file everywhere; plaintext = UUIDs + display names + trust.

### 4.3 Key model

| Key | Personal vault | Space |
|---|---|---|
| RootKey / SGK | today's model, unchanged | SGK random at creation; **no RootKey**; index key derives from SGK (`derive_index_key` generalization — today it takes RootKey) |
| Identity keypair | stored data (P1) | — |
| Item keys | HKDF(SGK, cipher_id, epoch) unchanged | unchanged; **no standalone item keys** (§4.6) |
| Collection key | — | random; wrapped under SGK (admin path) + per granted member identity; `index.enc` gitignored/untracked, rebuilt locally, incremental updates (P5) |

Rotation coverage (P4 applied): Space member removal → new SGK + collection rotations + re-wrap to remaining identities. Personal rotation → re-encrypt identity keypair + settings/avatar/emergency/attachments.

### 4.4 Enforcement — the policy table

| Path glob | Required signer role | Notes |
|---|---|---|
| `meta/members/<own_id>/**` (devices, pending, requests) | that member, any role | self-service enrollment, joins, JIT asks |
| `meta/members/<other>/**`, `meta/collections/**`, `meta/space.json` | admin/owner | membership, grants, settings |
| `meta/members/<pending joiner>/pending/<device>.json` | unenrolled signer, write-once | join queue self-introduction (the only path a no-role signer may touch) |
| `meta/folders/**`, `meta/tags/**` | write scope (editors included) | per-fact files + tombstones |
| `ciphers/**` | write scope per collection/Space grant | entries |
| `trash/**` | per `trash_policy`; restore/purge admin | signature policy |
| `entries/<id>/attachments/**` | write scope on the parent item | |

Net-diff rule: per new commit, `diff(first_parent, commit)` paths must each be covered by the signer's roles; merges judged by introduced changes (ordinary editor conflict merges stay legal). Rejection (v1): detect + notify + admin restore-from-history button + local audit ref; `space migrate` answers rogue pushers; synthesized-tree neutralization deferred (S4). Quorum decoupling: rotation commits need `quorum_admin_ops` admin signatures; fleet `ceil(N/2)` ack governs enrollment only.

### 4.5 Provider ACL coupling

`add_collaborator` + `collaborator_status` + `ensure_access_accepted` on ForgeProvider. **Per-provider reality (they are not symmetric):**

- **GitHub**: invites are PENDING until accepted (email link or API); clone 404s before acceptance. `ensure_access_accepted` = list the account's pending invitations, match the expected `repository.full_name` (NEVER accept-all — that is an auto-accept bot for attacker-sent invites), accept via `PATCH /user/repository_invitations/{id}`. **Invites expire after 7 days**: step-0 grant precedes unbounded async approval, so the admin client tracks invite age and auto-re-invites when the joiner's clone reports not-found.
- **GitLab**: adding by `user_id` grants access IMMEDIATELY — no pending state; `ensure_access_accepted` is a documented no-op. Constraint: never add by email (that path has an out-of-band acceptance with no invitee-side API). Read-only outbox = Reporter (20), NOT Guest (10) — a Guest cannot pull a private project.
- **Codeberg/Forgejo**: adds immediately (no pending state; no-op again). Scope gaps stay UI-flagged (`default_scopes` for Codeberg do not map to valid Forgejo scope strings; scoped PATs lack repo-admin).

Pre-flight before removal (§5.F-3). Branch-protection checklist at org setup. **Org readiness adds: who owns the repo** — a company Space on an employee's personal GitHub is a governance problem the admin must see; the access review reports it (§4.7-6). S1b roadmap item.

### 4.6 Sharing surfaces

- **IS-3 package** (one-shot copy): Level 1; inert; recipient-key-wrapped; cannot be un-shared; pre-send copy says so.
- **IS-6 reveal** (field-scoped, view-only help): default URL+username+password; TOTP opt-in with permanence warning. Contact-key flavor (viewer card, no import) + passphrase guest flavor (Level 0; Baluard app without a vault: "Open a shared file" on first-run; app-generated passphrase; voice delivery; expiry in AAD). Both v1 (§10.8 decided).
- **IS-5 pair Space** (B): visible 2-person Space, both editors. In Family shape (no collections) this is also the answer to "share one entry with my spouse but not the kids" — the share sheet creates it silently, without saying "Space".
- **Outbox, one repo per recipient** (C): `baluard-space-outbox-<opaque-id>`; recipient is a read-only collaborator; revoke = unpublish + rotate. **Per-recipient, deliberately**: a consolidated repo leaks the recipient roster (providers show collaborators to collaborators — a lawyer and a partner on one list) and the history shape (collection count, blob sizes, sharing cadence). O(recipients) is small; roster privacy wins. Transport-enforced read-only on GitHub/GitLab; Codeberg pollution-only, ignored, UI-flagged.
- **IS-4 inline item keys**: cut (S5 revisit if users ask by name).
- **Merged single-list presentation** + `vaults.list_full_all` — the UX that makes N repos feel like one vault. **One personal vault per OS account** (no local-suffix work personas; a work persona is a separate OS account, which is also the honest security boundary).

**Repo naming**: default `baluard-personal` for personal vaults (probe → adopt/restore → remote suffix on collision; never forced — Opus round-3 retraction, §10.6b); `baluard-space-<name>` for Spaces; `.baluard` marker remains the only identity check.

### 4.7 Org granularity ladder

1. Role templates (S3). 2. Collections + delegated `manage` (S3). 3. **Request-access JIT** — HPKE-sealed ask files under the requester's own subtree; approver wraps the collection key; caps + 30-day expiry + prune (S3/S4). 4. **Expiry-that-rotates** — admin's client executes on next sync after the date; clock floor = latest commit timestamp (§9.11). S3. 5. Groups as key layer (S4). 6. Access review report — includes repo-ownership governance (S4). 7. Dual control 2-of-2 XOR (S4). 8. Two-tier envelopes (S3+ only if orgs are near-term; §10.7: skip v1). 9. Per-item ACLs — rejected as primary (S5 exception). 10. Break-glass counters — theater as control; loud event only.

### 4.8 The screens (six)

1. **Share sheet** — person picker + "Can view / Can edit" + Share; context creates the pair Space, grant, or outbox silently. 2. **People** — faces, role pill, verification badge, add/remove. 3. **Invite & Accept** — the only ceremony; two taps per side. 4. **Activity** — human sentences, best-effort label. 5. **Requests** (Team shape) — approve/deny inbox. 6. **Space notices** — removals, blocked pushes, pre-flight failures ("this person still has push access on the remote"), restorable deletions. Guaranteed to fire on Codeberg; a toast cannot carry it.

First run asks no taxonomy question: password + recovery phrase, done. Shape is chosen only at Space creation, one line (Family = everyone sees everything / Team = groups of items), one-way ratchet. Vocabulary: "Your vault" and "Shared spaces".

---

## 5. Scenario designs

### 5.A Shared Space with roles

Capability matrix unchanged: owner > admin > editor > viewer; trash move = write scope (`write_scope_can_trash`); restore/purge admin; self-service device lifecycle all roles; invite/remove/rekey admin+; delete Space owner. Members unlock with their own passwords; Space keys unwrap against identities. Recovery: personal phrase → identity → all Spaces; `identity.rotate` for compromise. Remove flow: batch, pre-flight, survivors re-keyed (P3), evicted fails closed. Cover commits off in shared Spaces. Space auto-lock inherits the personal vault's timeout (§6.5).

### 5.B / 5.C Item sharing

Pair Space (B), outbox per recipient (C), package (IS-3), reveal (IS-6). Family-shape single-entry share = silent pair Space. Rejected: IS-1, IS-2, IS-4 (S5 revisit).

### 5.D Org granularity

CO-1 collections; per-identity wraps; grants with rotation-backed expiry; templates, delegated manage, JIT; local index = listing; trash policy + tombstone undo (72h, held from push); guests work because the index is local; groups (S4).

### 5.E Parity matrix (delta from Rev 5)

Row 2 sharing = pair Space + per-recipient outbox + package + reveal (S2); row 3 collections + local index (S3); row 7 Activity = signed event files, admin-signed rolling compaction with a hash over the replaced set (censorship-detectable), S1b min / S4 full; row 13 groups S4; row 21 expiry-that-rotates S3; row 6 personal areas S5; row 9 recovery spans identity; row 17 emergency re-scoped in P1 (identity excluded) + doc.

### 5.F Lifecycle and operations

1. **Multi-device member**: personal-only (H).
2. **Clean split**: `space.export` (package batch) / `space.sever` (fresh Space, new SGK, new remote).
3. **Departure pre-flight**: `collaborator_status`; checklist + deep link; "ask the repo owner"; offline override. Failures surface on screen 6.
4. **Offline member across a rekey** (after P3): pull → unwrap new Space key → re-encrypt unpushed commits → push; old commits to a local audit ref. Evicted: fails closed.
5. **Repo owner & quota**: owner + size surfaced; **padded buckets multiply history** (500 M-tier entries edited monthly ≈ 600 MB/year of undelta-able AEAD blobs): `space migrate` is ROUTINE maintenance (S3), not incident response; size warning fires at a fraction of the provider limit.
6. **Lost device**: personal-vault revocation; Spaces untouched. **Identity rotation — two paths (review catch, refined)**: routine (key still held) → self-wrap `space.wrap` under the new identity in the own subtree; zero admins, zero lockout. Compromise (key not trusted) → `identity.rotate` + admin re-wrap **and Space SGK rotation** per Space; non-admin members enter `AwaitingReWrap` per Space until an admin acts (rotation notice file in the member's own subtree; admins get a 1-click action on sync). Locked theft = personal rekey + routine rotation; unlocked theft = compromise path.
7. **Owner incapacitation / provider loss**: warning at one-provider-admin; `space.adopt` = any remaining admin re-points the Space at a remote they own (quorum-signed) — covers death, account closure, provider suspension; optional cold mirror at Space creation. `space.adopt`/migrate at S3.

---

## 6. Cross-cutting decisions (ranked)

### 6.1 Identity and trust
1. Identity-rooted Spaces **with lifecycle** (rotate, emergency scoping, quick-unlock warnings)
2. Contact cards + address book + graded dial (0–3), Level 1 inert-only
3. Join queue with step-0 provider grant
4. Bilateral QR — in-person rendering of the code check; provider discovery — sugar; key server — rejected

### 6.2 Enforcement
1. P2 + P5 + P7 (repair, staging, policy table as data)
2. Net-diff per-path policy
3. Read-scope keys + local index
4. Outbox per recipient (transport read-only)
5. Provider collaborator management + branch protection
6. Server-side enforcement — rejected

### 6.3 Sharing surfaces
Pair Space (B); outbox per recipient (C); package; reveal; merged list. IS-4 cut (S5 revisit); IS-1/IS-2 rejected.

### 6.4 Org granularity
§4.7 ladder. Groups before per-item ACLs; break-glass = event, not control.

### 6.5 Space settings

| Setting | Type | Default |
|---|---|---|
| `shape` | `family` \| `team` (one-way ratchet) | at creation |
| `allow_viewer_export` | bool | false |
| `trash_policy` | `write_scope_can_trash` \| `admins_only` | `write_scope_can_trash` |
| `restore_policy` | `admins_only` (tombstone aside) | `admins_only` |
| `invite_authority` | `owners` \| `admins` | `admins` |
| `join_approval` | `manual` \| `code` | `manual` |
| `quorum_admin_ops` | 1..n | 1 |
| `guest_enabled` | bool | true |
| `grant_expiry` | rotation-backed | on |
| `vault_timeout` | inherited — the host resolves `inherit` against the member's personal-vault policy at Space open | inherit |

Activity note: the merged multi-Space list must count activity only for the Space whose items the user actually touches — browsing the list must not refresh every Space's auto-lock clock (auto-lock is per-vault `last_activity`; inheritance resolves via the host at open, per §6.5).

---

## 7. Roadmap

| Phase | Content | Depends on | Size |
|---|---|---|---|
| **P Prerequisites** | P1 identity-rooted Spaces **+ lifecycle** (rotate, emergency scoping, quick-unlock warning, lock chokepoint + cascade with `SwitchOutcome`); P2 verification repair + binding; P3 keywrap distribution to identities; P4 rotation coverage (identity, settings, emergency, avatar, attachments); P5 multi-writer git layer (split, staging, multi-file conflicts, per-fact folders/tags with carve-out, index gitignored+untracked+incremental, **hardware-AES flag**); P6 default-deny IPC (with the `vaults.list` honesty limit); P7 policy table as data | — | L |
| **S1a Members** | Directory, cards + address book + dial, async states, join queue (provider grant step 0), `identity.rotate` end-to-end, invite/accept/role UI, batch removal + pre-flight, i18n | P | L |
| **S1b Policy + Activity** | Net-diff policy (consuming the P7 table), detect + notify + admin restore, event files + compaction + minimal Activity viewer, **`add_collaborator`/`collaborator_status` on ForgeProvider**, signed head gossip, screen 6 (Space notices), extension/desktop read scope (D21 allowlist decisions), shallow-clone depth policy | S1a | L |
| **S2 Items & Spaces** | IS-3 packages → IS-6 reveal (both flavors) → IS-5 pair Space (silent creation in Family shape) → per-recipient outboxes → merged multi-Space item list + `vaults.list_full_all` (desktop) | S1a | M |
| **S3 Orgs** | Collections + grants + rotation, role templates, delegated manage, request-access JIT, expiry-that-rotates, org settings + presets + readiness check (repo ownership), provider checklist, **`space.adopt` + `space migrate` as routine maintenance + size warnings**, collection-aware extension routes, mobile admin surfaces | S1b | L |
| **S4 Power + Parity** | Groups, dual control, access review report, full Activity timeline, org policies (advisory), emergency × org × identity doc, synthesized neutralization (revisit), **mobile multi-Space host** (uniffi VaultHost port + `:autofill` Space-open via identity + HPKE, OOM-safe — size L, own line item) | S3 | L |
| **S5 Deferred** | Personal areas, per-item ACL exception, IS-4 revisit, travel mode, P2P send, provider discovery | — | — |

---

## 8. Test plan

- **Property tests**: wrap/unwrap (identity, members, collections); revoke → unreadable; role × path × signer verdicts **against the P7 table**; XOR dual control; expiry rotation; identity rotation → old wraps dead, new wraps live.
- **P acceptance**: two humans, two passwords, one Space (P1); personal rotation preserves identity + Space wraps; **identity rotation locks out the stolen key everywhere (S1a)**; removal → survivors unlock (P3); legit verifies / foreign rejected on a production-shaped vault, fixture deleted (P2); **every `VaultState::lock` call site routes through the host cascade** (P1); net diff == intent (P5); multi-file conflict resolves; index gitignored + untracked + incremental, absent file harmless, undecryptable entries counted (P5); hardware-AES on for all release targets (P5); every action in exactly one token list (P6).
- **Integration**: join queue → states → keys at `active`; skip → badge; late check flips trust. **Invite lifecycle**: GitHub invite expires after 7 days → admin client auto-re-invites → joiner completes; acceptance scoped to the expected repo (an unrelated invitation is never accepted). Level rules enforced (Level 1 never wraps a live key). Reveal: seed absent unless opted in; guest viewer without vault; expiry refuses stale. Outbox: per-recipient isolation (A cannot decrypt B's collection), roster not visible, revoke works. Pair Space lifecycle. Batch removal. Merged list across N Spaces; **auto-lock still fires for untouched Spaces while the merged list stays open**. **Cascade**: lock/switch personal → dependent Spaces locked, tokens invalidated, no 60s stall, no autosync deadlock (generation bump), in-flight handler fails closed.
- **Policy-vs-engine**: every P7 table row exercised; **glob precision**: `meta/members/<m>.json` (admin) vs `meta/members/<m>/**` (self) — a member writing their own role file must be rejected; **roster snapshot**: admin-add (C1) + member push (C2) fetched in one pull → C2 verifies against the advanced in-memory roster, pull succeeds; pending joiner: write-once own pending path accepted, everything else rejected; editor content merge accepted; `meta/` smuggling rejected + restore flow; request files legal from own subtree, illegal elsewhere.
- **Cross-epoch offline** (after P3). **Crash safety**: RotationGuard; rekey concurrent with member sync.
- **Metadata hygiene**: no emails/plaintext beyond UUIDs + display names + trust; emergency contact encrypted; outbox repos carry no cross-recipient metadata.
- **Bloat**: migrate bounds clone size; padded-history growth curve documented; index cold-build measured WITH hardware AES on mid-range Android.
- **UX**: non-technical invite without docs; first run = password + recovery phrase, nothing else; six screens cover scenarios A–K; quick-unlock warning shown at enable.

---

## 9. Security notes and honest limitations

1. **Eventual revocation.** Removed members keep their bytes. Compliance-facing version: **no erasure promises** — git history plus retention is the architecture. Admin guide says it.
2. **Editors can damage.** Detect, notify, restore, migrate; provider ACLs fence.
3. **Read-only**: crypto for scope, policy for attribution, transport for one-way (outbox per recipient).
4. **The identity key is the crown jewel — with a lifecycle.** Rotation (P1a) answers unlocked-theft; emergency scoping (P1b) answers third-party blast radius; quick-unlock warnings answer shared machines. Remaining truth: identity compromise between last sync and rotation exposes every Space the person belonged to. Priced, not hidden.
5. **Level 1 is inert by rule.**
6. **Locked-device theft** = offline password attack via the KEK-sealed privkey fallback; unlocked = personal rekey + identity rotation.
7. **Metadata**: membership, commit timing, per-device activity, outbox graph shape (minimized per-recipient). `0600` local-only.
8. **Shared OS account is not a boundary** (constraint 12): pre-token `vaults.list`, shared biometric enrollment, same UID. Product states it; per-human OS accounts are the requirement.
9. **Verification graded and recorded**; Level 1 inert; skips badged.
10. **Head gossip detects rollback for members who observed the discarded head** (the active ones). Not a promise for newcomers or the offline.
11. **Policies and expiry advisory; clocks trust the latest commit timestamp as a monotone floor** — wrong clocks cannot extend access beyond the next honest sync.
12. **History bloat is structural** (padding × AEAD = no deltas): migrate is routine maintenance; size warnings early.
13. **Invariants**: AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroize-on-drop, 0600 at rest, token-gated IPC, mlock — mlock budget line updated to include the identity keypair and per-collection keys (still trivially inside `RLIMIT_MEMLOCK`).

---

## 10. Open questions (Esteban)

1. Multi-owner default quorum: 1 or 2? Plan: 1, configurable.
2. Editors create collections? Plan: no (they do manage their own folders/tags).
3. Trash default `write_scope_can_trash`: confirm.
4. Viewers and passkeys: autofill yes, export no: confirm.
5. Recovery on ownership transfer / identity compromise: re-escrow + `identity.rotate` as designed: confirm.
6a. **Identity-rooted Spaces**: Opus round 3 prices the crown-jewel trade honestly (rotation + emergency scoping + warnings added). Confirm the pivot with the lifecycle included.
6b. ~~Forced `baluard-personal`~~ **Decided (Esteban): default, never forced.** Opus round-3 retraction accepted (constant name buys nothing once collisions suffix it, and it discloses vault role). Default name `baluard-personal`, probe → adopt/restore → suffix on collision.
7. Two-tier envelopes: skip v1 (JIT covers the need)? Plan: skip.
8. ~~The adoption cliff~~ **Decided (Esteban): no hosted relay, ever.** Target audience is internet-literate people — 50 and under, the POP/SMTP/modem generation. Creating a provider account is inside their competence, and one family member setting Baluard up for another is an accepted, normal flow. Family sharing ships with guided provider-account setup inside Space creation; the no-server promise stands unbroken.
