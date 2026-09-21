# Plan: Sharing (Spaces, Roles, Collections, Item Sharing)

**Status**: P prerequisites shipped — P2, P6, P4, P5a/b/c, P1a/P1c/P1d, P3, P7, P8a, P8b (2026-09-19/20); P remainder blocked on S phases (P1 Space parts, P5 collection-scoped paths) or deferred (P8c transport staging, P5 staged path sets). S1a slice 1 shipped (2026-09-20): membership directory + role resolution. §2 lists the pre-P baseline.
**Rev 8.1**: shipping-state markers in §4.0 + §7; P8b revocation manifest replaces quorum-signed rewind (§10.9).
**Rev 8**: integrates a fresh-context independent review. The identity keypair gets a **key-layer split**: sealed under the OS keystore / recovery-phrase pubkey, never the plain master-password KEK (one cracked laptop must not yield every Space), and emergency escrow wraps a **personal-content key** that cannot reach the identity. **Write integrity is completed in P**: explicit merge/expected-tree rule, signing failure hard-errors on shared Spaces, quarantine + quorum-signed rewind primitive, transport least-privilege (pending/viewer = read-only collaborators). Every HPKE wrap is context-bound (purpose, space, member, epoch). Cipher paths become collection-scoped (`ciphers/<collection_id>/<uuid>.enc`) so the policy table is enforceable. Space key-derivation surface enumerated (seven RootKey derivations + vault_id/AAD + keyring namespace). New: member reset, ownership transfer, Space recovery phrase, per-provider transport staging, clock clamping.
**Rev 7/7.1/7.2**: identity lifecycle, policy table, per-recipient outboxes, provider asymmetry. **Rev 2–4**: independent peer reviews.
**Scope**: Every scenario where more than one person touches the same data, on the serverless architecture (git remote = transport, no backend).
**Companion docs**: `docs/software-architecture-decisions.md` (D9; DOMAIN 5 commit signing; D4 conflict resolution), `docs/software-architecture.md` §4, `docs/threat-model.md`. D-numbers have drifted; this plan cites decisions by name.

---

## 0. TL;DR

| # | Scenario | Design | Phase |
|---|----------|--------|-------|
| P | — | **Prerequisites**: identity-rooted Spaces with a **layered identity** (keystore/recovery-sealed, never master-password-reachable), signature repair with roster-snapshot rules, **complete write integrity** (merge rule, no unsigned commits, quarantine + quorum-signed rewind), transport least-privilege, multi-writer git layer, context-bound wraps, policy table, default-deny IPC. No sharing code before P | P |
| A | Whole Space shared, roles | Directory membership; per-member unlock via personal vault; net-diff policy | S1a/b |
| B | Item co-ownership | Pair Space (both editors) | S2 |
| C | Owner-controlled share | Outbox repo per recipient (read-only collaborator; live mirror; revoke = unpublish + rotate) or pair Space with viewer grant | S2 |
| D | Org granularity | Collections + grants, templates, JIT, expiry-that-rotates, groups; trash purge admin-only | S3/S4 |
| E | Parity gaps | §5.E matrix | S4 |

Trust: contact cards + address book; **Level 0** passphrase reveal, **Level 1** channel trust (packages only), **Level 2** code check (required for live shares and family invites), **Level 3** admin approval (org; replaces the code check). All async. No server, ever.

Enforcement: **read scope** = keys (+ local index); **write integrity** = policy table + signatures, merge-safe; **one-way availability** = read-only collaboration; **push rights** = provider ACLs, staged least-privilege.

---

## 1. Scenarios

- **A. Shared Space, roles.** 2+ people, each their own master password. Owner/admin full control; editors create/edit; viewers read/use. All sync.
- **B. Item co-ownership.** Two users, one entry, equal power; both can revoke.
- **C. Owner-controlled share.** Owner keeps power; recipient views/uses; owner revokes any time.
- **D. Org granularity.** Admins see all; members only their collections, read or write; trash purge admin-only.
- **E. Parity** (§5.E). **G. Guest**: one collection, read-only, end date. **H. Multi-device member.** **I. Clean split.** **J. Departure with live provider access.** **K. Owner incapacitation / provider loss.** **L. Member reset** (device gone AND phrase gone; §5.F-8).

---

## 2. Current state (verified against source)

What exists and is reused:

| Piece | Where | Notes |
|---|---|---|
| Key hierarchy | `keys/`, `vault/handle.rs` | RootKey → SGK → ItemKey (HKDF, epoch-bound), zeroize. **Seven key derivations take the 64-byte RootKey** (`crypto/hkdf_derive.rs`: index, folders, tags, profile, settings, activity, generator-history); `vault_id` (the AAD identity binding) and the keyring namespace derive from the KDF salt. A Space without a master password must re-home all of them (P1) |
| Org key wrapping (island) | `orgs.rs` | HPKE `WrappedKeyBundle`, add/remove member. Zero callers. **`OrgMember.email` is plaintext** in `access_list.json`. Becomes the Space-wrap engine in P1 |
| Rekey machinery | `handle.rs` | Rotation covers ciphers/trash/attachments/canary/folders/tags/profile/activity/recovery-rewrap plus settings + generator history (propagated failures, P4 2026-09-19); emergency escrow rewrapped to the new root in both rotation fns. avatar re-encrypted at rotation (P4, 2026-09-19). Keywrap distribution + txn consumer fixed (P3, 2026-09-19): `rotate_root_key` wraps every enrolled device; survivors adopt from the epoch-bound `meta/rekey/<epoch>.txn` at unlock. Index: untracked + sharded (P5b), rebuilt locally |
| Commit signing | `sync/engine.rs` | **FIXED IN P2 (2026-09-18)** — was: verification dead in production (test-only `meta/device-registry.json` fixture) + silent unsigned fallback. Now: roster-snapshot verification from commit trees, unsigned refused at creation on enrolled vaults, clone paths verify fetched history. Still open (by design): `load_signing_key` first-keyring-hit ordering; `unlock_with_kek` adopts another device's identity (S1a). Merge parent-order swap: content smuggling closed by the P8a merge-residue rule; first-parent roster resolution stays order-sensitive until S1a roles land |
| Cloning | `sync/engine.rs` | **Full clones only**: `SyncEngine::clone` ignores its shallow flag (`engine.rs:1252`) and sets no depth. Any "shallow-clone policy" is a policy for something that does not exist |
| Conflict resolution | `sync/engine.rs`, `runtime/state.rs` | Field-level cipher merge; 2-parent merges; single-file only; `add_all("*")` ×2; **devices.json churn FIXED (P5a, 2026-09-18)**: deterministic serialization + skip-if-unchanged + registry-union auto-resolve for devices.json-only conflicts |
| Emergency access | `emergency.rs` | **Island** (no daemon route, no CLI, no UI). The envelope wraps the **Root Key** (`emergency.rs:34`) — anything derived from RootKey, including a stored identity, is inside its grant |
| Recovery | `recovery.rs`, `device_manager.rs` | BIP-39 phrase wraps RootKey; `EnrollmentPolicy::{Personal, Strict}` |
| Multi-vault host | `baluard-runtime` | VaultHost map + per-vault tokens. `VaultState::lock` takes the inner RwLock write guard (drains in-flight handlers naturally); called from 5+ sites, no host back-pointer; **mobile has no VaultHost** (uniffi wraps a single vault) |
| Sync | `sync/engine.rs` | commit → pull (force-checkout) → resolve → push; **verification aborts the whole pull on the first bad signature** (`engine.rs:1620`) — one rejected commit wedges the remote for everyone |
| Trash | `handle.rs` | `trash/<id>.enc`; active ciphers `ciphers/<id>.enc` (flat, UUID-named); attachments under `entries/<id>/attachments/` |
| Providers | `providers/` | GitHub classic `repo` scope (collaborator write + invite accept OK; **grants read on ALL the account's repos** — corporate security-review blocker, §4.5); GitLab `api` OK; Codeberg scopeless. `create_signed_commit` unsigned-fallback applies to every provider |
| Daemon gating | `handler.rs` | **FIXED IN P6 (2026-09-18)** — was: `TOKEN_REQUIRED_ACTIONS` opt-in allowlist (default-allow). Now: default-deny with an 8-entry `TOKEN_EXEMPT_ACTIONS` + exact-set pin test + sentinel-forwarding invariant; `vaults.*` host routes remain pre-token (§9.8; `vaults.detach` destructive arm documented as socket-UID-trust) |
| Schema | `proto/space.proto` | Still models the plaintext-email membership; P must replace it |

Does not exist: callers of `orgs.rs` or `emergency.rs` (both islands); member identities or identity lifecycle; per-member unlock; keywrap distribution; signature policy; key exchange; collections; an Activity data source (T14: uniform commit metadata).

---

## 3. Architectural constraints

1. **No server.** Everything local, cryptographic, or signature-based.
2. **Git commits are storage, not a log** (T14). Audit trail = signed event files, built.
3. **Revocation is eventual.** Removed members keep their bytes. **Reads leave no trace**: per-credential read auditing is impossible by design; say so before any pilot.
4. **Integrity vs availability.** Detect, notify, rewind (quorum-signed), migrate; provider ACLs fence.
5. **Symmetric keys do not separate read from write** — except at the transport (read-only collaborator, outbox).
6. **Two authorities, one user**: crypto membership AND provider ACL, one flow.
7. **File modes do not survive git.**
8. **Padded buckets**: plaintext = opaque IDs + display names + trust. Padding also multiplies history.
9. **Pre-1.0**: formats break freely (envelope v2, path layout, wrap binding included).
10. **UX bar**: six screens; no HPKE, SGK, epochs, policies in any user surface.
11. **One credential per human, for life.** Second password prompts are forbidden — key-layer separation must not reintroduce them.
12. **A shared OS account is not a security boundary.** One OS account per human, or existence/names are shared (§9.8).

---

## 4. Building blocks

### 4.0 Prerequisites (phase P)

| # | Blocker | Work |
|---|---|---|
| P1 | **Identity-rooted Spaces with a layered identity.** The identity keypair is stored data — **sealed under a key that is not the master-password KEK**: OS keystore / non-exportable where available, escrowed to the recovery-phrase pubkey, never the plain KEK seal. Disk theft then yields personal ciphers (bad) but not the identity (catastrophic avoided); no second password prompt. **The keystore is a hard requirement for identity-bearing vaults** — every minimum platform ships one (Keychain, Windows Hello/Credential Manager, Secret Service on the Linux minimum), and quick-unlock already depends on it; there is no silent KEK-seal downgrade, and recovery-phrase escrow is the backup path, not the daily unlock path. **Keystore-less fallback (explicit, warned)**: on headless Linux, WSL, or CI where no keystore exists, the identity seals under an Argon2id passphrase-derived key with a visible downgrade warning ("on this system, your vault password also protects your shared Spaces") — never a silent downgrade, never a hard block. **Emergency scoping by construction**: emergency escrow wraps a **personal-content key** covering personal ciphers only; the identity sits under its own key, never wrapped to the emergency contact. **Space key-derivation surface enumerated** (P1 scope, not "swap the key source"): the seven RootKey derivations re-home to SGK (index, folders, tags, profile, settings, activity, generator-history); `vault_id`/AAD binding, keyring namespace, canaries, `find_device_id` get Space-side equivalents. Unlock dependency: Spaces open FROM the personal vault. **Lifecycle**: (a) `identity.rotate` two paths — routine (old key held; self-wrap in own subtree; **Space notice to every client, trust reset, contest window** — a thief holding a stolen key can run this path, so rotation must be visible and contestable; justified against the device-quorum bar) and compromise (admin re-wrap **and Space SGK rotation**; non-admins enter `AwaitingReWrap`); (b) emergency as above; (c) quick-unlock explicit-enable warning (shared biometric enrollment); (d) **lock chokepoint**: `VaultState::lock` host-private; cascade = generation bump + token invalidation + `VaultState::lock` drain; host lock outermost, released before per-vault locks; never await `cycle_lock` (held across 60s network `spawn_blocking`; its timeout does not cancel the blocking task) | **◐ In progress (2026-09-19)** — P1a done: identity keypair (Ed25519 signing + X25519 wrap from one 32-byte seed) generated at creation, sealed under keystore-held random wrapping key (never the vault KEK), HPKE-escrowed to recovery pubkey, passphrase fallback for keystore-less systems (dedicated salt, warned downgrade), `identity()` accessor, `rotate_identity()` (re-seal + re-escrow, no phrase needed), creation-order fix (identity generated before initial commit in both ceremony paths). **P1c done: lock chokepoint cascade — `VaultState::lock` bumps a session generation FIRST, all four token mint sites (unlock / unlock_with_kek / pin_unlock / create) stamp the mint generation, `verify_session_token` rejects generation mismatches (a stale token dies even if a future lock path forgets the explicit clear), TTL expiry + stale-generation paths clear the stamp uniformly, lock never awaits cycle_lock (regression-tested under a 2s deadline), lock_all cascades across vaults without holding the host lock.** P1d done: quick-unlock explicit-enable warnings — shared-biometric/PIN enrollment warning (`settings.quickUnlockSharedWarning` / `settings.pinSharedWarning`, en/es/pt) rendered in both enable panels before confirmation. Remaining P1 (Space-dependent): Space-side SGK re-homing, compromise-path rotation with Space notice. See also P8b for the revocation-manifest recovery path | |
| P2 | **Signature-verification repair, complete.** Verify keys from `meta/devices.json` (UUID map); bind signature → device → member → role; bind loaded signing key to `self.device_id`; no identity adoption in multi-member vaults; delete the fixture. **Roster-snapshot rule**: walk new commits topologically, resolve roles from each commit's first-parent tree, advance an in-memory roster. **Signing failure is a hard error on shared Spaces** (no unsigned fallback); provider-side commits (web merges, transfers) get an explicit policy verdict. Production-shaped tests | **✅ Done (2026-09-18)** — shipped: first-parent-tree roster (genesis transition + pre-enrollment grandfathering), unsigned refusal via tree check (worktree-immune), clone-path full-history verification + target cleanup, index restore on refusal, blob-cached rosters, creation-order fix (registry precedes initial commit), mismatch warning (create-side only — pull-side roster is the hard gate). Boundaries → P7/P8: merge parent-order swap; stripped parallel history at first clone (TOFU) |
| P3 | **Keywrap distribution to member identities.** Survivors unlock on next pull. **Concurrent rotations** (two admins removing different members at once): both commit SGK rotations; the epoch comparison makes the higher epoch win deterministically, the losing client re-applies its removal against the winner's state — no manual conflict resolution, no wedge | **✅ Done (2026-09-19, pre-Space scope)** — routine `rotate_root_key` stages HPKE wraps of the new Root Key for every enrolled device (actor-only write removed; staged .tmp committed with the rotation, failures propagate); revoke-path survivors adopt their per-device entry from the committed txn at unlock — binding: txn file name == `tx.new_epoch` == current canary epoch, any mismatch fails closed; adoption runs BEFORE the F1 cross-device heal so a survivor keeps its own identity; the adopted wrap is persisted (0600) so the next unlock takes the fast path. Tests: 3-device survivor unlock (identity + cipher + epoch), distribution content check (unwrap == new root), fail-closed (missing txn, tampered epoch). Boundary: loser-re-applies for concurrent multi-admin rotations needs S1a role flows | |
| P4 | **Rotation coverage, failures propagated.** `settings.enc` (eight RootKey-derived artifacts total, counting `derive_settings_key` in `handle.rs`), `emergency.json` (now the content key), avatar, attachments, identity keypair; **replace every `let _ =` in the rotation loop with propagated errors** — silent partial failure leaves files unreadable at the new epoch | **✅ Done (2026-09-19)** — shipped: settings + generator history joined the pre-swap read set (propagated `?`, never `.ok()`); attachment re-encryption staged in rotate_root_key (mirrors revoke); emergency escrow rewrapped to the NEW root key in both rotation fns with config-load errors propagated; RotationGuard armed-Drop keeps the marker (incomplete rotation never looks complete) and disarm/marker-removal moved to the very end; concurrent-rotation test coverage. avatar re-encryption shipped (same day): `meta/avatar.enc` is decrypted with the pre-swap SGK-epoch key and re-encrypted under the new one, staged into the atomic rename set in both rotation fns; the stale-epoch key refuses the new blob (test-verified). Known boundary: a crash in the narrow window between the keywrap commit and the metadata re-saves leaves the marker + a warned mixed-epoch state (P8 manifests will harden) | |
| P5 | **Multi-writer git layer.** Per-device split; explicit staged path sets; multi-file + non-cipher conflict strategies; per-fact folders/tags with carve-out; **`meta/index.enc` gitignored, untracked, rebuilt locally — and sharded** (the single padded envelope hits `Tier::fit`'s 2 MB ceiling around 8–13k entries; shard by collection or fixed ranges); **cipher paths become collection-scoped**: `ciphers/<collection_dir>/<uuid>.enc` where `<collection_dir>` is a **salted hash of the collection id** (opaque grouping and counts to the git host; the threat model notes the leak is structural otherwise); personal vaults: `ciphers/<uuid>.enc` as today — so the policy table can bind writes to collections; incremental index updates, undecryptable entries surfaced by count; **hardware AES enabled** (software fixslice is ~25–40 MB/s class on mid-range mobile; the flag divides crypto by ~20); cover commits off in shared Spaces | **◐ In progress (2026-09-18)** — P5a done: deterministic devices.json (all writers), churn kill, registry-union auto-resolve for devices.json-only conflicts. P5b done: index untracked (gitignore + open_repo untrack), staleness guard (set-equality disk scan + skipped-list + key-epoch), sharded layout (2048 entries/shard, sorted-by-id, prune orphans, shard-bound AAD, count-driven reader fails closed on truncation/torn), keyless invalidation hooks after pull/sync (autosync + daemon + CLI), 0600 vault-file writes. P5c done: per-fact folders (`meta/folders/<uuid>.enc`) and tags (`meta/tags/<sha256-prefix>.enc`, name stored inside, digest filename — no traversal surface) with skip-if-unchanged writes, orphan prune, legacy-envelope read fallback, migration-on-write (reads never delete); hardware AES on aarch64 via `.cargo/config.toml` `--cfg aes_armv8` (runtime-checked intrinsics, soft fallback; x86_64 autodetects by default). Remaining: explicit staged path sets, collection-scoped paths (S3 dependency) |
| P6 | **Default-deny IPC.** Invert to `TOKEN_EXEMPT_ACTIONS` + coverage test; `vaults.list` stays pre-token (§9.8 limitation) | **✅ Done (2026-09-18)** — shipped: default-deny inversion (exempt = 8 pre-token actions incl. the 8 provider sentinel routes…12 total: 4 vault + 8 provider), `SENTINEL_FORWARDED_ACTIONS` guard + invariant test (sentinel ⊆ exempt — catches the "gated action through tokenless sentinel" bug class), `HOST_ONLY_ACTIONS` tripwire hoisted before the token gate, exact-set pin on the exempt surface, host-only tripwire test on the tokenless sentinel. Boundaries: host surface (vaults.*, bridge ceremony) stays pre-token by design — per-vault token cannot exist pre-unlock; §9.8 stands | |
| P7 | **Policy table as data + wrap context binding.** The path-glob → role table (§4.4) consumed by the net-diff checker; `wrap_key`/`unwrap_key` bind AAD = `baluard-keywrap/<context>` with a per-call-site context string (`keywrap:{vault_id}:{device_id}` shape); readers reject a wrap whose binding does not match its file. Required tests: glob precision, pending-joiner row | **✅ Done (2026-09-19)** — P7a: context-bound HPKE wraps — `wrap_key`/`unwrap_key` take a `context` argument, seal under context-bound AAD (`baluard-keywrap/<context>`, info `baluard-hpke-wrap-v2`), keywrap call sites pass `keywrap:{vault_id}:{device_id}`; transplant and rollback rejection tests shipped. P7b: policy table as data (`sync/policy.rs`, §4.4 rows plus the device/rotation admin surface and a root-file row), first-match-wins segment matcher (`{self}`/`*`/`**`, deny by default), and net-diff consumption wired into BOTH verification walks (pull + clone): every path a regular commit touches must be admitted by the signer's row; merge commits exempt until P8a; the signature verifier now returns the matched device id and role resolution is roster-membership-is-admin-equivalent (S1a replaces the resolver). Tests: 6 matcher/table unit tests (glob precision — caught the `{self}`-literal arm bug, pending-joiner row, editor/admin boundaries, deny-by-default) + end-to-end pull refusal of an uncovered path (fail-first: pulled through as Ok(FastForward) before wiring) | |
| P8 | **Write-integrity completeness (moved up from S4 — the policy is decorative without it).** (a) **Merge rule**: for merge commits, recompute the expected merge from the parents; only the residue (difference between the actual merge tree and the recomputed one) is attributed to the merger — an honest merger's residue is empty, a smuggler's is their contraband; (b) **revocation manifests (append-only, never force-push)**: a rejected batch is never merged; an admin pushes a signed revocation manifest (append-only commit — works under default branch protection) listing the rejected commit hashes; clients never apply listed content, restoring the affected paths from the last clean state during checkout overlay, and the manifest rides normal pushes so recovery never needs history rewriting; (c) **transport least-privilege**: pending joiners and viewers are READ-only collaborators; write seats are granted only at `active` with an editor-or-above role | **◐ In progress (2026-09-19)** — P8a done: merge-residue rule — for merge commits the expected merge is recomputed from both parents over their merge base (`merge_trees`); the diff between that expectation and the actual tree is the merger's residue and must pass the signer's policy row; conflicted paths are attributed to the merger outright (a resolution is authored content); octopus merges refused outright. Closes the P2 content-smuggling boundary: residue is parent-order invariant for non-conflicted content, so a parent-order swap can no longer land contraband. Tests: honest merge verifies, smuggled residue refused (fail-first — it merged through as Ok before wiring), conflicted-resolution attribution. S1a note: P5a's registry-union auto-resolve authors `meta/devices.json` inside a merge — once roles land, a non-admin merger's union resolution will be policy-rejected; grant or gate it at S1a. P8b done: `meta/revocations.json` append-only signed entries (Ed25519 over canonical payload, domain-tagged `baluard-revoke/v1`); entry authorization = roster membership at the introducing commit + entry signature (no roles yet — every enrolled device is admin-equivalent, tightened at S1a); per-transition verification walks full history on tracker miss: append-only containment (parent entries must survive UNCHANGED — stripping, field-rewrite, and file deletion all fail closed), new entries signed by a roster device at their introduction snapshot (de-enrolled former signers can never wedge pulls); local tracker (`meta/revocations-verified.json`, gitignored: verified blob id + applied commits) makes steady-state pulls one file read; restore = affected paths (revoked vs first-parent diff, traversal-guarded) where HEAD still carries exactly the revoked content, written 0600/0700 and committed via targeted path-scoped signed commit (never sweeps unrelated worktree changes); applied from all three pull exits incl. up-to-date (closes the conflict-resolution gap); `append_revocation` derives the signer identity from the loaded key against the HEAD-tree roster (never an argument), self-heals the revoker's worktree, then the manifest + restore ride a normal push; surfaces: `baluard sync revoke <commit> --reason`, daemon `sync.revoke`; 5 new tests (append refusals, end-to-end restore + idempotency + 0600, retroactive field tamper, strip attack, signer derivation). Remaining P8: (a) merge-residue rule, (c) transport least-privilege | |

### 4.1 Identity and trust: cards, dial, lifecycle

Contact cards signed by the identity key; local encrypted address book; identity is a one-time cost per relationship.

| Level | Mechanism | Recorded as | Used for |
|---|---|---|---|
| 0. Passphrase | App-generated passphrase, Argon2id+AES-GCM, params+expiry in AAD; no identity involved | n/a | Guest reveals only |
| 1. Channel trust | Card from a trusted channel | `trust: channel` | Packages (IS-3) — inert only |
| 2. Code check | Both apps show a code; compare over chat whenever, or QR in person | `trust: verified` | **Required** for live shares and family invites |
| 3. Admin approval | Join link; approval vouches; **replaces** the code check for org joins (org invites are Level-3 by definition) | `trust: admin` / `admin-unverified` | Org onboarding |

Join queue: provider grant **read-only** at step 0 → one-time token → self-introduction at the member's own pending path → async admin approval → write seat granted at `active` (transport staging, P8c). Identity compromise → compromise-path rotate + Space rekeys. Emergency: personal content key only, never the identity (P1).

### 4.2 Membership v2

`meta/members/<member_id>.json` (id, display_name, role, trust, **per-provider handle in the encrypted portion**, encrypted email optional); `meta/members/<m>/devices/<d>.json`; wraps: **admins/owner hold `space.wrap` (W(K, id)); non-admins in Team shape hold only their collection wraps** (`meta/collections/<c>/<m>.wrap`) — a viewer or single-collection editor never receives K. `meta/collections/<id>.json`: grants `{member, access, expires_at?}` and `name_enc` encrypted under **CK** (grantees see real names; non-grantees see an opaque id; the optional org catalog that exposes names to requesters is a plaintext-id list, an explicit setting). `meta/members/<m>/requests/<id>.json`: JIT asks, HPKE-sealed to the approver set. Constraint: every member holds an account on the Space's provider (cross-provider membership impossible — say it at first run, not in a constraints section). Per-file everywhere; plaintext = UUIDs + display names + trust.

### 4.3 Key model

| Key | Personal vault | Space |
|---|---|---|
| RootKey / content key | today's RootKey plus a **new personal-content key** (personal ciphers + emergency escrow); identity keypair sealed separately (P1) | SGK random at creation; **no RootKey**; all seven derivations re-homed to SGK or per-purpose keys; index key from SGK |
| Identity keypair | stored data, keystore/recovery-sealed (P1) | — |
| Item keys | HKDF(SGK, cipher_id, epoch) | collection entries: HKDF(CK(c), cipher_id, epoch) |
| Collection key | — | random; wrapped under SGK (admin) + per granted member identity; Team-shape non-admins hold **no K** |

Rotation coverage (P4): Space member removal → new SGK + CK rotations + re-wraps; personal rotation → content key + identity re-encryption + settings/emergency/avatar/attachments, failures propagated.

### 4.4 Enforcement — the policy table

| Path glob | Required signer role | Notes |
|---|---|---|
| `meta/members/<own_id>/**` (devices, pending, requests, space.wrap routine self-wrap) | that member, any role | self-service; routine rotation signs with the old key |
| `meta/members/<other>/**`, `meta/collections/**`, `meta/space.json` | admin/owner | membership, grants, settings |
| `meta/folders/**`, `meta/tags/**` | write scope (editors included) | per-fact files + tombstones |
| `ciphers/<collection_id>/**` (personal: `ciphers/**`) | write scope on that collection | collection-scoped paths make the table enforceable |
| `trash/**` | per `trash_policy`; restore/purge admin | |
| `entries/<id>/attachments/**` | write scope on the parent item | |

**Net-diff and merge rule**: for each new commit, resolve the signer's roles from the commit's first-parent tree (roster snapshot, P2); regular commits: `diff(first_parent, commit)` paths must be covered. Merge commits: recompute the expected merge from the parents; only the **residue** (actual tree minus expected merge) is attributed to the merger — an honest merge leaves no residue, a smuggler's contraband is visible. This rule lives in P8, not S4. **Unsigned commits** on shared Spaces: never accepted (P2 hard-error at creation; provider-side unsigned commits hit the P8 revocation manifest). Rejection: detect + notify + **admin-signed revocation manifest** (append-only commit listing bad hashes; clients overlay-listed paths back to last clean state — recovery works under default branch protection, no force-push anywhere) + local audit ref; `space migrate` as the nuclear fallback.

### 4.5 Provider ACL coupling

`add_collaborator` + `collaborator_status` + `ensure_access_accepted` (GitHub: list-match-accept, scoped to the expected repo, 7-day expiry tracked with auto re-invite; GitLab: add by `user_id` only, immediate, Reporter(20) for read-only; Codeberg: adds immediately, acceptance no-op, scope gaps UI-flagged). **GitHub scope policy (staged)**: personal and family flows may use classic OAuth (`repo` scope — broad, and the blast radius is documented), but **org/shared Spaces from S3 require fine-grained PATs scoped to `baluard-*` repos or a GitHub App**: classic scope reads EVERY repo on the account, a corporate security-review blocker and a large token-theft blast radius. **Transport staging**: pending = read-only, viewer = read-only, editor/admin = write — granted at `active` (P8c). Pre-flight before removal: **provider seat removal is confirmed before the rotation commit is pushed** (offline override is explicit); failures on screen 6. **Org readiness**: repo ownership AND GitHub org third-party-app approval AND scope honesty. Free-tier seat/quota and ToS-for-non-code-data table verified per provider before S3.

### 4.6 Sharing surfaces

- **IS-3 package** (one-shot copy): Level 1; inert; cannot be un-shared; pre-send copy says so.
- **IS-6 reveal** (field-scoped, view-only help): default URL+username+password; TOTP opt-in with permanence warning. Contact-key flavor (viewer card) + passphrase guest flavor (**requires the Baluard app without a vault** — "Open a shared file" on first-run; app-generated passphrase; voice delivery; expiry in AAD). Both v1 (§10.8 decided).
- **IS-5 pair Space** (B): visible 2-person Space, both editors. In Family shape (no collections) this is also the answer to "share one entry with my spouse but not the kids" — the share sheet creates it silently, without saying "Space".
- **Outbox, one repo per recipient** (C): **live mirror** — the owner's client re-publishes on every edit of a published entry (own debounce), entries encrypted under a dedicated outbox content key; source deleted → entry unpublished; revoke = unpublish + rotate + provider seat removal. Recipient retention stated at share time. Transport-enforced read-only on GitHub/GitLab; Codeberg pollution-only, ignored, UI-flagged.
- **IS-4 inline item keys**: cut (S5 revisit if users ask by name).
- **Merged single-list presentation** + `vaults.list_full_all` (desktop); mobile multi-Space host is an S4 line item.
- **Repo naming**: default `baluard-personal` (probe → adopt/restore → remote suffix on collision; never forced — §10.6b decided); `baluard-space-<name>`; `.baluard` marker remains the only identity check.

### 4.7 Org granularity ladder

1. Role templates (S3). 2. Collections + delegated `manage` (S3). 3. Request-access JIT — HPKE-sealed asks; **the org optionally publishes a plaintext-id collection catalog so requesters can name what they ask for** (setting; names stay encrypted) (S3/S4). 4. Expiry-that-rotates — admin's client executes on next sync; **pending expirations surface on screen 6 for every member**, so holidays do not extend contractor access. S3. 5. Groups as key layer (S4). 6. Access review report — repo ownership + expired-but-unenforced grants (S4). 7. Dual control 2-of-2 XOR (S4). 8. Two-tier envelopes (skip v1, §10.7). 9. Per-item ACLs — rejected as primary (S5 exception). 10. Break-glass counters — theater as control; loud event only.

### 4.8 The screens (six)

1. **Share sheet** — person picker + "Can view / Can edit" + Share; context creates the pair Space, grant, or outbox silently. 2. **People** — faces, role pill, verification badge, add/remove, **member reset**, **transfer ownership**. 3. **Invite & Accept** — the only ceremony; "waiting on N people, last seen X" so ceremonies never rot silently. 4. **Activity** — human sentences, best-effort label. 5. **Requests** (Team shape) — approve/deny inbox. 6. **Space notices** — removals, blocked pushes, rewinds pinned by head hash, pre-flight failures, pending expirations, identity rotations awaiting contest or re-wrap.

First run asks no taxonomy question: password + recovery phrase, done. Shape is chosen only at Space creation, one line (Family = everyone sees everything / Team = groups of items), one-way ratchet. Vocabulary: "Your vault" and "Shared spaces".

---

## 5. Scenario designs

### 5.A Shared Space with roles

Capability matrix unchanged: owner > admin > editor > viewer; trash move = write scope (`write_scope_can_trash`); restore/purge admin; self-service device lifecycle all roles; invite/remove/rekey admin+; delete Space owner. Members unlock with their own passwords; Space keys unwrap against identities. Recovery: personal phrase → identity → all Spaces; `identity.rotate` for compromise; **member reset** (L) for phrase-loss: an admin issues a fresh identity (new member id, old row tombstoned, re-verify, re-wrap) — the #1 family support ticket, S1a. **Ownership transfer** is a first-class action (role change + provider repo transfer + adopt semantics). Remove flow: batch, pre-flight, survivors re-keyed (P3), evicted fails closed. Cover commits off in shared Spaces (a cover commit is not a true no-op — it rewrites `meta/devices.json` — which is the reason it is off). Space auto-lock inherits the personal timeout; the personal vault's timeout is the effective global ceiling.

### 5.B / 5.C Item sharing

Pair Space (B), per-recipient outbox live mirror (C), package (IS-3), reveal (IS-6). Family-shape single-entry share = silent pair Space. **Zero-ceremony rule inside an existing Space**: adding or moving an entry into a Space a verified member already belongs to is zero extra ceremony — no new repos, no new code checks; the pair Space and its one-time verification happened once, at the relationship. Rejected: IS-1, IS-2, IS-4 (S5 revisit).

### 5.D Org granularity

CO-1 collections; per-identity CK wraps; grants with rotation-backed expiry; templates, delegated manage, JIT; local sharded index = listing; trash policy + tombstone undo (72h, held from push); guests work because the index is local; groups (S4).

### 5.E Parity matrix (delta from Rev 5)

Row 2 sharing = pair Space + per-recipient outbox + package + reveal (S2); row 3 collections + local sharded index (S3); row 7 Activity = signed event files, admin-signed rolling compaction with a hash over the replaced set (censorship-detectable), S1b min / S4 full; row 13 groups S4; row 21 expiry-that-rotates with member-visible pending surfacing (S3); row 6 personal areas S5; row 9 recovery spans identity; row 17 emergency = personal-content key scoping (P1, by construction).

### 5.F Lifecycle and operations

1. **Multi-device member**: personal-only (H).
2. **Clean split**: `space.export` (package batch) / `space.sever` (fresh Space, new SGK, new remote).
3. **Departure pre-flight**: `collaborator_status`; checklist + deep link; "ask the repo owner"; offline override; failures on screen 6. **Plus the step that actually protects the company: rotate the exposed credentials themselves** (the departing member knows the passwords) — the offboarding checklist is a product surface, not prose.
4. **Offline member across a rekey** (after P3): pull → unwrap new Space key → re-encrypt unpushed commits → push; old commits to a local audit ref. Evicted: fails closed.
5. **Repo owner & quota**: owner + size surfaced; **growth is rotation-driven, not edit-driven** (every departure or guest expiry rewrites a collection): `space migrate` frequency derives from churn; size warnings early.
6. **Lost device**: personal-vault revocation; Spaces untouched. **Identity compromise (unlocked theft)**: `identity.rotate` compromise path — Spaces re-wrap via admins and rotate, async.
7. **Owner incapacitation / provider loss**: warning at one-provider-admin; `space.adopt` via the out-of-band adopt link (same channel as invites — the dead remote is not a channel); optional cold mirror. `space.adopt`/migrate at S3.
8. **Member reset (L)**: admin-issued fresh identity; old member row tombstoned; entries preserved. The answer to "tablet died, phrase lost" — the #1 family ticket.

---

## 6. Cross-cutting decisions (ranked)

### 6.1 Identity and trust
1. Identity-rooted Spaces **with layered identity + lifecycle** (rotate, reset, emergency content-key scoping, quick-unlock warnings)
2. Contact cards + address book + graded dial (0–3), Level 1 inert-only, Level 3 replaces Level 2 for org joins
3. Join queue with read-only step-0 grant; write seats at `active`
4. Bilateral QR — in-person rendering of the code check; provider discovery — sugar; key server — rejected

### 6.2 Enforcement
1. P2 + P5 + P7 + P8 (repair, staging, table, wrap binding, merge-residue rule, rewind, transport staging)
2. Net-diff per-path policy with the merge-residue rule
3. Read-scope keys + local sharded index
4. Outbox per recipient
5. Provider collaborator staging + branch protection
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
| `quorum_admin_ops` | 1..n | 2 when a second admin exists, else 1 |
| `guest_enabled` | bool | true |
| `grant_expiry` | rotation-backed, member-visible pending | on |
| `vault_timeout` | inherited from the personal vault (the global ceiling) | inherit |

---

## 7. Roadmap

| Phase | Content | Depends on | Size |
|---|---|---|---|
| **P Prerequisites** | P1 identity-rooted Spaces + **layered identity** (keystore/recovery seal, content-key split, seven-derivation re-homing, vault_id/AAD + keyring namespace equivalents) + lifecycle (rotate with notices/trust-reset/contest window, quick-unlock warnings, lock chokepoint + generation-bump cascade); P2 verification repair + roster-snapshot + **signing hard-error**; P3 keywrap distribution to identities; P4 rotation coverage with propagated failures **(P4 DONE 2026-09-19: settings/generator/attachments/emergency joined rotation coverage, avatar re-encrypted under the new SGK-epoch key in both rotation fns, all post-swap saves propagate, emergency escrow rewrapped to the new root, marker survives any failure)**; P5 multi-writer git layer + collection-scoped cipher paths + **sharded local index** + hardware AES **(P5a DONE 2026-09-18: deterministic devices.json serialization — all writers, kill of the per-commit churn that guaranteed multi-device conflicts on the shared registry, registry-union auto-resolve for devices.json-only conflicts. P5b DONE 2026-09-18: index untracked + gitignored (local-only, rebuilt from ciphers), sharded layout with deterministic boundaries + shard-bound AAD + truncation/ghost fail-closed, staleness guard (set-equality disk scan), keyless invalidation hooks after pull/sync, CLI direct sync unlock fallout fix. P5c DONE 2026-09-18: per-fact folders/tags (one encrypted file each, skip-if-unchanged writes, orphan prune, legacy fallback, migration-on-write — reads never delete), hardware AES on aarch64 via .cargo/config.toml aes_armv8 cfg (runtime-checked, soft fallback); remaining P5: explicit staged path sets, collection-scoped paths)**; P6 default-deny IPC; **P6 DONE (2026-09-18)**: default-deny inversion with pinned 12-entry TOKEN_EXEMPT_ACTIONS, sentinel-forwarding invariant, host-only tripwire before the token gate; **P1a DONE (2026-09-19)**: per-human identity keypair (Ed25519 signing + X25519 wrap from one seed) generated at creation, sealed under keystore-held random wrapping key (never KEK), HPKE-escrowed to recovery pubkey, passphrase fallback for keystore-less systems (dedicated salt, warned downgrade), identity() accessor, rotate_identity() (re-seal + re-escrow), seal-independence test (identity not decryptable with KEK-derived devkey seal); **P3 DONE (2026-09-19, pre-Space)**: keywrap distribution — `rotate_root_key` stages wraps for every enrolled device; survivors adopt their epoch-bound `meta/rekey/<epoch>.txn` entry at unlock (file name == txn epoch == canary, fail-closed, adoption precedes the F1 heal, adopted wrap persisted); loser-re-applies for concurrent multi-admin rotations awaits S1a; **P7 DONE (2026-09-19)**: policy table as data (`sync/policy.rs`, §4.4 rows) + net-diff consumption in both verification walks — regular commits deny-by-default on uncovered paths, merge commits await P8a's merge-residue rule; P7 policy table + **wrap context binding** (**P7a DONE 2026-09-19** — context-bound HPKE wraps in `hpke_wrap.rs`); P8 **write-integrity completeness**: merge-residue rule (**P8a DONE 2026-09-19** — expected-merge recomputation via `merge_trees`, conflict-resolution attribution to the merger, octopus refusal), revocation manifests (**P8b DONE 2026-09-19** — append-only signed manifest + signed restore commits; replaces quorum-signed rewind per §10.9), transport staging. **P2 DONE (2026-09-18, 2 review rounds): roster-snapshot verification from first-parent trees, genesis-transition + pre-enrollment grandfathering, tree-based unsigned refusal, clone-path full-history verification with target cleanup, index restore on refusal, roster blob cache, creation-order fix (registry before initial commit). Known boundaries → P7/P8: merge parent-order swap; fully-stripped parallel history at first clone (TOFU)** | — | L |
| **S1a Members** | Directory, cards + address book + dial, async states, join queue (read-only step-0 grant), `identity.rotate` end-to-end, **member reset**, invite/accept/role UI, batch removal + pre-flight + **offboarding checklist (rotate exposed credentials)**, **ownership transfer**, i18n. **S1a-1 DONE (2026-09-20)**: membership v2 directory (`meta/members/<member_id>.json`: id, display_name, role, trust; device bindings at `meta/members/<m>/devices/<d>.json`), owner genesis at creation (written before the initial commit), phrase-enroll/recovery binding to the owner member, and real role resolution in both verification walks (roster-snapshot rule extended to members; legacy rule: no member subtree = admin-equivalent; strict vaults treat unbound devices as pending joiners). Non-admin registry rule: `meta/devices.json` deltas by non-admins must be the signer's own last_seen_epoch bump (keeps the P5a per-commit bump from wedging lower roles). Tests: end-to-end role enforcement (editor cipher ok / editor meta refused / owner meta ok), owner-membership genesis in the initial tree. **S1a-2 DONE (2026-09-20, tracer bullet)**: end-to-end join ceremony walking skeleton — one-time invite codes (secret-hash pending record at `meta/invites/`), joiner introduction (clone + code proof + own password → device-local unlock material `meta/member-unlock.json`, gitignored), async admin approval (Root Key keywrap to the joiner's device + admin-authored member record/binding), member unlock via per-member KDF material + canary-override unlock tail, and pull-time enforcement (editor ciphers admitted, meta refused, HEAD unmoved). Integrity manifest deltas are self-authenticating (checkpoint signatures verified against roster keys — the manifest rides every commit and would otherwise wedge non-admins). Known tracer substitutions for later slices: member unlock material is device-local, not identity-rooted from a personal vault (S2/S3 upgrade); introductions travel out-of-band as codes (provider-grant staging = P8c); CLI/core surface only (UI = §4.8 screens). **S1a-3 DONE (2026-09-20, tracer)**: contact cards + trust dial — identity-signed contact cards (`SignedContactCard`, Ed25519 over a domain-separated canonical payload, verified against the card's own identity key); encrypted address book (`meta/contacts.enc` under the new RootKey-derived contacts key, rotation-covered in both flows, entries = UUIDs + display names + trust + public keys only); Level 2 verification code (both sides derive the same 8-hex code from the identity pubkey and compare out-of-band); trust dial enforcement — `approve_join` refuses roles above Editor unless the joiner's card is Verified in the address book (import lands at Channel; `contacts_mark_verified` records the code check; never downgrades). Joiner identity is generated at introduction and sealed under their devkey seal (device-local tracer substitution for the identity-rooted model). **S1a-4 DONE (2026-09-20, tracer)**: identity rotation end-to-end — `rotate_identity` records the new identity pubkey + rotation timestamp in the member record (self-service, ships via sync so rotation is visible to every client), member devices store identity artifacts member-scoped (`meta/members/<m>/identity.enc` + escrow, never in the synced meta/ root) and update their device-local sealed seed; the policy table's own-subtree row (`meta/members/{member}/**` Any) admits the member-scoped writes; `reconcile_stale_member_contacts` downgrades Verified contacts whose pubkey no longer matches any member's current identity (trust reset). Owner-path identity loading prefers the member-scoped sealed identity when a binding exists. **S1a-5 DONE (2026-09-20, tracer)**: member reset (§5.F-8, scenario L) — `member_reset` (admin-only, never owner/self, no double reset) tombstones the row (`reset: {successor, at}`, identity cleared, dead key parked in `identity_signing_pubkey_previous` so contact reconciliation resets the dial) and mints a reset invite bound to a fresh successor row (same display name + role, trust back at Channel for re-verification); `approve_join` binds the successor row instead of minting a member (intro cannot rename it; elevated roles re-verify at the existing gate). Enforcement is walk-scoped sticky: `MemberSnapshot` carries the tree's tombstoned ids, both verification walks thread a sticky set (pull seeds it from local-head ancestry, so a stale clone's rogue commit is refused even though its own ancestry predates the reset — asserted as a policy denial with HEAD unmoved); tombstoned rows resolve no role and no bindings; the structural member-record rule refuses any self-delta on a tombstoned row; `rotate_identity` refuses on a tombstoned member. Entries are preserved. Review round: fixed a latent S1a-1 privilege-escalation hole — `member_role_for_device` joined the binding path under the row FILE (always missed), so `assert_can_manage_members` always took the legacy-founder fallback; the gate now resolves roles correctly on strict vaults and fails closed for unbound devices. Also: tombstone enforcement hardened (own-tree harvest + batch pre-scan so topo order inside a pull cannot matter; tombstoned signers denied OUTRIGHT, covering the empty-residue merge shortcut); reset invites gate on the successor row's role (stale/tampered invite refused pre-consume, retryable); an identified successor cannot be re-bound. **S1a-6 DONE (2026-09-20, tracer)**: batch removal + offboarding (scenario J) — `member_remove` (admin-only batch; pre-flight refuses empty/duplicate/owner/self/unknown/already-tombstoned) tombstones each row (terminal `removed` marker, identity cleared, dead key parked in `previous` so contact reconcile resets the dial), strikes the members' device seats from the registry, deletes their keywraps + activity entries, and rotates the Root Key ONCE for the whole batch (survivors re-keyed via P3 staging; removed devices' wrapped copies die). Entries preserved across the rotation. Enforcement: `removed` joins the tombstone semantics everywhere (tree walk, sticky sets, structural rule, on-device role/binding lookups); a rogue commit from a removed member is refused at the roster layer (signer struck) or the sticky-tombstone layer (pre-removal race) — both asserted. Provider seat removal stays with S1b collaborator ops (documented boundary). Review round: `removed` rows sealed everywhere they were missed (approve_join successor rebinding, reset_member resurrection path, rotate_identity guard); member_remove now pre-flights the rotation's own preconditions (writes_allowed + actor privkey readable) so a rotation failure cannot strand tombstoned rows with an unrotated root; activity pruning went through the ENCRYPTED index (the plaintext-only call would shadow activity.enc with an empty file); removal report dedupes device seats. Tests cover a 2-member batch removal, survivor unlock after the rotation, and the pre-flight refusal branches. **S1a-7 DONE (2026-09-20, tracer)**: ownership transfer (§4.2, first-class action) — `transfer_ownership` (owner-only: the actor's member row must BE the current Owner row) demotes the old owner to Admin and promotes the successor to Owner with SelfTrust in one commit; exactly one Owner row before and after (the atomic unit is the commit, not the working tree); gates refuse unknown/self/tombstoned targets and non-owner actors (disk-backed role, so a demoted old owner cannot transfer until ownership returns); the gate follows the records, not the device — flip-back via the new owner asserted end-to-end. Provider repo transfer + adopt semantics stay with the provider layer (S1b collaborator ops, documented boundary). | P | L |
| **S1b Policy + Activity** | Net-diff policy (P7 table) **+ P8 merge rule + rewind**, detect + notify, event files + compaction + minimal Activity viewer, `add_collaborator`/`collaborator_status`/`ensure_access_accepted`, signed head gossip, screen 6 (notices incl. pending expirations), extension/desktop read scope (D21 allowlist decisions) | S1a | L |
| **S2 Items & Spaces** | IS-3 packages → IS-6 reveal (both flavors) → IS-5 pair Space (silent in Family shape) → per-recipient outboxes (live mirror) → merged multi-Space item list + `vaults.list_full_all` (desktop) | S1a | M |
| **S3 Orgs** | Collections + grants + rotation, role templates, delegated manage, request-access JIT (+ optional catalog), expiry-that-rotates + member-visible surfacing, org settings + presets + readiness (**org app approval, scopes, repo ownership, seats/ToS table**), provider checklist, **`space.adopt` + churn-derived migrate**, collection-aware extension routes, mobile admin surfaces | S1b | L |
| **S4 Power + Parity** | Groups, dual control, access review, full Activity timeline, org policies (advisory), emergency × org × identity doc, synthesized neutralization (revisit), **mobile multi-Space host** (uniffi VaultHost port, OOM-safe — L, own line) | S3 | L |
| **S5 Deferred** | Personal areas, per-item ACL exception, IS-4 revisit, travel mode, P2P send, provider discovery | — | — |

---

## 8. Test plan

- **Property tests**: wrap/unwrap **with context binding** (transplant and rollback rejected); revoke → unreadable; role × path × signer against the table; **merge-residue attribution** (honest merge = empty residue; smuggled tree = flagged); XOR dual control; expiry rotation; identity rotation (routine self-wrap; compromise re-wrap + SGK rotation).
- **P acceptance**: two humans, two passwords, one Space (P1); personal rotation preserves identity + wraps; **identity rotation locks out the stolen key (S1a)**; **offline disk theft cannot reach the identity (keystore/recovery seal)**; removal → survivors unlock (P3); legit verifies / foreign rejected on a production-shaped vault, fixture deleted (P2); **unsigned commit refused at creation on shared Spaces**; every `VaultState::lock` call site cascades via the host (P1); net diff == intent (P5); multi-file conflict resolves; index gitignored + untracked + incremental + **sharded past the tier ceiling**; hardware AES on; every action in exactly one token list (P6); **transport staging**: pending/viewer seats are read-only at the provider.
- **Integration**: join queue with invite expiry + re-invite + scoped acceptance; states to `active`; skip → badge; late check flips trust. Level rules (Level 1 never wraps a live key; Level 3 replaces Level 2 for orgs). Reveal: seed absent unless opted in; guest viewer without vault; expiry refuses stale. Outbox: live mirror on edit; per-recipient isolation; unpublish + rotate. Pair Space lifecycle. Batch removal. **Member reset** and **ownership transfer** flows. Merged list across N Spaces; auto-lock untouched-Space behavior; cascade without stalls or deadlock.
- **Policy-vs-engine**: every P7 table row; merge residue; roster snapshot (C1+C2 one pull); glob precision; pending joiner; unsigned verdict.
- **Cross-epoch offline** (after P3). **Crash safety**: RotationGuard; **rotation failures propagated, none swallowed**; rekey concurrent with member sync.
- **Clock clamp**: far-future commit date expires nothing; backdating stalls nothing.
- **Metadata hygiene**: no emails/plaintext beyond UUIDs + display names + trust; provider handles encrypted; emergency contact encrypted; outbox no cross-recipient metadata.
- **Bloat**: churn-derived migrate bounds clone size; sharded index past the tier cliff; cold-build measured WITH hardware AES.
- **UX**: six screens; non-technical invite without docs; first run = password + recovery phrase; quick-unlock warning at enable; "waiting on N people" surfacing.

---

## 9. Security notes and honest limitations

1. **Eventual revocation.** Removed members keep their bytes. Compliance version: **no erasure promises**; **no read auditing** (reads are local, no trace). Admin guide states all three.
2. **Editors can damage**: detect, notify, quorum-signed rewind, migrate. Provider ACLs fence.
3. **Read-only**: crypto scope, policy attribution, transport for one-way; elsewhere scope + policy + UI.
4. **The identity is the crown jewel — layered and priced**: keystore/recovery seal means disk theft yields personal ciphers, not Spaces; rotation answers online compromise; emergency scoping answers inheritance; quick-unlock warnings answer shared machines. Remaining truth: an attacker who phishes the master password AND defeats the OS keystore reaches everything. Priced.
5. **Level 1 is inert by rule**; Level 3 replaces Level 2 for org joins.
6. **Locked-device theft** = offline password attack against personal ciphers (identity sealed away); unlocked theft = personal rekey + compromise rotation.
7. **Metadata**: membership, commit timing, per-device activity, org-hosted push telemetry (org owners see per-member timing), outbox graph minimized per recipient. `0600` local-only.
8. **Shared OS account is not a boundary**; `vaults.list` is pre-token. Product states it.
9. **Verification graded and recorded**; org joins verify by approval, not by code.
10. **Head gossip**: detects rollback for members who observed the discarded head.
11. **Clocks clamp**: expiry floors come from admin-signed events, clamped to local clock + skew; wrong clocks neither extend nor stall enforcement.
12. **History bloat is structural and rotation-driven**; churn-scheduled migrate; size warnings early.
13. **Invariants**: AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroize-on-drop, 0600 at rest, token-gated IPC (complete after P6), mlock (budget includes identity + collection keys).

---

## 10. Open questions (Esteban)

1. Multi-owner default quorum: **2 when a second admin exists** (takeover-race answer), else 1. Confirm.
2. Editors create collections? Plan: no (own folders/tags yes).
3. Trash default `write_scope_can_trash`: confirm.
4. Viewers and passkeys: autofill yes, export no: confirm.
5. Recovery, ownership transfer, member reset as designed: confirm.
6a. **Identity-rooted Spaces with the layered identity** (keystore/recovery-sealed identity; emergency content-key split): confirm the pivot.
6b. `baluard-personal` default, never forced: decided.
7. Two-tier envelopes: skip v1: decided.
8. No hosted relay: decided.
9. ~~Quorum-signed rewind~~ **Superseded (review round 4):** force-push rewinds are blocked by default branch protection on GitLab (and hardened GitHub orgs). Replaced by the append-only revocation manifest (P8b) — recovery needs no history rewriting. No confirm needed.
