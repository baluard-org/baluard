# ADR 0085. Sharing Spaces, Roles, and Collections

> Status: Accepted (2026-09-28). Complete: every planned phase shipped (P, S1a, S1b, S2 with its UI waves, S3-1 through S3-9, the six sharing screens on desktop and mobile, the Space settings knobs, and S4-1). The organization power pack is recorded in ADR 0087, which also owns the deferred and parked sharing items. Per-slice implementation history lives in ADR 0030 through 0084 and is not repeated here.

## Context

Baluard has no application server. Git remotes store encrypted vault data, while local devices perform cryptography and enforce access. Sharing therefore requires cryptographic read scope, signed write authorization, and provider permissions that work together without relying on a central service.

The scenarios covered are: a whole Space shared with roles (A), item co-ownership (B), owner-controlled sharing (C), organization granularity (D), parity gaps with commercial managers (E), guests (G), a multi-device member (H), a clean split (I), departure with live provider access (J), owner incapacitation or provider loss (K), and member reset when both the device and the recovery phrase are gone (L). Users need whole-Space membership, equal item co-ownership, owner-controlled sharing, and organization-level collection access.

The existing personal vault hierarchy derives keys from a 64-byte RootKey. A shared Space must separate identity, personal content, Space metadata, and collection content so a member does not receive the RootKey or keys for ungranted collections.

The following constraints shaped every decision:

1. There is no server. Everything is local, cryptographic, or signature-based.
2. Git commits are storage, not an audit log. Reads are local operations and leave no shared evidence.
3. Revocation is eventual. A removed member keeps the bytes already received. Per-credential read auditing is impossible by design and must be stated before any pilot.
4. Integrity and availability are separate problems. The design detects, notifies, revokes through an append-only signed manifest, and migrates; provider ACLs fence the transport.
5. Symmetric keys do not separate read from write. Only the transport (a read-only collaborator seat, an outbox) provides that separation.
6. One user has two authorities, cryptographic membership and the provider ACL, and both must move in one flow.
7. File modes do not survive git.
8. Padded buckets leave plaintext limited to opaque identifiers, display names, and trust levels. Padding also multiplies retained history, so rotations and membership churn have a storage cost.
9. The format is pre-1.0 and may break freely.
10. The interface budget is six screens. HPKE, SGK, epochs, and policies never appear in a user surface.
11. Each human holds one credential for life. A second password prompt is forbidden, so key-layer separation must not reintroduce one.
12. A shared OS account is not a security boundary. Existence and names of vaults are shared on such an account.

The trust boundary includes both cryptographic membership and provider ACLs. A signature alone cannot prevent a repository collaborator from reading history, and a provider read-only seat cannot prevent an authorized writer from creating an invalid commit.

The baseline inspected before the work began shaped the prerequisite phase P:

- Seven key derivations took the 64-byte RootKey directly (index, folders, tags, profile, settings, activity, generator history), and the vault identity binding and keyring namespace derived from the KDF salt. A Space without a master password had to re-home all of them.
- Commit signature verification was dead in production (it read a test-only fixture) and silently fell back to unsigned commits.
- A pull aborted on the first bad signature, so one rejected commit wedged the remote for every member.
- Clones were always full; any shallow-clone policy would have governed something that does not exist.
- Daemon token gating was an opt-in allowlist (default allow).
- GitHub classic `repo` scope grants read access to every repository of the account.

## Decision

### Enforcement model

Four authorities enforce four different properties, and none substitutes for another. Read scope is enforced by keys (and by the local index). Write integrity is enforced by the policy table and signatures, and is merge-safe. One-way availability is enforced by read-only collaboration at the transport. Push rights are enforced by provider ACLs, staged by least privilege. Server-side enforcement is rejected because the architecture has no server.

### Identity and trust

Spaces use identity-based membership. Contact cards are identity-signed, the address book is local and encrypted, and identity is a one-time cost per relationship. The card payload carries the identity X25519 wrap public key under domain `baluard-contact-v2`, so the Level 2 code check covers the wrap key too. Trust is graded:

| Level | Mechanism | Recorded as | Used for |
|---|---|---|---|
| 0, passphrase | App-generated passphrase, Argon2id with AES-GCM, parameters and expiry in AAD, no identity involved | none | Guest reveals only |
| 1, trusted channel | A card received over a trusted channel | `trust: channel` | One-shot packages and contact-key reveals, which are inert by rule because they wrap no live keys |
| 2, code-verified | Both apps derive the same code from the identity public key (64 bits) and compare it out of band, or by QR in person | `trust: verified` | Required for roles above Editor at join approval |
| 3, administrator approval | The join link is approved by an administrator and the approval vouches | `trust: admin` or `admin-unverified` | Organization onboarding; it replaces the code check, because organization invites are Level 3 by definition |

Level 1 may carry inert packages and reveals, but it never authorizes live key grants. A bilateral QR is only the in-person rendering of the code check. A provider-based discovery service is sugar, and a key server is rejected.

### Identity key layering and lifecycle

The identity keypair (Ed25519 signing and X25519 wrap, derived from one 32-byte seed) is sealed under a key that is not the master-password KEK: a keystore-held random wrapping key, with an HPKE escrow to the recovery-phrase public key. The reason is that one cracked laptop must not yield every Space of its owner. Disk theft then yields personal ciphers but not the identity, and no second password prompt is needed. The keystore is a hard requirement for identity-bearing vaults, because every minimum platform ships one (Keychain, Windows Credential Manager, Secret Service) and quick unlock already depends on it. The recovery phrase is the backup path, not the daily unlock path.

A keystore-less system (headless Linux, WSL, CI) may seal the identity under a dedicated Argon2id passphrase key with its own salt, and only with a visible downgrade warning that states that the vault password now also protects shared Spaces. The downgrade is never silent and never a hard block.

Emergency escrow wraps a separate personal-content key that covers personal ciphers only. The identity sits under its own key and cannot be reached by an emergency contact. Quick-unlock enablement shows an explicit warning about shared biometric enrollment.

Identity rotation has two paths. Routine rotation is self-service: the old key is held, the identity is rewrapped under the new key in the member's own subtree, and the change is published in the member record so every client sees it and stale contact trust is reset. A contest window was designed for this path because a thief holding an unlocked key can also run it. Compromise rotation was designed as an administrative rewrap that also rotates the Space SGK, with non-admin members waiting for the rewrap. As built, routine rotation with visibility and trust reset shipped; the contest window and a dedicated waiting-for-rewrap state do not exist in source, and compromise response runs through member reset, device replacement, and removal with rotation (see Lifecycle).

### Key model

| Key | Personal vault | Space |
|---|---|---|
| RootKey and content key | The RootKey plus a separate personal-content key (personal ciphers and emergency escrow) | The RootKey stays admin-side. Neither RootKey nor SGK reaches a member device |
| Identity keypair | Keystore and recovery sealed | Not applicable |
| Space Meta Key (SMK) | Not applicable | Random 32 bytes. Admins open it from the RootKey-sealed `meta/space.enc`, members from the identity-bound `meta/members/<member>/space.wrap`. Member-visible metadata derives from `HKDF(SMK)` |
| Item keys | `HKDF(SGK, cipher_id, epoch)` | Admin-surface flat ciphers keep SGK derivation. Collection entries use `HKDF(CK, cipher_id, epoch)` with the same `baluard-item-v1` info |
| Collection key (CK) | Not applicable | Random. Admins unwrap through the SGK-derived wrap, members through a per-member HPKE wrap at `meta/collections/<collection>/<member>.wrap`. Rotation re-keys ciphers under the new epoch while CK values stay invariant, so member wraps survive |

The member-visible metadata split is: index, folders, tags, profile, settings, contacts, and share events ride the SMK-derived meta key (raw RootKey bytes before the flip, `HKDF64(SMK)` after it), and the existing derivation info strings are unchanged so a flipped vault's metadata is byte-compatible across roles. Admin-only metadata (activity, generator history, outbox registries, role templates) stays RootKey-derived. The vault identity binding and keyring namespace remain tied to the KDF salt, with Space-side equivalents for canaries and device lookup. Spaces open from the personal vault, which is the unlock dependency.

The Space re-homes index, folders, tags, profile, settings, contacts, share events, and the avatar to SMK-derived metadata keys. The unlock path for a flipped member is identity seed, then `space.wrap`, then SMK, and admin surfaces refuse through typed errors when the RootKey or SGK is absent.

Personal rotation covers the content key, identity re-encryption, settings, generator history, emergency escrow, avatar, and attachments, with failures propagated. Member removal from a Space rotates the SGK and the affected collection keys and re-wraps for survivors. Collection-key values stay stable across ordinary RootKey or SGK rotations; removing a member who could decrypt a collection requires rotating that collection key (see ADR 0086 and ADR 0087 for the revoke-with-rotation rule).

### Membership layout

Membership is stored per file everywhere, and plaintext is limited to identifiers, display names, and trust levels. Email addresses are never shipped.

- `meta/members/<member_id>.json` holds the identifier, display name, role, trust, and the forge username used for provider seat wiring. Device bindings live at `meta/members/<member>/devices/<device>.json`.
- `meta/collections/<id>.json` holds the grants (`{member, access, expires_at?}`) in plaintext and the collection name encrypted under the CK. Grantees see real names; non-grantees see an opaque identifier. An organization may opt in to a plaintext catalog of collection identifiers (`meta/collections/catalog.json`) so requesters can name what they ask for, and the names stay encrypted.
- `meta/members/<member>/requests/<id>.json` holds just-in-time access asks, sealed to the approver set with one random payload key wrapped per live Owner or Admin row. The seal binds request, requester, and approver, so a pending file copied into another member's subtree is inert.
- Every member must hold an account on the Space's provider. Cross-provider membership is impossible, and the product says so at first run.
- Roles are Owner, Admin, Editor, and Viewer, ranked in that order. Trash move is write scope when `trash_policy` allows it, restore and purge are administrator actions, device lifecycle is self-service for all roles, invitation, removal, and rekey require Admin or higher, and deleting a Space belongs to the Owner.
- A Space is a vault with slug `baluard-space-<name>` and a Space flag in plaintext `meta/settings-pub.json`. The `.baluard` marker remains the only repository identity check, and the personal default repository name is `baluard-personal`, probed and adopted but never forced.

### Write policy

Member authorization is evaluated against an ordered path policy in `sync/policy.rs` with first-match-wins semantics. Segments are literals, `*` (one segment), `**` (the remainder, last segment only), and `{member}` (the signer's member identifier resolved from the device binding snapshot, never the raw device identifier). Unmatched paths are denied. The effective rows are:

| Path pattern | Required signer | Notes |
|---|---|---|
| `meta/members/{member}/minor.enc` | Admin | Sealed minor record, see ADR 0086. Placed first so a member cannot rewrite it through the own-subtree row |
| `meta/members/{member}/**` | Any role | Self-service: devices, pending introduction, requests, routine identity rotation, own `space.wrap` |
| `meta/members/**`, `meta/space.json` | Admin | Role and trust assignment, Space settings |
| `meta/collections/**` | Admin | A parent-tree `manage` grant admits edits to that collection's definition and wraps, with an Editor floor, and a member may rewrite their own wrap file at any role |
| `meta/groups/**` | Admin | A member's own `.gkwrap` is a structural self-service exception (ADR 0087) |
| `meta/rekey/**`, `meta/keywrap/**` | Admin | Rotation artifacts |
| `meta/folders/**`, `meta/tags/**` | Editor | Per-fact files and tombstones |
| `ciphers/**`, `trash/**`, `entries/**` | Editor, plus collection write scope | Attachments follow the parent item |
| `meta/**` and root files | Admin | Canaries, settings, profile, avatar, revocation manifests, integrity state, epoch |

Collection scoping is applied on top of the table. A path `ciphers/<dir>/...` names a collection directory; it is admitted only when the directory maps to a known collection and the signer is Owner, Admin, or holds a write grant, and the role floor still applies, so a Viewer cannot write even with a grant. Unknown directories deny everyone. `trash/<dir>/**` follows the same scope as its ciphers. On a flipped Space, flat ciphers and root trash become Admin-only. Grant authority is read from the parent tree, never from the commit's own tree, so a member cannot self-grant in the commit being verified.

Regular commits are checked by net diff: `diff(first_parent, commit)` must be fully covered by the signer's row, with the signer's role resolved from the first-parent roster snapshot. Merge commits are recomputed from both parents over their merge base. Only the residue, meaning the actual tree minus the recomputed merge, is attributed to the merger. An honest merge has an empty residue, a smuggled tree is exposed, conflicted paths are attributed to the merger outright because a resolution is authored content, and octopus merges are refused. Parent order does not change the residue for non-conflicted content, which closes the parent-order swap smuggling path.

Two structural rules cover paths the table alone cannot judge. Device registry deltas by non-admins must be only the signer's own last-seen epoch bump, so the per-commit bump does not wedge lower roles. Integrity manifest deltas are self-authenticating through checkpoint signatures verified against roster keys, and the checkpoint sequence floor is unconditional so a device handoff cannot launder a higher sequence. Member record deltas by non-admins may change only identity fields, and a self-delta on a tombstoned row is refused.

Roster verification walks commits topologically and resolves roles from each commit's first-parent tree, with genesis transition and pre-enrollment grandfathering. Tombstone enforcement is sticky within a walk: a pull seeds the set from local-head ancestry, so a stale clone's rogue commit is refused even though its own ancestry predates the removal, and a tombstoned signer is denied outright, including through an empty-residue merge. A signing failure on an enrolled shared vault is a hard error with no unsigned fallback, and unsigned commits on shared Spaces are never accepted. Clone and pull verify the full fetched history and refuse before untrusted content is accepted. A vault without a member directory is a legacy vault and stays admin-equivalent, and a strict vault treats an unbound device as a pending joiner.

HPKE wraps bind context in AAD `baluard-keywrap/<context>` and info `baluard-hpke-wrap-v2`, with a per-call-site context string. Device wraps use `keywrap:<vault_id>:<device_id>`. Readers reject a wrap whose binding does not match its file, which defeats transplant and rollback.

Recovery from a rejected commit uses an append-only signed `meta/revocations.json` manifest and never a force-push. Entries carry canonical payloads and Ed25519 signatures under domain `baluard-revoke/v1`. A pull walks history on a tracker miss and verifies that parent entries survive unchanged (stripping, field rewrites, and file deletion all fail closed) and that each new entry was signed by a roster device at the snapshot where it was introduced, so de-enrolled former signers can never wedge pulls. Restoration covers only the paths whose revoked content HEAD still carries, is traversal-guarded, and is written with owner-only permissions through a path-scoped signed commit that never sweeps unrelated worktree changes. The gitignored `meta/revocations-verified.json` tracker records the verified manifest blob and applied commits, which makes steady-state pulls one file read. The manifest works under protected default branches, where force-push rewinds are blocked. The earlier idea of a quorum-signed rewind is superseded for that reason. The surfaces are `baluard sync revoke <commit> --reason` and the daemon route `sync.revoke`.

Rollback detection uses signed head gossip on a dedicated side branch `baluard-gossip`. Each device publishes `heads/<device>.json`, signed over a payload bound to the vault's root commit, and the announcement commit carries the announced head as a second parent so the announced history stays reachable even after the main branch is rewound. Every pull and clone checks that every verified announced head is contained in the fetched history and refuses with a rollback error otherwise. Gossip is a deny-only channel: unparseable or unverifiable announcements are inert, which keeps a removed device's stale files or a junk file from wedging survivors, and a forged announcement has no enforcement power. It detects rollback only for members who observed the discarded head, and an attacker with full push access can rewrite the gossip branch too.

### Provider coupling

Provider permissions follow membership state. Pending joiners and Viewers hold read-only seats; write access begins when a member becomes active with an Editor-or-higher role. The join flow is: a read-only seat is granted at invitation, the joiner clones, introduces themselves at their own pending path with a one-time code proof, an administrator approves, and the seat is upgraded to match the approved role. Seat operations are best effort and reported; neither invitation nor approval fails because the transport did.

Provider mechanics differ. GitHub uses collaborator PUT (`pull` or `push`), where 201 means a pending invitation and 204 means an updated seat; a seven-day expired invitation reports as no seat, and a notices check re-invites with the member's approved permission. GitLab resolves the username to a numeric user identifier first and uses Reporter (20) for read-only and Developer (30) for write, with an immediate grant. Codeberg and Forgejo grant immediately, and acceptance is a no-op. GitLab and Codeberg never auto re-add on a missing seat, because their grants are immediate and a missing seat may be a deliberate out-of-band removal. All removals are idempotent so retries cannot wedge offboarding.

Removal confirms provider seat revocation before the rotation commit is pushed, with an explicit offline override that is never pre-ticked. Seat status checks fail closed: a server or authentication error is never read as no seat, invitation scans paginate, and a malformed permission body is an error. The strike runs without the vault write lock, and the same precheck function (authorization, batch validation, seat collection) gates both the route and the core operation, so seat operations cannot run for an unauthorized caller. Provider HTTP clients carry connect and request timeouts. The permission endpoint reports effective access including organization and team roles while deletion removes direct seats only, so a lingering active seat after the strike is the signal to remove the organization seat by hand.

GitHub classic `repo` scope can read all account repositories and is unsuitable for organization use. Personal and family flows may use classic OAuth with a documented blast radius, while organization Spaces require a fine-grained token scoped to `baluard-*` repositories or a GitHub App. Organization readiness requires repository ownership, organization approval of the third-party application, and honest scope. The readiness review recorded GitHub as ready, GitLab with a five-seat free-tier caveat, and Codeberg as suitable for personal use only (see `docs/dev/git-provider-apps-and-tokens.md` and ADR 0088).

### Sharing surfaces

The model supports whole-Space roles, pair Spaces, one-shot packages, field-scoped reveals, and recipient-specific live outboxes. Two further item-sharing variants (numbered IS-1 and IS-2 in the planning record, whose descriptions were not preserved) were rejected, and inline item keys (IS-4) were cut and may be revisited only if users ask by name.

- Pair Space. Owner and Admin invitations are refused and a second joiner is refused once two bound live members exist. Viewer is the read-only variant. The cap skips removed and reset tombstones and unbound rows, so a reset never self-blocks. Ownership transfer demotes the old owner to Editor, and settings writers merge-preserve the Space flag. In Family shape this is also the silent answer to sharing one entry with a spouse but not the children. Adding or moving an entry into a Space the other person already belongs to needs no new ceremony.
- One-shot package. The sender identity key signs `recipient_wrap_pub || sent_at || item bytes`, because the card self-signature is copyable and HPKE Base mode authenticates neither party. The envelope carries key material only, with item, sender card, and timestamp inside the seal. Import mints a fresh entry under the recipient's keys and strips attachments, password history, folder, archived flag, and creation date. Payload cap is 2 MB with a 4 MB envelope to fit the daemon frame limit. A package cannot be un-shared, and the send screen says so.
- Reveal. Contact-key flavor (Level 1) binds recipient, expiry, creation time, label, and fields in the identity signature. Passphrase-guest flavor (Level 0) uses Argon2id over an app-generated seven-word passphrase of about 98 bits, delivered by voice or another channel, and requires the Baluard app without a vault. Expiry is plaintext in the envelope but bound in AAD and compared with the sealed copy. Untrusted guest KDF parameters are clamped (128 MiB memory, 6 iterations, 4 lanes) so a hostile file cannot abort the daemon. The default fields are URL, username, and password, TOTP is opt-in with a permanence warning, and a TOTP seed never crosses IPC because open returns only the current code. Opening is view-only.
- Outbox. One standalone repository per recipient carries a plaintext marker (outbox identifier, owner vault identifier, owner signed card), a keywrap file (HPKE wrap of a fresh content key, signed over recipient key, outbox identifier, and a hash of the wrap parts), and sealed entries under AAD `outbox-entry-v1/<outbox_id>/<cipher_id>`. The entry signature binds outbox identifier, entry identifier, timestamp, and item bytes and must equal the marker owner's identity. The mirror is live: a digest over a canonical document (no clock) drives re-publication after each edit, trashed or purged sources unpublish, and passkey material is stripped. The recipient link pins owner identity and outbox identifier at link time. Revocation is unpublish, rotate, and remove the provider seat. The transport is read-only on GitHub and GitLab; on Codeberg the recipient can only pollute the repository and the interface flags it. Recipient retention is stated at share time.
- Merged item list. The host route `vaults.list_full_all` merges every registered vault and is gated by the session token of the active vault; sibling, bridge, and empty tokens are refused, and the route is absent from the extension allowlist, so the extension holds no export primitive (ADR 0024). Locked and closed vaults contribute metadata only.

### Organization granularity

The ladder runs: role templates, collections with delegated `manage`, just-in-time access requests, expiry that rotates, groups as a key layer (ADR 0087), an access review report (ADR 0087), and dual control (ADR 0087). Pending expirations surface to every member so holidays do not extend contractor access. Two-tier envelopes are skipped in v1. Per-item ACLs are rejected as a primary mechanism and kept only as a deferred exception. Break-glass counters are rejected as a control because they are theater, and a loud event is the only reasonable product.

Collection access is `Read`, `Write`, or `manage`, with optional expiry. A Viewer cannot write even when granted Write, and viewer-plus-write or viewer-plus-manage grants are unmintable at the grant and template roots. Delegated managers hold Editor rank or higher, may grant, revoke, and rename only the collection they manage, cannot create or delete collections, and cannot modify the grant lists that delegate their authority. A crafted `manage` ask can never mint delegated authority: it is refused at submission, decryption, and approval.

A role template is a sealed store whose snapshot is embedded in the invitation at mint time, so the invitation is the contract. Approval applies the embedded grants best effort, in the fail-toward-less-access direction, with expiry computed at approval.

Expiry executes on the administrator's client after a pull or on demand: expired grants drop and their collection keys rotate in one save. A rotation must carry through entries, trash, and attachments, re-mint ckwraps of surviving group grants, and write a gitignored `meta/.sweep-pending.json` marker before the definition changes so a crash converges at the next unlock (ADR 0078). Commit verification is clock-free by design, so expired grants converge on pull; this is the accepted eventual-revocation boundary.

Folders and tags use per-fact files. Folder paths are `meta/folders/<uuid>.enc` and tag paths use a SHA-256 name prefix under `meta/tags/` with the tag name inside the encrypted record, which leaves no traversal surface. Writes skip when unchanged, orphans are pruned, and reads never delete. `meta/index.enc` is local, gitignored, rebuilt from disk, sharded at 2,048 entries per shard in sorted order with shard-bound AAD, and stale shards are pruned. Readers fail closed on truncation or torn data. A single padded envelope would hit the 2 MB tier ceiling at roughly 8,000 to 13,000 entries, which is why the index is sharded. Cipher paths are `ciphers/<salted-hash-of-collection-id>/<uuid>.enc`, where the salt is minted at creation so the git host sees only opaque grouping and counts, and personal flat ciphers keep `ciphers/<uuid>.enc`. Hardware AES is enabled on aarch64 through `.cargo/config.toml` (runtime-checked, soft fallback); x86_64 autodetects. Software AES is roughly 25 to 40 MB/s class on a mid-range phone.

### Space settings

| Setting | Type | Default |
|---|---|---|
| `shape` | `family` or `team`, one-way ratchet | Family; team is reached through the flip, never a creation setting |
| `quorum_admin_ops` | 1 to 5 | 1 (decided 2026-09-27: one admin acts alone, the admin may raise it) |
| `collection_create_authority` | `admins` or `editors` | `admins` |
| `allow_viewer_export` | bool | false: read-only members cannot export anything |
| `trash_policy` | `write_scope_can_trash` or `admins_only` | `write_scope_can_trash`; restore and purge stay with admins |
| `restore_policy` | `admins_only` | `admins_only` |
| `invite_authority` | `owners` or `admins` | `admins` |
| `join_approval` | `manual` or `code` | `manual`; in `code` mode the invite code approves and all gates still run |
| `guest_enabled` | bool | false: guest reveals are opt-in. The original plan default of true was reversed on 2026-10-03. Consumers test `== Some(true)` |
| `grant_expiry` | rotation-backed, member-visible pending | on |
| `vault_timeout` | inherited from the personal vault | the personal timeout is the effective global ceiling |

First run asks no taxonomy question: a password and a recovery phrase, nothing else. Shape is chosen only at Space creation, in one line, and the vocabulary is "your vault" and "shared spaces" for users.

### Lifecycle and operations

- Member reset (scenario L): an administrator tombstones the row and mints a fresh successor bound to a reset invitation (same display name and role, trust back at Channel for re-verification). Enforcement is sticky within a walk. The successor row inherits an Owner role when an Owner was reset.
- Batch removal (scenario J): pre-flight refuses empty, duplicate, owner, self, unknown, and already tombstoned targets. It tombstones each row with a terminal `removed` marker, strikes device seats, deletes keywraps and activity entries, and rotates the RootKey once for the whole batch. The offboarding checklist also names the step that actually protects the company: rotate the exposed credentials themselves, because the departing member knows the passwords. The access review exposure list in ADR 0087 supports that step.
- Ownership transfer is a first-class action that promotes the successor before demoting the old owner, so an interrupted transfer leaves two Owners (recoverable) and never zero. The gate keys on the actor's disk-backed Owner role. Owner invitations are unmintable except as successor-bound reset invitations.
- Offline member across a rekey: pull, unwrap the new Space key, re-encrypt unpushed commits, push, and keep old commits in a local audit reference. An evicted member fails closed.
- Repository growth is rotation-driven, not edit-driven: every departure or guest expiry rewrites a collection. Migration frequency follows churn, and size warnings come early.
- Owner incapacitation or provider loss: an administrator runs `space.migrate`, which pushes full history to the new remote first, then commits and pushes the plaintext `meta/remote.json` pointer to the old remote, then repoints origin. Every peer reads the pointer from verified committed HEAD and follows automatically within the same forge host, which also gates credential callbacks to that host. Cross-host moves are an explicit `vaults repoint`. Ordering, not cleanup, ensures a follower only repoints to a remote that already holds the history.
- Lost device: personal-vault revocation, Spaces untouched. Unlocked theft: personal rekey plus the member's replacement flow (ADR 0086).
- Parked items: `space.export`, `space.sever`, the out-of-band adopt link, and a cold mirror are recorded in ADR 0087.

### Rotation and crash safety

Rotation re-encrypts affected ciphers and attachments, updates wraps, and propagates every failure. Collection-key values remain stable across ordinary RootKey or SGK rotations. RootKey rotation stages HPKE wraps for every enrolled device; a survivor adopts its epoch-bound wrap from `meta/rekey/<epoch>.txn` only when the transaction filename, the declared epoch, and the canary epoch agree, and adoption runs before the cross-device heal so the survivor keeps its own identity. Rotation markers remain armed until all staged files are committed. A crash between the keywrap commit and the metadata re-saves leaves the marker and a warned mixed-epoch state. Concurrent rotations by two administrators converge by epoch comparison, and the losing administrator re-runs the removal; automatic loser re-application was not built and the quorum knob narrows the window.

### IPC and locking

Daemon IPC is default-deny. Only explicitly enumerated pre-token host actions are exempt, and an exact-set test pins the exempt set (15 entries in source at the time of writing). Sentinel-forwarded actions must be a subset of the exempt set, which catches a gated action routed through a tokenless sentinel. Host-only actions are rejected by a tripwire before the token gate. Host routes such as `vaults.*` and the bridge ceremony stay pre-token by design because a per-vault token cannot exist before unlock.

`VaultState::lock` is host-private. Locking bumps a session generation first, every token mint site stamps the mint generation, and verification rejects a mismatched generation, so a stale token dies even if a future lock path forgets to clear it. The host lock is acquired before per-vault locks and released before cascading locks. Lock never awaits the sync cycle lock, because that lock is held across a network call whose timeout does not cancel the blocking task.

The design preserves AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroization of key material, local file mode 0600, and token-gated IPC. The mlock budget includes identity and collection keys. No shared OS account is a security boundary.

### Acceptance invariants

The prerequisite phase was accepted only when these held: two humans with two passwords share one Space; personal rotation preserves identity and wraps; offline disk theft cannot reach the identity; removal leaves survivors able to unlock; a legitimate commit verifies and a foreign one is rejected on a production-shaped vault; an unsigned commit is refused at creation on shared Spaces; every lock call site cascades through the host; net diff equals intent; the index is gitignored, untracked, incremental, and sharded past the tier ceiling; every action sits in exactly one token list; and pending and viewer seats are read-only at the provider. Property tests cover wrap and unwrap with context binding (transplant and rollback rejected), role by path by signer against the table, merge-residue attribution, expiry rotation, and identity rotation.

### Rejected alternatives

| Alternative | Reason |
|---|---|
| Hosted relay or server-side enforcement | The architecture has no server |
| Quorum-signed history rewind | Force-push is blocked by default branch protection on GitLab and hardened GitHub orgs; replaced by the append-only revocation manifest |
| Identity sealed under the plain master-password KEK | One cracked laptop would yield every Space |
| Silent keystore downgrade | The downgrade must be explicit and warned |
| Key server | Contact cards and the trust dial replace it |
| Two-tier envelopes | Skipped in v1 |
| Per-item ACLs as the primary mechanism | Groups first; kept only as a deferred exception |
| Break-glass counters as a control | Theater; a loud event is enough |
| Cover commits off in shared Spaces | Superseded: a deterministic `meta/devices.json` with skip-if-unchanged made cover commits effective no-ops |
| Shallow-clone policy | Clones are always full |

## Consequences

Members can decrypt only their personal data and explicitly granted collection content. Policy verification prevents unauthorized writes from being accepted during pull or clone.

Revocation cannot erase bytes already copied by a former member. History grows with churn and key rotations. Collection names, grant lists, member identities, commit timing, and some metadata remain visible to repository collaborators. Organization owners also see per-member push timing at the provider.

The provider must support a user account and repository seat for every member. GitHub classic `repo` scope can read all account repositories and is unsuitable for organization use; organization deployments require a narrowly scoped GitHub App or fine-grained token.

The identity key is a higher-value secret than personal cipher content. A disk image alone should not disclose it, but an attacker who obtains the master password and defeats the OS keystore can reach the account's shared Spaces. The downgrade warning makes the headless-system tradeoff visible. A locked-device theft is an offline password attack against personal ciphers only, and an unlocked theft requires a personal rekey and the member replacement flow.

File modes do not survive Git. Repository access, signatures, encrypted payloads, and policy verification provide the shared boundary; local files and key stores still require restrictive permissions.

One OS account shared by several people does not provide member isolation. Pre-token host routes can disclose vault existence and names. The product must state this constraint wherever shared-machine use is discussed.

Members can retain all bytes they received before removal. Append-only revocation prevents future acceptance of listed commits but cannot erase copies or guarantee that every clone has observed a newer head. Editors can damage shared content; the defenses are detection, notification, the revocation manifest, migration, and provider ACLs.

Reads cannot be audited. A pilot or organization policy must not promise per-entry access histories, an erasure promise, or the absence of copies, and the derived Activity timeline must not imply that it records credential views. The administrator guide states all three.

The identity contest window for routine rotation and a dedicated waiting-for-rewrap state were designed but are not in source. Commit verification is clock-free, so grant expiry depends on the administrator device clock and converges on pull. Forged fully-stripped parallel histories remain a trust-on-first-use limit at first clone, narrowed by head-anchored verification at pull time and full-history re-verification after enrollment.

The design intentionally has no hosted relay, backend authorization service, or file-mode-based remote control. Availability depends on members synchronizing through their Git provider.

## References

- ADR 0086 (`docs/adr/0086-family-spaces.md`) and ADR 0087 (`docs/adr/0087-power-pack.md`).
- Per-slice history: ADR 0030 through 0061 (item sharing, Spaces, collections, member surfaces, settings), ADR 0062 through 0077 (power pack and its hardening), ADR 0078 (`docs/adr/0078-the-hardening-wave.md`), and ADR 0081 (`docs/adr/0081-the-proof-rides-the-commit.md`).
- ADR 0011 (`docs/adr/0011-zero-knowledge-rbac-b2b-family-sharing.md`), ADR 0003 (`docs/adr/0003-key-hierarchy-device-bootstrapping.md`), ADR 0024 (`docs/adr/0024-browser-extension-paired-companion-bridge.md`), ADR 0088 (`docs/adr/0088-git-providers-multi-vault.md`).
- `docs/security/threat-model.md`, `docs/security/emergency-org-identity.md`, `docs/dev/software-architecture.md`.
- `crates/baluard-core/src/sync/policy.rs`, `crates/baluard-core/src/sync/gossip.rs`, `crates/baluard-core/src/vault/space_meta.rs`, `crates/baluard-core/src/vault/collections.rs`, `crates/baluard-runtime/src/host.rs`, `crates/baluard-daemon/src/handler.rs`.
