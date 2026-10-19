# Adversarial Review Map

> Whole-repo adversarial review program: unit map, dispatch contract, status tracker, findings log.
> Status: ACTIVE. Sweep not started. The repo is ~185K LOC across 6 Rust crates, desktop, browser, and mobile, so the review is chunked into 36 units across 4 phases.

## Method

Two independent external peer reviewers (PRC and PRA) review every unit, read-only. The name-to-slot mapping lives in the dispatch commands, never in tracked docs or commits (no-naming rule). Both reviews for a unit land before any triage, so neither reviewer anchors the other.

The orchestrator (this agent) triages every finding zero-trust against the code, applies confirmed fixes, runs the test suite, and updates this doc. Reviewers never edit code.

Pacing is checkpoint-per-phase: after a phase closes, the orchestrator reports (units covered, findings by severity, fixes landed, rejections) and waits for a go/no-go before the next phase. Phase order: A (trust core) -> B (sync + IPC) -> C (client surfaces) -> D (cross-cutting).

## Ground rules

Severity scale:

| Sev | Meaning |
|-----|---------|
| S1 | Security: breaks a load-bearing crypto/trust invariant (AES-256-GCM, Argon2id, X25519/Ed25519, HPKE, zeroize-on-drop, 0600 socket, token gating, fail-closed verification) |
| S2 | Correctness: bug, data loss, broken flow, wrong state transition |
| S3 | Code health: cruft, dead code, duplication, over-engineering |
| S4 | UX/parity: i18n gap, plain-language violation, parity regression per the UX axis (ongoing ease of use for non-technical users) |

Verdicts on triage: `confirmed` (fix now), `rejected` (why, one line), `dup` (points at the finding it duplicates), `deferred` (real but out of phase scope; logged for close-out).

Evidence rule: a finding without file:line evidence is noise and is discarded without logging. Reviewers must quote the offending code. Confidence level (high/medium/low) is required per finding.

Non-goals: pre-1.0 format/flag/route compatibility concerns are NOT findings (see STATUS in AGENTS.md). Closed design records (plan-sharing, plan-power-pack, and the D-records) are not re-litigated unless a unit surfaces a live invariant break. Style nits below the code-comment budget are not findings.

## Dispatch contract

Every reviewer dispatch carries, self-contained:

1. Unit scope: exact file paths (and slice anchors for megafile units).
2. Invariants: the CODING STANDARDS security block from AGENTS.md plus the GOTCHAS entries touching the unit's files.
3. Context pointers: threat-model.md and software-architecture.md sections relevant to the unit.
4. The review axes (full spectrum: security, correctness, code health, UX/parity) and the severity scale above.
5. Output format: numbered findings, each with severity, file:line evidence, quoted code, impact sketch, and a suggested fix direction. A unit with no findings returns an explicit "no findings" statement, not silence.
6. Read-only constraint and the no-naming rule for anything that might land in the repo.

## Per-unit workflow

1. Dispatch both reviewers on the unit (parallel, independent).
2. Collect both finding lists; deduplicate; assign IDs `F-<UNIT>-NN`.
3. Triage each finding against the code (zero-trust: reviewer claims are untrusted until verified). Log verdicts in the findings log.
4. Fix confirmed findings, test-first where the fix is behavioral; run `just check` (or the unit's tightest gate) and the relevant e2e surface.
5. Update the unit row and the findings log in the same commit as the fix. Rejections and dups log at phase checkpoint.
6. A unit is `verified` only when its fixes are committed with green tests AND both reviewer slots are done.

Status legend for unit rows: `todo` -> `prc` -> `pra` (both reviewers in) -> `triage` (verdicts logged) -> `fixed` -> `verified`.

## Phase A: trust core

| Unit | Scope | ~LOC | Focus | Status |
|------|-------|------|-------|--------|
| A1 crypto-primitives | crates/baluard-core/src/crypto/{aead,hkdf_derive,hpke_wrap,kdf,signature,totp}.rs | 2.4K | KDF params, nonce and domain separation, zeroize coverage, TOTP window, timing safety | todo |
| A2 webauthn-ceremony | crates/baluard-core/src/crypto/webauthn/ | 1K | Challenge freshness, CeremonyCache TTL/FIFO/eviction, ES256 verify, counter monotonicity, SEC-1 boundary | todo |
| A3 key-hierarchy | crates/baluard-core/src/keys/ | 0.9K | HKDF info labels, epoch derivation, SGK vs item key separation, RootKey handling | todo |
| A4 vault-format | crates/baluard-core/src/vault/{envelope,padding,keywrap,canary,cipher,index,manifest,slug,events,templates,avatar,attachment,identity,registry}.rs | 4.5K | Envelope shape, tier fit metadata leakage, index key derivation, canary verification, atomic staging | todo |
| A5 handle-crud-unlock | crates/baluard-core/src/vault/handle.rs (slice: unlock/lock/CRUD/index hooks) | ~4.5K slice | Unlock tail (keywrap + canaries), already-unlocked short-circuit, index rebuild hooks, zeroize on drop | todo |
| A6a handle-rotation-rekey | crates/baluard-core/src/vault/handle.rs (slice: rotate_identity, rotate_recovery_phrase, rotate_root_key, revoke_device_and_rekey, force_evict_and_rotate, epoch helpers, adopt_rekey_txn_root) | ~2.2K slice | Rekey coverage of every artifact class, crash markers, HPKE wraps for all devices, survivor adoption ordering, fail-closed txn adoption | todo |
| A6b handle-space-wiring | crates/baluard-core/src/vault/handle.rs (slice: quorum/kit/approval gate fns, member ops, policies, contacts/reveals/package wrappers, collection_rotate_key) | ~1.6K slice | Gate logic before delegation, kit enable-over binding, minor-record path, wrapper-to-module contract drift | todo |
| A7 device-fleet | crates/baluard-core/src/{device_manager,devices,device_privkey,emergency,recovery,recovery_sheet,secret_file,health,integrity}.rs | ~5K | Revoke-and-rekey preconditions, BIP-39 recovery, escrow rebuild, integrity walk | todo |
| A8 space-engine | crates/baluard-core/src/vault/{space,space_meta,family,groups}.rs | 3.5K | Wrap chains (gkwrap/ckwrap), purpose union classification, flip invariants, pair gate | todo |
| A9 space-governance | crates/baluard-core/src/vault/{members,approvals,policies,access_requests}.rs | 4.5K | Signed quorum asks, fixed kit thresholds, minor record protection, leave journey rotations, contest window | todo |
| A10 space-resources | crates/baluard-core/src/vault/{collections,outbox,reveals,contacts,packages}.rs | 5.3K | Revoke-with-rotation, grant sweep convergence, reveal expiry model, guest opt-in policy check | todo |
| A11 vault-creation | crates/baluard-core/src/vault/{creation,recovery_kit}.rs | 1.9K | Builder chain atomicity, kit escrow issuance, phrase returned exactly once | todo |

Megafile slices (A5, A6a, A6b, B1, B2, B5, B6, B8): dispatch defines anchors by symbol names from the live source at dispatch time; the slice boundaries recorded here are thematic, not line ranges. If a slice overshoots ~7K lines at dispatch, split it and renumber as -a/-b in this table. handle.rs (18.5K lines) is split three ways per the anchors above.

## Phase B: sync + IPC

| Unit | Scope | ~LOC | Focus | Status |
|------|-------|------|-------|--------|
| B1 engine-cycle | crates/baluard-core/src/sync/engine.rs (slice: commit/pull/push cycle, force-checkout, signature verification walk, roster resolution) | ~5K slice | C1 force-checkout, H2 cycle order, P5 staged path sets, P2/P8a verification and merge-residue rule | todo |
| B2 engine-walks | crates/baluard-core/src/sync/engine.rs (slice: conflict verdict paths, timeline, enrollment/kit proof fallbacks) | ~5K slice | Merging-not-Idle on conflict, HEAD-guarded finalize, cross-epoch fail-closed, D78 proof fallback, per-clone identity | todo |
| B3 sync-support | crates/baluard-core/src/sync/{conflict,commit,state_machine,timeline,gossip,policy,revocation,known_hosts,tls,credentials}.rs | 3.6K | 3-way merge semantics, H1 network classification, TLS/known_hosts handling, revocation propagation | todo |
| B4 providers | crates/baluard-core/src/providers/ | 4.4K | OAuth device/web flows, PKCE, rolling refresh serialization, token storage, sentinel client_ids, secret leakage into providers.json or logs | todo |
| B5 state-session | crates/baluard-runtime/src/state.rs (slice: unlock/lock/activate, autofill_query, reprompt, biometric) | ~4.7K slice | Password-oracle gotcha surface, autofill wire format (no password keys), reprompt rate-limit coupling | todo |
| B6 state-conflict-zeroize | crates/baluard-runtime/src/state.rs (slice: conflict merge, pin wiring, zeroize paths) | ~4.8K slice | keep_both cloning, zeroize match coverage, PIN escrow boundaries, superseded-handle locking | todo |
| B7 runtime-rest | crates/baluard-runtime/src/{host,autosync,bridge,pin,rate_limit,providers,founding,crypto}.rs | 4K | Multi-vault active-pointer invariant, debounce/FOCUS_PULL gaps, bridge pairing ceremony, 5-strike nuke, constant-time compares | todo |
| B8 daemon | crates/baluard-daemon/src/handler.rs (slices) + {main,socket_path,lib}.rs | 7.7K | Token-gating coverage per route, D2 forbidden keys, socket perms, cover-mutation hooks, route dispatch exhaustiveness | todo |
| B9 bridges | crates/baluard-nmh/src/main.rs + crates/baluard-uniffi/src/lib.rs | 4K | NMH stdin trust boundary, allowlist scope, UniFFI surface parity with daemon routes, secret FFI crossings | todo |
| B10 cli | crates/baluard-cli/src/{main,commands/mod,client}.rs + build.rs | 7.2K | Dual-mode dispatch parity, destructive arms (detach --delete-from-disk), flag handling, direct-mode drift | todo |
| B11 import-export | crates/baluard-core/src/import/ | 4.3K | Hostile parser input hardening, .bldbak container invariants (passphrase-only KEK, endianness mix), export redaction | todo |

## Phase C: client surfaces

| Unit | Scope | ~LOC | Focus | Status |
|------|-------|------|-------|--------|
| C1 desktop-bridge | desktop/src-tauri/src/ + desktop/src/lib/{daemon,payload,cipherSchema,utils,helpers,filters,slug,vaultTimeout,clipboard,biometry,disableAutofill,heldPhrase,transition,transitionGuard,useCopyFeedback,vaultPrefetch,providerConnect,providers,cloneFlow,conflictFlow}.js | ~5K | spawn_blocking rule, in_path/out_path absence, clipboard auto-clear, held-phrase lifetime, payload shape drift | todo |
| C2 desktop-shell | desktop/src/App.jsx + context/ + components/{LoginScreen,SetupScreen,RecoveryScreen,CreateVaultScreen,VaultSwitcher,SwitchUnlockModal,RepromptModal,TypedConfirmModal,DetachVaultModal,ConfirmModal,FocusTrap}.jsx | 3.5K | Auth state machine transitions, token cache clearing on focus loss, focus trap coverage, detach safety | todo |
| C3 desktop-vault-ui | components/{CipherDetail,AddEditCipherForm,CipherRow,CipherAvatar,GeneratorModal,SshKeyGenerator,FolderTree,CardBrandDisplay,CopyButton,CopyableField,ArchiveConfirmModal,DeleteConfirmModal,ToastContainer,ThemeToggleFloating,ConsolePanel,Icon,Primitives}.jsx | 4K | Reprompt gating, password history UX, generator entropy source, XSS/escaping in rendered fields, console panel leak surface | todo |
| C4 desktop-sharing-ui | components/{PeopleTab,SpaceTab,CollectionsTab,GroupsTab,OutboxesTab,ContactsTab,ShareDialog,OpenSharedModal,AskAccessModal,RemovalBanner}.jsx | 4K | Role-action gating vs daemon enforcement (UI is advisory), removed-device notice, approval flows, plain-language rule in sharing copy | todo |
| C5 desktop-settings-sync-ui | components/{SettingsModal,SyncTab,DeviceFleetPanel,BridgeTab,BridgeUnlockBanner,GitExplainerModal,RecoveryPhraseCard,CloneFromProviderScreen,AutoSyncIndicator,ConflictBanner,ConflictResolutionPanel}.jsx | 4.5K | Conflict queue lifecycle on lock/switch, sync status honesty, recovery phrase display-once, provider warnings | todo |
| C6 browser | browser/shared/src/{background,content,inline,offscreen,autofill,settings,url}.js + popup.jsx + manifests | 6K | Origin classification (own-pages rule), sender trust, inline suggestion injection, offscreen lifecycle, settings storage, pairing allowlist | todo |
| C7 mobile-core | mobile/shared/src/commonMain/{data,auth,vault,sync,totp}/ + ui/App.kt + ui/components/ | 4K | MultiVaultSession state, stub-vs-real vault boundaries, TOTP parse, conflict models, search haystack | todo |
| C8 mobile-screens | mobile/shared/src/commonMain/{detail,edit,generator,settings,onboarding}/ | 3.5K | Payload assembly parity with daemon schema, reprompt enforcement, i18n coverage, back-press handling | todo |
| C9 android-platform | mobile/shared/src/androidMain/ + mobile/androidApp/src/ | 8K | AutofillSession mutex lifecycle, save token single-use, U+ dispatch, OOM invariant (no Argon2id in :autofill), a11y main-thread rule, trust isolation | todo |
| C10 ios-platform | mobile/shared/src/iosMain/ | 1.5K | expect/actual completeness vs Android actuals, secure storage equivalents, parked-feature stub honesty | todo |

## Phase D: cross-cutting

| Unit | Scope | ~LOC | Focus | Status |
|------|-------|------|-------|--------|
| D1 security-docs-vs-code | docs/{threat-model,post-quantum-readiness,forward-secrecy-model,2fa-analysis}.md checked against the code they describe | docs | Claims that no longer hold, mitigations without code, code paths without threat-model entries | todo |
| D2 test-audit | crates/baluard-cli/tests/, desktop/src/\_\_tests\_\_/, browser/shared/tests/, mobile tests, proptest usage | tests | Failure-mode coverage vs happy-path bias, implementation-coupled assertions, test-only production hooks, e2e surface gaps | todo |
| D3 i18n-copy | desktop/src/i18n/locales/{en,es,pt}.json + mobile Strings{En,Es,Pt}.kt + user-facing copy sweep | strings | Key parity (enforced by tests), plain-language rule (no "collection", no "space", no git/crypto terms), FocusTrap and aria coverage on new modals | todo |
| D4 parity-claims | docs/feature-parity.md + docs/progress.md claims spot-checked against source | docs | Matrix rows that drifted, closed-gap ledger accuracy, progress claims without landing commits | todo |

## Findings log

Format: `| ID | Unit | Sev | Finding (one line) | Verdict | Fix commit / note |`. One section per phase, append rows as triage lands.

### Phase A findings

| ID | Unit | Sev | Finding | Verdict | Fix commit / note |
|----|------|-----|---------|---------|-------------------|

### Phase B findings

| ID | Unit | Sev | Finding | Verdict | Fix commit / note |
|----|------|-----|---------|---------|-------------------|

### Phase C findings

| ID | Unit | Sev | Finding | Verdict | Fix commit / note |
|----|------|-----|---------|---------|-------------------|

### Phase D findings

| ID | Unit | Sev | Finding | Verdict | Fix commit / note |
|----|------|-----|---------|---------|-------------------|

## Phase checkpoint report template

At each phase close, the orchestrator reports:

1. Units: done / verified counts, any unit deferred with cause.
2. Findings: totals by severity, confirmed vs rejected vs dup vs deferred.
3. Fixes: commit list with finding IDs, test gates run.
4. Rejections: one-line why each.
5. Go/no-go request for the next phase.

## Program close-out

After Phase D: sweep the findings log for `deferred` rows, resolve or convert them to issues, then mark this doc COMPLETED with the final tallies (like the closed plan records). The doc then becomes the audit trail for the 1.0 release claim.
