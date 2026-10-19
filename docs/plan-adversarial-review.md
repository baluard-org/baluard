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

Status legend for unit rows: `todo` -> `reviewing` (dispatched, at least one reviewer in) -> `reviewed` (both in) -> `triaged` (verdicts logged) -> `fixed` -> `verified`. Reviewer attribution lives in the finding IDs (`F-<UNIT>-<PRC|PRA>-NN`), not in the status.

## Phase A: trust core

| Unit | Scope | ~LOC | Focus | Status |
|------|-------|------|-------|--------|
| A1 crypto-primitives | crates/baluard-core/src/crypto/{aead,hkdf_derive,hpke_wrap,kdf,signature,totp}.rs | 2.4K | KDF params, nonce and domain separation, zeroize coverage, TOTP window, timing safety | triaged |
| A2 webauthn-ceremony | crates/baluard-core/src/crypto/webauthn/ | 1K | Challenge freshness, CeremonyCache TTL/FIFO/eviction, ES256 verify, counter monotonicity, SEC-1 boundary | triaged |
| A3 key-hierarchy | crates/baluard-core/src/keys/ | 0.9K | HKDF info labels, epoch derivation, SGK vs item key separation, RootKey handling | triaged |
| A4 vault-format | crates/baluard-core/src/vault/{envelope,padding,keywrap,canary,cipher,index,manifest,slug,events,templates,avatar,attachment,identity,registry}.rs | 4.5K | Envelope shape, tier fit metadata leakage, index key derivation, canary verification, atomic staging | todo |
| A5 handle-crud-unlock | crates/baluard-core/src/vault/handle.rs (slice: unlock/lock/CRUD/index hooks) | ~4.5K slice | Unlock tail (keywrap + canaries), already-unlocked short-circuit, index rebuild hooks, zeroize on drop | reviewed |
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
| F-A1-PRA-01 | A1 | S1 | hpke_wrap.rs:105 `recipient_priv.to_bytes()` copy of device privkey lands on stack unzeroized | confirmed | |
| F-A1-PRA-02 | A1 | S1 | aead.rs:104 `build_nonce` shard id = 4 UUID bytes, birthday bound ~2^16 objects; canary counter hardcoded 0 risks nonce reuse | partially confirmed (legacy counter path; current cipher/index/attachment writes use 96-bit OsRng nonces; the live instance is the canary fixed nonce, folded into F-A2-PRC-16) | |
| F-A1-PRA-03 | A1 | S2 | signature.rs uses ZIP-215 `verify`, not `verify_strict`; malleable sigs vs quorum/dedup barriers | confirmed | |
| F-A1-PRA-04 | A1 | S2 | totp.rs `urldecode` casts decoded bytes to chars, corrupts multibyte percent-encoded issuer/label | confirmed | |
| F-A1-PRA-05 | A1 | S3 | `build_aad` omits envelope header version byte; version tamper does not fail auth | confirmed | |
| F-A1-PRA-06 | A1 | S3 | kdf.rs `auto_calibrate` bakes the calibration salt into the returned KdfParams | confirmed | |
| F-A2-PRA-01 | A2 | S1 | store.rs Drop clears shared store on any clone drop, can wipe `take_new_credentials` before caller extracts | confirmed | |
| F-A2-PRA-02 | A2 | S1 | store.rs stores full COSE key (private scalar) into `key_value`; `PasskeyData::zeroize` never clears it | confirmed | |
| F-A2-PRA-03 | A2 | S2 | ceremony.rs generates local challenge instead of accepting an RP challenge (peer assumes external RP server; Phase-1 local-first design may reject) | rejected (Phase-1 local-first design: Baluard IS the relying party; the second reviewer did not flag it either) | |
| F-A2-PRA-04 | A2 | S2 | counter update stores `counter.unwrap_or(0)`, not `max(stored, new)`; assertion extract failure falls back to 0 | confirmed | |
| F-A2-PRA-05 | A2 | S2 | CeremonyCache eviction picks an arbitrary expired entry, and duplicate-id insert evicts an unrelated ceremony | confirmed | |
| F-A3-PRA-01 | A3 | S1 | hierarchy.rs stack temps in `generate`/`from_bytes`/`item_key_expand` hold raw key bytes unzeroized | confirmed | |
| F-A3-PRA-02 | A3 | S1 | `derive_item_key` epoch check is `debug_assert` only: release builds ignore the epoch arg and fail open | confirmed | |
| F-A3-PRA-03 | A3 | S1 | rotation.rs wrap context `keywrap:rotation:{epoch}` lacks vault/device binding; cross-vault transplant passes tag verification | confirmed, low (implicit recipient-key binding limits the transplant; align with the P7 convention anyway) | |
| F-A3-PRA-04 | A3 | S1 | quorum `div_ceil(2)` = bare 50% for even N (epoch.rs + devices.rs); split-brain on N=4 | confirmed (fix: strict majority N/2+1) | |
| F-A3-PRA-05 | A3 | S3 | `derive_avatar_key` returns bare `[u8; 32]`, no zeroizing wrapper | confirmed | |
| F-A2-PRC-01 | A2 | S1 | registration route serializes full passkey_data (private_key) into the response and finish_register trusts the echoed data; key_value carries the private COSE scalar (SEC-1 closure) | confirmed | |
| F-A2-PRC-02 | A2 | S1 | dup of F-A2-PRA-02 (zeroize skips key_value) | confirmed (dup) | |
| F-A2-PRC-03 | A2 | S1 | store/index materialize every vault passkey as plain heap per ceremony; passkey-types Passkey is Clone-only, Drop clear() does not wipe, full-vault conversion not RP-filtered | confirmed | |
| F-A1-PRC-04 | A1 | S1 | derived Debug on TotpParams (secret) and PasskeyData (private_key, prf_key) prints key material under BALUARD_DEBUG | confirmed | |
| F-A1-PRC-05 | A1 | S1 | aes-gcm/aes/argon2 run without their zeroize features; key schedules and Argon2 blocks stay in freed memory | confirmed | |
| F-A2-PRC-06 | A2 | S2 | CeremonyCache::remove returns expired states; TTL not enforced at consumption | confirmed | |
| F-A2-PRC-07 | A2 | S2 | assertion counter persisted only via client echo at finish (crash reuses counters, concurrent asserts emit duplicates, forged u32::MAX bricks credential) | confirmed (known-open SEC-1) | |
| F-A1-PRC-08 | A1 | S2 | aead::decrypt authenticates the on-disk envelope.aad; only 4 call sites recompute expected AAD, so same-key file swap/rollback is unbound for the rest (fold in the F-A1-PRA-05 version byte) | confirmed | |
| F-A3-PRC-09 | A3 | S2 | dup of F-A3-PRA-02 (derive_item_key silent in release) | confirmed (dup) | |
| F-A1-PRC-10 | A1 | S2 | dup of F-A1-PRA-03 (verify vs verify_strict; callers pass untrusted keys: cards, contacts, reveals, rosters) | confirmed (dup) | |
| F-A1-PRC-11 | A1 | S2 | calibration floor protects memory only (tc can reach 1 at 32 MiB) and derive_kek trusts unbounded plaintext KDF params (hostile memory_kib DoS at unlock) | confirmed | |
| F-A1-PRC-12 | A1 | S2 | master password not NFKC-normalized (backup container does); NFC/NFD keyboard variance breaks cross-device unlock | confirmed | |
| F-A1-PRC-13 | A1 | S2 | dup of F-A1-PRA-04 (urldecode Latin-1); adds: secret= not percent-decoded, to_uppercase expansion accepts non-base32 | confirmed (dup) | |
| F-A3-PRC-14 | A3 | S3 | dup of F-A3-PRA-01 + F-A1-PRA-01 (stack/heap temp sweep); adds unwrap_key returning plain Vec and Clone impls | confirmed (dup) | |
| F-A3-PRC-15 | A3 | S3 | mlock not reference-counted; dropping one key may unlock a page other live keys sit on | confirmed as accepted (best-effort by design, no fix) | |
| F-A2-PRC-16 | A2 | S3 | bundle: canary fixed nonce (fold F-A1-PRA-02), quorum div_ceil (dup F-A3-PRA-04), misplaced doc comments in hkdf_derive.rs, rotation wrap context (dup F-A3-PRA-03), PasskeyIndex silently overwrites duplicate credential ids, allow_credentials None picks account by HashMap order, and rp_id substring URI match attaches passkeys to lookalike domains (use UriMatchStrategy instead) | partially confirmed (all real; severity per sub-item, match fix via UriMatchStrategy) | |
| F-A5-PRA-01 | A5 | S1 | unlock skips canary verification when `meta/kek-canary.enc` missing (empty vec -> verify bypassed) | confirmed | |
| F-A5-PRA-02 | A5 | S1 | `UnlockedState::drop` never zeroes `devkey_seal`; `IdentityKeys`/ed25519 SigningKey has no zeroize | confirmed | |
| F-A5-PRA-03 | A5 | S1 | `Cipher` plaintext has no Drop/Zeroize; `zeroize_decrypted_cipher` not wired into CRUD drops | confirmed | |
| F-A5-PRA-04 | A5 | S2 | update_cipher history-preservation `else if` chained at wrong level; wipes history when password unchanged and caller sent empty | confirmed | |
| F-A5-PRA-05 | A5 | S2 | update_cipher overwrites `kind` wholesale; passkeys in `fido2_credentials` destroyed when caller omits them | confirmed | |
| F-A5-PRA-06 | A5 | S2 | delete_folder hardcodes flat `ciphers/{id}.enc` path; collection-resident ciphers keep dangling folder_id | confirmed | |
| F-A5-PRA-07 | A5 | S2 | collect_descendant_ids loops forever on a folder parent cycle (insert result ignored) | confirmed | |
| F-A5-PRA-08 | A5 | S2 | delete_cipher/purge_old_trash remove the envelope but orphan `entries/{id}` attachment dirs | confirmed | |
| F-A5-PRA-09 | A5 | S3 | restore_cipher/purge_old_trash skip the `writes_allowed()` gate every other mutator has | confirmed | |
| F-A5-PRA-10 | A5 | S3 | rename_folder lacks the sibling duplicate-name check create_folder_with_parent enforces | confirmed | |
| F-A5-PRC-01 | A5 | S1 | dup of F-A5-PRA-01 (canary skip); adds: zero-byte file behaves as missing, `change_master_password` has the same `exists()` skip, rotate_recovery_phrase comment states the fail-closed intent | confirmed | |
| F-A5-PRC-02 | A5 | S1 | dup of F-A5-PRA-03 (cipher plaintext zeroize); adds: `zeroize_decrypted_cipher` itself skips Identity/BankAccount/Passport/DriversLicense/URIs/password_history/fido2 key_value, and is called only from rotation paths | confirmed | |
| F-A5-PRC-03 | A5 | S1 | dup of F-A5-PRA-02 (devkey_seal unzeroized); adds: `derive_kek` returns plain `[u8;32]`, unlock_tail locals never wiped, devkey_seal() returns a plain copy | confirmed | |
| F-A5-PRC-04 | A5 | S1 | runtime state.rs:8062 `cipher_to_json` serializes `kind` wholesale: fido2 `private_key`/`prf_key` cross IPC inside get_cipher payload, contradicting the never-crosses-IPC invariant | cross-slice: confirmed (ciphertext-only, not decryptable client-side, but a stated-invariant break; skip_serializing fix at types.rs) | |
| F-A5-PRC-05 | A5 | S2 | lock() spawns normalize_timestamps_bg that resets mtimes of everything under trash/ to vault creation; purge_old_trash(30) judges by mtime, so after one lock+unlock the whole trash purges | confirmed | |
| F-A5-PRC-06 | A5 | S2 | dup of F-A5-PRA-06 (delete_folder flat path); adds trashed ciphers also skipped | confirmed | |
| F-A5-PRC-07 | A5 | S2 | rebuild_tag_index rebuilds from cipher metas only, pruning empty tags made by create_tag; runtime calls it after every update | confirmed | |
| F-A5-PRC-08 | A5 | S2 | index staleness check compares id sets only; a pulled edit to an existing cipher does not invalidate, no rebuild after pull | confirmed | |
| F-A5-PRC-09 | A5 | S2 | dup of F-A5-PRA-08 (purge orphans attachments) | confirmed | |
| F-A5-PRC-10 | A5 | S2 | save_profile_and_strip_settings uses get_settings().unwrap_or_default(); a settings.enc decrypt/parse failure writes defaults back over the real encrypted settings | confirmed | |
| F-A5-PRC-11 | A5 | S2 | dup of F-A5-PRA-09 (writes_allowed gate); adds assign_cipher_to_collection | confirmed | |
| F-A5-PRC-12 | A5 | S2 | clear_failed_attempts failure after state already Unlocked returns Err, leaving the vault unlocked with a reported failure | confirmed | |
| F-A5-PRC-13 | A5 | S2 | list_folders hard-fails on one corrupt per-fact file so save_folders heal never runs; also deletes folders.json contradicting its own reads-never-delete comment | partially confirmed (hard-fail real; the folders.json removal is the intentional legacy-migration cleanup) | |
| F-A5-PRC-14 | A5 | S2 | dup of F-A5-PRA-04 + F-A5-PRA-05 (history contract + wholesale kind replace destroying fido2_credentials) | confirmed | |
| F-A5-PRC-15 | A5 | S2 | save_settings can erase device names: device_display_names() swallows errors to empty map, writes device_names: None | confirmed | |
| F-A5-PRC-16 | A5 | S2 | locked get_settings falls back to plaintext legacy meta/settings.json for policy fields (unauthenticated) when settings.enc exists | confirmed | |
| F-A5-PRC-17 | A5 | S2 | rename_tag/delete_tag abort mid-loop on first failure; earlier ciphers rewritten, index not rebuilt | confirmed | |
| F-A5-PRC-18 | A5 | S3 | bundle: dup of F-A5-PRA-10 (rename_folder dup names); plus dead legacy branch in get_settings/load_profile, derive_item_key/unlocked panic paths, CrossEpoch error-type drift in decrypt_cipher_bytes no-local branch, rebuild_index failure after write lands (caller retry duplicates), trash move and collection move non-atomic two-step | partially confirmed (rename dup + CrossEpoch drift + rebuild-after-write real; panicking derive_item_key/unlocked are the by-design twins of try_/is_unlocked; dead branch and atomic-move refactors deferred) | |

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
