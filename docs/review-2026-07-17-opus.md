# Baluard Senior Codebase Review (2026-07-17, Claude Opus)

> Three isolated deep-dive reviews by Claude Opus (read mode, high thinking), each scoped to one layer with the load-bearing invariants suppressed so the reviewer could not rubber-stamp them as intentional. Findings preserved verbatim per layer; cross-cutting synthesis and a sequenced action plan at the top.
>
> Reviewer bias guard: each pass ran in a clean session (`isolated: true`) with explicit file paths, so Opus formed its own view rather than inheriting the session's self-assessment.
>
> Layers:
> - **A. Cryptography** (`crates/baluard-core/src/crypto/`, `keys/`)
> - **B. Data-integrity, Concurrency & IPC** (`vault/`, `sync/`, `device_manager.rs`, `baluard-daemon/src/`)
> - **C. Frontend** (`desktop/`, `browser/`)

---

## 0. Synthesis

**Overall: mature for a pre-1.0 codebase.** The trust boundary is clean (secrets stay daemon-side, session tokens held in zeroized Rust memory rather than web storage, TOTP seeds and passkey private keys never cross IPC). The concurrency primitives (`VaultHost` single-lock discipline, PIN escrow critical section, autosync generation counters, `cycle_lock`) are correct and unusually well-commented with the *why*. The crypto posture (AAD binding, epoch-bound item-key derivation, constant-time compares everywhere, `zeroize`+`mlock`) is solid. The AAD construction is textbook.

### The theme: silent loss instead of loud failure

The highest-severity cluster cuts across all three layers. It is the same disease repeated four times: data that disappears or derives wrong with no error surfaced.

| # | Sev | Layer | Finding | Location |
|---|-----|-------|---------|----------|
| 1 | 🔴 HIGH | B | Conflict merge silently discards remote edits for 7 of 8 cipher kinds | `sync/conflict.rs:141-146` |
| 2 | 🔴 HIGH | B | Cross-epoch ciphers silently disappear from the index | `vault/handle.rs:1365-1368` + `keys/hierarchy.rs:215-221` |
| 3 | 🔴 HIGH | B | `rotate_root_key` is not crash-safe (no guard, marker never read) | `vault/handle.rs:2410-2588` |
| 4 | 🔴 HIGH | C | Biometric unlock ignores `switchTarget`, unlocks the wrong vault | `desktop/src/components/LoginScreen.jsx:129-142` |

### Medium tier (batch-able)

- 64-bit random nonce on index/meta path contradicts the project's own C1 fix (`vault/index.rs:47-54`, `vault/handle.rs:562-568`).
- HPKE is a homegrown ECIES, not RFC 9180 (`crypto/hpke_wrap.rs:22-74`).
- Attachment download is fully broken and leaks raw errors (`CipherDetail.jsx:483-495`).
- Custom-field merge is 2-way, not 3-way (`sync/conflict.rs:166-171`).
- `rotate_root_key` never zeroizes decrypted plaintext during re-encryption (`vault/handle.rs:2440-2467`).
- Sync state machine persisted with a non-atomic write (`sync/state_machine.rs:80-86`).
- `en.json` / `es.json` i18n drift (~16-key gap).

### Suggested sequencing

1. **Finding C-8 (biometric + switchTarget)** — one-line fix mirroring the PIN path. Highest-stakes flow, adjacent to recent LoginScreen work. Fast win.
2. **Finding B-3 (conflict merge for non-Login kinds)** — biggest data-loss surface, fires during ordinary concurrent multi-device editing.
3. **Crash-safety cluster** — B-7/B-1 (rotate_root_key guard + marker reconciliation on open) and B-6 (sync-state-machine atomic write) as a batch.
4. **Crypto nonce** — A-1 (index/meta path), trivial because `build_random_nonce()` already exists.
5. **Homegrown HPKE** (A-2) — real debt but lower urgency given the quorum-signature backstop. Adopting the `hpke` crate retires A-2, A-3, A-4 together.

---

## Layer A — Cryptography

### Scope

`crates/baluard-core/src/crypto/{aead,kdf,hkdf_derive,hpke_wrap,signature,totp}.rs`, `crypto/webauthn/{mod,store,ceremony}.rs`, `keys/{epoch,hierarchy,nonce,rotation}.rs`.

### Load-bearing invariants given to the reviewer (intentional, not to be flagged)

AES-256-GCM only (strict AAD). Argon2id KDF. X25519/Ed25519 device keys. HPKE key wrapping. Zeroize-on-drop for key material, TOTP secrets, passkey private keys. mlock on RootKey/ItemKey. TOTP seed never crosses IPC. Passkey private key never crosses IPC. 256-bit session token, constant-time compare, token-gated IPC over 0600 socket. Passkeys via passkey-rs 0.5.x, ES256 only, embedded in `LoginData::fido2_credentials`.

### Findings

1. **[Medium]** Security / DRY — Meta and index writes use a 64-bit random nonce, contradicting the project's own C1 fix
   - `crates/baluard-core/src/vault/index.rs:47-54`, `crates/baluard-core/src/vault/handle.rs:562-568`
   - Both generate an 8-byte random `nonce_counter` and pass it to `build_nonce(counter, Uuid::nil())`. The shard tail is `Uuid::nil().as_bytes()[..4]` = all zeros, so the effective nonce is only **64 random bits** under a fixed key (`derive_index_key`/meta key is deterministic per epoch). The index is re-encrypted on every CRUD/tag mutation; birthday collision hits 2^-32 at ~90k writes, reachable over a vault's lifetime. AES-GCM nonce reuse leaks plaintext XOR and enables GHASH auth-key recovery → index forgery. The cipher path already switched to 96-bit `build_random_nonce()` for exactly this reason (`aead.rs:71-82`); meta was left behind.
   - Fix: replace both call sites with `aead::build_random_nonce()` (96-bit OsRng) and drop the ad-hoc `thread_rng` counter. Deletes code and closes the gap.

2. **[Medium]** Security — HPKE is a homegrown ECIES, not RFC 9180
   - `crates/baluard-core/src/crypto/hpke_wrap.rs:22-74`
   - The comment admits it ("Simplified HPKE seal... For production, use a full HPKE library"). It deviates from DHKEM: the HKDF `kem_context` binds only the ephemeral public key as salt (`hkdf::new(Some(eph_public), shared)`), not the recipient public key, and the AES-GCM nonce is the raw first 12 bytes of the DH shared secret rather than an HKDF-derived nonce. It works and per-wrap uniqueness holds (fresh ephemeral each call), but CLAUDE.md declares HPKE load-bearing and this is not HPKE.
   - Fix: adopt the `hpke` crate (RFC 9180, X25519-HKDF-SHA256 + AES-256-GCM) or document explicitly that this is a custom ECIES construction and freeze its test vectors.

3. **[Low]** Security — No X25519 low-order / contributory check on unwrap
   - `crates/baluard-core/src/crypto/hpke_wrap.rs:95` (and `:34`)
   - `diffie_hellman` result is used without `shared.was_contributory()`. A crafted low-order `ephemeral_public` in a `WrappedKeyEntry` yields an all-zero shared secret → attacker-computable `wrap_key` + zero nonce, letting them forge an entry that unwraps to a chosen RootKey. Currently gated by the quorum Ed25519 signature over `compute_txn_hash` (`device_manager.rs:1792-1806` covers `ephemeral_public`/`encrypted_key`/`tag`), so it is defense-in-depth, not an open hole.
   - Fix: reject `!shared.was_contributory()` in both `wrap_key` and `unwrap_key`.

4. **[Low]** Security — Static keywrap AAD, no epoch/device/vault binding
   - `crates/baluard-core/src/crypto/hpke_wrap.rs:60`, `:124`
   - AAD is the constant `b"baluard-keywrap"`. The wrap is bound to the recipient only implicitly via ECDH, and epoch is not bound at all. A `WrappedKeyEntry` could be structurally relocated across transactions/epochs without the AEAD noticing (again caught today only by the quorum signature). The cipher AAD (`aead.rs:build_aad`) does this correctly with full context binding; keywrap should match.
   - Fix: bind `device_id || old_epoch || new_epoch || vault_id` into the keywrap AAD.

5. **[Low]** Perf/Security — `SpaceGroupKey::derive_item_key` re-derives via HKDF and mlocks a fresh heap alloc on every cipher op
   - `crates/baluard-core/src/keys/hierarchy.rs:237-253`
   - Every encrypt/decrypt derives the item key from scratch (HKDF-SHA256 + `Box` + `mlock` syscall + later `munlock`+zeroize on drop). For `list_full` over a large vault this is N HKDF passes plus 2N mlock/munlock syscalls. Correct and safe, but the per-item mlock churn is measurable at scale.
   - Fix: acceptable as-is for security; if profiling shows cost, batch-derive under one mlock'd arena. Not urgent.

6. **[Nit]** DRY — `derive_*_key` from RootKey is copy-pasted 7 times
   - `crates/baluard-core/src/crypto/hkdf_derive.rs:41-122`
   - `derive_sequence/index/folders/tags/profile/settings/activity/generator_history_key` are byte-identical except the `INFO` constant, yet they don't route through the existing private `derive_key` helper (which is hardcoded to a `[u8;32]` KEK).
   - Fix: generalize `derive_key` to take `ikm: &[u8]` and have all root-key derivations call it. Removes ~60 lines.

7. **[Nit]** Docs — `derive_sequence_key` comment is wrong
   - `crates/baluard-core/src/crypto/hkdf_derive.rs:42-44`
   - Comment says "use first 32 bytes as HKDF input" but the code passes the full 64-byte root key (`Hkdf::new(None, root_key)`). Harmless (HKDF takes any-length IKM) but misleading.
   - Fix: correct the comment to "full 64-byte root key as IKM."

8. **[Nit]** KISS — `decode_base32` never masks the `bits` accumulator
   - `crates/baluard-core/src/crypto/totp.rs:169-186`
   - `bits = (bits << 5) | val` accumulates indefinitely; stale high bits are silently dropped by the `u64` shift. Output is correct (only low `bit_count+8` bits are read) but the unbounded shift is a code smell.
   - Fix: `bits &= (1 << bit_count) - 1` after each push, or switch to the `data-encoding` crate's RFC4648 base32.

9. **[Good]** Security — AAD construction is textbook
   - `crates/baluard-core/src/crypto/aead.rs:21-54`
   - Length-prefixed, domain-separated (`baluard-aad-v2`), binds vault/object/tier/alg/epoch/seq. This is exactly right and defeats cut-and-paste and rollback at the cipher layer.

10. **[Good]** Security — Key material lifecycle is disciplined
    - `crates/baluard-core/src/keys/hierarchy.rs:41-135`, `crypto/totp.rs:12`
    - Heap-boxed for stable mlock address, `Zeroize` (volatile) on drop, munlock before free, Debug redaction, `Clone` re-mlocks. `try_derive_item_key` failing closed on foreign epoch (`hierarchy.rs:230-235`) instead of panicking on the conflict-merge path is a genuinely thoughtful fix.

### Senior Evaluation (Crypto)

This layer is more mature than most pre-1.0 crypto: the AAD binding, HKDF domain separation, epoch-bound item-key derivation, and zeroize+mlock hygiene are all done properly, and the fail-closed `try_derive_item_key` shows the team learned from a real incident. The single most important thing to fix is Finding 1: the 64-bit random nonce on the index/meta path directly contradicts the C1 fix you already applied to ciphers, and the index is your highest-write-frequency object, so it is the one place where GCM nonce reuse is realistically reachable. The fix is trivial because `build_random_nonce()` already exists. The HPKE homegrown construction (Finding 2) is the other real debt: it is currently safe because quorum Ed25519 signatures authenticate the wrapped entries, but "our custom ECIES is fine because a signature covers it" is not what CLAUDE.md's HPKE invariant promises, and swapping in the `hpke` crate removes Findings 2, 3, and 4 at once. Everything else is polish.

---

## Layer B — Data-integrity, Concurrency & IPC

### Scope

`crates/baluard-core/src/vault/{handle,creation,envelope,padding,registry,manifest,keywrap}.rs`, `sync/{engine,conflict,state_machine,commit}.rs`, `device_manager.rs`, `crates/baluard-daemon/src/{host,handler,state,autosync,pin,bridge,rate_limit}.rs`.

### Load-bearing invariants given to the reviewer (intentional, not to be flagged)

VaultHost single `RwLock<VaultHostInner>` over map + active pointer; active-implies-in-map; switch = pointer flip; per-vault session tokens; snapshot-once-per-request (no TOCTOU); `vaults.close` = Arc-drain. Sync cycle order = commit → pull → push; pull MUST force-checkout; network errors classified via `git2::Error::class()`. Token-gated IPC over 0600 socket, constant-time compare. Session PIN: in-memory KEK escrow, 5-strike nuke, never on disk, survives soft-lock, dies on restart/close. Bridge token: `TokenKind::Bridge{pairing_id}`, allowlist-enforced, field-gated `vault.update`. Zeroize-on-drop; mlock on RootKey/SGK.

### Findings

1. **[HIGH] [Security/Concurrency]** `rotate_root_key` is not crash-safe: no guard, non-atomic multi-file commit, marker never read
   - `crates/baluard-core/src/vault/handle.rs:2410-2588`
   - Unlike `revoke_device_and_rekey` (arms `RotationGuard` at 2693, disarms at 2932), `rotate_root_key` writes `.rotation-pending` (2411) by hand and commits with a per-file rename loop (2519-2525). A crash mid-loop leaves some ciphers at new epoch, some at old, canary/keywrap untouched. The marker is written and deleted but **never read on `open`** (2411/2582 are the only sites; `open` at 187-196 does no reconciliation), so there is no roll-forward/rollback. The "enables recovery" comment at 2517 describes machinery that does not exist.
   - Fix: arm a `RotationGuard` in `rotate_root_key` exactly as the revoke path does, and add a marker check in `VaultHandle::open` that finishes or reverts a pending rotation before serving reads.

2. **[HIGH] [Data-integrity]** Cross-epoch ciphers silently disappear from the index instead of failing loudly
   - `crates/baluard-core/src/vault/handle.rs:1365-1368` + `1475,1533-1537,1463` → `keys/hierarchy.rs:215-221`
   - The normal read path (`get_cipher`, `try_decrypt_cipher_with_root_key`, `derive_item_key_from_sgk`) calls `SpaceGroupKey::derive_item_key`, which `debug_assert_eq!`s the epoch then ignores it (`derive_item_key_unchecked` always uses `self.epoch`). Only the conflict path was migrated to the checked `try_derive_item_key`. For any envelope at a foreign epoch (the half-rotated state of #1, or a pulled remote cipher at a higher epoch), debug builds panic the daemon; release builds derive the wrong key → AEAD fails → and the index rebuild `Err(_) => continue`s (1367), dropping the entry from `vault.list` with no error surfaced.
   - Fix: route `get_cipher`/`try_decrypt_cipher_with_root_key` through `try_derive_item_key`, map `None` to a `cross_epoch` error, and stop swallowing decrypt errors silently in the index rebuild (log + count them).

3. **[HIGH] [Data-integrity]** Conflict merge silently discards remote edits for 7 of 8 cipher kinds
   - `crates/baluard-core/src/sync/conflict.rs:141-146`
   - When base/local/remote are the same non-Login type, the merge arm is a no-op comment: "keep local as-is." So if two devices edit the same Card (local changes the name, remote changes the number), the number change is thrown away and the local tree is what gets committed and pushed, reverting the other device. Only `Login` gets real field-level 3-way merge. For a password manager whose entire value proposition is multi-device sync, silently losing a remote edit is the worst-case failure.
   - Fix: run `merge_3way_field` per field for every `CipherKind`, or at minimum flag `remote != base` as a conflict so the user is asked instead of losing data.

4. **[MEDIUM] [Data-integrity]** Custom-field merge is 2-way, not 3-way — remote edits and deletions are lost
   - `crates/baluard-core/src/sync/conflict.rs:166-171`
   - "Union by name, prefer local on collision" ignores `base`. A remote-edited custom field value loses to the stale local value; a remote-*deleted* field silently reappears from local. Both diverge from remote intent with no conflict raised.
   - Fix: 3-way merge per custom field keyed by name, using `base` to decide who changed.

5. **[MEDIUM] [Security]** `rotate_root_key` never zeroizes decrypted plaintext during re-encryption
   - `crates/baluard-core/src/vault/handle.rs:2440-2467`
   - The revoke path zeroizes decrypted passwords/notes/TOTP/SSH/card material after re-encrypt (2789-2833). `rotate_root_key` decrypts every cipher into `existing`, clones fields into `input`, re-encrypts, and lets both drop with no zeroize — every secret in the vault lingers in freed heap after a routine (non-revocation) rotation.
   - Fix: add the same post-encrypt zeroize block the revoke path uses.

6. **[MEDIUM] [Concurrency]** Sync state machine is persisted with a non-atomic write
   - `crates/baluard-core/src/sync/state_machine.rs:80-86`
   - `save_to_file` uses `std::fs::write` (truncate-in-place), while `engine.rs` correctly uses tmp+rename for the device-epoch file. A crash mid-write yields a torn `sync-state.json`; `load_from_file` (69-77) falls back to `Idle`, so a paused `Merging` state is lost and the next `commit_all`/`add_all` can stage a still-conflicted git index (the `recover_state` gap in #10).
   - Fix: write tmp+rename, mirroring `bump_device_epoch`.

7. **[LOW] [Concurrency]** `recover_state` forces `Idle` out of `Merging` without cleaning the git conflict state
   - `crates/baluard-core/src/sync/engine.rs:99-117` + `state_machine.rs:119-127`
   - On restart after a paused conflict, the machine is forced to `Idle` but nothing runs `repo.cleanup_state()` or resets the conflicted index; the next `add_all` stages conflict markers. The `NeedsDecision` doc comment even acknowledges "may trip on the dirty/conflicted index" but the recovery path doesn't address it.
   - Fix: when forcing out of `Merging`, open the repo and `cleanup_state()` + hard-reset the index to HEAD.

8. **[LOW] [Security]** Bridge tokens can drive unbounded writes; only `vault.get` is rate-capped
   - `crates/baluard-daemon/src/handler.rs:1590` (only `vault.get` calls `charge_read`) + allowlist in `crates/baluard-core/src/bridge/token.rs`
   - `vault.add`, `generator.history_add`, and the destructive `generator.history_clear` are in the bridge allowlist but are not counted against the per-pairing read window. A compromised extension can spam cipher creation (commit churn) or wipe generator history at line speed.
   - Fix: extend the rate cap to bridge-permitted mutations, at least the destructive ones.

9. **[LOW] [Security]** `unlock_with_kek` skips the KEK canary when the canary file is absent
   - `crates/baluard-core/src/vault/handle.rs:265-269`
   - The KEK-canary verification is gated on file existence, so an attacker with write access who deletes `kek-canary.enc` weakens the "still verifies keywrap + canaries" contract the PIN path relies on (the RK canary still fails a wrong root key, so impact is bounded).
   - Fix: on a non-legacy vault, treat a missing `kek-canary.enc` as corruption and fail closed.

10. **[LOW] [Data-integrity]** `finalize_conflicts` semantic-group backfill mislabels the "local" side in the UI
    - `crates/baluard-core/src/sync/conflict.rs:182-183`
    - Non-conflicting group members are backfilled with `get_field_value(&merged, field)` for the local value, but `merged` may already hold the remote value for a field merged in at 116. The resolution panel then shows the remote value under "local." Cosmetic but misleading during a security-sensitive decision.
    - Fix: read the pre-merge `local` input, not `merged`.

11. **[Nit] [DRY]** Slug-resolution ladder and desktop-token check are copy-pasted across host routes
    - `crates/baluard-daemon/src/handler.rs:1351-1531` (5× desktop-token block), `1861-2163` (4× slug ladder)
    - The `active_slug → get → verify_session_token` block appears 5×; the `req.slug → payload slug → active` ladder 4× (and `vault.open`'s copy already drifted with an extra registry fallback). Each duplicate is a place a future edit can drop the check.
    - Fix: extract `require_desktop_token(host, &req)` and `resolve_slug(&req, host)` helpers.

12. **[Nit] [KISS]** Dead network-error arm on a purely-local operation
    - `crates/baluard-daemon/src/autosync.rs:536-540`
    - `run_pull_only` matches `is_network_error` on `engine.open_repo()`, but `open_repo` only does a local `Repository::open` and never yields `SyncError::Network`. Misleads the reader into thinking there's a network guard there.
    - Fix: drop the arm.

### Things done well (Good)

- **`VaultHost` (`host.rs`)** — the single `RwLock<VaultHostInner>` holding map + active pointer genuinely makes the "active never dangles" invariant provable; `close` clears `active` in the same critical section (246-253). The lock is *never* nested: every method snapshots arcs, `drop`s the host guard, then awaits per-vault locks (210, 264-267, 328-335, 480-493). `snapshot_target` (125-138) resolves once — no TOCTOU re-lookup after the token check.
- **PIN escrow (`pin.rs` + `state.rs:2523-2591`)** — verify + counter-increment + nuke run under one hold of the escrow mutex (2532-2551); the slow `unlock_with_kek` runs *after* release; `pin_failures` is reset on enable/disable/success (2497/2506/2561); all fields zeroize on drop. The 5-strike cap cannot be outrun by concurrency.
- **Constant-time everywhere** — session token (`crypto::constant_time_eq`), bridge token (accumulate-no-short-circuit `ct_eq`, length-checked before hex-decode, `bridge.rs:272-295`), bridge secret (338), PIN (103). No `==` on any secret.
- **Sync engine invariants hold** — force-checkout on both ff and merge paths, cycle order commit→pull→push, `classify_remote_err` wrapping both push and fetch, keep_both new-UUID, all three verdict paths rebuild the index, `finalize_conflicts` HEAD-guarded, `note_resolved` still called when the merge landed but push failed.
- **autosync generation-guarding + `cycle_lock`** — stale spawned tasks bail on generation mismatch; the inner mutex is never held across `spawn_blocking`; only the `cycle_lock` is (intentional). `deactivate` clears `pending_conflicts` so state and queue can't desync.
- **Path-traversal closed** — attachment ids are validated against stored metadata before the join and get a fresh UUID on write; cipher/folder/tag ids are typed `Uuid` (parse-validated) before any `format!`. AAD identity binding blocks cipher swap/rename.

### Senior Evaluation (Data/IPC)

This layer is **mature and unusually self-aware** — the concurrency primitives (host lock discipline, PIN critical section, autosync generation counters, cycle_lock) are correct and thoroughly commented with the *why*, and the security posture (constant-time compares, token gating, zeroize-on-drop, path validation) is solid. No token-gating bypass, no TOCTOU on the host map, no lock-across-await, no path traversal.

The weak spot is **epoch/multi-device data integrity**, and it clusters into one theme: silent loss instead of loud failure. The single most important fix is **finding #3 (conflict merge discards remote edits for 7 of 8 cipher kinds)** — it fires during ordinary concurrent multi-device editing, which is the product's core promise, and it destroys user data without a prompt. Findings #1 and #2 are the same disease in the rotation path: a non-atomic multi-file commit with no crash-recovery-on-open, and a read path that panics (debug) or silently drops entries (release) on the resulting mixed-epoch state. Fix the merge first (highest frequency), then close the rotation crash window (highest blast radius).

What's genuinely impressive: the invariants you called load-bearing are all actually upheld in code, and the hard concurrency edges (Arc-drain close, resolve-during-focus-flicker, PIN nuke race) were clearly reasoned through rather than hand-waved.

---

## Layer C — Frontend

### Scope

`desktop/src/{context,lib,components,App.jsx}`, `browser/shared/`, `desktop/src-tauri/src/lib.rs`.

### Load-bearing invariants given to the reviewer (intentional, not to be flagged)

All secrets daemon-side; frontend receives only derived TOTP codes (never seeds), decrypted cipher data on demand, formatted SSH keys (never private bytes). `crypto.getRandomValues` only RNG. Token-gated IPC, 256-bit token in frontend cache. Browser extension paired-companion model: scoped bridge token, action allowlist, field-gated `vault.update`, top-frame-only content script, popup-driven fill (no auto-fill on load), per-pairing rate cap. i18n via `t()` keys, en/es in sync. All modals use FocusTrap.

### Findings

#### Security

1. **[Medium]** Security — Attachment download feature is broken AND the error path leaks raw messages
   - `desktop/src/components/CipherDetail.jsx:483-495`
   - ```js
     const result = await daemon("vault.attach_download", ...);
     const b64 = result.data_base64;   // result is a JSON *string*, not an object
     ```
   - `daemon()` returns `res.payload` (a string — see `daemon.js:36`). Every other caller does `JSON.parse(await daemon(...))`; this one doesn't, so `result.data_base64` is `undefined`, `atob(undefined)` throws, and the user always sees "download failed". The catch then `alert()`s `e.message` (raw internal error).
   - Fix: `const result = JSON.parse(await daemon(...));` and route the failure through `toastError(sanitizeError(e, t))` instead of `alert`.

2. **[Low]** Security — Content-script origin check fails open when `expectedOrigin` is empty
   - `browser/shared/src/content.js:21`
   - ```js
     if (msg.expectedOrigin && currentHost !== msg.expectedOrigin) { return; }
     ```
   - If `hostnameOf(tabUrl())` returned `""` (URL parse failure in the popup), the guard is skipped and the credential fills unconditionally. A security check should fail closed.
   - Fix: refuse when `expectedOrigin` is missing: `if (!msg.expectedOrigin || currentHost !== msg.expectedOrigin) return;`.

3. **[Low]** Security — Fill message is broadcast to all frames
   - `browser/shared/src/popup.jsx:308`
   - ```js
     chrome.tabs.sendMessage(tabId, { type: "baluard-fill", credential: {...} });
     ```
   - No `{ frameId: 0 }` option, so the password-bearing message is delivered to every frame in the tab. Only frame 0 has a listener today (injection is `frameIds:[0]`), and web pages can't register `chrome.runtime` listeners, so it's not currently exploitable — but this is the exact spot to keep tight.
   - Fix: `chrome.tabs.sendMessage(tabId, msg, { frameId: 0 })` as defense in depth.

4. **[Low]** Security — One shared `revealPass` signal unmasks every sensitive field at once
   - `desktop/src/components/CipherDetail.jsx:45,295,311-313,323,340`
   - A single `revealPass()` drives the password, CVV, SSN, passport/license numbers, bank PIN, and SSH private key. Toggling "show" on the password shoulder-surfs all of them simultaneously. Custom fields correctly use per-field `revealCustom` (line 431); the built-in fields should too.
   - Fix: per-field reveal signals (or a keyed set), matching the custom-field pattern.

5. **[Low]** Security — Reprompt may be pure UI theater
   - `desktop/src/components/RepromptModal.jsx:27-30`
   - Reprompt "verifies" by calling `vault.unlock` then invoking the callback client-side. If the daemon already ships reprompt-flagged ciphers' secrets in `vault.list_full`, the plaintext is already in JS memory before the modal ever renders, so the gate protects nothing. This needs a daemon-side check: reprompt ciphers must have secrets withheld from `list_full` and only released after re-auth. Flagging for verification — can't confirm from the frontend alone.
   - Fix: verify whether `list_full` withholds reprompt cipher secrets; if not, implement daemon-side withholding + release-on-reauth.

6. **[Low]** Security — Modulo bias in the password/passphrase generator
   - `desktop/src/lib/utils.js:43,54,60,83`
   - `arr[i] % pool.length` over a 32-bit value biases toward low indices when `pool.length` isn't a power of two (pools here are 3344 and ~70). The bias is small but this is a password manager's core RNG; rejection sampling is the correct primitive.
   - Fix: reject-and-resample values in the non-uniform tail before taking the modulus.

7. **[Good]** Security — Token handling, RNG, and extension model are sound
   - Session tokens live in Rust memory as `zeroize::Zeroizing<String>` keyed per slug (`lib.rs:393`), never in `localStorage`. `crypto.getRandomValues` is the only RNG in production JS (Math.random appears only in dev mocks). Extension: top-frame-only injection, fill-time origin re-check, NMH version-skew hard gate (`background.js:149`), clipboard auto-clear (desktop 30s, extension 20s via alarms), no secrets in `chrome.storage`. `spawn_blocking` correctly wraps the blocking socket I/O (`lib.rs:216`).

#### State management / correctness

8. **[Medium]** Reactivity — Biometric unlock ignores `switchTarget`, unlocks the wrong vault
   - `desktop/src/components/LoginScreen.jsx:129-142`
   - ```js
     await daemon("vault.open");            // no slug
     await daemon("vault.biometric_unlock"); // no slug -> active vault
     auth.setStatus("unlocked");
     ```
   - The PIN path directly below (lines 175-181) correctly passes `auth.switchTarget()`. The biometric path doesn't, so when a user selects a non-active locked vault whose biometric button is shown, it opens/unlocks the *active* vault instead of the selected one.
   - Fix: mirror the PIN path — `const target = auth.switchTarget(); await daemon("vault.open","",target); await daemon("vault.biometric_unlock","",target);`

9. **[Medium]** Reactivity — Repeat fill on the same page silently no-ops
   - `browser/shared/src/content.js:10-29`
   - The injection guard (`__baluardFillInjected`) returns early on the second injection, but the message listener was already `removeListener`'d after the first fill (line 15). Second "Fill" click on the same tab → no listener → nothing happens, no error.
   - Fix: don't remove the listener (keep it idempotent), or re-register on each injection independent of the guard.

10. **[Low]** Reactivity — Biometric unlock skips `vaultInfo` and prefetch
    - `desktop/src/components/LoginScreen.jsx:137`
    - The password path sets `vaultInfo` and calls `startVaultPrefetch()` (`AuthContext.jsx:112-114`); the biometric path jumps straight to `setStatus("unlocked")`. Result: `vaultInfo` is stale/null after biometric unlock and the first `vault.list_full` isn't prefetched. Route biometric unlock through the same `unlock()` tail.
    - Fix: reuse `auth.unlock(t)` for the biometric path, or replicate its tail (`setVaultInfo`, `startVaultPrefetch`).

11. **[Low]** Reactivity — Direct `setStatus` bypasses the transition guard
    - `LoginScreen.jsx:137,183`, `App.jsx:44`
    - `auth.setStatus("unlocked")` skips `guardedSetStatus`, defeating the dev-only invalid-transition warning the codebase built. Expose a guarded setter or reuse `unlock()`.

#### Performance

12. **[Low]** Perf — Duplicate focus/visibilitychange listeners trigger redundant polls
    - `AutoSyncContext.jsx:130-131` and `VaultSwitcherContext.jsx:48-49`
    - Both providers attach `focus` + `visibilitychange` handlers. Every window focus fires `nudge_pull` + `autosync_status` refresh *and* a `vaults.list` refresh — 3 daemon round-trips per focus event, which fires often (alt-tab, dialogs). Consolidate the focus handling in one place.

13. **[Low]** Perf — `updateCipher` makes 3 IPC calls per edit
    - `desktop/src/context/VaultContext.jsx:142-145`
    - `vault.update` → `refreshCiphers` (full `list_full`) → `vault.get`. The `list_full` already returns the updated cipher; read it from the refreshed `ciphers()` instead of the extra `vault.get`.

#### DRY / KISS / i18n

14. **[Medium]** i18n — en.json and es.json have drifted
    - `desktop/src/i18n/locales/en.json` (574 key lines) vs `es.json` (558). ~16-key gap violates the "both files must stay in sync" invariant; Spanish users hit English fallbacks. Add a CI parity check (the `flatten()` helper already exists — assert key-set equality in a test).

15. **[Low]** KISS — `alert()` used in two places, against the toast convention
    - `CipherDetail.jsx:495`, `DeviceFleetPanel.jsx:35`. CLAUDE.md mandates toasts for all user feedback. Replace both with `toastError(sanitizeError(e, t))`.

16. **[Low]** YAGNI — Dev-only mock conflict code ships in the production bundle
    - `ConflictResolutionContext.jsx:128-152` (`mockSampleConflict`/`mockSampleTypeChange`) and `conflictDevTriggers.jsx` are exported/imported unconditionally (`App.jsx:19,112`). Gate behind `import.meta.env.DEV` so they tree-shake out of release builds.

17. **[Nit]** KISS — Dead ref assignment
    - `CipherDetail.jsx:252` — `ref={(el) => { let dialogRef = el; }}` assigns to a local that's immediately discarded. Delete it (the FocusTrap uses `getElementById` anyway).

### Senior Evaluation (Frontend)

**Maturity:** High for a pre-1.0 codebase. The trust boundary is respected — secrets stay daemon-side, tokens live in zeroized Rust memory rather than web storage, the RNG discipline is correct, and the extension's paired-companion model (top-frame injection, fill-time origin recheck, version-skew gate, no secrets in `chrome.storage`) is genuinely well thought through. The comment density explaining *why* each guard exists is excellent and rare. This is not a rubber stamp: the frontend is in good shape.

**Single most important fix:** #8 — biometric unlock ignoring `switchTarget`. It's a silent correctness bug in the auth path (the highest-stakes flow), it diverges from the PIN path that got it right, and in a multi-vault setup it can unlock a vault the user didn't select. #1 (broken attachment download) is a close second because it's a fully dead feature.

**Done well:** token storage model, `spawn_blocking` on socket I/O, clipboard auto-clear on both surfaces, `crypto.getRandomValues` everywhere, FocusTrap on all modals, the careful vault-switch race handling in AutoSyncContext (capture-slug-before-await, re-check-after), and the fail-closed NMH version gate. The recurring weakness is the biometric-unlock path being a second-class citizen relative to the password/PIN paths (#8, #10, #11) and minor convention drift (alert vs toast, i18n parity).

---

## Appendix: full finding index

| # | Sev | Category | Layer | Title | Location |
|---|-----|----------|-------|-------|----------|
| A-1 | Medium | Security/DRY | Crypto | 64-bit nonce on index/meta vs C1 fix | `vault/index.rs:47-54`, `vault/handle.rs:562-568` |
| A-2 | Medium | Security | Crypto | HPKE is homegrown ECIES, not RFC 9180 | `crypto/hpke_wrap.rs:22-74` |
| A-3 | Low | Security | Crypto | No X25519 contributory check on unwrap | `crypto/hpke_wrap.rs:95,34` |
| A-4 | Low | Security | Crypto | Static keywrap AAD, no epoch/device binding | `crypto/hpke_wrap.rs:60,124` |
| A-5 | Low | Perf/Sec | Crypto | Per-op HKDF re-derive + mlock churn | `keys/hierarchy.rs:237-253` |
| A-6 | Nit | DRY | Crypto | `derive_*_key` copy-pasted 7× | `crypto/hkdf_derive.rs:41-122` |
| A-7 | Nit | Docs | Crypto | `derive_sequence_key` comment wrong | `crypto/hkdf_derive.rs:42-44` |
| A-8 | Nit | KISS | Crypto | `decode_base32` never masks accumulator | `crypto/totp.rs:169-186` |
| A-9 | Good | Security | Crypto | AAD construction textbook | `crypto/aead.rs:21-54` |
| A-10 | Good | Security | Crypto | Key material lifecycle disciplined | `keys/hierarchy.rs:41-135`, `crypto/totp.rs:12` |
| B-1 | HIGH | Sec/Concurrency | IPC | `rotate_root_key` not crash-safe | `vault/handle.rs:2410-2588` |
| B-2 | HIGH | Data-integrity | IPC | Cross-epoch ciphers silently vanish from index | `vault/handle.rs:1365-1368`, `keys/hierarchy.rs:215-221` |
| B-3 | HIGH | Data-integrity | IPC | Conflict merge discards remote for 7/8 kinds | `sync/conflict.rs:141-146` |
| B-4 | Medium | Data-integrity | IPC | Custom-field merge is 2-way | `sync/conflict.rs:166-171` |
| B-5 | Medium | Security | IPC | `rotate_root_key` skips zeroize | `vault/handle.rs:2440-2467` |
| B-6 | Medium | Concurrency | IPC | Sync state machine non-atomic write | `sync/state_machine.rs:80-86` |
| B-7 | Low | Concurrency | IPC | `recover_state` forces Idle without git cleanup | `sync/engine.rs:99-117` |
| B-8 | Low | Security | IPC | Bridge tokens unbounded writes | `daemon/handler.rs:1590` |
| B-9 | Low | Security | IPC | `unlock_with_kek` skips KEK canary if absent | `vault/handle.rs:265-269` |
| B-10 | Low | Data-integrity | IPC | `finalize_conflicts` mislabels local side | `sync/conflict.rs:182-183` |
| B-11 | Nit | DRY | IPC | Slug ladder + token check copy-pasted 4-5× | `daemon/handler.rs:1351-1531,1861-2163` |
| B-12 | Nit | KISS | IPC | Dead network-error arm on local op | `daemon/autosync.rs:536-540` |
| B-G | Good | Concurrency | IPC | VaultHost lock discipline, PIN escrow, constant-time, sync invariants, autosync gen-guard, path-traversal closed | (see "Things done well") |
| C-1 | Medium | Security | FE | Attachment download broken + error leak | `CipherDetail.jsx:483-495` |
| C-2 | Low | Security | FE | Content-script origin check fails open | `browser/shared/src/content.js:21` |
| C-3 | Low | Security | FE | Fill broadcast to all frames | `browser/shared/src/popup.jsx:308` |
| C-4 | Low | Security | FE | Shared `revealPass` unmasks all fields | `CipherDetail.jsx:45` |
| C-5 | Low | Security | FE | Reprompt may be UI theater (verify) | `RepromptModal.jsx:27-30` |
| C-6 | Low | Security | FE | Modulo bias in generator | `desktop/src/lib/utils.js:43` |
| C-7 | Good | Security | FE | Token/RNG/extension model sound | `lib.rs:393,216`, `background.js:149` |
| C-8 | Medium | Reactivity | FE | Biometric unlock ignores switchTarget | `LoginScreen.jsx:129-142` |
| C-9 | Medium | Reactivity | FE | Repeat fill silently no-ops | `browser/shared/src/content.js:10-29` |
| C-10 | Low | Reactivity | FE | Biometric unlock skips vaultInfo/prefetch | `LoginScreen.jsx:137` |
| C-11 | Low | Reactivity | FE | `setStatus` bypasses transition guard | `LoginScreen.jsx:137,183` |
| C-12 | Low | Perf | FE | Duplicate focus listeners | `AutoSyncContext.jsx:130-131`, `VaultSwitcherContext.jsx:48-49` |
| C-13 | Low | Perf | FE | `updateCipher` 3 IPC calls | `VaultContext.jsx:142-145` |
| C-14 | Medium | i18n | FE | en/es drift (~16 keys) | `desktop/src/i18n/locales/{en,es}.json` |
| C-15 | Low | KISS | FE | `alert()` vs toast convention | `CipherDetail.jsx:495`, `DeviceFleetPanel.jsx:35` |
| C-16 | Low | YAGNI | FE | Dev mock conflict code in prod bundle | `ConflictResolutionContext.jsx:128-152`, `App.jsx:19,112` |
| C-17 | Nit | KISS | FE | Dead ref assignment | `CipherDetail.jsx:252` |
