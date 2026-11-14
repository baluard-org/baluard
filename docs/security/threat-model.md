# Baluard: Threat Model

> Formal adversary model for the Rust-backed Space Manager.
> Covers: adversary classes, in-scope threats, local socket security, bucket metadata leakage, biometric attack surface, attachment handling, import parser risks, TOTP secret lifecycle, and JIT sync security.

---

## Summary Table

| Adversary Class | Capability Level | Primary Threat | Security Guarantee |
|-----------------|-----------------|----------------|-------------------|
| A, Honest-but-curious Git Provider | Passive read of all repository objects | Metadata inference (bucket distribution), timing analysis | Cannot read entry plaintexts. File names are UUID hashes; entry sizes are uniform buckets (5KB, 30KB, 100KB, 250KB, 2MB). Cover commits obscure push frequency. |
| B, Malicious Git Provider | Active: can modify refs, inject corrupted index | Rollback attacks, corrupted index injection | index.enc auto-healed locally by baluard-core. Rebuilt from entries if corrupted or conflicted. Unsigned commits rejected. Integrity manifest (Ed25519 checkpoints) detects rollback. |
| C, Local Process (on same device) | Read IPC socket or pipes | Intercept IPC commands, steal secrets | Unix only today: `0600` socket permissions + SO_PEERCRED (Linux) / getpeereid (macOS). Windows transport is unimplemented; restrictive named-pipe ACLs are a design commitment for when it ships, not a current control. Capability-based authorization: a per-vault 256-bit session token is required for all cipher/sync operations (R7-2). |
| D, Local Attacker (physical disk access) | Read stored files directly | Offline brute force or cache recovery | Files are AES-256-GCM encrypted. Keys are isolated in host OS Keyring or `zeroize`-protected memory. |
| E, Malware with OS root privileges | Full process memory interception | Dump memory, steal secrets | `zeroize`-protected memory with `mlock` guards prevents standard paging and core dump leakage. Key material mlock'd to prevent swap persistence (R7-3). Multi-vault (Phase 6) widens the amount of resident key material; bounded by per-vault auto-lock. See T15. |
| F, Evicted Space Member | Possesses historical local git checkout | Read new entries or make unauthorized commits | Rotated Space Group Key renders future additions unreadable. Root key rotation re-encrypts all entries under new epoch. Git credential rotation is out-of-band (user must rotate deploy keys/PATs manually). |
| G, Active Git Remote Adversary | Modify encrypted files on git remote | Swap/replace entries, cause victim to decrypt wrong data | SHA-256 hashed AAD identity binding in every envelope blocks swap attacks (T5). Git commit signing (Ed25519) provides repository-level integrity. |
| H, Malicious Import File | Supply crafted CSV/JSON/XML/1PUX file | Parser exploitation, injected malicious data | Import parsers run in Rust (memory-safe). Parsed into `CipherInput` structs, batch-created. No code execution from import data. |
| I, OS Keychain Compromise | Extract master password from OS keyring | Full vault access without user interaction | Biometric unlock is opt-in. Keychain-stored MP is no stronger than the OS keychain itself. See T10. |

---

## Design Principle: Brokered Capabilities, Never Bearer Secrets

Baluard trusts exactly one boundary: the Rust daemon. Every privileged operation is **brokered** there. The client (Tauri webview, CLI, mobile UI, browser extension) is untrusted by default and receives **scoped capabilities**, never raw key material.

This is the **capability broker** pattern, the opposite of bearer authority:

- **Bearer authority**: whoever holds the secret wields it. A key handed to a client can end up anywhere that client's output goes.
- **Brokered capability**: authority delegated as a narrow, revocable handle. The broker holds the secret and performs the action on the holder's behalf.

The client never holds a vault key. It holds a token that *permits the daemon* to use the key on its behalf.

| What the client receives | What never crosses the boundary | Reference |
|---|---|---|
| Per-vault 256-bit session token (opaque, constant-time verified) | Root Key, Space Group Key, Item Keys | T2, T15 |
| Derived numeric TOTP code | TOTP seed | T9 |
| Signed passkey assertion (COSE outputs) | Passkey private key | WebAuthn ceremony |
| Brokered vault unlock (run server-side) | Master password (never returned over IPC) | T10 |
| Scoped bridge token (allowlist-enforced) | Long-lived daemon session | Browser extension bridge |

**Invariants**

1. A same-UID process that did not take part in the unlock exchange holds no capability and is refused (T2, R7-2). The CLI stores its session token in the OS keyring (audit C2 closed); a plaintext `baluard.tok` file exists only as a fallback when no keyring service is available.
2. Authority is **per-vault scoped**: a token minted for vault A is rejected for a vault B operation (multi-vault, Phase 6).
3. Capabilities are **revocable and short-lived**: tokens die on lock, on close, and on daemon shutdown.
4. The transport is **authenticated**: `0600` socket, peer-credential UID check (SO_PEERCRED on Linux, getpeereid on macOS). Windows has no transport yet (see T2).

The session token is a capability in the object-capability sense: it is the only authority the client holds, it grants a scoped set of operations, and it does not expose the underlying secrets. This is why "token-gated IPC" and "capability-based authorization" name the same mechanism in Baluard.

---

## 1. In-Scope Threats & Security Controls

### T1: Git Provider Observing File Counts and Sizes
- **Threat**: Attacker infers vault contents based on specific file size signatures.
- **Control**: All entries under `entries/` are padded to uniform bucket sizes (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB) prior to encryption. Filenames are random UUID hashes. Attacker only observes counts of files per size bucket. `Tier::fit()` auto-selects the smallest bucket that fits the plaintext plus the padding length prefix.
- **Attachments (audit C4, fixed)**: attachment blobs join the same tier padding and carry AAD binding (vault + cipher + attachment + tier + epoch + seq), so neither exact plaintext sizes nor same-cipher blob swaps are available to a push-capable attacker. Input cap is 1.9 MB so the padded XL envelope stays within budget.
- **Attachments side channel**: blobs no longer ride `main`; they publish to a signed, content-addressed append-only line at `refs/notes/baluard-attachments`, so a provider observing branch history sees ciphertext tree entries only, keyed by the SHA-256 of the stored bytes. The provider sees the same per-bucket size classes as before plus raw padded byte counts on the line (identical to the old main-tree exposure). Deletion is logical until the owner runs compaction, which force-replaces the line with only still-referenced files.

### T2: Local IPC Interception
- **Threat**: Another application on the same machine connects to the daemon and requests secrets.
- **Control**: IPC sockets are locked to `0600` permissions, allowing only the current user's process to connect. Peer credential verification (SO_PEERCRED on Linux, getpeereid on macOS) rejects connections from other UIDs. The Windows transport is unimplemented; a named-pipe DACL design is committed for that platform before any Windows release.
- **R7-2 Enhancement**: After unlock, the daemon generates a random 256-bit session token. All subsequent requests for cipher data, sync operations, and device listing must include this token. Without it, the daemon rejects the request. This prevents any same-UID process from extracting secrets after unlock without having participated in the unlock exchange.

### T3: Mobile Autofill Timing and Exfiltration Attacks
- **Threat**: Network attacker maps when mobile users autofill credentials by observing network traffic or git fetch spikes during input focus.
- **Control**: Mobile autofill is strictly offline-first. The autofill service resolves credentials purely from local storage on disk (`VaultState::autofill_query`) with no network calls or sync operations on the fill path.

### T4: Evicted Space Member (Offboarding Revocation)
- **Threat**: Evicted member tries to decrypt new entries pushed to the Space.
- **Control**: The Admin rotates the Space Group Key. Every remaining entry is re-encrypted with the new Group Key. The access list `meta/access_list.json` is updated to exclude the evicted member's public key wrapper. Future commits are unreadable to the evicted user.

### T5: Active Git Remote Adversary (Swap/Rollback)
- **Threat**: The git remote host (or any party with push access) modifies vault entries by renaming, replacing, or rolling back encrypted files. Without integrity binding, the victim decrypts the wrong entry and sends its contents to an attacker-controlled service (CVE-2020-28086 class attack).
- **Control**: Every encrypted envelope includes AES-256-GCM AAD (Additional Authenticated Data). The AAD is derived via SHA-256 hash over length-prefixed fields: `vault_id || object_type || object_id || tier || alg_id || key_epoch || update_seq` with domain separation prefix `baluard-aad-v2`. On decryption, the daemon recomputes expected AAD from caller parameters and asserts before decryption. Mismatches are rejected with `Corrupt("cipher identity mismatch")`. This blocks swap attacks, rename attacks, and cross-entry cut-and-paste.
- **Control**: Git commit signing (Ed25519) provides repository-level integrity. Unsigned commits are rejected.
- **Control**: Ed25519-signed integrity manifest checkpoints detect rollback. Fresh devices bootstrap trust from the manifest.

### T6: Key Material Paged to Swap
- **Threat**: OOM kill, `kill -9`, or process crash bypasses Rust `Drop` destructors. Key material (RootKey, ItemKey, TOTP secrets) may persist in RAM pages or be paged to swap/hibernation files, where it can be recovered by anyone with disk access.
- **Control**: All key material buffers (RootKey 64 bytes, ItemKey 32 bytes) are `mlock`'d immediately on creation. `munlock` + zeroize on drop. Best-effort and silent per key (individual mlock failures are not logged); the daemon logs the resident key budget and RLIMIT_MEMLOCK at unlock. Not fatal (RLIMIT_MEMLOCK may be low on some systems). TOTP `TotpParams.secret` is zeroized on drop.

---

### T7: Attachment Plaintext Leakage
- **Threat**: During upload or download, unencrypted attachment data exists in process memory or as a temp file on disk.
- **Control**: Attachments are encrypted with the cipher's item key (AES-256-GCM, random nonce) in memory. No temp files are written. Plaintext is zeroized in both daemon and CLI after use. Max attachment size: 1.9 MB (`MAX_ATTACHMENT_SIZE`), enforced before encryption to prevent resource exhaustion.
- **Line fetch path (post side-channel move)**: downloads fall back to fetching the stored blob from `refs/notes/baluard-attachments` when the worktree copy is absent. Every fetched blob is verified against its content pin (SHA-256 of the stored bytes) inside the fetch before it can reach decryption, so a hostile remote cannot substitute foreign bytes; ref-absent reads surface as "not finished syncing" rather than an error. The upload path holds its base64 transport buffer only long enough to decode, and zeroizes it immediately after.

### T8: Import Parser Exploitation
- **Threat**: A crafted import file (CSV, JSON, XML, 1PUX) exploits a parser bug to cause memory corruption or code execution.
- **Control**: All import parsers are written in Rust (memory-safe). Parsed data flows into typed `CipherInput` structs before batch-creation. No code execution from import data. Parser errors produce `BaluardError` without panicking.

### T9: TOTP Secret Exposure
- **Threat**: TOTP secret is extracted from daemon memory or intercepted over IPC.
- **Control**: TOTP secrets are stored encrypted in the vault (part of Login cipher data). The dedicated code route (`cipher.totp`) returns only the derived numeric code; the stored `otpauth://` URI also rides inside full cipher reads (`vault.get`, `vault.list_full`) because the editor round-trips it. Treat the seed as session-scope material behind the session token, not socket-absent. `TotpParams.secret` is zeroized on drop. TOTP codes are short-lived (30/60s), limiting replay window.

### T10: Biometric Unlock / OS Keychain Compromise
- **Threat**: An attacker with access to the OS keychain extracts the stored master password, gaining full vault access without user interaction.
- **Control**: Biometric unlock is opt-in (disabled by default). On macOS, the master password is stored using the native `security-framework` API with `SecAccessControl` configured for biometric validation (`AccessControlOptions::BIOMETRY_ANY`), ensuring Touch ID / Face ID is required on read. On other platforms, it uses the `keyring` crate (utilizing Windows Credential Manager, Linux libsecret, etc.). The daemon performs vault unlock server-side: the secret never returns over IPC. Users who distrust the OS keychain should not enable biometric unlock.
- **Residual**: Keychain access typically requires OS-level authentication (TouchID, Windows Hello, Linux PAM). Compromise implies the attacker has already bypassed OS security.

### T11: Reprompt Grant Window Abuse
- **Threat**: A same-UID process exploits the 30-second reprompt grant window to access a protected cipher after the user authenticates.
- **Control (as implemented)**: Reprompt opens a temporary vault handle, verifies the master password, and holds the result for 30 seconds. No grant token is minted — a returned token would be a bearer capability the client could replay; the daemon keeps the window internal, and the verification route is rate-limited on the shared per-vault budget (audit C23). Against the same-UID adversary this is a UX deterrent, not a security boundary; the session token (R7-2) is still required.

### T12: Online Brute Force (Master Password)
- **Threat**: An attacker with local or daemon access attempts rapid password guesses.
- **Control (layered, stated honestly)**: Three layers apply, each with a known limit. (1) Argon2id KDF (memory-hard) makes each attempt computationally expensive; this is the layer that dominates attack cost and cannot be reset. (2) An in-memory IPC rate limiter throttles guessable routes (unlock, bridge pairing, bridge reads); its state is volatile, so a daemon restart resets it (audit C7), and it covers only the routes it is wired into (see `rate_limit.rs` for the authoritative list; audit C22). (3) An on-disk attempt counter in vault metadata records exponential backoff, but it is a file the attacker can edit or delete, so it is advisory only against a same-UID adversary (audit C6).

### T13: Recovery Phrase Exposure
- **Threat**: The BIP-39 24-word recovery phrase is written down, photographed, or observed during vault creation.
- **Control**: The phrase is displayed once during creation and never stored in plaintext. Derived via BIP-39 from 256 bits of CSPRNG entropy. The recovery phrase bypasses all device enrollment and quorum controls. Physical security of the phrase is the user's responsibility. **Mandatory write-down verification** during creation (user must re-enter 4 random words) reduces the risk that the user proceeds without actually writing it down.
- **Residual**: The phrase IS the root of trust. If compromised, full vault access is possible from any device. No mitigating control exists beyond physical protection. With `EnrollmentPolicy::Personal`, the phrase can also be used to enroll new devices (non-destructive). With `Strict`, it only works via destructive `recover_from_phrase`.

### T14: Cover Commit Correlation
- **Threat**: A git remote adversary (compromised host, MITM, or rogue admin) observes commit timestamps, push timing, frequency patterns, and tree diffs to infer active usage hours, edit frequency, file count changes, or silence gaps.
- **Control**: Cover commits use CSPRNG-backed timing jitter on push/pull intervals. Commit content is padded to uniform bucket sizes, so diff sizes are indistinguishable from real commits.
- **Defense Mechanism**: Cover commits are no-op commits (same tree as HEAD) combined with static commit messages (`COMMIT_MESSAGE` in engine.rs), a generic git author (`"Baluard User" <vault@baluard.local>`), encrypted metadata, and timestamp normalization on vault lock. Timing jitter helpers exist (`push_with_jitter`/`pull_with_jitter` in engine.rs) but are NOT wired into the sync cycle — push/pull timing jitter is planned, not active.
- **Scheduling Policy**:
  * **Triggered Cover Commits**: After every real vault operation that triggers a `commit_all()`, a cover commit is scheduled at a uniform random delay (Min: 30 minutes, Max: 4 hours).
  * **Periodic Cover Commits**: A background timer fires cover commits independently of user activity at random intervals of 2–6 hours (jittered ±30 minutes) if the vault is unlocked.
  * **Push Policy**: Cover commits accumulate locally and push on the next sync push or periodic auto-sync to avoid detectable push correlation patterns.
  * **Interactions**:
    * *Real commit*: Schedule cover commit at T+random(30m, 4h).
    * *Timer fires*: Create no-op commit if vault is unlocked.
    * *Push*: Push all local commits (real + cover) with jitter.
    * *Lock*: Cancel pending cover commit timers.
    * *Unlock*: Start periodic cover timer.
- **Residual**: High-frequency push patterns may still leak usage timing. Mitigation is probabilistic, not deterministic.

### T15: Concurrent Multi-Vault Key Material (Phase 6)
- **Threat**: When a user keeps two or more vaults unlocked simultaneously (the Phase 6 keep-unlocked / switch-pointer model), up to N Root Keys and their derived Item/Space Group Keys are resident in daemon memory at once for as long as each vault is within its own auto-lock window. This widens the blast radius of any single memory-exposure event (actor E: `kill -9`, OOM, core dump, memory-scraping malware) from one vault to all currently-unlocked vaults.
- **Control**:
  * **Per-vault auto-lock bounds the exposure window.** Each vault independently zeroizes its key material on its own `auto_lock_minutes` idle timer. The user controls residency per vault via settings; nothing raises the default timer for multi-vault setups.
  * **All existing key-protection controls still apply, unchanged.** Every Root/Item Key remains `mlock`'d immediately on creation and zeroized on drop (T6); the daemon socket is `0600` with peer-credential UID checks and a **per-vault** 256-bit session token (R7-2), so a same-UID process cannot read a vault's data without that vault's token.
  * **Switching never touches key material.** `vaults.switch` flips only the `active` pointer; it performs no zeroization and no token rotation, so it cannot widen or reset any vault's residency. Key material leaves memory only via per-vault auto-lock, explicit `lock`/`vaults.close`, or daemon shutdown.
  * **Explicit unload.** `vaults.close` removes one vault from the in-memory map and zeroizes its keys (via Arc-drain, in-flight handlers finish and zeroize on last drop) without disturbing other open vaults, letting a user reduce exposure on demand.
  * **Lock-all on unattended/device events.** Screen lock, system sleep / lid-close, and app-resign-active (Tauri window blur + OS suspend hooks) trigger an immediate lock of **every** currently-unlocked vault, not just the active one. This caps the multi-vault exposure the moment the device becomes unattended instead of waiting for each vault's idle timer. App quit locks all as well.
  * **Aggregate `mlock` budget monitoring.** Each unlocked vault mlocks its Root Key (64 B), SGK (32 B), and active Item Keys (32 B each). With N vaults the total mlocked footprint scales with N and can approach `RLIMIT_MEMLOCK` on low-default systems (older Linux defaults are 64 KB). The daemon logs total mlocked bytes across all open vaults at unlock time; `mlock` failure remains best-effort (logged, not fatal) per T6.
- **Residual**: For the window a vault sits idle-but-unlocked, its keys are exposed to the same memory-interception vectors as a single-vault setup (T6/E). Multi-vault increases the *amount* of simultaneously-exposed material, not the strength of protection per key. Legibility control: settings surface the count of currently-unlocked vaults and their per-vault timers so the exposure is visible. See `docs/adr/0088-git-providers-multi-vault.md` Phase 6.

### T16: Mobile Autofill Process Isolation & Intent Spoofing
- **Threat**: Untrusted Android apps intercept filled credentials, spoof save-login prompts via exported activities, or trigger OOM denial of service. Malicious apps could also craft custom URL schemes (`androidapp://`) to harvest web credentials.
- **Control**:
  * **Memory-capped process isolation**: `BaluardAutofillService` runs in a dedicated `:autofill` process. Unlocking executes `unlock_with_kek` using the Keystore-held biometric KEK, skipping the 64-256 MB Argon2id master KDF to prevent low-memory termination.
  * **One-time save handoff token**: when saving new credentials, `onSaveRequest` generates a random single-use token (`AutofillSaveToken`) in app sandbox storage before launching `MainActivity`. Callers without the token cannot inject prefilled entries into the create form.
  * **Scheme isolation**: `UriMatchStrategy::matches` strictly separates `androidapp://` URIs from web schemes (`https://`). An app cannot harvest credentials for a web domain by declaring an identical package name.
  * **App-to-web phishing protection**: Web credentials never auto-fill into native apps. When `suggest_app_logins` is enabled, package-derived candidate domains are validated against public suffixes and shown only as suggestions alongside an explicit trust confirmation. User decisions are bound per `(package, domain)` pair; package-name lookalikes (`com.mybank.evil`) cannot inherit trust from another app.
  * **Accessibility fill bounds**: the quick-settings tile accessibility service operates strictly on user demand (no background overlay, no continuous screen monitoring), copies TOTP to clipboard instead of typing, and caps retries to 3 attempts per selection.

## 2. Platform Trust Boundaries

```
+-------------------------------------------------------------+
| TRUSTED BOUNDARY (Rust Daemon, zeroize memory, mlock)       |
|                                                             |
|  +----------------------+  +-----------------------------+  |
|  | Root Key / SGK /     |  | Device Private Key          |  |
|  | Item Keys            |  | (sealed file on disk,       |  |
|  | (zeroize + mlock)    |  |  zeroize on load)           |  |
|  +----------------------+  +-----------------------------+  |
+------------------------------+------------------------------+
                               |
              +----------------+----------------+
              |                                 |
    SEMI-TRUSTED boundary            SEMI-TRUSTED boundary
    (OS Keyring / Keychain)          (Protobuf IPC Gateway)
    - Biometric: MP stored here      - Unix Socket 0600
    - OAuth PAT stored here          - Session token gated
    - Keyring = OS security          - SO_PEERCRED / getpeereid
              |                                 |
              |       Unified IPC Protobuf      |
              |       v (Unix Socket 0600)       |
+-------------------------------------------------------------+
| SEMI-TRUSTED (Tauri v2 SolidJS Webview, CLI, KMP UI)       |
|                                                             |
|  - No cryptographic logic or direct vault keys in UI        |
|  - Communicates strictly via HandleRequest(action, payload) |
|  - TOTP codes, not secrets. Attachments streamed, not cached|
+------------------------------+------------------------------+
                               | Network / Git Synchronization
                               v
+-------------------------------------------------------------+
| UNTRUSTED (Git Provider Host, Host OS Filesystem)           |
|                                                             |
|  - entries/*.enc (Uniformly padded, UUID hashed)            |
|  - index.enc (Encrypted fast-lookup index)                  |
|  - meta/device_activity.json (Plaintext, UUIDs only)        |
|  - meta/devices.json (Plaintext, public keys + names)       |
+-------------------------------------------------------------+
```

---

## 3. Residual Risks

1. **Host OS Root Compromise**: If malware obtains root-level keylogger or debugger capabilities, it can intercept user input (Master Password) or compromise the OS Keyring. No defense within application scope.
2. **Metadata Pattern Inference**: High-frequency Git pushes reveal active usage periods. Mitigated through optional cover commits with CSPRNG jitter (T14). Probabilistic, not deterministic.
3. **Lost Device Quorum Override**: Single-device emergency force-evict relies on the user proving possession of both the Master Password (KEK) and the remaining hardware token. If both are compromised, the vault is fully taken over.
4. **Revoked Device Stale Snapshot**: A revoked device retains a readable copy of the vault at the epoch of revocation. Root key rotation ensures the copy becomes stale, but historical data remains readable. Fundamental to serverless model.
5. **Git Credentials Out-of-Band**: Revoking vault access does NOT revoke git push access. User must manually rotate deploy keys/PATs on GitHub/GitLab. Fleet dashboard shows persistent warning, but no automated enforcement.
6. **Recovery Phrase is Root of Trust**: If the BIP-39 phrase is compromised, full vault access is possible from any device, bypassing all device enrollment and quorum controls. No mitigating control beyond physical protection.
7. **Plaintext Metadata Files**: `meta/devices.json` (public keys) and `meta/device_activity.json` (UUIDs, timestamps) are plaintext in the git repo. Acceptable for single-user private repos, but leaks sync patterns to anyone with repo read access, and enables cross-vault correlation when one provider account hosts several vaults (audit C5). Device display names no longer leak: since the C5 code fix they live encrypted in `meta/settings.enc` (device UUID → name map) and are stripped from the git-tracked registry on every unlock (fold-and-strip migration; names may briefly persist in devices.json between a pre-unlock enrollment and the first unlock). Residual: UUIDs, timestamps, and key material hashes remain visible.
8. **Keywrap Gap After Revocation**: After device revocation, the keywrap file for the revoked device is not cleaned up. Recovery phrase is the fallback. (Known gap, tracked in progress doc.)
9. **Mobile TLS Trust (Android)**: provider API traffic uses the platform TLS stack and the OS trust store, outside the app's network security config; no certificate pinning. Decision: accept OS trust store, skip pinning (rotation outages hurt availability for marginal gain against a device-compromise adversary that already wins otherwise; audit M9).
