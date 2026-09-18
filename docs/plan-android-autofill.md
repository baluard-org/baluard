# Plan: Android Autofill (Phase 6)

Status: implemented (2026-09-17). Authoritative requirements: `docs/plan-mobile-apps.md` §3.2, §3.7, Phase 6. All build phases complete and verified on hardware over wireless adb.

## 0. Current state (audited)

Already exists, reuse as-is:

| Piece | Location | State |
|---|---|---|
| Service declaration | `androidApp/.../AndroidManifest.xml` | `<service>` with `:autofill` process + `BIND_AUTOFILL_SERVICE`, source-tested by `AutofillProcessIsolationTest` (M8) |
| Service scaffold | `androidApp/.../autofill/BaluardAutofillService.kt` | Correct `FillCallback` API, AssistStructure walk skeleton, returns empty response |
| KEK quick-unlock FFI | `baluard-uniffi` `MobileVault.unlock_with_kek` | Skips Argon2id, verifies keywrap + canaries. The OOM-guard invariant path |
| KEK derive FFI | `derive_kek_for_vault` | Reads per-vault `meta/kdf-params.json` |
| Biometric KEK storage | `shared/androidMain/.../Biometric.android.kt` (B5) | AndroidKeystore AES-GCM key, `setUserAuthenticationRequired(true)` + `AUTH_BIOMETRIC_STRONG`, auth-per-use CryptoObject ceremony, wrapped blob in prefs, alias per vault path |
| Vault scoping | `MobileVault.vault_id()` | Per-vault keychain/alias scoping |
| Vault discovery | `platform/VaultRegistry` | Scans sandbox, persists last-active vault path |
| Process context | `platform/AppContextHolder` | Context holder + FragmentActivity host for BiometricPrompt |

Phase 6 implementation scope (completed):

1. **`BaluardApplication`**: initializes context in both the main and `:autofill` processes.
2. **URI matching and equivalence engine in core**: `UriMatchStrategy::matches` and `matches_with` in `baluard-core` with public-suffix eTLD+1 support, bundled Bitwarden global equivalent domains, user-defined custom equivalent domain groups (`custom_equivalent_domains`), candidate domain reversal (`app_domain_candidates`), and strict scheme isolation.
3. **Autofill query batch endpoint**: `VaultState::autofill_query` in `baluard-runtime` / `baluard-uniffi` returning `{matches, app_suggestions}` without passwords.
4. **App-to-web matching with per-app trust**: opt-in `suggest_app_logins` setting with in-process trust prompt in `AutofillActivity` and persistence to `trusted_app_packages` / `rejected_app_packages`.
5. **Service implementation**: `BaluardAutofillService` with heuristics-based AssistStructure parsing, inline suggestions (`supportsInlineSuggestions`), dataset building, and split save prompt handling.
6. **`AutofillActivity`**: translucent trampoline host for `BiometricPrompt` with `CryptoObject` response-level authentication, app-to-web trust prompts, and a11y credential picker.
7. **Session management**: `AutofillSession` with mutex-serialized lifecycle, KEK-only unlock (`unlock_with_kek`), and auto-lock tracking.

## 1. Architecture decisions

D1. **Matching lives in Rust.** `UriMatchStrategy::matches(uri, target)` and `matches_with(uri, target, custom_groups)` in `baluard-core/src/types.rs` (proptests over the strategy matrix), plus one batch FFI call `MobileVault.autofill_query(target) -> String` implemented in `baluard-runtime::VaultState`: decrypt logins, extract only `id, name, username, favorite, uris[]` with strategies, match, return ranked JSON object `{matches, app_suggestions}`. Kotlin does zero matching and never sees passwords during matching. iOS Phase 7 reuses the same engine.

D2. **Passwords cross the FFI only on selection.** The chosen cipher is fetched via existing `get_cipher(id)` at fill time. `autofill_query` output never contains passwords.

D3. **`domain` strategy needs a public-suffix list.** Host-equality is wrong for `co.uk` style suffixes. Add the pure-Rust `publicsuffix` crate (offline, ~200 KB compiled list) to `baluard-core` for eTLD+1 extraction. Fallback if rejected: v1 treats `domain` as host equality (conservative: misses matches, never offers wrong credentials) and we upgrade later.

D4. **Native app targets match via package.** The service passes `androidapp://<package>` for native apps and the real `https://` URL (from `ViewNode.webDomain`) for browsers/webviews. `matches()` treats an `androidapp://` target as: package exact-equality against `androidapp://` entry URIs, else no match. Browser fills use the per-URI strategy. App-to-web matching (Path B) expands candidates only after explicit per-app user trust.

D5. **Biometric is structurally mandatory in the service.** The KEK wrap key is auth-per-use (`AUTH_BIOMETRIC_STRONG`, 0-second window), so no KEK leaves the Keystore without a fresh prompt, and the master-password KDF is forbidden in this process (OOM invariant, plan §3.2). The plan's "biometric prompt before filling (configurable, default ON)" therefore lands as: the prompt gates session unlock; the configurable part is session lifetime (D6). Update the plan wording when Phase 6 closes.

D6. **Session = one unlocked `MobileVault` in the `:autofill` process.** Per-process unlock invariant: the service holds its own runtime instance, own session token, never shares the main app's. First fill of a cold session: respond with a **response-level** authentication (`FillResponse.Builder.setAuthentication(requiredIds, intent, presentation)` with a single generic "Unlock Baluard" placeholder), never dataset-level, because pre-unlock we cannot know which or how many logins match; matching needs decrypted URIs. The OS launches transparent `AutofillActivity` (FragmentActivity, plain Views, no Compose in this process) -> BiometricPrompt CryptoObject -> KEK -> `unlock_with_kek` -> match -> build real datasets -> `setResult(RESULT_OK, intent.putExtra(EXTRA_AUTHENTICATION_RESULT, fillResponse))` -> finish. Subsequent fills inside the vault's auto-lock window are answered directly (no prompt). Each `onFillRequest` checks `should_auto_lock()` (already in FFI) and locks + zeroizes on expiry. Process death = fail secure by design.

D6a. **Per-process lock states are independent by design.** Locking the main app does not lock the autofill session, and vice versa; both honor the same per-vault `vault_timeout` policy value. This matches user expectations set by every mainstream manager (browser extension and app sessions are also independent) but must be documented in-app (settings note) so "the vault is locked" never promises more than the process in front of the user.

D7. **Presentation modes = inline IME keyboard suggestions and dropdown RemoteViews.** The manifest declares `supportsInlineSuggestions="true"`. Datasets attach keyboard chips when enabled in Settings (default INLINE) in addition to themed RemoteViews menu items (`autofill_dataset_item.xml`).

D8. **Save flow routes through the main app.** `FillResponse` carries `SaveInfo` (username + password) built with `FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE`: most login forms destroy/hide the field hierarchy on submit (SPA redirects, view recycling), and without the flag `onSaveRequest` silently never fires. `onSaveRequest` parses committed values and launches the main-app task with extras; `App()` reads them and opens the edit screen prefilled as a new Login. Compose runs in the main process anyway; the `:autofill` process stays lean.

D9. **No Compose, no network, no autosync in the `:autofill` process.** Remote fetch never happens on the fill path (acceptance criterion). The vault on disk is the index (git IS the cache, plan §1).

## 2. Build phases (each independently verifiable)

P1. **Matcher in core.** `UriMatchStrategy::matches` + host/eTLD+1 helpers (+ `publicsuffix` dep per D3). Unit + proptest matrix: every strategy x target kinds (https URL, androidapp URI, bare host, non-http scheme). Verify: `cargo test -p baluard-core`.

P2. **`VaultState::autofill_query` + FFI.** Runtime method (decrypt logins via the existing `get_cipher` decrypt path, filter Login kind, exclude trash/archive, extract URI list, call matcher, rank: strategy-ordered then favorite/name). Thin `uniffi::export`. Integration test: matches found, trash/archive/non-login excluded, no `password` key in output JSON. Regenerate `baluard_uniffi.kt` (`just android-bindings`; the APK build also auto-regens when `lib.rs` is newer). Verify: `cargo test -p baluard-uniffi`.

P3. **Fill path end-to-end.**
   - `BaluardApplication.kt` + `android:name` in manifest (fixes context init in both processes).
   - `autofill/AutofillSession.kt`: singleton in `:autofill` process (open, unlock state, auto-lock check, zeroize).
   - Parser hardening in `BaluardAutofillService`: hint-based, then inputType-based (`TYPE_TEXT_VARIATION_PASSWORD`/`WEB_PASSWORD`, email), then id/resource-entry heuristics; web fields via htmlInfo/autocomplete; webDomain + webScheme extraction (https only; http = refuse); saveType hints.
   - Dataset building with RemoteViews presentation + save info.
   - `AutofillActivity` trampoline: biometric ceremony, response-auth result, graceful failure message on cancel/invalidated key. Manifest entry: `android:process=":autofill"` (same process as the service), `android:exported="false"` (launched via our own PendingIntent), `android:noHistory="true"`, `android:excludeFromRecents="true"`, translucent dialog theme (NOT `NoDisplay`: BiometricPrompt needs a visible window).
   - Drop the scaffold's `@RequiresApi(O)` (dead weight, minSdk 32). While touching the service, note that `VaultRegistry` persistence is app-sandbox disk state readable from both processes, so an active-vault switch in the main app is honored on the next fill (stale-read within one session is acceptable and re-checked per request).
   - Verify: `just android-install`; enable in Settings > Passwords; fill in Chrome + one native app; cold-start log < 500 ms.

P4. **Save path.** SaveInfo on responses, `onSaveRequest` -> main-app routing, edit-screen prefill from extras, save via existing `addCipher`. Verify: submit a new login in Chrome, save prompt lands in Baluard.

P5. **Settings + i18n + a11y.** Settings section: autofill status + deep link to system autofill settings; biometric note (structurally on, D5); per-vault default match strategy surfaced if not already on the mobile settings screen. All new strings via shared `I18n` en/es. RemoteViews contentDescription for TalkBack.

P6. **Device matrix + polish.** Chrome, Firefox, one banking app, one social app, a webview app. Biometric-cancel path, auto-lock re-prompt, process-kill recovery, multi-vault active switch honored. Known-bad-app list doc (plan §6 risk). Release R8 pass. Perf: measure with `adb shell am start -W` + logcat timestamps.

## 3. Test strategy

- Rust: unit + proptest for the matcher; integration for `autofill_query` (correctness + secret-absence invariant).
- Kotlin (androidUnitTest): parser heuristics behind a node-walker abstraction (AssistStructure is not constructible in JVM tests; fake nodes cover hint/type/id branches), target classification (package vs URL), session auto-lock decisions. `AutofillProcessIsolationTest` stays green.
- Manual: the P6 matrix; no emulator-only sign-off for the first release.

## 4. Risks

- AssistStructure variance across apps (plan §6 risk): layered heuristics + manual matrix + known-bad list. Expect iteration after dogfooding.
- `:autofill` memory cap: KEK path only (no KDF), no Compose, vault index read from disk. The invariant is already source-tested; keep it that way.
- Dataset-auth UX costs one extra tap + prompt per cold session. Standard for password managers; inline suggestions later soften it.
- Filled values are plaintext to the OS by design: the autofill framework and the filled target app see the cleartext password, and `FillEventHistory` may retain field metadata. Inherent to the Android Autofill API (true for every password manager), not a Baluard leak; noted so review never mistakes it for one.
- PSL data staleness: compiled-in list updated on crate bumps; `domain` misses degrade to no-match, never to wrong-match.

## 5. Explicitly out of scope (v1)

- TOTP codes in the autofill picker (desktop extension parity candidate, separate pass).
- Autofill of passkeys (`CredentialProviderService`, API 34): plan §10 marks platform credential-provider as v2+.
- iOS: Phase 7 per plan, starts only on Esteban's signal; D1 keeps the matcher reusable.
