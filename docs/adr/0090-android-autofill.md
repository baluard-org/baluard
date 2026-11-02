# ADR 0090. Android Autofill

> Status: Accepted (2026-09-17). Implemented and verified on hardware over wireless adb: service, matcher, batch query, inline and dropdown presentation, save flow, domain equivalence, and app-to-web matching with per-app trust.

## Context

Android Autofill runs in a system-managed process separate from the main app. It has strict memory limits and receives untrusted field structures from target apps. Credential matching must not expose passwords before the user selects an entry.

The existing vault matcher is shared Rust logic. Public-suffix handling is required because host equality does not correctly identify registrable domains such as `example.co.uk`.

The mobile architecture fixes the constraints that shape this design (see ADR 0089): each OS process unlocks independently, the master-password Argon2id KDF (64 to 256 MB) must never run in a memory-capped process, and the vault on disk is the index (Git is the cache). The foundation already existed when this work began: the `:autofill` service declaration with `BIND_AUTOFILL_SERVICE` (source-tested for process isolation), `MobileVault.unlock_with_kek`, the per-vault KEK derivation reading `meta/kdf-params.json`, the Android Keystore KEK storage, the per-vault identifier used for keystore alias scoping, and the sandbox vault registry.

## Decision

### Service and parsing

Implement `BaluardAutofillService` in the `:autofill` process with `BIND_AUTOFILL_SERVICE`. A `BaluardApplication` class initializes the shared context in both the main and `:autofill` processes. Use `AssistStructure` heuristics to identify username and password fields. Parsing prioritizes autofill hints, then input type (`TYPE_TEXT_VARIATION_PASSWORD`, web password, email), then resource identifiers and entry names. Web fields use HTML metadata and autocomplete attributes, plus `webDomain` and `webScheme` extraction. Only HTTPS web targets are served; insecure HTTP targets are refused. The scaffold's `@RequiresApi(O)` was dropped as dead weight, because the minimum SDK is 32.

### Matching lives in Rust

Matching runs in Rust through `UriMatchStrategy::matches` and `matches_with` in `baluard-core`, covered by property tests over the strategy matrix (every strategy against https URLs, `androidapp://` URIs, bare hosts, and non-http schemes). A single batch call, `MobileVault.autofill_query(target)`, is implemented by `VaultState::autofill_query`. It decrypts logins, keeps only `id`, `name`, `username`, `favorite`, and URI metadata with strategies, excludes non-login, trashed, and archived ciphers, matches, and returns a ranked JSON object `{matches, app_suggestions}`. Ranking puts strategy matches before favorites and names. Kotlin does no matching and never sees a password during matching, and the same engine remains reusable by iOS. The query result contains no password key; the selected cipher is fetched through `get_cipher` only after selection, so passwords cross FFI only on selection. Application suggestions are returned separately from direct URI matches so the UI can apply the explicit trust decision without reproducing matching rules in Kotlin.

Use the `public-suffix` crate and its compiled suffix list (offline, roughly 200 KB) for eTLD+1 matching. A stale list may cause a missed match but must not produce a broader or incorrect match. The conservative alternative considered if the dependency had been rejected was treating `domain` as host equality, which misses matches but never offers wrong credentials. Native application targets use `androidapp://<package>` and match only by exact package equality against `androidapp://` entry URIs; otherwise there is no match. Browser and WebView targets use their real HTTPS URL (from `ViewNode.webDomain`) and the configured per-URI match strategy. Non-regex strategies reject mixed-scheme pairs, so `androidapp://` never cross-matches `https://`.

Apply custom equivalent-domain groups after the built-in match strategy, together with the bundled global equivalent domains. The matcher also supports candidate-domain reversal so a trusted native application can be compared with associated web domains. App-to-web suggestions are opt-in (`suggest_app_logins`). Expand application package candidates to web domains only after the user explicitly trusts that package, in a prompt hosted in-process by `AutofillActivity`. Persist decisions in `trusted_app_packages` and `rejected_app_packages`; trust is scoped to the exact package name, so lookalike packages derive the same candidate domain but must pass their own prompt (see ADR 0029).

### Unlock and session model

Biometric authentication is structurally mandatory in the service. The per-vault KEK wrap key is an Android Keystore AES-GCM key with `AUTH_BIOMETRIC_STRONG` and a zero-second authentication window, so no KEK leaves the Keystore without a fresh `BiometricPrompt` `CryptoObject` ceremony. Unlock through `MobileVault.unlock_with_kek`, which skips Argon2id but verifies keywraps and canaries. The master-password KDF is forbidden in this process. The originally planned "configurable biometric prompt before filling" therefore lands differently: the prompt gates session unlock, and the configurable part is session lifetime.

The process owns one independent unlocked `MobileVault` and session token, never shared with the main app. `AutofillSession` serializes open, unlock, and lock operations with a mutex and zeroizes superseded handles. On a cold session, return a generic response-level authentication placeholder ("Unlock Baluard") through `FillResponse.Builder.setAuthentication`, never dataset-level authentication, because matching needs decrypted URIs and the number of matching logins is unknown before unlock. A transparent `AutofillActivity` (a `FragmentActivity` with plain Views, no Compose) hosts the `BiometricPrompt`, runs the unlock and match, builds the real datasets, and returns them through `EXTRA_AUTHENTICATION_RESULT` before finishing. Its manifest entry runs in `:autofill`, is not exported (launched only through the service's own `PendingIntent`), is excluded from recents, has an empty task affinity, and uses a translucent dialog theme. `noHistory` is deliberately absent, because the result is set asynchronously after fingerprint, unlock, and response build, and a `noHistory` activity would be destroyed on stop and lose the result. The theme is not `NoDisplay`, because `BiometricPrompt` needs a visible window. The cost is one extra prompt per cold session, which is standard for password managers.

Each `onFillRequest` checks the configured per-vault `vault_timeout` and locks and zeroizes on expiry. Subsequent fills inside the window are answered without a prompt. The main app and autofill process lock independently while applying the same timeout value; locking one does not lock the other, which matches other managers but must be stated in-app so that "the vault is locked" never promises more than the process in front of the user. Process death fails closed. No remote fetch occurs on the fill path, and Compose, network access, and autosync stay out of `:autofill`.

The service resolves the active vault path from the shared app-private vault registry on each fill. A vault switch in the main app is honored on the next request; an in-flight session may use its current vault until that request ends.

### Presentation

Support both inline keyboard suggestions and the dropdown `RemoteViews` presentation (themed item layout, with content descriptions for TalkBack). Declare `supportsInlineSuggestions="true"` in the service metadata. The default presentation is INLINE, and inline chips supplement, and do not replace, dropdown items. API 33 and later use the `Presentations` builder; API 32 uses the deprecated `Dataset.Builder.setInlinePresentation`. When the keyboard supplies fewer inline specifications than datasets, reuse the final specification and cap inline datasets at five. If the IME does not support inline UI, the dropdown remains. Empty datasets are skipped because `Dataset.build()` throws when no field values are set.

### Save flow

Save new credentials through the main app. The `FillResponse` carries `SaveInfo` for username and password with `FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE`, because most login forms hide or destroy their fields on submit (single-page redirects, view recycling) and without the flag `onSaveRequest` silently never fires. `onSaveRequest` parses committed values and opens the main-app task through a one-time sandbox file token (`AutofillSaveToken`) rather than raw intent extras, which blocks intent spoofing on all API levels. The app opens a new Login edit screen prefilled with the values and persists it through its existing cipher creation path. The service holds no separate vault writer, keeping `:autofill` lean.

### Settings

The settings screen reports system Autofill status and links to Android settings. It carries the inline or popup presentation preference, per-vault matching strategy, and opt-in app suggestions, all through the shared en and es dictionaries. Brave integration mirrors the installed Brave package's `autofill_third_party_state` value from `content://<package>.AutofillThirdPartyModeContentProvider/autofill_third_party_mode`; it is guidance only and does not branch the fill path. Compatible Brave and Chrome-family packages are declared in the service configuration. Because `SharedPreferences` caches per process, cross-process flags travel through filesystem flag files (`AutofillFlagFile`).

When biometric authentication is cancelled or the Keystore key is invalidated, the service returns a friendly failure result. It does not fall back to master-password entry in the constrained process.

### Verification and scope

The AssistStructure parser is tested behind a node-walker abstraction, because `AssistStructure` cannot be constructed in JVM tests and fake nodes cover the hint, type, and id branches; target classification and session auto-lock decisions are unit-tested, and the process-isolation source test stays green. The matcher and query have Rust unit and property tests, including an integration check that matches are found, trashed, archived, and non-login entries are excluded, and no `password` key appears. Release sign-off requires a manual device matrix (Chrome, Firefox, a banking app, a social app, a WebView app) covering biometric cancel, auto-lock re-prompt, process-kill recovery, and multi-vault switching, with a known-bad-app list; emulator-only sign-off is not accepted for the first release. The cold-start target is under 500 ms, measured with `adb shell am start -W` and logcat timestamps.

Out of scope for this decision: TOTP codes in the autofill picker (a desktop-parity candidate for a separate pass), and iOS. Passkey credential-provider integration is also outside this service: it is a separate Android `CredentialProviderService` in the main process, specified in ADR 0095.

## Consequences

Matching and filtering remain consistent with other clients, and passwords cross FFI only after a user selects a result. Public-suffix errors fail toward missed suggestions, and PSL updates can change matching results as the bundled list changes.

Biometric authentication is mandatory for a cold autofill session. Separate process sessions may remain unlocked independently until their timeout expires. The autofill framework and the receiving application see the filled plaintext by design, and `FillEventHistory` may retain field metadata. This is inherent to the Android Autofill API for every password manager and is not a Baluard leak.

`AssistStructure` behavior varies among applications, so parser heuristics are layered and need ongoing device and application coverage, with iteration expected after dogfooding.

## References

- `docs/adr/0089-mobile-apps.md`
- `docs/adr/0091-android-accessibility-tile.md`
- `docs/adr/0028-android-autofill-quick-settings-accessibility-architecture.md`
- `docs/adr/0029-domain-equivalence-app-to-web-matching-with-per-app-trust.md`
- `docs/adr/0095-passkey-support.md`
- `crates/baluard-core/src/types.rs`
- `crates/baluard-runtime/src/state.rs`
- `crates/baluard-uniffi/src/lib.rs`
- `mobile/androidApp/src/androidMain/kotlin/xyz/actitud/baluard/autofill/`
