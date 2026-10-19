# Mobile Passkeys: Baluard as an Android Credential Provider (G10)

- **Status**: Draft for review (v2 — folded from two review rounds)
- **Date**: 2026-10-20
- **Author**: Esteban
- **Reviewers**: two external peer review rounds (recorded in the header of the
  shipped commit; no reviewer naming in docs bearing the user's name)

## 1. Product story

A user visits github.com in Chrome on Android, clicks "Create a passkey", and
the system sheet offers Baluard next to Google Password Manager. Baluard
unlocks (biometric), shows which vault entry the passkey lands in, and the
sign-up completes. Weeks later, signing in offers the Baluard passkey in the
same system sheet; the assertion is computed from the vault entry's key
material and the site accepts it. This is table stakes for a password manager
in 2026 and the last major mobile gap (G10, promoted into 1.0).

Everything crypto-side already exists: `crates/baluard-core/src/crypto/webauthn/`
(passkey-rs 0.5 ceremonies, `PasskeyIndex`, `BaluardCredentialStore`, ES256,
zeroized keys) and the runtime two-phase routes. What is missing is the Android
platform layer that makes Baluard a **credential provider**: the OS-facing
service, the origin-validation rulebook, and provider-grade ceremony entry
points that honor the relying party's own challenge.

The reference implementation is Bitwarden's Android client (GPL-3.0, same
license): `app/src/main/kotlin/com/x8bit/bitwarden/data/credentials/` — this
plan copies its architecture piece by piece (§3) rather than inventing one.
Where this plan deliberately deviates from Bitwarden, the deviation is marked
**[deviation]** with the reason.

## 2. Scope

**In scope (Android, API 34+):**

- `BaluardCredentialProviderService` (extends
  `androidx.credentials.provider.CredentialProviderService`) with the
  `android.service.credentials.CredentialProviderService` intent action,
  `BIND_CREDENTIAL_PROVIDER_SERVICE` permission, and a `provider.xml`
  capabilities file declaring `androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL`
  (passkeys only for v1 — see non-goals).
- A non-exported trampoline activity receiving the framework's PendingIntents
  and forwarding into the app for-result (Bitwarden's
  `CredentialProviderActivity` shape, including the `exported="false"`
  extraction-protection rationale and the translucent-not-NoDisplay theme
  constraint).
- Begin-phase flows: create-query entries, get-query credential entries,
  locked-vault handling per surface, origin validation.
- Fulfillment flows in-app: passkey creation (choose existing login or new),
  assertion (credential picker when several match), ceremony execution, result
  relay back through the framework.
- Origin validation: the standard Chromium-derived trusted-browser allowlist
  format plus live Digital Asset Links checks for unprivileged native apps,
  fail-closed.
- Ceremony rework so the RP's own challenge/client-data and requested
  user-verification level drive the ceremony (§8) — the current core entry
  points generate their own challenge and hardcode `Required`, which is
  correct for our Phase-1 desktop routes but wrong for a provider.
- Settings: a row (hidden below API 34) deep-linking to the system default
  credential provider page (§10 — the service component is never toggled).

**Out of scope (explicit):**

- Password credentials through the provider
  (`TYPE_PASSWORD_CREDENTIAL`): Bitwarden ships it, but it doubles the
  fulfillment surface for no passkey value; it can ride the same service later
  as a small add-on.
- iOS (parked as G12; iOS has no third-party provider story short of an
  extension-app anyway).
- Desktop and browser-extension ceremonies (separate waves; the existing
  two-phase daemon routes remain their contract).
- Hybrid/CaBLE cross-device transport (we become a local platform
  authenticator only).
- Multi-vault passkey selection: the **active vault** answers provider
  requests for v1; the create screen names the target vault and offers an
  unlocked-vault picker (§9), but background vault-hopping is deferred.

## 3. The Bitwarden blueprint (GPL-3.0; files on `github.com/bitwarden/android`)

| Piece | Their file | Their decisions we copy |
|---|---|---|
| Service | `data/credentials/BitwardenCredentialProviderService.kt` | Thin service: all callbacks delegate to a processor. |
| Begin processor | `data/credentials/processor/CredentialProviderProcessorImpl.kt` | No active account → typed exception; **locked get → `AuthenticationAction`** ("Unlock" + PendingIntent into the app); create query reads `androidx.credentials.BUNDLE_KEY_REQUEST_JSON`; `CreateEntry` per account with `setAutoSelectAllowed(true)` and last-used = now for the active account; get query lists matched `CredentialEntry`s. |
| Biometric inside the sheet | same file, `setBiometricPromptDataIfSupported` | When unlocked, attach `BiometricPromptData` (`BIOMETRIC_STRONG` + `CryptoObject(Cipher)` from `getOrCreateCipher`) so the system sheet itself performs user verification — verified real in their source (androidx.credentials **1.6.0**; `providerevents` 1.0.0-alpha06; we pin the same line, not 1.3.x). |
| Trampoline | `CredentialProviderActivity.kt` | `exported="false"` (only our PendingIntents may launch it); stores the request, launches the main activity for-result, relays `setResult` back; translucent theme because `Theme.NoDisplay` cannot host ActivityResult. |
| Origin rulebook | `data/credentials/manager/OriginManagerImpl.kt` | Two paths on `CallingAppInfo.isOriginPopulated()`: privileged callers validated against bundled allowlists in the **Google trusted-caller format** (`fido2_privileged_google.json`: `apps[].info.package_name` + `signatures[].cert_fingerprint_sha256`); unprivileged native apps via a live Digital Asset Links fetch against `https://<rp_id>/.well-known/assetlinks.json` matching package + SHA-256 fingerprint. **[deviation]** we check the documented credential relation `delegate_permission/common.get_login_creds`, not Bitwarden's `handle_all_urls` — the app-links relation is far more widely granted and would admit apps that never consented to credential access (developer.android.com pins `get_login_creds`). |
| Ceremony | Rust SDK `Fido2CredentialStore` via `VaultSdkSource` | Crypto in Rust, Kotlin parses request JSON, resolves `Origin.Web` vs `Origin.Android(UnverifiedAssetLink)`, honors the RP's `clientDataHash` when present. |

## 4. Platform layer

**Manifest additions (androidApp):**

```xml
<service
    android:name=".passkeys.BaluardCredentialProviderService"
    android:enabled="true"
    android:exported="true"
    android:label="@string/app_name"
    android:permission="android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE">
    <intent-filter>
        <action android:name="android.service.credentials.CredentialProviderService" />
    </intent-filter>
    <meta-data
        android:name="android.credentials.provider"
        android:resource="@xml/provider" />
</service>

<activity
    android:name=".passkeys.PasskeyTrampolineActivity"
    android:exported="false"
    android:theme="@style/Theme.Translucent.NoTitleBar" ... >
    <intent-filter>
        <action android:name="xyz.actitud.baluard.ACTION_CREATE_PASSKEY" />
        <action android:name="xyz.actitud.baluard.ACTION_GET_PASSKEY" />
        <action android:name="xyz.actitud.baluard.ACTION_UNLOCK" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

`res/xml/provider.xml` declares only
`androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL` for v1.

**Dependencies:** `androidx.credentials:credentials` **1.6.x** in `androidApp`
(the line Bitwarden pins; `BiometricPromptData` and the provider surface we
use require 1.5+, not the 1.3.x the first draft named).

**PendingIntent discipline (every entry/action we hand the framework):**
`FLAG_MUTABLE` (the framework injects the request extras — immutable kills the
flow), explicit component, and a **unique requestCode per entry** so entries
never collapse. Fulfillment receives the request bundle through
`PendingIntentHandler`; the request always re-reads from the **intent, never
from in-memory state** (the trampoline's manager is a cache only — process
death must not lose or stale a request).

**Trampoline:** receives the intent actions, re-reads the request from the
intent extras (`PendingIntentHandler`), hands it to the manager as a cache,
and launches the app for-result with a route derived from the action.
`App.kt` renders the passkey screens while a request is pending; the screens
`setResult` through the trampoline and finish.

**The unlock return leg:** after the in-app unlock completes on an
`AuthenticationAction`, the result intent MUST carry
`PendingIntentHandler.setBeginGetCredentialResponse(...)` with the freshly
computed entries — finishing without it silently blanks the sheet.
**[deviation]** For a locked vault during **create**, there is no
AuthenticationAction on `BeginCreateCredentialResponse` (create entries only):
we always return the `CreateEntry` whose PendingIntent routes into the app,
and the fulfillment screen runs the unlock first. Bitwarden does the same.

**`onClearCredentialStateRequest`: complete with success, no-op** — sign-out
flows invoke it; an error response is pointless noise. (Bitwarden errors; a
clean success is strictly better.) **[deviation]**

## 5. Process model and unlock

The service runs in the **main process** (Bitwarden parity): the Begin phase
needs decrypted usernames/display names, and the main process already owns
`MultiVaultSession`. The `:autofill` process and its OOM invariant are
untouched — and the main-process choice needs no new exception to the
invariant: Argon2id runs only inside the user-initiated in-app unlock, the
same place it runs today. Fulfillment re-checks unlock state (auto-lock or
LRU eviction may fire between Begin and fulfillment; a mid-flow lock routes
back to the unlock screen, never fails silently).

Per-request user verification (UV):

- API 35+ with the vault unlocked: `BiometricPromptData` on the entry with
  `BIOMETRIC_STRONG` + `CryptoObject(Cipher)` from a **dedicated Keystore key**
  (per-use auth, timeout 0, invalidated by enrollment; `KeyPermanentlyInvalidatedException`
  recreates it; the Cipher is consumed once per request, never cached).
- API 34, or strong-biometric unavailable: the fulfillment screen runs an
  in-app `BiometricPrompt` or the master-password re-prompt — **a plain tap is
  never UV** and never sets the verified state.
- The verified state is a **single-use grant object tied to the request id**,
  created by the prompt outcome and consumed by the ceremony call — never a
  shared boolean that a stale or racing path could set (§11).

## 6. Begin-phase flows

**Create query** (`onBeginCreateCredentialRequest`): if the request is
`BeginCreatePublicKeyCredentialRequest` and its candidate bundle carries a
non-empty request JSON, return one `CreateEntry` for the active account —
built through the account-list shape so multi-vault later is additive —
`setAutoSelectAllowed(true)` per the RP request, description "The passkey will
be saved to your vault."

**Get query** (`onBeginGetCredentialRequest`): locked → `AuthenticationAction`
with the unlock PendingIntent. Unlocked → decrypt Login ciphers, run the
passkey match against the request's RP ID (`PasskeyIndex.by_rp` plus the
autofill `UriMatchStrategy` machinery for the app-origin case), and return
`CredentialEntry`s. **`private_key_missing` credentials (Bitwarden imports) are
excluded from listing** — they cannot assert. Auto-select only when exactly
one entry matches and the RP did not demand explicit selection; when the
RP's `user_verification` is `required`, the entry carries the
`BiometricPromptData` so the sheet collects UV before fulfillment.

**Cancellation:** the `CancellationSignal` is honored everywhere — the DAL
fetch (§7) runs under it, so a dismissed sheet cancels network work instead of
leaking it.

## 7. Origin validation (fail-closed)

New module `androidApp .../passkeys/OriginValidator.kt` + two bundled assets
in the standard Google allowlist format, copied from the Chromium-derived
lists Bitwarden also bundles and refreshed at release time like any vendored
data file (the assets carry a source URL and refresh date in a header
comment; a stale list means new browser builds are refused — visible failure,
logged, never a pass-through).

- **Trusted-caller model (the standard semantics, not per-RP mapping):** for
  `CallingAppInfo.isOriginPopulated()` callers, the allowlist answers exactly
  one question — *is this package + signing cert a browser we trust to assert
  web origins?* If yes, the populated origin is the ceremony origin; the
  normal WebAuthn rule (rp_id equals or is a registrable suffix of the
  origin's effective domain) does the rest. **[deviation from the first
  draft's package→RP-ID mapping, which would break the open web.]**
- **Unprivileged native apps:** the RP must publish a Digital Asset Links
  statement at `https://<rp_id>/.well-known/assetlinks.json` granting
  `delegate_permission/common.get_login_creds` to the calling package with
  the caller's signing-cert SHA-256. Fetch hardening: HTTPS only, **no
  redirects**, 5-second timeout, 64 KiB size cap, hostname must resolve
  public (no IPs, no localhost, no private ranges — SSRF guard), every signer
  in the package's signing history checked with exact package/fingerprint
  comparison. Fetch failure = refusal. Cache per (rp_id, package,
  fingerprint) for 1 hour; failures cache at most 60 seconds.
- **TOCTOU:** the check runs at **fulfillment** time too, not only Begin —
  Begin lists optimistically from cached results; fulfillment re-validates
  before any ceremony.
- **Native caller origin string:** for native flows the clientDataJSON origin
  is `android:apk-key-hash:<base64url SHA-256 of the signing cert>` with
  `androidPackageName` in the extra client data — the string RPs verify —
  while rp_id validation stays separate. `androidapp://` is never used.
- **Debug affordance:** an `http://localhost` origin is accepted only in
  debug builds (E2E, §12), compiled out of release.

## 8. Ceremony rework (core) — the load-bearing change

The shipped entry points are wrong for a provider in five ways; all are fixed
without touching the existing desktop routes:

1. **Challenge:** `run_registration`/`run_assertion` self-generate an OsRng
   challenge (ceremony.rs:214/288). A provider must sign the RP's challenge:
   for web requests the `challenge` field of the request JSON (base64url —
   byte-equality with the request string pinned by a test), for native apps
   the framework's `clientDataHash`.
2. **Client data strategies:** passkey-rs 0.5 already exposes the needed
   machinery (verified against `passkey-client/src/client_data.rs`):
   `DefaultClientDataWithCustomHash(client_data_hash)` for privileged browser
   flows (the signature covers the browser's own hash; the browser ignores the
   clientDataJSON we return) and `DefaultClientDataWithExtra(json)` carrying
   `androidPackageName` for native flows. The two functions' third parameter
   stops hardcoding `DefaultClientData`.
3. **UV level:** `UserVerificationRequirement::Required` is hardcoded
   (:229/:296). The functions take the RP's requested level; `discouraged`
   runs with no verification requirement, and the user-validation gate
   consumes a per-call `user_verified` grant (§5) instead of unconditionally
   accepting. `Required` + missing grant = the ceremony aborts.
4. **Credential selection:** `run_assertion` gains the selected
   `credential_id`, applied as the sole `allow_credentials` entry (and
   validated against the request's `allowCredentials` when that list is
   non-empty — a caller-nominated id outside the list refuses). Create
   honors `excludeCredentials`: a vault hit refuses the ceremony up front
   (no new key material is minted) and the UI offers replacement, which is an
   explicit delete-and-recreate of the old credential, never a silent
   duplicate. `pubKeyCredParams` without ES256 (-7) fails explicitly; a
   missing `rp.id` defaults to the origin's effective domain.
5. **Synced-credential flags:** Baluard vaults are git-synced and passkeys are
   usable from every enrolled device — the **synced model** applies: BE=1,
   BS=1 in `authenticatorData`, signature **counter always 0** (W3C L3
   guidance for multi-device credentials; incrementing would trip RP
   clone-detection across devices racing a sync), and
   `clientExtensionResults.credProps.rk = true`. AAGUID stays all-zeros under
   `attestation: none`. **This refines the recorded "counter max(local,
   remote)" invariant, which was written for the Phase-1 desktop model** —
   the AGENTS gotcha is updated when this ships.

**Response shape:** the provider returns `PublicKeyCredential.toJSON()`-shaped
JSON — registration: `id`, `rawId`, `type`, `authenticatorAttachment`,
`response.{clientDataJSON, attestationObject, authenticatorData, publicKey,
publicKeyAlgorithm, transports}`, `clientExtensionResults`; assertion:
`response.{clientDataJSON, authenticatorData, signature, userHandle}`. The
passkey-rs struct serialization is mapped to this shape explicitly, and a
core test verifies a ceremony output with an **independent verifier as the
oracle** (webauthn-rs or SimpleWebAuthn) — a JSON round-trip alone proves
nothing.

**UniFFI surface (pending state stays Rust-side — SEC-1):**

- `passkey_provider_register(request_json, origin, client_data_hash?) ->
   {ceremony_id, attestation_json, rp_id, user_name}` — parses the create
  options, validates UV/params, runs the ceremony, and holds the pending
  `PasskeyData` in a Rust-side ceremony cache keyed by `ceremony_id` (the
  existing `CeremonyCache` shape; TTL 300s). The private key never crosses
  FFI.
- `passkey_provider_assert(request_json, origin, credential_id,
  user_verified: bool) -> {ceremony_id, assertion_json, new_counter: 0}` —
  same shape for assertions; the counter value is recorded but stays 0 per
  the synced model.
- `passkey_store_registered(ceremony_id, cipher_id?, new_login_payload?) ->
   {credential_id}` — consumes the pending state Rust-side and persists into
  the matched Login's `fido2_credentials` or a new Login built from the
  user-confirmed payload. `passkey_consume_assertion(ceremony_id)` mirrors it
  (records the zero counter / updates nothing when 0).
  The first draft's `passkey_data` echo across FFI is gone: ciphertext in
  non-zeroizable JVM heap was the exact SEC-1 violation the Phase-1 doc
  warns about.

The two-phase daemon routes stay exactly as they are (desktop/extension
Phase-1 contract; their self-generated challenge is correct there because the
"RP" is our own finish step).

## 9. Fulfillment flows (in-app)

**Create:** trampoline → `PasskeyCreateScreen` — shows RP name/ID, the
validated origin, username, and **the target vault by name** with a picker
over unlocked vaults (defaulting to the personal vault; a shared/Space vault
is offered only if writable — a passkey must never land silently in a shared
space). Existing-login picker (matches by username and RP via `PasskeyIndex`)
or a prefilled new-login form; a `reprompt`-flagged login demands
`reprompt_verify` before the ceremony; UV per §5; `passkey_provider_register`
then `passkey_store_registered`; `setResult(RESULT_OK)` through the
trampoline. Cancel maps to the typed cancellation exception; internal faults
to the typed unknown/failed exceptions.

**Assert:** trampoline → `PasskeyAssertScreen` (skipped when exactly one
auto-selectable entry matched and the sheet already collected UV) —
credential picker when several (`private_key_missing` and
reprompt-flagged-without-verification entries excluded); origin re-validated;
`passkey_provider_assert` + `passkey_consume_assertion`; `setResult` with the
assertion JSON.

**Failure mapping:** unknown RP / no match / origin refusal → the framework's
silent no-credential result and a log line — never a reason string that
leaks validation internals to the calling app. User cancel → the typed
`*CancellationException`. Internal fault → `*UnknownException`.

## 10. Settings and in-app management

- Settings → Autofill section gains a row (API 34+ only) that **deep-links to
  the system default credential provider settings** — it never toggles the
  service component. Component-disabling was rejected: it removes Baluard
  from the user's chosen-provider registry behind a label that reads like a
  preference, and only the user can re-select a provider in system settings —
  invisible breakage for a non-technical user.
- Existing passkey display/delete/rename in CipherDetail stays. No "create a
  passkey" button inside Baluard — passkeys belong to RPs.

## 11. Security invariants

- Origin validation fails closed: no allowlist membership (trusted-caller
  model) and no DAL statement means no ceremony; fetch failures are
  refusals; the check repeats at fulfillment (TOCTOU).
- The SSRF guard on the DAL fetch (§7): hostname resolve rules, no redirects,
  size cap, HTTPS only.
- The ceremony signs the RP's challenge or clientDataHash; self-generated
  challenges never enter provider paths.
- Private keys stay encrypted under the item key, zeroized on drop, and never
  cross FFI — pending ceremony state lives Rust-side behind a ceremony id
  (§8), and the UV grant is a single-use object tied to the request id,
  cleared on every new request (no stale-flag bypass, no race).
- The Keystore `Cipher` for `BiometricPromptData` is dedicated to provider UV
  (per-use, enrollment-invalidated) and never reused for anything else.
- The trampoline is `exported="false"`; the app's passkey routes accept only
  request ids that exist in the internal manager — never intent extras as
  authority. `FLAG_SECURE` and obscured-touch filtering apply to the
  confirmation screens.
- `reprompt`-flagged logins demand `vault.reprompt_verify` before assertion
  and are excluded from auto-select.
- New passkeys never land silently in a shared Space vault (§9).

## 12. Threat model (summary)

- **Malicious native app with no DAL statement:** refused at Begin or
  fulfillment; sees only the silent no-credential result.
- **Malicious app that IS the target of a DAL statement:** it holds
  `get_login_creds` for that RP by the RP's own choice — it may request its
  own passkeys; it cannot name another rp_id (origin/rp_id rule) nor see
  entries beyond its RP.
- **Rogue browser build:** not on the allowlist → its populated origin is
  unusable; it is treated as an unprivileged caller and needs DAL like any
  app.
- **Stale/rushed allowlist:** fail-closed — a new browser build is refused
  (visible, logged) until the bundled list refreshes; never silently
  admitted.
- **Compromised calling app mid-ceremony:** it holds the response JSON by
  design (it is the RP client); it never holds key material, and UV grants
  die with the request.
- **Project-side:** the reprompt flag and the shared-vault default protect
  Baluard's own surfaces from Baluard's own convenience.

## 13. Tests

- **Core:** challenge byte-equality with the request; `clientDataHash` path
  (signature verifies against the given hash, oracle-checked); UV honored
  (`discouraged` no requirement; `Required` + no grant aborts); `None` params
  keep existing behavior (existing suite green unchanged); `excludeCredentials`
  refusal; ES256-absence refusal; BE/BS/counter-0/credProps assertions;
  response JSON verified by an independent WebAuthn verifier as oracle.
- **Origin validator (Kotlin unit):** allowlist parse (Google format),
  trusted-caller hit/miss, DAL JSON variants, the SSRF hostname rules, fetch
  failure = refusal, cache TTL, cancellation honored. The fetcher is an
  injected interface so tests never touch the network.
- **Request parsing (Kotlin unit):** create/get option extraction,
  exception mapping, `BUNDLE_KEY_REQUEST_JSON` absence.
- **UniFFI:** provider register/assert round-trips against a fixture vault;
  pending-state consumption; `needs_new_login` resolution; private-key
  absence from all returned JSON.
- **E2E (honest boundaries):** the in-app screens, the settings deep link,
  and the Begin listing are ordinary Maestro targets. The full browser loop
  on the emulator needs the default credential provider selected (adb
  `settings put secure` against the provider component — resolved at
  bring-up), an enrolled emulated fingerprint, Chrome in the bundled
  allowlist, and a local loopback test page driving
  `navigator.credentials.create/get` (the `http://localhost` origin is
  debug-only). The native-app DAL path needs a real domain + a test-signed
  app — covered by validator unit tests plus a manual handoff, stated as a
  boundary rather than forced into the harness.

## 14. Landing order

1. **Core ceremony rework + UniFFI** (§8) with tests — client-data
   strategies, challenge pass-through, UV levels, selection rules, synced
   flags, response shaping, pending-state surface.
2. **Origin validator** with bundled allowlists + hardened DAL + unit tests
   (injectable fetcher).
3. **Platform skeleton**: manifest + service + capabilities + trampoline +
   PendingIntent plumbing + Begin listing with the locked/unlocked branches —
   listing **refuses all callers** (stub origin check) until this step's
   validator integration lands in the same change, so no credential set is
   ever exposed unvalidated; the unlock return leg rides here.
4. **Fulfillment screens**: create + assert + settings deep-link row.
5. **Emulator E2E** (§13) + parity-matrix G10 closure + docs + the AGENTS
   counter-invariant update.

Each step is independently verifiable; step 3 alone already makes Baluard
visible as a credential provider — safely, because listing refuses until the
validator is wired.
