# Browser passkey interception (WebAuthn) — design proposal

Status: Implemented (shipped with the browser extension, 2026-11-15; BW claims re-verified in source 2026-11-16). Implements the "Browser extension (shipped 2026-11-15)" section of ADR 0095. Grounded in a full read of Bitwarden's shipped fido2 implementation (`apps/browser/src/autofill/fido2/`, `apps/browser/src/autofill/popup/fido2/fido2.component.ts`, `apps/browser/src/vault/popup/utils/vault-popout-window.ts`, `libs/common/src/platform/services/fido2/`).

## Goal

Baluard's browser extension must offer to use stored passkeys (assertion, `navigator.credentials.get`) and to save new passkeys (registration, `navigator.credentials.create`) on both Chrome and Firefox. Today neither browser offers either ceremony. The vault, daemon routes, and signing already exist; only the browser half is missing.

## How Bitwarden does it

Re-verified against bitwarden/clients @ 4d61897 (2026-11-13). Bitwarden runs a pipeline; each layer has exactly one job.

**1. Page script (MAIN world).** An IIFE (`fido2-page-script.ts`) binds the native `navigator.credentials.create/get`, then replaces them with proxies. Non-`publicKey` calls pass through untouched. Proxied calls serialize the options to plain JSON (BufferSources to base64) and send them over a `window.postMessage` bridge, waiting on a per-request `MessageChannel` port. Responses come back as base64 strings and are rebuilt into `PublicKeyCredential` objects via object literals plus `Object.setPrototypeOf(credential, PublicKeyCredential.prototype)` so site-side `instanceof` checks pass, with `getPublicKey()`, `getTransports()`, `getClientExtensionResults()`, and `toJSON()` implemented by hand. Gates: `text/html` only, `https:` or `http://localhost` only, bail in sandboxed (opaque-origin) iframes, rehydrate `DOMException("NotAllowedError")` that JSON stripping flattens, restore natives on a Disconnect request (extension reload/unload). If the browser lacks WebAuthn entirely it polyfills `PublicKeyCredential` and reports `isUserVerifyingPlatformAuthenticatorAvailable() === true`. If the site requests `authenticatorAttachment: "platform"` and the browser has a platform authenticator, the proxy still answers — but on `fallbackRequested` errors it waits for window focus (Safari rule) and falls through to the native call, so hardware keys and OS passkeys keep working.

**2. Conditional mediation race.** For `get({ mediation: "conditional" })` the page script races Bitwarden's answer against the browser's own conditional autofill (`Promise.race` of two independent AbortControllers, both aborted when one settles). Bitwarden errors in this mode are swallowed, never surfaced. The inline-menu entry path is: a conditional request creates an "active request" in the background carrying silently discovered credentials; the overlay background exposes them to the inline menu; the menu renders passkey rows on fields it has marked (autocomplete `webauthn` detection); picking one sends `{ type: Continue, credentialId }` into the active request, which narrows `allowCredentials` to that credential and resumes the assertion with `assumeUserPresence: true`; a `webRequest.onCompleted` watch then closes the menu and aborts the pending request if the login response status is a failure.

**3. Content script (isolated world bridge).** `fido2-content-script.ts` mirrors the same protocol gates, forwards page-world messages to the background over `chrome.runtime.sendMessage`, and — critically — stamps every request with `origin: location.origin` and `sameOriginWithAncestors: self === top` from the isolated world, where the page cannot tamper with them. It also enforces the Permissions-Policy gate (`publickey-credentials-create/get`) from the isolated world, and maintains a long-lived `runtime.connect` port that the background uses to push aborts and inline-menu updates; port disconnect cascades into page-script destroy.

**4. Background (the WebAuthn client).** `fido2-client.service.ts` implements the W3C client algorithm: validate `sameOriginWithAncestors`, default `rp.id` to the origin hostname, require https (localhost exempt), verify `rp.id` is the origin's registrable-domain suffix (tldts), filter `pubKeyCredParams` to ES256 (`NotSupportedError` if none), clamp timeouts (UV: 30–600s default 300s; non-UV: 30–180s default 120s), build `collectedClientData` (`{type: "webauthn.create"|"webauthn.get", challenge, origin, crossOrigin}`) and its SHA-256 hash **in the extension**, and hand the authenticator a normalized call. Registration honors the `requireResidentKey` string quirk; assertion refuses (`FallbackRequestedError`) when every `allowCredentials` entry specifies only non-internal transports — the spec's "no authenticator will become available" check, letting the browser reach the hardware key. One active request per tab; per-request abort registry; tab and window are re-focused after the ceremony.

**5. Authenticator (the vault).** `fido2-authenticator.service.ts` does vault work: sync-if-stale before checking `excludeCredentials` (skip sync when last sync < 30 min), reject the ceremony when the new credential ID already exists (`informExcludedCredential`), find assertion candidates by `allowCredentials` or by `rpId` (sync again only when candidates exist but any has `counter > 0`), and decide the picker: `requireUserVerification || !assumeUserPresence || >1 candidate || master-password-reprompt` → show UI, else take the single credential silently. Signing: ECDSA P-256 over authData + clientDataHash, authData flags UP always and UV per grant, counter stays 0 for synced credentials (multi-device L3 guidance), increment-and-persist only when already non-zero. No match → `informCredentialNotFound` → `NotAllowedError`.

**6. UI.** Modal ceremonies (registration confirm, credential pick, not-found/excluded notices) render in a **popout window** anchored to the tab, driven by runtime messaging with a session id; closing the window aborts with `fallbackRequested`, which makes the page script hand the ceremony to the browser. Unlock is driven through the same popout. Single-credential conditional assertions skip UI entirely.

**7. Injection.** No `web_accessible_resources`. MV3: two `scripting.registerContentScripts` entries — the page script with `world: "MAIN"`, the bridge isolated, both `document_start`, `https://*/*` + `http://localhost/*`, `allFrames: true` — registered dynamically when the `enablePasskeys` setting turns on (and the vault has an unlocked session), unregistered when it turns off; port disconnect then restores natives in already-loaded tabs. Existing tabs get `scripting.executeScript({world: "MAIN"})`. MV2 uses a script-tag append shim; irrelevant for Baluard (MV3 both targets).

## What Baluard already has

The daemon side is done (ADR 0095, accepted and shipped):

- Vault model: `LoginData::fido2_credentials: Vec<PasskeyData>`, Bitwarden-importable including private keys, ES256, `fmt: "none"`, zero AAGUID.
- **Provider ceremony surface** (built for Android, in `state.rs`): `passkey_provider_register(request_json, origin, client_data_json_b64?, client_data_hash_b64?, user_verified)`, `passkey_provider_assert(request_json, origin, credential_id, client_data_json_b64?, client_data_hash_b64?, user_verified)`, `passkey_store_registered(ceremony_id, cipher_id?, new_login?)`, `passkey_consume_assertion(ceremony_id)`, plus `passkey.list(rp_id?)`. These take the RP's own options JSON and the caller-built clientDataJSON — the exact Bitwarden client/authenticator split — pin assertions to one credential, hold fresh keys Rust-side behind the ceremony id, return `PublicKeyCredential.toJSON()`-shaped JSON, keep `private_key`/`prf_key`/PKCS#8 off IPC, and update counters only internally (`consume_assertion` takes no client-supplied counter).
- Trust boundary already ruled: browser clients are untrusted and may never supply authoritative credential data or counter values. The desktop two-phase routes (`finish_assert` echo hole) stay desktop-only and off the bridge allowlist.
- NMH + pairing + token allowlist: `BRIDGE_ALLOWED_ACTIONS` in `crates/baluard-core/src/bridge/token.rs` currently carries no `passkey.*` route — the deliberate gate this feature opens.

## Architecture

Adopt Bitwarden's layer split with Baluard's trust rules. Four new extension pieces, one NMH surface, zero daemon ceremony changes.

### Components

| Piece | World | Job |
|---|---|---|
| `passkey-page.js` | MAIN, document_start | Wrap `navigator.credentials.create/get`; postMessage bridge with per-request MessageChannel; rebuild `PublicKeyCredential` with prototype fixes; conditional race; fallback on `fallbackRequested`; destroy on disconnect |
| `passkey-bridge.js` | isolated, document_start | Same protocol gates; stamp `origin` + `sameOriginWithAncestors` from the isolated world; forward to SW; runtime port for push (aborts, inline-menu candidates); restore page natives on port disconnect |
| `background.js` (new module) | SW | WebAuthn client: rpId validation, ES256 filter, timeout clamp, clientDataJSON build + hash; NMH calls; per-tab active-request registry; picker orchestration; setting-driven script registration into all tabs |
| `passkey popout` | extension page | Registration confirm ("save to which Login?"), assertion pick when >1 candidate, not-found/excluded notices, unlock leg. Reuse the popup app with a `#/passkey` route in a window anchored to the tab |
| `inline.js` (extend) | isolated | Conditional mediation: render passkey rows (name + username, ring already exists as pattern) into the existing dropdown for fields with `autocomplete="webauthn"`; picking sends Continue into the active request |

### Injection and the setting

`enablePasskeys` setting, default **off** (ADR: opt-in like 1Password/Bitwarden; a WebAuthn-intercepting extension is a fingerprinting surface). While on AND paired: `scripting.registerContentScripts` — page script `world: "MAIN"` + bridge isolated, `document_start`, `https://*/*`, `http://localhost/*`, `xml` excluded; then inject into all open tabs. While off: unregister + disconnect ports (page scripts self-restore natives). Badge shows a visible "PK" indicator while interception is active (ADR requirement). Gate the whole feature on `browser.scripting.registerContentScripts` + MAIN-world support (Firefox 128+); without it the toggle stays disabled with an explanatory hint.

### Message protocol

Page ⇄ bridge: Bitwarden's exact shape — `{SENDER: "baluard-webauthn", senderId, type, data}` over `window.postMessage`, per-request `MessageChannel`, `isTrusted` + origin + sender-tag checks, AbortRequest over the port, ErrorResponse with own-property error serialization. Bridge ⇄ SW: `passkey.registerRequest`, `passkey.getRequest`, `passkey.abortRequest`. SW ⇄ NMH: `passkey.list`, `passkey.provider_register`, `passkey.provider_assert`, `passkey.store_registered`, `passkey.consume_assertion`.

### Registration flow

Page calls `create()` → page script serializes options → bridge stamps origin/sameOrigin → SW: feature enabled? locked vault → trigger unlock leg; validate origin https (localhost exempt), `rp.id` coarse-check (host equality or dot-boundary suffix — the daemon's `RpIdVerifier` remains authoritative), filter algs to ES256, build `collectedClientData` + SHA-256 → `passkey.provider_register(request_json, origin, client_data_json_b64, client_data_hash_b64, user_verified)` with the flag decided by the SW (`session.requiresUv`, never page-echoed) → popout confirm: attach to an existing Login (search list) or create `new_login` → `passkey.store_registered(ceremony_id, cipher_id|new_login)` → return the `toJSON()`-shaped attestation → page script rebuilds the `PublicKeyCredential`. `excludeCredentials` overlap → daemon returns the conflict → informational popout, then `NotAllowedError`. New-credential creation happens daemon-side inside `provider_register`; the browser never sees or echoes key material.

### Assertion flow (non-conditional)

`get()` → SW validations as above → `passkey.list({rp_id})` → 0 candidates: informational popout → `NotAllowedError`. 1 candidate + no UV needed: sign immediately. Otherwise popout picker (or reuse inline dropdown) → `passkey.provider_assert(request_json, origin, credential_id, client_data_json_b64, client_data_hash_b64, user_verified)` → `passkey.consume_assertion(ceremony_id)` (counter persistence, no client-supplied counter) → rebuild `PublicKeyCredential`. `allowCredentials` entries that match nothing in the vault but the request is satisfiable by a hardware key (all non-internal transports) → `fallbackRequested` → native ceremony, matching Bitwarden's spec-step-20 behavior.

### Conditional mediation

`get({mediation:"conditional"})` → SW registers a per-tab active request with `passkey.list(rp_id)` results (only when unlocked; re-list after unlock, Bitwarden's Refresh loop). The inline dropdown renders those as passkey rows on qualifying fields (top frame, `autocomplete="webauthn"` detection in the existing collector). Pick → SW pins the credential and finishes the assertion (UV granted by the pick itself, `assumeUserPresence` semantics). Race semantics stay in the page script: if the browser's native conditional sheet wins, Baluard's pending request is aborted silently. After the chosen fill posts, watch the next response and close the menu (Bitwarden's `onCompleted` pattern is optional polish for v1; the menu already closes on navigation).

### Trust boundary (hard rules)

1. Origin and `sameOriginWithAncestors` come from the isolated-world bridge and `sender` metadata in the SW — never from page-supplied data.
2. `rp.id` vs origin is validated Rust-side by the existing verifier; the SW check is coarse pre-filtering only.
3. No counter, credential ID, or key material is ever client-echoed: assertions pin by `credential_id` into `provider_assert` and the result flows from the ceremony cache; registrations stay behind the ceremony id until `store_registered`.
4. `user_verified` is a SW-side grant (unlock happened, picker confirmed) — the page cannot assert it.
5. Bridge allowlist gains exactly: `passkey.list`, `passkey.provider_register`, `passkey.provider_assert`, `passkey.store_registered`, `passkey.consume_assertion`. The desktop `finish_assert` echo hole stays out of browser reach; the `vault.update` fido2 field gate stays intact (saves ride the dedicated provider route).
6. The vault.update-style metadata projection for `passkey.list` carries only names/ids/rp/username/favorite/counter/`private_key_missing` — never key bytes.

### v1 scope cuts (deliberate)

- Top frames only. Cross-origin iframe ceremonies (payment frames, `allow="publickey-credentials-get"`) fall back to the native browser path via `sameOriginWithAncestors=false`. Bitwarden's Permissions-Policy subsystem (webRequest header parsing + iframe `allow=` scraper, ~15 files) is the largest non-essential chunk of their implementation; defer to a follow-up ADR when cross-origin RP frames matter.
- No PRF (`hmac-secret`), no largeBlob, no cross-device QR assertion (ADR 0095 already defers those).
- No enterprise attestation.

## Testing plan

- Unit (vitest): option serialization (BufferSource/algorithm-string quirks), `PublicKeyCredential` reconstruction prototype checks, SW rpId pre-check + origin rules, clientDataJSON build, active-request Continue/Abort lifecycle, allowlist projection shape.
- Daemon (cargo): provider routes already covered; add the allowlist membership tests for the five new actions and a negative test that `finish_assert` stays bridge-refused.
- E2E: extend the extension harness with a local WebAuthn RP fixture (a small `@simplewebauthn/server` express app on the harness's local origin, or a static page driving the platform authenticator is not enough — the harness needs a real RP verifier): Leg C registers a passkey through Baluard on the fixture RP, asserts the stored credential, and asserts the fallback path on a hardware-key-only request. Reuse the sealed harness conventions (deterministic EXT_ID, `app.baluard.browser` manifest, kept-sandbox debugging).
- Test seams: `inline.js` deliberately exposes `window.__pkRowIds` (credential ids from the last dropdown render, refreshed on every render because node expandos do not survive re-renders) and `window.__baluardPasskeyPickFirst()` (invokes `requestPasskeyFill` on the first rendered id, bypassing the click event, whose trusted-click delivery into the closed shadow root proved flaky under the harness). Both live in the isolated world; the harness reaches them via CDP `Runtime.evaluate` on the content script's execution context. They carry no feature behavior.

## Work breakdown (ordered, each independently shippable)

1. Daemon: add the five actions to `BRIDGE_ALLOWED_ACTIONS` (+ tests). Review `provider_*` payloads for exact JSON shapes the SW will send.
2. SW: passkey module — settings toggle, script registration lifecycle, WebAuthn client (validation, clientDataJSON, timeouts), NMH calls, active-request registry, popout orchestration.
3. Page script + bridge + messenger (ported from the Bitwarden shape, tightened to Baluard gates), with unit tests.
4. Popout `#/passkey` route (confirm/pick/not-found/unlock) on the existing popup app.
5. Conditional mediation: inline dropdown passkey rows + active-request Continue wiring.
6. Chrome build + harness Leg C; then Firefox (128+ gating) and harness Firefox leg.
7. Docs: ADR 0095 status flip to "browser interception shipped", settings docs, threat-model note on the new allowlist surface.
