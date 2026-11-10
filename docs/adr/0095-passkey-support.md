# ADR 0095. WebAuthn Passkey Support

> Status: Accepted (2026-09-28). The model was settled on 2026-06-12 (passkeys embedded in `LoginData::fido2_credentials`, no standalone cipher kind). Implemented: schema, Bitwarden import and export, ceremony module, seven daemon routes, CLI, desktop list and management, and the Android credential provider over UniFFI. Open: browser extension interception (not started), iOS provider, cross-device QR assertion, the remaining trust-boundary hardening listed under "Open items".

## Context

Baluard must store, generate, and serve WebAuthn passkeys across desktop, browser, and mobile clients. Baluard is a software authenticator that lives inside the user's encrypted vault. It is not a FIDO2 server, and it has no cloud. Passkeys are the modern replacement for password autofill, and being a credible autofill vault on iOS, Android, and the browser requires acting as a WebAuthn authenticator. Mobile and browser clients are the primary delivery surface. The desktop app is the local orchestrator that talks to the daemon.

Passkeys require signing during WebAuthn registration and assertion. A credential must be usable on more than one Baluard device, which requires its private key to sync as encrypted vault data. Imported passkey metadata may lack private key material and therefore cannot necessarily be used for assertions. Private keys must remain encrypted in the vault, and the signing path must remain in Rust.

WebAuthn browser integration has a different trust boundary from the same-process desktop flow. Browser clients are untrusted and must not be allowed to supply authoritative credential data or counter updates to the daemon. Mobile operating systems restrict background processes, so mobile must not depend on a long-running daemon.

### Specification notes that drive the design

- Two ceremonies, both client-driven: registration (`navigator.credentials.create`, result is an attestation object, public key, and credential ID) and assertion (`navigator.credentials.get`, result is a signature over the challenge and authenticator data).
- Complexity lives in COSE key encoding, the binary AuthenticatorData layout, CTAP2 canonical CBOR, base64url without padding everywhere, and attestation statement formats. Baluard skips attestation verification: `fmt: "none"` is acceptable for a self-attested software authenticator, and consumer relying parties (GitHub, Google, Cloudflare) accept it. Enterprise relying parties that enforce attestation are not v1 users.
- Algorithms: ES256 (P-256, COSE -7) is the baseline and the only algorithm the chosen library supports. EdDSA (-8) is desirable later. RS256 and PS256 are legacy and add little for a software authenticator that controls its own keys.
- Credential IDs are opaque, at least 16 bytes with 100 bits of entropy. The AAGUID identifies the authenticator model. The RP ID must equal the origin's effective domain or a registrable domain suffix of it, and is stored per credential.
- Passkeys are discoverable (resident) by default, so non-discoverable credentials are not supported.
- The sign counter is a monotonic clone-detection value. The PRF extension (`hmac-secret`) is a stretch goal.

### Reference architectures

Bitwarden stores passkeys as `Login` ciphers with an optional `fido2Credentials` array (PM-3807 removed its earlier standalone key type). It stores the full credential key pair in the cipher: Bitwarden is a software authenticator, not a wrapper for the platform one. An earlier version of this paragraph claimed it stored only the public key and relied on a platform authenticator (TPM, Secure Enclave, Keychain) for the private key; that was wrong, and its plaintext JSON export proves it, carrying the private key in `keyValue` — which is how KeePassXC imports Bitwarden passkeys as working credentials (corrected 2026-11-10). Its extension bridges page, background, and native messaging. Bitwarden covers two cases: passkey login as a 2FA replacement and stored passkeys as vault items. Baluard implements the second. The first is a possible later feature (see `docs/security/2fa-analysis.md`).

Vaultwarden uses `webauthn-rs` as a relying-party server: it accepts registrations and verifies assertions. Baluard needs the authenticator side, for which there is no first-party `webauthn-rs` crate.

| Aspect | Relying-party server | Baluard |
|--------|----------------------|---------|
| Role | Verifies credentials | Authenticator |
| Storage | Plaintext database row | Encrypted inside the vault cipher envelope |
| Private key | In the user's hardware authenticator | Held in daemon memory only during a ceremony, persisted only as an encrypted private key in the cipher |
| Multi-device | One credential per user, used for 2FA | One credential per relying party and account, synced through git |
| Attestation | Server validates packed or TPM formats | Self-attested `none` |

## Decision

### Library

Use `passkey` 0.5.x as the authenticator library and `webauthn-rs` 0.5.x for relying-party challenge generation and verification (in tests). The evaluation and its findings are recorded in ADR 0094. Support ES256 only. Emit `fmt: "none"` attestation with the zero AAGUID; Baluard does not validate attestation certificate chains for software passkeys. Registering AAGUIDs with the FIDO Alliance Metadata Service is deferred to polish.

### Data model

Represent passkeys inside `LoginData::fido2_credentials: Option<Vec<PasskeyData>>`. Do not add a standalone `CipherKind` or `CipherType` variant. The field uses `#[serde(default, skip_serializing_if = "Option::is_none")]`, so existing Login ciphers without it deserialize unchanged and no migration is needed in either direction. A Login may contain multiple credentials (one Login, two devices, two passkeys). This keeps account metadata and passkeys grouped, avoids a cipher per credential, preserves one entry per relying party in the UI, and matches Bitwarden's shape for interoperable import and export. An absent value is the canonical no-passkeys state. Removing the final credential returns the field to `None` and never stores an empty vector. A Login can hold a password, URI, TOTP seed, and passkeys without changing its cipher kind.

`PasskeyData` fields: credential ID (base64url), key type, algorithm, curve, COSE key material in `key_value`, RP ID and name, user handle (bytes) and user name and display name, counter (u32), AAGUID, optional PRF key, optional encrypted private key, `private_key_missing`, optional `linked_login_id`, creation date (unix seconds), and optional per-credential `name`. `linked_login_id` links a passkey created from an existing Login detail view for UI grouping and is `None` when created standalone. The per-credential name can identify a device (for example "YubiKey 5C" or "iPhone 15") and falls back to the RP name or RP ID.

Discoverability is not a field. It is an invariant enforced by always sending `residentKey: "required"` and `requireResidentKey: true` in registration options, together with `userVerification: "required"`. A stored boolean would describe something that cannot vary.

Private key storage. Bitwarden stores the credential's private key in its vault cipher just as Baluard does; the earlier framing that Baluard must store it only because Bitwarden could not was wrong (corrected 2026-11-10). The private key is encrypted under the cipher item key inside the envelope, consistent with TOTP secrets and SSH private keys. It is decrypted only for the duration of a ceremony into zeroizing memory, never cached across calls (if the daemon process is dumped, only the current call's key is exposed, not the fleet), and never sent over IPC. `PasskeyData` has a manual `Zeroize` and `Drop` that clear only `private_key` and `prf_key`, and the vault handle's cipher zeroize block clears them on cipher drop. The key is rejected from IPC payloads and responses.

Rejected alternatives for key storage and counters: deriving the key deterministically from the master password and cipher ID (no wrap needed, but it ties the credential to the password and diverges from the existing SSH and TOTP pattern); storing the counter in plaintext cipher metadata (faster, but the counter is part of cipher authenticity and must not be tamperable, so it stays inside the authenticated encrypted envelope).

Epoch rotation re-encrypts Login envelopes like every other cipher, and passkey credentials must survive it. Rotation must never skip Login ciphers or every passkey is silently lost; a regression test asserting that `fido2_credentials` survive `revoke_device_and_rekey()` is a required guard. Size: a passkey-only Login fits the Xs tier and a Login with password and passkey fits S, since the private key is 32 bytes and metadata is well under 1 KB per credential.

### Import and export

Bitwarden exports include the private key: `keyValue` is base64url PKCS#8 DER holding the credential's P-256 key pair (an earlier version of this section claimed exports contain no private key and marked every import view-only; corrected 2026-11-10 and the importer now decodes it). `keyValue` decodes into `private_key` as a private COSE key — the format the ceremony path stores and parses — and the credential imports fully usable, with signing, sync merge, and epoch rotation behaving like a vault-created passkey. The nil AAGUID is kept: BW does not export which authenticator produced the credential. Credentials whose `keyValue` is absent, malformed, or not a P-256 key stay metadata-only, marked `private_key_missing`, viewable but unable to sign until re-registered; Ed25519 passkeys land in that bucket while Baluard is ES256-only. Import accepts `user_handle` in both URL-safe-no-pad and standard base64 and parses ISO 8601 dates (a hand-written civil-date conversion, no `chrono` dependency); password history dates use the same parser. Export emits Bitwarden's `fido2_credentials` shape for round trips: `user_handle` as URL-safe base64 without padding, `creation_date` as ISO 8601, and `key_value` always included — public COSE material only for Baluard-created credentials, Bitwarden's original PKCS#8 string for imported ones, so the private key survives a round trip.

### Counter policy

Use the existing `update_cipher` path for counter updates. A dedicated counter-increment route was rejected: the counter lives inside the encrypted envelope, so the full cipher must be decrypted, updated, re-encrypted, and written anyway, and a separate route would be a race magnet and an asymmetric API surface.

Synced and provider credentials follow the W3C Level 3 multi-device guidance: backup-eligible and backup-state flags set, the counter pinned to zero and never incremented. Legacy device-bound credentials keep a counter, and `passkey.finish_assert` stores `max(stored, new)`. The spec only requires the new counter to exceed the stored one, so `max` never regresses. The residual risk is inherent to every synced passkey implementation (Apple, Google, 1Password share it): two devices that both assert before synchronizing can emit equal counters and one assertion may be rejected by the relying party. FIDO Alliance guidance now recommends relying parties accept a zero counter and not reject non-monotonic counters without other cloning evidence, and the major consumer relying parties follow it.

### Daemon routes

All seven routes are token-gated. Payloads are JSON strings inside `GatewayRequest.payload`.

| Action | Purpose |
|--------|---------|
| `passkey.challenge_register` | Takes `{rp_id, rp_name, user_name, user_display_name, user_id}` and returns the creation options plus a ceremony ID. Registration options always set `authenticatorSelection` to resident-key required and user verification required. The response redacts key material. |
| `passkey.finish_register` | Consumes the ceremony and saves the credential into an existing Login for the RP or a new Login. |
| `passkey.challenge_assert` | Takes `{rp_id, allow_credentials?}` and returns the request options plus a ceremony ID. |
| `passkey.finish_assert` | Updates the counter inside the Login's `fido2_credentials`. |
| `passkey.list` | One record per credential across all Logins, with `credential_id`, RP and account metadata, `name`, counter, `private_key_missing`, `login_name`, `has_password`, and `pk_name`, so the UI can tell a linked credential from a standalone one. It filters to Login ciphers before decrypting, avoiding a full decrypt pass on every list call (the plan claimed about a 5x speedup on a 500-entry vault). |
| `passkey.delete` | Takes `{cipher_id, credential_id}` and removes only that credential. A Login that still holds password, URI, or TOTP data is preserved. If the removed passkey was the Login's only content, the empty Login is deleted. A type guard refuses non-Login ciphers. |
| `passkey.rename` | Takes `{cipher_id, credential_id, name}` and updates `PasskeyData.name`. It never renames the Login, and a type guard refuses non-Login ciphers. |

Ceremony state is in memory, keyed by a random 256-bit ID drawn from a CSPRNG (hex-encoded, which exceeds the 128-bit minimum the design asked for), consumed on finish, expires after 300 seconds, and is capped at 64 pending ceremonies per vault with FIFO eviction as defense against memory exhaustion from authenticated clients. The 300 second TTL matches the browser's WebAuthn user-interaction timeout; 60 seconds is too short for a user who fails a biometric once and retries. Validation runs before the state is consumed, so a locked vault or malformed payload does not destroy a pending ceremony whose credential the relying party has already registered. `finish_assert` is in the cover-commit mutation set. `CeremonyState` has variants for registration, assertion, provider registration, and provider assertion, with a manual `Debug` that never prints key material.

The CLI exposes `baluard passkey list [--rp-id]`, `delete`, and `rename`, in daemon and direct mode, with `--credential-id` required for delete and rename. `baluard get` shows a Login's passkeys.

### User verification

Registration options require user verification. No user verification means no signing. Platform integrations provide verification where available (Touch ID, Windows Hello, Android `BiometricPrompt`). On Linux there is no platform path, so a fresh master-password verification is the substitute, with a fresh KDF check and not a cached unlock, and the reduced convenience is documented. User validation goes through the library's asynchronous `UserValidationMethod` (ADR 0094).

### Trust model: two phases

The same-process desktop client is trusted in Phase 1. The browser extension is untrusted, so a structural fix is a mandatory prerequisite before any browser ceremony ships (finding SEC-1):

- `finish_register` and `finish_assert` must not trust client-supplied data. `CeremonyState` must carry the computed results: the registration state holds the new `PasskeyData`, and the assertion state holds the credential ID, the new counter, and the RP ID, so finish verifies that the credential belongs to the ceremony's RP. Without this, a client can forge the counter (a `u32::MAX` denial of service) or update a credential of another relying party.
- The ceremony API must split for the browser: `challenge_register` returns challenge bytes to the browser, the browser calls `navigator.credentials.create`, the extension feeds the result to the daemon, and `finish_register` accepts the `PublicKeyCredential` JSON; assertion is symmetric, using the library's relying-party verification primitives. The Phase 1 runners that execute the whole ceremony internally cannot serve a browser as they are.
- `passkey.list` needs a `list_ciphers_by_type` batch method, because browser autofill triggers on every page load.
- `key_value` holds the public COSE key without the private scalar. The field name stays `key_value` for Bitwarden wire compatibility; the private COSE key remains only in `private_key`. This was fixed on 2026-11-02.
- COSE key bytes must be zeroized (`coset::CoseKey` lacks `Zeroize`) or the upstream gap tracked.

Current code. Registration is fixed: the fresh credential stays behind the ceremony ID, the challenge response redacts key material, and `finish_register` reads the passkey from the cache and rejects a mismatched credential ID. Provider ceremonies (below) also hold results server-side. Assertion is not fixed: `passkey.finish_assert` still takes `credential_id` and `new_counter` from the request, and the code marks this as Phase 1 only. The other trust-boundary items above remain open.

### Browser extension (not started)

The extension is opt-in (an `enable_passkeys` setting, the same model as 1Password and Bitwarden) and visibly indicates when interception is active, because an extension that intercepts WebAuthn on every page is a fingerprinting and tracking concern. The page script replaces `navigator.credentials.create` and `get` with proxies and runs in the main world through `chrome.scripting.executeScript({ world: "MAIN" })`. A `web_accessible_resources` script tag is rejected: strict-CSP sites such as GitHub and banks block it, while extension-owned scripts injected into the main world are exempt from page CSP. Pick one mechanism, not both, and declare no `web_accessible_resources` for the page script. A content script bridges page script and background, the background routes to the native messaging host, and a popup provides the explicit picker (`PasskeyUseModal`).

Conditional mediation is a hard requirement. Modern sites call `get({ mediation: "conditional" })` to request passkeys as inline autofill in the username field, not as a popup. The page script must detect that mode and surface matching passkeys into the autofill suggestion list (the Bitwarden `fido2-autofill-utils` pattern: pre-filter by RP ID and username and add autocomplete entries). Without it Baluard passkeys will feel broken on every modern site. Permissions: `nativeMessaging`, `<all_urls>`, `tabs`, and `storage`. The native messaging host is the existing `baluard-nmh` (ADR 0092), which forwards to the token-gated daemon. The existing bridge allowlist does not include any `passkey.*` route, so browser passkeys need a deliberate allowlist change.

### Mobile

Mobile runs `baluard-core` in-process through UniFFI and keeps its own git-synced vault copy. iOS background-execution limits make a long-running socket daemon infeasible, and Android is no better. Kotlin and Swift are glue only: they query the FFI for matching passkeys, format entries for the platform, and forward the system callback to the FFI for signing. The ceremony never leaves Rust. The earlier plan asked for a synchronous UniFFI interface because signing is CPU-bound; ADR 0089 now maps async functions to Kotlin suspend and Swift async over one shared runtime, and the provider ceremonies are async methods.

Android is implemented: `BaluardCredentialProviderService` (API 34 and later) lists passkeys from the process-wide shared vault session, so the sheet only shows credentials from a vault the user unlocked in the app, with an unlock return leg that re-lists after unlock. Callers are admitted by a fail-closed origin validator: bundled trusted-browser allowlists for privileged callers, live Digital Asset Links for unprivileged native apps, and a refusal that is silent (no origin, no entry). Ceremonies run through `MobileVault.passkey_provider_register`, `passkey_provider_assert`, `passkey_store_registered`, and `passkey_consume_assertion`; the registration result stays Rust-side behind a ceremony ID until `store_registered` consumes it, and an assertion narrows the index to the one selected credential. iOS `ASCredentialProviderViewController` integration remains unbuilt.

### Cross-device assertion (not started)

The FIDO hybrid transport needs a cloud relay, which Baluard does not have. Considered: (a) a simplified local-only hybrid over BLE advertisements, which works only when both devices are BLE-reachable; (b) a one-time QR pairing between phone and desktop extension. Option (b) is the chosen MVP: the phone shows a QR code carrying a one-time pairing token, the desktop extension scans it, they set up a local encrypted channel, and the assertion completes (discoverable credentials: the phone returns candidates for the RP, the user picks one and signs). No cloud relay.

Scope limit, which must appear in user-facing documentation: the path works only when the Baluard browser extension is installed and active on the desktop browser. It does not work with native OS passkey dialogs (Chrome's Android passkey sheet, Safari's iOS sheet), which bypass the extension and require the relay Baluard does not implement. Mobile users who tap a native passkey prompt will not see Baluard in the system picker. Mitigations for pairing abuse: the QR code must be scanned within 30 seconds, pairing codes are single use, and biometric verification is required on both ends. Mobile-native autofill uses passkeys already synced to the device.

### Telemetry

Passkey operations add no telemetry. Debug-level logs are enabled only when `BALUARD_DEBUG=1`.

## Consequences

Embedding credentials in Login data supports multiple passkeys for one account, preserves existing cipher organization, and allows normal envelope encryption, sync, and epoch rotation. Private keys remain protected by item keys and are redacted from IPC payloads. The counter is part of the authenticated envelope and cannot be tampered with as unauthenticated metadata.

The counter policy prevents stored counters from regressing, but simultaneous assertions before synchronization may be rejected by a relying party. Imported metadata without private keys is viewable but not usable for assertions.

Browser interception requires broad origin access and creates fingerprinting risk, so it must stay disabled until the user opts in and sees a visible active indicator. Conditional mediation is required for modern autofill behavior. Cross-device QR pairing is limited to the Baluard extension and does not integrate with native OS prompts.

Mobile integrations depend on platform credential APIs, and the Android provider needs API 34. Linux verification costs an extra password prompt. Out of scope: passkeys as vault-unlock second factors (a separate plan), a passkey server or relying-party service, FIDO1 and U2F migration, user-to-user passkey sharing, custom RP ID overrides, attestation certificate verification, and federated sync between different Baluard vaults (git sync already covers one vault).

### Phase status

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Schema, Bitwarden import, library spike (ADR 0094) | Complete (2026-06-12) |
| 1 | Ceremony module, seven daemon routes, CLI, in-process relying-party test harness | Complete; desktop list and management in the entry detail view |
| 2 | Browser extension: ceremony redesign, SEC-1, page script, conditional mediation | Not started |
| 3 | Mobile: Android credential provider | Android shipped, iOS not built |
| 4 | Cross-device assertion over QR pairing | Not started |
| 5 | Polish: PRF extension, large blob, AAGUID rotation and metadata service submissions, passkey export from other ecosystems | Not started |

### Open items

- Assertion trust boundary: `passkey.finish_assert` trusts the echoed credential ID and counter, and the SEC-1 ceremony split for browsers is not done.
- Counter merge. The plan called for a `max(local, remote)` merge in the sync engine. The three-way merge in `conflict.rs` keys passkeys by credential ID and treats a differing counter as an edit (both edited: keep local and flag a conflict); no counter-specific `max` was found there. Synced credentials keep counter zero so it is mostly moot, but legacy device-bound counters are not covered by a dedicated merge rule.
- Desktop UI: the entry detail view lists, renames, and deletes passkeys. A create modal and an assertion picker were planned but are not present.
- Linux user verification: the master-password substitute is a decision. The daemon's `BaluardUserValidation` grants without prompting, so the re-prompt is not enforced at that layer.
- Test gaps to close before the browser phase: finish with a wrong ceremony type; finish after expiry; malformed COSE bytes in `private_key` (currently skipped silently, should surface an error); duplicate registration for the same RP and user (`exclude_credentials` behavior); `new_counter` equal to `u32::MAX` after the SEC-1 fix; rename on a non-passkey cipher; a daemon-level challenge-to-finish round trip through `VaultState`; epoch rotation preserving passkeys; counter merge across sync. Also planned: FIDO test vectors, property tests for COSE and AuthenticatorData, and a coverage gate. The earlier plan targeted 80 percent.
- Interop risk: ceremony bugs against real relying parties. The local `webauthn-rs` harness is the acceptance test. Manual checks on GitHub, Google, and Cloudflare are smoke tests only.
- Ed25519 support depends on the upstream library.
- Provider detail for the Android service is specified in source comments that cite a section of a document named `ADR 0089-passkeys`, which does not exist as a record. This ADR is the home for that design. A dedicated record for the provider origin rules and ceremony flow would be worthwhile.

### Source versus plan differences

Source was preferred over the plan text. Differences: the plan's phase 2 ceremony prerequisites are partly done (registration) and partly open (assertion, COSE zeroize, batch listing); mobile passkey integration shipped for Android through UniFFI provider ceremonies, which the plan's Phase 3 only sketched; counter policy changed from incrementing `max(local, remote)` to the zero-counter synced model; the plan's file list (`cose.rs`, `authenticator_data.rs`, `sync/counter_merge.rs`, `PasskeyCreateModal`, `extension/` tree) did not materialize as written.

## References

- `docs/adr/0094-passkey-rs-evaluation.md`
- `docs/adr/0092-browser-extension.md`
- `docs/adr/0089-mobile-apps.md`
- `docs/adr/0090-android-autofill.md`
- `docs/security/2fa-analysis.md`
- `crates/baluard-core/src/types.rs` (`LoginData`, `PasskeyData`)
- `crates/baluard-core/src/crypto/webauthn/`
- `crates/baluard-core/src/import/bw_json.rs`
- `crates/baluard-core/src/import/export.rs`
- `crates/baluard-runtime/src/state.rs`
- `crates/baluard-daemon/src/handler.rs`
- `crates/baluard-uniffi/src/lib.rs`
- `mobile/androidApp/src/androidMain/kotlin/xyz/actitud/baluard/passkeys/`
