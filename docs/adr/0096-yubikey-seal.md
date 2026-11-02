# ADR 0096. FIDO2 Security Key Vault Seal

> Status: Accepted (2026-10-30). Slices 0 through 4C are implemented and peer-reviewed. Slice 4D (mobile parity closure) and the slice 5 physical acceptance checklist remain open. Android ships NFC and USB-OTG for 1.0; iOS is a post-1.0 follow-up. Existing hardware seals require re-enrollment after the credential-bound authenticated-data change.

## Context

Baluard's hardware-backed key framework (ADR 0097) protects a device private key with a hardware answerer. The first design targeted a PIV applet. The reference device, a YubiKey Security Key C NFC, carries only the FIDO U2F and FIDO2 applets (no PIV, OTP, or OpenPGP), so the design was retargeted at the FIDO2 `hmac-secret` extension. A hardware seal must work offline, preserve recovery by phrase, and avoid making the key a single point of failure.

The reference device runs FIDO2 firmware 5.7.4 and reports AAGUID `b7d3f68e-88a6-471e-9ecf-2df26d041ede`. The AAGUID is pinned as a test fixture only; runtime model resolution uses bundled metadata and never a hardcoded device list. `hmac-secret` on non-discoverable credentials works on YubiKey-family firmware 5.2 and later. Non-discoverable credentials are not stored on the token, so no resident-key slot limit applies. PIN-less `hmac-secret` (the `CredRandomWithoutUV` path) is specified behavior and is shipped by `systemd-cryptenroll` with `--fido2-with-client-pin=no`.

### Prior art

Bitwarden uses the YubiKey as a server-validated OTP. The key protects the login to the vendor backend, the vault stays protected by the master password alone, and offline the key adds nothing. KeePassXC uses the OTP slot HMAC-SHA1 challenge-response, which enforces the key offline, but it requires programming the OTP slot (displacing its other use), the secret is a symmetric key the host saw during personalization, and the card is a dumb answerer. Baluard adopts the offline answerer model and modernizes it: `hmac-secret` gives the same challenge-response shape, with the secret generated on the token, never exportable, optionally PIN-less, on a standard applet, with no slot programming and no server. From Bitwarden the design keeps the product polish: guided plain-language enrollment, honest status copy, and a recovery story that assumes the key will be lost.

### Threat model

The seal protects against an attacker who holds the vault files (stolen laptop, leaked synced repository, pulled disk) and lacks the key, including a password thief who can read every seal file but cannot make the token answer. The `hmac-secret` output is generated inside the token, never leaves it as a key, and never existed on any host, so possession is cryptographically load-bearing.

The seal does not protect against an operating system compromise that waits for a legitimate unlock, nor against physical coercion. Every assertion demands its own physical tap, so no same-user process can answer silently. The residual human risk on desktop is tap phishing: a malicious process triggers an assertion and the user taps believing the request came from Baluard. The touch prompt therefore names the vault and the action in plain language, and the attacker still needs the seal file and the master password for the tap to matter.

On a phone the gesture is proximity, not a deliberate button press: holding the key to the reader implies presence, so the desktop tap-phishing framing does not carry over. The residual there is a relay or an unattended key next to an unlocked phone. The application never asserts without the credential ID and salt, which live only in the sandboxed seal file, so another application cannot trigger an assertion.

Resetting the key (the power-cycle ritual, whose timing window varies by source and must never be hardcoded in copy) destroys every FIDO credential on the token, including the user's passkeys for other services. For the seal this is a denial of service and never a disclosure. Baluard must not initiate a reset. Recovery guidance leads with the recovery phrase and re-enrollment, and any mention of reset warns that the key's other logins die with it.

Attestation certificates are public in every genuine device, so copying one proves nothing. Forging an attestation requires the batch private key, which only a counterfeiter with factory-side access can extract, and then every unit of that batch is forgeable. Chain verification detects the documented clone classes. It is a strong signal and not mathematical certainty; the vendor's own genuine-device check carries the same property. Attestation matters because keys are often bought through gray markets where an authorized channel costs several times as much, so local verification gives every user the genuineness check without trusting a marketplace listing.

## Decision

Use the FIDO2 `hmac-secret` extension as a backend for the existing hardware seal. The seal derives from the password-derived KEK subkey and a chip-contributed secret through `combine_seal_inputs`, using the existing `baluard-devkey-seal-v2-hw` format. The seal math is unchanged from ADR 0097.

### Registry and handshake contract

Hardware backends register in a multi-backend registry keyed by `backend_id()`. The seal file records the backend ID and the consent capability in its authenticated data, length-framed, so an open resolves the same backend that sealed the file. The mobile store reports the same backend ID (`fido2`) and the same `fido:` binding format as desktop, so the authenticated data is identical and transports are interchangeable on a device that has both.

The handshake is an opaque variable-length blob with a documented maximum of 65 bytes (`MAX_HANDSHAKE_BYTES`). Chip backends store a 65-byte uncompressed P-256 point; the FIDO2 backend stores a 32-byte salt. Readers bound-check the stored length before allocation so a hostile seal file cannot drive allocation. Failures use typed errors: no key, wrong key, touch timeout, touch cancelled, device busy, and driver down.

The backend declares an interaction capability, `Never` or `PerUse`. FIDO2 reports `PerUse`. `HwConsent::Silent` means the operation must never prompt. Firmware refuses `up=false` assertions (`CTAP2_ERR_UNSUPPORTED_OPTION`; the historical bypass was fixed as a security bug), so a FIDO2 token always prompts and silent access is closed permanently. A call requesting silent behavior against a per-use backend therefore fails fast before assertion. The seal layer forces the consent flag in the authenticated data to `PerUse` for tap backends.

Every unlock route must open the hardware-sealed device key and require the token. Password unlock and session-PIN quick unlock both end in `unlock_tail`, whose admin path opens the device file through the hardware-aware read. The member tail (`unlock_tail_member`) re-opens a hardware-sealed device file the same way before touching the identity seed; this was the one path that previously skipped the chip.

### FIDO2 backend

| Operation | Behavior |
|---|---|
| `probe` | Enumerate HID FIDO devices, issue CTAP2 `getInfo`, report `Available` when `hmac-secret` is supported. Reasons: `no-hid`, `no-token`, `token-without-hmac-secret`, `uv-forced`, `disabled`. Probes are cached and rate-limited. |
| `create_binding` | Create a non-discoverable credential whose `makeCredential` carries the `hmac-secret` extension. No PIN authorization by default, which selects the `CredRandomWithoutUV` path. `makeCredential` returns no HMAC output, so no secret exists at creation time. |
| `derive_ephemeral` | Generate a fresh random 32-byte salt, call `getAssertion` over the credential ID with `hmac-secret`, return the 32-byte secret and the salt as the handshake. |
| `derive` | Call `getAssertion` with the stored salt. Deterministic: reproduces the same secret from stored bytes. |

The binding string is `fido:<vault_id>:<base64 credential id>`, and `binding_vault_id` parses the `fido:` prefix. The binding record holds the RP ID, the pinned user-verification mode, and the attestation verdict.

The user-verification mode is pinned. If the host asserts with a different UV state than at enrollment, the token derives a different secret, so the recorded mode is checked before every assertion and a mismatch fails closed (the vault stays locked and phrase recovery remains). PIN-less is the default. Only a token that forces UV (`alwaysUv` or equivalent in `getInfo`) takes a PIN path, and then the PIN is the token's own PIN, prompted plainly and framed as the key's PIN, never stored.

The CTAP 2.2 `hmac-secret-mc` extension is deliberately unused. The salt is chosen at seal-write time, which keeps creation secret-free. Firmware 5.8 adds CTAP 2.3 features this design does not need.

### Interaction and tap lifecycle

An assertion needs a physical tap. The daemon runs all hardware operations through `spawn_blocking` so a touch wait never blocks the asynchronous executor. The desktop shows a touch prompt that names the vault and the action, allows cancellation (mapped to `fido_dev_cancel`, a typed `Cancelled` outcome), and reports typed timeout, wrong-key, missing-key, and busy outcomes. The daemon exposes no deadline and the key's own timeout governs, so the interface shows "waiting for your touch" with a cancel and never a fabricated countdown. A touch timeout does not charge the unlock rate-limit budget, because it is not a password attempt. HID is exclusive: a browser WebAuthn call in progress surfaces as the typed busy error and never a hang. Multiple connected tokens are handled by credential ID, trying each plugged token in turn. The desktop settings re-probe `vault.hw_status` periodically while open so a plugged key appears without reopening, because the daemon has no push channel.

| Operation | Taps |
|---|---|
| Unlock, including quick unlock | 1 |
| Password change or rotation (open old seal, write new) | about 2 |
| Enroll (create credential, write seal) | 2 or more |
| Disable | 1 |

Quick unlock (biometric or session PIN) does not bypass the seal. Unlock friction for a sealed vault is exactly one tap, and the user-facing documentation says so plainly. Synchronization never taps: unlock caches the device's Ed25519 signing key in memory (cleared on lock) and `SyncEngine` reads that cache before touching the sealed private-key file, so automatic and manual sync on a sealed vault run with the key unplugged. The member tail parses and caches the signing keys it opens, so post-unlock sync stays tap-free on member devices too.

### Attestation at enrollment

`makeCredential` returns an attestation certificate chain. Baluard verifies it against Yubico attestation roots bundled with the release and updated with the application. No online metadata service is used, in keeping with the no-server rule. The real Yubico hierarchy is all-RSA (SHA-256 inner links, SHA-512 root self-signature) and device attestation signs with RS256, so the verifier dispatches RSA PKCS#1 v1.5 and EC/ES256 per certificate. The pinned root is the self-signed "Yubico Attestation Root 1", taken from the FIDO metadata entry for the reference device.

Policy: an invalid chain is refused with honest copy. A valid chain from an unknown vendor (for example Nitrokey, SoloKeys, or Titan) is allowed with plain copy stating that the device is not verified as Yubico-made, because a non-genuine token answering with a fixed secret reduces the seal to password-only, which is the pre-feature status quo and not a new harm. The verdict (`verified` or `unknown-vendor`) is recorded in the binding and in the seal file as `hw_attestation`, shown at enrollment and in the enabled card, and is informational only: it is never an input to opening the seal. A strict Yubico-only mode could ship later as a setting.

### Enroll, open, lose

Enrollment (Settings, "Require my security key") probes, verifies attestation, creates the per-vault credential, and writes a v2-hw seal with the binding and backend ID. If the token already holds a user-set FIDO PIN or other passkeys, nothing about them changes, because PIN-less assertions never touch the PIN. Disabling the seal requires the existing key to open it and writes the unsealed v1 format; it does not delete credentials from the token. A password change opens the old seal and writes the replacement through the key, and with the token absent it fails closed before any write so the old password still opens the vault. Root Key rotation leaves the seal intact.

The recovery phrase, any second enrolled device, and the Legacy Contact kit never consult the token. Phrase recovery with a lost token creates a fresh device key and the vault opens on the password alone with the seal off; re-arming is a separate user decision. Hardware is an upgrade and never a single point of failure.

### Member identity binding

On member devices of shared vaults, a seal that only gated the device file would be a procedural gate and not a cryptographic one: the member identity seed would open under the bare KEK subkey, so password plus files would reach the shared-vault keys without the chip. Identity artifacts therefore bind to `HKDF-SHA256(hw content key, "baluard-identity-hw-v1")` whenever `meta/device-privkey.json` is v2-hw. The member seed rebinds eagerly at all four re-key sites (enable, disable, consent change, master-password change), and `identity.enc` heals lazily at the next full unlock. The admin unlock tail threads the content key out of the single chip assertion, and the unlocked state carries the zeroized identity key, which takes precedence over the plain identity wrap key. Disable rebinds identity artifacts back before the unsealed commit and aborts with the seal intact on any rebind failure. Residuals: a passphrase-mode `identity.enc` after disable is recovered by the identity escrow phrase, because no master password exists in the token-gated flow to re-seal with; and enable leaves a passphrase-mode window until the first full unlock, healed by the lazy path.

A review claim that "canary before chip is a password oracle" was refuted: the canary is readable from disk, offline password guessing is inherent to any password KDF, and the seal gates the Root Key and not the password.

### Phrase-enroll plaintext window

The earlier phrase-enrollment route wrote `meta/device-privkey.json` as plaintext, leaving an indefinite window in which a disk reader held the vault. `vault.enroll_with_phrase` now requires `master_password`, proves it against the KEK canary before any enrollment write (the ghost-device guard), and seals the fresh device key at birth under the KEK devkey seal subkey (0600, atomic). The CLI direct mode applies the same proof-then-seal sequence. The mobile provider join flow retains a seconds-wide plaintext window (it proves the password, writes plaintext, and unlocks, whose tail re-seals); closing it is part of slice 4D.

### Dependencies, transports, and platform behavior

Desktop uses `ctap-hid-fido2`, a pure-Rust CTAP2 HID implementation behind the optional `fido2` feature (daemon feature forwards `baluard-core/fido2`). It was chosen at a vendor review gate: it is MIT-licensed, maintained, supports firmware 5.8, and `hmac-secret` was verified at source. The libfido2 route failed the gate because its only Rust binding is a small single-maintainer crate with no macOS support and undocumented extension coverage. The crate requires Rust 1.89 against the workspace's declared 1.85 MSRV. This is acceptable because every minimum-platform target ships a compiler of 1.90 or later; the declared MSRV line in project documentation reflects default builds only. USB transport is HID, so the PC/SC dependency of the earlier PIV design disappears. Linux needs the Yubico udev rules for non-root HID access; `uaccess` grants the local session, the same boundary as the existing same-UID model. The application prints per-distro install commands and never runs them. Debian metadata recommends `libu2f-udev`; RPM systems rely on the system FIDO rules; `just sysdeps desktop` checks libudev and the rules package. Desktop NFC readers are not supported because none exist on target machines.

Phones cannot use the desktop adapter: it is bound to `hidapi`, an application sandbox has no `/dev/hidraw`, and iOS grants no raw USB. The mobile backend is therefore a transport-agnostic pure-Rust CTAP2 client in `baluard-core` (`hwkey/ctap/`), with one protocol implementation across desktop and phones. Alternatives were re-evaluated at a second gate. `webauthn-authenticator-rs` 0.5.5 has a CTAP2 client and an ISO 7816 transport, but documents itself as alpha with known lock-out edge cases and lists request extensions as unsupported; `hmac-secret` rides request extensions, so it fails the gate for a security seal and is kept only as a specification cross-reference. A named plan B, the vendor mobile SDKs behind a coarse token callback with Rust retaining the seal math, authenticated data, and attestation, was not needed.

The protocol scope is four commands: `getInfo`, `makeCredential`, `getAssertion` with `hmac-secret`, and `authenticatorClientPIN` subcommand `getKeyAgreement`, which PIN-less operation still requires because the salt is encrypted under the pinUvAuth shared secret (ECDH P-256 against the token's key-agreement key, HMAC-SHA-256 `saltAuth`, AES-256-CBC with a zero IV in protocol 1 and a random IV in protocol 2, chosen from the token's advertised `pinUvAuthProtocols`). Request maps are emitted with keys in ascending order by hand because CTAP2 requires canonical CBOR and the CBOR library does not canonicalize. NFC framing follows ISO 7816-4: select AID `A0000006472F0001` and check the `FIDO_2_0` reply, `NFCCTAP_MSG` as `80 10 00 00`, chain `61xx` through `GET RESPONSE`, poll `NFCCTAP_GETRESPONSE` (`80 11`) after `9100`, and use extended-length APDUs where supported and command chaining otherwise. A `U2F_V2` selection is followed by a CTAP2 `getInfo` proof. USB uses CTAPHID report framing with bounded messages and stale-frame recovery. Typed error mapping includes `0x2E NO_CREDENTIALS` to unknown credential, `0x2F USER_ACTION_TIMEOUT` to timeout, and `0x36 PIN_REQUIRED` to the UV-required outcome (a token with a PIN set and `makeCredUvNotRqd=false` refuses PIN-less enrollment). `getInfo` parsing covers versions, extensions, the options `clientPin`, `alwaysUv`, `uv`, and `makeCredUvNotRqd`, `pinUvAuthProtocols`, `maxMsgSize`, and `aaguid`. Secrets are zeroized and debug output is redacted.

Mobile runtime model: hardware work runs inside `spawn_blocking`, and the global registry is consulted inside the unlock tail and password-change paths, so the shipped design uses one serialized process-wide operation lock plus an RAII transport scope (uninstalled on scope exit, so no dead transport lingers in the registry). The UniFFI callback interface is `transact(request) -> response`, called synchronously from the Rust blocking thread, carrying NFC APDUs or 65-byte CTAPHID reports. A foreign exception escaping a callback maps to the callback error type and never aborts. The session is lazy: the transport opens the reader session on its first `transact` and closes at an explicit close at operation end, because the Argon2id KDF (seconds, 64 to 256 MB) runs before the chip and an eagerly opened iOS session would hold the system sheet open through it against its 60-second cap. One session spans the multiple chip calls of enrollment so the token stays in the field. Without a session, status probes answer from platform facts (NFC present and enabled) as a capability-only verdict and operations refuse until a transport is provided.

Android uses reader mode with `FLAG_READER_SKIP_NDEF_CHECK` so the system tag dispatcher cannot capture the tap, retains one `IsoDep` across all APDUs with a raised transceive timeout (the default is sub-second and breaks cold-token `makeCredential`), selects NFC-A and NFC-B, evicts a failed tag for a clean retry, and chooses extended or chained framing from `IsoDep` capability. USB accepts generic FIDO devices after validating usage page `0xF1D0` from the HID report descriptor, requires a non-boot interface with 64-byte IN and OUT endpoints, handles the per-plug permission dialog and cleanup, and converts Android's 64-byte reports at the CTAPHID boundary. A sealed vault refuses Android autofill datasets with explicit open-in-app copy: unlock is always an in-app foreground decision, and hosting the NFC ceremony inside the autofill flow is future work. Background or lockscreen tag dispatch is not supported. For iOS, the NFC session must run on its own serial dispatch queue, never the main queue, with the Rust call blocked on a semaphore over the CoreNFC completion handler. The repository has an Android host and no iOS host application, so the iOS host target, the tag-reading entitlement and usage description, the FIDO AID in the select identifiers, and the Rust XCFramework build land with the iOS follow-up, which reuses slices 4A to 4D unchanged. Whether the NFC entitlement is self-service must be verified in the developer portal before planning around a wait.

The daemon exposes `vault.hw_enable` (with an optional explicit `backend` selector; an unavailable requested backend fails closed) and `vault.hw_status` (selected backend, a per-backend array of capability, reason, and interaction mode, and any-backend capability). The unlock UX over NFC is tap and hold, with copy adapted to the gesture, quick-unlock copy that says "biometric, then hold the key" so the second factor never reads as a bug, and typed outcomes sanitized to localized plain language in en, es, and pt.

### Test bar

Hermetic tests use a mock keystore that exercises the full trait contract: binding-swap failing closed (the credential ID is wrapped by the token's master secret, so a swapped token fails natively with no AAGUID check needed), UV-mode mismatch failing closed, salt determinism vectors, attestation chain verification against pinned good and bad roots including the real root's parse and self-verification, typed busy, timeout, and cancel outcomes, seal round trips identical to the SE and TPM shape, registry routing across all backends, and hostile seal files with oversized handshake lengths rejected. Wrong-backend refusal and missing-backend-record corruption are covered. A test proves phrase recovery succeeds with the token unplugged. The audit tests prove every unlock tail fails closed with a typed `HardwareUnavailable` when the token is gone, that the Legacy Contact view and the heartbeat perform zero hardware operations.

For the CTAP client, byte-for-byte transcript replay is impossible because every exchange draws a fresh ECDH key and a fresh salt. The hermetic harness is a software CTAP2 authenticator model (key agreement, `hmac-secret`, packed self-attestation) driven over scripted transports, with an RNG and key seam in the client so vectors are deterministic, plus independent protocol 1 and 2 `saltAuth` vectors and an adapter-parity test asserting that both adapters parse the same recorded `makeCredential` response into byte-identical attestation. The exit gate for the client is a run over CTAPHID on the Linux desktop against the reference key before any phone work, so protocol bugs never first surface in Kotlin or Swift; the ignored test is `cargo test -p baluard-core --features fido2 real_key_enroll -- --ignored --nocapture` (one non-discoverable credential, two taps).

CI has no token, so the automated suite stays hermetic under `BALUARD_DISABLE_HWKEY`. Hardware-in-loop acceptance (slice 5) is a manual checklist on the reference device: enroll, unlock with tap, wrong-key rejection, pull during touch, cancel during touch, disable, re-enroll, rotation re-seal, phrase recovery unplugged, `gpg-agent` and browser WebAuthn running alongside, a second token inserted, and a token that already carries a user PIN and other services' passkeys, confirming Baluard disturbs nothing. The same checklist runs on the phone: NFC enroll, NFC unlock in the foreground, mid-session removal, timeout, wrong key, the same token carrying browser passkeys, the autofill refusal copy, and Android USB-OTG unlock. USB-OTG enrollment and verified attestation have passed on the reference phone and key; the remaining legs need a fresh build and re-enrollment after the authenticated-data change. The desktop HID gate has not run because no token has been attached to the workstation. iOS legs run with the follow-up.

### Non-goals

Server OTP second factor (there is no server). The OTP, OpenPGP, and PIV applets on this device class. A strict Yubico-only mode in the first release. Silent no-tap unlock, which firmware physically refuses. Background or lockscreen NFC dispatch on phones. Desktop NFC readers. Any claim that the key protects against operating system compromise; the user documentation states exactly what it does and does not.

### Open questions

1. A future owner of a PIV-capable YubiKey 5 would revive the earlier PIV design as a sibling backend behind the same registry.
2. UV-forced tokens are rare; prompting the token's own PIN plainly and never storing it is the current behavior and is pending acceptance.

## Consequences

The token contributes a secret that is never exported from the hardware and makes possession of the key necessary for every sealed unlock path. The design works offline and does not require a server or OTP-slot programming.

The user must tap the key for every unlock, including quick unlock, and needs about two taps for password change or rotation and at least two for enrollment. Loss or reset of the key requires phrase recovery and re-enrollment. The seal is an additional factor and not the only recovery path.

Bundled attestation roots provide local verification without a network dependency. Chain validation detects documented clone classes but cannot prove authenticity against an attacker with factory access to batch signing keys. Unknown vendors remain usable with an explicit warning. Trust roots update only with releases.

Hardware acceptance is incomplete: slice 4D and the physical checklist are open, and existing hardware seals must be re-enrolled after the credential-bound authenticated-data change. The Rust 1.89 requirement of the desktop adapter exceeds the workspace's 1.85 MSRV for builds with the `fido2` feature. Android NFC and USB-OTG are in the 1.0 scope; iOS follows after 1.0.

## References

- `docs/adr/0097-hardware-backed-keys.md`
- `docs/adr/0100-legacy-contact.md`
- `crates/baluard-core/src/hwkey/`
- `crates/baluard-core/src/hwkey/ctap/`
- `crates/baluard-runtime/src/`
- `crates/baluard-daemon/src/handler.rs`
- `justfile` (`sysdeps`)
