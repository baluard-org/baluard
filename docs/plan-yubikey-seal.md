# Plan: security key seal (FIDO2 hmac-secret backend)

> Status: DRAFT v4 (2026-10-28), external-review round applied, scope ruled: Android 1.0 ships NFC + USB-OTG; iOS is a post-1.0 fast-follow; autofill refuses on hw-sealed vaults. v3 was desktop-only; v4 pulls
> the phone into 1.0 (slices 4A-4D): the mobile app becomes the NFC reader and the same seal,
> consent, and attestation contracts carry over. The review round corrected the 4A protocol scope
> (hmac-secret needs the pinUvAuth shared-secret layer, not three bare commands), named the
> runtime registry change the per-operation session model requires, replaced byte-transcript
> tests with a software authenticator model plus an RNG seam, fixed the NFC gesture (tap and
> hold — no second sensor touch), and decided the autofill stance. v1 designed a PIV backend; the target
> hardware turned out to be a Security Key C NFC (FIDO-only, 5.7.4, genuine per Yubico's
> verification service), so the design retargeted at the FIDO2 hmac-secret extension. Round two
> removed the PIN design entirely (hmac-secret works PIN-less), answered the silent-mode question
> (no knob exists; the tap is the model), and tightened the consent contract, binding format, and
> attestation policy. Builds on `docs/plan-hardware-backed-keys.md`.

## Why this, and what we steal

Bitwarden uses the YubiKey as a server-validated OTP: the key protects the login to their
backend, the vault stays master-password-only, and offline the key is a plastic sticker.
KeePassXC uses the OTP slot's HMAC-SHA1 challenge-response: real offline enforcement, but it
requires programming the OTP slot (clobbering its day job), the secret is a symmetric key the
host saw during personalization, and the card is a dumb answerer.

Baluard takes KeePassXC's offline answerer model and modernizes it: the FIDO2 `hmac-secret`
extension gives the same challenge-response shape with the secret generated ON the token, never
exportable, PIN-less, on a standard applet, with no slot programming and no server. From
Bitwarden we take the polish: guided plain-language enroll, honest status copy, a recovery story
that assumes the key WILL be lost. The feature family covers cheap FIDO2 keys (this design) and
full PIV-capable YubiKey 5 series (future sibling backend behind the same trait).

Positioning line for the docs page: "Your vault can require the key in your pocket."

## The device, verified — and the market that made it

The reference device is Esteban's Security Key C NFC: FIDO U2F + FIDO2 applets only, firmware
5.7.4, AAGUID b7d3f68e-88a6-471e-9ecf-2df26d041ede (pinned as the test fixture; AAGUID-to-model
resolution at runtime comes from bundled metadata, never a hardcoded list). It was purchased
gray-market (AliExpress, shipped to Chile) for $56.86 all-in, versus $90 for an authorized-channel
YubiKey 5C NFC from Amazon with Yubico as seller — Yubico does not ship to Chile, and customs
makes the authorized channel cost multiples. That purchase story is the norm in whole regions,
which promotes attestation verification from nice-to-have to core: Baluard verifies the FIDO
attestation chain at enroll so every user gets Yubico's genuine-check assurance locally, without
trusting a marketplace listing. The key passed Yubico's own check (yubico.com/genuine,
2026-10-26). One honest caveat, sharper than v2's wording: attestation certificates are public
in every genuine device; copying one proves nothing. A forgery requires the BATCH private key —
extractable only by a counterfeiter with factory-side access, and then every unit of that batch
is forgeable. Chain verification detects the documented clone classes; it is a strong signal,
not mathematical certainty. Yubico's own genuine check carries the same property.

## Threat model

Protects: an attacker with the vault files (stolen laptop, synced-repo leak via a compromised
git remote, pulled disk) who lacks the key; a password thief who can read every seal file but
cannot make the token answer. The hmac secret is generated inside the token, never leaves it,
and never existed on any host — possession is cryptographically load-bearing.

Does not protect: an evil-maid OS compromise that waits for a legitimate unlock; a $60 wrench.
Every assertion demands its own physical tap, so no same-user process can silently answer —
the residual human risk is TAP PHISHING: a malicious process triggers an assertion and the user
taps thinking it was Baluard. The touch prompt names the vault and the action in plain language,
and the attacker still needs the seal file plus the master password for any of it to matter.
On the phone the gesture is proximity, not a deliberate button: NFC presence is implied by
holding the key to the reader, so the HID tap-phishing framing does not carry over. The residual
there is a relay or an unattended key next to an unlocked phone; the app never asserts without
the credential id and salt, which live only in the sandboxed seal file, so another app cannot
trigger an assertion. Android autofill is an unlock path the app already ships: a hw-sealed
vault REFUSES autofill datasets with honest copy (1.0 decision) — the unlock gesture is always
an in-app, foreground decision, and hosting the NFC ceremony inside the autofill flow is future
work.

Factory reset (the power-cycle ritual; the timing window varies by source — never hardcode a
number in copy) destroys all FIDO credentials on the token, including the user's passkeys for
other services and ours. That is a denial of service against the seal, never a disclosure, and
the app never auto-resets; recovery copy leads with the phrase path and re-enroll, and any reset
mention warns that the key's other logins die with it.

## Design: the answerer backend

The seal math is unchanged: `baluard-devkey-seal-v2-hw` combines the password-derived KEK subkey
and a chip-contributed secret via `combine_seal_inputs`. Slice 0 carries everything every backend
needs, and the round-two review expanded it from v1's list:

Slice 0 is LANDED (2026-10-26): registry keyed by `backend_id()`, backend id recorded in the
seal file and AAD-bound (length-framed), the opaque `Handshake` blob (65-byte cap, bound-checked
reads), the `Interaction` capability with the silent-on-tapping-backend refusal, typed no-card vs
wrong-card errors on open, and four new core tests (wrong-backend refusal, missing-backend-record
corruption, oversized handshake, silent refused). The quick-unlock enforcement point is settled:
every unlock shape pays the tap — password unlock and PIN quick unlock both end in
`unlock_tail`, whose admin path opens the device file through the hw-aware read, and the member
tail (`unlock_tail_member`) now re-opens an hw-sealed device file the same way before touching
the identity seed (the one path that previously skipped the chip).

- Multi-backend `hwkey` registry keyed by backend id.
- Backend id recorded in the seal file's AAD next to the consent flag.
- Typed hardware error enum: no key, wrong key, touch timeout, touch cancelled, device busy,
  driver down.
- The handshake reshape: `EphemeralPub([u8; 65])` becomes an opaque variable-length blob with a
  documented maximum; the seal file gains length framing for it, and reads bound-check the length
  so a hostile file cannot drive allocation. All four backends move in one pre-1.0 change.
- Consent contract honesty: `HwConsent::Silent` means "must never prompt", and a FIDO2 token
  always prompts — `up=false` assertions are refused by firmware (CTAP2_ERR_UNSUPPORTED_OPTION;
  the historical bypass was fixed as a security bug). The trait gains an interaction capability
  (`Never | PerUse`) so each backend declares what it can do; the FIDO backend reports PerUse,
  the seal layer forces the AAD consent flag to PerUse for it, and Silent-calling code fails
  fast instead of silently prompting. The SE/TPM/PCP mock models Silent; an interactive mock is
  added so tests exercise the FIDO contract.

The FIDO2 backend itself, trait call by call:

- `probe` → enumerate HID FIDO devices, issue CTAP2 getInfo, report `Available` when hmac-secret
  is supported; reasons `no-hid`, `no-token`, `token-without-hmac-secret`, `uv-forced`,
  `disabled`. Probes are cached and rate-limited.
- `create_binding(vault_id, consent)` → create a NON-DISCOVERABLE credential whose
  makeCredential carries the `hmac-secret` extension (PIN-less: no pinUvAuth, so the secret is
  the `CredRandomWithoutUV` path). makeCredential returns no hmac output — nothing secret exists
  at create time; the salt is chosen at seal-write time. The binding is the string
  `fido:<vault_id>:<base64 credential id>` carrying the credential id, and the binding record
  holds the RP id, the UV mode (always `without-uv` unless the token forces otherwise), and the
  attestation verdict. The `binding_vault_id` parser learns the `fido:` prefix in slice 0.
- `derive_ephemeral(binding)` → fresh random 32-byte salt, getAssertion over our credential id
  with the hmac-secret extension, return `(secret = HMAC(sk, salt), handshake = salt)`. The
  output is already 32 bytes.
- `derive(binding, handshake)` → getAssertion over the STORED salt; deterministic, reproducing
  the same secret from stored bytes. The UV mode is pinned: if the host ever asserts with a
  different UV state than at enroll, the token derives a DIFFERENT secret — so the binding's UV
  mode is checked before every assertion and mismatch fails closed (vault stays locked; phrase
  recovery remains). PIN-less is the default; only a token forcing UV (`alwaysUv` or equivalent
  in getInfo) takes a PIN path, and then the PIN is the user's own, prompted plainly and framed
  as the key's PIN, never stored silently.
- Interaction: getAssertion demands a physical tap. The daemon blocks in spawn_blocking with a
  bounded wait; the desktop shows "touch your security key" naming the vault, with cancel
  (mapped to `fido_dev_cancel`, a typed `Cancelled` outcome) and a countdown (typed
  `TouchTimeout`). A touch timeout never charges the unlock rate-limit budget — it is not a
  password attempt. HID is exclusive: a browser WebAuthn call mid-assertion surfaces as the
  typed `device busy` error, never a hang. Multiple tokens: operations key on the credential id
  and try each plugged token in turn.

### Tap lifecycle (the honest friction table)

| Operation | Taps |
|---|---|
| Unlock (including quick unlock) | 1 |
| Password change / rotation (open old seal, write new) | ~2 |
| Enroll (create credential, seal write) | 2+ |
| Disable | 1 |

Quick unlock (biometric/session PIN) does NOT bypass the seal: when a hardware seal is active,
every unlock path that would unseal the device key demands the chip, and the slice-0 design
settle makes the enforcement point explicit so no unlock path skips it. Unlock friction for a
sealed vault is exactly one tap; the docs page says so plainly.

### Attestation at enroll

makeCredential returns an attestation certificate. Baluard verifies the signature chain against
Yubico's published attestation roots bundled with the release (updated with the app; no online
metadata service — the no-server rule holds). Landed fact-check (slice 1): the real Yubico
hierarchy is all-RSA (sha256 inner links, sha512 root self-signature) and its device attestation
rides RS256, so the verifier dispatches RSA (PKCS#1 v1.5) and EC/ES256 per certificate; the
pinned root is the self-signed "Yubico Attestation Root 1" from the FIDO MDS entry of the
reference device (AAGUID b7d3f68e-88a6-471e-9ecf-2df26d041ede). Policy: invalid signature chain → hard refuse with
honest copy; valid chain but unknown vendor (Nitrokey, SoloKeys, Titan) → allow with plain copy
saying "not verified as Yubico-made", because a non-genuine token that answered with a fixed
secret would reduce the seal to password-only — the pre-feature status quo, not a new harm. The
attestation verdict is recorded in the binding record and shown at enroll.

### Enroll, open, lose

Enroll (Settings, "Require my security key"): probe, attestation verify, create the per-vault
credential, write the seal as v2-hw with the binding and backend id. If the token already holds
a user-set FIDO PIN or other passkeys, nothing about them changes — PIN-less assertions never
touch the PIN, and slice 5 verifies that explicitly. The recovery phrase path, any second
enrolled device, and the Legacy Contact kit never consult the token — a test proving recovery
succeeds with the token unplugged is part of the test bar. Disable requires the key (it opens
the old seal) and downgrades to v1 without deleting anything on the token. Lost or damaged key:
phrase recovery re-enrolls a device, then the user enrolls a new key. Hardware is an upgrade,
never a single point of failure.

## Facts this design relies on

Security Key C NFC, firmware 5.7.4: FIDO U2F + FIDO2, hmac-secret supported, no PIV/OTP/OpenPGP
applets. hmac-secret via getAssertion on non-discoverable credentials works on YubiKey-family
firmware 5.2+; non-discoverable credentials are not stored on the token, so no resident-key slot
limit applies. PIN-less hmac-secret (CredRandomWithoutUV) is spec behavior, shipped by
systemd-cryptenroll's `--fido2-with-client-pin=no`. `up=false` assertions are refused by YubiKey
firmware, closing silent mode permanently. Firmware 5.8 (July 2026, YubiKey 5 series) adds CTAP
2.3 features this design does not need. The `hmac-secret-mc` makeCredential-time secret is CTAP
2.2+ and deliberately unused — the salt-at-seal-write shape keeps creation secret-free.

## Implementation

Crates: the vendor-review gate (slice 1, 2026-10-27) chose **ctap-hid-fido2** — pure Rust, MIT,
maintained (releases through 2026), firmware 5.8 supported, hmac-secret verified at source. The
libfido2 route failed the gate: its only Rust binding (fido2-rs) is a 2-star single-maintainer
crate with no macOS support and undocumented extension coverage. ctap-hid-fido2 uses ring (already
in the tree) behind default features. Cost: the crate's MSRV is 1.89 vs the workspace's declared
1.85 — acceptable because every minimum-platform target ships rustc ≥ 1.90 (Ubuntu 26.04: 1.93,
Fedora 43: 1.90, macOS/Windows current toolchains); AGENTS.md's MSRV line reads stale until
corrected. USB transport is HID — the pcscd /
libpcsclite dependency from the v1 plan disappears entirely. Desktop needs the Yubico udev rules
for non-root HID access (`uaccess` grants the local session, the same boundary as the existing
same-UID model): `just sysdeps` gains the line and Linux packages declare it; the app prints
per-distro install commands, never runs them. Desktop NFC readers are out (none on target
machines); the PHONE is in 1.0 as the NFC reader (slices 4A-4D) — the trait and the seal math
carry over, only the transport changes.

Slices: (0) LANDED (2026-10-26, commit 4e9a654). (1) vendor review LANDED (ctap-hid-fido2 chosen;
see Implementation) + `hwkey/fido.rs` LANDED (2026-10-27): the backend behind a narrow `Token`
seam, hermetic stateful mock, binding round-trip / salt determinism / UV-forced / no-hmac-secret /
consent-refusal / typed touch outcomes / swapped-credential / missing-key tests (8, default
features, zero new build deps in CI); the real ctap-hid-fido2 adapter compiles under the
non-default `fido2` feature. Slice 1 is COMPLETE: the remaining attestation leg landed (2026-10-27) as `hwkey/attest.rs` —
chain walking with per-cert RSA/EC dispatch, the bundled Yubico pin, the hard-refuse/unknown-
vendor policy in `FidoStore::create_binding`, and ten hermetic tests including the real root's
parse-and-self-verify. The `rsa` dependency and a sha2 `oid` feature were added for it; `p256`
moved from dev-dependencies to dependencies (the verifier needs ES256 in production). (2) LANDED
(2026-10-28) daemon plumbing, status copy per typed reason, udev/sysdeps/packaging: `FidoStore`
enforces PerUse (tap) on binding creation and both derive paths, with Silent refused as
`HardwareTouchRequired`; `enable_hw_seal` forces PerUse for tap-interaction backends (the tap
requirement stays AAD-bound) and the PerUse open path no longer demands biometric-style consent
support; the daemon registers `hwkey::fido::store()` behind a new non-default `fido2` feature
(forwarding `baluard-core/fido2`) and `vault.hw_enable` accepts an optional `backend` selector
resolved explicitly (an unavailable requested backend fails closed); `vault.hw_status` reports
the selected `backend`, a per-backend `backends` array (capable/reason/interaction), and
any-backend capability, with consent support read from the sealed or first-available backend;
hardware sealing/opening runs in `spawn_blocking` so a tap wait never stalls the async executor;
`just sysdeps desktop` checks libudev plus the U2F udev rules package per distro and prints the
install command; deb metadata recommends `libu2f-udev` while rpm relies on systemd's FIDO rules; all desktop daemon-sidecar
build branches in the justfile compile with `baluard-daemon/fido2`. Two latent bugs fixed along
the way: `hw_status` read consent from the vault directory instead of `meta/device-privkey.json`
(always false), and the TPM backend plus its real-chip test lagged the slice-0 `Handshake`/
`HwConsent` contract (the `hw-seal` feature now compiles again). Test drift repaired in the same
pass: the route-inventory scanner no longer splits the handler on quote characters (URLs in
string literals broke parity), `vaults.copy_items` tests carry the now-required per-vault payload
tokens, and the ownership-claim test rewinds `ask_initiated_at`/`confirmed_at` together with
`window_until` because the record is tamper-evident by design. (3) LANDED (2026-10-28, two legs).
First leg (verdict surfacing): `HardwareKeyStore::create_binding` now returns `BindingInfo {
binding, attestation }` with the new `HwAttestation` enum (`verified` / `unknown-vendor`) — FIDO
reports its enroll-time verdict, chip backends return `None`; `seal_bytes_hw` records it as
`hw_attestation` in the seal file (informational only, never an open input), seal-key rotation and
consent changes carry the recorded verdict over, and `vault.hw_enable` returns `attestation` while
`vault.hw_status` surfaces it for the enroll UI. Second leg (desktop): the guard card gains a
touch-wait panel (title + vault-named body + cancel) whenever the pending enable/disable sits on a
tap backend — cancel hides the panel while the daemon request keeps waiting, and the completion
toast still reports the outcome; an `unknown-vendor` verdict warns instead of celebrating and the
enabled card shows the recorded verdict line; settings re-probe `vault.hw_status` every 4 s while
open so a plugged key appears without a reopen (the daemon has no push channel — a poll is the
honest hot-plug mechanism), and the error sanitizer maps the typed touch outcomes (timeout,
busy, wrong key, missing key) to plain-language copy in en/es/pt. Deviation from the draft: no
fabricated countdown in the touch panel — the daemon exposes no deadline and the key's own timeout
governs, so the panel says "waiting for your touch" with a cancel instead of a fake number.
i18n keys ship in en/es/pt under the existing parity test; desktop vitest covers the touch
panel, cancel, unknown-vendor warning, verdict line, and the hot-plug poll.
(4) LANDED (2026-10-28) recovery/rotation audit + the enroll plaintext-window fix. Audit verdict,
all hermetic (five new core tests, mock backends): the seal binds EVERY unlock tail — password and
KEK quick-unlock fail closed with the typed HardwareUnavailable when the token is gone, and the KEK
tail pays the tap when it is back (no bypass; the dormant SecureKeystore fast path in
load_device_privkeys is never installed by any surface today, so it cannot leak either); phrase
recovery works with the token LOST — the phrase path never reads the sealed device file, enrolls a
fresh device, and the vault opens on the password alone with the guard OFF (re-arming is a user
decision); the Legacy Contact view opens the kit copy with the Root Key alone and never touches the
seal; the heartbeat side-effect performs zero hardware operations (in-memory Root Key read only);
Root Key rotation leaves the seal intact, and a master-password change re-keys it under the chip —
with the token gone the change fails closed BEFORE any write (the Step-4 privkey load backstops the
narrower C1 pre-check), so the old password still opens the vault. The review round on this slice
also closed a real gap in the phrase-enroll path: the daemon route `vault.enroll_with_phrase` and
the CLI direct mode used to write `meta/device-privkey.json` as PLAINTEXT (an indefinite window
between enroll and the next unlock — a disk reader there held the vault). The route now REQUIRES
`master_password`, proves it against the KEK canary BEFORE any enrollment write (the providers
join flow's ghost-device guard), and seals the fresh device key at birth under the KEK's devkey
seal subkey (`seal_file`, 0600 atomic); the CLI prompts (or reads BALUARD_PASSWORD, matching the
e2e-hooks convention) and its direct mode got the same proof-then-seal treatment; a silently
swallowed devices.json reload now propagates. The runtime enroll tests pin the sealed-at-birth and
no-ghost-device-on-wrong-password properties. Residual: the mobile providers join flow still has
a seconds-wide plaintext window (it proves the password, writes plaintext, and immediately
unlocks, whose tail re-seals) — closed in slice 4D.
(4A) pure-Rust CTAP2 client behind the existing `Token` seam — the mobile backend. The desktop
real adapter (ctap-hid-fido2) is hidapi-bound and cannot exist on a phone (no /dev/hidraw in an
app sandbox; iOS grants no raw USB at all), so the mobile backend is a transport-agnostic CTAP2
client in baluard-core. Step 0 re-runs the slice-1 vendor-review gate on the alternatives before
any code: kanidm's webauthn-authenticator-rs and a
named plan B — the Yubico YubiKit SDKs behind a COARSE Token callback (the platform implements
info/make_credential/get_secret with YubiKit; Rust keeps seal math, AAD, and attestation). Pure
Rust stays the default: one protocol implementation across desktop and phones, hermetically
testable in CI. GATE RESULT (2026-10-28): webauthn-authenticator-rs 0.5.5 has a ctap2 client and
an iso7816 transport module, but self-documents as alpha with known lock-out edge cases and
lists request extensions as unsupported — hmac-secret rides request extensions, so it fails the
gate for a security seal. Its iso7816 module stays a spec cross-reference, not a dependency. The protocol scope the review corrected: FOUR commands, not three — getInfo,
makeCredential, getAssertion with hmac-secret, plus authenticatorClientPIN subcommand
getKeyAgreement, which PIN-less still requires: the salt is encrypted under the pinUvAuth shared
secret (ECDH P-256 against the token's key-agreement key, HMAC-SHA-256 saltAuth, AES-256-CBC
decrypt — zero IV in protocol 1, random IV in protocol 2, chosen by the token's advertised
pinUvAuthProtocols). Deps are near-zero: p256 already in-tree, aes in-tree, the cbc/hkdf/hmac
pieces are stdlib-class. CBOR: ciborium rides in via coset today (optional); the mobile feature
declares it directly, and request maps are emitted with keys in ascending order BY HAND — CTAP2
wants canonical CBOR and ciborium does not canonicalize. Transport framing: ISO 7814-4 for NFC
(select AID A0000006472F0001 and check the FIDO_2_0 reply; NFCCTAP_MSG 80 10 00 00; 61xx chains
through GET RESPONSE; after 9100 poll NFCCTAP_GETRESPONSE 80 11 until final; extended-length
APDUs where the device supports them, command chaining otherwise) and CTAPHID report framing for
the desktop real-key gate. Typed error map: 0x2E NO_CREDENTIALS -> UnknownCredential, 0x2F
USER_ACTION_TIMEOUT -> timeout, 0x36 PIN_REQUIRED -> the UV-required outcome (a token with a PIN
set and makeCredUvNotRqd=false refuses PIN-less enroll — the same exposure the landed desktop
adapter already carries via without_pin_and_uv), 0x2B UNSUPPORTED_OPTION and the rest get
explicit entries. getInfo parsing covers versions, extensions, options
(clientPin/alwaysUv/uv/makeCredUvNotRqd), pinUvAuthProtocols, maxMsgSize, aaguid. Testing:
byte-for-byte transcript replay is impossible (every exchange draws a fresh ECDH key and an
OsRng salt), so the hermetic harness is a SOFTWARE CTAP2 AUTHENTICATOR MODEL (clientPIN key
agreement, hmac-secret, packed self-attestation — a few hundred lines) driven over scripted
transports, plus an RNG/key seam in the client so test vectors are deterministic; spec and
ctap-hid-fido2 vectors pin the crypto. EXIT GATE: the new client runs over CTAPHID on the Linux
desktop against the reference key — real firmware contact BEFORE any phone work, so
Kotlin/Swift is never where protocol bugs surface. An adapter-parity test asserts both adapters
parse the same recorded makeCredential response into byte-identical PackedAttestation.
CODE COMPLETE (2026-10-28; physical-key exit gate still pending): `hwkey/ctap/` now carries the
canonical CBOR codec, pinUvAuth protocols 1+2, ISO 7814-4/APDU and CTAPHID framing, the four-command
client, the software authenticator, and `CtapToken` behind the existing `Token` seam. The hermetic
suite covers end-to-end enroll/derive, salt tampering, wrong credentials, algorithm and capability
refusals, and byte-identical attestation parsing against ctap-hid-fido2. Cross-checking the reference
adapter caught and fixed two model/client mismatches before firmware contact: makeCredential key 1
is clientDataHash, and packed attStmt uses text keys. The ignored real-key test is
`cargo test -p baluard-core --features fido2 real_key_enroll -- --ignored --nocapture`; it creates
one non-discoverable credential and requires two taps. NFC is also wired through `NfcToken`, with
extended or chained APDUs selected from platform capability. Review hardening added independent
protocol-1/2 saltAuth vectors, U2F_V2 selection followed by a CTAP2 getInfo proof, correct 61xx and
91xx response handling, secret zeroization/redacted debug output, bounded CTAPHID messages, and
stale-frame recovery; 56 hermetic tests pass with the physical-key gate still pending.
(4B) platform transports, the runtime store model, and the UniFFI surface. The runtime change
the review forced into the open: the global registry (a OnceLock map) is consulted INSIDE the
unlock tail and password-change paths, and MobileVault has no hw surface at all today — "call
the existing runtime methods with a live transport" is not a thing yet. Chosen model: a
task-scoped store guard — an RAII guard sets a thread-local hardware-store override at
spawn_blocking closure start and clears it at the end; store_for consults the thread-local
before the global map. Tokio blocking closures do not migrate threads and every hw path is
synchronous inside one closure, so the override is race-free; a regression test fails if any
store_for call site becomes reachable outside a guard. Fallback if the guard proves leaky:
thread an explicit Arc<dyn HardwareKeyStore> through unlock_tail, unlock_tail_member,
enable/disable/set_consent, and the seal re-key paths (the slice-4 audit tests re-run either
way). Status without a session: hw_status probes must not touch the transport, so the mobile
store answers probe from platform facts (NFC present/enabled) as a capability-only verdict and
refuses operations until a session transport is provided. UniFFI gains the hw surface
(hw_status/enable/disable/set_consent plus unlock/enroll taking a per-operation transport
handle), and all hw work stays inside spawn_blocking the way the desktop route does. Threading
contract, stated once: the callback interface is `transact(request) -> response`, called
synchronously from the Rust blocking thread; iOS implements it by blocking on a semaphore over
CoreNFC's completion handler, with the NFCTagReaderSession on its OWN serial dispatch queue —
never the main queue, and nothing on the main thread may wait on the Rust call; Android uses
IsoDep.connect plus a raised transceive timeout (the default is sub-second and breaks
cold-token makeCredential); a foreign exception escaping a callback maps to the callback error
type, never an abort. Session lifecycle is LAZY: the transport object opens the reader session
on its first transact and closes it at an explicit close() at operation end — the Argon2id KDF
(seconds, 64-256 MB) runs BEFORE the chip, and an eagerly opened iOS session would hold the
system sheet open through it against a 60 s cap; one session spans enroll's multiple chip calls
so the token stays in the field and no re-tap is needed. Host reality: the repo has an
androidApp target today and NO iOS host app — Android host wiring lands in 4B; the iOS host app
(iosApp target, entitlement com.apple.developer.nfc.readersession.formats TAG,
NFCReaderUsageDescription, the FIDO AID in select-identifiers, the Rust XCFramework build) is
a
POST-1.0 fast-follow that reuses 4A-4D unchanged (open question 6). The mobile store reports the SAME backend id
(`fido2`) and the SAME `fido:` binding format as desktop, so the seal AAD is identical and the
transports are interchangeable on a device that has both (state.rs's match arm and the trait
doc currently disagree on `fido` vs `fido2` — fixed in this slice).
CODE COMPLETE (2026-10-28; Android physical NFC/USB gates pending): the implementation uses one
serialized process-wide operation lock plus an RAII transport scope rather than thread-locals,
because runtime hardware work hops into spawn_blocking. The UniFFI callback carries NFC APDUs or
65-byte CTAPHID reports and is always shut down by scope exit and Kotlin finally. Android reader
mode is lazy, retains one IsoDep across all APDUs, selects NFC-A/B, and chooses extended or chained
framing from IsoDep capability. USB filtering requires a Yubico non-boot HID interface with 64-byte
IN/OUT endpoints, handles permission and cleanup, and converts Android's 64-byte reports at the
CTAPHID boundary. Settings, password and quick unlock select the key path before the KDF, mobile
autofill refuses sealed vaults with explicit open-in-app copy, and password changes perform all
hardware work before metadata writes with old-file restoration on later write failure. Sync never
taps: an unlock caches the device's Ed25519 signing key in memory (cleared on lock) and
`SyncEngine` reads that cache before touching the sealed privkey file, so autosync and manual sync
on a sealed vault run with the key unplugged. Change-master-password holds the executor politely:
`block_in_place` wraps the core op so a mid-change tap does not stall other tasks.
(C1 review wave, LANDED 2026-10-29) — the Opus review's critical finding, fixed and
agy-peer-reviewed. Finding: on member devices of shared vaults the hw seal was a procedural gate,
not a cryptographic one — unlock_tail_member opened the sealed device file only as a discarded
check while the member identity seed opened under the bare KEK subkey, so password plus files
reached the SMK without the chip. Fix: identity artifacts bind to
HKDF-SHA256(hw content key, "baluard-identity-hw-v1") whenever meta/device-privkey.json is
v2-hw — the member seed rebinds EAGERLY at all four re-key sites (enable, disable, consent
change, master-password change) and identity.enc heals LAZILY at the next full unlock
(keystore-mode identity.enc rebinds eagerly too; passphrase-mode cannot at token-gated flows).
The admin unlock tail threads the content key out of the single chip assertion
(load_device_privkeys_with_ck), UnlockedState carries identity_hw_key (zeroized, cleared with
the state on lock) taking precedence over identity_wrap_key, and the member tail performs a real
chip open whose content key also feeds the signing-key cache. The agy review round amended the
first cut: identity.enc (member-scoped and legacy) rebinds old-ik-to-new-ik at rotation and
consent changes; disable rebinds identity artifacts back BEFORE the unsealed commit (a rebind
failure aborts with the seal intact) and restores the keystore key where derivable, while a
passphrase-mode identity.enc after disable is a documented residual recovered by the identity
escrow phrase (no master password exists in the token-gated flow to re-seal with); enable
rebinds eagerly where the old keys are derivable (member seed, keystore-mode identity.enc), the
passphrase window until the first full unlock remains and is healed by the existing lazy path;
load_identity_cache tries the hw key BEFORE requiring a master password so KEK/PIN quick
unlocks load a healed identity (new regression test); the post-tail member-identity block in
unlock no longer clobbers the tail-set hw binding with the bare devkey subkey; the member tail
now parses and caches the device signing keys it opens (post-unlock sync stays tap-free on
member devices too); change_master_password snapshots the identity artifacts and restores them
with the device file on keywrap/canary write failure; derive_identity_hw_key and ik_of return
Zeroizing; the UniFFI security-key unlock and password-change paths consume the recorded
transport error detail instead of generic copy, and TransportScope::drop uninstalls MobileToken
so no dead transport lingers in the core registry. Review items already tracked as their own
waves (sync engine device id, rate-limit charging, typed touch outcomes, CBOR recursion,
CTAPHID field offsets, auth_data extensions parsing, mobile error mapping and copy, NFC/USB
lifecycle, password-change lock scope) were dispositioned to those waves, not absorbed here;
the "canary before chip is a password oracle" claim was refuted (the canary is disk-readable —
offline password guessing is inherent to any password KDF; the seal gates the Root Key, not the
password). Suites at close: core 959 (+2 amend assertions), runtime + uniffi 90, daemon 193,
all 0 failed under the kill switches, red-check on the rebind regression.
(4C) Compose flows (shared
UI, platform actuals behind expect/actual): the enroll wizard, the unlock-with-key gesture —
tap and HOLD: over NFC user presence is implied by the field, no second sensor touch — with
copy adapted to the gesture ("hold your key to the back of your phone until the check
finishes"), the touch prompt naming the vault in the system sheet's alert message plus an
in-app screen behind it (iOS chrome is the system sheet; Android uses reader mode with
FLAG_READER_SKIP_NDEF_CHECK so the system tag dispatcher cannot steal the tap), tag-lost mapped
to KeyMissing/Cancelled with retry copy, timeout and cancel handling, quick-unlock copy that
says "biometric, then hold the key" so the second factor never reads as a bug, and the
autofill-refusal copy from the threat model. Error sanitizer maps the typed outcomes; i18n in
StringsEn/Es/Pt under the parity tests. (4D) mobile parity closure: the providers join flow
adopts the slice-4 proof-then-seal privkey write (closing the recorded plaintext residual), the
feature-parity matrix gains the hardware row, and the hermetic audit legs re-run through the
UniFFI surface (dependent on 4B's store model) to pin the mobile path. (5) hardware-in-loop on
the reference device: enroll, unlock with tap, wrong-key rejection, pull-mid-touch, cancel
mid-touch, disable, re-enroll, rotation re-seal, phrase recovery unplugged, gpg-agent/browser
WebAuthn running alongside, a second token
inserted, and — importantly — a token that already carries a user PIN and other services'
passkeys, confirming Baluard disturbs nothing. The same checklist runs on the PHONE over NFC:
NFC enroll, NFC unlock (foreground), mid-session removal, timeout, wrong key, the same token that
carries browser passkeys on the phone platform, the autofill refusal copy on a hw-sealed
vault, and Android USB-OTG unlock (the per-plug permission dialog accepted). iOS legs run with
the post-1.0 fast-follow.

## Test bar

Unit (no hardware): mock keystore exercises the full trait contract including binding-swap
fail-closed (the credential id is wrapped by the token's master secret, so a swapped token fails
the assertion natively — no AAGUID check needed for that); UV-mode mismatch fail-closed; salt
determinism vectors; attestation chain verification against pinned good and bad roots; typed
outcomes for busy, timeout, and cancel; seal round-trips identical to the SE/TPM shape;
registry routes all backends; hostile seal files with oversized handshake lengths rejected.
Hardware-in-loop: the slice-5 checklist, run by hand — CI has no token, so the automated suite
stays hermetic (`BALUARD_DISABLE_HWKEY`).

## Open questions

1. Unknown-vendor attestation: allow-with-plain-copy is the round-two recommendation and the
   plan's default; a strict Yubico-only mode could ship later as a setting.
2. UV-forced tokens (rare): prompt the user's own PIN plainly, never store it. Acceptable?
3. When a 5-series PIV key owner appears: the v1 PIV design gets dusted off as a sibling
   backend; the registry already carries the shape.
4. RESOLVED (Esteban, 2026-10-28): Android 1.0 ships BOTH transports — NFC AND USB-OTG
   (CTAPHID over UsbManager with its per-plug permission dialog). The 4A CTAPHID framing is
   therefore a shipping transport, not just the desktop real-key gate.
5. iOS NFC entitlement: the standard Near Field Communication Tag Reading capability is
   reportedly self-service (no app-review gate); verify in the developer portal before the iOS
   sub-slice plans around a wait.
6. RESOLVED (Esteban, 2026-10-28): iOS is a fast-follow AFTER 1.0. Android carries the 1.0
   mobile scope (NFC + USB-OTG); the iosApp host target, entitlements, and XCFramework build
   land with the iOS fast-follow, reusing 4A-4D unchanged.

## Non-goals

Server OTP 2FA (we have no server). The OTP, OpenPGP, and PIV applets on this device class.
Silent no-tap unlock (physically refused by the firmware; settled). Background or lockscreen NFC
tag dispatch on phones (no background unlock; the gesture is always an in-app, foreground
decision). Desktop NFC readers.
Claiming the key protects against OS-level compromise; the manual says exactly what it does and
does not.
