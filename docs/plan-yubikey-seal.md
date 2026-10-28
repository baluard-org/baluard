# Plan: security key seal (FIDO2 hmac-secret backend)

> Status: DRAFT v3 (2026-10-26), round-two peer-reviewed. v1 designed a PIV backend; the target
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
machines); phone NFC is post-1.0 mobile work behind the same trait.

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
install command, and the deb/rpm metadata recommends `libu2f-udev`; all desktop daemon-sidecar
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
(4) recovery/rotation audit: phrase and Legacy paths prove
token-unplugged recovery, rotation re-seals through the same seam, the heartbeat never taps,
quick-unlock enforcement holds. (5) hardware-in-loop on the reference device: enroll, unlock
with tap, wrong-key rejection, pull-mid-touch, cancel mid-touch, disable, re-enroll, rotation
re-seal, phrase recovery unplugged, gpg-agent/browser WebAuthn running alongside, a second token
inserted, and — importantly — a token that already carries a user PIN and other services'
passkeys, confirming Baluard disturbs nothing.

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

## Non-goals

Server OTP 2FA (we have no server). The OTP, OpenPGP, and PIV applets on this device class.
Silent no-tap unlock (physically refused by the firmware; settled). Mobile NFC (post-1.0).
Claiming the key protects against OS-level compromise; the manual says exactly what it does and
does not.
