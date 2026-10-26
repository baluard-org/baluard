# Plan: YubiKey hardware key seal (PIV backend)

> Status: DRAFT round one peer-reviewed (2026-10-26): two S1s (slot capacity, delete semantics)
> and five S2s found and folded in — the design now uses dedicated retired slots 82/83, a no-op
> delete, a multi-backend registry slice, a 5.3 minimum firmware, and runtime-loaded PCSC.
> Builds on `docs/plan-hardware-backed-keys.md` (the seal's parent plan). Scope: a YubiKey (PIV
> applet) as a `HardwareKeyStore` backend. YubiKey-as-server-2FA (Bitwarden-style OTP) is out of
> scope; see Non-goals.

## Why this, and what we steal from Bitwarden

Bitwarden uses the YubiKey as a server-validated OTP: the key protects the login to their backend,
the vault itself stays master-password-only, and offline the YubiKey is a plastic sticker.
KeePassXC uses the OTP slot's HMAC-SHA1 challenge-response: real offline enforcement, but it
requires programming the OTP slot (clobbering its day job), the secret is a symmetric key the host
already saw during personalization, and the card is a dumb answerer.

Baluard takes the stronger half of each. From Bitwarden we take the polish: a guided,
plain-language enroll flow, honest status copy, and a recovery story that assumes the key WILL be
lost. From KeePassXC we take the offline property. And then we improve on both by using the PIV
applet's on-device ECDH: the vault is sealed to a key that was generated on the YubiKey, never
existed on the host, and cannot be exported. Possession of the physical device is
cryptographically load-bearing, not a checkbox a server ticks. No slot clobbering, no server, no
shared symmetric secret ever touching the host.

Positioning line for the docs page: "Your vault can require the key in your pocket."

## Threat model

Protects: an attacker with the vault files (stolen laptop, synced-repo leak via a compromised git
remote, pulled disk) who lacks the YubiKey; a password thief who can read `settings.enc`,
`identity.enc`, and the device key but cannot make the card answer; silent-mode users against
exfiltrated-seal-file attackers, per-use users additionally against on-device malware that unlocks
while the key sits in the port (touch demanded).

Does not protect: an attacker who has BOTH the machine and the key in the port (silent mode) —
that is what per-use touch is for; an evil-maid OS-level compromise that waits for a legitimate
unlock and steals the running daemon's secrets; a $60 wrench.

Honest extra exposures this design accepts, documented in the user manual: with the factory
management key unchanged, a few seconds of physical access to the card lets anyone delete or
regenerate the Baluard keys — a denial of service against every seal bound to the card, never a
vault disclosure. A silent-mode card is a bearer factor: any process running as the same user with
PCSC access can use it as an ECDH oracle, but that oracle is useless without the seal file and the
master password. And the card's PIN and management key protect the PIV applet's own
administration, not the vault.

## Design: a fourth backend, plus the registry it requires

The seal math is unchanged: `baluard-devkey-seal-v2-hw` combines the password-derived KEK subkey
and a chip-contributed ECDH secret via `combine_seal_inputs`. But the platform registry is NOT
unchanged, and the round-one review caught the plan pretending otherwise: `HW_STORE` holds a
single `Option<Arc<dyn HardwareKeyStore>>` and `platform_store()` returns one backend per OS. To
let a user choose between the Secure Enclave, the TPM, and a YubiKey, three things must land
first, as slice 0:

1. A multi-backend registry: `hwkey` holds all installed backends keyed by a backend id.
2. A backend id recorded in the seal file, inside the AAD next to the consent flag, so an open
   knows which backend must answer. Pre-1.0 format change, permitted and free.
3. `hw_status`, `hw_enable`, `hw_disable`, and `hw_set_consent` take the backend id; status
   reports every installed backend's probe result.

Without slice 0, installing the YubiKey store would replace the TPM or Secure Enclave store and
existing TPM-sealed files would fail closed. With it, the user picks a backend at enroll (the
plan's answer to open question 1: user-pick, defaulting to the platform chip, because a YubiKey
travels and a TPM does not).

### The YubiKey backend, trait call by call

- `probe` → PCSC reader scan + PIV SELECT AID (`A0 00 00 03 08`). Available when a PIV-answering
  card is present and PCSC is reachable; `Unavailable` with machine-readable reasons `no-pcsc`,
  `no-card`, `card-without-piv`, `firmware-too-old`, `disabled`. Probes are cached and
  rate-limited inside the backend (card state is dynamic; the seal layer's callers treat
  `available()` as a capability check, and pre-unlock routes poll it).
- `create_binding(vault_id, consent)` → check the card reports firmware >= 5.3; pick the slot for
  the consent kind from the free retired-key slots (default 82 silent, 83 per-use; next free on
  collision, detected via GET METADATA on 5.3+); refuse to overwrite any occupied slot; generate a
  fresh P-256 key ON the card with the policy matrix below; export the public point at generation
  time; return the binding string. The binding stores: slot, public point, a fingerprint over the
  generation (so a later open detects a replaced or regenerated key and fails closed), the card
  serial, and the firmware version. The serial is matched on every open; a different card in the
  reader is a wrong-key refusal, not a mystery AEAD error.
- `ecdh_ephemeral(binding, consent)` → generate a fresh software P-256 keypair (private side
  zeroized on drop), validate the stored card public point, send our public point to the card's
  slot via PIV General Authenticate (ECDH), return the card's raw X coordinate (hashed before use
  as key material) as the `SharedSecret` and our public point as `EphemeralPub` (65-byte X9.62
  uncompressed, the trait's existing wire shape).
- `ecdh(binding, peer, consent)` → validate `peer`, send it to the card, return the same shape of
  secret. Mechanism note the plan must be precise about: both calls are the card computing
  `card_sk x peer`; the second call equals what `ecdh_ephemeral` produced because the stored peer
  was the ephemeral public point. PIV returns the raw X coordinate with no hashing; the backend
  hashes (SHA-256) before handing the 32 bytes to `combine_seal_inputs`. Test vectors against a
  software P-256 reference are part of the test bar.
- `supports_consent` → true, enforced by the card: the per-use slot's key is generated with TOUCH
  ALWAYS, so the card refuses to answer until a finger is on the sensor. The daemon surfaces a
  "touch your security key" state with a visible cancel and a bounded wait.
- `delete_binding` → deliberate NO-OP, same contract as the TPM backend. A card key is shared
  infrastructure across vaults on the device; deleting it because one vault disabled its seal
  would brick every other vault sealed to that card. Card keys are only ever deleted by an
  explicit "forget this security key" action that first verifies no seal on this device still
  references the binding — and on firmware below 5.7 there is no key-delete APDU at all (overwrite
  by regeneration is the only mechanism), which is one more reason the no-op is the honest
  default.

### Slot and policy matrix

PIV slots hold exactly one key each, and PIN/touch policies are fixed at generation. The
silent and per-use consent kinds are therefore separate slots, matching the trait's
separate-binding discipline. Default slots are the retired-key range (82, 83), never 9a/9c/9d,
so the card's standard PIV identity surface stays untouched for any future day job.

| Binding | Slot | PIN policy | Touch policy | Daily UX |
|---|---|---|---|---|
| Silent `baluard-hw:` | 82 | NEVER | NEVER | unlock exactly as today; the card must merely be present |
| Per-use `baluard-hwc:` | 83 | NEVER | ALWAYS | every unlock waits for a tap; a password change opens the old seal and re-seals, so it costs TWO taps with staged UI copy ("touch to confirm, then touch again to save") |

The two-taps honesty is deliberate: TOUCH CACHED would collapse them into one within a 15-second
window but weakens the "tap IS consent" property; v1 keeps ALWAYS and honest copy.

The PIN stays at its factory default and is never prompted: possession (silent) or touch
(per-use) is the factor, and the house rule stands — the app collects exactly one typed
credential, the master password. A "PIN + touch" hardened mode is a later, opt-in design round.
The PIV management key is used only at enroll (generate) and explicit-forget time; it is never
stored, and a management key the user has changed (or a PIN-protected management key) fails enroll
with instructions to run `ykman` themselves. No management-key field in the UI: a second typed
secret is phishing-shaped by our own rule. The factory management key stays: rotating it would
create a second secret the user must keep, and the DoS-only exposure it leaves open is documented
in the threat model.

### Enroll, open, disable, lose

Enroll (Settings, "Require my security key"): daemon probes (min firmware 5.3 enforced, recorded
with the serial), generates the slot keys per the chosen consent mode, exports the public points
at generation time, writes the seal as v2-hw with the YubiKey binding and backend id, and leaves
the recovery paths untouched. Per-use is the recommended default. Note for older cards: below
firmware 5.3 there is no metadata APDU and no reliable later policy read, so the plan gates on
5.3+ rather than pretending regeneration detection works everywhere; on any card, a regenerated
key still fails closed through the AEAD, just with less precise copy.

Open (silent): unlock derives the KEK subkey as today, asks the card for the ECDH over the stored
peer point (serial matched first), combines, unwraps. Card absent, wrong card, PCSC down, and
touch timeout are DISTINCT typed errors so the status copy can be honest — the round-one review
flagged that today's seal layer maps every backend error to one "unavailable" shape, so the typed
hardware error enum is part of slice 0.

Open (per-use): same, plus the desktop shows "touch your security key" with cancel and countdown;
the daemon waits on the card with a bounded timeout; refusal or timeout fails closed into the
same status copy. Hot-plug is a first-class state: card removal and insertion refresh the status
event live, and the unlock offer re-enables without a reload.

Disable: the seal downgrades to v1; `delete_binding` stays a no-op (above), so other vaults and
the card keys are untouched. Disable requires the key present (it opens the old seal by design) —
a lost key cannot use the Disable toggle, which is exactly why the recovery paths below matter.

Lost or damaged key: the recovery phrase path re-enrolls a device without consulting the card, as
do any second enrolled device and the Legacy Contact kit — a test proving recovery succeeds with
no card in any reader is part of the test bar (the round-one review correctly demanded this be
proven, not asserted). After recovery the user re-enrolls a new key. Hardware is an upgrade,
never a single point of failure for the vault.

## YubiKey facts this plan relies on

PIV ECDH (General Authenticate, P-256) is supported by ECC-capable YubiKeys (firmware 4.3+,
YubiKey 4/5 families). This plan gates on 5.3+ for GET METADATA (public key, policy, origin) and
stays P-256 to share the existing `EphemeralPub` shape across all four backends (5.4+ Ed25519 in
PIV is not used). Key deletion exists only from firmware 5.7; the management key is 3DES below
5.7 and AES from 5.7 (same usage flow). The Security Key series is FIDO-only and has no PIV
applet — it is not supported, and the probe's `card-without-piv` reason covers it.

Dependency honesty: the `yubikey` crate is community-maintained (iqlusion), not Yubico's, and is
unaudited. Before slice 1 commits to it: a vendor review of its source for the APDUs we use
(SELECT, General Authenticate, metadata, generate) with hand-rolled APDUs over `pcsc` as the
fallback if coverage or quality disappoints. PCSC itself is loaded at runtime (dlopen) so a
machine without libpcsclite gets `no-pcsc` instead of a daemon that fails to start; `just
sysdeps` gains the pcsc-lite lines and the Linux packaging deps list them, and the install-copy
prints per-distro commands (`pcsc-lite` + `pcsc-lite-ccid` + `pcscd.socket` on Fedora, `pcscd` on
Ubuntu) — the app prints commands, never runs them.

Multi-card and contention: the binding pins the card serial; reader order is irrelevant. Other
processes holding the card exclusively (gpg-agent/scdaemon, browsers doing WebAuthn over CCID)
make card ops hang or fail — the backend uses bounded timeouts, and the hardware-in-loop checklist
includes running alongside gpg-agent.

## Implementation slices (commit-sized)

0. Registry and seal-format groundwork: multi-backend `hwkey` registry, backend id in the seal
   AAD, typed hardware error enum (no card / wrong card / touch timeout / pcsc down), status and
   enable routes take a backend argument. No YubiKey code.
1. `hwkey/yubikey.rs`: the trait impl behind `hw-seal` + the runtime-loaded PCSC link, with a
   compile-gated mock for tests. Unit tests for binding fingerprints, slot selection, the policy
   matrix, and ECDH test vectors against a software P-256 reference. No hardware.
2. Daemon plumbing: status copy per typed reason, plain-language unavailable messages with distro
   install commands, rate-limited probe caching.
3. Desktop flow: the Settings hardware toggle gains "security key" as a backend choice; enroll
   wizard (probe, mode choice, touch test); per-use touch-wait state with cancel and countdown;
   hot-plug status events; i18n keys in en/es/pt with parity tests; UI copy says "security key",
   never the brand.
4. Recovery/rotation audit: prove phrase recovery and Legacy kit paths never touch the card (test
   with no card present); confirm rotation re-seals through the same seam; settle the heartbeat
   question by verification (the seal opens once at unlock and the heartbeat runs after, so no
   extra tap is expected — verified, not assumed).
5. Hardware-in-loop checklist (this dev machine + the user's finger): enroll silent and per-use,
   unlock, lock, wrong-card rejection, card pulled mid-touch-wait, second card inserted, pcscd
   stopped, disable + re-enroll, rotation re-seal, phrase recovery with no card, gpg-agent running
   alongside.

## Test bar

Unit (no hardware): mock keystore exercises the full trait contract including fingerprint and
serial mismatch fail-closed; slot selection never touches occupied slots; policy matrix maps
consent kinds to the right generation parameters; ECDH vectors match a software P-256 reference;
typed error mapping; seal round-trips identical to the SE/TPM shape; registry holds and routes
all backends. Hardware-in-loop: the checklist above, run by hand — CI has no card, so the
automated suite stays hermetic (`BALUARD_DISABLE_HWKEY` already covers this).

## Open questions

1. Backend default for a roaming user (YubiKey vs platform chip): user-pick at enroll is locked
   in; the default highlight is a copy decision.
2. Heartbeat under per-use: expected to need no extra tap (verify in slice 4). If verification
   surprises us, the answer is a UX look, never silently skipping the heartbeat.
3. Management-key rotation at enroll: rejected (round one). The factory key stays; the DoS-only
   exposure is documented.
4. Occupied retired slots: next free slot, refusal to overwrite, `ykman` instructions in the
   failure copy. 9a/9c/9d are never touched.

## Non-goals

Server-OTP 2FA (Bitwarden's model — we have no server). OpenPGP and FIDO2/CTAP applets. PIN-based
card modes (later opt-in design round). Mobile (NFC could come later; the daemon owns hardware ops
and mobile has no daemon). The Security Key series (no PIV). Claiming YubiKey protects against
OS-level compromise; the docs page says exactly what it does and does not.
