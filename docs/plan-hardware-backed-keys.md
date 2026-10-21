# Hardware-Backed Key Seal (Secure Enclave / TPM)

- Status: Phases 0 + core seal LANDED 2026-10-20 (trait, probe, kill-switch, vault.hw_status routes, v2-hw seal with mock tests, desktop toggle). Phase 1's macOS backend is committed behind the hw-seal feature but needs on-device verification plus the keychain-access-groups entitlement + provisioning profile (persistent SE keys require them). Phase 3's Linux TPM backend LANDED 2026-10-21 and is verified against this box's real TPM (Intel PTT): build needs `tpm2-tss-devel` plus `tss` group membership, the one-chip-key shared-slot design below, and real-chip tests via `BALUARD_HW_KEY_TEST=1`. Phase 2's Windows PCP backend LANDED 2026-10-21, type-checked against the real windows-sys signatures via a host-target harness (the windows-msvc cargo target cannot cross-build ring without an MSVC toolchain) but never executed - on-device verification (`BALUARD_HW_KEY_TEST=1`) is Esteban-side; per-vault named keys, software-minted ephemerals, RAW-secret little-endian reversal.
- Date: 2026-10-18
- Author: Esteban
- Related: `docs/threat-model.md` (adversary D: local disk access), `crates/baluard-core/src/vault/device_privkey.rs` (the file this plan protects), `crates/baluard-core/src/biometric.rs` (audit C3 asymmetry note that first deferred this), `docs/post-quantum-readiness.md` (identity-layer posture)

## 1. Problem

The vault's entire key hierarchy bottoms out at one local file: `meta/device-privkey.json`. It holds the device X25519 key, and that key is what opens the Root Key keywrap (`meta/keywrap/<device>.json`, HPKE purpose `root-key-keywrap`). Protect the device key and the Root Key is protected; lose it and everything above it is unreachable.

Since the C1 fix, that file is an AES-256-GCM envelope sealed under a purpose-scoped HKDF subkey of the KEK. That is a real improvement over the plaintext era, but the seal inherits the KEK's one weakness: everything needed to attack it lives on disk. An adversary with a disk image (stolen laptop, cloned drive, pulled backup, exfiltrated synced clone) can run an offline Argon2id brute force against the master password for as long as the ciphertext is worth attacking. Argon2id raises the cost per guess; it does not remove the attack. The same image also carries the keywrap file, so a recovered password yields the Root Key with no further hardware in the way.

Two existing audit notes point at the same gap:

- Threat model adversary D: "Offline brute force or cache recovery" is listed as the remaining path against encrypted files.
- `biometric.rs` (audit C3): on Linux and Windows the keyring backends have no per-read gate, and the module comment names the deferred fix: "TPM-backed key / Windows Hello KeyCredential".

The user-visible consequence: a strong-but-guessable master password is the only thing standing between a disk thief and the vault. Secretive-class apps close this by generating keys inside a security chip where the private half physically cannot leave. Baluard's model is different on purpose (keys must be exportable, syncable, recoverable), so the goal here is not to copy that model. The goal is to buy the same offline resistance for the one file that guards everything, without giving up recoverability.

## 2. Product rule

One plain-language toggle in Security settings: "Guard this vault with this device's security chip". The promise it makes to a non-technical user: a stolen disk or backup alone cannot open this vault, even with the password; the machine's chip is part of the lock. The failure it must disclose in the same sentence: if the chip or the machine dies, this device needs the recovery phrase to rejoin, like any new device would.

No git term, no crypto term, no TPM/SE jargon reaches the user. The vault stays fully syncable; nothing about the wire format, sharing, backup, or recovery changes.

## 3. Design

### 3.1 What gets hardware-wrapped (and what does not)

Only the devkey seal. The device private key stays X25519, the Root Key keywrap stays HPKE to the device public key, the canary stays the unlock verifier, and the phrase paths stay untouched. This is strictly a change to how ONE local file's content key is protected at rest. Every wire-visible artifact is byte-identical before and after.

The hardware layer never sees vault keys directly. It contributes a secret to the seal's content key; that is all.

### 3.2 Seal construction (AND-wrap, fresh per write)

New seal type `baluard-devkey-seal-v2-hw` alongside the existing `baluard-devkey-seal-v1`:

1. On write, the hardware keystore performs an ECDH between its non-exportable private key and a fresh ephemeral public key. The result runs through HKDF-SHA256 together with the existing KEK subkey: `ck = HKDF(ikm = hw_secret || kek_subkey, info = "baluard-devkey-seal-v2-hw")`.
2. The inner privkey JSON encrypts under `ck` with the same envelope format and the same AAD discipline as `v1` (purpose string as AAD, so the blob cannot replay as another meta file).
3. The file stores the envelope, the ephemeral public key, the hardware binding ID, and the device ID. It stores no key material and no KDF salt.

Unwrap needs BOTH inputs: the hardware ECDH (impossible off-device, impossible without the chip's private half) and the KEK subkey (master password). Composition is AND: password alone fails offline; hardware alone fails without the password. This preserves the rule that the master password remains the single user-facing credential while the chip becomes a silent second factor of the at-rest seal.

Silent operation: on all three platforms the ECDH primitive chosen for Phase 1-3 does not demand per-use user consent. Unlock friction stays exactly what it is today. A per-use-gated variant (Touch ID on every unlock, Hello consent, TPM auth session) is a separate opt-in phase (§7 Phase 5), not the default.

### 3.3 Platform matrix

| Platform | Primitive | Notes |
|---|---|---|
| macOS 15+ | Secure Enclave P-256 key agreement (`SecureEnclave.P256`, keychain-persisted reference, app-scoped ACL) | Every qualifying Mac (T2/Apple Silicon) has an SE. Key material is generated inside the SE and is non-exportable by construction. Keychain ACL binds the reference to the daemon's bundle ID; the stable signing identifier (`xyz.actitud.baluard.daemon`) is load-bearing here (P2 gotcha: ad-hoc re-signs re-prompt and can strand the reference). |
| Windows 11 | TPM 2.0 via CNG Platform Crypto Provider (PCP) | `Microsoft Platform Crypto Provider` keys are TPM-resident and non-exportable. Windows Hello KeyCredential is the consent-gated variant for Phase 5, not the base wrap. Implemented 2026-10-21 with three PCP-reality choices recorded in `hwkey/pcp.rs`: per-vault named keys (no slot scarcity, delete really deletes), software-minted ephemerals imported as the agreement peer (secrecy lives in the chip key), and `BCRYPT_KDF_RAW_SECRET` output reversed from CNG's little-endian. |
| Linux (Ubuntu 26.04, Fedora 43) | TPM 2.0 via `tss-esapi` (TSS 2.0 ESAPI) | Hardware presence varies (VMs, older boxes). Probe-or-hide is mandatory. CI uses `swtpm`. Implemented 2026-10-21 with three firmware-reality deviations recorded in `hwkey/tpm.rs`: ONE shared chip key per TPM (slot-constrained parts like Intel PTT expose only a handful of persistent slots; vault separation rides the password-derived seal subkey either way), key identity by TPM name (outside info never shows in the public area), and a per-command session matrix (ESYS refuses sessionless hierarchy commands but misbehaves with sessions on TR open and keygen).

Mobile (Android Keystore / iOS SEP via UniFFI) is parked with G12-adjacent work; the trait interface below is built so the platform impls drop in later without core changes.

### 3.4 Trait and placement

New module `crates/baluard-core/src/hwkey/`:

```rust
pub trait HardwareKeyStore: Send + Sync {
    fn probe(&self) -> HwCapability;            // Available { binding_id } | Unavailable(reason)
    fn create_binding(&self, vault_id: Uuid) -> Result<HwBindingId>;
    fn ecdh(&self, binding: &HwBindingId, peer: &EphemeralPub) -> Result<SharedSecret>;
    fn delete_binding(&self, binding: &HwBindingId) -> Result<()>;
}
```

- One binding per vault, named/namespaced by the deterministic `vault_id` (same discipline as quick-unlock `quick-unlock:<vault_id>`), so multi-vault never crosses bindings.
- The daemon owns all hardware operations (it already owns all vault crypto). Desktop, CLI, NMH, and mobile never touch the keystore directly; IPC and FFI surfaces are unchanged.
- Cargo feature `hw-seal`, runtime probe with env kill-switch `BALUARD_DISABLE_HWKEY=1` (mirrors `BALUARD_DISABLE_KEYRING` so `just test` stays hermetic).
- File-type detection joins `file_kind()`: `v2-hw` unwraps only when both seal inputs are available; a `v1` file keeps working untouched. `vault.hw_status` (pre-unlock, host-level, mirrors `pin_status`/`biometric_status`) reports capability + current seal kind without touching vault material.

### 3.5 Migration and lifecycle

- Enabling the toggle (unlocked session): re-key the seal v1 -> v2-hw via the existing `rotate_seal_key` pattern (open under old content key, rewrite under new, staged `.tmp` + atomic rename, inside the `RotationGuard` crash-safety discipline).
- Disabling the toggle: re-key v2-hw -> v1 (needs the hardware once; a dead chip cannot downgrade, by design).
- Master password change: `rotate_seal_key` re-keys the KEK input and re-runs the ECDH with a fresh ephemeral; hardware binding survives.
- Device unenrollment / revoke-and-rekey: untouched; the keywrap chain changes, the seal does not care.
- Vault delete-from-disk: delete the binding. Plain detach: keep it (detach is reversible).
- Fresh clone on the same machine: new vault path, new `vault_id`, new binding. A clone on a machine whose chip holds no binding takes the normal enroll flow; hardware seal is re-offered after enrollment.

### 3.6 Failure model (must be pinned by tests)

- Chip or logic board dies, keychain restored from backup to new hardware, PCP key lost on a Windows reset: the local `v2-hw` file is unwrappable forever on that device. The rescue is the existing phrase path: phrase enrollment derives a NEW device identity and overwrites the local devkey, so the same physical device rejoins without any external reset. No new recovery machinery is invented; the plan depends on this and must pin it with a test ("phrase rescue after simulated hardware death").
- The UI must present this BEFORE enabling the toggle, in plain language, as part of the same dialog as the theft-resistance promise (§2). Asymmetric disclosure is a dark pattern; both halves go in one dialog.
- Probe failure at unlock (driver gone, TPM disabled in firmware): fail closed with a typed error pointing at the toggle, never silently fall back to ignoring the hardware half. Silent fallback would convert the feature into a no-op without telling the user.

## 4. What this buys (and what it does not)

Buys:

- Offline adversary D is closed on hardware-sealed vaults: a disk image plus unlimited time plus a correct password guess is not enough, because the hardware ECDH input does not exist off-device. The brute-force window shrinks from "forever, at Argon2id speed" to "nothing".
- Linux/Windows same-UID silent reads (audit C3 asymmetry) get strictly harder for the devkey file: the file's content key now requires chip participation, not just a keyring read. (The quick-unlock password entry itself is a separate, unchanged surface; Phase 5's consent variants are where that story completes.)

Does not buy:

- While-unlocked memory scraping. Root Key, SGK, item keys, and the seal subkey still live in daemon memory while open, mlock'd and zeroize-on-drop. A same-UID attacker who can read process memory while the vault is open still wins. That residual is inherent to an in-memory session model and is unchanged.
- Active malware riding an unlocked session (any IPC caller with the token). Token gating, rate limits, re-prompt, and auto-lock remain the controls there.
- Firmware-level attack on the chip itself, or DMA-class attacks. Out of scope; no attestation story is claimed.

Say this honestly in the settings copy's detail view: the chip guards the vault at rest, not while it is open.

## 5. Non-goals

- No remote attestation, no server-side chip verification, no anti-tamper claims.
- No change to keywrap HPKE wire format, canary, sharing, `.bldbak`, or phrase recovery.
- No hardware binding of stored SSH keys beyond what vault-key protection already transitively gives them (they are item-key ciphers; binding the device key covers them).
- No mobile phases in this plan (parked; interface only).
- No OS-versions below the Minimum Platform Compatibility table.

## 6. Testing

- Unit (hermetic, always run): mock `HardwareKeyStore` for seal/open roundtrip, AND-property (either input missing fails), v1<->v2-hw migrations, master-password-change re-key, AAD purpose binding, probe-unavailable hide path, fail-closed on missing hardware at unwrap. Property tests (`proptest`) over random keys and ephemeral pairs.
- Integration (hardware-gated, env `BALUARD_HW_KEY_TEST=1`, manual or self-hosted runner): real SE on the Mac workstation, real TPM on the Linux box, `swtpm` in CI for Linux.
- E2E: extend the Phase 1 CLI+daemon harness with a software mock (already covered by unit) plus a manual per-platform checklist: enable, unlock, lock, password change, phrase rescue after simulated hardware death, disable.
- Hermeticity: `BALUARD_DISABLE_HWKEY=1` in `just test` from day one; no test ever requires a chip.

## 7. Phases

| Phase | Scope | Done when |
|---|---|---|
| 0 | `hwkey/` trait, capability probe, `vault.hw_status` route, env kill-switch, no behavior change | Probe reports truthfully on all 3 desktop platforms; tests green |
| 1 | macOS SE implementation + v2-hw seal + settings toggle + migration | Toggle works end to end on a Touch ID Mac; offline-image test (copy vault dir to another machine) fails closed; phrase rescue test passes |
| 2 | Windows PCP implementation behind the same trait | Same acceptance on TPM 2.0 hardware |
| 3 | Linux `tss-esapi` implementation + `swtpm` CI | Same acceptance with real TPM and with swtpm |
| 4 | Surface polish: Security settings detail view, hw_status in device-info surfaces, detach/delete binding lifecycle | UI strings in en/es/pt, key-parity tests green |
| 5 (optional) | Per-use consent variants: `BIOMETRY_CURRENT_SET`-style SE ACL, Hello KeyCredential wrap, TPM auth session | Separate decision; ships only if the unlock-friction tradeoff is wanted |

Phases are independently shippable; Phase 1 alone covers every macOS user, which is the largest hardware-capable share of the desktop fleet.

## 8. Open questions

1. macOS keychain ACL vs the signing identifier: confirm the daemon's stable signing identity survives `just install-local` ad-hoc rebuilds without stranding SE references, or whether local installs must keep the stable identifier always (P2 gotcha suggests yes).
2. `tss-esapi` MSRV and build deps on Fedora 43 / Ubuntu 26.04 (tabrmd as runtime service; `just sysdeps` needs a new line).
3. Should the enable toggle live per-vault (default) with a global "enable on all vaults" convenience row in Settings, or strictly per-vault? Leaning per-vault-only for v1 (mirrors quick unlock).
4. Windows VMs and dev containers: PCP virtual TPM availability varies; probe must distinguish "no TPM" from "TPM without PCP" for honest status copy.
