# Post-Quantum Readiness Assessment

**Status:** Source-verified and peer-reviewed (2026-06-17); initial draft corrected after peer review identified factual errors in the key-escrow layer.
**Trigger:** Cloudflare and Google post-quantum roadmap announcements (both targeting full PQ security by 2029)
**Scope:** Baluard's local cryptographic stack. Git sync transport is out of scope (see Inherited Risks).

## References that drove this assessment

- Cloudflare, "Cloudflare targets 2029 for full post-quantum security" (2026-04-07), accelerated timeline citing neutral-atom + error-correction progress and Google's P-256 factoring advance; prioritizes PQ **authentication** over harvest-now/decrypt-later.
- Google, "Quantum frontiers may be closer than they appear" (2026-03-25): sets a 2029 internal PQC migration deadline, prioritizing authentication services and digital-signature migration.

## Summary

Baluard is **not post-quantum ready**, but its **data-at-rest layer already is**. The bulk vault is encrypted with AES-256-GCM under a symmetric key hierarchy derived from an Argon2id KEK; that chain is quantum-safe. The exposure is concentrated entirely in the **asymmetric identity and key-escrow layer** (Ed25519 device identity, X25519 key agreement for Root-Key wrapping, and the X25519 recovery escrow), which is exactly the surface both announcements flag as top priority.

> **Source-verified (updated 2026-10-25).** The key-escrow layer is RFC 9180 HPKE: `hpke_wrap.rs` was migrated to the `hpke` crate (single-shot Base mode, DHKEM(X25519, HKDF-SHA256) + AES-256-GCM), retiring the earlier bespoke ECIES this document described. The identity layer (Ed25519 device signatures) remains the PQ gap.

Because Baluard is young, self-contained, epoch-rotating, and owns both endpoints of every protocol, its migration surface is far smaller than the federated systems Cloudflare and Google must fix. Realistic hybrid migration is on the order of months, gated primarily on Rust PQ-crate audit status rather than engineering scope.

The data survives Q-Day. The keys that guard the data are the debt.

## What is already PQ-safe

| Primitive | Role in Baluard | PQ status |
|---|---|---|
| AES-256-GCM | Item keys, attachments, all `.enc` blobs | Grover halves security to 128-bit. Still safe. |
| Argon2id | KEK derivation from master password | Hash-based memory-hard KDF. Not number-theoretic. PQ-safe. |
| HKDF (SHA-256) | Key derivation across the hierarchy | HMAC-based. PQ-safe. |
| SHA-256 | AAD identity binding, manifest checkpoints | Hash-based. PQ-safe. |
| Symmetric root-to-item chain | Root Key -> SGK -> Item Keys (all 256-bit symmetric) | Pure symmetric. Quantum-safe. |

**Harvest-now / decrypt-later does not crack the bulk vault.** An attacker who stores an encrypted vault blob today cannot recover its plaintext with a future Cryptographically Relevant Quantum Computer (CRQC), because no part of the data envelope depends on an asymmetric primitive.

## What is NOT PQ-safe (gaps, ranked auth-first)

Per both announcements, authentication is the top priority once Q-Day nears. A forgeable signature is catastrophic; a decryptable ciphertext is merely a leak.

### G1: Ed25519 device identity: HIGHEST RISK
- **Role:** Device enrollment, epoch rotation, `revoke_device_and_rekey`, git commit signing, integrity manifest checkpoints.
- **Threat:** A CRQC forges Ed25519 signatures. Attacker impersonates a device, rotates keys, revokes the legitimate fleet, pushes forged commits, and walks in the front door.
- **Why first:** This is the "any overlooked quantum-vulnerable remote-login key is an access point" case Cloudflare calls out. Long-lived identity keys are exactly what to prioritize.
- **Where the keys are used (source):** enrollment approval verification (`crates/baluard-core/src/device_manager.rs:849`), quorum commit-barrier signatures (`crates/baluard-core/src/keys/rotation.rs:44-50`), and git commit signing. The commit signature is **application-layer**: `crates/baluard-core/src/sync/commit.rs` (`verify_commit_signature`, line 13) verifies a raw Ed25519 signature over the signed payload, and the embedding into git objects happens in `create_signed_commit` (`crates/baluard-core/src/sync/engine.rs` ~1267) via git2 `commit_create_buffer`/`commit_signed`. A hybrid "sign with both, verify either" scheme is therefore **not** a drop-in: it requires restructuring this API to accept a signature bundle, and changes the git object format in a way external verifiers (e.g. CI checking commit signatures) will not understand.

### G2: X25519 Root-Key wrapping (RFC 9180 HPKE — migrated)
- **Role:** The Root Key (512-bit) is wrapped per-device so each device can unwrap it after deriving its KEK. The wrap is performed by `hpke_wrap::wrap_key()` (`crates/baluard-core/src/keys/rotation.rs:60-73`), one `WrappedKeyEntry` per enrolled device inside every `RekeyTransaction`.
- **What it is now:** `hpke_wrap.rs` seals via the `hpke` crate, RFC 9180 Base mode: proper DHKEM encapsulation (kem_context binds both ephemeral and recipient keys), HKDF-derived AEAD key and nonce, low-order point rejection inside the KEM, and caller AAD flowing through the HPKE context. The bespoke ECIES is retired. What remains classical is the X25519 DH itself — see the hybrid ML-KEM step below.
- **Deviations from RFC 9180 DHKEM(X25519, HKDF-SHA256):** (a) the recipient's static public key is **not** bound into the key-derivation context, so the scheme is sender-anonymous but lacks the recipient-binding of a proper KEM; (b) the AES-GCM nonce is the first 12 bytes of the raw DH shared secret (`hpke_wrap.rs:51-52`), deterministic rather than independently random (unique per ephemeral key, but derived from the secret being protected). Note also that the KEK derived from the master password (`crypto/kdf.rs:13-16`) is **not** involved in this wrap, it feeds only Session/Sync keys. The earlier draft's framing ("device private key HPKE-wrapped under the KEK") conflated two separate layers and has been corrected.
- **Threat:** X25519-native. Shor's algorithm recovers the ephemeral or recipient X25519 private key (or the shared secret directly), letting an attacker who harvests the per-device keywrap today unwrap the Root Key tomorrow.
- **Migration note:** step 1 (RFC 9180 HPKE) is done. What remains is step 2: a hybrid construction adding ML-KEM alongside X25519 for harvest-now-decrypt-later resistance.

### G3: X25519 recovery escrow: HIGHEST HNDL RISK
- **Role:** A 24-word BIP-39 recovery phrase derives a 64-byte key; the first 32 bytes become a **static X25519 private key** that the Root Key is wrapped to at vault creation (`crates/baluard-core/src/vault/creation.rs:92-99`). The wrapped Root Key and the recovery X25519 **public key** are stored in `meta/recovery.json`. Unlock-via-recovery HPKE-unwraps the Root Key with that static key (`crates/baluard-core/src/device_manager.rs:1250-1292`).
- **Status:** the recovery X25519 keypair rotates: `VaultHandle::rotate_recovery_phrase` (handle.rs, exposed as `vault.rotate_recovery`) derives a fresh recovery keypair and re-escrows the identity seed under the new public key, so the escrow is no longer permanent for the vault's life. Epoch rotation re-wraps each new Root Key to the current recovery pubkey (`rewrap_recovery_key`). The classical-X25519 exposure stands: the recovery public key is stored in plaintext in `meta/recovery.json` (`creation.rs`, field `recovery_x25519_pubkey`), so a harvested vault hands an attacker the exact Shor target for that key — a PQ KEM hybrid for the escrow remains the open work.
- **Threat:** after Q-Day, an attacker recovers the recovery X25519 private key from the harvested public key and unwraps the current Root Key (and every prior one, all wrapped to the same static key). This is the single most damaging harvest-now/decrypt-later target in Baluard, a persistent, plaintext-published Shor-vulnerable public key that unlocks the whole hierarchy regardless of how many epochs have rotated.
- **Migration note:** the rotation path exists (`rotate_recovery_phrase` re-issues the phrase and re-escrows), so migrating G3 to ML-KEM means swapping the KEM inside that flow and issuing the user a fresh phrase wrapped under the hybrid — incremental work on an existing path, not vault re-creation.

### G4: Passkeys (WebAuthn / FIDO2)
- **Role:** `passkey-rs` 0.5.x, ES256 (P-256) for **ceremony-generated** credentials (`Cargo.toml:90` `passkey = "0.5"`; ceremony hardcodes ECDSA/P-256, `crates/baluard-core/src/types.rs:1296`).
- **Import caveat:** the stored data model (`PasskeyData.key_algorithm`, `types.rs:511-513`) explicitly permits `"ECDSA"` (P-256) **or `"EDDSA"` (Ed25519)**. Bitwarden imports can therefore carry **Ed25519** passkeys into the vault. So "ES256 only" is accurate for Baluard-generated credentials but **not** for the imported set.
- **Threat:** P-256 and Ed25519 are both Shor-vulnerable, same class as the identity keys.
- **Status:** PQ WebAuthn (hybrid ES256+ML-DSA) is still standardizing at the FIDO Alliance / W3C. Baluard inherits whatever `passkey-rs` and the platform authenticators support. Tracked, not actionable today.

## Migration path

### Standards to adopt
- **ML-KEM (FIPS 203)**: replaces/augments X25519 in Root-Key wrapping and the recovery escrow.
- **ML-DSA (FIPS 204)**: replaces/augments Ed25519 for device identity, commit signing, and manifest checkpoints.
- **SLH-DSA (FIPS 205)**: optional conservative hash-based fallback for the highest-value long-lived keys (signatures are large; see Size Impact).
- **RFC 9180 HPKE**: first-class migration target. The bespoke ECIES in `hpke_wrap.rs` should be retired in favour of the `hpke` crate that is **already declared** in the manifest (see Rust crate gate below), before layering ML-KEM on top.

### Recommended sequencing (auth-first, matching the announcements)
1. **Hybrid ML-DSA + Ed25519 device identity.** Sign with both during a transition epoch; verify either. (Note the API/git-object rework this requires in G1.)
2. **Replace bespoke ECIES with RFC 9180 HPKE** (classical X25519 only) using the already-declared `hpke` crate, a standalone prerequisite that is unblocked today.
3. **Hybrid X25519 + ML-KEM-768 HPKE** for per-device Root-Key wrapping.
4. **Re-escrow the recovery artifact under a hybrid PQ KEM (G3).** This is net-new work: there is currently no path to rotate the recovery X25519 key or re-wrap under a new recovery artifact without re-creating the vault (`crates/baluard-core/src/vault/handle.rs:2334-2379` always re-uses the stored static pubkey).
5. **Disable classical-only** to stop downgrade attacks. Unlike Cloudflare/HTTPS, Baluard owns both endpoints of its protocols (no federation, no legacy client negotiation), so dropping classical-only is actually feasible here.
6. **Key rotation across the device fleet** via the existing epoch model (`rotate_root_key`, `revoke_device_and_rekey`). The rotation machinery already exists; per-device Root-Key wrapping (G2) slots into it, but the recovery escrow (G3) does not (see step 4).
7. **Passkeys** follow upstream standardization; no action until `passkey-rs` / platform authenticators ship PQ support.

### Rust crate gate (the real blocker)
Migration scope is small; **library maturity is the constraint.** Verify before committing:
- FIPS-203/204-conformant ML-KEM and ML-DSA implementations with current security audits (RustCrypto PQ crates, `pqcrypto`, `rust-crystals`).
- PQ HPKE support, or compose ML-KEM into the HPKE path manually.
- Constant-time / side-channel posture for the chosen crate.

Note: a **classical** RFC 9180 `hpke` crate is **already pinned** (`Cargo.toml:25`, `crates/baluard-core/Cargo.toml:18`) but is not currently imported anywhere in the codebase. Step 2 of the sequencing above is therefore unblocked today; the remaining gate is a PQ-hybrid HPKE that does not yet exist in that crate.

If no audited FIPS-conformant crate exists at implementation time, block G1/G2 on it rather than shipping an unaudited lattice implementation.

## Size and schema impact

Lattice primitives are one to two orders of magnitude larger than their classical counterparts. This affects the protobuf IPC schema and the padded-bucket tiers.

| Primitive | Public key | Signature / ciphertext |
|---|---|---|
| X25519 | 32 B | 32 B (shared secret) |
| Ed25519 | 32 B | 64 B |
| ML-KEM-768 | 1184 B | 1088 B (ciphertext) |
| ML-DSA-65 | 1952 B | 3309 B |
| SLH-DSA-SHA2-128s | 32 B | 7856 B |

- **Padded buckets:** the `Xs:5KB` tier should be reviewed. A keywrap envelope carrying an ML-KEM-768 public key + ciphertext plus an ML-DSA-65 signature can approach 6-7 KB and may need to promote to the `S:30KB` tier. Run `Tier::fit()` against representative hybrid envelopes before locking sizes. (The five tiers are confirmed at `crates/baluard-core/src/types.rs:40-44`; `Tier::fit()` at `types.rs:61`.)
- **Protobuf schema:** device registry, epoch metadata, and integrity manifest fields grow. Bump relevant message capacity; keep wire-compatibility by adding PQ fields as optional repeated/bytes rather than resizing existing fields. The rotation structures already use dynamically-sized fields (`WrappedKeyEntry.ephemeral_public: Vec<u8>`, `CommitBarrierSig.signature: Vec<u8>` in `keys/rotation.rs:41,49`), so lattice-sized ciphertexts/signatures fit without a struct change.
- **Git objects:** Ed25519 commit signatures today are 64 B embedded in git objects via git2 callbacks. An ML-DSA-65 signature is ~3.3 KB and a hybrid bundle is larger still. This bloats every signed commit, and, more importantly, external tooling that verifies git commit signatures will not recognize the hybrid format. Plan for a Baluard-internal verification path rather than relying on native git signature tooling.
- **Git sync churn:** a fleet-wide rotation to hybrid keys produces one large re-encryption commit (same shape as the existing `revoke_device_and_rekey` operation), not ongoing bloat.

## Inherited risks (out of Baluard's control)

- **Git sync transport (TLS).** PQ-readiness of the TLS connection to GitHub, GitLab, and Codeberg is the provider's responsibility. Baluard inherits it. Document as an accepted external dependency; revisit when providers publish PQ-TLS defaults. See `docs/git-provider-apps-and-tokens.md`.
- **OS keyring / DPAPI / libsecret.** The master-password and token storage layer is as strong as the host OS. PQ-irrelevant in the direct sense, but a compromised keyring short-circuits the whole hierarchy regardless of PQ status.
- **Provider OAuth / PAT issuance.** Token-based auth to git providers is not a Baluard cryptographic primitive; it inherits provider token lifetimes and revocation.

## Local surfaces that are NOT a PQ risk (listed for scope completeness)

These touch cryptography but carry **no** asymmetric/Shor-vulnerable primitive, so they are out of PQ scope. Documented here so the scope boundary is explicit rather than assumed.

- **IPC socket.** The daemon's Unix domain socket (`crates/baluard-daemon/src/`) is **plaintext, token-gated**: peer-credential verification via `SO_PEERCRED` (`handler.rs:23`) plus a 256-bit session token (constant-time compared) on unlock. There is **no transport crypto on the wire**. Because no asymmetric primitive runs over the socket, it is not a CRQC surface. (A compromised same-UID process is a classical security boundary problem, not a PQ one.)
- **TOTP.** TOTP codes (`crates/baluard-core/src/crypto/totp.rs`) use HMAC, with **SHA-1 as the default** algorithm (`totp.rs:16,29`; SHA-256/512 supported but not default). HMAC-SHA-1 is symmetric and therefore not Shor-vulnerable, but post-Grover its effective security is ~80 bits, borderline, not urgent. Worth noting, not a PQ gap.
- **Recovery phrase derivation.** The BIP-39 mnemonic → 64-byte seed step is symmetric/PBKDF2-style, not a PQ surface. The PQ exposure of the recovery path is the **X25519 escrow** it feeds (G3), not the phrase derivation itself.

## PQ threat table

| Threat (post-Q-Day) | Current defense | Residual risk |
|---|---|---|
| CRQC forges device identity | Ed25519 signatures | Full impersonation (G1) |
| CRQC forges git commits / manifest | Ed25519 commit signing + checkpoints (application-layer via git2 callbacks) | Forged history accepted by fresh devices (G1) |
| CRQC unwinds per-device Root-Key wrap | Bespoke X25519 ECIES (`hpke_wrap.rs`), not RFC 9180 HPKE | Root Key recoverable from harvested keywrap (G2) |
| CRQC unwinds recovery escrow | Static X25519 ECIES; recovery pubkey stored in plaintext in `meta/recovery.json` | **Permanent full-vault compromise**: breaking one never-rotating X25519 key unlocks every epoch's Root Key (G3) |
| CRQC forges passkey assertions | ES256 (P-256) ceremony creds via passkey-rs; imported creds may be Ed25519 | Passkey impersonation (G4, upstream-tracked) |
| HNDL on bulk vault data | AES-256-GCM at rest | None (128-bit post-Grover) |
| HNDL on recovery phrase derivation | BIP-39 → 64-byte seed (symmetric) | None on the derivation itself; the X25519 escrow it feeds is exposed (G3) |
| Downgrade to classical-only after PQ lands | (none today) | Mitigated by disabling classical-only post-migration |

## Verification status

**Source-verified on 2026-06-17** against the codebase (initially drafted from `AGENTS.md`; corrected after a peer review caught two factual errors in the key-escrow layer). Confirmed against source:

- `crates/baluard-core/src/crypto/`: AES-256-GCM AEAD, Argon2id KDF, HKDF-SHA256, and the **bespoke X25519 ECIES** key wrap in `hpke_wrap.rs` (which explicitly disclaims RFC 9180, lines 22-25). The declared `hpke = "0.12"` dependency is **not imported** anywhere.
- `crates/baluard-core/src/keys/`: `RootKey([u8;64])`, `SpaceGroupKey([u8;32])`, `ItemKey([u8;32])`; KEK feeds Session/Sync keys only (`kdf.rs:13-16`); the Root Key is what is wrapped per-device (`rotation.rs:60-73`).
- `crates/baluard-core/src/crypto/webauthn/`: ES256/P-256 ceremony (`types.rs:1296`); stored `PasskeyData.key_algorithm` permits `"EDDSA"` (Ed25519) on the import path (`types.rs:511-513`).
- `crates/baluard-core/src/device_manager.rs`: device identity keys minted/verified via Ed25519 (e.g. `:849`); recovery-via-phrase HPKE-unwraps the Root Key with a static X25519 key (`:1250-1292`).
- `crates/baluard-core/src/vault/creation.rs`: recovery escrow created at vault creation (`:92-99`), recovery X25519 pubkey stored in plaintext (`:425`).
- `crates/baluard-core/src/vault/handle.rs`: `rewrap_recovery_key` re-wraps each epoch's Root Key to the current recovery pubkey; `rotate_recovery_phrase` replaces the keypair itself. Classical X25519 remains the Shor target.
- `crates/baluard-core/src/sync/commit.rs`: single-key/single-signature Ed25519 verification API (`:31`), embedded via git2 callbacks (`:16`).
- `crates/baluard-core/src/crypto/totp.rs`: HMAC-TOTP, SHA-1 default (`:16,29`).
- `crates/baluard-daemon/src/handler.rs`: plaintext token-gated IPC with `SO_PEERCRED` peer verification, no wire crypto (`:23`).

## References

- Forward secrecy model: `docs/forward-secrecy-model.md`
- Threat model: `docs/threat-model.md`
- Passkey plan (ES256 / passkey-rs 0.5.x): `docs/plan-passkey-support.md`
- Device lifecycle and rotation: `crates/baluard-core/src/device_manager.rs`, `crates/baluard-core/src/keys/rotation.rs`
- Root-Key wrapping (bespoke ECIES): `crates/baluard-core/src/crypto/hpke_wrap.rs`
- Recovery escrow (creation + re-wrap): `crates/baluard-core/src/vault/creation.rs`, `crates/baluard-core/src/vault/handle.rs`
- Signed commits: `crates/baluard-core/src/sync/commit.rs`
- Crypto primitives: `crates/baluard-core/src/crypto/`
- Cloudflare: https://blog.cloudflare.com/post-quantum-roadmap/
- Google: https://blog.google/innovation-and-ai/technology/safety-security/cryptography-migration-timeline/
