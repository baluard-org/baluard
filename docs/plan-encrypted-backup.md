# Plan: Encrypted Backup Container (`baluard.backup` v1)

**Status**: Design approved. Not started.
**Date**: 2026-10-05
**Author**: Esteban
**Reviewers**: External peer review (crypto design round, FIX-FIRST verdict; all findings folded in)
**Goal**: A single-file, passphrase-encrypted backup of a whole vault that ANY Baluard vault can adopt on import. Backups are never locked to the vault, account, or device that made them.

---

## 1. Why now

`baluard.vault` v1 (D79, this week) gives Baluard a first-party plaintext backup. A plaintext file holding every secret a user owns is the weakest artifact the product ever writes, and it is the artifact most likely to sit in a Downloads folder or a cloud drive. An encrypted option closes that gap.

The product requirement is stronger than "encrypt the export": the file must be **re-importable into a different Baluard vault**. The competitor's default encrypted export (Bitwarden "account restricted") is the cautionary tale — it is encrypted with the account's own key, so it dies on key rotation, dies on server migration, and dies with the account itself. That pattern is rejected outright. No vault key material, no vault id, no epoch may participate in the backup's key derivation, ever.

The design was researched against Bitwarden's two export modes, Aegis' vault format, the age file format, and archive-based options (zip/7z). It was then reviewed externally at the crypto-design level; this document is the post-review spec.

## 2. Goals and non-goals

Goals:

- One passphrase unlocks the file. Nothing else does.
- Any Baluard vault (or a brand-new one) can import the file and adopt every entry, re-encrypted under the target vault's own keys.
- Self-describing format: everything needed to decrypt lives in the file's header, published with test vectors, so third parties can build readers. Portability by construction, not by promise.
- Vault metadata leakage stays minimal: file size padded to a bucket, no slug, no entry counts, no timestamps in the header.
- Works on all three surfaces (CLI, desktop, Android) from the one Rust implementation.

Non-goals for v1:

- No multi-slot key wrapping (passkey/biometric slots on the backup). One passphrase slot; the version field leaves room to add slots later if a real need appears.
- No compression. It adds a size side channel and a canonicalization flag for zero current benefit.
- No incremental/differential backups. The file is a one-shot snapshot.
- No restore-from-setup flow in the first slice (import lands in an already-open vault). Listed as a follow-up in §10.

## 3. Threat statement

What the container protects: the confidentiality and integrity of the full vault contents when the file is at rest (cloud folder, USB stick, email attachment) or in transit.

What it does not protect:

- A compromised device or a screen observer during export. The export dialog shows the passphrase; that moment is exposure.
- A weak passphrase. Argon2id raises the cost per guess but cannot save `password123`. The passphrase is the whole security of the file, which is why the default is a generator (§7).
- Availability. Losing the passphrase loses the backup forever. The dialog says so, plainly.
- Deniability. The header announces "this is a Baluard backup, version 1" to anyone holding the file.

This backup is for portability and cold storage. It is not a replacement for the recovery phrase (vault identity) or the git remote (continuity and sync), and the UI must never blur those three.

## 4. Prior art and rejected options

**Bitwarden, both modes.** Account-restricted export binds to the account key: re-import to another account fails, same email on another server fails, key rotation bricks every old file. Their password-protected mode is the shape we want (user-chosen passphrase, salted KDF, importable anywhere) but the format is undocumented, third-party readers do not exist, and it has a history of dropping folders. We copy the shape, publish the format, and keep the folders.

**Aegis.** The model for a portable encrypted format: public header carrying KDF and AEAD parameters, LUKS-inspired slots, a documented layout with published test vectors and a reference decrypt script — which is why third-party apps can open Aegis encrypted backups. We copy the philosophy (self-describing header, published vectors) and modernize the primitives (Argon2id over scrypt, AES-256-GCM as our standing invariant).

**age.** The strongest alternative: reviewed spec, STREAM chunked payload, header MAC, and `age -d` as the universal escape hatch. Rejected for v1 on invariants — age uses scrypt and ChaCha20-Poly1305, we standardize on Argon2id and AES-256-GCM — and it has no Unicode normalization rule. We steal its construction instead: STREAM chunking, header bytes bound into key derivation and AAD, and a final-chunk flag. If the product ever values "opens with a stock tool" over the invariants, age is the answer.

**Zip/7z containers.** Rejected on every axis that matters. Legacy ZipCrypto is broken (known-plaintext). WinZip AES keys derive from PBKDF2-HMAC-SHA1 at a fixed 1000 iterations — not memory-hard, not raisable, orders of magnitude weaker than Argon2id against GPU guessing. 7z's KDF is iterated SHA-256, also not memory-hard (its cipher mode is reported as AES-CBC with only a CRC; verify before quoting publicly). Archive listings leak names and sizes unless header encryption is explicitly enabled. Stock Explorer/Finder cannot open encrypted archives, so the non-technical user gains nothing. And archive parsers bring their own attack surface (zip-slip, bombs) that a fixed 73-byte header reader does not have.

**Recipient-vault public key.** Rejected: it re-creates exactly the lock-in this format exists to prevent, and it fails the total-loss scenario where the target vault no longer exists.

**XChaCha20-Poly1305.** Rejected for v1: AES-256-GCM is the stated vault invariant, present in every platform's standard crypto library, which also matters for third-party implementers of the published format. Per-file unique keys remove the large-nonce advantage.

**Key slots (Aegis/LUKS style).** Deferred, not rejected: a passphrase-change-without-re-encryption story is real but solves no current user problem, and the version field is the upgrade path.

## 5. Format spec: `baluard.backup` v1

All integers little-endian. One file, no compression.

### 5.1 Header (73 bytes, plaintext)

| Offset | Size | Field | v1 value |
|---|---|---|---|
| 0 | 6 | magic, ASCII `BLDBAK` | — |
| 6 | 1 | container major version | `1` |
| 7 | 1 | KDF id | `1` = Argon2id |
| 8 | 1 | AEAD id | `1` = AES-256-GCM |
| 9 | 1 | reserved | `0` |
| 10 | 4 | `memory_kib` | 65536 on export |
| 14 | 4 | `iterations` | 3 on export |
| 18 | 4 | `parallelism` | 1 on export |
| 22 | 32 | KDF salt | random |
| 54 | 7 | nonce prefix | random |
| 61 | 4 | chunk size | 65536 |
| 65 | 8 | payload length (true inner length) | — |

The header must never carry: vault id, slug, epoch, device id, entry or folder counts, timestamps, app version, hostname, or a passphrase hint.

### 5.2 Key derivation

1. Normalize the passphrase with NFKC. Never trim. The normalization is part of the spec because an es/pt accented wordlist word can arrive in different Unicode forms from different keyboards; a mismatch must be impossible, not rare.
2. Derive `dk = Argon2id(NFKC(passphrase), salt, memory_kib, iterations, parallelism)`, 32 bytes.
3. Derive the file key with HKDF-SHA256: extract with salt `b"baluard.backup.v1"` over `dk`, expand with the **exact 73 header bytes** as `info`. The header is therefore key-committing: any change to version, ids, or parameters changes the key, and a tampered header fails authentication rather than decrypting garbage.

### 5.3 Payload framing

The inner plaintext is: `u64 payload_length` (again, in-band) followed by the `baluard.vault` v1 JSON bytes, followed by zero padding up to the next **padding bucket**. Buckets: 256 KiB, 1 MiB, 4 MiB, 16 MiB, 64 MiB, 256 MiB. The bucket round-up hides the vault's true size, the same metadata-minimalism thesis as the vault's per-entry padded buckets, applied to the whole file. Payloads above 256 MiB fail closed on export (attachments are capped at 2 MiB each; multi-gigabyte vaults do not exist in this product).

### 5.4 Encryption: STREAM chunks

The padded plaintext is encrypted in 64 KiB chunks with AES-256-GCM:

- Chunk nonce (12 bytes): the 7-byte header prefix, then the chunk counter as `u32` starting at 0, then a 1-byte final flag (0 for all chunks, 1 for exactly the last one).
- AAD for every chunk: the full 73-byte header.
- Each chunk on disk: ciphertext followed by its 16-byte GCM tag.

This is the STREAM construction (Hoang et al.) as used by age and Tink. It gives chunk-level integrity, truncation and reordering detection (the counter and final flag are inside the nonce, so a removed tail leaves a file whose last chunk lacks the final flag, and the GCM tag fails), and constant memory on decrypt regardless of vault size.

Export writes the 73-byte header, then the chunks, in one pass, straight to the destination. No plaintext temp file ever exists.

### 5.5 Parameter rules

- Export uses the fixed constants above (64 MiB / 3 / 1), never machine-calibrated parameters. A calibrated desktop would write files a phone cannot open, and calibration breaks reproducible test vectors.
- Import accepts parameters within caps and fails closed outside them: `memory_kib <= 1048576` (1 GiB), `iterations <= 16`, `parallelism <= 8`, chunk size must be exactly 65536, KDF and AEAD ids must be 1, major version must be 1. Out-of-range values produce the plain-language error "this backup needs more memory than this device has" for the memory case and "update Baluard to open this backup" for an unknown major version.
- Rising KDF defaults in a future release need no version bump: the parameters ride in the header.

### 5.6 Sniffing

Import auto-detection order: first 6 bytes equal `BLDBAK` → encrypted backup, prompt for the passphrase. Otherwise fall through to the existing `baluard.vault` v1 header sniff, then the 8 migration parsers. An encrypted backup is identified before the plaintext sniff so the two never collide.

## 6. Import rules

- Decryption failure and corruption are indistinguishable by design; the only error surfaced is "wrong password or damaged file". Nothing more precise, ever.
- A successful decrypt proves only that someone knew the passphrase. Anyone can forge a valid file. The decrypted `baluard.vault` v1 payload still goes through the full existing import validation: format id, version, manifest counts, field validation, folder depth cap of 16, attachment cap of 2 MiB. The container adds zero trust to the payload.
- Entries land with fresh UUIDs, re-encrypted under the target vault's keys, riding the existing `backup_to_import` → `ImportResult` pipeline. Restoring the same file twice duplicates every entry; v1 documents this behavior instead of guessing at dedup keys (follow-up in §10).
- Folder hierarchy restores flat per the existing documented import boundary. The container changes nothing about that.

## 7. UX

**Export (all surfaces).** Behind the existing master-password re-prompt gate (same credential, not a new one). The passphrase dialog then:

- Defaults to a generated passphrase: 6 words from the EFF wordlist, shown in plain text, with Copy, Regenerate, and (desktop) Print.
- Allows typing a custom passphrase with a confirm field. Hard floor: 8 characters, matching the master-password rule. Strength meter advisory below that.
- Never offers or prefills the master password. Typing the master password into a second dialog is exactly the phishing shape the product forbids, it turns a leaked file into an offline brute-force oracle for the master password, and it fails the scenario the backup exists for — the master password being the lost thing.
- Requires an explicit "I saved this password somewhere safe" acknowledgment before Export enables. Losing the passphrase loses the backup forever; the dialog says so.
- Copies clear automatically per the existing clipboard auto-clear, and the mobile screen showing the passphrase carries the secure flag.
- Writes `baluard-backup-YYYY-MM-DD.baluard` — generic, dated, no slug. MIME `application/octet-stream`.
- Auto-verifies after writing: re-opens the file, decrypts, parses, counts. Toast: "Backup checked: N entries." This catches truncated writes to cloud-folder sync targets for the cost of one local decrypt.

**Import (all surfaces).** File picker (or `baluard import`), sniff detects the magic, dialog prompts: "This backup is protected. Enter the password you saved when you created it — it is not your master password." The dialog names the file. No autofill from the vault, no reprompt coupling. Success reports the same imported/skipped/folders summary as plaintext import.

**Wordlists.** Use the existing EFF wordlist assets per surface (desktop ships en + es). Where a surface lacks a localized list, English fallback is acceptable; the passphrase is NFKC-normalized and format-agnostic.

## 8. Platform wiring

- **Core** (`crates/baluard-core/src/import/backup_container.rs`): header build/parse, key derivation, chunked encrypt/decrypt, padding, sniffing, parameter caps. Zero new dependencies (`argon2`, `aes-gcm`, `hkdf`, `rand` are all in-tree).
- **Runtime** (`VaultState::export_backup_encrypted(passphrase) -> Vec<u8>`): v1 JSON assembly (existing `export_backup`) wrapped by the container, behind `assert_export_allowed`. Import path symmetric: `import_backup_encrypted(bytes, passphrase)` decrypts then rides the existing pipeline.
- **Daemon**: `vault.export` payload gains `{"format": "baluard-encrypted", "passphrase": "..."}`; response carries the container bytes. `vault.import` gains the same format id with base64 container bytes. Both token-gated like today; the passphrase field is zeroized on the daemon side after use.
- **UniFFI**: `MobileVault.export_encrypted_backup(passphrase) -> Vec<u8>` and `import_encrypted_backup(bytes, passphrase) -> String`. Bytes only across the FFI; no path ever crosses.
- **CLI**: `baluard export --encrypted <path>` prompts for the backup passphrase (generator printed with `--generate`); `baluard import` auto-detects the magic and prompts. `BALUARD_BACKUP_PASSPHRASE` env override for the e2e harness, mirroring the established env-first pattern.
- **Desktop**: passphrase dialog in the Settings export flow, `.baluard` filter on the save dialog, magic sniff in the import flow, auto-verify toast.
- **Mobile**: same flow on `SettingsScreen`'s Data section; the passphrase screen carries `SecureFlag`; the file rides the existing SAF saver (`application/octet-stream`).

## 9. Test plan

- **Unit (core)**: header round-trip with byte-exact layout assertions; key derivation reproducibility (same inputs, same key) and header-tamper sensitivity (flip one header bit, decryption must fail); NFKC normalization of an accented es/pt passphrase (composed and decomposed forms both open the file); chunk counter/final-flag enforcement (truncated file, removed middle chunk, duplicated chunk all fail); padding bucket round-trip and the 256 MiB fail-closed cap; parameter caps (at-bound pass, over-cap fail); wrong-passphrase generic error; sniff precedence over the v1 plaintext sniff.
- **Published vectors**: one golden file with fixed salt, nonce prefix, fixed 64 MiB/3/1 parameters, and a tiny fixed payload, generated once and committed with its full derivation transcript (passphrase, header hex, expected ciphertext SHA-256). Third parties implement against it; our own future refactors must reproduce it byte-for-byte.
- **Roundtrip (core)**: all 8 cipher kinds through export → encrypt → decrypt → import, semantic-equality assertions, passkey private keys and TOTP seeds intact.
- **E2E (CLI layer, existing harness)**: init → entries → `export --encrypted` with `BALUARD_BACKUP_PASSPHRASE` → wrong passphrase refused → second vault created → `import` with the passphrase → entries present; auto-verify output asserted.
- **Surface tests**: desktop vitest for the passphrase dialog states (generated default, saved-checkbox gating, custom-passphrase floor), mobile compile + manual checklist for the secure-flag passphrase screen.

## 10. Boundaries and follow-ups

- Restoring into a fresh install currently requires creating a vault first. A "Restore from backup" action on the setup screen is the fix and is deliberately out of the first slice.
- Repeat restores duplicate entries (documented). A "skip entries that already exist" option is a candidate follow-up, not a v1 promise.
- Passphrase slots (change the file's passphrase without re-encrypting the body; add a biometric slot) remain a version-field upgrade path.
- Compression, if ever, arrives as a header flag in a future minor revision, never silently.
- The plaintext `baluard.vault` v1 export stays: migration out to other tools and estate printing still need it, and the spreadsheet option stays for the same reason.

## 11. Open decisions

- None blocking. The passphrase generator defaults to the EFF list at export (peer-reviewed position, adopted); the only watch-item is mobile wordlist localization, which is an implementation detail per surface.

## 12. Implementation order

1. Core container module, tests first (§9 unit list), golden vector committed.
2. Runtime + daemon + CLI wiring, then UniFFI + regen-bindings.
3. Desktop and mobile UI slices with i18n (en/es/pt).
4. Wave verification (fmt, clippy, core suite, vitest, gradle, `just test-e2e` with the new flow), agy review, per-surface commits, parity-matrix and D-record updates.
