# Plan: Encrypted Backup Container (`baluard.backup` v1)

**Status**: Design approved. Not started.
**Date**: 2026-10-05
**Author**: Esteban
**Reviewers**: External peer review (crypto design round, FIX-FIRST verdict; all findings folded in). Plan-doc review: external adversarial pass (FIX-FIRST, ten findings, all adopted — header length leak removed, daemon base64 contract, in-memory auto-verify, crash-guard caps, reserved-byte enforcement, bucket arithmetic, dependency note, test additions).
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

**Zip/7z containers.** Rejected on every axis that matters. Legacy ZipCrypto is broken (known-plaintext). WinZip AES keys derive from PBKDF2-HMAC-SHA1 at a fixed 1000 iterations — not memory-hard, not raisable, orders of magnitude weaker than Argon2id against GPU guessing. 7z's KDF is iterated SHA-256, also not memory-hard (its cipher mode is reported as AES-CBC with only a CRC; verify before quoting publicly). Archive listings leak names and sizes unless header encryption is explicitly enabled. Stock Explorer/Finder cannot open encrypted archives, so the non-technical user gains nothing. And archive parsers bring their own attack surface (zip-slip, bombs) that a fixed 65-byte header reader does not have.

**Recipient-vault public key.** Rejected: it re-creates exactly the lock-in this format exists to prevent, and it fails the total-loss scenario where the target vault no longer exists.

**XChaCha20-Poly1305.** Rejected for v1: AES-256-GCM is the stated vault invariant, present in every platform's standard crypto library, which also matters for third-party implementers of the published format. Per-file unique keys remove the large-nonce advantage.

**Key slots (Aegis/LUKS style).** Deferred, not rejected: a passphrase-change-without-re-encryption story is real but solves no current user problem, and the version field is the upgrade path.

## 5. Format spec: `baluard.backup` v1

All integers little-endian. One file, no compression.

### 5.1 Header (65 bytes, plaintext)

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

Total header: 65 bytes. There is deliberately NO payload-length field in the header: the true inner length rides in-band inside the ciphertext (§5.3), authenticated by GCM. Printing the length in the clear would hand every observer the exact vault size down to the byte and defeat the padding entirely — an observer watching backups over time could count individual entries appearing and disappearing.

The header must never carry: vault id, slug, epoch, device id, entry or folder counts, timestamps, app version, hostname, or a passphrase hint. The reserved byte is part of that rule: it must be zero in v1, and importers reject any non-zero value with "update Baluard to open this backup" so a future v1.x flag can never be silently misread by an old reader.

### 5.2 Key derivation

1. Normalize the passphrase with NFKC. Never trim. The normalization is part of the spec because an es/pt accented wordlist word can arrive in different Unicode forms from different keyboards; a mismatch must be impossible, not rare.
2. Derive `dk = Argon2id(NFKC(passphrase), salt, memory_kib, iterations, parallelism)`, 32 bytes.
3. Derive the file key with HKDF-SHA256: extract with salt `b"baluard.backup.v1"` over `dk`, expand with the **exact 65 header bytes** as `info`. The header is therefore key-committing: any change to version, ids, or parameters changes the key, and a tampered header fails authentication rather than decrypting garbage.

### 5.3 Payload framing

The inner plaintext is: a `u64 payload_length` prefix (the ONLY place the true length exists — inside the ciphertext, authenticated), followed by the `baluard.vault` v1 JSON bytes, followed by zero padding so that **8 + payload_length + padding equals exactly the chosen bucket size**. Buckets: 256 KiB, 1 MiB, 4 MiB, 16 MiB, 64 MiB, 256 MiB. The bucket round-up hides the vault's true size, the same metadata-minimalism thesis as the vault's per-entry padded buckets, applied to the whole file. Payloads above 256 MiB minus the 8-byte prefix fail closed on export. The payload is metadata-only JSON (baluard.vault v1 carries no attachment blobs), where 256 MiB comfortably represents hundreds of thousands of entries. The whole ladder is deliverable on every surface because daemon transports move paths, not bytes (§8) — a byte-carrying route would have silently capped the usable buckets at 1 MiB, since the daemon rejects 4 MiB request frames and the Tauri bridge rejects 5 MiB responses before base64 inflation is even counted. The payload cap (256 MiB of JSON) and the memory cap (§5.5, 256 MiB of Argon2id) are unrelated numbers that happen to match; changing either does not touch the other.

### 5.4 Encryption: STREAM chunks

The padded plaintext is encrypted in 64 KiB chunks with AES-256-GCM:

- Chunk nonce (12 bytes): the 7-byte header prefix, then the chunk counter as `u32` starting at 0, then a 1-byte final flag (0 for all chunks, 1 for exactly the last one).
- AAD for every chunk: the full 65-byte header.
- Each chunk on disk: ciphertext followed by its 16-byte GCM tag.

This is the STREAM construction (Hoang et al.) as used by age and Tink. It gives chunk-level integrity, truncation and reordering detection (the counter and final flag are inside the nonce, so a removed tail leaves a file whose last chunk lacks the final flag, and the GCM tag fails). "Constant memory" is a property of the chunk construction, not of the surfaces: the container layer processes one chunk at a time, but a whole-file surface still holds the padded plaintext, the ciphertext, and the parsed JSON in memory at once, and a 256 MiB vault therefore peaks at several multiples of 256 MiB. That peak is acceptable on desktop; mobile sizes are far below the top buckets in practice.

Export writes the 65-byte header, then the chunks, in one pass, straight to the destination. No plaintext temp file ever exists. Before the bytes are handed to any save surface, the exporter runs an **in-memory verify**: it decrypts the container it just built, strips the padding via the in-band length, parses the JSON, and counts entries. This catches container and encoding bugs at their source. It is a check on the bytes we produced, not on the file after it reached disk — the webview Blob download and the Android SAF document picker both hand bytes to the platform without a path back, so no surface can re-open the written file, and the plan does not claim to detect cloud-sync truncation.

### 5.5 Parameter rules

- Export uses the fixed constants above (64 MiB / 3 / 1), never machine-calibrated parameters. A calibrated desktop would write files a phone cannot open, and calibration breaks reproducible test vectors.
- Import accepts parameters within caps and fails closed outside them: `memory_kib <= 262144` (256 MiB), `iterations <= 6`, `parallelism <= 4`, chunk size must be exactly 65536, KDF and AEAD ids must be 1, major version must be 1, reserved byte must be 0. Any cap violation means "update Baluard to open this backup" — the realistic benign cause of over-cap parameters is a future Baluard writing larger KDF settings, so the memory case has no special wording, and a hostile file learns nothing. A parameter set INSIDE the caps whose allocation still fails on this device maps to "this backup needs more memory than this device has". Below the legal floor (`m < 8 * p`), the parameters cannot be genuine; that is the generic damaged-file error. The memory cap is a crash guard: on mobile, an allocation that overcommits dies by SIGKILL on first touch, uncatchable, so the cap — not error handling — is what protects the process. Rising KDF defaults in a future release need no version bump: the parameters ride in the header, and the caps leave room above the export constants.

### 5.6 Sniffing

Import auto-detection order: first 6 bytes equal `BLDBAK` → encrypted backup, prompt for the passphrase. Otherwise fall through to the existing `baluard.vault` v1 header sniff, then the 8 migration parsers. An encrypted backup is identified before the plaintext sniff so the two never collide.

## 6. Import rules

- Decryption failure and corruption are indistinguishable by design; the only error surfaced is "wrong password or damaged file". Nothing more precise, ever.
- The layout is fully determined by the file length before any key derivation runs, and every rule is checked before the first Argon2id call: `(file_len − 65)` must be a positive multiple of `65552` (one 65536-byte chunk plus its 16-byte tag each); the implied plaintext size must equal one of the bucket sizes in §5.3 exactly; the final flag must belong to the chunk at the last position and to no other; the in-band length prefix must satisfy `8 + payload_length <= plaintext_len` and is never used to allocate. After decrypt: the padding bytes must be zero and the payload must be valid UTF-8 before parsing. A reference implementation and the Rust importer must agree on these rules or they diverge; the committed decryptor script is the second implementation that keeps them honest.
- A successful decrypt proves only that someone knew the passphrase. Anyone can forge a valid file. The decrypted `baluard.vault` v1 payload goes through the existing `parse_backup` validation: format id, version, and manifest counts versus content. Deeper checks (folder depth, per-field limits) are the import pipeline's business and are NOT re-implemented in the container; the container adds zero trust to the payload, and claims to the contrary would be false.
- Entries land with fresh UUIDs, re-encrypted under the target vault's keys, riding the existing `backup_to_import` → `ImportResult` pipeline. Restoring the same file twice duplicates every entry; v1 documents this behavior instead of guessing at dedup keys (follow-up in §10).
- Folder hierarchy restores flat per the existing documented import boundary. The container changes nothing about that.

## 7. UX

**Export (all surfaces).** Behind the existing master-password re-prompt gate (same credential, not a new one). The passphrase dialog then:

- Defaults to a generated passphrase: 6 words from the EFF wordlist, shown in plain text, with Copy and Regenerate. (Desktop printing is deliberately absent from v1: the webview print path is unreliable across Tauri platforms, and the recovery-sheet precedent is a Rust-side renderer, which is follow-up scope here, not v1.)
- Allows typing a custom passphrase with a confirm field. Hard floor: 8 characters, matching the master-password rule. Strength meter advisory below that. The tension is stated knowingly: the passphrase is the whole security of the file (§3), and an 8-character typed passphrase is weak against offline Argon2id guessing. The generator default is what carries the real security (~77 bits); the floor exists for consistency with the one credential rule, and the meter argues for more.
- Never offers or prefills the master password. Typing the master password into a second dialog is exactly the phishing shape the product forbids, it turns a leaked file into an offline brute-force oracle for the master password, and it fails the scenario the backup exists for — the master password being the lost thing.
- Requires an explicit "I saved this password somewhere safe" acknowledgment before Export enables. Losing the passphrase loses the backup forever; the dialog says so.
- Copies clear automatically per the existing clipboard auto-clear, and the mobile screen showing the passphrase carries the secure flag.
- Writes `baluard-backup-YYYY-MM-DD.bldbak` — generic, dated, no slug. The `.bldbak` extension echoes the file magic and deliberately avoids `.baluard`, which is the vault marker filename inside vault directories. MIME `application/octet-stream`.
- Auto-verifies in memory before the save surface opens: it re-derives the key from the passphrase STRING (never reuses the derived key, so a normalization bug in either direction is caught at the source), decrypts, strips padding, parses, and counts. Toast: "Backup checked: N entries." A self-check can still pass when the same bug exists in both directions — the committed reference decryptor, run in CI against fresh Rust output, is the real correctness guard. The CLI in `--direct` mode holds the destination path and MAY additionally re-read the written file; GUI surfaces cannot, because the webview Blob download and the Android SAF picker hand bytes to the platform with no path back, and the plan does not claim to detect cloud-sync truncation.

**Import (all surfaces).** File picker (or `baluard import`), sniff detects the magic, dialog prompts: "This backup is protected. Enter the password you saved when you created it — it is not your master password." The dialog names the file. No autofill from the vault, no reprompt coupling. Success reports the same imported/skipped/folders summary as plaintext import.

**Wordlists.** Use the existing EFF wordlist assets per surface (desktop ships en + es). Where a surface lacks a localized list, English fallback is acceptable; the passphrase is NFKC-normalized and format-agnostic.

## 8. Platform wiring

**Transport first, because it shaped the format's reach.** The daemon rejects request frames over 4 MiB and the Tauri bridge caps responses at 5 MiB, so a byte-carrying route would make every bucket above 1 MiB dead spec on daemon-routed surfaces — padding would make large vaults LESS importable than plaintext. Daemon surfaces therefore move PATHS, not bytes: `vault.export` takes `{"format": "baluard-encrypted", "passphrase": "...", "out_path": "..."}` and the daemon builds and writes the container itself, answering `{"written_bytes": N, "entries": N}`; `vault.import` takes `{"format": "baluard-encrypted", "passphrase": "...", "in_path": "..."}` and answers the usual summary. No base64, no frame caps, no extra memory copies through IPC. This is the recovery-sheet architecture (one Rust-side writer, path handling never in the webview) applied to backups. Mobile has no daemon: UniFFI is in-process, and `export_encrypted_backup(passphrase) -> Vec<u8>` / `import_encrypted_backup(bytes, passphrase) -> String` ride bytes directly with no transport ceiling. The format itself is transport-blind — the same file, whatever wrote it.

- **Core** (`crates/baluard-core/src/import/backup_container.rs`): header build/parse, key derivation, chunked encrypt/decrypt, padding, sniffing, parameter caps, and the §6 pre-decrypt layout rules. One new direct dependency: `unicode-normalization` (NFKC is not in `std`; the crate is already in the tree transitively). `argon2`, `aes-gcm`, `hkdf`, and `rand` are existing dependencies.
- **Zeroization requirements** (invariant, reviewed, tested where testable): the container module holds `dk`, the file key, the padded plaintext, and the NFKC-normalized passphrase in `Zeroizing` buffers. Daemon handlers extract the passphrase from the payload into a `Zeroizing` binding immediately, before any `serde_json::Value` exists to hold a copy — a `Value`'s strings cannot be zeroized, so extract-then-zero is the only compliant pattern. The auto-verify path re-derives from the same `Zeroizing` passphrase and drops its own buffers the same way.
- **Runtime** (`VaultState`): `export_backup_encrypted(passphrase, out_path)` assembles the v1 JSON (existing `export_backup`), wraps the container, runs the in-memory verify, and writes the file — behind `assert_export_allowed`. Import symmetric: `import_backup_encrypted(passphrase, in_path) -> summary`, reading the file, checking the §6 layout rules, decrypting, and riding the existing pipeline.
- **Daemon**: the two routes above, both token-gated like today. A wrong passphrase or damaged file is an `err_response` — never a skipped-entry summary, which would render the failure as "Imported 0, skipped 1" and hide the real problem. Sniffing gains an `ImportFormat::BaluardEncrypted` variant (magic-based) alongside the existing name-keyed dispatch, and every surface reads BYTES before sniffing — the CLI's current `read_to_string` errors on binary before any sniff could run.
- **CLI**: `baluard export --encrypted <path>` prompts for the backup passphrase (generator printed with `--generate`), passes the path in daemon mode, and in `--direct` mode builds the container locally (and may re-read to verify, since it holds the path). `baluard import` sniffs the magic and prompts. `BALUARD_BACKUP_PASSPHRASE` env override for the e2e harness, mirroring the established env-first pattern. The daemon path transport retires the CLI's 50 MiB byte pre-check for encrypted backups; direct mode reads the file itself.
- **Desktop**: passphrase dialog in the Settings export flow, then the Rust-side save dialog (same pattern as the recovery sheet: the webview never holds a path and never touches Blob download for backups), and the Rust-side open dialog for import. Auto-verify toast.
- **Mobile**: same flow on `SettingsScreen`'s Data section; the passphrase screen carries `SecureFlag`; the bytes ride the existing SAF saver (`application/octet-stream`).

## 9. Test plan

- **Unit (core)**: header round-trip with byte-exact layout assertions (65 bytes, no length field); key derivation reproducibility (same inputs, same key) and header-tamper sensitivity (flip one header bit, decryption must fail); NFKC normalization of an accented es/pt passphrase (composed and decomposed forms both open the file); chunk counter/final-flag enforcement (truncated file, removed middle chunk, duplicated chunk, and trailing garbage appended after the final chunk all fail); padding bucket round-trip and the 256 MiB fail-closed cap; parameter caps (at-bound pass, over-cap fail, including the reserved-byte and chunk-size checks); wrong-passphrase generic error; sniff precedence over the v1 plaintext sniff.
- **Published vectors**: the golden file lives at `crates/baluard-core/tests/golden/backup-v1.bldbak` (256 KiB bucket, 4 chunks, fixed salt/nonce prefix, 64 MiB/3/1, tiny fixed payload) with its full derivation transcript in the `.txt` sidecar (passphrase, header hex, expected SHA-256). A Rust test pins it byte-for-byte: `backup_container::tests::golden_vector_is_reproducible` re-encrypts the same inputs with the deterministic `encrypt_with_entropy` variant and fails on any drift in header layout, KDF wiring, chunk framing, or serialization. Alongside it, `scripts/decrypt_backup.py` — a standalone reference decryptor (Python, `argon2-cffi` + `cryptography` declared; stdlib has neither Argon2id nor AES-GCM; everything else is stdlib) — proving a third party can implement the format from the spec alone. The script runs in CI against fresh Rust output, including a non-ASCII passphrase case.
- **Roundtrip (core)**: all 8 cipher kinds through export → encrypt → decrypt → import, semantic-equality assertions, passkey private keys and TOTP seeds intact.
- **E2E (CLI layer, existing harness)**: init → entries → `export --encrypted` with `BALUARD_BACKUP_PASSPHRASE` → wrong passphrase refused → second vault created → `import` with the passphrase → entries present; auto-verify output asserted. A multi-megabyte-bucket roundtrip through the daemon path transport (the transport-boundary case the byte-carrying design would have failed). Layout-rule unit pins: trailing garbage after the final chunk, a non-bucket plaintext size, a bad padding byte, and a non-UTF-8 payload all fail before or at decrypt.
- **Surface tests**: desktop vitest for the passphrase dialog states (generated default, saved-checkbox gating, custom-passphrase floor), mobile compile + manual checklist for the secure-flag passphrase screen.

## 10. Boundaries and follow-ups

- Restoring into a fresh install currently requires creating a vault first. A "Restore from backup" action on the setup screen is the fix and is deliberately out of the first slice.
- Repeat restores duplicate entries (documented). A "skip entries that already exist" option is a candidate follow-up, not a v1 promise.
- Passphrase slots (change the file's passphrase without re-encrypting the body; add a biometric slot) remain a version-field upgrade path.
- Compression, if ever, arrives as a header flag in a future minor revision, never silently.
- The plaintext `baluard.vault` v1 export stays: migration out to other tools and estate printing still need it, and the spreadsheet option stays for the same reason.
- This is the first NFKC use in the codebase: the master-password path normalizes nothing today, so an accented master password typed in different Unicode forms can already fail on different keyboards. Out of scope here; ticket it.

## 11. Open decisions

- None blocking. The passphrase generator defaults to the EFF list at export (peer-reviewed position, adopted); the only watch-item is mobile wordlist localization, which is an implementation detail per surface.

## 12. Implementation order

1. Core container module, tests first (§9 unit list), golden vector committed.
2. Runtime + daemon + CLI wiring, then UniFFI + regen-bindings.
3. Desktop and mobile UI slices with i18n (en/es/pt).
4. Wave verification (fmt, clippy, core suite, vitest, gradle, `just test-e2e` with the new flow), agy review, per-surface commits, parity-matrix and D-record updates.
