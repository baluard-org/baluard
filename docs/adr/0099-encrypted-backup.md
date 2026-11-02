# ADR 0099. Encrypted Backup Container

> Status: Accepted (2026-10-05). The container, the daemon routes, the CLI flow, the desktop dialog commands, the mobile UniFFI surface, the golden vector, and the reference decryptor are implemented.

## Context

The plaintext `baluard.vault` v1 export is the first-party backup, but a file holding every secret a user owns is the weakest artifact the product writes, and it is the artifact most likely to sit in a downloads folder, a cloud drive, an email attachment, or removable media. An encrypted option closes that gap.

The requirement is stronger than encrypting the export: the file must be re-importable into a different Baluard vault, including a newly created one, and must never be locked to the vault, account, or device that made it. A competitor's default encrypted export, encrypted under the account's own key, is the cautionary pattern: it dies on key rotation, on server migration, and with the account itself. No vault key, vault ID, epoch, or account identity may participate in backup key derivation, ever.

The goals are: one passphrase unlocks the file and nothing else does; any Baluard vault can adopt every entry, re-encrypted under its own keys; the format is self-describing and published with test vectors so third parties can build readers (portability by construction and not by promise); metadata leakage stays minimal (size padded to a bucket, no slug, no counts, no timestamps in the header); and all surfaces (CLI, desktop, Android) share one Rust implementation, using the project primitives AES-256-GCM and Argon2id.

### Threat statement

The container protects the confidentiality and integrity of the full vault contents while the file is at rest (cloud folder, removable media, email attachment) or in transit. It does not protect against a compromised device or a screen observer during export, because the export dialog shows the passphrase and that moment is exposure. It does not protect against a weak passphrase: Argon2id raises the cost per guess but cannot rescue a guessable string, and the passphrase is the whole security of the file, which is why the default is a generator. It does not provide availability, because losing the passphrase loses the backup forever and the dialog says so plainly. It does not provide deniability, because the plaintext header announces a Baluard v1 backup to anyone holding the file.

The backup serves portability and cold storage. It is not a replacement for the recovery phrase (vault identity) or for the git remote (continuity and sync), and the interface must never blur those three.

### Prior art and rejected options

Bitwarden's account-restricted export binds to the account key, so re-import into another account fails, the same email on another server fails, and key rotation bricks every old file. Its password-protected mode has the desired shape (user-chosen passphrase, salted KDF, importable anywhere), but the format is undocumented, third-party readers do not exist, and it has a history of dropping folders. Baluard copies the shape, publishes the format, and keeps folders.

Aegis is the model for a portable encrypted format: a public header with KDF and AEAD parameters, a documented layout, published test vectors, and a reference decrypt script, which is why third-party applications can open its backups. Baluard copies the philosophy and modernizes the primitives (Argon2id over scrypt, AES-256-GCM as the standing invariant).

age is the strongest alternative: a reviewed specification, STREAM chunked payload, header binding, and a universal escape hatch. It was rejected for this format on invariants, since age uses scrypt and ChaCha20-Poly1305 while Baluard standardizes on Argon2id and AES-256-GCM, and it defines no Unicode normalization rule. Baluard takes its construction instead: STREAM chunking, header bytes bound into key derivation and authenticated data, and a final-chunk flag. If the product ever values opening with a stock tool over the invariants, age is the answer.

Zip and 7z containers were rejected on every axis that matters. Legacy ZipCrypto is broken by known-plaintext attacks. WinZip AES derives keys with PBKDF2-HMAC-SHA1 at a fixed 1000 iterations, which is neither memory-hard nor raisable and is orders of magnitude weaker than Argon2id against GPU guessing. The 7z KDF is iterated SHA-256, also not memory-hard. Archive listings leak names and sizes unless header encryption is explicitly enabled, stock file managers cannot open encrypted archives so non-technical users gain nothing, and archive parsers bring their own attack surface (path traversal, decompression bombs) that a fixed 65-byte header reader does not have.

Encrypting to a recipient vault public key was rejected: it recreates the lock-in this format exists to prevent and fails the total-loss scenario in which the target vault no longer exists. XChaCha20-Poly1305 was rejected: AES-256-GCM is the stated vault invariant and is present in every platform's standard crypto library, which also matters to third-party implementers, and per-file unique keys remove the large-nonce advantage. Key slots in the Aegis or LUKS style are deferred and not rejected: changing a passphrase without re-encrypting the body is real but solves no current user problem, and the version field is the upgrade path.

## Decision

### Container format

Define the single-file `baluard.backup` v1 container with magic `BLDBAK`, file extension `.bldbak`, and MIME type `application/octet-stream`. The extension echoes the file magic and deliberately avoids `.baluard`, the vault marker filename inside vault directories. The plaintext header is exactly 65 bytes. All header integers are little-endian. Two integers follow age's STREAM convention and are big-endian: the per-chunk nonce counter and the in-band payload length. There is no compression, which would add a size side channel and a canonicalization flag for no current benefit.

| Offset | Size | Field | v1 value |
|---|---|---|---|
| 0 | 6 | magic, ASCII `BLDBAK` | fixed |
| 6 | 1 | container major version | `1` |
| 7 | 1 | KDF ID | `1` (Argon2id) |
| 8 | 1 | AEAD ID | `1` (AES-256-GCM) |
| 9 | 1 | reserved | `0` |
| 10 | 4 | `memory_kib` | 65536 on export |
| 14 | 4 | `iterations` | 3 on export |
| 18 | 4 | `parallelism` | 1 on export |
| 22 | 32 | KDF salt | random |
| 54 | 7 | nonce prefix | random |
| 61 | 4 | chunk size | 65536 |

The header has no payload-length field. Printing the length in the clear would give every observer the exact vault size to the byte and defeat the padding, letting an observer watching backups over time count individual entries appearing and disappearing. The header also carries no vault ID, slug, epoch, device ID, entry or folder count, timestamp, application version, hostname, or passphrase hint. The reserved byte must be zero in v1, and importers reject a non-zero value, as well as unsupported IDs or versions, with an update-required error so that a future v1.x flag can never be silently misread by an old reader.

### Key derivation

Normalize the passphrase with Unicode NFKC and never trim it. Normalization is part of the specification because an accented es or pt wordlist word can arrive in different Unicode forms from different keyboards, so a mismatch must be impossible and not merely rare. Derive a 32-byte `dk = Argon2id(NFKC(passphrase), salt, memory_kib, iterations, parallelism)`. Derive the file key with HKDF-SHA256: extract with salt `b"baluard.backup.v1"` over `dk`, expand with the exact 65 header bytes as `info`. The header is therefore key-committing: any change to version, IDs, or parameters changes the key, and a tampered header fails authentication instead of decrypting to garbage.

Export always uses the fixed constants 65536 KiB, 3 iterations, parallelism 1, never machine-calibrated values: a calibrated desktop would write files a phone cannot open, and calibration breaks reproducible vectors. The header carries the parameters, so raising KDF defaults in a future release needs no version bump and the import caps leave room above the export constants.

### Payload framing and padding

The plaintext is a big-endian u64 payload length, the `baluard.vault` v1 JSON bytes, and zero padding, such that the total equals exactly one bucket: 256 KiB, 1 MiB, 4 MiB, 16 MiB, 64 MiB, or 256 MiB. The length prefix exists only inside authenticated ciphertext. Bucket rounding hides the vault's true size, applying the vault's padded-bucket thesis to the whole file. A payload larger than 256 MiB minus eight bytes fails closed on export. The payload is metadata-only JSON with no attachment blobs, so 256 MiB represents hundreds of thousands of entries. The payload cap and the import memory cap happen to both be 256 MiB but are unrelated, and changing one does not touch the other.

### Encryption

Encrypt the padded plaintext in 65536-byte AES-256-GCM chunks (the STREAM construction). Each chunk uses a 12-byte nonce consisting of the seven-byte header prefix, a big-endian u32 chunk counter starting at zero, and a one-byte final flag that is zero except for the last chunk. The full 65-byte header is the authenticated data for every chunk. On disk, each chunk is ciphertext followed by its 16-byte tag, so a chunk occupies 65552 bytes. Because the counter and final flag sit inside the nonce, a removed tail leaves a last chunk lacking the final flag and the tag check fails, which gives chunk-level integrity plus truncation and reordering detection.

Constant memory is a property of the chunk construction and not of the surfaces: the container processes one chunk at a time, but a whole-file surface still holds the padded plaintext, the ciphertext, and the parsed JSON together, so a 256 MiB vault peaks at several multiples of 256 MiB. That is acceptable on desktop, and mobile sizes are far below the top buckets in practice. Export writes the header and chunks in one pass to the destination and no plaintext temporary file ever exists.

### Import rules and caps

Import checks every layout rule before the first Argon2id call, because the layout is fully determined by the file length. `file_len - 65` must be a positive multiple of 65552. The implied plaintext size must equal a bucket size exactly. The final flag must belong to the last chunk and to no other, and trailing data, truncation, or reordering is rejected. The in-band length must satisfy `8 + payload_length <= plaintext_len` and is never used to size an allocation. After decryption the padding must be zero and the payload must be valid UTF-8 before parsing. The Rust importer and the reference decryptor must agree on these rules, and the committed script is the second implementation that keeps them honest.

Import caps are `memory_kib <= 262144`, `iterations <= 6`, and `parallelism <= 4`. Chunk size must equal 65536, KDF and AEAD IDs must equal 1, major version must equal 1, and reserved must be zero. Any cap violation reads as an update-required error, since the realistic benign cause is a future Baluard writing larger settings, and a hostile file learns nothing. Parameters inside the caps whose allocation still fails on the device, and parameters below the Argon2id legal floor (`m < 8 * p`, which cannot be genuine), use the generic damaged-file error, because allocation failure is not portably distinguishable from any other Argon2id failure. The memory cap is a crash guard: on mobile, an overcommitted allocation dies by an uncatchable kill on first touch, so the cap and not error handling protects the process.

Decryption failure and corruption are indistinguishable by design: the only error is "wrong password or damaged file", and nothing more precise is ever surfaced. A wrong passphrase or damaged file is an error response and never a skipped-entry summary, which would render as "Imported 0, skipped 1" and hide the real problem.

A successful decrypt proves only that someone knew the passphrase, and anyone can forge a valid file. The decrypted payload therefore goes through the existing `parse_backup` validation (format ID, version, manifest counts versus content) and the existing import pipeline. Deeper checks such as folder depth and per-field limits belong to that pipeline and are not re-implemented in the container; the container adds no trust to the payload. Entries receive fresh UUIDs and are encrypted under the target vault's keys. Restoring the same file twice duplicates every entry, which v1 documents instead of guessing at deduplication keys. Folder hierarchy follows the existing flat-import behavior.

Import auto-detection checks the first six bytes for `BLDBAK` before the plaintext `baluard.vault` header sniff and the migration parsers, so the formats never collide. Every surface reads bytes before sniffing, because a text read errors on binary data before any sniff could run.

### Export interface and user experience

Export remains behind the existing master-password re-prompt, the same credential and not a new one. The passphrase dialog defaults to a generated passphrase of six words from the EFF wordlist, shown in plain text with Copy and Regenerate (about 70 bits from the merged 3344-word list, adequate given the 64 MiB Argon2id cost). A custom passphrase requires confirmation and at least eight characters, matching the master-password rule, with an advisory strength meter. The tension is deliberate: an eight-character typed passphrase is weak against offline guessing, and the generator default carries the real security. Desktop printing is out of scope for v1 because the webview print path is unreliable across platforms; a Rust-side renderer in the style of the recovery sheet is follow-up scope.

The master password is never offered or prefilled. Typing it into a second dialog is the phishing shape the product forbids, it would turn a leaked file into an offline brute-force oracle for the master password, and it fails the scenario the backup exists for, in which the master password is the lost item. The user must acknowledge that the passphrase was saved before Export enables, and the dialog states that losing it permanently loses the backup. Copies clear through the existing clipboard auto-clear, and mobile screens showing the passphrase carry the secure flag. The file is named `baluard-backup-YYYY-MM-DD.bldbak`, generic and dated with no slug. The import dialog names the file and says: "This backup is protected. Enter the password you saved when you created it. It is not your master password." It never autofills from the vault, and success reports the same imported, skipped, and folder summary as plaintext import. Each surface uses its existing EFF wordlist assets (desktop ships en and es), with English acceptable as a fallback because the passphrase is NFKC-normalized and format-agnostic.

### In-memory verification

Before opening any save surface, export re-derives the key from the passphrase string (never reusing the derived key, so a normalization bug in either direction is caught at the source), decrypts its own output, strips padding through the in-band length, parses the JSON, and counts entries, then reports "Backup checked: N entries." This verifies the bytes produced and not the final file after a platform save or cloud synchronization: the webview download and the Android document picker hand bytes to the platform with no path back, so GUI surfaces cannot reopen the destination and the design does not claim to detect cloud-sync truncation. The CLI direct mode holds the destination path and may additionally reread it. A self-check can pass when the same bug exists in both directions, so the reference decryptor run against fresh Rust output is the real correctness guard.

### Platform wiring

Daemon-routed surfaces move file paths and not bytes. The daemon rejects request frames over 4 MiB and the Tauri bridge caps responses at 5 MiB before base64 inflation, so a byte-carrying route would make every bucket above 1 MiB unusable and padding would make large vaults less importable than plaintext. `vault.export` accepts `{"format":"baluard-encrypted","passphrase":"...","out_path":"..."}`, builds and writes the container itself, and returns `{"written_bytes": N, "entries": N}`. `vault.import` accepts `{"format":"baluard-encrypted","passphrase":"...","in_path":"..."}` and returns the usual summary. Both routes are token-gated, and export runs behind `assert_export_allowed`. Mobile has no daemon: UniFFI is in-process, and `export_encrypted_backup(passphrase)` returns bytes while `import_encrypted_backup(bytes, passphrase)` returns a summary string, with no transport ceiling. The format is transport-blind, so the same file results whatever wrote it.

The desktop webview never holds a path. In keeping with the forbidden-keys gate, `in_path` and `out_path` are forbidden payload keys on the desktop webview, so a compromised webview cannot gain a file read or write primitive through `vault.import` or `vault.export`. Desktop uses the dedicated Rust-side commands `backup_save_encrypted` and `backup_import_encrypted`, which own the native save and open dialogs and call the daemon with the path. The daemon caps container reads at 300 MB and refuses non-regular files. The CLI supports `baluard export --encrypted <path>` (with `--generate` to print a fresh six-word passphrase once), `baluard import` with magic sniffing and a passphrase prompt, and the `BALUARD_BACKUP_PASSPHRASE` environment override for the end-to-end harness, which takes precedence and makes `--generate` ignored with a note. In daemon mode the CLI passes the path, and in `--direct` mode it builds the container locally. Android uses the Data section of the settings screen with the secure flag on the passphrase screen and the existing document-saver for the bytes. Sniffing adds an `ImportFormat::BaluardEncrypted` variant based on magic alongside the existing name-keyed dispatch.

### Memory hygiene

The normalized passphrase, `dk`, the file key, the padded plaintext, each decrypted chunk after it is copied out, and the whole-vault export JSON use zeroizing buffers. Passphrase-bearing daemon payloads deserialize directly into typed structures whose passphrase field moves into a zeroizing wrapper, and the raw payload is zeroized right after parsing. A `serde_json::Value` is never constructed for such a payload because its strings cannot be zeroized. The runtime importer borrows the decrypted plaintext as `&str` and never copies it out. Argon2id and AES run on the blocking pool, and the verification path re-derives from the same zeroizing passphrase.

### Published vector and reference decryptor

The golden file `crates/baluard-core/tests/golden/backup-v1.bldbak` (256 KiB bucket, four chunks, fixed salt of `0xA5` bytes and nonce prefix of `0x5A` bytes, 64 MiB, 3, 1, a tiny fixed payload) comes with a transcript in `backup-v1.bldbak.txt` giving the passphrase, the header in hexadecimal, and the SHA-256 of the whole file. A Rust test, `backup_container::tests::golden_vector_is_reproducible`, re-encrypts the same inputs through the deterministic `encrypt_with_entropy` variant and fails on any drift in header layout, KDF wiring, chunk framing, or serialization. The standalone reference decryptor `scripts/decrypt_backup.py` (Python with `argon2-cffi` and `cryptography`, everything else standard library) proves a third party can implement the format from the specification alone. It is run by `just decrypt-vector` and by a dispatch-only CI workflow against the golden vector. The workflow does not run on push while remote CI awaits approval, and a non-ASCII passphrase case against fresh Rust output remains a test requirement that the current workflow does not cover.

### Test requirements

Core unit tests cover byte-exact header layout (65 bytes, no length field), derivation reproducibility and header-tamper sensitivity (one flipped header bit must fail), NFKC agreement between composed and decomposed forms of an accented passphrase, chunk counter and final-flag enforcement (truncated file, removed middle chunk, duplicated or swapped chunk, trailing data), bucket round trips including the 256 MiB fail-closed cap and exact fill and spill boundaries, parameter caps (at-bound pass, over-cap fail, reserved byte, chunk size, sub-floor parameters), generic wrong-passphrase error, a non-bucket plaintext size refused before key derivation, non-zero padding, non-UTF-8 payload, and sniff precedence. A round trip covers all eight cipher kinds through export, encrypt, decrypt, and import with passkey private keys and TOTP seeds intact. The end-to-end CLI harness runs init, entries, encrypted export with the environment passphrase, wrong passphrase refused, a second vault, import with the passphrase, entries present, and the verification output, plus a multi-megabyte-bucket round trip through the daemon path transport, the boundary case a byte-carrying design would have failed. Desktop tests cover dialog states (generated default, saved-acknowledgment gating, custom-passphrase floor). The mobile passphrase screen is covered by compilation and a manual secure-flag checklist.

### Boundaries and follow-ups

Restoring into a fresh install currently requires creating a vault first; a restore action on the setup screen is the fix and is out of this decision. Repeat restores duplicate entries, and a skip-existing option is a candidate follow-up and not a v1 promise. Passphrase slots (changing the file passphrase without re-encrypting the body, or adding a biometric slot) remain a version-field upgrade path. Compression, if ever added, arrives as a header flag in a future minor revision and never silently. The plaintext `baluard.vault` v1 export stays, because migration to other tools and estate printing still need it. This is the first NFKC use in the codebase: the master-password path normalizes nothing today, so an accented master password typed in different Unicode forms can already fail across keyboards. That is out of scope here and should be ticketed. The only open watch-item is localization of the mobile wordlist, an implementation detail per surface.

## Consequences

The backup is independent of the source and destination vault identities and can be adopted by any Baluard vault, including after key rotation, a master-password change, or loss of the source vault. Bucket padding hides the exact JSON size and the absence of a plaintext length hides entry-level changes across successive backups. The public format, the published golden vector, and the reference decryptor support independent implementations and keep the Rust implementation honest.

The full file and parsed JSON may coexist in memory, so peak memory exceeds the selected bucket size, and mobile vaults are expected to use smaller buckets. The passphrase is the sole secret protecting the file, and a weak typed passphrase remains vulnerable to offline guessing. The encrypted format does not include attachments, and the existing plaintext export remains available. The header identifies the file as a Baluard v1 backup to anyone who holds it.

The first release imports only into an already-open vault. A setup-screen restore flow, duplicate detection, desktop printing of the passphrase, compression, differential backups, and multiple key slots are not included; a future format revision may add slots or compression through explicit versioned fields.

## References

- `crates/baluard-core/src/import/backup_container.rs`.
- `crates/baluard-core/tests/golden/backup-v1.bldbak` and `crates/baluard-core/tests/golden/backup-v1.bldbak.txt`.
- `scripts/decrypt_backup.py`.
- `docs/adr/0085-sharing.md`, key isolation constraints.
