# Phase A (Import/Export) Review

**Reviewer:** TARS (automated code review)
**Date:** 2026-05-31
**Scope:** 8 import parsers, 2 export formats, daemon routes, CLI wiring

---

## Summary

The import/export system is well-structured with consistent patterns, good error handling, and proper security foundations (token-gated daemon routes, peer UID verification, frame size limits). The code compiles clean (0 errors) with only benign warnings. All 26 import-related tests pass.

**Critical issues: 1 | High: 2 | Medium: 4 | Low: 4**

---

## Findings

### [Critical] BW JSON parser ignores folders entirely

**File:** `crates/idtty-core/src/import/bw_json.rs:296,305`

The BW JSON parser deserializes `BwFolder` structs and reads `item.folder_id` but never:
1. Builds a mapping from folder UUID to folder name
2. Calls `result.add_with_folder()` instead of `result.add()`

All imported BW JSON ciphers land in the root folder regardless of their original organization.

```rust
// Line 296: folder_id hardcoded to None
folder_id: None, // Resolved later via folder_map

// Line 305: plain add() discards folder info
result.add(cipher);
```

The `BwExport.folders` field and `BwItem.folder_id` are deserialized but never used. The `BwFolder` struct triggers dead_code warnings.

**Fix:** Build a `HashMap<String, String>` mapping folder_id to folder_name from `export.folders`, then use `result.add_with_folder(cipher, folder_name)` for each item.

---

### [High] Export writes plaintext secrets to user-specified path without confirmation

**File:** `crates/idtty-cli/src/commands/mod.rs:handle_export` (end of file)

The `handle_export` function writes fully decrypted vault contents (passwords, card numbers, SSNs, SSH private keys) to an arbitrary filesystem path with no overwrite confirmation and no warning about plaintext storage:

```rust
std::fs::write(path, &resp.payload)
    .map_err(|e| format!("Failed to write {path}: {e}"))?;
```

The export JSON has `"encrypted": false` hardcoded (`export.rs:292`). An existing file at that path is silently overwritten.

**Fix:** 
1. Add a confirmation prompt if the file already exists.
2. Print a clear warning that the export contains unencrypted secrets.
3. Set file permissions to 0600 on the output file (on Unix).

---

### [High] KeePass XML imports everything as Login type regardless of content

**File:** `crates/idtty-core/src/import/keepass_xml.rs:90-110`

All KeePass entries are hardcoded as `CipherKind::Login`. KeePass XML has no explicit type discriminator, but entries without UserName/Password are common (e.g., custom entries, TOTP-only entries). These become Login ciphers with empty username/password fields, which is semantically incorrect and confusing in the UI.

```rust
kind: CipherKind::Login(LoginData {
    username,
    password,
    uris,
    // ...
}),
```

**Fix:** Detect entries that have no username AND no password and import them as `CipherKind::SecureNote` instead, preserving all fields as custom fields + notes.

---

### [Medium] BW JSON parser does not handle "ciphers" key correctly for folder resolution

**File:** `crates/idtty-core/src/import/bw_json.rs:114-120`

The parser chains `items` and `ciphers` arrays from BW exports:
```rust
let items: Vec<&BwItem> = export.items.iter().chain(export.ciphers.iter()).collect();
```
But the folder_map is never populated (see Critical finding above), and if it were, the index-based folder_map used by `import_ciphers` in `state.rs` would break because the indices would need to account for the chained items+ciphers ordering.

---

### [Medium] No import size limit on file read in CLI

**File:** `crates/idtty-cli/src/commands/mod.rs:handle_import`

```rust
let file_data = std::fs::read_to_string(path)
    .map_err(|e| format!("Failed to read {path}: {e}"))?;
```

The CLI reads the entire file into memory without size checks. A user pointing import at a multi-GB file would cause OOM. The daemon side is protected by `MAX_FRAME_SIZE` (4MB), but the CLI reads the file before sending.

**Fix:** Add a pre-read file size check (e.g., max 10MB for text, 50MB for 1PUX ZIP).

---

### [Medium] LastPass CSV last row parsing may miss trailing comma variations

**File:** `crates/idtty-core/src/import/lastpass_csv.rs` test `lastpass_no_folder`

The test CSV has 8 trailing commas but the header only has 7 columns. While `csv::ReaderBuilder::flexible(true)` handles this, the test masks that LastPass exports can have variable column counts. The `col_extra` and `col_fav` columns may shift position in some LastPass export versions. The parser should validate that key columns were found.

**Fix:** After column detection, verify that at least `url`, `username`, `password`, and `name` columns were found. Log a warning if expected columns are missing.

---

### [Medium] 1PUX ZIP extraction falls back to any .json file in archive

**File:** `crates/idtty-core/src/import/onepassword_1pux.rs:155-170`

```rust
// Fallback: try any .json file in the archive
for i in 0..archive.len() {
    if let Ok(mut file) = archive.by_index(i) {
        let name = file.name().to_string();
        if name.ends_with(".json") || name.ends_with(".data") {
```

If `export.data` is missing, the parser reads any JSON file in the ZIP. A crafted ZIP could inject arbitrary JSON data. While the data is just parsed into `CipherInput` structs (no code execution), this is an unnecessary attack surface.

**Fix:** Remove the fallback or at minimum log a warning when falling back to a non-standard file.

---

### [Low] Dead code warnings in import modules

**Files:** Multiple import files

8 compiler warnings from unused struct fields across `bw_json.rs` and `onepassword_1pux.rs`. These are deserialization structs where not all fields are consumed - this is intentional for forward compatibility, but the warnings should be suppressed.

```
warning: unused import: `uuid::Uuid` (bw_json.rs:11)
warning: field `folders` is never read (bw_json.rs:19)
warning: fields `id` and `name` are never read (bw_json.rs:28)
warning: field `fido2_credentials` is never read (bw_json.rs:63)
warning: field `type` is never read (bw_json.rs:75)
warning: field `section` is never read (onepassword_1pux.rs:65)
warning: field `id` is never read (onepassword_1pux.rs:70)
```

**Fix:** Add `#[allow(dead_code)]` to the affected structs, or annotate unused fields with `#[serde(skip)]` if they truly aren't needed for deserialization.

---

### [Low] Chrome CSV does not detect duplicate headers

**File:** `crates/idtty-core/src/import/chrome_csv.rs`

If the CSV has duplicate column headers (malformed export), `position()` returns the first match. This silently uses wrong column data. Same pattern in `firefox_csv.rs`, `lastpass_csv.rs`, `onepassword_csv.rs`.

**Fix:** Validate that detected column indices are unique.

---

### [Low] Export CSV silently drops non-Login/non-SecureNote ciphers

**File:** `crates/idtty-core/src/import/export.rs:export_bw_csv`

```rust
_ => {} // Skip non-login/non-note types in CSV
```

Cards, Identities, and SSH Keys are silently omitted from CSV export with no warning. The user gets fewer entries than expected with no indication of data loss.

**Fix:** Track and report the count of skipped ciphers. Print a warning in the export response.

---

### [Low] 1PUX import reads the file twice for 1PUX format

**File:** `crates/idtty-cli/src/commands/mod.rs:handle_import`

```rust
// First read as string (for all formats)
let file_data = std::fs::read_to_string(path)...;
// Then re-read as bytes for 1PUX
let bytes = std::fs::read(path)...;
```

For 1PUX format, the file is read twice. The first `read_to_string` call on a binary ZIP file will also potentially fail or produce garbage.

**Fix:** Check the format first, and only read as string for text-based formats. Read as bytes for 1PUX.

---

## Correct: What's Already Good

1. **Consistent error handling** - All parsers use `ImportResult` with skip/error tracking. No panics or unwraps on user data. Parse errors are captured per-row, not fatal.

2. **Token-gated routes** - `vault.import` and `vault.export` are in `TOKEN_REQUIRED_ACTIONS` (handler.rs:131-132). Import/export requires an authenticated session.

3. **Encrypted export rejection** - BW JSON parser correctly rejects `encrypted: true` exports with a clear error message (bw_json.rs:122-125).

4. **Password zeroization** - The handler zeroizes request payload after use (`req.payload.zeroize()`, handler.rs:362).

5. **Frame size limit** - 4MB daemon frame limit prevents OOM via socket (handler.rs:20).

6. **CSV flexible parsing** - All CSV parsers use `flexible(true)` to handle ragged rows gracefully.

7. **1PUX ZIP safety** - The ZIP is read in-memory (not extracted to filesystem), eliminating path traversal risk.

8. **roxmltree XML safety** - Version 0.20 has built-in entity expansion limits, preventing billion laughs attacks.

9. **Export round-trip tested** - `export_bw_json_round_trip` test verifies exported JSON parses back correctly.

10. **Folder creation with dedup** - `import_ciphers` in state.rs handles duplicate folder names gracefully by looking up existing folders.

---

## Missing Test Coverage

| Area | Status |
|------|--------|
| BW JSON folder round-trip | **Missing** - No test verifying folder_id resolves after import |
| BW CSV with malformed rows | **Missing** - No test for broken CSV rows |
| Export with all 5 cipher types | **Partial** - JSON export tested, CSV only tests Login + Card skip |
| Daemon import route | **Missing** - No integration test for vault.import handler |
| KeePass XML with custom fields | **Covered** |
| 1PUX with multiple accounts/vaults | **Missing** |
| Export of empty vault | **Missing** |
| Import of empty data | **Covered** (multiple parsers) |
| 1PUX identity + SSH key | **Missing** |
| Large import (1000+ entries) | **Missing** - performance/stress test |

---

## Recommended Priority

1. **Fix Critical** (BW JSON folder resolution) - data loss for organized vaults
2. **Fix High** (export safety prompts + file perms) - security UX
3. **Fix High** (KeePass type detection) - semantic correctness
4. **Fix Medium** (import file size check) - robustness
5. Suppress dead_code warnings (Low, cosmetic)
