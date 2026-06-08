# Tags Feature — Implementation Plan

**Date:** 2026-06-08
**Status:** Peer-reviewed

## Decisions

| Decision | Choice |
|----------|--------|
| Storage model | C: Encrypted `tags: Vec<String>` on cipher + `meta/tag_index.json` cache |
| Cache rebuild | C2: Rebuild in `VaultHandle` (core), called by daemon `list_all` |
| Git visibility | Cache committed to git (tag names visible, same as folder names) |
| Tag constraints | 64 **char** max (`.chars().count()`), any UTF-8, lowercase-normalized, max 20 per cipher, no empty/whitespace |
| Tag input UX | Free-text + autocomplete, Enter/comma to add, pills with X to remove. `stopPropagation` on Enter to prevent form submit |
| Daemon routes | `tag.list`, `tag.create`, `tag.rename`, `tag.delete`, `tag.rebuild_index` |
| CipherMeta tags | **Yes** — `list_cipher_meta_full` already decrypts all ciphers; tags in meta avoids N+1 |
| BW export | Skip tags in BW-compat format (no standard field). Tags preserved in git.
| Sync merge | Union-merge for `tag_index.json` (same as folders). Two offline devices adding tags = union of arrays |

## Peer Review Amendments (agy + peer review)

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| M1 | CRITICAL | `update_cipher` in state.rs builds `CipherInput` manually — strips tags | Add `tags` to merge block |
| M2 | CRITICAL | `attach_upload`/`attach_delete` also build `CipherInput` manually | Add `tags` to all CipherInput construction sites |
| M6 | HIGH | Git sync merge strategy undefined for `tag_index.json` | Union-merge, same as folders |
| M3 | HIGH | `EMPTY_CIPHER` needs `tags: []` | Add to VaultContext.jsx |
| M5 | MEDIUM | `clone_cipher` must copy tags | Verify and patch |
| M8 | MEDIUM | Case normalization underspecified | Store lowercase; display preserves user input |
| R3 | MEDIUM | 64-char limit must use `.chars().count()`, not `.len()` | Use `.chars().count()` |
| R4 | MEDIUM | Tag input Enter must `stopPropagation` to prevent form submit | Add to UX implementation |

---

## Phase 1: Core Data Model + Storage

**Goal:** Tags exist on ciphers. Cache works. Tests pass.

### Files changed:

1. **`crates/idtty-core/src/types.rs`**
   - Add `tags: Vec<String>` to `CipherInput` (line ~498, `#[serde(default)]`)
   - Add `tags: Vec<String>` to `CipherEnvelopeData` (line ~630)
   - Add `tags: Vec<String>` to `Cipher` (line ~703)
   - Add `tags: Vec<String>` to `CipherMeta` (line ~729) — `list_cipher_meta_full` already decrypts
   - Update test helpers (`make_cipher` etc.) to include `tags: vec![]`
   - Grep all `Cipher { .. }` and `CipherInput { .. }` struct literals for compilation

2. **`crates/idtty-core/src/vault/manifest.rs`**
   - Add `TagIndex` struct: `pub tags: Vec<String>`, `pub updated_at: u64`

3. **`crates/idtty-core/src/vault/handle.rs`**
   - Add `fn rebuild_tag_index(&self) -> Result<(), IdttyError>` — scan all decrypted ciphers, extract unique tags, write `meta/tag_index.json`
   - Add `fn list_tags(&self) -> Result<Vec<String>, IdttyError>` — read from cache, or rebuild if missing
   - Add `fn create_tag(&mut self, name: &str) -> Result<(), IdttyError>` — validate, add to index, save
   - Add `fn rename_tag(&mut self, old: &str, new: &str) -> Result<usize, IdttyError>` — rename across all ciphers + update index
   - Add `fn delete_tag(&mut self, name: &str) -> Result<usize, IdttyError>` — remove from all ciphers + remove from index
   - Add `fn validate_tag(tag: &str) -> Result<String, IdttyError>` — `.chars().count() <= 64`, non-empty, trim, lowercase-normalize
   - Add `fn validate_tags(tags: &[String]) -> Result<Vec<String>, IdttyError>` — dedup (case-insensitive), max 20, validate each
   - Update cipher CRUD to pass through `tags` field
   - Update `list_cipher_meta_full` CipherMeta construction (~line 637) to include `tags: c.tags`
   - Update `list_archived_meta` CipherMeta construction (~line 1965) to include `tags: c.tags`
   - Update ALL `CipherInput { .. }` struct literals (grep first) — handle.rs, cipher.rs, health.rs, conflict.rs

4. **`crates/idtty-core/src/crypto/aead.rs`** (if AAD needs tag data — verify)
   - Tags are inside the envelope, encrypted with item key. No AAD change needed.

### Tests:
- `create_cipher_with_tags` — roundtrip tags through create + get
- `tag_validation_rejects_empty` — empty/whitespace tags rejected
- `tag_validation_max_length` — 65-char tag truncated or rejected
- `tag_validation_case_insensitive_dedup` — ["Work", "work"] → ["Work"]
- `tag_validation_max_count` — 21 tags rejected
- `rebuild_tag_index_from_ciphers` — index reflects all unique tags
- `create_tag_to_empty_index` — pre-create tag appears in index
- `rename_tag_updates_all_ciphers` — rename propagates
- `delete_tag_removes_from_all_ciphers` — delete propagates

---

## Phase 2: Daemon IPC Routes

**Goal:** CLI can manage tags. Cache rebuilt on `vault.list_full`.

### Files changed:

1. **`crates/idtty-daemon/src/handler.rs`**
   - Register routes: `"tag.list"`, `"tag.create"`, `"tag.rename"`, `"tag.delete"`, `"tag.rebuild_index"`

2. **`crates/idtty-daemon/src/state.rs`**
   - Add `pub async fn list_tags(&self) -> Result<String, String>`
   - Add `pub async fn create_tag(&self, payload: &str) -> Result<String, String>`
   - Add `pub async fn rename_tag(&self, payload: &str) -> Result<(), String>`
   - Add `pub async fn delete_tag(&self, payload: &str) -> Result<String, String>`
   - Add `pub async fn rebuild_tag_index(&self) -> Result<String, String>`
   - Update `list_all()` to include `"tags"` in response JSON (from cache)
   - Update `list_all()` to call `rebuild_tag_index` before returning
   - Update `cipher_to_json()` to include `"tags"` field
   - Update `add_cipher`/`update_cipher` to pass `tags` through to core
   - **CRITICAL**: Update ALL manual `CipherInput { .. }` construction sites:
     - `update_cipher` merge block (~line 465-518) — add `tags` field
     - `attach_upload` (~line 949) — add `tags` field
     - `attach_delete` (~line 1076) — add `tags` field

---

## Phase 3: CLI Commands

**Goal:** Full CLI parity for tags.

### Files changed:

1. **`crates/idtty-cli/src/commands/mod.rs`**
   - Add `TagCommands` enum: `List`, `Create`, `Rename`, `Delete`
   - Wire into command dispatch
   - `tag list` — print one tag per line
   - `tag create <name>` — create tag
   - `tag rename <old> <new>` — rename tag
   - `tag delete <name>` — delete tag

---

## Phase 4: Desktop UI

**Goal:** Full tag UX in desktop app.

### Files changed:

1. **`desktop/src/context/VaultContext.jsx`**
   - Add `tags: []` to `EMPTY_CIPHER`
   - Add `tags` signal (populated from `vault.list_full` response)
   - Add `selectedTag` signal
   - Add `setSelectedTag` setter

2. **`desktop/src/components/AddEditCipherForm.jsx`**
   - Add tag input: text field + autocomplete dropdown from `vault.tags()`
   - Enter/comma adds tag pill, X removes. **`e.stopPropagation()` on Enter keydown** to prevent form submit
   - Pre-populate tags when editing

3. **`desktop/src/components/CipherDetail.jsx`**
   - Show tags as pills in header (after folder badge)

4. **`desktop/src/components/VaultView.jsx`**
   - Add "Tags" sidebar section after folders
   - Click tag to filter (sets `selectedTag`)
   - Pass `tags` prop to AddEditCipherForm

5. **`desktop/src/lib/filters.js`**
   - Add `filterByTag(ciphers, tag)` function

6. **`desktop/src/lib/payload.js`**
   - Update `buildAddPayload` and `buildUpdatePayload` to include `tags`

7. **`desktop/src/lib/cipherSchema.js`**
   - Update `cipherToFlat` to include `tags`
   - Update `toKind` to pass `tags` through

8. **`desktop/src/i18n/locales/en.json`**
   - Add `entry.tags`, `entry.addTag`, `entry.tagPlaceholder`

---

## Phase 5: Import/Export

**Goal:** Tags round-trip through import/export. 1Password importer preserves tags.

### Files changed:

1. **`crates/idtty-core/src/import/onepassword_1pux.rs`**
   - Preserve all tags on cipher instead of using first tag as folder hint

2. **`crates/idtty-core/src/import/export.rs`**
   - Export tags in BW-compatible format
   - Add `tags` field to export struct

---

## Phase 6: Docs + Progress

1. **`docs/progress.md`** — Update with tags feature status
2. **`docs/architecture-decisions.md`** — Add DOMAIN for tags
3. **`AGENTS.md`** — Update key concepts and file map
