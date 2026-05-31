# Plan: Desktop BW Parity - Final Push (A-G)

> Goal: Full Bitwarden desktop feature parity (or improved) across CLI, daemon, and desktop app.
> Process: Sequential phases. Peer review after each. Fix issues before moving on.

---

## Phase A: Import/Export
**Status**: In Progress

### Import Formats
1. BW JSON (full fidelity: all 5 types, folders, URIs, history, custom fields)
2. BW CSV (lossy: logins only, single URI)
3. Chrome CSV (url, username, password, name)
4. Firefox CSV (same shape as Chrome)
5. LastPass CSV (url, username, password, name, grouping, extra)
6. 1Password .1pux (ZIP+JSON, full fidelity)
7. 1Password CSV (lossy fallback)
8. KeePass XML (title, username, password, url, notes, custom fields)

### Export Formats
1. BW-compatible JSON (all types, folders, history)
2. BW-compatible CSV (logins only)
3. Encrypted JSON (IDtty Argon2id + AES-256-GCM, NOT BW's scheme)

### Scope
- Rust core: `crates/idtty-core/src/import/` module with parsers
- Daemon: `vault.import` and `vault.export` routes
- CLI: `idtty import <format> <file>` and `idtty export <format> <file>`
- Desktop: Import/Export UI screens

### Acceptance Criteria
- [ ] Each import format has a parser in idtty-core
- [ ] Each parser outputs `Vec<CipherInput>` for batch-create
- [ ] Import handles malformed input gracefully (skip bad entries, report count)
- [ ] BW JSON round-trip: export → re-import = identical data
- [ ] CLI commands work for all formats
- [ ] Daemon routes work
- [ ] Desktop UI: import screen with format dropdown + file picker
- [ ] Desktop UI: export screen with format + path selection
- [ ] All existing tests pass
- [ ] New tests per format with fixtures

---

## Phase B: Reprompt
**Status**: Pending

Per-entry `reprompt: bool` flag. When enabled, viewing password or editing entry requires master password confirmation.

- [ ] `reprompt: bool` on `Cipher` + `CipherMeta`
- [ ] Daemon route: `vault.reprompt_verify` (password + session token → 30s grant)
- [ ] Desktop: shield icon on reprompt entries, modal challenge before reveal/edit
- [ ] CLI: master password prompt on `get` for reprompt entries

---

## Phase C: Password Health Reports
**Status**: Pending

Local computation: weak (short/common), reused (same password across entries), old (>90 days unchanged).

- [ ] Rust core: password scoring functions
- [ ] Daemon route: `vault.health_report` → { weak: [...], reused: [...], old: [...] }
- [ ] Desktop: health dashboard view
- [ ] CLI: `idtty health` command

---

## Phase D: Attachments
**Status**: Pending

Encrypted file storage attached to cipher entries. Uses existing 64KB/1MB padding tiers.

- [ ] Rust core: attachment structs, file encryption/decryption
- [ ] Daemon routes: attachment upload/download/delete
- [ ] CLI: attachment commands
- [ ] Desktop: attachment UI in cipher detail view

---

## Phase E: FIDO2 / Biometric Unlock
**Status**: Pending

Platform authenticator integration per `07-2fa-analysis.md` Tier 2.

- [ ] Evaluate `libfido2` crate maturity
- [ ] FIDO2 registration flow
- [ ] FIDO2 challenge on vault unlock
- [ ] Desktop: biometric settings toggle
- [ ] Fallback for devices without FIDO2

---

## Phase F: Linked Custom Fields
**Status**: Pending

Reference fields from parent cipher type.

- [ ] `LinkedCustomField` variant in custom field enum
- [ ] Type resolution logic in Rust core
- [ ] Desktop: linked field dropdown in custom field editor

---

## Phase G: Nested Folders UI
**Status**: Pending

Tree rendering for folder hierarchy. `parent_id` already stored in data model.

- [ ] Rust core: already supports `parent_id`
- [ ] Daemon: folder tree endpoint
- [ ] Desktop: tree component replacing flat list
- [ ] Drag-and-drop folder reorganization
