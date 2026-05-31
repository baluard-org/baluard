# Plan: Bitwarden Desktop Feature Parity

> Source PRD: `docs/prd-bitwarden-parity.md`

## Architectural decisions

Durable decisions that apply across all phases:

- **CipherKind is a Rust sum type (enum with associated data)**, NOT flat `Option<T>` fields. Invalid states are unrepresentable at the type level. Serialized as `#[serde(tag = "type", content = "data")]`.
- **CipherType enum**: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`. Bank/DriversLicense/Passport deferred.
- **Multi-URI**: `Vec<LoginUri>` where `LoginUri { uri, match_strategy }`. Ordered, reorderable.
- **UriMatchStrategy**: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5). Global default from `VaultSettings.default_uri_match`, per-URI override. **Type change**: `VaultSettings.default_uri_match` changes from `Option<String>` to `Option<UriMatchStrategy>` with serde migration. Unknown string values produce a hard error, not silent fallback to Domain.
- **Identity has three address lines**: `address1`, `address2`, `address3`. Not singular.
- **CipherMeta stores cipher_type + favorite + username** in manifest index (Option A: plaintext metadata, low-sensitivity). Vault list renders without decryption. These fields land on both `Cipher` and `CipherMeta` atomically (same phase).
- **Proto schema**: `vault.proto` is updated as documentation of the data model. The actual daemon wire format uses JSON strings inside `GatewayRequest.payload` — not typed proto fields. Proto updates are cosmetic until a future migration to typed proto fields is explicitly planned.
- **Password history**: `Vec<PasswordHistoryEntry>` on Cipher, updated on password change.
- **Favorite**: `bool` on Cipher and CipherMeta. Added atomically in the same phase.
- **Folders**: `Folder` struct exists in manifest.rs with `parent_id` (stored but ignored Phase 1). CRUD wired through daemon + CLI. Entries store `folder_id: Option<Uuid>`, not folder names. Name resolution happens at display time.
- **TOTP**: Rust core parses otpauth URI (algorithm/period/digits), generates code. Seed never crosses Tauri IPC.
- **Generator**: Frontend-only (`crypto.getRandomValues`), available standalone and inline. EFF word list bundled as static asset in `desktop/src/assets/`.
- **Import**: Rust core parsers, output `Vec<CipherInput>`, batch-create. Never parse secrets in JS.
- **Backward compat**: Missing `type` → Login via custom `Deserialize` impl. `Vec<String>` → `Vec<LoginUri>` with Domain default. Migration tested against real old-format byte fixtures.
- **`vault.update` route**: Must exist before any phase that edits ciphers (password change, folder move, type-specific edit forms). Added in Phase 3.

---

## Phase 1: CipherType Enum + CipherKind Sum Type

**User stories**: 4, 5, 6, 7, 8
**Depends on**: Nothing (foundation phase)

### What to build

Introduce `CipherType` enum and `CipherKind` sum type to `types.rs`. Define type-specific data structs: `LoginData`, `CardData`, `IdentityData` (with three address lines), `SshKeyData`. Replace the flat `Cipher` struct with one that uses `kind: CipherKind`. Implement backward migration so existing vaultes (no `type` field) load as `Login`. All existing tests must continue passing with the new model.

Does NOT change daemon wire format yet. Rust core types only.

### Acceptance criteria

- [ ] `CipherType` enum defined: Login, SecureNote, Card, Identity, SshKey
- [ ] `CipherKind` sum type defined with associated data for each variant
- [ ] `LoginData`: username, password, uris (still Vec<String> this phase), totp_uri, autofill_on_page_load, password_revision_date
- [ ] `CardData`: cardholder_name, brand, number, exp_month, exp_year, code
- [ ] `IdentityData`: title, first_name, middle_name, last_name, username, company, email, phone, address1, address2, address3, city, state, postal_code, country, ssn, passport_number, license_number
- [ ] `SshKeyData`: private_key, public_key, key_fingerprint
- [ ] `Cipher` struct uses `kind: CipherKind` instead of flat fields
- [ ] `CipherInput` updated to accept type-specific data
- [ ] Custom `Deserialize` impl for `Cipher`: detects old flat format (no `kind`/`type` field) and maps to `CipherKind::Login(LoginData { ... })` preserving all existing fields
- [ ] Backward migration test using literal old-format bytes: deserialize `{"name":"x","username":"y","uris":["a.com"]}` → verify `CipherKind::Login` with username="y" and uris=["a.com"]
- [ ] Backward migration test using real vault test fixture file in pre-Phase-1 format → verify all fields migrated
- [ ] `cargo test` passes: all existing 87 tests still green
- [ ] New test: create each cipher type, serialize/deserialize, verify all fields preserved
- [ ] Compile-time safety verified: no public API allows `CipherKind::Card(LoginData)`. Confirmed via exhaustive match check (clippy `unreachable_pub` + manual review of enum variants).
- [ ] `cargo clippy` 0 errors

---

## Phase 2: Multi-URI with Match Strategy + Settings CRUD

**User stories**: 1, 2, 3, 10, 11, 12, 13
**Depends on**: Phase 1

### What to build

Replace `uris: Vec<String>` on LoginData with `uris: Vec<LoginUri>` where `LoginUri { uri: String, match_strategy: UriMatchStrategy }`. Define the `UriMatchStrategy` enum. Wire `VaultSettings.default_uri_match` as the global default. Change `default_uri_match` from `Option<String>` to `Option<UriMatchStrategy>` with serde migration. Add daemon routes for settings CRUD (needed by Phase 7 auto-lock UI and this phase's URI match setting). Backward migration converts flat strings to LoginUri with Domain default.

### Acceptance criteria

- [ ] `LoginUri` struct: `uri: String`, `match_strategy: UriMatchStrategy`
- [ ] `UriMatchStrategy` enum: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5)
- [ ] `LoginData.uris` is `Vec<LoginUri>`, ordered
- [ ] Backward migration: `Vec<String>` → `Vec<LoginUri>` with Domain match and original string as uri
- [ ] `VaultSettings.default_uri_match` type changed from `Option<String>` to `Option<UriMatchStrategy>`. Custom serde: unknown string values produce a hard error, not silent fallback.
- [ ] Global default read from `VaultSettings.default_uri_match` when per-URI strategy not set
- [ ] Daemon routes: `settings.get` → returns current VaultSettings as JSON, `settings.set` → accepts partial VaultSettings JSON, merges, persists
- [ ] CLI: `idtty settings get` and `idtty settings set default_uri_match=Host`
- [ ] `CipherInput` updated: `uris` field accepts `Vec<LoginUri>`
- [ ] New test: 3 URIs saved in specific order → load → verify order preserved
- [ ] New test: match strategy round-trip (set Host → save → load → verify Host)
- [ ] New test: migration: old vault with `uris: ["a.com","b.com"]` → loads as `Vec<LoginUri>` with Domain
- [ ] New test: `default_uri_match: "exakt"` (typo) → deserialization returns hard error, not silent Domain fallback
- [ ] `cargo test` all pass, `cargo clippy` 0 errors

---

## Phase 3: CipherMeta Expansion + vault.update + vault.list Upgrade

**User stories**: 8, 9, 36 (partially)
**Depends on**: Phases 1, 2

### What to build

Expand `CipherMeta` to include `cipher_type`, `favorite`, and `username` so the vault list can render type icons and filter favorites without full decryption. These fields land on both `Cipher` and `CipherMeta` atomically. Store them in the manifest index. Add `vault.update` daemon route (required for password change, folder move, and edit forms in later phases). Upgrade `vault.list` response from `{"cipher_ids": [...]}` to `{"ciphers": [...CipherMeta]}`. Update `vault.proto` as documentation of the data model (proto is not used in the wire format).

### Acceptance criteria

- [ ] `CipherMeta` expanded: `cipher_type: CipherType`, `favorite: bool`, `username: Option<String>`
- [ ] `favorite: bool` added to `Cipher` struct atomically with CipherMeta (same phase, no dead-field gap)
- [ ] Manifest index stores cipher_type + favorite + username per cipher (plaintext metadata, Option A)
- [ ] `vault.list` response format changed from `{"cipher_ids": ["uuid1","uuid2"]}` to `{"ciphers": [{id,name,cipher_type,favorite,username,...}]}` — documented as breaking API change
- [ ] CLI `idtty list` updated to parse new format, display type icon and favorite marker
- [ ] Daemon route: `vault.update` — accepts cipher ID + partial CipherInput, re-encrypts and overwrites. Validates cipher exists, updates `updated_at` timestamp, increments `update_seq`.
- [ ] CLI: `idtty edit <id> --name "New Name"` (basic, extensible)
- [ ] `vault.proto` updated as schema documentation: CipherType enum, LoginUri message, oneof cipher_data. Not used in wire format. Documented as "reference schema."
- [ ] New test: create Card entry → list → verify CipherMeta has cipher_type=Card without decrypting
- [ ] New test: favorite set on entry → list → verify CipherMeta shows favorite=true
- [ ] New test: vault.update changes name → get → verify new name, updated_at incremented
- [ ] `cargo build`, `cargo test`, `cargo clippy` all pass

---

## Phase 4: Password History + Clone

**User stories**: 20, 21, 22, 36, 37, 39

### What to build

Add `password_history: Vec<PasswordHistoryEntry>` to Cipher, updated automatically when password changes via `vault.update`. Add `password_revision_date` to LoginData. Add clone/duplicate daemon route. Note: `favorite` and `created_at` already exist on Cipher from Phase 3.

### Acceptance criteria

- [ ] `PasswordHistoryEntry` struct: `password: String`, `last_used_date: u64`
- [ ] `password_history: Vec<PasswordHistoryEntry>` on Cipher
- [ ] `vault.update` with changed password: old password appended to history with timestamp, `password_revision_date` updated on LoginData
- [ ] `password_revision_date: Option<u64>` on LoginData
- [ ] Regression test: `created_at` is non-zero after decrypt (already exists, just verify it survives the refactor)
- [ ] Daemon route: `cipher.clone` — duplicate entry with new UUID, same data except: empty password_history, reset update_seq to 0, new created_at
- [ ] CLI: `idtty clone <id>` creates duplicate
- [ ] New test: change password 3 times → verify history has 3 entries with ascending dates
- [ ] New test: clone entry with password history → verify cloned entry has empty history, different UUID
- [ ] `cargo test` all pass, `cargo clippy` 0 errors

---

## Phase 5: Folder CRUD Wiring

**User stories**: 14, 15, 16, 17, 18, 19
**Depends on**: Phases 1-3 (vault.update must exist for folder assignment changes)

### What to build

Wire existing `Folder` struct through daemon routes and CLI commands. Folder data model already exists in manifest.rs. Add daemon routes: folder.create, folder.rename, folder.delete, folder.list. Add CLI commands. Entries store `folder_id`, not folder names — name resolution at display time.

### Acceptance criteria

- [ ] Daemon routes: folder.create, folder.rename, folder.delete, folder.list
- [ ] CLI: `idtty folders create/list/rename/delete` commands working
- [ ] `idtty add --folder <id>` assigns entry to folder
- [ ] `idtty list` shows folder_name per entry (resolved from folder_id at display time)
- [ ] Move entry between folders: `idtty edit <id> --folder <new_id>` via vault.update
- [ ] Delete folder: entries with that folder_id get folder_id set to None via batch update
- [ ] Rename folder: updates `meta/folders.enc` only. Cipher files unchanged (they store folder_id, not name). Next vault.list call resolves updated name.
- [ ] New test: create folder → assign entry → list → verify folder_id matches
- [ ] New test: delete folder → verify entries become unassigned (folder_id=None)
- [ ] New test: rename folder → verify folder name in list updated, cipher folder_id unchanged
- [ ] New test: move entry from folder A to folder B → verify folder_id changed
- [ ] `cargo test` all pass

---

## Phase 6a: Desktop UI — Login + Secure Note + Vault List Infrastructure

**User stories**: 1, 2, 3, 4, 8, 9 (partially)
**Depends on**: Phases 1-5

### What to build

Vault list infrastructure (type icons, filter bar, favorite star). Login form updated for multi-URI reorder + match strategy. Secure Note form. Type-specific detail views for Login and Secure Note. This is the end-to-end tracer bullet: create → view → edit a Login from UI with the new multi-URI model.

### Acceptance criteria

- [ ] Vault list: type icon per entry (globe for Login, note for SecureNote)
- [ ] Vault list: favorite star toggle per entry
- [ ] Filter bar: All, Logins, Notes (more types added in 6b/6c)
- [ ] New item dropdown: Login, Secure Note (more in 6b/6c)
- [ ] Login form: username, password, reorderable URI list (add/remove/reorder via drag-and-drop), match strategy dropdown per URI, TOTP URI, notes, custom fields, folder selector, favorite toggle
- [ ] Secure Note form: notes textarea + custom fields + favorite toggle
- [ ] Login detail view: all Login fields with copy/reveal, multi-URI list with launch buttons
- [ ] Secure Note detail view: notes with copy, custom fields
- [ ] Edit existing entry: pre-populates form with current values, saves via vault.update
- [ ] `just desktop-dev` runs without errors

---

## Phase 6b: Desktop UI — Card + Identity Forms

**User stories**: 5, 6

### What to build

Card form with brand auto-detection. Identity form with three address lines. Type icons and filter bar extended. Detail views for Card and Identity.

### Acceptance criteria

- [ ] Card form: cardholder, brand (auto-detect from number prefix), number (masked), exp month/year, CVV (masked), notes, custom fields
- [ ] Identity form: title dropdown, first/middle/last name, username, company, email, phone, address1/2/3, city, state, postal code, country, SSN (masked), passport# (masked), license# (masked)
- [ ] New item dropdown: add Card, Identity options
- [ ] Filter bar: add Cards, Identities
- [ ] Card detail view: card fields with copy/reveal, brand logo placeholder
- [ ] Identity detail view: all fields with copy/reveal for sensitive fields (SSN, passport, license)
- [ ] `just desktop-dev` runs without errors

---

## Phase 6c: Desktop UI — SSH Key Form

**User stories**: 7

### What to build

SSH Key form with masked private key. Type icon and filter bar extended. Detail view for SSH Key.

### Acceptance criteria

- [ ] SSH Key form: private key (textarea, masked by default, reveal button), public key, fingerprint, notes
- [ ] New item dropdown: add SSH Key option
- [ ] Filter bar: add SSH Keys
- [ ] SSH Key detail view: public key + fingerprint visible, private key behind reveal + reprompt (if Phase 7 complete) or reveal button
- [ ] `just desktop-dev` runs without errors

---

## Phase 7: Generator + Reprompt + Auto-lock UI

**User stories**: 23, 24, 25, 26, 38, 40, 42
**Depends on**: Phase 2 (settings CRUD routes exist)

### What to build

Standalone password generator accessible from vault view. Configurable: length, uppercase, lowercase, digits, symbols, passphrase mode (EFF word list). Reprompt: require master password before revealing password/hidden fields. Auto-lock: settings UI for timeout + daemon-side tokio timer.

### Acceptance criteria

- [ ] Generator accessible from toolbar/floating button in vault view
- [ ] Slider: length (4-128, default 20)
- [ ] Toggles: uppercase, lowercase, digits, symbols (all on by default)
- [ ] Passphrase tab: word count slider (3-10, default 4), separator dropdown, capitalize toggle, include number toggle
- [ ] EFF large word list (7776 words) bundled as static asset in `desktop/src/assets/eff-words.json`
- [ ] Passphrase generation works offline with no network calls
- [ ] One-click copy of generated value
- [ ] Generator also available inline in add/edit forms (existing behavior preserved)
- [ ] Reprompt: clicking "reveal" on password/hidden field prompts master password, shows field for 30s
- [ ] Auto-lock settings: number input for minutes, default 15, persisted via `settings.set`
- [ ] Daemon: tokio timer resets on each IPC request, triggers lock after timeout
- [ ] Manual `idtty lock` resets timer
- [ ] `just desktop-dev` runs without errors

---

## Phase 8: TOTP Code Generation

**User stories**: 41
**Depends on**: Phases 1-5

### What to build

Parse `otpauth://` URIs in Rust core. Generate TOTP codes (HMAC-based, time-stepped). Return only the numeric code via daemon IPC (never the seed). UI widget shows code with countdown timer, auto-refreshes.

### Acceptance criteria

- [ ] `otpauth://` URI parser: extracts secret, algorithm (SHA1/256/512), period (30/60), digits (6/8), issuer
- [ ] TOTP code generation: HMAC with configured algorithm, time step from period, truncate to configured digits
- [ ] Daemon route: `cipher.totp_code <id>` → returns `{ code: "123456", period_seconds: 30, expires_at: <timestamp> }`
- [ ] Response contains ONLY the derived code. otpauth URI (seed) never sent to frontend.
- [ ] UI widget: 6/8-digit code display, circular countdown timer, auto-refresh
- [ ] Click to copy TOTP code
- [ ] New test: known otpauth URI → generate code → verify against reference implementation
- [ ] New test: SHA256 and SHA512 algorithm codes generate correctly
- [ ] New test: period=60 generates code with 60-second window
- [ ] New test: digits=8 generates 8-digit code
- [ ] New test: daemon response does NOT contain the seed/URI
- [ ] New test: `expires_at` is within `[system_time_now, system_time_now + period_seconds]`
- [ ] `cargo test` all pass

---

## Phase 9: Import — BW JSON + BW CSV

**User stories**: 27, 28, 34, 35
**Depends on**: Phases 1-5 (all cipher types, folders, URIs, favorites, password history must be implemented before import)

### What to build

Bitwarden JSON and CSV import parsers in Rust core. Handles all 5 cipher types, folders, URIs, history, custom fields. BW JSON is full-fidelity. BW CSV is lossy (single URI, no folders, no history). Also implement export: BW-compatible JSON and CSV output.

### Acceptance criteria

- [ ] BW JSON parser: parses all 5 cipher types, folders, URIs with match strategy, password history, custom fields (Text/Hidden/Boolean), favorite flag
- [ ] BW CSV parser: parses Login entries only (lossy: single URI, no folders, no history, no custom fields)
- [ ] SecureNote import: accepts `type: 0` field without error
- [ ] Import strips `uriChecksum` from BW URIs without error
- [ ] Daemon route: `vault.import --format bw-json <path>` and `vault.import --format bw-csv <path>`
- [ ] CLI: `idtty import bw-json <file>` and `idtty import bw-csv <file>`
- [ ] Export: `idtty export bw-json <file>` produces BW-compatible JSON with all fields
- [ ] Export: `idtty export bw-csv <file>` produces BW-compatible CSV (logins only)
- [ ] New test: BW JSON fixture with all 5 types → import → verify each type preserved
- [ ] New test: BW CSV fixture → import → verify logins with single URI
- [ ] New test: export BW JSON → re-import → round-trip fidelity for all types
- [ ] `cargo test` all pass

---

## Phase 10: Import — Browser + LastPass + 1Password + KeePass

**User stories**: 29, 30, 31, 32, 33
**Depends on**: Phases 1-5

### What to build

Additional import parsers: Chrome CSV, Firefox CSV, LastPass CSV, 1Password .1pux (ZIP+JSON), 1Password CSV (fallback), KeePass XML. Each parser maps source fields to IDtty's CipherInput. Encrypted JSON export using IDtty's own crypto (Argon2id + AES-256-GCM), NOT BW's incompatible scheme. Format is documented and IDtty-specific.

### Acceptance criteria

- [ ] Chrome CSV parser: url, username, password, name → Login entry
- [ ] Firefox CSV parser: same shape as Chrome
- [ ] LastPass CSV parser: url, username, password, name, grouping (→ folder), extra (→ notes)
- [ ] 1Password .1pux: extract ZIP, parse JSON, map all fields including multiple URIs and custom fields
- [ ] 1Password CSV: login entries only, lossy
- [ ] KeePass XML: entries with title, username, password, url, notes, custom string fields
- [ ] CLI: `idtty import <format> <file>` for each format
- [ ] Encrypted JSON export: password-protected using IDtty's Argon2id + AES-256-GCM. Format documented in `docs/export-format.md`. NOT compatible with BW's encrypted export (different KDF and AEAD). Plaintext JSON/CSV export remains BW-compatible.
- [ ] New test per format: fixture → import → verify field mapping
- [ ] `cargo test` all pass

---

## Cross-cutting: After each phase

- `cargo build` must succeed
- `cargo test` must pass (all existing + new)
- `cargo clippy` must report 0 errors
- Commit with descriptive message
- Push to main
