# Plan: Bitwarden Desktop Feature Parity

> Source PRD: `docs/prd-bitwarden-parity.md`

## Architectural decisions

Durable decisions that apply across all phases:

- **CipherKind is a Rust sum type (enum with associated data)**, NOT flat `Option<T>` fields. Invalid states are unrepresentable at the type level. Serialized as `#[serde(tag = "type", content = "data")]`.
- **CipherType enum**: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`. Bank/DriversLicense/Passport deferred.
- **Multi-URI**: `Vec<LoginUri>` where `LoginUri { uri, match_strategy }`. Ordered, reorderable.
- **UriMatchStrategy**: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5). Global default from `VaultSettings.default_uri_match`, per-URI override.
- **Identity has three address lines**: `address1`, `address2`, `address3`. Not singular.
- **CipherMeta stores cipher_type + favorite + username** in manifest index (Option A: plaintext metadata, low-sensitivity). Vault list renders without decryption.
- **Proto schema**: `vault.proto` evolves alongside core. `oneof` for type-specific data. Coordinate CLI/daemon release together.
- **Password history**: `Vec<PasswordHistoryEntry>` on Cipher, updated on password change.
- **Favorite**: `bool` on Cipher and CipherMeta.
- **Folders**: `Folder` struct exists in manifest.rs with `parent_id` (stored but ignored Phase 1). CRUD wired through daemon + CLI.
- **TOTP**: Rust core parses otpauth URI (algorithm/period/digits), generates code. Seed never crosses Tauri IPC.
- **Generator**: Frontend-only (`crypto.getRandomValues`), available standalone and inline.
- **Import**: Rust core parsers, output `Vec<CipherInput>`, batch-create. Never parse secrets in JS.
- **Backward compat**: Missing `type` → Login. `Vec<String>` → `Vec<LoginUri>` with Domain default. `created_at` added to Cipher from disk metadata.

---

## Phase 1: CipherType Enum + CipherKind Sum Type

**User stories**: 4, 5, 6, 7, 8

### What to build

Introduce `CipherType` enum and `CipherKind` sum type to `types.rs`. Define type-specific data structs: `LoginData`, `CardData`, `IdentityData` (with three address lines), `SshKeyData`. Replace the flat `Cipher` struct with one that uses `kind: CipherKind`. Implement backward migration so existing vaultes (no `type` field) load as `Login`. All existing tests must continue passing with the new model.

Does NOT change proto schema or daemon wire format yet. Rust core types only.

### Acceptance criteria

- [ ] `CipherType` enum defined: Login, SecureNote, Card, Identity, SshKey
- [ ] `CipherKind` sum type defined with associated data for each variant
- [ ] `LoginData`: username, password, uris (still Vec<String> this phase), totp_uri, autofill_on_page_load, password_revision_date
- [ ] `CardData`: cardholder_name, brand, number, exp_month, exp_year, code
- [ ] `IdentityData`: title, first_name, middle_name, last_name, username, company, email, phone, address1, address2, address3, city, state, postal_code, country, ssn, passport_number, license_number
- [ ] `SshKeyData`: private_key, public_key, key_fingerprint
- [ ] `Cipher` struct uses `kind: CipherKind` instead of flat fields
- [ ] `CipherInput` updated to accept type-specific data
- [ ] Backward migration: missing `type` field deserializes as LoginKind with existing flat fields mapped into LoginData
- [ ] `cargo test` passes: all existing 87 tests still green
- [ ] New test: create each cipher type, serialize/deserialize, verify all fields preserved
- [ ] New test: verify `CipherKind` makes `type=Card` with `LoginData` impossible at compile time
- [ ] `cargo clippy` 0 errors

---

## Phase 2: Multi-URI with Match Strategy

**User stories**: 1, 2, 3, 10, 11, 12, 13

### What to build

Replace `uris: Vec<String>` on LoginData with `uris: Vec<LoginUri>` where `LoginUri { uri: String, match_strategy: UriMatchStrategy }`. Define the `UriMatchStrategy` enum (Domain, Host, StartsWith, Exact, Regex, Never). Wire `VaultSettings.default_uri_match` as the global default when no per-URI strategy is set. Backward migration converts flat strings to LoginUri with Domain default.

### Acceptance criteria

- [ ] `LoginUri` struct: `uri: String`, `match_strategy: UriMatchStrategy`
- [ ] `UriMatchStrategy` enum: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5)
- [ ] `LoginData.uris` is `Vec<LoginUri>`, ordered
- [ ] Backward migration: `Vec<String>` → `Vec<LoginUri>` with Domain match and original string as uri
- [ ] Global default read from `VaultSettings.default_uri_match` when per-URI strategy not set
- [ ] `CipherInput` updated: `uris` field accepts `Vec<LoginUri>`
- [ ] New test: 3 URIs saved in specific order → load → verify order preserved
- [ ] New test: match strategy round-trip (set Host → save → load → verify Host)
- [ ] New test: migration: old vault with `uris: ["a.com","b.com"]` → loads as `Vec<LoginUri>` with Domain
- [ ] `cargo test` all pass, `cargo clippy` 0 errors

---

## Phase 3: Proto Schema Evolution + CipherMeta Expansion

**User stories**: 8, 9 (partially)

### What to build

Update `vault.proto` to support the new cipher model: add `CipherType` enum, replace singular `url` with `repeated LoginUri`, add `oneof` for type-specific data. Update daemon handler and CLI client to use the new proto. Expand `CipherMeta` to include `cipher_type`, `favorite`, and `username` so the vault list can render type icons and filter favorites without full decryption. Store these fields in the manifest index.

### Acceptance criteria

- [ ] `vault.proto`: `CipherType` enum, `LoginUri` message, `oneof cipher_data` for type-specific fields
- [ ] Daemon `handler.rs` updated for new proto: serialize/deserialize new cipher types
- [ ] CLI `client.rs` updated: send/receive new proto format
- [ ] `CipherMeta` expanded: `cipher_type: CipherType`, `favorite: bool`, `username: Option<String>`
- [ ] Manifest index stores cipher_type + favorite + username per cipher (plaintext, low-sensitivity)
- [ ] `list` command returns CipherMeta with type and favorite populated
- [ ] New test: create Card entry → list → verify CipherMeta has cipher_type=Card without decrypting
- [ ] New test: proto round-trip for each cipher type
- [ ] `cargo build`, `cargo test`, `cargo clippy` all pass

---

## Phase 4: Favorites + Password History + Clone

**User stories**: 20, 21, 22, 36, 37, 39

### What to build

Add `favorite: bool` to Cipher and CipherMeta (already on CipherMeta from Phase 3, wire the actual flag). Add `password_history: Vec<PasswordHistoryEntry>` to Cipher, updated automatically when password changes. Add `password_revision_date` to LoginData. Fix `created_at` gap: expose it on the decrypted Cipher struct. Add clone/duplicate daemon route.

### Acceptance criteria

- [ ] `favorite: bool` on Cipher, populated in CipherMeta during listing
- [ ] `PasswordHistoryEntry` struct: `password: String`, `last_used_date: u64`
- [ ] `password_history: Vec<PasswordHistoryEntry>` on Cipher
- [ ] Password change on existing entry: old password appended to history with timestamp
- [ ] `password_revision_date: Option<u64>` on LoginData
- [ ] `created_at: u64` added to Cipher (populated from CipherData disk metadata)
- [ ] Daemon route: cipher.clone (duplicate entry with new UUID, same data)
- [ ] CLI: `idtty clone <id>` creates duplicate
- [ ] New test: change password 3 times → verify history has 3 entries with ascending dates
- [ ] New test: clone entry → verify same data, different UUID
- [ ] New test: favorite set on entry → list shows favorite=true in CipherMeta
- [ ] `cargo test` all pass, `cargo clippy` 0 errors

---

## Phase 5: Folder CRUD Wiring

**User stories**: 14, 15, 16, 17, 18, 19

### What to build

Wire existing `Folder` struct through daemon routes and CLI commands. Folder data model already exists in manifest.rs. Add daemon routes: folder.create, folder.rename, folder.delete, folder.list. Add CLI commands: `idtty folders create <name>`, `idtty folders list`, `idtty folders rename <id> <name>`, `idtty folders delete <id>`. Add proto messages for folder operations.

### Acceptance criteria

- [ ] Proto messages: `FolderRequest`, `FolderResponse` for CRUD operations
- [ ] Daemon routes: folder.create, folder.rename, folder.delete, folder.list
- [ ] CLI: `idtty folders create/list/rename/delete` commands working
- [ ] `idtty add --folder <id>` assigns entry to folder
- [ ] `idtty list` shows folder_id per entry
- [ ] Delete folder: entries with that folder_id get folder_id set to None
- [ ] Rename folder: all entries referencing it see updated name on next list
- [ ] New test: create folder → assign entry → list → verify folder_id matches
- [ ] New test: delete folder → verify entries become unassigned (folder_id=None)
- [ ] New test: rename folder → verify name change propagates
- [ ] `cargo test` all pass

---

## Phase 6: Desktop UI — Type-Specific Forms

**User stories**: 1, 2, 3, 4, 5, 6, 7, 8, 9

### What to build

Desktop UI for creating and editing all cipher types. New item dropdown replaces current add button with options: Login, Secure Note, Card, Identity, SSH Key. Each type gets its own form layout. Type icon/monogram in vault list. Multi-URI reorderable list in Login form (drag-and-drop). Filter by type in vault view.

### Acceptance criteria

- [ ] New item dropdown: Login, Secure Note, Card, Identity, SSH Key
- [ ] Login form: username, password, reorderable URI list (add/remove/reorder), TOTP URI, notes, custom fields
- [ ] Each URI row: URL input + match strategy dropdown (Domain/Host/Exact/StartsWith/Regex/Never)
- [ ] Secure Note form: notes textarea + custom fields (no other fields)
- [ ] Card form: cardholder, brand (auto-detect from number), number, exp month/year, CVV, notes
- [ ] Identity form: title, first/middle/last name, username, company, email, phone, address1/2/3, city, state, postal code, country, SSN, passport#, license#
- [ ] SSH Key form: private key (textarea, masked), public key, fingerprint, notes
- [ ] Vault list: type icon (globe/card/note/person/key) per entry
- [ ] Filter bar: filter by type (All, Logins, Cards, Notes, Identities, SSH Keys)
- [ ] Cipher detail view shows type-specific fields with copy/reveal for sensitive fields
- [ ] `just desktop-dev` runs without errors

---

## Phase 7: Generator + Reprompt + Auto-lock UI

**User stories**: 23, 24, 25, 26, 38, 40, 42

### What to build

Standalone password generator accessible from vault view (not just inside forms). Configurable: length, uppercase, lowercase, digits, symbols, passphrase mode (EFF word list). Reprompt: require master password before revealing password/hidden fields. Auto-lock: settings UI for timeout + daemon-side tokio timer.

### Acceptance criteria

- [ ] Generator accessible from toolbar/floating button in vault view
- [ ] Slider: length (4-128, default 20)
- [ ] Toggles: uppercase, lowercase, digits, symbols (all on by default)
- [ ] Passphrase tab: word count slider (3-10, default 4), separator dropdown, capitalize toggle, include number toggle
- [ ] One-click copy of generated value
- [ ] Generator also available inline in add/edit forms (existing behavior preserved)
- [ ] Reprompt: clicking "reveal" on password/hidden field prompts master password, shows field for 30s
- [ ] Auto-lock settings: number input for minutes, default 15
- [ ] Daemon: tokio timer resets on each IPC request, triggers lock after timeout
- [ ] Manual `idtty lock` resets timer
- [ ] `just desktop-dev` runs without errors

---

## Phase 8: TOTP Code Generation

**User stories**: 41

### What to build

Parse `otpauth://` URIs in Rust core. Generate TOTP codes (HMAC-based, time-stepped). Return only the numeric code via daemon IPC (never the seed). UI widget shows code with countdown timer, auto-refreshes every 30s (or per configured period).

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
- [ ] `cargo test` all pass

---

## Phase 9: Import — BW JSON + BW CSV

**User stories**: 27, 28, 34, 35

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

### What to build

Additional import parsers: Chrome CSV, Firefox CSV, LastPass CSV, 1Password .1pux (ZIP+JSON), 1Password CSV (fallback), KeePass XML. Each parser maps source fields to IDtty's CipherInput. Encrypted JSON export (password-protected).

### Acceptance criteria

- [ ] Chrome CSV parser: url, username, password, name → Login entry
- [ ] Firefox CSV parser: same shape as Chrome
- [ ] LastPass CSV parser: url, username, password, name, grouping (→ folder), extra (→ notes)
- [ ] 1Password .1pux: extract ZIP, parse JSON, map all fields including multiple URIs and custom fields
- [ ] 1Password CSV: login entries only, lossy
- [ ] KeePass XML: entries with title, username, password, url, notes, custom string fields
- [ ] CLI: `idtty import <format> <file>` for each format
- [ ] Encrypted JSON export: password-protected, decryptable by BW and IDtty
- [ ] New test per format: fixture → import → verify field mapping
- [ ] `cargo test` all pass

---

## Cross-cutting: After each phase

- `cargo build` must succeed
- `cargo test` must pass (all existing + new)
- `cargo clippy` must report 0 errors
- Commit with descriptive message
- Push to main
