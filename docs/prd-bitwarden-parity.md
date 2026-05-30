# PRD: Bitwarden Desktop Feature Parity

## Problem Statement

IDtty's desktop vault can store logins (username, password, single URI, notes, custom fields). Users migrating from Bitwarden expect the same entry types, multi-URI support, folders, password history, import/export, and generator features they rely on daily. Without these, IDtty cannot be a viable Bitwarden replacement.

## Solution

Extend IDtty's cipher model to support multiple entry types (Login, Secure Note, Card, Identity, SSH Key), multi-URI with match detection, folders, password history, import/export, and a standalone password generator. All changes must work offline with no server dependency.

## Bitwarden Feature Analysis

Source: BW clients repo (`bitwarden/clients`), server repo (`bitwarden/server`), Android repo (`bitwarden/android`).

### Cipher Types (8 in BW)

| Type | BW Fields | IDtty Status |
|------|-----------|--------------|
| **Login** | username, password, URIs (ordered, match strategy), TOTP, FIDO2, autofill toggle, password revision date | Partial: has username, password, single flat URIs vec, TOTP. Missing: URI ordering, match strategy, FIDO2, password revision |
| **Secure Note** | `type: SecureNoteType` (always `Generic=0`) + notes + custom fields | Not implemented (all entries are login) |
| **Card** | cardholderName, brand, number, expMonth, expYear, CVV code | Not implemented |
| **Identity** | title, firstName, lastName, middleName, username, company, email, phone, address1, address2, address3, city, state, postalCode, country, SSN, passportNumber, licenseNumber | Not implemented |
| **SSH Key** | privateKey, publicKey, keyFingerprint | Not implemented |
| **Bank Account** | bankName, nameOnAccount, accountType, accountNumber, routingNumber, branchNumber, pin, swiftCode, iban, bankContactPhone | Not implemented |
| **Driver's License** | firstName, middleName, lastName, dateOfBirth, licenseNumber, issuingCountry, issuingState, issueDate, expirationDate, issuingAuthority, licenseClass | Not implemented |
| **Passport** | surname, givenName, dateOfBirth, sex, birthPlace, nationality, issuingCountry, passportNumber, passportType, nationalIdentificationNumber, issuingAuthority, issueDate, expirationDate | Not implemented |

### Login URI Model (BW)

Each URI in a login entry has:
- `uri`: string (the URL)
- `match`: enum (Domain=0, Host=1, StartsWith=2, Exact=3, RegularExpression=4, Never=5)
- `uriChecksum`: string (integrity check)
- Computed: `domain`, `hostname`, `host`, `canLaunch`, `isWebsite`, `launchUri`

URIs are **ordered**. BW stores them as an array, displayed in order, reorderable.

### Custom Fields (BW)

- Text (0)
- Hidden (1) — encrypted value
- Boolean (2)
- Linked (3) — references a field on the parent cipher type (e.g., link to card.number)

IDtty currently has Text, Hidden, Boolean. `Linked` is deferred to Phase 2 (requires type-specific field resolution, low user demand for single-user vaults).

### Password History (BW)

Array of `{ password: string, lastUsedDate: Date }`. Stored on the cipher. Updated when password changes.

### Folders (BW)

- Named folders, each cipher has `folderId`
- Nested folders NOT supported (flat only)
- "No Folder" is the default

**IDtty existing state**: `Folder` struct already exists in `vault/manifest.rs` with `id`, `name`, `parent_id: Option<Uuid>`, `icon`. The `parent_id` field supports nesting at the data level but is **ignored in Phase 1** (flat only, same as BW). Stored for future use and BW import compatibility. `folder_id: Option<Uuid>` already exists on `Cipher` and `CipherInput`. What's missing: folder CRUD daemon routes, CLI commands, and UI sidebar.

### Existing IDtty Infrastructure

Several PRD items have partial or full data model support already:

| Item | Status | What exists | What's needed |
|------|--------|-------------|---------------|
| **Folders** | Data model done | `Folder` struct in manifest.rs, `folder_id` on Cipher | CRUD routes, CLI, UI |
| **Vault settings** | Data model done | `VaultSettings` in manifest.rs: `auto_lock_minutes`, `theme`, `default_uri_match` | Settings UI, daemon routes |
| **URI match default** | Setting stored | `VaultSettings.default_uri_match` | Per-URI override, wire to match logic |
| **Trash** | Fully implemented | Soft delete, restore, purge in daemon handler | — |
| **Auto-lock** | Setting stored | `VaultSettings.auto_lock_minutes` | Daemon timer, settings UI |

### Other BW Desktop Features

| Feature | Description | IDtty Status |
|---------|-------------|--------------|
| **Favorites** | Star/unstar entries, filter by favorites | Not implemented |
| **Trash (soft delete)** | Delete → trash → permanent delete or restore | Implemented |
| **Archive** | Archive entries (hide from main list) | Not implemented |
| **Collections** | Org-level groupings (multi-user) | Out of scope (no org) |
| **Attachments** | File attachments with encrypted storage | Not implemented |
| **Password Generator** | Standalone generator, configurable length/charset | Inline only (in add/edit form) |
| **Import** | 30+ formats (BW CSV/JSON, 1Password, LastPass, KeePass, Chrome, Firefox, etc.) | Not implemented |
| **Export** | BW CSV, BW JSON, encrypted JSON | Not implemented |
| **URI Match Detection** | 6 strategies per URI for browser autofill | Setting stored (`default_uri_match`), per-URI override not implemented |
| **TOTP** | Time-based OTP with built-in authenticator | Stored (totp_uri) but no code generation/display |
| **Search** | Full-text search across vault | Implemented (client-side) |
| **Password Revision Date** | When password was last changed | Not tracked |
| **Reprompt** | Require master password re-entry to view password | Not implemented |
| **Clone** | Duplicate an entry | Not implemented |
| **Move to folder** | Bulk or single entry move | Not implemented (no folder UI) |
| **Organization vault** | Shared vault for teams | Out of scope (no server) |
| **Emergency Access** | Trusted contact gets access after timeout | Not implemented |
| **Breach Report** | Check passwords against HaveIBeenPwned | Out of scope (requires API) |
| **Password Health** | Weak/reused/old password detection | Not implemented (local computation, no API needed) |
| **Auto-lock** | Lock vault after N minutes of inactivity | Setting stored, no timer enforcement |
| **Biometric unlock** | Touch ID, Windows Hello, fingerprint | Not implemented (Phase 2, requires FIDO2 platform authenticator) |
| **Send** | Encrypted file/text sharing via temporary URL | Out of scope (requires server relay) |

## User Stories

### Entry Types

1. As a user, I want to create a Login entry with multiple URIs, so that one entry works across login pages for the same service (e.g., app.example.com and web.example.com)
2. As a user, I want to reorder URIs in a Login entry, so that the primary URL appears first
3. As a user, I want to set a URI match strategy (domain, host, exact, etc.) per URI, so that autofill works correctly on different sites
4. As a user, I want to create a Secure Note entry, so that I can store arbitrary text securely (bank details, recovery codes, software licenses)
5. As a user, I want to create a Card entry, so that I can store credit/debit card details (number, expiry, CVV, cardholder)
6. As a user, I want to create an Identity entry, so that I can store personal information (name, address, email, phone, SSN) for form filling
7. As a user, I want to create an SSH Key entry, so that I can store private key, public key, and fingerprint
8. As a user, I want to see the entry type clearly in the vault list, so that I can distinguish logins from cards from notes at a glance
9. As a user, I want to filter the vault by entry type, so that I can quickly find all cards or all identities

### Multi-URI

10. As a user, I want to add multiple URIs to a login entry, so that autofill matches across subdomains or regional sites
11. As a user, I want to remove a URI from an entry, so that I can clean up outdated URLs
12. As a user, I want to see which URI will be launched when I click the launch button, so that I know where I'm going
13. As a user, I want the vault list to show the domain icon/initial for the first URI, so that entries are visually distinguishable

### Folders

14. As a user, I want to create named folders, so that I can organize entries by category (Work, Personal, Finance)
15. As a user, I want to move entries to folders, so that I can keep my vault organized
16. As a user, I want to rename folders, so that I can update category names
17. As a user, I want to delete folders (entries move to "No Folder"), so that I can reorganize
18. As a user, I want to filter the vault by folder, so that I see only relevant entries
19. As a user, I want to see the folder name in the cipher detail view, so that I know where an entry lives

### Password History

20. As a user, I want to see the history of previous passwords for a login entry, so that I can recover a recently changed password
21. As a user, I want to copy a previous password from history, so that I can use it if the new one doesn't work
22. As a user, I want to see when each password was last used, so that I know the timeline

### Password Generator

23. As a user, I want a standalone password generator (not inside add/edit), so that I can generate passwords without creating an entry
24. As a user, I want to configure generator length and character sets (uppercase, lowercase, digits, symbols), so that I can match site requirements
25. As a user, I want to generate passphrases (word-based), so that I can use memorable but strong passwords
26. As a user, I want to copy the generated password with one click, so that I can paste it elsewhere

### Import/Export

27. As a user migrating from Bitwarden, I want to import my BW JSON export, so that all my entries transfer with types and folders intact
28. As a user migrating from Bitwarden, I want to import my BW CSV export, so that I can switch easily
29. As a user migrating from 1Password, I want to import my 1Password .1pux export (full fidelity), so that switching is painless
30. As a user migrating from 1Password, I want to import my 1Password CSV export (fallback), so that I can switch even without the full format
31. As a user migrating from LastPass, I want to import my LastPass CSV export, so that I can leave after recent security incidents
32. As a user migrating from KeePass, I want to import my KeePass XML export, so that I can move from offline managers
33. As a user migrating from Chrome/Firefox, I want to import browser saved passwords, so that I can consolidate
34. As a user, I want to export my vault as JSON (encrypted or plaintext), so that I have a backup
35. As a user, I want to export my vault as CSV, so that I can use it in other tools

### Favorites

36. As a user, I want to mark entries as favorites, so that my most-used entries are easy to find
37. As a user, I want to filter by favorites, so that I see only my starred entries

### Other

38. As a user, I want to clone/duplicate an entry, so that I can create similar entries without re-typing
39. As a user, I want to see when a password was last changed, so that I know if it's stale
40. As a user, I want master password reprompt before showing sensitive fields, so that shoulder-surfers on an unlocked machine can't see passwords
41. As a user, I want to generate and display TOTP codes from the totp_uri, so that I don't need a separate authenticator app
42. As a user, I want to set an auto-lock timeout, so that my vault locks itself after inactivity
43. As a user, I want to see which of my passwords are weak or reused, so that I can improve my security posture

## Implementation Decisions

### 1. Cipher Type Enum (Sum Type, Not Flat Options)

Add `CipherType` enum to `types.rs`: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`.

Bank Account, Driver's License, and Passport are BW-specific types added recently. Defer to Phase 2.

**Critical design decision**: Use a Rust sum type (enum with associated data), NOT flat `Option<T>` fields. The flat option approach (one field per type) allows the discriminant and data to disagree — nothing prevents `type = Card` with `login = Some(...)` and `card = None`. Rust's type system can make invalid states unrepresentable:

```rust
enum CipherKind {
    Login(LoginData),
    SecureNote,        // notes field on Cipher is the content
    Card(CardData),
    Identity(IdentityData),
    SshKey(SshKeyData),
}

struct Cipher {
    id, name, folder_id, favorite, notes, custom_fields, password_history,
    key_epoch, update_seq, tier, created_at, updated_at,
    kind: CipherKind,
}
```

Serialization uses `#[serde(tag = "type", content = "data")]` to produce `{"type": "Login", "data": {...}}`, matching BW's JSON convention. SecureNote has no payload data — an enum variant without associated data, not `Option<()>` (which is structurally just `bool`).

### 2. Identity: Three Address Lines

BW's `IdentityView` has `address1`, `address2`, `address3` as three separate fields. Not one "address" field. This matters for:
- BW JSON import: collapsing three lines into one loses data
- UI form layout: three text inputs, not one textarea
- Export: BW expects three fields

```rust
struct IdentityData {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    username: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    ssn: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}
```

### 3. Multi-URI with Match Strategy

Replace `uris: Vec<String>` with `uris: Vec<LoginUri>` where:

```rust
struct LoginUri {
    uri: String,
    match_strategy: UriMatchStrategy,
}

enum UriMatchStrategy {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}
```

URIs are ordered. UI provides drag-to-reorder.

**Global default**: `VaultSettings.default_uri_match` already exists in `manifest.rs`. Per-URI strategy overrides the global default. If neither is set, default is `Domain`.

**Import note**: BW JSON exports include `uriChecksum` per URI. The import parser must strip this field without erroring. IDtty does not use URI checksums.

### 4. Folders (Existing Infrastructure)

`Folder` struct already exists in `vault/manifest.rs` with `id`, `name`, `parent_id: Option<Uuid>`, `icon`. `folder_id: Option<Uuid>` already on `Cipher` and `CipherInput`. Phase B adds CRUD wiring only.

`parent_id` is stored but **ignored in Phase 1** (flat hierarchy only, same as BW). The field remains for:
- BW import compatibility (BW exports may include nested folder structures)
- Future nested folder support

Phase B deliverables:
- Daemon routes: folder.create, folder.rename, folder.delete, folder.list
- CLI commands: `idtty folders create/list/rename/delete`
- Desktop UI: folder sidebar with filter

### 5. Password History

Add `password_history: Vec<PasswordHistoryEntry>` to `Cipher`. Each entry: `{ password: String, last_used_date: u64 }`. Updated on password change.

**Migration note**: Existing entries have empty history. First password change post-migration starts history from that point. Imported entries from BW will carry their existing history.

### 6. Favorites

Add `favorite: bool` to `Cipher` and `CipherMeta`. Filter toggle in vault view.

**Critical**: `favorite` must also be added to `CipherMeta` (the lightweight listing struct). Without it, the vault list UI cannot show favorite icons or filter by favorites without decrypting every entry — defeating the purpose of the separate metadata struct.

### 7. CipherMeta Expansion

`CipherMeta` is used for vault list rendering without full decryption. Currently lacks fields needed for the UI. Must add:

- `cipher_type: CipherType` — type icon in vault list
- `favorite: bool` — star icon and filter
- `username: Option<String>` — subtitle line (BW shows this)

These fields are stored in the manifest or as unencrypted cipher header metadata. Architectural options:

**Option A**: Store type + favorite in the manifest index (plaintext metadata file). Pros: fast listing, no cipher file access. Cons: metadata in plaintext (type and favorite are low-sensitivity, but still visible).

**Option B**: Store type + favorite as unencrypted header on each cipher file. Pros: co-located with cipher, consistent. Cons: must read all cipher files for listing.

**Recommendation**: Option A (manifest index). Cipher type and favorite status are not sensitive — they don't reveal what the entry contains, only what category it belongs to. BW stores these unencrypted on the server for the same reason. The manifest already tracks cipher IDs and names; extend it.

### 8. Import/Export

Phase 1 import formats (priority order):
1. **BW JSON** — highest priority (direct migration path, preserves all types, folders, URIs, history)
2. **BW CSV** — second priority (lossy: no folders, no history, single URI only)
3. **Chrome CSV** — most common browser password store
4. **LastPass CSV** — largest migration wave (2022-2023 security incidents drove mass exodus)
5. **1Password .1pux** — full-fidelity ZIP+JSON format (preserves custom fields, multiple URLs, tags)
6. **1Password CSV** — fallback (lossy, loses custom fields and most metadata)
7. **KeePass XML** — offline manager users
8. **Firefox CSV** — browser consolidation

Import runs in Rust core (no JS parsing of secrets). Output: `Vec<CipherInput>`, then batch-create.

**1Password has two formats**: `.1pux` (ZIP containing JSON, official format since 1PW 7+) preserves custom fields, multiple URLs, and tags. CSV is lossy. The import parser must handle both. `.1pux` is the primary target.

**BW SecureNote import**: BW's `SecureNoteView` has a `type: SecureNoteType` field (enum, only value is `Generic = 0`). The import parser must accept this field without erroring. IDtty ignores it (all secure notes are generic).

Phase 2 import formats: Dashlane, Enpass, NordPass, Avast, Avira, Keeper, RoboForm, Myki, mSecure, Blur, and others.

Export: BW-compatible JSON, CSV, encrypted JSON (password-protected).

### 9. Password Generator

Standalone UI component available in Phase C (not Phase D). Users need it immediately when creating entries.

Pure frontend (SolidJS), no daemon call needed for generation. Uses `window.crypto.getRandomValues`. Config: length, uppercase, lowercase, digits, symbols, passphrase mode.

Also remains available inline in add/edit forms (existing behavior).

### 10. TOTP Code Generation

Rust core: parse `otpauth://` URI, compute TOTP code, return digits. UI refreshes periodically.

**The otpauth URI spec supports multiple parameters. The parser must handle all of them:**
- `algorithm`: SHA1 (default), SHA256, SHA512 — some enterprise SSO providers use SHA256. Hardcoding SHA1 silently produces wrong codes.
- `period`: 30 seconds (default), or 60 seconds — `period=60` exists in the wild.
- `digits`: 6 (default), or 8 — `digits=8` is used by some services.
- `secret`: base32-encoded TOTP seed (required).
- `issuer`: optional label for the service name.

**Security constraint**: The raw `otpauth://` URI (which contains the TOTP seed) must **never** cross the Tauri IPC boundary to frontend JS. Only the derived numeric code should be sent. TOTP seeds are equivalent in sensitivity to passwords — compromise of the seed allows unlimited code generation.

**HOTP** (counter-based, `hotp://` URIs) is out of scope. IDtty only supports time-based TOTP.

### 11. Backward Compatibility

Existing vaultes have `type` field absent. `load` treats missing type as `Login`. `uris: Vec<String>` migrated to `Vec<LoginUri>` with default `Domain` match. Migration runs on first load.

**Proto schema evolution**: `vault.proto` currently has `string url = 5` (singular). The Rust core uses `Vec<String>`. These are already inconsistent. Phase A changes the core to `Vec<LoginUri>`, which will break the daemon's Protobuf wire format. The proto schema must be versioned in parallel with the core changes:
- Add `CipherType` enum to proto
- Replace `string url` with `repeated LoginUri uris` in proto
- Bump proto message version or use `oneof` for type-specific data
- Existing CLI clients built against the old proto will fail — coordinate release

**`created_at` gap**: `CipherData` (serialized on disk) tracks `created_at`, but `Cipher` (decrypted view) does not expose it. Callers cannot surface creation dates. The migration should fix this by adding `created_at: u64` to `Cipher`.

### 12. Auto-Lock

`VaultSettings.auto_lock_minutes` already exists. What's missing:
- Daemon-side: tokio timer that triggers vault lock after N minutes of inactivity (no IPC requests)
- Settings UI: slider/number input to configure the timeout
- Default: 15 minutes (same as BW desktop)

## Testing Decisions

- **Cipher type round-trip**: Create each type → serialize → deserialize → verify all fields preserved
- **Cipher type invalid state**: Verify that `CipherKind` enum makes it impossible to have `type=Card` with `LoginData`
- **Multi-URI ordering**: Create entry with 3 URIs → save → load → verify order preserved
- **Folder CRUD**: Create, rename, delete folders. Verify cipher folder_id references stay valid
- **Password history**: Create entry, change password 3 times → verify history has 3 entries with correct dates
- **Import parsing**: BW JSON fixtures → parse → verify types, URIs, folders, custom fields. Include SecureNote with `type: 0` field.
- **Import BW CSV**: Verify lossy import (missing fields gracefully defaulted, not errored)
- **Import 1Password .1pux**: Verify ZIP extraction, JSON parse, field mapping
- **Export format**: Create entries → export BW JSON → parse with serde → verify schema matches BW spec
- **TOTP generation**: Known otpauth URIs (SHA1, SHA256, SHA512; period 30 and 60; digits 6 and 8) → generate codes → verify against reference implementation
- **TOTP security**: Verify otpauth URI never appears in Tauri IPC responses
- **Migration**: Old-format vault (no type field, flat URIs) → load → verify auto-migrated to Login type with LoginUri wrappers
- **Migration `created_at`**: Verify old vault entries get `created_at` populated from disk metadata
- **CipherMeta listing**: Create entries of multiple types → list → verify type and favorite available without full decryption
- Test external behavior only, not implementation details
- Prior art: existing `vault/cipher.rs` tests for CRUD round-trips

## Out of Scope

- **FIDO2/WebAuthn passkey storage** — requires browser integration, complex, defer indefinitely
- **Browser extension autofill** — separate client, not desktop
- **Organization/team vaults** — requires server infrastructure
- **Collections** — org feature, not applicable to single-user
- **Attachments** — file encryption/storage is a separate subsystem, defer to Phase 2
- **Breach report (HaveIBeenPwned)** — requires external API, violates offline-first
- **Bank Account, Driver's License, Passport types** — BW recently added, defer to Phase 2
- **Emergency access UI** — emergency.rs exists in core, UI deferred
- **Mobile app** — separate PRD
- **Bitwarden server API compatibility** — IDtty is serverless, no API compat needed
- **Send (encrypted sharing)** — requires server relay for temporary URL delivery
- **HOTP (counter-based OTP)** — TOTP only
- **Nested folders** — data model supports it (`parent_id`), UI deferred to Phase 2
- **Biometric unlock** — requires FIDO2 platform authenticator integration, Phase 2

## Phase 2 Features (not out of scope, just later)

These features are planned but not in the initial Phase A-E implementation:

- **Password Health Reports**: Detect weak (short, common patterns), reused (same password on multiple entries), and old (>90 days) passwords. Pure local computation, no network. High-value security audit tool for post-import vault review.
- **Biometric unlock**: Touch ID, Windows Hello, fingerprint. Uses FIDO2 platform authenticators (see `docs/07-2fa-analysis.md`).
- **Nested folders**: `parent_id` already stored, UI tree needed.
- **Attachments**: Encrypted file storage attached to cipher entries.
- **Linked custom fields**: Reference fields from parent cipher type.
- **Additional import formats**: Dashlane, Enpass, NordPass, Avast, Avira, Keeper, RoboForm.
- **BW Bank Account, Driver's License, Passport types**: If user demand warrants.

## Further Notes

### Phased Implementation

**Phase A (Core Model)**: CipherType enum, `CipherKind` sum type, multi-URI with match strategy, Identity (three address lines), `CipherMeta` expansion (type + favorite + username), proto schema versioning, backward migration. Rust core only.

**Phase B (Folders + Favorites + History + Auto-lock)**: Wire folder CRUD through daemon routes and CLI. Favorite flag on Cipher and CipherMeta. Password history tracking. Auto-lock timer in daemon. Rust core + daemon routes + CLI commands.

**Phase C (Desktop UI + Generator)**: Type-specific add/edit forms, folder sidebar, favorite filter, multi-URI reorder, password history view, standalone password generator, clone/duplicate, reprompt, auto-lock settings UI. SolidJS/Tauri.

**Phase D (TOTP)**: otpauth URI parser (SHA1/256/512, period 30/60, digits 6/8), TOTP code generation in Rust core, TOTP display widget with auto-refresh in UI. Security: seed never crosses IPC boundary.

**Phase E (Import/Export)**: BW JSON import, BW CSV import, 1Password .1pux import, 1Password CSV import, LastPass CSV import, Chrome CSV import, KeePass XML import, Firefox CSV import. BW JSON/CSV/encrypted-JSON export. Rust core parsers.

### Import Priority

1. BW JSON (direct migration, full fidelity)
2. BW CSV (lossy but common)
3. Chrome CSV (most common browser)
4. LastPass CSV (largest migration wave)
5. 1Password .1pux (full fidelity)
6. 1Password CSV (lossy fallback)
7. KeePass XML (offline manager users)
8. Firefox CSV (browser consolidation)

### URI Match Strategy Default

BW defaults to `Domain` match. IDtty should match this behavior. The global default is read from `VaultSettings.default_uri_match` (already exists). Per-URI strategy overrides the global default. Users who need exact or regex matching explicitly set it per URI.

### Passphrase Generator

Use EFF large word list (7776 words). Configurable: word count (default 4), separator (dash, space, period, comma, number), capitalize (on/off), include number (on/off).

### Padding Tier Verification

All cipher types must fit within the Xs tier (5KB). Verify that a max-length `IdentityData` (17 string fields, potentially long addresses) serializes within Xs padding. If not, adjust tier assignment logic for identity-heavy vaults.
