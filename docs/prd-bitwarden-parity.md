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
| **Secure Note** | notes + custom fields only | Not implemented (all entries are login) |
| **Card** | cardholderName, brand, number, expMonth, expYear, CVV code | Not implemented |
| **Identity** | title, firstName, lastName, middleName, username, company, email, phone, address (city, state, postalCode, country), SSN, passportNumber, licenseNumber | Not implemented |
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

### Password History (BW)

Array of `{ password: string, lastUsedDate: Date }`. Stored on the cipher. Updated when password changes.

### Folders (BW)

- Named folders, each cipher has `folderId`
- Nested folders NOT supported (flat only)
- "No Folder" is the default

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
| **URI Match Detection** | 6 strategies per URI for browser autofill | Not implemented |
| **TOTP** | Time-based OTP with built-in authenticator | Stored (totp_uri) but no code generation/display |
| **Search** | Full-text search across vault | Implemented (client-side) |
| **Password Revision Date** | When password was last changed | Not tracked |
| **Reprompt** | Require master password re-entry to view password | Not implemented |
| **Clone** | Duplicate an entry | Not implemented |
| **Move to folder** | Bulk or single entry move | Not implemented (no folders) |
| **Organization vault** | Shared vault for teams | Out of scope (no server) |
| **Emergency Access** | Trusted contact gets access after timeout | Not implemented |
| **Breach Report** | Check passwords against HaveIBeenPwned | Out of scope (requires API) |

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
29. As a user migrating from 1Password, I want to import my 1Password export, so that switching is painless
30. As a user migrating from KeePass, I want to import my KeePass XML export, so that I can move from offline managers
31. As a user migrating from Chrome/Firefox, I want to import browser saved passwords, so that I can consolidate
32. As a user, I want to export my vault as JSON (encrypted or plaintext), so that I have a backup
33. As a user, I want to export my vault as CSV, so that I can use it in other tools

### Favorites

34. As a user, I want to mark entries as favorites, so that my most-used entries are easy to find
35. As a user, I want to filter by favorites, so that I see only my starred entries

### Other

36. As a user, I want to clone/duplicate an entry, so that I can create similar entries without re-typing
37. As a user, I want to see when a password was last changed, so that I know if it's stale
38. As a user, I want master password reprompt before showing sensitive fields, so that shoulder-surfers on an unlocked machine can't see passwords
39. As a user, I want to generate and display TOTP codes from the totp_uri, so that I don't need a separate authenticator app

## Implementation Decisions

### 1. Cipher Type Enum

Add `CipherType` enum to `types.rs`: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`.

Bank Account, Driver's License, and Passport are BW-specific types added recently. Defer to Phase 2.

### 2. Typed Cipher Data

Replace the flat `Cipher` struct with a type-specific data union:

```
Cipher {
  id, name, folder_id, favorite, notes, custom_fields, password_history,
  type: CipherType,
  login: Option<LoginData>,
  secure_note: Option<()>,  // notes field is the content
  card: Option<CardData>,
  identity: Option<IdentityData>,
  ssh_key: Option<SshKeyData>,
}
```

### 3. Multi-URI with Match Strategy

Replace `uris: Vec<String>` with `uris: Vec<LoginUri>` where:

```
LoginUri {
  uri: String,
  match_strategy: UriMatchStrategy,  // Domain, Host, StartsWith, Exact, Regex, Never
}
```

URIs are ordered. UI provides drag-to-reorder. Match strategy defaults to `Domain`.

### 4. Folders

Add `folders: Vec<Folder>` to vault manifest. Each cipher has `folder_id: Option<Uuid>`. Flat hierarchy (no nesting, same as BW). UI: folder tree in left sidebar.

### 5. Password History

Add `password_history: Vec<PasswordHistoryEntry>` to `Cipher`. Each entry: `{ password: String, last_used_date: u64 }`. Updated on password change.

### 6. Favorites

Add `favorite: bool` to `Cipher`. Filter toggle in vault view.

### 7. Import/Export

Phase 1: BW JSON, BW CSV, 1Password, KeePass, Chrome, Firefox. 
Import runs in Rust core (no JS parsing of secrets). Output: `Vec<CipherInput>`, then batch-create.

Export: BW-compatible JSON, CSV, encrypted JSON.

### 8. Password Generator

Standalone UI component. Pure frontend (SolidJS), no daemon call needed for generation. Uses `window.crypto.getRandomValues`. Config: length, uppercase, lowercase, digits, symbols, passphrase mode.

### 9. TOTP Code Generation

Rust core: parse `otpauth://` URI, compute TOTP code (HMAC-SHA1, 30s step). Return 6-digit code. UI refreshes every 30s.

### 10. Backward Compatibility

Existing vaultes have `type` field absent. `load` treats missing type as `Login`. `uris: Vec<String>` migrated to `Vec<LoginUri>` with default `Domain` match. Migration runs on first load.

## Testing Decisions

- **Cipher type round-trip**: Create each type → serialize → deserialize → verify all fields preserved
- **Multi-URI ordering**: Create entry with 3 URIs → save → load → verify order preserved
- **Folder CRUD**: Create, rename, delete folders. Verify cipher folder_id references stay valid
- **Password history**: Create entry, change password 3 times → verify history has 3 entries with correct dates
- **Import parsing**: BW JSON fixtures → parse → verify types, URIs, folders, custom fields
- **Export format**: Create entries → export BW JSON → parse with serde → verify schema matches BW spec
- **TOTP generation**: Known otpauth URI → generate code → verify against reference implementation
- **Migration**: Old-format vault (no type field, flat URIs) → load → verify auto-migrated to Login type with LoginUri wrappers
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

## Further Notes

### Phased Implementation

**Phase A (Core Model)**: CipherType enum, typed data structs, multi-URI with match strategy, backward migration. Rust core only.

**Phase B (Folders + Favorites + History)**: Folder CRUD, favorite flag, password history tracking. Rust core + daemon routes + CLI commands.

**Phase C (Desktop UI)**: Type-specific add/edit forms, folder sidebar, favorite filter, multi-URI reorder, password history view. SolidJS/Tauri.

**Phase D (Generator + TOTP)**: Standalone generator UI, TOTP code display with auto-refresh.

**Phase E (Import/Export)**: BW JSON/CSV import, 1Password import, KeePass import, Chrome/Firefox import, BW JSON/CSV export. Rust core parsers.

### Import Priority

BW JSON is highest priority (direct migration path). Then Chrome CSV (most common browser), then 1Password, KeePass, Firefox, LastPass.

### URI Match Strategy Default

BW defaults to `Domain` match. IDtty should match this behavior. Users who need exact or regex matching explicitly set it per URI.

### Passphrase Generator

Use EFF large word list (7776 words). Configurable: word count (default 4), separator (dash, space, period, comma, number), capitalize (on/off), include number (on/off).
