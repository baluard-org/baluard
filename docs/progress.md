# IDtty: Master Progress Document

> Single source of truth for project state. Update after every work session.
> Last updated: 2026-06-04

---

## Project Overview

**What**: Git-backed password manager. Encrypted vault stored as a git repo. No server.
**Stack**: Rust Core Engine (`idtty-core` crypto/keys/vault/sync + `idtty-daemon` IPC socket server + `idtty-cli` terminal client) + Tauri v2 Desktop (SolidJS/Tailwind) + Single-String Protobuf Gateway.
**Platforms**: Windows, Linux (deb/rpm), macOS. CLI: bash, zsh, PowerShell.
**Architecture docs**: `docs/architecture-decisions.md` through `docs/software-architecture.md`.

---

## Current Status

**0 clippy errors workspace-wide.**

Full desktop feature set: CRUD, 8 cipher types, generator, TOTP, auto-lock, import/export, reprompt, password health, attachments, biometric unlock, linked custom fields, nested folders, archive entries.

**Monorepo Structure**:
- `/proto` - Shared Protobuf schemas (`vault.proto`, `space.proto`, `auth.proto`)
- `/crates/idtty-core` - Rust core engine: crypto, keys, vault, padding, git sync
- `/crates/idtty-cli` - Terminal CLI client (clap, daemon-first with `--direct` fallback)
- `/crates/idtty-daemon` - Background IPC daemon (tokio Unix socket, Protobuf gateway, vault state)
- `/desktop` - SolidJS/Tailwind/Tauri v2 desktop app (full CRUD, 8 cipher types, generator, TOTP, auto-lock, dark/light themes)

---

## Implementation Progress

| Module | Status | What's Implemented |
|--------|--------|--------------------|
| `workspace` | Done | Rust workspace with idtty-core, idtty-cli, idtty-daemon crates |
| `proto/schemas` | Done | `vault.proto`, `space.proto`, `auth.proto`. Compiled by prost-build in daemon and CLI |
| `crypto/aead` | Done | AES-256-GCM with strict AAD binding |
| `vault/handle` | Done | Vault CRUD operations |
| `vault/creation` | Done | Vault creation ceremony with BIP-39 recovery phrase |
| `sync/engine` | Done | git2-rs sync: init_repo, commit, push, pull, fetch, Ed25519 signed commits |
| `sync/conflict` | Done | Conflict auto-healing (index rebuild, entry rename) |
| `sync/state_machine` | Done | Sync state machine for tracking sync progress |
| `daemon/socket` | Done | Unix socket listener. 0600 via umask. SIGINT/SIGTERM graceful shutdown |
| `daemon/handler` | Done | Protobuf gateway. Length-delimited wire. Token-gated IPC. Password zeroized |
| `daemon/state` | Done | VaultState with Arc<RwLock>. KDF outside write lock. Double-check unlock pattern |
| `cli/dual-mode` | Done | All commands: daemon-first + `--direct` fallback. `--socket <path>` override |
| `desktop` | Done | SolidJS/Tailwind v4 + Tauri v2. 3-column layout, dark/light themes, tray, daemon spawn |
| Uniform bucket padding | Done | 5 tiers (Xs:5KB, S:30KB, M:100KB, L:250KB, XL:2MB). Auto-selected via `Tier::fit()` |
| `index.enc` fast lookup | Done | Encrypted lookup table. O(1) list_cipher_meta. Auto-healing on corruption |
| Git commit signing | Done | Ed25519 signatures in commit `gpgsig` header. Verified on pull. Merge commits signed |
| Cover commits / jitter | Done | No-op cover commits + CSPRNG-backed timing jitter on push/pull |
| Integrity manifest | Done | Ed25519-signed checkpoints, rollback detection, bootstrap for fresh devices |
| Token-gated IPC | Done | 256-bit session token on unlock. Constant-time comparison. Cleared on lock |
| `mlock` on key material | Done | `libc::mlock` on RootKey/ItemKey. Re-mlocked on Clone. Redacted Debug |
| AAD swap protection | Done | `decrypt_cipher` recomputes expected AAD, asserts before decryption |
| Device lifecycle | Done | Enrollment, quorum, force-evict, epoch rotation, recovery phrase path |
| Space Group Key | Done | RootKey -> SpaceGroupKey -> ItemKey hierarchy. Epoch-bound. Volatile zeroize |
| Import/Export | Done | 8 import parsers + 2 export formats (BW-compatible) |
| Reprompt | Done | Per-entry master password challenge with 30s grant |
| Password Health | Done | Weak/reused/old password detection |
| Attachments | Done | AES-256-GCM encrypted, max 2MB. Plaintext zeroized after use |
| Biometric Unlock | Done | OS keychain (keyring crate). Daemon-side unlock, secret never over IPC |
| Linked Custom Fields | Done | 24 LinkedFieldType variants with type-safe resolution |
| Nested Folders | Done | Max depth 16. Cascade delete. BFS descendant collection |
| Archive | Done | Archive/unarchive ciphers. Separate list view |
| Extra cipher types | Done | BankAccount (10 fields), DriversLicense (12 fields), Passport & ID (13 fields) |
| Orgs | Done | Team/org sharing. HPKE key wrapping. Auto-rekey on member removal |
| Emergency access | Done | Break-glass access. Pre-wrapped Root Key. Advisory time gate |
| Providers | Done | GitHub/GitLab adapters. OAuth + PAT. Auto-create vault repo |

### BW Parity Phases 1-8

| Phase | Description | Key Changes |
|-------|-------------|-------------|
| 1 | CipherKind sum type | Tagged enum (Login/Card/Identity/SshKey/SecureNote). Invalid states unrepresentable |
| 2 | Multi-URI + settings | Multiple URIs with match strategy. `VaultSettings` CRUD |
| 3 | CipherMeta + vault.update | `vault.list` returns CipherMeta. `vault.update` with PATCH semantics |
| 4 | Password history + clone | Auto-append on change, cap 10. `cipher.clone` with new UUID |
| 5 | Folder CRUD | Create/rename/delete. Delete unassigns ciphers first |
| 6a-c | Desktop: All forms | Login, SecureNote, Card, Identity, SSH Key forms |
| 7 | Generator + auto-lock | CSPRNG generator, EFF passphrase. Configurable auto-lock timer |
| 8 | TOTP | RFC 6238/4226. SHA1/256/512, 6/8 digits. Daemon route + UI widget |

### BW Parity Phases A-G

| Phase | Description | Key Changes |
|-------|-------------|-------------|
| A | Import/Export | 8 parsers + 2 export formats. Daemon routes. CLI commands |
| B | Reprompt | Per-entry MP challenge. 30s grant. Shield icon |
| C | Password Health | Weak/reused/old detection. CLI + desktop reports |
| D | Attachments | AES-256-GCM encrypted files. Max 2MB. Zeroized after use |
| E | Biometric Unlock | OS keychain via keyring. Daemon-side. Quick Unlock button |
| F | Linked Custom Fields | 24 variants. Type dropdown + linked field selector |
| G | Nested Folders | Depth 16. Cascade delete. Recursive tree UI |

---

## Pending Work

All items not yet implemented. Focus: core, CLI, daemon, desktop only.

### Device Fleet Visibility

**Architecture**: See DOMAIN 5 in `docs/architecture-decisions.md`

| Phase | Description | Effort | Status |
|-------|-------------|--------|--------|
| 1 | Activity index (`meta/device_activity.json`) + daemon route | 1-2 days | **Done** |
| 2 | Enhanced DeviceEntry (`enrolled_by`, `last_seen_epoch`) + revocation cleanup | 1 day | **Done** |
| 3 | Epoch timeout + deterministic coordinator election | 1 day | **Done** |
| 4 | CLI fleet commands (`devices list/revoke/info/rotation-status/rotation-abort`) | 0.5 days | **Done** |
| 5 | Fleet dashboard (desktop: devices tab, status badges, revoke UI) | 2-3 days | **Done** |

### Desktop Features

| Item | Description | Status |
|------|-------------|--------|
| Additional import formats | Dashlane, Enpass, NordPass, Avast, Avira, Keeper, RoboForm, Myki, mSecure, Blur | Not started |

### Nice to Have / Future

Features parked for the far future. Do not start without explicit confirmation.

| Item | Description | Blocker |
|------|-------------|---------|
| Encrypted JSON export | IDtty-native format (Argon2id + AES-256-GCM). Git clone + recovery phrase already covers disaster recovery | Low priority, needs format documentation |
| FIDO2 credential storage | On Login cipher type. Requires hardware auth infrastructure | Needs FIDO2-compatible hardware for testing |

### Out of Scope (No Server)

| Item | Why |
|------|-----|
| Collections | Org-level groupings, requires multi-user infrastructure |
| Breach report | HaveIBeenPwned requires external API |
| Send | Encrypted sharing requires server relay |
| HOTP | TOTP only. Counter-based OTP out of scope |
| BW server API compat | IDtty is serverless |

### Security

| Item | Description | Effort |
|------|-------------|--------|
| OAuth PAT escrow | PAT stored in OS keyring (never in git config) | Days |
| 2FA Tier 1 | Document "local-only = 2FA" framing in UX | Hours |
| 2FA Tier 2 | FIDO2 vault unlock via `libfido2` (hardware second factor) | Weeks |
| 2FA Tier 3 | OS keychain sync gate (separate auth for git push/pull) | Days |
| 2FA Tier 4 | TOTP for device enrollment confirmation (ephemeral liveness check) | Days |
| 2FA Tier 5 | FIDO2-only mode (no master password) | Weeks |

#### 2FA Open Questions

1. `libfido2` Rust crate maturity and audit status
2. OS keychain availability in headless CI (mock trait needed)
3. Multiple FIDO2 credentials per vault
4. Recovery after FIDO2 credential loss
5. Org/team vault 2FA requirements (deferred)

---

## Architecture Reference

### Cipher Model

- **CipherKind**: serde-tagged enum `#[serde(tag = "type", content = "data")]`. 8 variants: Login, Card, Identity, SshKey, BankAccount, DriversLicense, Passport, SecureNote
- **CipherType enum**: `Login`, `SecureNote`, `Card`, `Identity`, `SshKey`, `BankAccount`, `DriversLicense`, `Passport` (Passport covers national ID documents)
- **Multi-URI**: `Vec<LoginUri>` where `LoginUri { uri, match_strategy }`. Ordered, reorderable
- **UriMatchStrategy**: Domain(0), Host(1), StartsWith(2), Exact(3), Regex(4), Never(5)
- **Favorite**: `bool` on both `Cipher` and `CipherMeta`
- **Password history**: `Vec<PasswordHistoryEntry>` on Cipher, cap 10 entries (FIFO)

### Daemon Wire Format

- JSON strings inside `GatewayRequest.payload`. Proto updates cosmetic until typed migration planned
- `get_cipher` returns BOTH nested `kind` object AND flat top-level fields
- `update_cipher` parses `kind` from payload JSON (does NOT clone existing kind)

### Import/Export

- Import runs in Rust core (no JS parsing of secrets). Output: `Vec<CipherInput>`, batch-create
- 8 formats: bw_json, bw_csv, chrome_csv, firefox_csv, lastpass_csv, 1password_1pux, 1password_csv, keepass_xml
- 2 export formats: bw_json, bw_csv (both BW-compatible)

### TOTP

- RFC 6238/4226. SHA1/256/512, 6/8 digits, 30/60s periods
- Seed NEVER crosses IPC. Only derived numeric code sent to frontend
- `TotpParams.secret` zeroized on drop

### Password Generator

- `crypto.getRandomValues` exclusively (never `Math.random`)
- EFF large word list (7776 words) bundled as static asset

### Backward Compatibility

- Missing `type` field auto-migrated to `Login`
- `Vec<String>` URIs auto-migrated to `Vec<LoginUri>` with Domain default
- Unknown `UriMatchStrategy` string values produce hard error

### Key Hierarchy

```
Master Password -> KEK (Argon2id) -> Device Private Key (X25519, HPKE-escrowed)
  -> Root Key (512-bit, per-epoch) -> Space Group Key (256-bit, per-space)
    -> Item Keys (256-bit, per-cipher)
```

### Epoch State Machine

`CREATED -> ACTIVE -> ROTATING -> RETIRED -> DESTROYED`

Root key rotation generates new RootKey, re-encrypts all entries, wraps KEK only for surviving devices.

### Device Registry

- `DeviceRegistry`: enroll, revoke, force-evict, quorum (ceil(N/2))
- Stored in `meta/devices.json` (plaintext, per DOMAIN 5/D1 in architecture decisions)
- Epoch rotation with two-phase commit via git-mediated ack files

---

## Known Limitations

1. **No real-time revocation**: Revoked device retains data until it pulls. Root key rotation limits damage to stale snapshot.
2. **Git credentials out-of-band**: Revoking vault access does NOT revoke git push access. User must rotate deploy keys / PATs manually.
3. **Metadata leakage via bucket sizes**: Standard logans mapped to 1KB, notes to 8KB, attachments to 64KB/1MB.
4. **Offline sharing limitation**: Invites and revokes require push to remote git host.
5. **Sync routed through daemon**: All sync commands default to daemon with `--direct` fallback.

---

## CLI Command Reference

| Command | Mode | Description |
|---------|------|-------------|
| `init --profile <p>` | Direct | Create new vault |
| `unlock` | Daemon/Direct | Unlock vault |
| `lock` | Daemon | Lock vault, zeroize keys |
| `add --name N ...` | Daemon/Direct | Add cipher |
| `get <id> --decrypt` | Daemon/Direct | Get cipher by UUID |
| `list` | Daemon/Direct | List all cipher UUIDs |
| `edit <id>` | Daemon/Direct | Edit cipher metadata |
| `delete <id>` | Daemon/Direct | Delete cipher |
| `archive <id>` / `unarchive <id>` | Daemon/Direct | Archive/restore cipher |
| `folders {create\|list\|rename\|delete}` | Daemon/Direct | Folder management |
| `sync {init\|remote\|push\|pull\|...}` | Daemon/Direct | Git sync operations |
| `import <format> <file>` | Daemon | Import entries |
| `export <format> <file>` | Daemon | Export entries |
| `health` | Daemon | Password health report |
| `attach-*` | Daemon | Attachment upload/download/delete/list |
| `devices list` | Direct | List enrolled devices |
| `ping` | Daemon | Check daemon connectivity |

**Flags**: `--vault-path <dir>`, `--direct` (skip daemon), `--socket <path>`

---

## File Map

```
idtty/
├── proto/                        # Shared Protobuf Schemas (vault, space, auth)
├── crates/
│   ├── idtty-core/               # Rust Core: crypto, keys, vault, padding, sync, import/export, health, biometric, attachments
│   ├── idtty-cli/                # Terminal CLI (daemon-first + --direct fallback)
│   └── idtty-daemon/             # IPC daemon (Unix socket, Protobuf, VaultState, auto-lock, TOTP, attachments, biometric)
├── desktop/                      # Tauri v2 Desktop (8 cipher types, generator, TOTP, import/export, custom fields, nested folders)
├── docs/                         # Architecture & design docs
├── plans/                        # Implementation plans
└── justfile                      # Build system
```
