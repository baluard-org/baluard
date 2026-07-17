# PRD: Git Provider Sync + Multi-Vault Foundation

**Date:** 2026-06-10
**Status:** Draft (original requirements record)
**Author:** Esteban (product)

> **Implementation note (2026-06-15):** Phases 1-3 + 5 + provider selection UI are **Done**. Phase 4 (clone) and Phase 6 (switching) remain. This PRD is the original requirements record; for current implementation reality see `docs/plan-git-providers-multi-vault.md` (Phase 5) and `docs/git-provider-apps-and-tokens.md` (provider app registration + token strategy).
>
> **Key divergences from this PRD:** (1) GitLab uses **device flow** as primary auth (it does NOT require `client_secret` — that claim in §5 was incorrect; GitLab supports public-client device flow since 17.9). (2) Codeberg uses **web-OAuth (auth-code + PKCE)** as primary, not PAT-only. (3) Providers use **raw `reqwest`**, not the `gitlab`/`forgejo-api` crates named in §5. (4) PAT is an Advanced Options fallback for all three, not the primary path for GitLab/Codeberg.

---

## Problem Statement

Users cannot synchronize their vault across devices. Baluard stores encrypted data locally but has no mechanism to connect to a Git hosting provider, authenticate, create a remote repository, or clone an existing vault on a new machine.

Additionally, the application assumes a single vault. There is no vault registry, no standard local storage layout, and no machine-friendly identifier for vaults. This blocks multi-vault support (personal, work, corporate) and makes provider integration harder because there is no unique, filesystem-safe, URL-safe name to use as a repository slug.

## Solution

Two capabilities delivered together because they share foundational architecture:

1. **Git Provider Sync.** Users connect to GitHub, GitLab, or Codeberg via OAuth device flow or PAT. The provider creates a private repository, and the sync engine pushes/clones vault data. Non-technical users get a simple flow: pick provider, authorize in browser, name your repo.

2. **Multi-Vault Foundation.** Replace the cosmetic "subtitle" field with a machine slug (e.g. `baluard-personal`). Standardize local storage layout under `<data_dir>/vaults/<slug>/`. Build a vault registry that tracks all known vaults. Adapt daemon and CLI to be vault-aware (accept `--vault <slug>` or default to last-opened). Implement vault switching in the daemon layer even if the desktop UI for switching ships later.

## User Stories

### Vault Slug and Identity

1. As a user creating a vault, I want to type a friendly name like "Personal" and have the system auto-suggest a slug `baluard-personal`, so that I don't have to think about technical naming rules.
2. As a user, I want to edit the auto-suggested slug before confirming vault creation, so that I can customize it to my preference (including removing the `baluard-` prefix if I want).
3. As a user, I want to be warned that the slug cannot be changed after creation, so that I choose carefully.
4. As a user, I want to be warned that the slug should be unique among my vaults, so that I avoid confusion when I add more vaults later.
5. As a user, I want the slug to appear as my repository name on the Git provider, so that I can easily find my vault in my repositories list.

### Provider Authentication

6. As a user setting up sync, I want to choose from a list of supported providers (GitHub, GitLab, Codeberg), so that I can use the service I already have an account with.
7. As a user choosing a provider, I want to see a recommendation to enable two-factor authentication on my provider account, so that my vault's first line of defense is strong.
8. As a user, I want to click "Connect" and have my browser open to the provider's authorization page, so that I don't need to understand tokens or API keys.
9. As a user, I want the authorization page to show me a code to paste or confirm, so that the process is clear and familiar (device flow).
10. As a user, I want Baluard to automatically receive and securely store my authorization after I approve in the browser, so that I don't need to copy anything manually.
11. As a power user, I want to optionally provide a Personal Access Token instead of using the browser flow, so that I can use automation or restricted environments.
12. As a user, I want my provider credentials stored in my OS keyring, so that they never appear in plaintext on disk or in git.

### New Vault + First Sync

13. As a user creating a new vault, I want to optionally connect it to a Git provider during or after the creation wizard, so that my vault is backed up from the start.
14. As a user connecting a new vault to a provider, I want to name my repository (defaulting to my vault slug), so that I control how it appears on the provider.
15. As a user, I want Baluard to automatically create a private repository on my chosen provider, so that I don't need to visit the provider's website.
16. As a user, I want the first sync to happen automatically after repository creation, so that my data is immediately backed up.

### Existing Vault on a New Device

17. As a user on a new device, I want to see three options on the first screen: "Create new vault", "Open local vault", "Download from provider", so that the onboarding covers all scenarios.
18. As a user selecting "Download from provider", I want to pick my provider, authenticate, and see a list of my repositories that contain Baluard vaults, so that I can find my vault easily.
19. As a user browsing remote vaults, I want repositories that contain a Baluard vault marker to be highlighted or filtered, so that I can distinguish my password vault from my code repos.
20. As a user selecting a remote vault, I want Baluard to clone it locally and then prompt me for my master password to unlock, so that my data is secure.
21. As a user opening a local vault, I want to browse my filesystem and select the vault directory, so that I can open vaults stored on external drives or non-standard locations.

### Multi-Vault Foundation

22. As a user with multiple vaults, I want a known local directory where all my vaults are stored (`<data_dir>/vaults/<slug>/`), so that vaults are organized consistently.
23. As a user with multiple vaults, I want the application to remember which vault I last had open, so that it opens automatically on next launch.
24. As a user with multiple vaults, I want to switch between them from the CLI using `baluard --vault <slug>`, so that I can target specific vaults in scripts.
25. As a user with multiple vaults, I want to see a list of my vaults from the CLI using `baluard vaults list`, so that I know what's available.
26. As a user, I want provider credentials to be shared across vaults (one GitHub auth, multiple vault repos), so that I don't re-authenticate for each vault.

### Vault Marker

27. As the application, I want to write a `.baluard` marker file at the root of every vault (local and remote), so that I can programmatically detect whether a git repository is a Baluard vault.
28. As the application scanning remote repositories, I want to read the `.baluard` marker to determine vault compatibility (version, vault ID), so that I can filter and present only valid vaults to the user.

---

## Implementation Decisions

### 1. Vault Slug

- Replace the `subtitle` field in `VaultSettings` and the creation wizard with a `slug` field.
- Slug rules: lowercase, `a-z0-9`, hyphens only, 4-63 characters, no forced prefix.
- Default suggestion includes `baluard-` prefix for discoverability, but user can remove or change it.
- Default value: "Personal" (so slug pre-fills as `baluard-personal`). Users in a rush can accept immediately.
- Auto-generation: user types "Personal" (or edits to any name) -> system generates `baluard-personal` by lowercasing, replacing spaces/special chars with hyphens, collapsing consecutive hyphens, prepending `baluard-` as a suggested prefix. Slug updates live as the user types. User is free to remove or change the prefix.
- Slug is immutable after vault creation. Stored in `meta/settings.enc` as part of `VaultSettings`.
- Slug used as: repository name on provider, local folder name under `<data_dir>/vaults/`, vault registry key, CLI `--vault` argument.
- Collision handling: if slug already exists in registry, surface clear error with suggested alternatives before creation proceeds.

### 2. `.baluard` Marker File

- JSON file at vault root (alongside `entries/`, `meta/`, etc.).
- Content:

```json
{
  "version": 1,
  "vault_id": "550e8400-e29b-41d4-a716-446655440000",
  "slug": "baluard-personal"
}
```

- Written at vault creation. Never modified (slug is immutable, vault_id is derived).
- Not encrypted (not secret data; equivalent to `meta/locale`). Used for fast detection without decrypting vault contents.
- Tracked in git (NOT in `.gitignore`) so remote repos are detectable.
- **Note:** `vault_id` is a stable UUID committed to the repo. If a user syncs the same vault to multiple providers in the future, both repos share the same `vault_id`, enabling cross-provider correlation. Acceptable for current single-provider scope; document for future multi-provider planning.

### 3. Local Storage Layout

Current: vaults live at arbitrary user-specified paths. Data dir is `data_dir()` which returns `<platform_data_dir>/baluard/`.

New layout:

```
<platform_data_dir>/baluard/
  vaults/
    baluard-personal/          # actual vault (git repo)
      .baluard
      entries/
      meta/
      ...
    work-vault/
      .baluard
      entries/
      meta/
      ...
  registry.json               # vault registry
  providers.json               # provider auth state
```

- `data_dir()` gains a `vaults_dir()` function returning `<data_dir>/vaults/`.
- Individual vault path: `vaults_dir().join(slug)`.
- Imported local vaults (via "Open local vault"): vault stays at its original location. Registry stores the absolute path. No copy or move. Registry must handle arbitrary paths gracefully.
- Backward compatibility not required (unreleased software).

### 4. Vault Registry

- `registry.json` stored at `<data_dir>/registry.json` (plaintext, not secret).
- Schema:

```json
{
  "version": 1,
  "vaults": {
    "baluard-personal": {
      "slug": "baluard-personal",
      "display_name": "Personal Vault",
      "path": "/absolute/path/to/baluard-personal",
      "provider": "github",
      "last_opened": "2026-06-10T12:00:00Z"
    },
    "work-vault": {
      "slug": "work-vault",
      "display_name": "Work",
      "path": "/absolute/path/to/work-vault",
      "provider": null,
      "last_opened": null
    }
  },
  "active_vault": "baluard-personal",
  "default_provider": "github"
}
```

- Updated on: vault creation, vault open, vault delete, sync setup.
- `active_vault`: which vault the daemon currently has open (or last opened). Daemon reads this on startup.
- **All writes use atomic rename** (temp file + `rename(2)`), matching existing `write_vault_file()` pattern.
- **Cross-process locking** via `fd-lock` or `flock` on registry file. Prevents corruption when CLI `--direct` mode and daemon both write concurrently.

### 5. Provider Architecture

- New module: `crates/baluard-core/src/providers/`.
- Not a separate crate. Providers are core functionality tightly coupled to sync and vault operations.

**Provider trait:**

All methods are `async fn` (stable since Rust 1.75, MSRV is 1.85, no `async-trait` crate needed).

```rust
#[async_trait] // conceptually; use native async fn in trait
pub trait ForgeProvider: Send + Sync {
    fn name(&self) -> &str;                          // "github", "gitlab", "codeberg"
    fn display_name(&self) -> &str;                  // "GitHub", "GitLab", "Codeberg"

    // Device flow: two-phase (client owns the polling loop)
    async fn device_flow_start(&self) -> Result<DeviceFlowSession>;
    async fn device_flow_poll(&self, session: &DeviceFlowSession) -> Result<DeviceFlowStatus>;

    // PAT auth
    async fn authenticate_pat(&self, token: &str) -> Result<ProviderToken>;

    // Token lifecycle
    async fn validate_token(&self, token: &ProviderToken) -> Result<UserInfo>;
    async fn refresh_token(&self, token: &ProviderToken) -> Result<ProviderToken>;

    // Repository operations
    async fn list_repos(&self, token: &ProviderToken) -> Result<Vec<RepoInfo>>;
    async fn create_private_repo(&self, token: &ProviderToken, name: &str) -> Result<RepoInfo>;
    async fn get_clone_url(&self, token: &ProviderToken, repo: &RepoInfo) -> Result<String>;

    // Vault detection
    async fn detect_vault_repos(&self, token: &ProviderToken) -> Result<Vec<VaultRepoInfo>>;
}
```

**Key types:**

```rust
pub struct DeviceFlowSession {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,  // polling interval in seconds
}

pub enum DeviceFlowStatus {
    Pending,
    Success(ProviderToken),
    Expired,
}

pub struct ProviderToken {
    pub access_token: SecretString,  // zeroized on drop
    pub refresh_token: Option<SecretString>,
    pub expires_at: Option<DateTime<Utc>>,
    pub token_type: String,
    pub scopes: Vec<String>,
}
```

- `ProviderToken` wraps `SecretString` (zeroize on drop). Not a plain string.
- `refresh_token` and `expires_at` are required for GitLab (tokens expire in 2 hours). Optional for GitHub (tokens don't expire unless revoked). Always stored so the schema is uniform.

**Provider implementations:**

| Provider | Crate | Auth Methods |
|----------|-------|-------------|
| GitHub | `octocrab` | OAuth device flow (primary), PAT (fallback) |
| GitLab | `gitlab` | PAT only (device flow requires `client_secret`, unacceptable for open-source security product) |
| Codeberg | `forgejo-api` | PAT only (Codeberg lacks device flow) |

### 6. OAuth Device Flow

- GitHub only for this PRD. Uses `octocrab`'s built-in `authenticate_as_device()`.
- GitLab and Codeberg: PAT only. Users paste a token. The flow explains where to generate one on each provider.
- Device flow is split into two daemon routes (not one blocking call):
  - `provider.connect_start` -> returns `{ user_code, verification_uri, expires_in, interval }`
  - `provider.connect_poll` -> called by client, returns `{ pending | success | expired }`
- Client (CLI or desktop) owns the polling loop and UI.
- PKCE does not apply to device flow (RFC 8628 has no authorization code to intercept). Not mentioned or implemented for device flow.

### 7. Provider Credential Storage

- Tokens stored in OS keyring via `keyring` crate (already a dependency for biometric unlock).
- Keyring entry: `baluard-<provider>-<username>`.
- `ProviderToken` (including `refresh_token` and `expires_at`) serialized and stored as a single keyring entry.
- One token per provider, shared across all vaults for that provider.
- **`providers.json`** (plaintext, at `<data_dir>/providers.json`) stores non-sensitive lookup state:

```json
{
  "version": 1,
  "providers": {
    "github": {
      "username": "alice",
      "connected_at": "2026-06-10T12:00:00Z",
      "scopes": ["repo"]
    },
    "gitlab": null
  }
}
```

- Schema defined explicitly. Stores only: provider name, username, connection timestamp, scopes. No tokens or secrets.
- Used to construct keyring lookup key (`baluard-github-alice`) without needing the keyring first.
- Atomic writes (temp + rename), same as registry.
- **Headless fallback:** when OS keyring is unavailable (headless Linux, CI), error with a clear message directing user to `--direct` mode with PAT via env var `BALUARD_PROVIDER_TOKEN_<PROVIDER>`.

### 8. Token Refresh

- GitLab tokens expire (default 2 hours). GitHub tokens do not expire unless revoked.
- Daemon checks `expires_at` before every provider operation. If expired or within 5 minutes of expiry, calls `refresh_token()`.
- Refreshed token (including new `refresh_token` if rotated) stored back to keyring.
- If refresh fails (revoked, network), clear keyring entry + `providers.json` state. Surface re-auth prompt to user.
- For GitHub: `refresh_token()` is a no-op (token is long-lived). Method exists for trait uniformity.

### 9. Remote Vault Detection

Three-tier strategy, tried in order:

1. **Search API** (GitHub, maybe GitLab on gitlab.com): `GET /search/code?q=filename:.baluard+user:USERNAME`. Single API call, returns filtered list of vault repos.
2. **List + fetch** (GitLab fallback, Codeberg): List user repos, then concurrently fetch `.baluard` marker for each (up to 10 concurrent requests). Most users have under 50 repos; completes in seconds.
3. **Manual selection** (final fallback): Show full repo list, user identifies their vault.

- All repo listing uses paginated API calls. Provider implementations handle pagination transparently.
- `detect_vault_repos()` returns `Vec<VaultRepoInfo>` with repo name, provider, clone URL, and parsed marker content.

### 10. Daemon Changes

- `VaultState` currently holds a single vault path and handle.
- New: `VaultState` reads `active_vault` from registry on startup.
- **Phase 6 multi-vault model (design revision 2026-06-17):** the daemon no longer serves a single active vault. It holds every opened vault in an in-memory map `HashMap<String, Arc<VaultState>>` plus an `active` slug pointer. A vault is inserted into the map on first open/unlock (lazy). Users can keep two or more vaults unlocked at once and switch between them instantly; each unlocked vault stays unlocked according to **its own** `auto_lock_minutes` setting, auto-locking independently. See `docs/plan-git-providers-multi-vault.md` Phase 6 and the security note in `docs/threat-model.md` (T15).
- **CLI `--vault <slug>`** targets a specific vault. If that vault is already open in the daemon map (even if not active), the request routes through the daemon with the slug attached. `--direct` mode (in-process, no daemon) is the fallback only for a vault the daemon has never opened, or when the daemon is not running.
- `vaults.switch` daemon route: **pointer flip only.** Validates the target slug is registered, sets `active = Some(slug)`, touches the registry's `last_opened`. Does **not** zeroize the previously-active vault and does **not** rotate any session token. Returns `{ active, state }` where `state` is `unlocked`/`locked`/`closed` so the caller knows whether to present an unlock prompt. Switching is therefore instant and never invalidates in-flight requests to other vaults (the handler resolves the target vault once per request, avoiding a TOCTOU on `active`).
- `vaults.close` daemon route (new): removes one vault from the in-memory map, clearing `active` if it was active, without affecting other open vaults. Returns immediately (Arc-drain): in-flight handlers holding a cloned `Arc<VaultState>` finish and zeroize on last drop. No busy/retry.

New daemon routes:

| Route | Description |
|-------|-------------|
| `provider.list` | List supported providers with connection status |
| `provider.connect_start` | Start OAuth device flow (returns code + URL) |
| `provider.connect_poll` | Poll device flow status (pending / success / expired) |
| `provider.connect_pat` | Validate and store a PAT for a provider |
| `provider.disconnect` | Remove stored credentials for a provider. **Attempt token revocation at provider** (GitHub: `DELETE /applications/{client_id}/token`, GitLab: `DELETE /oauth/tokens/{token}`). Failure to revoke is non-blocking (log warning, proceed with local cleanup). |
| `provider.status` | Check if current provider token is valid |
| `provider.repos` | List user's repos on a connected provider |
| `provider.vault_repos` | List repos detected as Baluard vaults (three-tier detection) |
| `provider.create_repo` | Create a private repo on provider. **Verify `private: true` on response.** If public, delete repo immediately and return error. Never push vault data to a public repo. |
| `vault.setup_sync` | Connect current vault to a provider repo + first push |
| `vault.clone_remote` | Clone a remote vault, add to registry |
| `vaults.list` | List all vaults in registry, each with live state (`unlocked`/`locked`/`closed`) |
| `vaults.switch` | Flip the live `active` pointer to another slug (no zeroization, no token change); returns target state |
| `vaults.set_active` | Persist the default/active vault slug in the registry |
| `vaults.active` | Return the current active slug + its state |
| `vaults.close` | Remove one vault from the in-memory map (clears `active` if active); Arc-drain — returns immediately, in-flight handlers finish and zeroize on last drop |

### 11. Git Credential Transport

- HTTPS with token-based authentication.
- **Use git2-rs `RemoteCallbacks::credentials()` callback**, not an external credential helper binary. The callback reads from OS keyring directly. No separate process, no PATH dependency, no packaging changes.
- No tokens in git config or on-disk credentials files.
- SSH deploy keys not in scope for this PRD (future enhancement for air-gapped setups).

### 12. CLI Changes

- `baluard --vault <slug>` flag on all commands to target a specific vault. Routes through the daemon (with slug) if that vault is open in the daemon map; otherwise falls back to `--direct` mode.
- `baluard vaults list` to show registered vaults (with live state: unlocked/locked/closed, last opened).
- `baluard vaults switch <slug>` to flip the active vault instantly; prompts for the master password if the target is locked/closed.
- `baluard vaults close <slug>` to lock and unload a single vault without affecting others.
- `baluard provider connect <github|gitlab|codeberg>` to authenticate (GitHub: device flow, others: prompts for PAT).
- `baluard provider disconnect <provider>` to remove credentials.
- `baluard provider repos <provider>` to list remote repos.
- `baluard sync setup` to connect current vault to a provider repo.
- `baluard sync clone <provider> <repo>` to clone a remote vault.

### 13. Desktop Wizard Changes

Current first screen: "Create new vault" or "Unlock existing vault".

New first screen: three options:

1. **Create new vault** (existing wizard flow, with slug step replacing subtitle).
2. **Open local vault** (file picker, imports into registry if not already known).
3. **Download from provider** (provider selection -> auth -> vault repo list -> clone -> unlock).

The slug step in vault creation:
- Vault name field pre-filled with "Personal".
- Slug auto-generated from name and shown below (live, updates as user types). Default suggestion includes `baluard-` prefix.
- User can edit slug directly, including removing the prefix.
- Warning: "This name cannot be changed later."
- Confirmation step showing final local directory path and repository URL before proceeding.
- "Enable sync" toggle at bottom of wizard (off by default). If on, provider selection flow follows.

### 14. 2FA Warning

- When user selects a provider (in wizard or settings), a dismissible info banner appears:
  - "We recommend enabling two-factor authentication on your [GitHub/GitLab/Codeberg] account for maximum security."
- Not blocking. User can dismiss and continue.
- Shown once per provider connection (stored in local prefs, not synced).

### 15. Self-Hosted Providers

- Initial scope: hosted forges only (`github.com`, `gitlab.com`, `codeberg.org`).
- Architecture allows self-hosted later via custom host field on provider config.
- UI for self-hosted deferred to future PRD.

### 16. OAuth Scopes

Principle of least privilege. Exact scopes requested per provider:

| Provider | Scope | Rationale |
|----------|-------|-----------|
| GitHub | `repo` | Required for private repo read/write. Fine-grained PATs would be better but device flow does not support them. Document this tradeoff. |
| GitLab | `read_repository` + `write_repository` | Narrowest scope for clone/push operations. PAT only, no OAuth. |
| Codeberg | `repository` | Forgejo equivalent for repo read/write. PAT only. |

### 17. Clone Progress Reporting

- `vault.clone_remote` can block for extended periods on slow connections or large vaults.
- git2-rs `RemoteCallbacks::transfer_progress()` provides byte/object counts.
- IPC response streams progress events to desktop. CLI prints progress dots or percentage.

---

## Testing Decisions

### Unit Tests

- **Slug generation and validation**: test normalization rules, length constraints, edge cases (unicode, special characters, consecutive hyphens, prefix not forced).
- **`.baluard` marker**: test serialization/deserialization, version field forward compatibility.
- **Vault registry**: test CRUD operations, active vault switching, atomic write verification, concurrent access via file locking.
- **Provider trait**: mock implementations for all provider operations, test daemon routing with mocked providers.
- **Token refresh**: mock token expiry and verify refresh flow. Test refresh failure path (clear credentials).
- **Vault switch semantics**: verify `vaults.switch` flips only the `active` pointer (no zeroization, no session-token change), and that a previously-active vault remains unlocked after the switch. Verify per-vault auto-lock fires independently.

### Integration Tests

- **Provider device flow**: test against provider test/dev OAuth applications (requires CI secrets for client IDs). Mock HTTP responses as fallback for CI.
- **Repository detection**: create test repos with/without `.baluard` marker, verify filtering across all three detection tiers.
- **First sync flow**: create vault -> connect to mock provider -> push. Verify `.baluard` present in remote, sync engine operational, repo is private.
- **Clone flow**: mock provider returns vault repo -> clone -> verify `.baluard` present -> verify vault can be unlocked.
- **Vault registry + daemon**: create multiple vaults, verify daemon switches between them correctly.
- **Adversarial cases**: expired token mid-operation, repo creation succeeds but push fails (orphaned remote cleanup), keyring read failure after token stored, registry corruption recovery, device flow code expiry.

### Property-Based Tests

- Slug generation: any input string produces a valid slug (matches regex `^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$`).
- Marker round-trip: any valid marker JSON survives serialize/deserialize.

### Test Scope Priority

1. Slug generation/validation (critical, simple)
2. Vault registry operations (critical, new module)
3. Provider trait with mocks (critical, core abstraction)
4. Token refresh + lifecycle (critical, security)
5. Marker file operations (high, simple)
6. Full sync flow with mocked provider (high, complex)
7. Vault switch semantics: keep-unlocked, per-vault auto-lock (high, security)
8. Desktop wizard flow (medium, UI-level)

---

## Out of Scope

- **Vault switching UI in desktop.** Daemon and CLI support it. Desktop sidebar/switcher UI is a separate PRD.
- **Bitbucket support.** No mature Rust crate for Bitbucket Cloud API. Deferred.
- **Self-hosted GitLab/Gitea/Forgejo instances.** Architecture supports it, UI and config not included.
- **SSH deploy keys.** HTTPS + PAT/OAuth token only for this PRD.
- **Mobile (JIT sync).** Provider auth layer will be reusable, but mobile integration is out of scope.
- **Multiple accounts on same provider.**** Current keyring design stores one token per provider. Multi-account requires a separate credential selection UI. Documented as future constraint.
- **Encrypted JSON export.** Already in "nice to have" in progress.md.
- **FIDO2 credential storage.** Already in "nice to have" in progress.md.

---

## Further Notes

### Crate Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `octocrab` | ^0.53 | GitHub API + device flow |
| `gitlab` | verify actual current version | GitLab API |
| `forgejo-api` | verify actual current version, pin semver | Codeberg/Forgejo API |
| `oauth2` | ^5.0 | OAuth2 flows (GitHub device flow) |
| `keyring` | existing | OS credential storage (already used for biometric) |
| `fd-lock` | ^4 | Cross-process file locking for registry |

**Note on dependency weight:** `octocrab`, `gitlab`, and `forgejo-api` bring significant transitive dependency counts. If compile time or audit surface becomes a concern, a lightweight HTTP client (e.g. `ureq`) targeting only the 4-5 endpoints we need per provider is a viable alternative. Evaluate after initial implementation.

### Breaking Changes (Unreleased, Acceptable)

- `subtitle` field removed from `VaultSettings` and creation wizard.
- `data_dir()` behavior changes: vaults now live under `vaults/` subdirectory.
- `VaultState::new(vault_path)` changes to `VaultState::new(slug)` or similar registry-aware constructor.
- CLI default vault path changes from arbitrary to registry-based.
- Desktop wizard first screen changes from 2 options to 3 options.

### Provider OAuth Application Registration

Baluard needs OAuth applications registered on each provider:

| Provider | Type | Notes |
|----------|------|-------|
| GitHub | OAuth App (device flow) | Client ID embedded in binary (not secret) |
| GitLab | PAT only | No OAuth app needed |
| Codeberg | PAT only | No OAuth app needed |

Client IDs are not secrets (they identify the app, not the user). Safe to embed in open-source code.

### Future Multi-Vault UI Sketch

When the vault switcher UI ships later:

- Sidebar header shows active vault name + slug.
- Click to open vault picker (list from registry).
- Each vault shows: name, provider icon (if synced), last-opened timestamp.
- "Add vault" button leads to wizard or provider clone flow.
- This PRD builds all the data layer; the UI just needs to wire to it.
