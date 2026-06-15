# Plan: Git Provider Sync + Multi-Vault Foundation

> Source PRD: `docs/prd-git-providers-multi-vault.md`

## Architectural decisions

Durable decisions that apply across all phases:

- **Slug**: replaces `subtitle` in `VaultSettings`. Lowercase, `a-z0-9`, hyphens, 4-63 chars. `baluard-` prefix suggested but not enforced. Immutable after creation.
- **`.baluard` marker**: JSON at vault root (`{ version, vault_id, slug }`). Tracked in git. Machine-readable detection mechanism.
- **Local layout**: `<data_dir>/vaults/<slug>/` for managed vaults. Imported vaults stay at original path. Registry stores absolute paths.
- **Registry**: `<data_dir>/registry.json`. Atomic writes (temp + rename). Cross-process locking via `fd-lock`.
- **Provider trait**: `ForgeProvider` with native `async fn` methods. Two-phase device flow (`start` + `poll`) for GitHub/GitLab. Web-OAuth (`oauth_start` + `oauth_exchange`, PKCE) for Codeberg. `ProviderToken` wraps `access_token` + `refresh_token` as `SecretString` with `expires_at`.
- **Keyring**: `baluard-<provider>-<username>`. `providers.json` stores non-sensitive lookup state (username, scopes, connected_at, instance_url, client_id).
- **Auth strategy**: GitHub gets device flow (octocrab). GitLab gets device flow (reqwest; public client, no `client_secret` — supported since GitLab 17.9). Codeberg gets web-OAuth (auth-code + PKCE, reqwest; Forgejo has no device flow). PAT is an Advanced Options fallback for all three. No `client_secret` in codebase.
- **ProviderConfig**: `{ client_id, instance_url }` (both `Option`, None = public default). Enables self-hosted instances + user-owned OAuth apps. Persisted on `ProviderInfo` in `providers.json`.
- **Credential transport**: git2-rs `RemoteCallbacks::credentials()` callback. No external credential helper binary.
- **CLI cross-vault**: `--vault <slug>` on non-active vault uses `--direct` mode. Daemon serves only the active vault.
- **OAuth scopes**: GitHub `repo`, GitLab `read_repository` + `write_repository`, Codeberg `repository`.

---

## Phase 1: Slug + Marker + Registry Foundation

**User stories**: 1, 2, 3, 4, 5, 22, 23, 24, 25, 27, 28

### What to build

Replace the `subtitle` field with a `slug` field in `VaultSettings` and the creation wizard. Add slug generation (normalize input, suggest `baluard-` prefix, user can edit/remove). Write `.baluard` marker JSON at vault root on creation. Create vault registry module with atomic writes and `fd-lock` cross-process locking. Implement `vaults_dir()` in paths. Update `VaultState` to read `active_vault` from registry on startup. Add CLI commands: `vaults list`, `--vault <slug>`. Update vault creation to place new vaults under `<data_dir>/vaults/<slug>/`. No provider integration yet. Purely local multi-vault foundation.

### Acceptance criteria

- [x] Slug generation normalizes any input string to `^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$`, suggests `baluard-` prefix
- [x] Slug stored in `VaultSettings`, replaces `subtitle` in creation wizard
- [x] `.baluard` marker written at vault creation with `{ version: 1, vault_id, slug }`
- [x] Vault registry module: create, read, update, delete vault entries
- [x] Registry writes are atomic (temp + rename)
- [x] Registry uses `fd-lock` for cross-process safety
- [x] `vaults_dir()` returns `<data_dir>/vaults/` platform-correctly
- [x] New vaults created under `vaults_dir().join(slug)`
- [ ] Daemon reads `active_vault` from registry on startup
- [x] `baluard vaults list` prints registered vaults
- [x] `baluard --vault <slug>` targets a specific vault (uses `--direct` if not active)
- [x] Slug collision detected and surfaced with clear error before creation
- [x] Property-based test: any string input produces valid slug
- [x] Registry survives crash (atomic write verification test)

---

## Phase 2: Provider Trait + GitHub Auth

**User stories**: 6, 8, 9, 10, 11, 12

### What to build

Define the `ForgeProvider` trait with `async fn` methods. Implement `DeviceFlowSession`, `DeviceFlowStatus`, `ProviderToken` (with `SecretString`, `refresh_token`, `expires_at`, zeroize on drop). Build GitHub provider using `octocrab` with device flow. Implement keyring storage for provider tokens (`baluard-<provider>-<username>`). Create `providers.json` schema and read/write module. Add daemon routes: `provider.list`, `provider.connect_start`, `provider.connect_poll`, `provider.connect_pat`, `provider.status`. Only GitHub. Auth only. No repo operations.

### Acceptance criteria

- [x] `ForgeProvider` trait defined with two-phase device flow (`start` + `poll`) and PAT auth
- [x] `ProviderToken` wraps `SecretString`, includes `refresh_token` + `expires_at`, implements `Zeroize`
- [x] GitHub device flow works end-to-end: `connect_start` returns code+URL, `connect_poll` returns pending/success/expired/slow_down
- [x] Token stored in OS keyring on successful auth
- [x] `providers.json` written with non-sensitive state (username, scopes, connected_at, version)
- [x] `provider.list` returns GitHub as connected with username, others as available (uniform shape)
- [x] `provider.connect_pat` validates token against GitHub API before storing
- [x] `provider.status` validates stored token is still valid
- [x] Mock provider trait implementation for unit tests
- [x] Headless fallback: clear error when keyring unavailable, suggesting `--direct` with PAT

---

## Phase 3: GitHub Repo Operations + First Sync

**User stories**: 13, 14, 15, 16, 26

### What to build

Implement GitHub `list_repos`, `create_private_repo`, `detect_vault_repos` (search API: `filename:.baluard+user:USERNAME`), `get_clone_url`. Add git2-rs `RemoteCallbacks::credentials()` callback that reads token from keyring. Add daemon routes: `provider.repos`, `provider.vault_repos`, `provider.create_repo`, `vault.setup_sync`. Implement repo creation with private visibility verification. Wire "Enable sync" toggle in vault creation wizard: on toggle, show provider picker, auth flow, repo name field (defaults to slug), create + first push. Token refresh for provider token (no-op for GitHub, but plumbing exists).

### Acceptance criteria

- [x] `provider.repos` lists user's GitHub repos with pagination
- [x] `provider.vault_repos` returns only repos containing `.baluard` marker (search API)
- [x] `provider.create_repo` creates private repo, verifies `private: true` on response
- [x] If repo is public after creation, delete it and return error (never push to public)
- [x] `vault.setup_sync` connects active vault to provider repo, sets git remote, performs first push
- [x] git2-rs credential callback reads token from keyring, no external binary
- [ ] "Enable sync" toggle in wizard: off by default, on triggers provider selection + auth + repo creation + first push
- [x] Repo name defaults to vault slug, user can edit
- [x] Provider credentials shared across vaults (one GitHub auth)
- [x] Token refresh plumbing exists (no-op for GitHub, ready for GitLab)

### Review notes

All BLOCKERs resolved: token-gated routes, spawn_blocking for git ops, credentials already gitignored.

Deferred to later phases:
- **W2**: `CredentialConfig.https_token` as `SecretString` (token handed to git2 as `&str`, minimal gain)
- **W3**: `ProviderToken.refresh_token` field as `SecretString` (zeroize-on-drop already protects it)
- **W9**: TOCTOU on registry load/save (single-process daemon, small window)
- **N2**: Extract provider+token loading boilerplate into helper (revisit when Phase 5 adds providers)
- **N4**: GitHub code search does not index private repos (need list+fetch fallback in Phase 4)

---

## Phase 4: Remote Vault Clone + Three-Screen Wizard

**User stories**: 7, 17, 18, 19, 20, 21

### What to build

Redesign desktop wizard first screen: three buttons (new vault, open local vault, download from provider). Build "Download from provider" flow: pick provider -> authenticate if needed -> show detected vault repos (filtered by `.baluard` marker) -> user selects one -> clone with progress events -> prompt for master password -> unlock. Implement three-tier vault detection (search API, list+fetch fallback, manual). Add `vault.clone_remote` daemon route with git2-rs `transfer_progress()` streaming progress. Implement `provider.disconnect` with token revocation attempt. Add 2FA warning banner on provider selection.

### Acceptance criteria

- [ ] Desktop wizard shows three options: new vault, open local vault, download from provider
- [ ] "Open local vault" opens file picker, imports into registry at original path
- [ ] "Download from provider" shows provider picker -> auth -> vault repo list -> clone -> unlock
- [ ] Remote vault list filters by `.baluard` marker (search API on GitHub, fallback on others)
- [ ] Clone shows progress (bytes/objects) streamed to desktop, percentage in CLI
- [ ] Cloned vault registered in registry with provider info
- [ ] `provider.disconnect` revokes token at provider (non-blocking on failure), clears keyring + providers.json
- [ ] 2FA warning banner shown on provider selection, dismissible, shown once per provider
- [ ] Full adversarial test: expired token, orphaned repo cleanup, keyring failure, device flow expiry

---

## Phase 5: GitLab + Codeberg Providers

**Status**: Implemented (2026-06-15). Peer-reviewed by peer review: 2 blockers + 7 high + 6 medium + 6 low findings, all addressed.

### What was built

**GitLab** (`crates/baluard-core/src/providers/gitlab.rs`): device flow (RFC 8628) as the PRIMARY auth method (GitLab supports it since 17.9). OAuth tokens expire 2h with a refresh_token; daemon auto-refreshes via `ensure_valid_token()` before any op + before `sync.push`/`sync.pull`. PAT fallback (detected by `glpat-` prefix, sent as `PRIVATE-TOKEN`). Requires the `api` scope (broader scopes are insufficient for `POST /projects`).

**Codeberg** (`crates/baluard-core/src/providers/codeberg.rs`): web-OAuth (auth-code + PKCE) as the primary flow. Forgejo has NO device flow, so the daemon runs a localhost `TcpListener` for the OAuth callback (`OAUTH_SESSIONS` keyed by provider, JoinHandle abort on restart). Forgejo OAuth tokens have no scope support (full account access) — the scoped PAT (`write:repository`) is documented as the more secure fallback, surfaced via Advanced Options.

Both providers use **raw reqwest** (not the `gitlab`/`forgejo-api` crates the original plan named) — PAT-only REST is trivial with zero new deps. Same git2-rs credential callback works for all three.

### Design decisions (diverged from original plan text)
- Device flow for GitLab (not PAT-only as the plan said) — user-friendly automatic flow.
- Web-OAuth PKCE for Codeberg (not PAT-only) — only browser-based option (no device flow).
- PAT moved into Advanced Options for ALL providers (power-user escape hatch); automatic flows are primary.
- `ProviderConfig { client_id, instance_url }` enables self-hosted instances + user-owned OAuth apps.
- One active instance per provider in v1 (switching = disconnect + reconnect).

### Acceptance criteria

- [x] `GitLabProvider` implements full `ForgeProvider` trait (device flow + PAT + repo ops + 2h refresh)
- [x] `CodebergProvider` implements full `ForgeProvider` trait (web-OAuth + PAT + repo ops)
- [x] GitLab token validated against `/api/v4/user` before storing
- [x] GitLab token refresh: daemon auto-refreshes expiring tokens, stores updated token (per-provider mutex, double-checked locking)
- [x] GitLab refresh failure: clear credentials, surface re-auth prompt (desktop State D)
- [x] Provider selection shows all three providers with auth method (device-flow / web-oauth / PAT label)
- [x] PAT input under Advanced Options includes scope hint (write:repository for Codeberg)
- [x] `provider.vault_repos` works for GitLab and Codeberg (list+fetch `.baluard`, concurrent per page via JoinSet)
- [ ] `vault.clone_remote` works with GitLab and Codeberg repos (Phase 4, not yet implemented)
- [x] Same git2-rs credential callback works for all three providers (token as password, username from URL)

### Known limitations
- `provider.oauth_start_web`/`oauth_status_web` are desktop-only routes; CLI does not yet drive the Codeberg web-OAuth flow.
- Codeberg OAuth2 redirect URI with dynamic loopback port needs live verification before release (TODO(H1) in `handler.rs`, tracked in `docs/git-provider-apps-and-tokens.md` §9.6).
- Default GitLab/Codeberg client_ids are placeholders until project OAuth apps are registered.

---

## Phase 6: Vault Switching + CLI Polish

**User stories**: 23, 24

### What to build

Implement `vaults.switch` daemon route: lock current vault (zeroize Root Key, SGK, Item Keys, session token), load target vault, generate new session token. Add `baluard vaults switch <slug>` CLI command. Verify `--vault <slug>` correctly routes to `--direct` mode for non-active vaults. Add vault switch integration tests verifying complete key material zeroization. Polish CLI output for `vaults list` (table format with provider status, last opened). Add `vaults.set_active` route to persist default vault choice. Handle edge cases: switch during in-flight request (error response), switch to locked vault (prompts for unlock), switch to unregistered slug (clear error).

### Acceptance criteria

- [ ] `vaults.switch` zeroizes all key material from current vault before loading new
- [ ] Session token changes on switch
- [ ] In-flight requests receive error response during switch
- [ ] Switch to locked vault prompts for master password
- [ ] Switch to unregistered slug returns clear error
- [ ] `baluard vaults switch <slug>` changes active vault
- [ ] `baluard --vault <slug>` on non-active vault uses `--direct` mode
- [ ] `baluard vaults list` shows table: slug, display name, provider, last opened
- [ ] Integration test: verify key material zeroization on switch (memory inspection or state assertion)
- [ ] Integration test: registry concurrent access (CLI + daemon writing simultaneously)
