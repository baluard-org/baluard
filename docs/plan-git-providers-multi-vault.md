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
- **CLI cross-vault**: `--vault <slug>` targets a specific vault. Under the Phase 6 keep-unlocked model the daemon holds every opened vault in a map, so a non-active-but-open vault is served by the daemon directly (slug passed per request); `--direct` mode is only the fallback for a vault the daemon has never opened, or when the daemon is not running. See Phase 6.
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

> **Design revision (2026-06-17):** Phase 6 was reworked from a *lock-on-switch*
> model to a *keep-unlocked / switch-pointer* model. The previous design locked
> (zeroized) the current vault whenever the user switched. That defeats the
> product goal: users with two or more connected vaults should be able to jump
> between them instantly, and a vault they unlock stays unlocked according to
> **its own** auto-lock setting until it times out. The daemon therefore holds
> every opened vault in memory at once and a "switch" is just changing which
> one is active. See the security note below for the tradeoff.

### Product behaviour

- A user connects **two or more vaults** to the same app instance.
- Switching between them is **instant**: no KDF re-derivation, no re-prompt.
- An unlocked vault **remains unlocked** when the user switches away from it.
- Each unlocked vault auto-locks independently on **its own** `auto_lock_minutes`
  schedule (idle-based, same rule as today, evaluated per vault).
- Manually locking a vault (explicit `lock`) only affects that vault; **app quit
  locks all** open vaults.
- **Batch reads target a specific vault.** `vault.list_full` (and every batch
  read) takes the explicit `slug` (or falls back to `active`). A switch event in
  the desktop triggers a fresh `vault.list_full` for the new active vault — the
  desktop must not reuse a cached list across a switch, or it will show the old
  vault's entries.

### Daemon architecture change: vault map

Today the daemon binds to a single `SharedVaultState` resolved at startup
(`crates/baluard-daemon/src/main.rs`, `run()` constructs one `VaultState`). This
phase replaces that single state with a **vault map**:

```text
struct VaultHost {
    /// Single lock guards BOTH the map and the active pointer together.
    /// Holding one write lock makes slug-validation + `active` updates atomic,
    /// so `active` can never point at a vault that was just removed by
    /// `vaults.close`. (Earlier draft had two separate locks — that allowed
    /// close+switch to interleave and leave `active` dangling.)
    inner: RwLock<VaultHostInner>,
}

struct VaultHostInner {
    /// All vaults the daemon has opened, keyed by slug.
    /// Each Arc<VaultState> is independent: own handle, own session token,
    /// own last_activity, own cover timer, own auto-lock countdown.
    vaults: HashMap<String, Arc<VaultState>>,
    /// The slug currently "focused" by the desktop/CLI. Switching only
    /// mutates this; it never touches any vault's key material. Invariant:
    /// if `Some(slug)`, that slug MUST exist in `vaults`. The single lock
    /// above is what makes this invariant provable.
    active: Option<String>,
}
```

Consequences:

- **Lazy load.** A vault is inserted into the map on first open/unlock, not at
  daemon startup. Startup still needs an initial `active` slug (resolved via the
  existing `resolve_active_vault` priority: `--vault-slug` > `--vault-path` >
  registry `active_vault` > fallback). The resolved vault is opened lazily; the
  rest of the map starts empty and fills as the user switches/unlocks.
- **`vaults.switch`** becomes a pointer flip. Under the single `VaultHostInner`
  write lock it: (1) validates the target slug is present in the map (adding it
  first if this is a switch to a not-yet-opened vault — see "locked / never-opened"
  below); (2) sets `active = Some(slug)`; (3) releases the lock. Only then,
  **outside** the lock, does it touch the registry's `last_opened` for that slug.
  Keeping the registry I/O (atomic rename) out of the critical section prevents
  every switch from serializing all vault-map operations behind a filesystem
  write; `last_opened` is best-effort metadata and need not be atomic with the
  in-memory flip (losing it on a crash is acceptable). It does **not** zeroize
  the previously-active vault and does **not** generate a new session token for
  the target — the target keeps the session token it already had (or is still
  locked, see below). Because validation and the `active` write share one
  critical section, no concurrent `vaults.close` can leave `active` pointing at
  a removed vault.
- **Re-open after close.** After `vaults.close("A")` an in-flight handler may
  still hold `Arc<VaultState_A>`. A subsequent `vault.unlock "A"` inserts a
  **fresh, independent** `VaultState_A'` into the map; the old Arc draining and
  zeroizing does not touch it. A mutating op that completes via the old Arc
  *after* the re-unlock would therefore write through a handle the map no longer
  knows about. Callers MUST NOT retry an operation after observing a close for
  its slug — a close observed mid-op is a terminal result for that op, not a
  transient error to retry against the re-opened vault.
- **Switch to a locked / never-opened vault** does **not** block on the daemon
  side. The route returns a `locked: true` flag (and the slug). The desktop
  shows the unlock screen for that vault; the unlock IPC targets the specific
  slug. The CLI prompts for the master password. The vault is added to the map
  (locked) on switch so its state is tracked, then unlocked in place.
- **Removal (`vaults.close`).** Removing a vault from the map drops the daemon's
  strong reference; its key material is zeroized when the **last** `Arc<VaultState>`
  is dropped. In-flight handlers that already cloned the Arc finish normally and
  zeroize on their own last drop — so `close` returns success **immediately**
  and does NOT track an in-flight counter or block. The vault becomes logically
  closed (no new request can be routed to it from the map) the instant its map
  entry is removed. If the closed vault was `active`, `active` is cleared to
  `None` in the same critical section (see "active pointer on auto-lock / close"
  below for the desktop's resulting UX).

### New / changed daemon routes

| Route | Behaviour under keep-unlocked model |
|-------|--------------------------------------|
| `vaults.list` | Returns every registered vault with a per-vault `state`: `unlocked`, `locked`, or `closed` (not currently in the map). Drives the desktop vault switcher UI. |
| `vaults.switch` | **Pointer flip only.** Validates slug, sets `active`, touches `last_opened`. No zeroization, no token change. Returns `{ active, state }` so the caller knows whether to show the unlock screen. |
| `vaults.set_active` | Persists `active_vault` in the registry (default vault on next launch). Distinct from `switch`, which is the live focus change. |
| `vaults.active` | Returns the current `active` slug + state. |
| `vaults.close` | **New.** Removes a vault from the in-memory map (clears `active` if it was active, same lock). Returns immediately — in-flight handlers holding a cloned `Arc<VaultState>` drain to completion and zeroize on last drop. No busy/retry. |
| `vault.unlock` | Returns `{ slug, token }` so the desktop can file the per-vault session token (see "Desktop token contract"). Gains an explicit `slug` argument. |
| `vault.lock` | Gains an explicit `slug` argument so it targets a specific vault in the map instead of the implicit "current" one. |

Every cipher/sync/settings route that today implicitly targets the single
`VaultState` gains a `slug` (or reads the current `active`) so it addresses the
right entry in the map. The session token check (R7-2) becomes per-vault: a
request must carry the token matching the **targeted** vault.

### Auto-lock: per-vault, independent

`VaultState::spawn_auto_lock_checker` today watches one state. Under the new
model a **single** checker iterates the map every 30s and applies each vault's
own `auto_lock_minutes` + `last_activity`. The plumbing is already per-vault —
session token, `last_activity`, cover timer, and `auto_lock_minutes` all live on
`VaultState` — so each entry auto-locks itself with no shared state. A vault
that auto-locks stays in the map in the `locked` state (handle retained, keys
zeroized); it can be re-unlocked without re-opening from disk.

**Active pointer on auto-lock / close (explicit policy).** When the
*currently-active* vault auto-locks, the checker **leaves `active` pointing at
it** (still in the map, just `locked`). It does **not** clear `active`. Any
subsequent implicit-`active` request therefore resolves to a locked vault and
the handler returns `locked: true`; the desktop shows a re-unlock prompt for
that same vault (not the vault picker). This keeps the user's focus stable
across a timeout. `vaults.close` on the active vault is the one case that
**does** clear `active` to `None` (the vault is gone from the map), and there
the desktop falls back to the vault picker. Both behaviours are covered by
acceptance criteria below.

**Cover-commit timers are per-vault, not per-active.** Each `VaultState` starts
its cover timer on unlock and cancels it on lock, keyed to `locked`/`unlocked`
state — never to `active`. With N unlocked vaults, N cover timers run
concurrently and `vaults.switch` must NOT touch any of them. Cover commits
continue to mask activity for non-active unlocked vaults; any code path that
gates a cover commit on "am I active?" is a privacy bug.

### Desktop token contract (per-vault session tokens)

The session token check (R7-2) becomes **per-vault**: a request must carry the
token matching the **targeted** vault, and a token issued for vault A is
rejected for any vault-B operation (constant-time compare against the target
vault's token only). To support this the desktop keeps a `Map<slug, token>`:

- `vault.unlock` returns `{ slug, token }`; the desktop files the token under
  the slug.
- Every cipher/sync/settings request carries an explicit `slug` plus that
  slug's token. A request with no `slug` uses the current `active` slug and its
  token.
- Token eviction policy (resolved): the daemon does **not** push events; the
  desktop polls. It refreshes vault state via `vaults.list` on two triggers: (a)
  on every switch, and (b) on a 30s heartbeat while the app is open. When a
  vault's state transitions to `locked` or `closed`, the desktop drops that
  slug's token from its `Map<slug, token>`. **Fallback:** if the desktop ever
  sends a request whose token is rejected (e.g. the vault auto-locked between a
  poll and the request), the rejection is treated as a signal to refresh vault
  state immediately — the token-rejection path is the correctness backstop, not
  the primary mechanism. This keeps the contract unambiguous (no push channel to
  build) and guarantees the desktop never silently treats a locked vault as
  unlocked.

This is a frontend contract change from today's single `sessionToken` signal.

### In-flight requests and concurrency

- A switch never needs to invalidate in-flight requests, because it does not
  touch any vault's state — it only changes the `active` pointer. In-flight
  requests to the *previously-active* vault keep running against that vault.
- **Target resolution is mandatory and happens once per request.** The handler
  determines the target slug from the request's explicit `slug`, falling back
  to `active` only when `slug` is absent. It **snapshots the target
  `Arc<VaultState>` clone** at request start and operates on that clone for the
  whole request. This removes the TOCTOU where a mid-request `switch` would
  re-route an in-flight operation to a different vault, and means a request
  that omits `slug` is pinned to whatever `active` was at entry — it cannot
  wander. (Implicit-`active` requests are discouraged for mutating ops; the
  desktop always sends an explicit slug.)
- **`vaults.close` uses Arc-drain, not a busy error.** `close` takes the
  `VaultHostInner` write lock, removes the entry, clears `active` if needed,
  and returns success immediately. Handlers that already hold a cloned
  `Arc<VaultState>` drain to completion naturally and zeroize on last drop;
  there is no in-flight counter and no `busy`/retry. New requests for the
  closed slug are rejected at the map lookup. (`Arc::strong_count` is NOT used
  as a synchronization primitive — it is unreliable under concurrent cloning.)

### CLI

- `baluard vaults list` — table: slug, display name, provider, state
  (`unlocked`/`locked`/`closed`), last opened.
- `baluard vaults switch <slug>` — flips the live active vault via the daemon.
  If the target is locked/closed, the CLI prompts for the master password and
  runs `vault.unlock` against that slug.
- `baluard --vault <slug>` — **revisited.** Under the multi-vault daemon, a
  non-active slug that is already unlocked in the map can be served by the
  daemon directly (pass `slug` on each request). `--direct` mode is now only
  the fallback for: (a) a vault the daemon has never opened, or (b) daemon not
  running. This is a softening of the earlier "non-active always uses `--direct`"
  rule and keeps single-shot scripting fast while preserving instant switching.
- `baluard vaults close <slug>` — explicit lock-and-unload of one vault.

### Security note (see `docs/threat-model.md`, new T15)

Keeping N vaults unlocked means up to N Root Keys + their Item Keys are resident
in daemon memory simultaneously, for as long as each is within its auto-lock
window. This is a deliberate UX-for-exposure trade:

- **Bounded by per-vault auto-lock.** Each vault independently drops its key
  material on its own `auto_lock_minutes` idle timer. The user controls the
  exposure window per vault via settings.
- **Existing controls still apply.** All key material remains `mlock`'d +
  zeroized-on-drop (T6); the socket is `0600` with peer-credential checks and
  per-vault session tokens (T2/R7-2). Multi-vault does not weaken any of these;
  it widens the *amount* of resident material, not the per-key protection.
- **Recommended guidance.** Surface in settings the count of currently-unlocked
  vaults and their per-vault auto-lock timers, so the exposure is legible.
  Default `auto_lock_minutes` should not be raised for multi-vault setups.
- **Lock-all on system events.** Screen lock, system sleep / lid-close, and
  app-resign-active (Tauri window blur + OS suspend events) trigger an immediate
  lock of **every** currently-unlocked vault — not just the active one. This
  caps the multi-vault exposure the moment the device becomes unattended,
  instead of waiting for each vault's idle timer. (Explicit per-vault `lock` and
  app quit also lock all on quit.)
- **Aggregate `mlock` budget.** Each unlocked vault mlocks its Root Key (64 B),
  SGK (32 B), and active Item Keys (32 B each). With N vaults the total mlocked
  footprint scales with N and can approach `RLIMIT_MEMLOCK` on low-default
  systems (older Linux defaults are 64 KB). The daemon logs total mlocked bytes
  across all open vaults at unlock time; `mlock` failure remains best-effort
  (logged, not fatal) as in T6.

### Acceptance criteria

- [ ] Daemon holds a single `RwLock<VaultHostInner>` containing both the `HashMap<String, Arc<VaultState>>` and the `active` pointer (one critical section, no two-lock race)
- [ ] Invariant: if `active` is `Some(slug)`, that slug exists in the map (provably maintained by the single lock)
- [ ] `vaults.switch` validates slug + sets `active` under one write lock; no zeroization, no token change
- [ ] Previously-active vault remains unlocked after a switch (state assertion)
- [ ] Switching to an unlocked vault requires no master password (instant)
- [ ] Switching to a locked/closed vault returns `locked: true`; unlock targets that slug
- [ ] Each vault auto-locks independently on its own `auto_lock_minutes` schedule
- [ ] **Active-pointer-on-autolock policy:** when the active vault auto-locks, `active` is left pointing at it and implicit-active requests return `locked: true` (desktop shows re-unlock for the same vault)
- [ ] `vaults.close` on the active vault clears `active` to `None` (desktop falls back to vault picker)
- [ ] Cipher/settings/batch routes accept a `slug` (or fall back to `active`) and address the correct vault
- [ ] `vault.list_full` targets the named/active slug; desktop re-fetches it on every switch (no stale cross-vault list)
- [ ] Session token check is per-vault: request token must match the targeted vault; a vault-A token is rejected for a vault-B operation
- [ ] `vault.unlock` returns `{ slug, token }`; desktop maintains a `Map<slug, token>` and sends the matching token per request
- [ ] Handler snapshots the target `Arc<VaultState>` clone once per request (no TOCTOU; implicit-`active` request pinned to entry-time active)
- [ ] `vaults.close` returns success immediately (Arc-drain); in-flight handlers holding a cloned Arc complete and zeroize on last drop; new requests to the closed slug are rejected
- [ ] `Arc::strong_count` is NOT used as a synchronization primitive
- [ ] Cover-commit timers are per-`VaultState`, keyed to `locked`/`unlocked`, never to `active`; a switch does not touch any cover timer
- [ ] Lock-all fires on screen lock / system sleep / lid-close / app-resign-active (every unlocked vault locks, not just active)
- [ ] Daemon logs total mlocked bytes across all open vaults at unlock time
- [ ] Switch to unregistered slug returns a clear error
- [ ] `baluard vaults list` shows state column (unlocked/locked/closed) + last opened
- [ ] `baluard vaults switch <slug>` flips active vault; prompts for password if locked
- [ ] `baluard --vault <slug>` uses the daemon when the vault is open in the map, `--direct` otherwise
- [ ] `baluard vaults close <slug>` unloads one vault without affecting others
- [ ] Integration test: two vaults unlocked, switch A→B→A, both stay unlocked (no re-prompt)
- [ ] Integration test: per-vault auto-lock fires independently (one times out, the other stays unlocked)
- [ ] Integration test: active vault auto-locks → `active` still points at it → next implicit request returns `locked: true`
- [ ] Integration test: in-flight request to vault A is unaffected by a concurrent switch to B (request pinned to A)
- [ ] Integration test: `vaults.close` returns immediately while a long request to that vault is in flight; the in-flight request completes and the vault's keys zeroize after it finishes
- [ ] Integration test: concurrent `vaults.close("A")` + `vaults.switch("A")` never leaves `active` pointing at a missing entry (single-lock invariant)
- [ ] Integration test: cover commit still fires for a non-active unlocked vault after a switch
- [ ] Integration test: registry concurrent access (CLI + daemon writing simultaneously)
- [ ] `vaults.switch` writes the registry `last_opened` OUTSIDE the `VaultHostInner` write lock (no I/O in the critical section)
- [ ] Token-rejection on a request is the correctness backstop: desktop treats any token reject as a trigger to refresh vault state (polling is primary: on switch + 30s heartbeat)
- [ ] Re-open after close: `vault.unlock` of a closed slug creates a fresh independent `VaultState`; a close observed mid-op is terminal for that op (no retry against the re-opened vault)
