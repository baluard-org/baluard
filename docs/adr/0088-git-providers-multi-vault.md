# ADR 0088. Git Providers and Multi-Vault Foundation

> Status: Accepted. Implemented in six phases: slug, marker and registry; provider trait and GitHub authentication; GitHub repository operations and first sync; remote clone; GitLab and Codeberg; vault switching. Phase 5 landed 2026-06-15 and Phase 6 on 2026-06-17. One acceptance item remains open from the plan (see Consequences).

## Context

Baluard stores synchronized vaults in user-owned Git repositories. Users need local vault registration, remote discovery, provider authentication, cloning, and explicit selection when more than one vault is open. The application must keep provider credentials outside vault data and must not expose secrets through logs or external credential helpers.

Repository names and slugs are convenient labels, not proof that a repository contains a Baluard vault. Discovery must inspect a versioned marker so unrelated repositories never appear in the vault picker.

Provider capabilities differ. GitHub classic scopes are broad, GitLab tokens expire after two hours, and Forgejo has no device authorization flow or OAuth scope support. The interface must state these differences instead of presenting one misleading security model.

A single-vault daemon also defeats a core product goal: a user with two or more connected vaults should switch between them instantly, and a vault that was unlocked should stay unlocked according to its own auto-lock setting. The first Phase 6 design locked and zeroized the current vault on every switch. It was rejected for that reason and replaced by the keep-unlocked, switch-pointer model recorded below. The runtime record of that model is ADR 0022; this ADR remains the full design reference for it.

## Decision

### Slug, marker and registry

Every vault has an immutable lowercase slug matching `^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$` (4 to 63 characters). The slug replaced the former `subtitle` field in `VaultSettings` and in the creation wizard. Entry points (CLI `init`, `vault.create`, clone, `vault.setup_sync`, `provider.create_repo`) run `slug::normalize_slug()`, which prepends the `baluard-` prefix rather than rejecting an unprefixed name: the user types "personal" and both the slug and the remote repository become "baluard-personal". `validate_slug` stays a shape check applied after normalization. A property-based test asserts that any input string normalizes to a valid slug.

The `.baluard` marker at the repository root contains `{ version, vault_id, slug }` and is tracked in git. The marker identifies the vault and is the machine-readable detection mechanism. Repository names are recognition aids, never identity, and `vault_id` stays stable across rename or repository changes. A slug collision is reported before the vault is created. Managed vaults live under `<data_dir>/vaults/<slug>/` (`vaults_dir()` in `paths.rs`); imported vaults retain their original path and the registry stores absolute paths.

The local registry is `<data_dir>/registry.json`. Writes use a temporary file plus atomic rename, so a crash never exposes a partial registry, and `fd-lock` serializes updates from the daemon and CLI. A crash-survival test and a concurrent daemon-plus-CLI access test cover both properties. The registry records the persisted default (`active_vault`) and per-vault `last_opened`. At startup the active vault resolves in this order: `--vault-slug`, `--vault-path`, registry `active_vault`, fallback path.

### Provider abstraction and credentials

`ForgeProvider` uses native `async fn` methods. It exposes a two-phase device flow (`start` and `poll`) for GitHub and GitLab, a web-OAuth pair (`oauth_start` and `oauth_exchange`, PKCE) for Codeberg, PAT authentication, repository operations, and token validation. `ProviderToken` carries `access_token` and `refresh_token` as `SecretString` with `expires_at` and zeroization on drop. A mock implementation of the trait backs the unit tests.

Tokens are stored in the OS keyring under `baluard-<provider>-<username>`. `providers.json` stores only non-sensitive lookup data (username, scopes, connection time, instance URL, client ID, version). If the keyring is unavailable the operation fails with a clear error and never persists a token in the vault or provider metadata. Tokens reach git2 through `RemoteCallbacks::credentials()` with the token as password and the username taken from the URL; no external credential helper binary is invoked, and one callback serves all three providers.

### Authentication per provider

| Provider | Primary flow | Fallback | Notes |
|----------|--------------|----------|-------|
| GitHub | Device flow via octocrab | PAT (validated against the API before storing) | Scope `repo`. |
| GitLab | RFC 8628 device flow via reqwest, public client, GitLab 17.9 or later | PAT (`glpat-` prefix, sent as `PRIVATE-TOKEN`), validated against `/api/v4/user` | Scopes `read_repository` and `write_repository` for OAuth. The PAT needs `api`, because narrower scopes cannot `POST /projects`. OAuth tokens expire after two hours and carry a refresh token. |
| Codeberg | Authorization-code OAuth with PKCE and a localhost `TcpListener` callback | Scoped PAT with `write:repository` | Forgejo has no device flow. Forgejo OAuth tokens have no scope support, so the scoped PAT is the least-privilege option. Scope string `repository`. |

PAT entry sits under Advanced Options for all providers, with a scope hint (for example `write:repository` for Codeberg). The automatic flows are primary. No `client_secret` is stored or shipped. GitLab and Codeberg use raw `reqwest` instead of the `gitlab` and `forgejo-api` crates the original plan named, because the REST surface is small and the choice adds no dependencies. Device flow for GitLab and web-OAuth for Codeberg replaced the plan's PAT-only design for a friendlier default.

`ProviderConfig` is `{ client_id, instance_url }`, both optional (`None` means the public default), persisted on `ProviderInfo` in `providers.json`. It supports self-hosted instances and user-owned OAuth apps. One active instance per provider is supported; switching instances requires disconnect and reconnect.

Provider token refresh runs before any provider operation and before sync push or pull (`ensure_valid_token()`). GitLab refresh is rolling: it invalidates the prior access and refresh pair, so concurrent refreshes are serialized by a per-provider mutex with a second validity check after the lock is acquired. A failed refresh clears credentials and surfaces a reauthentication prompt. Codeberg's `OAUTH_SESSIONS` map is keyed by provider, and restarting a flow for the same provider aborts the previous callback listener task so the port is freed. GitHub refresh is a no-op, kept as plumbing.

`provider.disconnect` attempts token revocation at the provider (failure does not block), then clears the keyring entry and `providers.json`. Provider credentials are shared across vaults for the same provider account.

Daemon provider routes: `provider.list` (uniform shape: connected with username, others available), `provider.connect_start`, `provider.connect_poll` (pending, success, expired, slow_down), `provider.connect_pat`, `provider.status`, `provider.repos`, `provider.vault_repos`, `provider.create_repo`, `provider.disconnect`, and the desktop-only `provider.oauth_start_web` and `provider.oauth_status_web`. Provider and token-gated routes run git and network work through `spawn_blocking`, never on async executor threads. `provider.repos` and `provider.vault_repos` are not token-gated because they run before unlock and are safe against sentinel tokens. Sync setup is `vault.setup_sync`, which sets the git remote and performs the first push.

### Discovery and repository creation

Vault repository discovery is marker-based. GitHub lists owned repositories (`affiliation=owner`) with pagination, probes `.baluard` concurrently per page, and caps the scan at 20 pages. It then adds a supplementary, deduplicated pass through code search (`filename:.baluard user:<login>`). Code search is secondary because it lags for fresh repositories, indexes only default branches, and does not see private repositories. This primary-list-plus-supplement design replaced an earlier search-first design after that limitation was confirmed. GitLab and Codeberg paginate and probe the marker concurrently per page (`JoinSet`); Codeberg is scoped to owned repositories. An earlier three-tier plan (search, list-and-fetch, manual) was superseded by this arrangement.

Private repository creation verifies `private: true` on the response. A repository found public after creation is deleted and the operation fails before any push, so vault data never reaches a public repository.

### Clone flow

Clone uses the host-level routes `vault.clone_start`, `vault.clone_progress`, and `vault.clone_finalize`. They run before unlock, are not token-gated because no session token exists yet, and are limited to repository selection and the clone lifecycle. `SyncEngine::clone_remote` streams git2 `transfer_progress` to a live `CloneProgress` (objects and bytes on desktop, percentage on CLI). Failed clones remove the incomplete directory. The cloned vault is registered with its provider information. `vaults.register_local` imports an existing path without copying it. The CLI entry is `baluard sync clone <provider> <repo>` (daemon only). Desktop uses a welcome screen with three actions (new vault, open local vault, download from provider) and a clone screen that runs provider pick, authentication, marker-filtered repository list, clone with progress, and master-password unlock. A dismissible two-factor warning banner appears once per provider at selection.

### Multi-vault host

`VaultHost` wraps one `RwLock<VaultHostInner>` holding `vaults: HashMap<String, Arc<VaultState>>` and `active: Option<String>`. Invariant: if `active` is `Some(slug)`, the slug exists in the map. A single lock makes slug validation and the `active` write one critical section, so a concurrent `vaults.close` and `vaults.switch` can never leave `active` dangling. An earlier draft used two locks and allowed exactly that interleaving. Each `VaultState` is independent: its own handle, session token, `last_activity`, cover timer, and auto-lock countdown.

Vaults load lazily. The map starts with at most the resolved initial vault, opened on first unlock, and fills as the user switches and unlocks.

| Route | Behavior |
|-------|----------|
| `vaults.list` | Every registered vault with a state of `unlocked`, `locked`, or `closed` (not in the map). Drives the switcher. |
| `vaults.switch` | Pointer flip only. Validates the slug, sets `active`, then updates registry `last_opened` outside the lock so registry I/O never serializes map operations; losing `last_opened` in a crash is acceptable. No zeroization, no token change. Returns `{ active, state }`. An unregistered slug is a clear error. |
| `vaults.set_active` | Persists the default vault for the next launch. Distinct from `switch`, the live focus change. |
| `vaults.active` | Current active slug and state. |
| `vaults.close` | Removes the map entry and clears `active` in the same critical section if it pointed there. Returns immediately. |
| `vaults.lock_all` | Locks every unlocked vault. |
| `vault.unlock`, `vault.lock` | Take an explicit `slug`. Unlock returns `{ slug, token }`. |

Switching to a locked or never-opened vault does not block: the route returns `locked: true` with the slug, the vault is added to the map in locked state, and the unlock targets that slug. Every cipher, sync, settings, and batch route takes an explicit `slug` or falls back to `active`.

Target resolution happens once per request. The handler snapshots the target `Arc<VaultState>` at entry and uses it for the whole request, so a mid-request switch cannot re-route an operation, and an implicit-active request stays pinned to the entry-time active vault. Mutating callers should send an explicit slug. A switch never invalidates in-flight requests because it touches no vault state.

`vaults.close` uses Arc-drain. It does not track an in-flight counter and never returns a busy error. In-flight handlers keep their cloned `Arc` and zeroize on the last drop; new requests for the slug fail at map lookup. `Arc::strong_count` is not used as a synchronization primitive because it is unreliable under concurrent cloning. A later `vault.unlock` of the same slug inserts a fresh, independent `VaultState`. Because an old handler could otherwise write through a handle the map no longer knows, a close observed mid-operation is terminal for that operation and callers must not retry it against the re-opened vault.

Auto-lock is per vault. A single walker visits the map every 30 seconds and applies each vault's own `auto_lock_minutes` against its `last_activity`. A vault that auto-locks stays in the map as `locked` with keys zeroized and can be unlocked again without reopening from disk. When the active vault auto-locks, `active` is left pointing at it, so the next implicit request returns `locked: true` and the desktop shows the re-unlock screen for the same vault. Only `vaults.close` on the active vault sets `active` to `None`, after which the desktop falls back to the vault picker. Cover-commit timers are per `VaultState`, started on unlock and cancelled on lock, never keyed to `active`; N unlocked vaults run N cover timers, and a switch touches none. Gating a cover commit on "am I active" would be a privacy bug.

Session tokens are per vault. A request must carry the token of its targeted vault, verified in constant time against that vault only, and a vault-A token is rejected for a vault-B operation. The desktop keeps a `Map<slug, token>` and attaches the matching token to every request. The daemon pushes no events. The desktop polls `vaults.list` on every switch and on a 30-second heartbeat, and drops a slug's token when its state becomes `locked` or `closed`. A rejected token triggers an immediate state refresh; this is the correctness backstop, not the primary mechanism. The desktop must refetch `vault.list_full` for the new active vault on every switch and must not reuse a cached list across a switch.

CLI behavior: `baluard vaults list` shows slug, display name, provider, state, and last opened. `baluard vaults switch <slug>` flips the active vault and prompts for the master password if the target is locked or closed. `baluard vaults close <slug>` unloads one vault. `baluard --vault <slug>` is served by the daemon when that vault is open in the map (the slug travels on each request), and uses `--direct` only for a vault the daemon has never opened or when no daemon runs. This softens an earlier rule that every non-active vault used `--direct`, and keeps single-shot scripting fast. Sync operations are per vault in the same way.

### Security model of keep-unlocked

Keeping N vaults unlocked holds up to N Root Keys, Space Group Keys, and active Item Keys in daemon memory at once, for as long as each stays inside its own auto-lock window. This is a deliberate trade of exposure for switching speed, recorded as T15 in `docs/security/threat-model.md`. Existing controls are unchanged: key material is `mlock`ed and zeroized on drop, the socket is `0600` with peer-credential checks, and tokens are per vault. Multi-vault widens the amount of resident material, not per-key protection. Mitigations: each vault expires on its own idle timer; the default `auto_lock_minutes` should not be raised for multi-vault setups; the desktop locks every vault when the window loses focus (Tauri `WindowEvent::Focused(false)` calls `vaults.lock_all`, the frontend clears its token cache and refreshes on focus regain); and `VaultHost::log_mlock_budget` logs resident key bytes (96 bytes per vault for the Root Key and SGK, plus Item Keys) against `RLIMIT_MEMLOCK` after every unlock, with a warning at twice the budget on Unix. Older Linux defaults of 64 KB can be approached with many vaults; `mlock` failure stays best-effort (logged, not fatal). Showing the unlocked-vault count and timers in settings is recommended so the exposure is legible.

## Consequences

Users share provider credentials across vaults and switch between open vaults without repeating key derivation. The marker supports safe discovery without treating a repository name as proof of identity.

All unlocked vaults remain resident simultaneously. A switch is a pointer change, not a cryptographic lock operation, so it provides no memory-isolation boundary. Memory exposure under a compromised process or OS account grows with the number of open vaults.

OS suspend, screen-lock, and lid-close hooks do not yet lock all vaults; only the window-focus trigger is wired. The platform hooks are macOS `NSWorkspace` sleep notifications, Linux login1 `PrepareForSleep` over D-Bus, and Windows `WM_POWERBROADCAST` and session-switch messages, documented as follow-up in `desktop/src-tauri/src/lib.rs`.

GitHub `repo` scope grants access to all repositories on the account, broader than a single vault repository. GitLab needs `api` for repository creation. Codeberg OAuth tokens have full account access. These limits must be stated at connection time, and the desktop shows a dedicated Codeberg full-access warning. Users with stricter needs must use a separately registered app or a narrower credential where the provider supports one.

GitHub owned-repository detection is bounded by the 20-page cap and by code-search limits, so a fresh or unlisted repository can require a manual refresh or another discovery path.

Known limitations and open items:

- The CLI cannot drive the Codeberg web-OAuth flow; the web routes are desktop-only.
- The Codeberg redirect URI with a dynamic loopback port needs live verification before release (see `docs/dev/git-provider-apps-and-tokens.md`).
- The default GitLab and Codeberg client IDs are placeholders (`REPLACE_WITH_GITLAB_CLIENT_ID`, `REPLACE_WITH_CODEBERG_CLIENT_ID`) until project OAuth applications are registered; users can override them in Advanced Options.
- The adversarial test matrix (expired token, keyring failure, device-flow expiry) was only partly built; orphan-directory cleanup is covered.
- Review findings deferred at Phase 3: hold `CredentialConfig.https_token` and `ProviderToken.refresh_token` as `SecretString` end to end (token reaches git2 as `&str`, zeroize-on-drop already covers the field), a registry load-then-save race (single-process daemon, small window), and extracting the provider-and-token loading boilerplate into one helper.
- The plan left the creation-wizard "Enable sync" criterion unchecked. The post-creation setup screen (`desktop/src/components/SetupScreen.jsx`) now drives provider connection, `provider.create_repo`, and `vault.setup_sync`; the criterion text predates it and the code is authoritative.
- The registry is device-local and stores absolute paths, so moving a vault directory leaves a stale entry until the user registers it again.
- Self-hosted instances use `ProviderConfig`, but one instance per provider is active at a time.

## References

- `docs/adr/0022-phase-6-multi-vault-switching.md`
- `docs/adr/0006-desktop-auto-sync.md`
- `docs/adr/0085-sharing.md`
- `docs/dev/git-provider-apps-and-tokens.md`
- `docs/security/threat-model.md` (T6, T15)
- `crates/baluard-core/src/providers/`
- `crates/baluard-core/src/paths.rs`
- `crates/baluard-core/src/sync/engine.rs`
- `crates/baluard-runtime/src/host.rs`
- `crates/baluard-daemon/src/handler.rs`
- `crates/baluard-daemon/tests/phase6_switching.rs`
