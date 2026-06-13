# Sync Settings Tab - Implementation Plan

**Date:** 2026-06-13
**Scope:** New "Sync" tab in SettingsModal for post-creation git provider configuration.
**Providers:** GitHub (device-flow), GitLab (PAT), Codeberg (PAT).
**Features:** Connect, disconnect, status display, existing remote detection, manual push/pull.
**Reviewed by:** peer review (2026-06-13)

---

## Phase 1: Daemon IPC Routes

### 1.1 New route: `sync.status_json`
**Problem:** Current `sync.status` returns a human-readable string (for CLI). Desktop needs structured JSON.

**New daemon route** returns:
```json
{
  "initialized": true,       // git repo exists
  "has_remote": true,        // origin remote configured
  "remote_url": "https://github.com/user/vault.git",
  "provider": "github",      // inferred from URL hostname or null
  "dirty": false,
  "ahead": 0,
  "behind": 0,
  "last_commit": {
    "id": "abc1234",
    "message": "cover commit",
    "time": 1718236800
  }
}
```

**File:** `crates/baluard-daemon/src/handler.rs`
- Add `sync.status_json` alongside existing `sync.status` (keep CLI compat).
- Infer provider from remote URL hostname (github.com / gitlab.com / codeberg.org).
- **Self-hosted limitation:** Only matches public instances. Self-hosted GitLab/Gitea returns `provider: null`. Document as unsupported for v1. Do NOT silently misclassify.

### 1.2 New route: `sync.disconnect`
Removes the `origin` remote from the local git repo. Does NOT delete the provider token or repo on the remote.

**Steps:**
1. Open repo, verify `origin` exists.
2. Remove `origin` remote via `git2`.
3. Clear `provider`/`remote_url`/`last_synced` in `VaultRegistry` for this slug.

**File:** `crates/baluard-daemon/src/handler.rs`
- Add `sync.disconnect` to the handler match.

### 1.3 Token-gating (CRITICAL)

Both new routes MUST be added to `TOKEN_REQUIRED_ACTIONS` set in `handler.rs`:
- `sync.status_json` exposes `remote_url` (same sensitivity as `sync.status`).
- `sync.disconnect` is a mutation (removes remote). Ungated = any same-UID process can disconnect.

### 1.4 Device signing bootstrap check

A standalone vault (never synced) may lack signing identity in the sync engine. Before first push via `vault.setup_sync`:
- Verify `meta/device-registry.json` has the current device enrolled with an Ed25519 signing key.
- Verify `meta/device-privkey.json` exists for this device.
- If missing: `vault.setup_sync` must bootstrap the signing identity before pushing (or the first push produces unsigned commits, breaking multi-device integrity).

**Investigate:** Does `vault.setup_sync` already handle this via `SyncEngine::new()` + the commit path? Read `engine.rs` cover commit logic to confirm. If it doesn't, add a step.

### 1.5 Repo creation visibility

`provider.create_repo` creates a **private** repository. Assert this in the daemon route (already the case in the existing code, but document it here). A public vault repo exposes encrypted blobs + padded-bucket metadata.

### 1.6 Guard: `vault.setup_sync` for existing vaults
The existing `vault.setup_sync` route already works for this case (it inits repo if needed, adds remote, pushes). No changes needed here. The desktop just needs to call it.

### 1.7 Existing route reuse
| Action | Route | Notes |
|--------|-------|-------|
| List providers + status | `provider.list` | Already exists, returns all 3 with connected state |
| Start GitHub device flow | `provider.connect_start` | Already exists |
| Poll device flow | `provider.connect_poll` | Already exists |
| PAT auth (GitLab/Codeberg) | `provider.connect_pat` | Already exists |
| Validate token | `provider.status` | Already exists |
| Disconnect provider token | `provider.disconnect` | Already exists (clears token only, **global** - affects all vaults) |
| Create remote repo (private) | `provider.create_repo` | Already exists |
| Init + remote + push | `vault.setup_sync` | Already exists |
| Manual push | `sync.push` | Already exists |
| Manual pull | `sync.pull` | Already exists |
| Structured status | `sync.status_json` | **NEW** |
| Disconnect remote | `sync.disconnect` | **NEW** |

---

## Phase 2: Desktop Sync Settings Tab

### 2.1 UI States

The tab has 4 top-level states based on sync status, each with sub-states:

**State A: Not Connected (no provider, no remote)**
- Show "Set up sync" CTA.
- 3 provider cards: GitHub, GitLab, Codeberg.
- Each card shows: provider icon/name, auth method label.
- Clicking a card starts the auth flow.

**Sub-states of A:**
- `A-idle`: Provider picker visible.
- `A-authenticating`: Device flow polling (GitHub) or PAT input (GitLab/Codeberg).
- `A-error`: Auth failed / device flow expired. Show error + "Try again".

**State B: Provider Connected, No Remote**
- Provider is authenticated (token in keyring) but no git remote configured.
- Show: "Connected as @username" badge.
- Show: "Create vault repository" CTA.
- Show: "Or select an existing repo" (lists repos from `provider.vault_repos`).

**Sub-states of B:**
- `B-create`: Repo name input + "Create Repository" button.
- `B-select`: List of existing repos from provider (via `provider.vault_repos`).
- `B-creating`: Spinner while `provider.create_repo` + `vault.setup_sync` run.
- `B-error`: Creation/setup failed. Show error + retry.

**State C: Sync Active (provider + remote)**
- Show: Provider badge + username + repo name.
- Show: Sync status (last commit, dirty/clean, ahead/behind).
- Show: Manual "Push" and "Pull" buttons.
- Show: "Disconnect" button (with confirmation modal).

**Sub-states of C:**
- `C-idle`: Normal display, actions enabled.
- `C-syncing`: Push or pull in progress. Buttons disabled. Show spinner.
- `C-error`: Sync failed. Distinguish between:
  - **Network/auth error:** "Push failed. Check connection."
  - **Merge conflict:** "Conflicting changes. Manual resolution required."
  - **Integrity failure:** "Signature verification failed. Remote may be tampered." **This is a security event** - show with red warning, do NOT offer retry without explicit user acknowledgment.

**State D: Remote Only (no provider auth)**
- Git remote exists but provider token is missing/expired.
- Show: Remote URL (read-only).
- Show: Warning: "Provider disconnected. Reconnect to sync."
- Show: "Reconnect" CTA (starts provider auth flow).
- Show: "Remove remote" CTA (calls `sync.disconnect`).

**Sub-states of D:**
- `D-reconnecting`: Provider auth in progress (device flow or PAT).
- `D-error`: Reconnect failed.

### 2.2 Component: `SyncTab` (new file)

**File:** `desktop/src/components/SyncTab.jsx`

Extracted from SettingsModal. Own signals for:
- `syncStatus` (from `sync.status_json`)
- `providerList` (from `provider.list`)
- `topState` (`A` | `B` | `C` | `D`)
- `subState` (`idle` | `authenticating` | `error` | `creating` | `syncing` | etc.)
- `authSession` (DeviceFlowSession for GitHub polling)
- `repoName` (for create repo input)
- `loading`, `error` signals

**Sub-components (inline, not separate files):**
- `ProviderPicker` - 3 provider cards for State A-idle
- `DeviceFlowPolling` - GitHub device flow spinner + user_code + link (State A-authenticating)
- `PatInput` - PAT text input for GitLab/Codeberg (State A-authenticating)
- `RepoSetup` - create or select repo (State B)
- `SyncStatus` - active sync display (State C-idle)
- `DisconnectConfirm` - confirmation modal for disconnect

### 2.3 Auth Flow (GitHub Device Flow)

1. User clicks GitHub card.
2. Desktop calls `provider.connect_start` with `github`.
3. Daemon starts device flow, returns `DeviceFlowSession` (user_code, verification_uri).
4. Desktop shows user_code + "Open GitHub" link. Polls `provider.connect_poll` every `interval_secs`.
5. On `pending`: keep polling. On `slow_down`: increase interval, keep polling.
6. On `expired`: transition to `A-error` with "Code expired. Try again."
7. On `success`: transition to State B (create/select repo).

### 2.4 Auth Flow (GitLab/Codeberg PAT)

1. User clicks GitLab or Codeberg card.
2. Desktop shows PAT input + link to provider token page.
3. User pastes PAT, clicks "Connect".
4. Desktop calls `provider.connect_pat`.
5. On success: transition to State B (create/select repo).
6. On failure: stay in `A-authenticating`, show error.

### 2.5 Repo Setup Flow (State B)

**Create path:**
1. After provider auth, show repo name input (default: vault slug).
2. "Create Repository" button calls `provider.create_repo`.
3. On success, call `vault.setup_sync` which: inits git (if needed), adds remote, commits, pushes.
4. Transition to State C.

**Select existing path:**
1. Call `provider.vault_repos` to list repos that look like Baluard vaults.
2. User selects one. Call `vault.setup_sync` with the existing repo's clone URL.
3. On success: transition to State C.

**Partial failure rollback:**
- If `provider.create_repo` succeeds but `vault.setup_sync` fails: orphaned remote repo exists.
- On retry, `provider.create_repo` will error "repo already exists" - catch and offer to use existing.
- Do NOT attempt to delete the remote repo on failure (irreversible, could be user's existing repo).

### 2.6 Disconnect Flow (CRITICAL: per-vault only)

1. User clicks "Disconnect Sync" in State C.
2. Show confirmation modal (FocusTrap): "Remove the git remote from this vault? Your data stays local."
3. Checkbox (unchecked by default): "Also revoke provider token (affects all vaults using this provider)".
4. On confirm:
   - Always call `sync.disconnect` (per-vault: removes `origin` remote, clears registry).
   - If checkbox checked: also call `provider.disconnect` (global: revokes token from keyring).
5. Transition to State A.

**Why this matters:** `provider.disconnect` is global (clears the token from the system keyring). If the user has multiple vaults synced to the same GitHub account, revoking the token breaks sync for ALL of them. The checkbox makes this explicit.

---

## Phase 3: i18n

### 3.1 New keys (en.json + es.json)

**Note:** Project uses single-brace interpolation (`{variable}`), not double-brace.

```
settings.tabSync = "Sync"
sync.title = "Vault Sync"
sync.description = "Connect to a git provider to sync your vault across devices."
sync.statusActive = "Synced"
sync.statusNotConnected = "Not connected"
sync.statusRemoteOnly = "Remote configured, provider disconnected"
sync.providerGitHub = "GitHub"
sync.providerGitLab = "GitLab"
sync.providerCodeberg = "Codeberg"
sync.authMethodDeviceFlow = "Device Flow"
sync.authMethodPat = "Personal Access Token"
sync.connect = "Connect"
sync.connectedAs = "Connected as @{username}"
sync.disconnect = "Disconnect Sync"
sync.disconnectConfirm = "Remove the git remote from this vault? Your data stays local."
sync.disconnectConfirmTitle = "Disconnect Sync?"
sync.disconnectRevokeToken = "Also revoke provider token (affects all vaults)"
sync.disconnecting = "Disconnecting..."
sync.reconnect = "Reconnect"
sync.createRepo = "Create Repository"
sync.selectRepo = "Select existing repository"
sync.repoName = "Repository name"
sync.repoNamePlaceholder = "my-vault"
sync.settingUp = "Setting up sync..."
sync.push = "Push"
sync.pull = "Pull"
sync.pushing = "Pushing..."
sync.pulling = "Pulling..."
sync.lastCommit = "Last commit"
sync.noCommits = "No commits yet"
sync.workingTree = "Working tree"
sync.clean = "Clean"
sync.dirty = "Uncommitted changes"
sync.ahead = "{count} ahead"
sync.behind = "{count} behind"
sync.deviceFlow.title = "Authenticate with GitHub"
sync.deviceFlow.instructions = "Visit the link below and enter the code:"
sync.deviceFlow.openLink = "Open GitHub"
sync.deviceFlow.polling = "Waiting for authorization..."
sync.deviceFlow.expired = "Code expired. Try again."
sync.pat.title = "Enter your {provider} token"
sync.pat.instructions = "Generate a personal access token with repository permissions."
sync.pat.generateToken = "Generate token"
sync.pat.placeholder = "Paste your token here"
sync.pat.connecting = "Connecting..."
sync.error.authFailed = "Authentication failed."
sync.error.syncFailed = "Sync operation failed."
sync.error.repoCreateFailed = "Failed to create repository."
sync.error.integrityFailure = "Signature verification failed. The remote repository may have been tampered with."
sync.error.mergeConflict = "Merge conflict. Manual resolution required."
sync.warning.title = "Provider Disconnected"
sync.warning.description = "Your git remote is configured but the provider token is missing or expired."
sync.removeRemote = "Remove Remote"
sync.syncInProgress = "Sync in progress..."
sync.notAvailable = "Sync is not available on this build."
```

Both `en.json` and `es.json` must be updated in sync.

---

## Phase 4: Icon Additions

Need icons for:
- GitHub logo
- GitLab logo
- Codeberg logo (or a generic git icon)
- Cloud/sync icon
- Upload (push) icon
- Download (pull) icon

Check existing `Icon.jsx` for what's already available. If provider logos are complex, use text-based provider badges (colored card with text) instead.

---

## Phase 5: Safety Guards

### 5.1 Pre-sync Checks (mirrors wizard)

Before calling `vault.setup_sync`:
1. **Provider authenticated:** Verify `provider.status` returns `valid: true`.
2. **No existing remote:** Check `sync.status_json` has `has_remote: false`. If remote exists with different URL, block with error.
3. **Vault unlocked:** The settings modal is only accessible when vault is unlocked (already enforced by UI flow).
4. **Device signing identity:** Confirm signing key enrolled (see Phase 1.4).

### 5.2 Disconnect Safety
1. Confirmation modal (FocusTrap, accessible).
2. Only disconnects `origin` remote. Local git history preserved.
3. Provider token revocation is opt-in via explicit checkbox (default: unchecked). See Phase 2.6.

### 5.3 Sync Locking
- Disable push/pull buttons while any sync operation is in flight.
- Show "Sync in progress..." with spinner.
- The daemon's cover commit + scheduled sync can conflict with manual push/pull from this tab. The `SyncStateMachine` provides the guard. Check `sync-state.json` before initiating manual sync. If not `Idle`, reject with "Sync in progress."

### 5.4 Error Classification
Push/pull errors must be classified before surfacing:
- **Auth failure** (401/403): Prompt reconnect → State D.
- **Network failure**: Generic retry.
- **Merge conflict**: Show conflicting files. No auto-resolve.
- **Integrity failure** (signature mismatch): Security event. Red warning. No silent retry.

---

## Phase 6: SettingsModal Integration

### 6.1 Tab Addition

Add "Sync" tab alongside "General", "Data", "Devices":
```
General | Data | Sync | Devices
```

**File:** `desktop/src/components/SettingsModal.jsx`
- Add `activeTab === "sync"` condition.
- Import and render `SyncTab` component.
- Add tab button with sync icon.

### 6.2 Status Check on Tab Open
When sync tab becomes active, call `sync.status_json` + `provider.list` to get current state. Determine top-level state (A/B/C/D) from the response.

### 6.3 Feature Flag Guard
If `sync.status_json` returns an error containing "not available" (compiled without `git-sync`), show the `sync.notAvailable` message instead of the tab content.

---

## Implementation Order

1. **Daemon routes + tests** (`sync.status_json`, `sync.disconnect`, token-gating, signing check) - backend first, tests ship with routes
2. **i18n keys** - both locales (single-brace interpolation!)
3. **SyncTab component** - full state machine with sub-states
4. **SettingsModal integration** - tab wiring
5. **Icons** - provider logos or text badges

---

## Edge Cases

1. **Feature flag off:** `git-sync` feature not compiled. Tab shows "Sync not available" message.
2. **Network errors:** Auth/push/pull fail gracefully with toast errors.
3. **Token expiry:** `provider.status` returns `valid: false`. Show reconnect prompt → State D.
4. **Multiple vaults:** Provider auth is global (keyring). Sync config is per-vault. Disconnect only touches per-vault state unless user explicitly opts into token revocation.
5. **Remote already exists:** User re-opens tab after setting up sync. Show State C (active).
6. **Push fails (dirty state):** Show error, offer retry.
7. **Pull conflicts:** Show error with guidance. Distinguish from integrity failures.
8. **Pull integrity failure:** Signature verification fails on remote commits. Red warning, security event. Do NOT auto-resolve.
9. **Self-hosted providers:** URL hostname won't match known providers. `provider: null` in status. Show remote URL without provider badge. User must reconnect manually.
10. **Partial failure (repo created, setup_sync failed):** Orphaned remote repo. On retry, catch "already exists" error and offer to use existing.
11. **Remove then re-add remote:** May trigger `last_head` rollback detection. Verify this path works cleanly.
12. **Registry consistency:** `vault.setup_sync` populates `VaultRegistry` (`provider`, `remote_url`, `last_synced`). `sync.disconnect` clears them. Verify `sync.status_json` and registry agree after each operation.

---

## Peer Review Log

**Reviewer:** peer review
**Date:** 2026-06-13

### Issues found and addressed:

| ID | Severity | Issue | Resolution |
|----|----------|-------|------------|
| A1 | MUST | New routes not in `TOKEN_REQUIRED_ACTIONS` | Added Phase 1.3 |
| A2 | MUST | Disconnect flow revoked global provider token unconditionally | Fixed: per-vault only, token revocation is opt-in checkbox (Phase 2.6, 5.2) |
| A3 | HIGH | Standalone vault may lack signing identity for first push | Added Phase 1.4: signing bootstrap check |
| S1 | HIGH | Auth-in-progress/error not modeled as sub-states | Added sub-states to all 4 top-level states |
| S2 | MED | "Select existing repo" referenced but never designed | Added State B-select sub-state + flow |
| S3 | LOW | Mid-session token expiry won't transition C→D | Accepted: error handler shows reconnect prompt |
| S4 | MED | Manual push/pull vs background sync conflict | Added SyncStateMachine guard (Phase 5.3) |
| Sec1 | HIGH | Partial failure (create_repo succeeds, setup_sync fails) | Added rollback strategy (Phase 2.5) |
| Sec2 | HIGH | Pull integrity failure vs merge conflict conflated | Split into distinct error classes (Phase 5.4, 2.1 C-error) |
| Sec3 | MED | Repo visibility not stated | Added Phase 1.5: private by default |
| E1 | MUST | i18n uses `{{var}}` instead of `{var}` | Fixed all interpolation to single-brace |
| E2 | LOW | Self-hosted providers return `provider: null` | Documented as v1 limitation (Phase 1.1) |
| E3 | MED | `last_synced`/registry consistency | Added Edge Case #12 |
| E4 | LOW | Remove/re-add remote + rollback detection | Added Edge Case #11 |
| ORD | MED | Tests listed last for security routes | Moved daemon route tests into Phase 1 |
