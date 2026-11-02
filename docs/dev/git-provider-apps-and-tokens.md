# Git Provider App Registration & Token Strategy

**Date:** 2026-06-15
**Scope:** How Baluard registers OAuth applications on GitHub, GitLab, and Codeberg, which token types each flow uses, and the privacy/security tradeoffs.
**Audience:** Project maintainers registering the apps; engineers wiring the client_ids.

---

## 1. Uniform posture

All three providers follow the same model:

| Principle | Implementation |
|-----------|----------------|
| Project-owned app, not personal | App lives under a project namespace (GitHub org / GitLab group / Codeberg org or user), never an individual's personal account. Consent screens attribute to the project brand. |
| Automatic flow primary | OAuth browser/device flow is the default. User logs in, grants permission, Baluard handles the rest. No token-pasting for non-technical users. |
| No client_secret shipped | Device flow and PKCE public-client flows need no secret. Nothing secret lives in the binary. |
| PAT fallback | Every provider supports a Personal Access Token path for headless, CI, air-gapped, or self-hosted instances. Surfaced under "Advanced options" in the desktop UI. |
| Advanced Options override | Power users can supply their own client_id and/or instance URL to run fully independently of Baluard's infrastructure. Defaults are embedded; overrides are per-connection. |

The embedded default `client_id` for each provider is a placeholder until the project app is registered. GitHub ships a real client_id today (`Ov23liuGmBAmBRWm3Ni`); verify it is org-owned (see §3.1) or re-register.

---

## 2. Provider capability matrix

This matrix drove every app-type decision. Researched 2026-06-15.

| Capability | GitHub | GitLab | Codeberg (Forgejo) |
|------------|--------|--------|--------------------|
| Device flow (RFC 8628) | Yes (OAuth App only) | Yes, GitLab >= 17.1, GA 17.9 | **No** |
| Authorization Code + PKCE | Yes | Yes | Yes |
| OAuth token expiry | None (long-lived) | 7200s (2h) + refresh_token | 3600s (1h) + refresh_token |
| OAuth scopes | `repo` (broad but bounded) | `api` (broad, required for repo creation) | **None implemented** (full account access) |
| PAT scopes | `repo`, fine-grained PATs available | `api`, `read_repository`, `write_repository`, etc. | **Scoped: `write:repository` + repo/visibility selection** |
| PAT expiry | User-set or never | User-set or never | User-set or never |
| Self-hosted instance support | N/A (github.com only) | Yes (`instance_url` override) | Yes (`instance_url` override) |

### 2.1 Key constraints that forced decisions

- **GitHub App vs OAuth App**: Device flow is OAuth App only. GitHub Apps do not support `/login/device/code`. Since Baluard's UX is device-flow-based, GitHub App is ruled out unless we deliberately switch to a web-redirect flow. Tradeoff accepted: OAuth App requires the broad `repo` scope and long-lived tokens, forfeiting GitHub App's fine-grained permissions and 8h short-lived tokens.
- **GitLab scope**: `POST /api/v4/projects` (create repository) requires the `api` scope. `read_repository` / `write_repository` are insufficient. The broad scope is unavoidable for a managed-sync client.
- **Codeberg scopes**: Forgejo OAuth2 tokens have no scope support. Any OAuth2 token grants full account access. This is the weakest security posture of the three and is flagged explicitly to users at connect time.

---

## 3. GitHub

### 3.1 App type: OAuth App, org-owned

- **Type**: OAuth App (NOT GitHub App). Device flow requires it.
- **Owner**: A project organization (e.g. `baluard` or `actitud-studio`), not a personal account. OAuth Apps can be org-owned; the consent screen and the app's public page (`/settings/connections/applications/:client_id`) then attribute to the org.
- **Device flow toggle**: Must be enabled in the app's settings. Without it, `POST /login/device/code` returns 403 with `device_flow_disabled`.
- **Client secret**: Not needed. Device flow is a public-client flow.
- **Scopes requested**: `repo`.

### 3.2 Registration steps

1. Create the project org if it does not exist. Set an org avatar/logo; it appears on the consent screen.
2. Org settings > Developer settings > OAuth Apps > New OAuth App.
   - Application name: `Baluard`
   - Homepage URL: project site
   - Authorization callback URL: device flow does not redirect, but the field is required. Use the project site or `http://127.0.0.1`.
3. After creation, open the app settings and **enable device flow** (checkbox).
4. Copy the **Client ID**. No secret is needed.
5. Provide the client_id to be set as `GITHUB_CLIENT_ID` in `crates/baluard-core/src/providers/github.rs`.

### 3.3 Token behavior

- **OAuth token (device flow)**: long-lived, no expiry, no refresh_token. Stored in the OS keyring (`baluard-github-<username>`).
- **PAT fallback**: user-generated at `https://github.com/settings/tokens/new`. Same `repo` scope. Useful for headless/CI.
- **Revocation**: OAuth tokens cannot be self-revoked via API (user deletes from GitHub settings). PATs likewise manual.

### 3.4 Existing client_id audit

The current hardcoded `Ov23liuGmBAmBRWm3Ni` predates this decision. Action required: verify which namespace owns it. If personal-account-owned, re-register under the project org and update the const. The consent screen seen by third-party users depends on this.

---

## 4. GitLab

### 4.1 App type: Group-owned application

GitLab offers three OAuth application types:

| Type | Verdict | Reason |
|------|---------|--------|
| User-owned | No | Owned by a personal namespace. Consent screen ties the app to an individual. |
| **Group-owned** | **Yes** | Owned by a group namespace. App identity is the project/brand. Group creator is not surfaced to authorizing end users. |
| Instance-wide | N/A | Admin-only on self-managed instances. On gitlab.com, only GitLab staff can create these. |

- **Device flow toggle**: Must be enabled on the app after creation (GitLab 17.1+, MR !224636). Verify the toggle is available for group-owned apps; if not present, reassess.
- **Client secret**: Not needed for device flow.
- **Scopes requested**: `api` (required for repository creation).

### 4.2 Registration steps

1. Create a top-level group (e.g. `baluard`). Set a group avatar/logo.
2. Group > Settings > Applications > Add new application.
   - Name: `Baluard`
   - Scopes: `api`
   - Redirect URI: device flow does not redirect. The field may be required; use a placeholder like the project site. Not load-bearing for v1.
3. After creation, **enable the device authorization grant flow** toggle on the app.
4. Copy the **Application ID** (this is the `client_id`). The Client Secret is not needed; do not copy it.
5. Provide the Application ID to replace the `REPLACE_WITH_GITLAB_CLIENT_ID` placeholder in `crates/baluard-core/src/providers/types.rs` (`Provider::default_client_id`).

### 4.3 Token behavior

- **OAuth token (device flow)**: expires in 7200s (2h). A `refresh_token` is returned and used to obtain fresh access tokens without re-auth. Refresh invalidates the prior access+refresh pair (rolling refresh). The daemon auto-refreshes before operations (task 6, pending).
- **PAT fallback**: detected by the `glpat-` prefix. Sent as `PRIVATE-TOKEN` header. Long-lived, optionally expiring, no refresh. Generated at `https://gitlab.com/-/user_settings/personal_access_tokens`.
- **Self-hosted GitLab**: supported via the instance URL override in Advanced Options. The user supplies `https://gitlab.example.com`; the client_id can also be overridden to point at an app registered on their instance.

### 4.4 Token refresh plumbing

OAuth tokens expire every 2h. The provider implements `refresh_token()`:

```
POST {instance}/oauth/token
  client_id, refresh_token, grant_type=refresh_token
-> new access_token + new refresh_token + expires_in
```

The daemon must call this before any provider operation when `token.is_expired()` returns true, re-store the refreshed token to the keyring, and surface a re-auth prompt if refresh fails (refresh failure clears credentials, transitions the desktop SyncTab to State D).

---

## 5. Codeberg (Forgejo)

Codeberg runs Forgejo. The OAuth2 behavior is Forgejo's, documented at `https://forgejo.org/docs/latest/user/oauth2-provider/`.

### 5.1 Critical caveat: no OAuth2 scopes

**Forgejo OAuth2 tokens have no scope support.** From the official docs:

> Scopes are not implemented for OAuth2 tokens and they can be used to execute any actions on behalf of the user, not just Git-related actions. Scoped application tokens or SSH keys limited to interactions with the repository should be preferred in environments where security is a concern.

This means a Codeberg OAuth2 token grants **full account access**, broader than GitHub's `repo` scope or GitLab's `api` scope. Users must be informed of this at connect time. The Forgejo project itself recommends scoped PATs over OAuth2 for security-sensitive environments.

### 5.2 App type: OAuth2 application (user-level), PKCE public client

- **Type**: OAuth2 application registered at `https://codeberg.org/user/settings/applications` (user-level) or under an org namespace. Instance-wide apps (`/admin/applications`) grant admin rights and must not be used.
- **Flow**: Authorization Code + PKCE. Forgejo does not support device flow. This requires a web-redirect flow with a loopback callback server (`http://127.0.0.1:<port>/callback`), which is a larger implementation surface than device flow (daemon task 4/5, pending).
- **Public client**: register as a public client. Redirect URI `http://127.0.0.1/` allows any port per RFC 8252. Avoid `localhost`.
- **Client secret**: not needed for PKCE public clients.
- **Scopes**: none available. Token = full account access.

### 5.3 Registration steps

1. Create a project user or org on Codeberg if one does not exist.
2. Settings > Applications > Create new OAuth2 application.
   - Name: `Baluard`
   - Redirect URI: `http://127.0.0.1/callback` (loopback; port is dynamic at runtime)
3. Register as a **public client** (PKCE, no secret).
4. Copy the **Client ID**. No secret for public clients.
5. Provide the client_id to replace the `REPLACE_WITH_CODEBERG_CLIENT_ID` placeholder in `crates/baluard-core/src/providers/types.rs`.

### 5.4 Token behavior

- **OAuth token (PKCE flow)**: expires in 3600s (1h). A `refresh_token` is returned. Full account access (no scopes).
- **PAT fallback**: generated at `https://codeberg.org/user/settings/applications` per `https://docs.codeberg.org/advanced/access-token/`. **Scoped**: the Codeberg web UI (running recent Forgejo) offers both scope selection (`write:repository`, `read:repository`, etc., per `https://forgejo.org/docs/latest/user/token-scope/`) and repository access selection (All / Public only / Specific repositories). For vault sync the target scope is `write:repository`; the user can further restrict it to the specific vault repo once created. Sent as `Authorization: token <PAT>` header. No expiry unless user sets one; no refresh. **This scoped PAT is materially more secure than the OAuth2 flow (which has no scopes).**
- **Self-hosted Forgejo/Gitea**: supported via instance URL override.

### 5.5 The PAT doc question

There are **three** relevant docs for Codeberg tokens, each covering a different token type:

| Doc | What it covers |
|-----|---------------|
| `https://docs.codeberg.org/advanced/access-token/` | How to generate a web-UI Personal Access Token (simplified; doesn't show the scope selector) |
| `https://forgejo.org/docs/latest/user/token-scope/` | The scopes available on access tokens (PATs): `write:repository`, `read:repository`, + repo/visibility selection |
| `https://forgejo.org/docs/latest/user/oauth2-provider/` | The OAuth2 automatic flow (no scopes, full account access) |

Key correction (from the token-scope doc): Codeberg PATs are **NOT** all-or-nothing. The web UI offers `write:repository` scope and "All / Public only / Specific repositories" selection. This makes the scoped PAT more secure than OAuth2 for Codeberg, the opposite of GitHub/GitLab where OAuth scopes are comparable to PAT scopes.

### 5.6 Security disclosure and the recommended path

Because Codeberg OAuth2 grants full account access, the desktop UI must surface an explicit warning before the user authorizes. Suggested i18n key `sync.codebergFullAccessWarning`:

> Codeberg OAuth2 has no scope support. Authorizing Baluard grants it full access to your Codeberg account. For tighter access, create a Personal Access Token with the `write:repository` scope under Advanced options instead.

This is more severe than the GitLab scope note (`sync.scopeNoteApi`) and must be presented as a warning, not a footnote.

Given the project priority (frictionless for the average user), the OAuth2 automatic flow remains the **primary** Codeberg path. But the scoped PAT (`write:repository` + specific repo) is the **recommended path for security-conscious users**, and the connect UI should make the tradeoff explicit.

---

## 6. Privacy posture

The core privacy requirement: third-party users authorizing Baluard must not see a maintainer's personal account handle on the consent screen.

### 6.1 Why namespace ownership matters

OAuth applications belong to an owner account. The provider surfaces the owner on the authorization/consent screen and on the app's public information page:

- **GitHub**: the OAuth authorization page and `/settings/connections/applications/:client_id` show the app's owner. For personal-account apps, the handle is attached.
- **GitLab**: issue #462655 ("OAuth authorization screen is misleading for GitLab-owned application") confirms owner identity is surfaced on the consent screen. Group-owned apps attribute to the group namespace.
- **Codeberg/Forgejo**: the OAuth2 authorize page shows the application name and the registering user/org.

### 6.2 Required namespace for each provider

| Provider | Register under | Do NOT register under |
|----------|---------------|----------------------|
| GitHub | Project org (e.g. `baluard`) | Personal account |
| GitLab | Project group | Personal namespace |
| Codeberg | Project user or org | Personal account |

The individual who creates the org/group is not surfaced to authorizing end users. The app's identity is the project brand.

### 6.3 Residual privacy surface

Even with org/group ownership, two indirect disclosures remain:

1. **Org/group membership**: if the project org is public, its members list is visible. This is standard for open-source projects and acceptable.
2. **App creator in audit logs**: the provider may log who created the app in admin/audit views. Not visible to authorizing end users.

Neither is a consent-screen leak. Both are acceptable for an open-source project.

---

## 7. Client_id placeholders and the override path

### 7.1 Defaults embedded in the binary

Each provider has a default `client_id` in `crates/baluard-core/src/providers/types.rs`:

```rust
Provider::GitHub => super::github::GITHUB_CLIENT_ID,  // real, verify org-owned
Provider::GitLab => "REPLACE_WITH_GITLAB_CLIENT_ID",   // placeholder
Provider::Codeberg => "REPLACE_WITH_CODEBERG_CLIENT_ID", // placeholder
```

Placeholders must be replaced with real client_ids before the automatic flow works for third-party users. Until then, users fall back to PAT under Advanced options.

### 7.2 Advanced Options override

The desktop SyncTab exposes a collapsible "Advanced options" panel in the connect flow. It accepts:

- **OAuth client ID**: overrides the embedded default. Lets a user register their own app (personal or org) and run fully independent of Baluard's infrastructure.
- **Instance URL**: overrides the public default (`https://gitlab.com`, `https://codeberg.org`). Points at a self-hosted GitLab or Forgejo instance.

Overrides are persisted in `providers.json` (`ProviderInfo.client_id`, `ProviderInfo.instance_url`) so later operations (token refresh, repo ops) reuse the same configuration. Keyring entries remain keyed by `baluard-<provider>-<username>`.

One active instance per provider is supported in v1. Switching instances (e.g. gitlab.com to self-hosted) requires disconnect and reconnect.

---

## 8. Implementation status

| Component | GitHub | GitLab | Codeberg |
|-----------|--------|--------|----------|
| Provider trait impl | Done | Done | Done |
| Device flow | Done | Done | N/A (not supported) |
| Web-OAuth (PKCE) | N/A | N/A | Done |
| PAT fallback | Done | Done | Done |
| Token auto-refresh | N/A (no expiry) | Done | Done |
| Desktop device-flow UI | Done (generalized) | Done (reuses GitHub UI) | N/A |
| Desktop PKCE UI | N/A | N/A | Done |
| Advanced Options UI | Done | Done | Done |
| Embedded client_id | Real (verify org) | Placeholder | Placeholder |

---

## 9. Open items for the maintainer

1. **Audit `Ov23liuGmBAmBRWm3Ni`**: confirm it is org-owned. If personal, re-register under the project org and update `GITHUB_CLIENT_ID`.
2. **Register the GitLab app** under a project group. Enable the device-flow toggle. Provide the Application ID.
3. **Register the Codeberg app** as a public PKCE client. Provide the Client ID.
4. **Verify the GitLab device-flow toggle** is available for group-owned apps (not just user-owned). Report back if it is group-restricted.
5. **Decide on the Codeberg full-access warning UX** before task 5 ships: warning modal vs inline banner. Recommended: modal blocking first connect, dismissible thereafter.
6. **H1 manual verification (release gate)**: confirm the registered Codeberg OAuth2 app actually accepts a loopback `redirect_uri` with a dynamic port (i.e. `http://127.0.0.1/` wildcarding any port per RFC 8252). The PKCE flow binds a random ephemeral port at runtime; if Codeberg requires an exact registered port, registration must use a fixed port and the listener bind must match. Test end-to-end against codeberg.org before release.

---

## 10. References

- GitHub OAuth Apps (device flow): `https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow`
- GitHub OAuth App creation: `https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app`
- GitLab OAuth2 identity provider: `https://docs.gitlab.com/api/oauth2/`
- GitLab OAuth provider config: `https://docs.gitlab.com/integration/oauth_provider`
- GitLab device-flow toggle MR: `https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224636`
- Forgejo OAuth2 provider: `https://forgejo.org/docs/latest/user/oauth2-provider/`
- Forgejo token scopes: `https://forgejo.org/docs/latest/user/token-scope`
- Codeberg access tokens (PAT): `https://docs.codeberg.org/advanced/access-token/`
- Forgejo token scopes (PAT): `https://forgejo.org/docs/latest/user/token-scope/`
- RFC 8628 (Device Authorization Grant): `https://datatracker.ietf.org/doc/html/rfc8628`
- RFC 8252 (Native Apps, loopback redirect): `https://datatracker.ietf.org/doc/html/rfc8252`
