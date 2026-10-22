# Plan: Custom Git Remote (Advanced Provider Flow)

- Status: Draft for review (folded from one review round)
- Date: 2026-10-22
- Author: Esteban
- Review: one external peer round (FIX-FIRST; 2 of 3 blockers accepted — the trust route is host-level and clone credentials ride the request; `VaultEntry.repo` declined with source evidence: the struct has no repo field, owner/repo derives from remote_url at runtime)

## 1. Problem

Power users run their own Git infrastructure (self-hosted GitLab, Gitea,
Forgejo, bare repos over SSH). The provider pickers on desktop and mobile
offer exactly GitHub/GitLab/Codeberg, so self-hosted users cannot point a
vault at their own server through the UI. The CLI already can
(`sync remote <url>`), but the CLI is not the surface power users reach
for first on mobile.

Product rule: power users may point a vault at any Git repository by full
URL, authenticating with a personal access token or an SSH key — after an
explicit, honest warning that everything the Baluard forge integrations
automate (repo creation, invite seat grants, repo migration) becomes
manual work on their server.

## 2. What already works (grounded)

- `validate_git_url` (engine.rs:3402) accepts `https://`, `ssh://`, `git@`
  on any host. No forge allowlist exists at the transport layer.
- HTTPS credentials (sync/credentials.rs): provider keyring
  (host-restricted via `allowed_hosts`) -> `BALUARD_GIT_TOKEN` env ->
  `meta/git-credentials.json` (`{"token": ...}`) in the vault directory.
  The file is already in `GITIGNORE_CONTENT` (device-local, never synced)
  and has **no writer** — hand-edit only today.
- SSH: the credential callback delegates to the ssh-agent
  (`Cred::ssh_key_from_agent`), and the M5 `certificate_check` enforces
  strict `known_hosts` verification (fail-closed on missing file, unknown
  key, or key mismatch). `scrub_git_error` keeps tokens out of logs.
- Unknown hosts already degrade manually everywhere else: the registry
  records provider `None`, `vault_transport_coords` returns `None` (seat
  grants report "grant clone access manually"), and repo pickers do not
  list the remote. The manual caveat is existing behavior for unknown
  hosts; this feature surfaces it deliberately.
- The daemon `vault.setup_sync` accepts an optional `clone_url` (skipping
  repo creation) but **requires** `provider` and routes it through the
  provider API path.

## 3. Gaps

1. No custom surface: desktop SyncTab and the mobile git-backup wizard
   offer only the three providers.
2. No writer for the custom HTTPS credential (token + optional username).
3. SSH only via agent: no `Cred::ssh_key` path from a key file or pasted
   material (mobile has no ssh-agent at all).
4. SSH host-key trust: `known_hosts_path()` reads `$HOME/.ssh/known_hosts`
   — fine on desktop, nonexistent on mobile, so mobile SSH fails closed
   today. There is no flow to display a fingerprint and record trust.
5. `setup_sync`/clone cannot run provider-less against a custom URL.

## 4. Design

### 4.1 Surface

Both pickers gain an "Use my own server" expand link (same page, no new
screen). Expanding shows, in order:

1. The warning card (see 4.7) with an "I understand" checkbox. The fields
   stay disabled until the checkbox is set.
2. Repository URL (full, validated by `validate_git_url`).
3. Auth method: **Access token** (token + optional username) or **SSH
   key** (device file picker or paste, optional passphrase).

### 4.2 HTTPS credentials for a custom host

One token-gated daemon route `vault.git_credentials_set` carries every
custom-remote secret: payload `{token?, username?, ssh_passphrase?,
ssh_key_b64?}` — present fields update, an empty string clears. Text
secrets land in `meta/git-credentials.json`
(`{"token", "username"?, "ssh_passphrase"?}`); key bytes are decoded and
written to `meta/git-ssh-key` (0600 via `write_secret_file`, atomic,
symlink-replacing — the D1/D77 pattern; gitignored). Desktop file-pick
reads the bytes Rust-side and posts the same base64 channel as paste, so
one path serves both platforms. Every secret field is a Zeroizing at the
daemon boundary and `req.payload` is zeroized on every exit path (the
backup-route pattern). The route joins DESKTOP_ALLOWED_ACTIONS.

The credential callback already reads the token file; it gains username
support (`userpass_plaintext(username_or_git, token)`).

### 4.3 SSH keys from file or paste

New device-local file `meta/git-ssh-key` (private key, OpenSSH PEM,
0600 via `write_secret_file`, added to `GITIGNORE_CONTENT`). Sources:

- Desktop: Rust-side open dialog returning bytes (the recovery-sheet
  pattern — the webview never sees a path).
- Mobile: SAF picker (existing ImportFilePicker machinery) or a paste
  field; bytes cross FFI, the runtime writes the file.

The callback gains a branch BEFORE the agent fallback:
`Cred::ssh_key_from_memory(username, key_bytes, passphrase)` (git2
0.20.4 cred.rs:77), reading the bytes from `meta/git-ssh-key` at callback
time. In-memory avoids the `.pub` sidecar file entirely (the path-based
`Cred::ssh_key` with a `None` pubkey depends on libssh2's pub-file
lookup). Passphrase lives in `meta/git-credentials.json`
(`"ssh_passphrase"`, SecretString) — never in the key file. Username
resolution order: URL username -> stored username -> `"git"`.

Paste-field lifecycle: the UI clears the input state after submit;
webview/Compose memory is not zeroizable (the same accepted boundary as
the master-password fields).

### 4.4 Host-key trust (TOFU with human eyes)

`verify_host_key` gains a platform-aware path: `$HOME/.ssh/known_hosts`
when set (desktop), else `<data_dir>/known_hosts` (mobile). Behavior is
unchanged otherwise: Missing/Unknown still fail closed.

The failure becomes a structured sync error carrying
`host`, `key_type`, and the SHA-256 fingerprint of the presented key.
Surfaces show: server host, key type, fingerprint, and a "Trust this
server" action. Trust is a DEVICE-level operation — during a first clone
there is no vault and no session token — so the writer is a HOST-level
route, `git.git_hostkey_trust` (pre-unlock, no session token; the same-UID
trust class as `vaults.list`, documented §9.8), appending to the platform
known_hosts file. Hardening at the route:

- `host` is sanitized (no whitespace or newlines, hostname charset) so a
  hostile caller cannot inject `known_hosts` lines.
- `key_type` must be one of the known SSH key-type strings.
- The route derives and returns the fingerprint FROM the submitted key;
  the UI displays the route's fingerprint, never a client-claimed one.
- A conflicting existing entry for the host REFUSES ("a different key is
  already recorded for this host") — the route never overwrites, which is
  exactly the MITM protection.

The app never trusts silently and re-verifies on every connection; a
changed key keeps failing.

Desktop alternative honored: a power user can also add the line to their
own `~/.ssh/known_hosts`; the in-app flow exists for mobile and for users
who should not edit SSH config by hand.

### 4.5 Provider-less setup and clone

`vault.setup_sync` (daemon) and the runtime `setup_sync_remote` accept
`provider: "custom"` (or absent) **with `clone_url` required**. On custom:
no provider-API call, no repo creation, no token lookup — validate URL,
set origin, commit, push, record the registry entry with provider `None`
and the remote URL.

Clone: `vault.clone_start` gains the same custom shape
(`{url, credentials: {token?, username?, ssh_key_b64?, passphrase?}}`),
and the credentials ride the REQUEST into memory — a `CredentialConfig`
override constructor feeds the callback directly, because the vault
directory does not exist before clone and pre-writing files into the
target would break it. After a successful clone the daemon persists the
credentials into the cloned vault's `meta/` through the same 0600 writer,
so background autosync authenticates from then on. Both desktop and
mobile clone flows gain the advanced expansion (URL + credentials) —
restoring a custom-remote vault onto a new phone must work without a
desktop detour.

Everything downstream already treats provider-None as manual (seat
grants, pickers, migration) — deliberately unchanged.

### 4.6 What the warning says

Repo creation is manual: create the (preferably private) repository on
your server first. Seat grants are manual: when you share this vault,
invite people to the repository on your server yourself (read access to
clone, write access to push). Migration is manual: moving the vault to a
different remote is done by you. Baluard only syncs to the URL you give
it; it never talks to your server's API.

Acceptance: a checkbox gating the fields, and the same summary repeated
at connect time in the confirm step.

### 4.7 Non-goals

- No forge API for custom hosts: no seat automation, no repo detection,
  no collaborator management. That is the product point.
- No `http://` (still rejected — plaintext transport).
- No per-custom-host keyring entries: the vault-local files are the store.
- No SSH host-key auto-accept, ever.

## 5. Security model

- Credentials stay device-local: `meta/git-credentials.json` and
  `meta/git-ssh-key` are 0600, atomic, gitignored, and never sync.
- Tokens crossing FFI are Strings mapped to SecretString at the boundary
  (existing UniFFI convention); the passphrase rides SecretString.
- `scrub_git_error` already scrubs URL userinfo and PAT prefixes from
  every surfaced error; new code paths must not print raw credentials.
- Host-key verification stays fail-closed; trust is an explicit human
  action on a displayed fingerprint, recorded to the platform store.

## 6. Tests

- Core (lands with layer 1): credentials load with username;
  `ssh_key_from_memory` branch shape; hostkey structured error carries
  host/type/fingerprint; host sanitization; conflicting-entry refusal;
  custom `setup_sync` skips provider API (the e2e-hooks file:// allowance
  covers sync in tests) and records provider-None registry entries.
- Daemon (lands with layer 2): route tests for `git_credentials_set`
  (0600 file, present-field update, clearing) and `git_hostkey_trust`
  (append, sanitization refusals, conflict refusal); `setup_sync` and
  `clone_start` custom arms with in-memory credential injection.
- Desktop e2e: the advanced flow is drivable — expand link, warning
  checkbox, URL field, paste-token path (no native dialog on the paste
  leg; the file-pick leg is a documented manual boundary like the save
  dialogs).
- Wire-level dogfood (this box): a local bare repo over `git://`-free
  https is not available; the file:// e2e-hooks path covers the sync
  machinery, and a real sshd/custom-server journey stays a documented
  manual test.

## 7. Landing order

1. Core: username support in the credential file, `Cred::ssh_key`
   callback branch, platform-aware known_hosts path, structured host-key
   error, trust writer, GITIGNORE addition for `meta/git-ssh-key`.
2. Daemon: `vault.git_credentials_set`, `vault.git_hostkey_trust`,
   `setup_sync` custom arm; UniFFI wrappers.
3. Desktop: SyncTab advanced expansion (warning, checkbox, URL, token /
   SSH legs, fingerprint trust dialog), paste-URL clone.
4. Mobile: git-backup wizard advanced expansion (same fields over the
   existing SAF picker), clone-side URL entry.
5. Tests + docs sweep + parity note (feature-parity.md row: custom
   remote, all surfaces).

## 8. Open questions

- RESOLVED in review: clone-time credentials ride the `clone_start`
  request (see 4.5); the remaining check at build time is that the
  clone callback site uses the injected override, not `load(target)`.
- Mobile known_hosts location: `<filesDir>/known_hosts` via the registry
  data dir — confirm UniFFI exposes a stable data-dir accessor for the
  core layer (paths.rs `data_dir()` already does; the question is only
  which process env it resolves under on Android).
- Username display: some servers want the login name as the HTTPS
  username; expose the optional username field on the token leg (planned)
  — confirm Gitea/Forgejo accept `git` vs real username for token auth
  (both usually work; the field covers the exception).
