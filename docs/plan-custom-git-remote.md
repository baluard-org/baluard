# Plan: Custom Git Remote (Advanced Provider Flow)

- Status: Draft for review (v2 — folded from two review rounds: agy, Claude)
- Date: 2026-10-22
- Author: Esteban

## 1. Problem

Power users run their own Git infrastructure (self-hosted GitLab, Gitea,
Forgejo, bare repos over SSH). The provider pickers on desktop and mobile
offer exactly GitHub/GitLab/Codeberg, so self-hosted users cannot point a
vault at their own server through the UI.

Product rule: power users may point a vault at any Git repository by full
URL, authenticating with a dedicated SSH deploy key (default), an access
token, or their own pasted/picked key — after an explicit, honest warning
that everything the forge integrations automate (repo creation, invite
seat grants, member removal on the server, repo migration) becomes manual
work on their server. Baluard never talks to a custom server's API; it
only syncs to the URL.

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
- Autosync activation is REMOTE-based, not provider-based: unlock probes
  `SyncEngine::has_remote` (state.rs ~490) and activates the coordinator
  when a remote exists — a custom vault syncs automatically with no
  provider connected.
- Unknown hosts already degrade manually everywhere else: the registry
  records provider `None`, `vault_transport_coords` returns `None` (seat
  grants report "grant clone access manually"), and repo pickers do not
  list the remote.
- The daemon `vault.setup_sync` accepts an optional `clone_url` (skipping
  repo creation) but **requires** `provider` and routes it through the
  provider API path.

## 3. Design

### 3.1 Surface

Both pickers gain an "Use my own server" expand link (same page, no new
screen). Expanding shows, in order:

1. The warning card (see 3.7) with an "I understand" checkbox. Fields
   render disabled (visible, not hidden — disabled inputs must stay
   focusable for screen readers) until the checkbox is set.
2. Repository URL (full, validated — see 3.8 for the new validation
   rules).
3. Auth method: **Generate a dedicated key** (default), **Access token**
   (token + optional username), **Use my SSH agent** (desktop), or
   **Paste / pick a key file** (advanced; carries its own warning, see
   3.3).
4. A "Test connection" button (see 3.6) before anything is written.

A shortened warning shows on the clone and restore paths (nothing is
created there); the full warning is creation-time only. The warning
summary repeats at connect time as text — never a second checkbox.

### 3.2 HTTPS credentials for a custom host

One token-gated daemon route `vault.git_credentials_set` carries every
custom-remote secret: payload is a TYPED struct with `Zeroizing<String>`
fields — `{token?, username?, ssh_passphrase?, ssh_key_pem?, keygen?}` —
present fields update, an empty string clears. No `serde_json::Value`
intermediate (the backup-route M1 pattern). Text secrets land in
`meta/git-credentials.json` (`{"token", "username"?, "ssh_passphrase"?,
"host"?}`); key bytes decode into `meta/git-ssh-key` (0600 via
`write_secret_file` — atomic, symlink-replacing; gitignored). Desktop
file-pick reads bytes Rust-side and posts the same channel as paste.
`req.payload` zeroizes on every exit path. The route joins
`DESKTOP_ALLOWED_ACTIONS`.

**Host binding (review B1):** the file stores the remote's host. The
credential callback releases the stored token ONLY when the URL libgit2
is authenticating matches that host — libgit2 follows HTTP redirects, and
a hostile server must never be able to redirect its way to the token.
Changing the remote (setup_sync to a new URL) clears or re-binds the
credentials, and changing the remote on an already-synced vault rides
`reprompt_verify` first. Set-time parsing uses a typed struct; the UI
sends only touched fields (tested — an all-fields send must not wipe
untouched secrets).

The credential callback gains username support
(`userpass_plaintext(username_or_git, token)`).

### 3.3 SSH keys: generate-first

**Default path — generate a dedicated deploy key (review A4):** the
daemon mints a fresh Ed25519 keypair via the existing `ssh-key` machinery
(the same path as SSH key generation for entries). The private half is
written to `meta/git-ssh-key` 0600 device-local; the public half is shown
once for the user to add as a deploy key on their server. The user's
personal `id_ed25519` never leaves their machine.

- **Use my SSH agent** (desktop): an explicit choice; stores no secret,
  uses the existing agent delegation.
- **Paste or pick a key file** (advanced): carries a warning — pasting a
  personal key gives Baluard access to every server it opens; prefer the
  dedicated key. Key bytes are parsed at set-time with the `ssh-key`
  crate: normalize the trailing newline (paste strips it), reject
  unsupported formats and encrypted-without-passphrase keys with plain
  messages (review C3), and store the private PEM. The UI clears input
  state after submit; webview memory is not zeroizable (accepted
  boundary, same as master-password fields). A clipboard-clear hint
  accompanies paste.

The callback branch runs BEFORE the agent fallback:
`Cred::ssh_key_from_memory(username, key_bytes, passphrase)` (git2 0.20.4
cred.rs:77), reading bytes from `meta/git-ssh-key` at callback time into
a `Zeroizing<String>` (the API takes `&str`). No `.pub` sidecar is
needed. The passphrase lives in `git-credentials.json` — next to the key
on disk, so the passphrase adds nothing against local disk theft; the
warning says so honestly (the "no second password prompt" rule forbids
demanding it per unlock; a keyring move is future design, out of scope
here). Username resolution: URL username -> stored username -> `"git"`.

**Callback hardening (review C4):** a per-credential-type attempt cap so
a wrong key or token cannot loop the callback forever; the USERNAME
allowed-cred type is answered with `Cred::username` for `ssh://host/path`
URLs without a user.

### 3.4 Host-key trust (TOFU with human eyes)

`known_hosts_path` becomes platform-aware: `$HOME/.ssh/known_hosts` when
set (desktop), else `<data_dir>/known_hosts` (mobile). Behavior is
unchanged otherwise: Missing/Unknown/Mismatch fail closed.

The failure becomes a structured sync error carrying host, PORT, key
type, and the SHA-256 fingerprint of the presented key. A non-default
port uses the `[host]:port` known_hosts entry form (review C2).

**Trust is device-level and daemon-observed (review C1):** the failed
handshake stashes the observation — host, port, key type, key bytes,
fingerprint — in an in-memory pending map with a TTL (the CeremonyCache
pattern) and returns an attempt id plus the fingerprint. Surfaces show
host/type/port/fingerprint and a "Trust this server" action; the trust
route (`git.git_hostkey_trust`, HOST-level — pre-unlock, no session
token, the same-UID trust class as `vaults.list`) takes ONLY the attempt
id and commits what the daemon itself observed. A compromised webview
cannot pre-trust an attacker-chosen key because it never supplies key
material. `key_type` comes from the observed set; the fingerprint the UI
shows is the route's answer, never client-claimed.

**Conflict handling:** before appending, the route checks the platform
known_hosts for the host. A plaintext conflicting entry refuses ("a
different key is already recorded for this host"). A HASHED entry (`|1|`
form) or an unparsable line matching the host also refuses, with copy
directing the user to manage the entry themselves — we never overwrite
any existing line, in any format (review C1).

**Write care (review C5):** append with a leading newline if the file
lacks a trailing one; create the `.ssh` directory 0700 on first write;
atomic tmp+rename; Windows home resolution fails closed (never a
cwd-relative path). Copy tells the user to compare the fingerprint with
`ssh-keygen -lf` on the server when they can (review C6); after trust the
connect retries automatically.

Baluard-owned entries land in the platform file so terminal `ssh` and
Baluard share one trust view; Mismatch in the file still fails closed.

### 3.5 Provider-less setup, clone, and management

`vault.setup_sync` (daemon) and runtime `setup_sync_remote` accept
`provider: "custom"` (or absent) **with `clone_url` required**. On
custom: no provider-API call, no repo creation, no token lookup —
validate URL, set origin, commit, push, record the registry entry with
provider `None` and the remote URL.

**Clone:** `vault.clone_start` gains the custom shape
(`{url, credentials: {...}}`); credentials ride the REQUEST into an
in-memory `CredentialConfig` override — the vault directory does not
exist before clone, and pre-writing files into the target would break it.
After a successful clone the daemon persists the credentials through the
same 0600 writer; if that persistence FAILS the error is surfaced loudly
— never a vault that silently cannot sync (review D5). The clone
callback site must use the injected override, not `load(target)` (pinned
by test). Desktop AND mobile clone flows gain the advanced expansion
(restoring a custom-remote vault onto a new phone works without a desktop
detour); the join-by-invite clone flow gets the same expansion, because
invitees on custom hosts hit it (review A5).

**Existing-repo guard (review D3):** before the custom arm's first push,
probe the remote. A non-empty remote that lacks a `.baluard` marker — or
whose marker vault_id differs — refuses; never force-push. An empty repo
and a bare repo whose HEAD points elsewhere are handled by passing the
branch explicitly (review D2: bare HEAD often says `master` while
Baluard pushes `main`, leaving later clones with an empty checkout —
clone/push carry the explicit branch).

**Management (review A5):** the SyncTab custom card gains "Change
sign-in" (reuses `git_credentials_set`), "Change address" (setup_sync
with the new URL — reprompt-gated, credentials re-bound or cleared), and
"Stop using this server" (clears credentials and the remote). Switching
from custom to a provider clears the leftover custom secrets.

**Test connection (review A6):** a host-level pre-flight probe (ls-remote
with the in-memory credentials) returning a structured result: ok, auth
rejected, host unknown (trust flow), not found, not a Baluard vault, TLS
untrusted, or unreachable. It runs before any commit or push and feeds
both the setup and clone paths.

**Transport security (review A7):** the system trust store only — never
an insecure-skip toggle, stated plainly in the plan and the UI. A
self-signed or private-CA server fails TLS verification with a
plain-language error; on Android, user-installed CAs are not trusted by
default at targetSdk 35 (network security config default), so that
limitation is named in the warning rather than worked around.

### 3.6 What the warning says

- Repo creation is manual: create the (preferably private) repository on
  your server first.
- Sharing is manual: when you share this vault, invite people to the
  repository on your server yourself (read access to clone, write access
  to push).
- Member removal is manual (review A1): removing someone from the space
  cuts their decryption immediately, but they keep server access until
  you remove them from the repository. The removal flow says so.
- Migration is manual: moving the vault to a different remote is done by
  you.
- You own the server: its uptime and backups are yours (review A2).
- Credentials live in files on this device, not in the OS keyring; the
  SSH passphrase, if any, sits beside the key and adds nothing against
  local disk theft (reviews A2/B3).
- Baluard only syncs to the URL you give it; it never talks to your
  server's API.

Acceptance: a checkbox gating the fields; the summary repeats at connect
as text.

### 3.7 Non-goals

- No forge API for custom hosts: no seat automation, no repo detection,
  no collaborator management. That is the product point.
- No `http://` (still rejected — plaintext transport).
- No per-custom-host keyring entries in v1 (the vault-local files are the
  store; a keyring move is future design).
- No SSH host-key auto-accept, ever. No insecure-TLS toggle, ever.
- CLI credential flags (review A3): the CLI already syncs custom URLs via
  `sync remote` plus the `BALUARD_GIT_TOKEN` env var; richer CLI flags
  (key file, username) are logged as a feature-parity gap at ship, not
  built in this wave.

### 3.8 URL validation additions (review B2)

`validate_git_url` gains: rejection of `user:pass@` userinfo on https
URLs (the credentials fields are the only place secrets go — today a
pasted userinfo URL would carry the password into the registry
`remote_url`, `.git/config`, and UI displays; VERIFIED: the current
validator checks scheme and host only) and rejection of control
characters anywhere in the URL. A custom URL on a known forge host
(github.com / gitlab.com / codeberg.org) steers to the provider flow
(review D6) so it can never reach provider API code by accident.

## 4. Security model

- Credentials stay device-local: `meta/git-credentials.json` and
  `meta/git-ssh-key` are 0600, atomic, gitignored, and never sync. The
  gitignore refresh (`refresh_gitignore` NEW_ENTRIES, the
  recovery-signer.key precedent) covers vaults created before the feature
  existed, and a test pins that `commit_all` never stages the credential
  files even when `.gitignore` is missing (review B4). Anything that
  copies or zips the vault directory (enrollment clone, export) is
  audited for these two files at build time.
- Host binding: stored credentials release only for the bound host
  (redirect-safe, review B1).
- Trust observations are daemon-side with a TTL; the trust route accepts
  an attempt id, never key material (review C1).
- `scrub_git_error` already scrubs URL userinfo and PAT prefixes; new
  paths must not print raw credentials, and daemon/desktop logs are
  checked never to echo payload fragments on serde errors (review B8).
- Sync commit trust is untouched: signing and roster verification are
  independent of transport credentials.

## 5. Tests (land with their layers)

- Core: typed-route payload shape (present-update / empty-clear /
  untouched-stays); host-bound release and redirect refusal; userinfo and
  control-char URL refusals (proptest on the sanitization, review E2);
  `ssh_key_from_memory` branch with newline normalization and format
  rejection; callback attempt cap; USERNAME handling; hostkey structured
  error carrying host/port/type/fingerprint; hashed-entry and conflicting
  -entry trust refusals; `[host]:port` entry form; custom `setup_sync`
  skipping the provider API and recording provider-None; existing-repo
  guard refusals; explicit-branch push against a master-HEAD bare repo;
  secrets absent from logs, errors, registry, `.git/config`, and the
  committed tree.
- Daemon: `git_credentials_set` route tests; `git_hostkey_trust`
  attempt-id flow (expired TTL, unknown id); `setup_sync` / `clone_start`
  custom arms; clone-callback override pinned; post-clone persistence
  failure surfaced; `DESKTOP_ALLOWED_ACTIONS` covers the new routes
  (review E5).
- CI-hermetic real-server coverage (review E1): a loopback sshd git
  server plus an HTTP basic-auth git server in the e2e harness covering
  key + passphrase auth, wrong-key no-loop, trust-then-clone, changed-key
  refusal, and basic-auth HTTPS. This lands with the core/daemon layers,
  BEFORE the mobile UI — it is where the risky paths actually live.
- Desktop e2e: expand link, warning checkbox, URL field, generate-key
  leg, paste-token leg, test-connection result states (the file-pick leg
  is a documented manual boundary like the save dialogs).
- UI: sends only touched fields; custom vault shows as sync-configured
  (keyed on remote_url, not provider — review D4); i18n keys land in
  en/es/pt in every UI step (review A9; the parity tests fail otherwise).
- An audit of every `VaultEntry.provider` reader is a build-time item
  (review D4): provider None + remote_url Some is "custom-synced",
  provider None + remote_url None is "local-only"; UI state keys on
  remote_url.

## 6. Landing order (review E3)

1. Core in ONE change: credentials writer types, host binding,
   `ssh_key_from_memory` branch, callback hardening, structured hostkey
   error variant — with EVERY exhaustive `SyncError` match site updated
   in the same commit (cli, daemon, uniffi) so nothing breaks
   mid-sequence. Core tests ride along.
2. Daemon + UniFFI: `git_credentials_set`, `git_hostkey_trust`,
   `setup_sync`/`clone_start` custom arms, the test-server harness. All
   UniFFI signature changes are additive, or the Kotlin callers update in
   the same change (the regen-bindings rule).
3. Desktop UI: expansion, warning, generate-key leg, test connection,
   trust dialog, management rows; e2e flows.
4. Mobile UI: expansion over the SAF picker, clone/join expansion,
   management rows.
5. Docs sweep: feature-parity row (custom remote, all surfaces; CLI gap
   noted), known-limitations line for the Android user-CA limitation.

## 7. Review record

- Round 1 (agy, FIX-FIRST): the trust route must be host-level (no vault
  or token exists at first clone) — accepted; clone credentials ride the
  request — accepted; `Cred::ssh_key` with a None pubkey depends on a
  `.pub` sidecar — replaced with `ssh_key_from_memory`; mobile clone
  parity — accepted; host sanitization and conflict refusal — accepted
  and hardened further in round 2; `VaultEntry.repo` — DECLINED with
  source evidence (the struct has no repo field; owner/repo derives from
  remote_url at runtime).
- Round 2 (Claude, FIX-FIRST): headline accepts — daemon-observed
  attempt-id trust (no client-supplied key material), host-bound
  credential release (redirect-safe), userinfo rejection, hashed-entry
  conflict handling, port-carrying trust entries, generate-a-dedicated-
  key as the default SSH path, member-removal warning line, test-
  connection probe, existing-repo guard, explicit-branch handling for
  master-HEAD bare repos, CI-hermetic sshd/basic-auth server coverage
  before mobile, and the build-safe landing order. Partially accepted:
  keyring storage for the SSH key (deferred as future design; the
  no-second-password rule forces storing the passphrase regardless).
  Declined: none substantive — `VaultEntry.repo` was the only false
  premise, from round 1.
