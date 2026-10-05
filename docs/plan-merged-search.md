# Plan: Merged Search and Autofill Across Personal Vault and Spaces (G24)

Status: In review (one external review round folded in)
Date: 2026-10-05
Author: Esteban
Reviewers: external peer review (round 1: FIX-FIRST, folded; verdicts below)

## 1. Problem

Baluard gives every vault its own master password and its own key
hierarchy. A joined Space (family, organization) is a separate vault.
Users expect what 1Password and Bitwarden do: browser autofill, mobile
autofill, and search list ALL entries together, with a badge per origin
vault.

Where Baluard actually stands today:

- Desktop app: already merged. `vaults.list_full_all`
  (`crates/baluard-daemon/src/handler.rs:939`) fans out over unlocked
  vaults; `VaultContext.jsx` tags foreign ciphers with `_vault`
  (S2-5); `VaultView.jsx:112` appends them to the list and
  `VaultView.jsx:118` runs search over the merged set; `CipherRow`
  renders the vault chip. This shipped as D31. The desktop is prior
  art here, not work to do.
- Browser extension autofill: single-vault. `bridge.match`
  (`crates/baluard-daemon/src/handler.rs:2133`) resolves against the
  active vault only. The follow-up reads (`vault.get {id, url}`,
  `cipher.totp_code {id, url}`) verify against the active vault too.
- Android autofill: single-vault. The `:autofill` process holds ONE
  vault (`AutofillSession.kt:15`, `ensureOpen` at `:75` opens the
  last-active path and locks the previous handle). Matching runs
  through `state.autofill_query` for that one vault.
- Mobile app search: single-vault, over the active session.
- CLI: no search at all (parity matrix row: None).

## 2. Scope and non-goals

In scope: merged autofill (extension, Android) and merged search
(mobile app, CLI) across unlocked vaults the user has opted in, with
per-result vault attribution and a locked-vault affordance.

Out of scope, deliberately:

- No crypto changes. Merging spans only vaults that are already
  unlocked.
- No change to the one-master-password-per-vault invariant.
- No shared device secret. Each vault generates its own device
  identity and wrap key (`identity:{vault_id}`,
  `crates/baluard-core/src/vault/creation.rs:530-545`). Making one
  device secret unlock every vault was considered and rejected: it
  contradicts the sharing plan's P1 principle that one cracked laptop
  must not yield every Space. Per-vault quick unlock is the answer to
  the second password, not a shared key.
- No cached index readable while vaults are locked. It would need a
  key outside any vault secret and would store domains and usernames
  at rest. A keystore-sealed set of domain hashes ("Family has a
  login for this site") is a future option, not v1.
- Desktop main list: already merged (D31). No new desktop surface in
  v1; a keyboard palette is optional polish, not planned.

## 3. Existing machinery and its limits

- The daemon keeps several vaults unlocked at once (`VaultHost` map,
  keep-unlocked switch model). Desktop blur locks only
  `Immediately`-policy vaults (`vaults.on_app_blur`,
  `handler.rs:1361`), so a typical personal-plus-family pair stays
  open side by side.
- Mobile main process holds up to three unlocked sessions
  (`MultiVaultSession.kt:196`, `MAX_UNLOCKED = 3`, LRU eviction).
  But `ON_STOP` locks every inactive session (`App.kt:332`), which
  is exactly when autofill runs.
- Per-vault quick unlock: Touch ID / Android biometric via per-vault
  Keystore keys. Linux and Windows use the session PIN, which exists
  only after a master-password unlock in the current daemon session;
  a never-unlocked-this-session vault needs the typed password once.
- `vaults.list` exposes per-vault lock state pre-token.
- Bridge tokens: the extension authenticates with a pairing token;
  `bridge.match` and friends are gate-checked against
  `BRIDGE_ALLOWED_ACTIONS` (`crates/baluard-core/src/bridge/token.rs:48`),
  which has NO unlock route and must not gain one that accepts a
  master password (the app collects exactly one credential in its
  life).
- D21/D31 boundary: `vaults.list_full_all` is deliberately absent
  from `BRIDGE_ALLOWED_ACTIONS` so a paired browser cannot export
  whole vaults. The merged extension route must not become a back
  door to that data.

## 4. Design

### 4.1 One fan-out helper, extracted

The daemon already has the fan-out loop: `vaults.list_full_all`
iterates `host.list()`, snapshots each unlocked row, tags slug, name,
presence, and degrades a vault that locks mid-scan to a locked row.
Extract that loop into a shared helper and reuse it. Do not write a
second loop.

### 4.2 Per-vault "available to browser and autofill" consent

Fan-out silently widens what a paired browser can see: today the
bridge token snapshots the active vault the user had in mind when
pairing; tomorrow a work Space becomes browser-readable too. That is
a trust-model change and needs consent:

- A device-local flag in the vault registry (not synced
  `settings.enc`): `browser_enabled`.
- Default: on for the personal vault; asked explicitly at Space join
  and in Space settings.
- A decision record documents the model change.
- The extension's merged match route returns match metadata only,
  never whole-vault payloads; it must not become a path to
  `list_full_all`-shaped data.

### 4.3 Extension autofill: `bridge.match` fans out over `autofill_query`

Today `bridge.match` calls `list_all`, which decrypts and serializes
every cipher including passwords, on every tab event. The merged
version rides `VaultState::autofill_query` (`state.rs:919`) instead:
login-only, no passwords, `UriMatchStrategy` with custom equivalent
domains. One matcher everywhere: the loose hostname matcher in the
handler retires in favor of `UriMatchStrategy` (the same matcher
Android and the daemon's fill-time check use).

Response shape: each match gains `vault_slug` and `vault_name`; the
top level gains a `vaults` array with slug, display name, and lock
state, so surfaces render unlock chips without a second call. Match
metadata only; still no passwords; still no session token required
(bridge pairing token only).

Gate change: today the bridge gate requires the ACTIVE vault
unlocked (`route_bridge_request` returns `locked` otherwise), which
would report "locked" whenever the personal vault sleeps even if the
family vault is open. The gate becomes: at least one
browser-enabled vault unlocked.

Ordering: slug resolution must happen before per-vault matching and
before the delegated token stamp binds the active state
(`handler.rs:~1950`); resolve through `host.snapshot_target(slug)`
first.

### 4.4 Slug-scoped reads

`vault.get {id, url, vault_slug}` and
`cipher.totp_code {id, url, vault_slug}`: with the slug, resolve that
vault and enforce the same server-side URI match against it; fail
closed on a locked, unknown, or not-enabled vault. Without the slug:
active vault, unchanged. Cipher ids are per-vault UUIDs, so the slug
disambiguates.

The extension popup currently calls `vault.get {id}` with no url
(`browser/shared/src/popup.jsx:348`, `:398`), which skips URL
matching for URI-less entries. Slug-scoped reads always carry the tab
URL, so a compromised extension page cannot read an arbitrary entry
from any enabled vault by id alone.

### 4.5 Service-worker payload projection (B4 rule)

`handleInlineMatches` returns the raw route payload to the page-
principal content script today (`background.js:208`). The new
`vaults` array and vault names must not cross that boundary (the
inline menu renders inside the page). The service worker projects the
inline payload to `{id, name, username, vault_slug}`. Vault names
show only in the popup, an extension-owned page. The inline menu gets
a neutral "from another vault" marker only when two or more vaults
contribute to the match set.

### 4.6 Bridge writes stay active-vault

`vault.add` and `vault.update` are bridge-allowlisted (field-gated).
Rule: bridge writes target the active vault only. Updating a
foreign-vault match is refused in v1 (the popup switches to that
vault first, an explicit act). Slug-routed writes with the
`bridge_write_allowed` role check are a later slice if capture UI
ever lands.

### 4.7 Locked-vault affordance in the extension

V1 is a text-only chip: "Family is locked. Open Baluard." There is no
unlock route in the bridge allowlist and none is added; a master
password never enters the extension. A future `bridge.request_unlock
{slug}` that raises the desktop unlock dialog with pairing-style
user approval is the candidate for v2.

### 4.8 Android autofill

The `:autofill` process holds one vault today, so "iterate unlocked
sessions" has nothing to iterate. Design choice: one handle per path
in `:autofill`, each unlocked through the existing `AutofillActivity`
biometric flow — per-vault Keystore alias and per-use `CryptoObject`
stay intact, and the OOM invariant holds because every unlock rides
`unlock_with_kek`, never the master KDF. Cost: a cold session costs
one BiometricPrompt per vault, sequential and explicit. Rejected
alternatives: time-bound Keystore keys (one prompt authorizes all
vault keys for a few seconds — trades away per-use crypto binding),
and a bound service into the main process (that process locks
everything on `ON_STOP`).

Merge: rank across open handles into one dataset; each dataset label
carries the vault name when two or more vaults contribute; selection
fetches from the owning vault — `credential(id)` becomes
`credential(path, id)`. Inline chips keep their existing cap
(`AutofillResponseBuilder`, max 5). App-trust lists stay per-vault:
an app trusted in the personal vault re-prompts before family
suggestions appear.

### 4.9 Android app search

The main-process list search fans out over its unlocked sessions
(here `MAX_UNLOCKED = 3` applies), badges results with the vault
name, and opens the owning vault on tap. Folders and tags stay
per-vault in their own screens.

### 4.10 CLI search

`baluard search --all` fans out over unlocked vaults and prints
slug-tagged rows, per the CLI-first-class principle: the command is
the executable spec of the fan-out contract and the e2e vehicle for
it.

### 4.11 Ranking and display

Order: exact host match first, then the personal vault, then
favorite, then name, then vault slug as a stable tiebreak. Favorite
is a shared field inside a Space, so a stranger's favorite must not
outrank the user's own login. No dedupe: two logins for the same
site from personal and family both show, and the user picks (nothing
autofills on load). Badges render only when two or more vaults
contribute, so single-vault users see no machinery. The toolbar
badge count counts across browser-enabled vaults.

## 5. Failure modes and product behavior

- Desktop blur: an `Immediately`-policy vault locks on window blur,
  and using the extension means the desktop window is blurred. Such
  a vault contributes nothing to the merge until re-unlocked. The
  chip says so. Accepted for v1; a per-vault timeout review for
  Spaces is future product work.
- Mobile `ON_STOP` locks inactive sessions at exactly the autofill
  moment. The active vault merges; inactive ones show as chips.
  Same accepted boundary, same future candidate (unlock-family-too
  prompt).
- Linux / Windows: a vault never unlocked this daemon session has no
  session PIN, so its chip means "type the password once". Stated,
  not hidden.
- A vault with a stale keywrap (password changed elsewhere) fails
  closed at unlock and contributes nothing.
- No new rate limits: match and search are local reads.
- Nothing from a locked or not-enabled vault ever crosses: no names,
  no usernames, no counts beyond the registered-vault lock-state
  array the chips need.

## 6. Test plan

Daemon: fan-out helper unit tests (unlocked mix, locked skip,
mid-scan lock following the `vaults.list_full_all` pattern at
`route_coverage.rs:425`, empty map, slug/name tagging). Route tests:
merged `bridge.match` shape; gate passes with active locked plus a
browser-enabled sibling unlocked; slug-scoped `vault.get` rejects
URL mismatch, unknown slug, locked vault, not-enabled vault; viewer
and pending-join vaults excluded; match payloads never contain
passwords. Extension: vitest for popup badges and slug pass-through
on all three call sites (`popup.jsx:348`, `:356`, `:398`) and the
background call sites (`background.js:230`, `:249`); a projection
test asserting the `vaults` array never reaches the inline
connection. Android: merged ranking, dataset labels, two-vault
prompt flow, stale-KEK failure, process death, inline cap. CLI: e2e
`search --all` across two vaults with one locked.

## 7. Landing order

1. Extract the shared fan-out helper from `vaults.list_full_all`.
2. `browser_enabled` registry flag, join-time ask, D-record.
3. `bridge.match` fan-out over `autofill_query`, gate change,
   matcher unification.
4. Slug-scoped `vault.get` / `cipher.totp_code`, route reorder,
   popup URL fix.
5. Service-worker projection, popup badges, locked chips.
6. CLI `search --all`.
7. Android autofill (per-handle design above).
8. Android app search merge.

Steps 1 through 6 land value for every extension user before the
Android slice begins. The desktop needs nothing; it shipped in D31.
