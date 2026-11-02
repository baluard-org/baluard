# ADR 0098. Merged Search and Autofill Across Vaults

> Status: Accepted (2026-10-09). The plan was drafted on 2026-10-05; all nine landing steps (fan-out helper, consent model, bridge fan-out, slug-scoped reads, extension surfaces, CLI search, Android autofill, Android app search, slug-routed writes and unlock requests) have landed by this date.

## Context

Baluard keeps each vault's master password and key hierarchy independent, and a joined Space (family, organization) is a separate vault. Users expect what other password managers offer: autofill and search list all entries together, with a badge for the origin vault. Users may keep personal and family vaults unlocked together and expect search and autofill to find entries across them. Organization entries must remain separate from personal surfaces: companies do not want personal and company items mixed, so organization entries never surface in a member's personal search or autofill, and organization Spaces keep the vault-switch friction on purpose.

Before this decision the surfaces stood as follows. The desktop already merged: `vaults.list_full_all` fans out over unlocked vaults, the frontend tags foreign ciphers with their vault, and the list renders a vault chip (ADR 0034). That desktop merge mixed every unlocked vault, including organization Spaces, so it had to be retrofitted to the same eligibility rule, otherwise organization members would meet friction in the extension and none on the desktop. The browser extension was single-vault: `bridge.match` resolved against the active vault only, and it called a list-all path that decrypted and serialized every cipher including passwords on every tab event, with a loose hostname matcher. Android autofill held one vault in its isolated process. Mobile application search covered the active session only. The CLI had no search.

The daemon supports multiple unlocked vaults. The desktop blur policy locks only vaults whose auto-lock policy is `Immediately`, so a typical personal-plus-family pair stays open side by side. The mobile main process holds at most three unlocked sessions (`MAX_UNLOCKED = 3`, least-recently-used eviction), but locks every inactive session when the application stops, which is exactly when autofill runs. Quick unlock is per vault: biometric keys on macOS and Android, and on Linux and Windows a session PIN that exists only after a master-password unlock in the current daemon session. The extension bridge authenticates with a pairing token and is gate-checked against an allowlist (`BRIDGE_ALLOWED_ACTIONS`) that has no unlock route. The bridge must not gain access to whole-vault payloads (`vaults.list_full_all` is deliberately absent from the allowlist) and must not accept a master password, because the application collects exactly one credential in its life. Android autofill runs in a separate process and must preserve per-vault biometric authorization and the rule that the Argon2id master KDF never runs there. No index may reveal domains or usernames while vaults are locked.

## Decision

### Eligibility and consent

Use one daemon fan-out helper for eligible vaults (`merge_fanout_rows`, fail closed when the registry cannot be loaded). It returns eligible vaults only; a vault that locks mid-scan degrades to a locked row. The personal vault is always eligible. A Space is eligible only when its synced merge ceiling is enabled, the device-local opt-in is enabled, and no removal notice (ADR 0076) stands against the device. The decision function is `VaultRegistry::merge_eligible`, and every consumer calls it.

The synced ceiling is `personal_merge: Option<bool>` on `VaultSettings`, written by an owner or admin through the existing Space settings plumbing. Absence fails closed, and its default follows the stored Space purpose: family Spaces default to merge-enabled and organization Spaces to disabled. The device registry stores `merge_opt_in: Option<bool>`, which defaults on at join only when the ceiling is on and may be turned off per device at any time, and `merge_ceiling_seen: bool`, a cache of the last observed ceiling refreshed at every unlock and settings pull so that a locked vault can be classified without decrypting it. A Space never unlocked on this device has no cache and is therefore ineligible: it fails closed and never nags. A ceiling turned on later is a one-time ask and never auto-on.

Space classification uses the union of stored purpose (`family` or `org`, in plaintext `meta/settings-pub.json`), flipped team shape, and the legacy `space: true` flag. Purpose sets defaults; `personal_merge` is the enforcement setting and an optional override whose absence follows the purpose. Purpose became a stored field once it gained consumers beyond merge defaults (minors, kits, departure, the pair-gate split), which supersedes the earlier idea of storing no Space kind (see ADR 0086). Classification must include flipped organizations, which are created as plain vaults and flipped later, carrying neither purpose nor the legacy flag; classifying on the flag alone would silently make every organization merge-eligible. The creation wizard asks one plain-language question ("Who is this space for? Family or home / Work or organization") whose answer only sets the default.

The ceiling is a guardrail for honest clients, not data-loss prevention. A member who holds the keys can read and copy items regardless of this setting; the real organization controls are `allow_viewer_export`, `guest_enabled`, and quorum. Apply the same predicate to daemon fan-out, `vaults.list_full_all`, desktop badges, CLI search, mobile search, and autofill. An ineligible Space keeps its metadata row (slug, name, lock state) where vault management needs it, including the active row, but carries no ciphers or match metadata. A removal notice makes a Space ineligible immediately because it is local; a changed synced ceiling takes effect after the next pull.

### Extension autofill

The extension `bridge.match` fans out over `VaultState::autofill_query`, which returns login matching data without passwords and applies `UriMatchStrategy` and equivalent-domain rules, including custom equivalent domains. One matcher serves every surface: the loose handler hostname matcher retires, and the fill-time origin check uses the same matcher (`VaultState::cipher_matches_uri`). Each match carries `vault_slug` and `vault_name`; the response's `vaults` array lists eligible vaults only, with slug, display name, and lock state, so surfaces render unlock chips without a second call. The route returns match metadata only, never passwords and never whole-vault contents, and requires no session token beyond the bridge pairing token. It must not become a path to data shaped like `vaults.list_full_all`.

The bridge gate requires at least one eligible unlocked vault, not that the active vault be unlocked; otherwise the route would report locked whenever the personal vault sleeps while the family vault is open. Slug resolution (`host.snapshot_target(slug)`) must happen before per-vault matching and before the delegated token stamp binds the active state.

Slug-scoped reads use `vault.get {id, url, vault_slug}` and `cipher.totp_code {id, url, vault_slug}`. The daemon resolves the target vault before every gate and repeats URI matching against it. Locked, unknown, disabled, ineligible, or removal-notice vaults fail closed. The URL is required on slug-scoped reads: the popup formerly called `vault.get {id}` without a URL, which skips URL matching for entries without URIs, and a compromised extension page must not read an arbitrary entry from any enabled vault by id alone. Calls without a slug target the active vault. Cipher IDs are per-vault UUIDs, so the slug disambiguates.

The service worker projects inline page-principal results to `{id, name, username, vault_slug}`. The `vaults` array and vault names must not cross into the page, because the inline menu renders inside page context; they remain in extension-owned UI. The inline menu shows a neutral "from another vault" marker only when two or more vaults contribute. Popup surfaces show vault labels and locked-vault chips, and the toolbar badge counts across eligible vaults. Chips list eligible vaults only: an organization Space never renders an unlock chip on a member's personal surface, and a Space under a removal notice reads "You may no longer have access to this space" and offers detach. Unlock requests use `bridge.request_unlock {slug}`, which is allowlisted for the bridge, plus desktop peek and take routes: the extension's locked chip asks, the desktop banner (login screen and vault view) offers Unlock or Not now, and the user's approval is the unlock. No unlock route ever accepts a credential from the extension.

Bridge writes target the active vault unless an explicit `vault_slug` is supplied. Slug-routed `vault.add` and `vault.update` resolve the target before the gates, then apply the same eligibility and unlock requirements as reads, plus the existing write-scope and role checks against the target vault (Editor and above through the bridge write-role check; Viewer refused). This covers the common family case, such as a rotated shared Wi-Fi password, where an active-vault-only rule would leave the shared entry stale.

### Android and mobile

Android autofill opens one handle per discovered vault in its own `:autofill` process. Each handle uses the existing per-vault biometric flow with a per-vault Keystore alias and per-use `CryptoObject`, and `unlock_with_kek`, never the master KDF, so the out-of-memory invariant holds. Prompts are sequential and explicit: a cold session costs one biometric prompt per vault. Results rank together into one dataset, carry the vault name when two or more vaults contribute, and selection reads credentials from the owning vault (`credential(path, id)` and `totpCode(path, id)`). Inline suggestions retain the maximum of five. App-trust stays per vault, so an app trusted in the personal vault re-prompts before family suggestions appear.

Rejected alternatives for Android: time-bound Keystore keys (one prompt authorizing all vault keys for a few seconds, which trades away per-use cryptographic binding), and a bound service into the main process (that process locks everything when the application stops).

Mobile application search fans out over other still-unlocked sessions up to the existing `MAX_UNLOCKED = 3`, filtered by a keyless eligibility check in Kotlin (family purpose merges; organization, pair, flipped shapes, and damaged files fail closed). Results show per-vault section headers and open the owning vault on selection. Foreign matches use names and usernames only; the deep-content index, folders, and tags remain scoped to the active vault.

### CLI

`baluard search --all` fans out over unlocked eligible vaults and prints slug-tagged rows. `baluard search --vault <slug>` is explicit single-vault search, the CLI form of switching vaults, and works for organization Spaces. Both ride the daemon `vault.search` host route, which is token-gated in place against the active vault (the same trust as `vaults.list_full_all`) and matches names and usernames only.

### Ranking and display

Ranking orders exact host matches first, then personal results, then Spaces by favorite, name, and vault slug as the stable tiebreak. Spaces rank below personal because favorite is a shared field inside a Space, and a stranger's favorite must not outrank the user's own login. No cross-vault deduplication occurs: two logins for the same site from personal and family both show and the user chooses, because nothing autofills on page load. Badges appear only when two or more eligible vaults contribute, so a personal-only user or an organization-Space user sees no merge machinery. Organization Spaces do not appear in personal search or autofill unless the member explicitly searches that vault through the CLI.

### Rejected alternatives

A shared device secret that unlocks every vault was rejected: it contradicts the sharing principle that one cracked laptop must not yield every Space (ADR 0085), and each vault keeps its own device identity and wrap key. Per-vault quick unlock is the answer to the second password. A cached index readable while vaults are locked was rejected: it needs a key outside any vault secret and stores domains and usernames at rest. A keystore-sealed set of domain hashes ("Family has a login for this site") remains a possible future option. No crypto change, no change to the one-master-password-per-vault invariant, and no new desktop surface are part of this decision. A keyboard palette is optional polish and not planned.

### Failure modes

| Condition | Behavior |
|---|---|
| Desktop blur locks an `Immediately`-policy vault (using the extension means the desktop window is blurred) | The vault contributes nothing until re-unlocked and its chip says so. A per-vault timeout review for Spaces is future product work. |
| Mobile application stop locks inactive sessions at the autofill moment | The active vault merges and inactive ones appear as chips. A future unlock-family-too prompt is a candidate. |
| Linux or Windows vault never unlocked this daemon session | No session PIN exists, so the chip means "type the password once". |
| Stale keywrap (password changed elsewhere) | Fails closed at unlock and contributes nothing. |
| Ceiling turned off by an admin | Reaches a device at its next pull; a stale device keeps merging until then. Accepted because the member holds the keys anyway. |
| Removal notice | Local and immediate. |

No new rate limits apply because match and search are local reads. Nothing from a locked, ineligible, or disabled vault crosses any boundary: no names, no usernames, and no counts beyond the eligible-vault lock-state array that chips need.

### Test requirements

Daemon: fan-out helper tests (unlocked mix, locked skip, mid-scan lock, empty map, slug and name tagging, ineligible Space rows carrying metadata but no ciphers). Route tests: merged `bridge.match` shape; the gate passes with the active vault locked and an eligible sibling unlocked; organization entries absent from the `vaults` array and chips; slug-scoped `vault.get` rejects URL mismatch, unknown slug, locked vault, ineligible vault, and removal-notice vault; viewer and pending-join vaults excluded; match payloads never contain passwords. Consent: ceiling off at join (no prompt, no merge), ceiling turned on later (one-time ask, never auto-on), ceiling turned off (ineligible after the next pull), removal notice dropping eligibility immediately, and `personal_merge` surviving the policy validation round trip and riding the daemon integration lists (cover mutations, token-gate pins, desktop allowlist, frontend mutation list). Extension: tests for popup badges and slug pass-through on every call site, plus a projection test asserting the `vaults` array never reaches the inline connection. Android: merged ranking, dataset labels, two-vault prompt flow, stale-KEK failure, process death, inline cap. CLI: end-to-end `search --all` across two vaults with one locked, and `search --vault` against an organization Space.

A wire bug was fixed along the way: `cipher.totp_code` parsed a bare UUID while the extension sends JSON, so TOTP fill had been silently dead.

## Consequences

Search and autofill can use multiple unlocked vaults without sharing device secrets or weakening per-vault quick unlock. The extension receives only scoped match data, and the match route no longer decrypts every cipher on every tab event. Organization separation is consistent across desktop, mobile, CLI fan-out, and browser surfaces.

A vault locked by desktop blur or mobile lifecycle contributes no entries until it is unlocked. A vault without a session PIN may require its master password once during that daemon session. Changes to the synced merge ceiling are not immediate until the next pull; removal notices are immediate. These are explicit consequences of local keys and sync-based policy.

A merge operation is not an access-control boundary. It only controls which entries an honest client presents together. No locked-vault search index is stored. Existing desktop behavior changes for organization members, whose Space no longer appears in the merged personal list.

## References

- `docs/adr/0034-merged-multi-vault-item-list-vaults-list-full-all.md`, the desktop merge this decision retrofits.
- `docs/adr/0076-notice-never-wipe.md`, the removal notice.
- `docs/adr/0085-sharing.md`, per-Space key isolation.
- `docs/adr/0086-family-spaces.md`, purpose and classification.
- `crates/baluard-runtime/src/state.rs`, `autofill_query`.
- `crates/baluard-core/src/vault/registry.rs`, `merge_eligible`.
- `crates/baluard-daemon/src/handler.rs`, merge fan-out and scoped routes.
- `crates/baluard-core/src/bridge/token.rs`, bridge allowlist.
