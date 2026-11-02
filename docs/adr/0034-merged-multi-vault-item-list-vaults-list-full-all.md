# ADR 0034. Merged Multi-Vault Item List, `vaults.list_full_all` (S2-5)

> Status: Accepted (2026-09-22)

## Context

Users with several vaults need one combined item list. The merged call must stay under the response cap, must not weaken the browser extension's no-export boundary (ADR 0024), and must not leave stale foreign secrets on screen. The work completes S2 and was recorded as D31. An external review round produced 10 findings: 8 accepted and 2 declined, with one blocker.

## Decision

**Route.** One daemon call, `vaults.list_full_all`, returns every registered vault as a row with slug, display name, space flag, active flag, and presence.

- Unlocked vaults carry their full `vault.list_full` envelope (active row) or only the cipher list (sibling rows). Folders, trash, and tags belong to their own vault's view, and skipping them keeps the merged frame under the response cap.
- Locked and closed vaults carry metadata only.
- Rows sort by slug, because the registry is a HashMap.
- A vault that locks mid-scan degrades to a metadata row with corrected `presence` and never fails the merge.
- `VaultState::full_envelope` is the shared payload builder.

**Trust model.** The route is host-level but not pre-token. It verifies the caller's session token against the active vault's state. That is the same trust that already grants `vault.list_full` for the active vault, and sibling vaults belong to the same user. Sibling and empty tokens fail the constant-time compare. Bridge pairing tokens can never verify against a vault session, so the extension cannot pull the merge. The route is absent from `BRIDGE_ALLOWED_ACTIONS` at the NMH, daemon, and token-verification layers, so the ADR 0024 no-export boundary holds.

**Desktop**

- `VaultContext` pulls the merge alongside every cipher refresh and tags foreign ciphers with `_vault {slug, name, space}`.
- The merged list shows foreign rows with a vault-name chip in every category except trash and archive. Folder, tag, and search filters apply naturally, because foreign folder and tag ids never match the active vault's.
- Foreign entries open a read-only detail. Edit, archive, delete, and passkey delete are gated off. TOTP and attachment downloads are slug-routed to the source vault, using the desktop's per-slug token cache with sibling tokens minted at their unlock. A read-only notice points the user at the source vault.
- A sibling vault can lock (idle timer, blur policy, close) without the merge context hearing about it. Foreign rows therefore re-pull on focus regain and on a 30-second heartbeat. The daemon stays authoritative, the same design as the switcher's presence refresh.
- The sidebar All-items badge and row highlight count and compare across vaults using a composite `slug:id` key.

**Accepted review findings**

- Blocker: stale foreign secrets stayed rendered after a sibling locked or closed. The focus and heartbeat re-pull fixes this.
- Passkey delete was not gated for foreign entries.
- TOTP and attachment fetches targeted the active vault. They are now slug-routed.
- A fire-and-forget refresh race is now awaited.
- Payload-size blowout: sibling rows are trimmed to ciphers.
- A mid-scan lock left `presence: unlocked` with no payload. It is corrected to `locked`.
- Nondeterministic row order is fixed by sorting.
- Badge-count mismatch is fixed by summing across vaults.
- Row-highlight UUID collision is fixed with the composite key.

## Consequences

Foreign entries are view-only. Mutations stay slug-routed to the active vault, so no cross-vault write surface exists. Locked vaults surface as metadata rows, and unlock stays a switcher action. The mobile merged host is the S4 line item.

No review finding was declined beyond wording.

## References

- `docs/adr/0085-sharing.md` §4.6 (line 148) and the S2 tracking row
