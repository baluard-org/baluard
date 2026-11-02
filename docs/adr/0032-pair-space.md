# ADR 0032. Pair Space (IS-5)

> Status: Accepted (2026-09-22)

## Context

The S1a membership machinery needs to cover the two-person Space shape. The work is slice S2-3 and was recorded as D29. An external review round produced 9 findings, including 2 blockers. The accepted findings and the one declined finding are listed below.

## Decision

**Space shape.** A Space is a vault whose slug is forced to `baluard-space-<name>` (`space_slug`, idempotent). Its plaintext `meta/settings-pub.json` carries `"space": true`, which is readable before unlock and survives renames. An absent file or field means personal. `vaults.list` rows expose the flag before unlock alongside theme and lang.

**Route.** `space.create` is host-level and mirrors `vault.create`: it inherits unlock, inserts the registry entry, and issues a session token. It rewrites the payload slug before delegation and writes the shape flag after creation.

**Pair policy.** `space::pair_gate` runs at both invite minting (`create_invite`) and join approval (`approve_join`, before any mutation, so a refusal leaves the invite intact for retry). It refuses Owner and Admin roles on a space, because a pair shares as Editor or Viewer. It also refuses a second joiner once two bound live members exist. The cap counts rows with at least one `.json` device binding and no tombstone. Both `removed` and `reset` rows are skipped. A reset predecessor keeps its bindings on disk and must not occupy the slot while the successor is pending. Unbound rows (pending joiners, reset successors) are excluded so a reset approval never blocks itself.

**Accepted review findings**

1. The member counter ignored the `reset` tombstone, so a reset predecessor's persisted bindings made the space believe it was full and permanently wedged member reset. Tombstones of both kinds are now skipped (blocker).
2. `save_settings` and `save_locale` rebuilt `settings-pub.json` wholesale and silently stripped `space: true`, which deactivated the pair gates on the next settings save. Both writers now merge with the existing JSON and preserve unknown keys (blocker).
3. `transfer_ownership` demoted the old owner to Admin unconditionally. On a pair space, a later reset of that admin would mint an invite the gate refuses, which wedges recovery. The demotion now lands as Editor on space vaults.
4. (Partial) `handle_space_create` zeroizes the master-password-bearing payload on every path, early returns included, before handing off to `vault.create`.
5. `space.create` joined the desktop Tauri IPC allowlist.
6. The device-binding count requires a `.json` entry, so it is `.DS_Store`-proof and matches `list_members`.
7. `space_slug("space")` no longer double-suffixes.

## Consequences

Declined: failing the `space.create` response when the flag write fails. The flag is a policy guardrail and not a confidentiality control. The created vault is already unlocked with a token issued (the registry-add warn precedent), and failing closed would strand the client mid-wizard with a live vault to clean up.

CLI and UI are deferred. The Family-shape silent share sheet belongs to the §4.8 wave and P1. Before P1 a Space still has its own master password. S3 owns `space.adopt` and migration for churn.

## References

- `docs/adr/0085-sharing.md` §4.6 (IS-5) and the S2 tracking row for the wave context
