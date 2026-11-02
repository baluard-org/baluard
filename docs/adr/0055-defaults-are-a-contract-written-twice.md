# ADR 0055. Defaults Are a Contract Written Twice (§6.5 Space settings and provider gate)

> Status: Accepted (2026-09-27)

## Context

Three §6.5 Space settings were added to encrypted settings. The `guest_enabled` default differed by construction path: serde supplied true while the struct's derived `Default` supplied false.

The viewer-export gate also treated an unresolved member role as a legacy founder in every case. `member_role_for_device` returns `None` both for a legacy vault without a member directory and for a tombstoned member.

Provider readiness for organization-shaped Spaces depends on provider-specific ownership, application approval, scope, seat, and terms constraints.

## Decision

Represent `guest_enabled` with the existing Option-toggle convention: `None` and `Some(true)` mean enabled. This keeps deserialization, derived defaults, and manually built values consistent.

Treat a missing role as legacy founder only when the member directory does not exist. On a strict vault with a member directory, unresolved roles refuse viewer export.

Record organization-Space readiness per provider in `docs/adr/0088-git-providers-multi-vault.md`. The checklist records repository ownership, app approval, scope, seat, and terms-of-service fit. Its findings are: GitHub private repositories have no code-only restriction; GitLab's free tier limits new top-level private groups to five members; Codeberg's 100 MiB non-promoted bucket and FLOSS-mission clause make it personal-only.

## Consequences

The settings default is consistent across construction paths, and a tombstoned member's still-open session cannot export the vault as a founder. Organization readiness is based on recorded provider constraints rather than assumptions.

`join_approval`, `quorum_admin_ops`, `trash_policy`, and `restore_policy` remain unimplemented in this record. The settings had routes but no UI. Organization-shaped Spaces remain gated on the provider checklist.

## References

- Original record D52.
