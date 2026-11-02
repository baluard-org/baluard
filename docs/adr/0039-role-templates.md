# ADR 0039. Role Templates (S3-4)

> Status: Accepted (2026-09-24)

## Context

Admins repeat the same invite setup (role plus collection grants) for many members. A reusable preset removes that work, but it must not let a later edit or deletion change pending invites, and it must not create grants the git policy would reject. The work is slice S3-4 and was recorded as D36.

## Decision

**Template.** An admin-defined reusable invite preset: `RoleTemplate {id, name, role, grants, created_at}`, where each grant is `{collection_id, access, expires_in_days}`. Storage is one sealed blob at `meta/templates.enc` under a root-key HKDF (`baluard-role-templates-v1`, purpose `role-templates-v1`). It rides the `meta/**` Admin git-policy row like collections. Caps: 64 templates, 100 name characters, 64 grants. A missing store loads as empty, so legacy vaults work.

**The invite is the contract.** Inviting with a template embeds a snapshot (`EmbeddedTemplate`) in `PendingInviteFile` at mint time, with a fail-closed cross-check that the picked role equals the template's role. Approval applies the embedded grants and never re-reads `templates.enc`, so deleting or editing a template after minting changes nothing pending. Grant application is best-effort and fails toward less access: missing collections are skipped with a warning, and each applied grant mints the ADR 0038 per-member wrap immediately. Expiry is converted to an absolute `expires_at` at approval time (now plus days). Rotation re-seals the store in both rekey paths (read old, then resave).

**Fail-closed parsing.** A present-but-mistyped value refuses. This covers a negative or non-integer `expires_in_days` (which would have silently become permanent access), a non-string `template_id` (which would have silently minted a template-less invite), and a non-array `grants`.

**Access.** `templates.list` is open to unlocked members. Create and delete are admin-gated. List is correctly not in `COVER_MUTATION_ACTIONS`.

**Viewer plus write is unmintable.** The git policy floor for cipher commits is Editor, so a Viewer holding a write grant would pass locally and wedge their sync at peer verification (the wave-10 wedge class). `validate_template` refuses a Viewer template with write grants, and `upsert_grant` refuses a write grant to a Viewer-role member at the root. This covers the template path and the plain grant route. Template names also reject line breaks, following the newline discipline shared with contacts and members.

**Approval-side grant cap.** A git-synced invite file carrying more than `MAX_GRANTS_PER_TEMPLATE` entries is tampering. The approval peek phase refuses it before any mutation, so a hostile invite cannot run unbounded encrypt and wrap work under the vault lock.

## Consequences

Templates are advisory presets and not policy. Live access is still governed by grants and the git policy table. There is no template versioning or audit trail, because the activity log records the join and not the template. The UI surface rides the later §4.8 sharing-surfaces wave.
