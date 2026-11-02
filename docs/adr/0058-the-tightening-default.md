# ADR 0058. The Tightening Default (trash and restore policy knobs)

> Status: Accepted (2026-09-27)

## Context

The §6.5 policy adds `restore_policy`, whose only listed value is `admins_only`. Its serde default therefore tightens existing vaults on load and prevents members from restoring entries they could previously restore.

The keyless sync walker cannot read `settings.enc`. Policy enforcement is local, while peer admission remains grant-scoped. Permanent deletion and time-based purge are also destructive operations related to restore.

## Decision

Default `restore_policy` to `admins_only`. Show the setting on desktop and mobile, including as read-only text where the user cannot change it. Enforce trash and restore policy locally; leave sync admission grant-scoped. This asymmetry is acceptable because the local gate controls destructive intent, while sync needs to admit operations the stricter policy permits.

Apply the appropriate gate to permanent deletion and time-based purge as well as restore. The unlock-time purge is best-effort and does nothing for members. Purge is administrator-only under the §4.4 policy row, regardless of `trash_policy`.

## Consequences

Existing vaults tighten on load, and members can no longer restore trashed entries under the default. The visible setting prevents this change from being silent. A member's trash commit can still sync; an administrator performs restoration.

`join_approval` remains deferred pending a code-mode ceremony design. `quorum_admin_ops` remains deferred pending confirmation of §10 open question 1 because it touches rotation finalization.

## References

- Original record D55.
- Absent and null settings contract: ADR 0056.
