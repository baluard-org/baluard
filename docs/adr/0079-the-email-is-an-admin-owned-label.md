# ADR 0079. The Email Is an Admin-Owned Label

> Status: Accepted (2026-10-01)

## Context

Display names are self-chosen, changeable, and can be used to impersonate others. Email is a more stable display label, but neither a self-claimed nor provider-fetched address proves mailbox ownership after serialization to peers.

## Decision

Make email an optional, decorative, admin-owned member-row field. A member may declare it during join introduction; normalize it through an advisory shape check. Admin approval writes it onto the row, reset successors inherit it, and only admin-gated `members.set_email` may correct it. Sync the change through COVER and emit `MemberEmailChanged`. Freeze email deltas beside ID, display name, role, and trust. Require a full signed identity rotation for any own-subtree member-row rewrite, so members cannot set or change their own email.

Do not use email for permissions, URI matching, or transport. Display it as muted secondary text in People rows, approval inboxes, grant and group target pickers, access review, and desktop and mobile join forms. Preserve signed contact-card verification by appending the email payload line only when present. GitLab and Codeberg may populate a local convenience value from the `/user` response already fetched; GitHub remains empty because `user:email` scope is not requested. Provider autofill does not sync as a verified fact. Use `create_introduction_with_email` as a delegating wrapper to avoid changing numerous test call sites.

## Consequences

The shape check proves nothing about mailbox ownership, and email is never a verified attribute. Contact cards without email remain byte-exact under the existing signature format. Provider autofill is local convenience only.

## References

- `members.set_email`
- `MemberEmailChanged`
- `create_introduction_with_email`
