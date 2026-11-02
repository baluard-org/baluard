# ADR 0018. Tag Deletion with Confirmation

> Status: Accepted (completed 2026-06-09)

## Context

Deleting a tag changes every cipher that uses it, and the change cannot be undone from the UI. A delete control that sits permanently next to each tag invites accidental clicks, so the UI must require confirmation before applying this operation without cluttering the sidebar.

## Decision

Sidebar tag pills reveal a delete control (an X) on hover. Selecting it opens a confirmation modal. On confirmation, the UI calls the `tag.delete` daemon command, whose payload is the plain tag name. The daemon requires an unlocked vault, removes the tag from every cipher that carries it, rebuilds the tag index, and returns the number of ciphers updated. The modal follows the existing `DeleteConfirmModal` pattern and uses `FocusTrap` (ADR 0015).

`tag.delete` is a mutation route like folder deletion: the daemon treats it as a vault change that triggers the cover commit and the debounced auto-sync push (ADR 0006), so affected ciphers reach other devices without a manual step. After a successful call the desktop clears the active tag filter if it pointed at the deleted tag and refreshes the cipher list. A failure is shown as a toast and leaves the state unchanged.

## Consequences

Tag deletion requires explicit confirmation and updates affected ciphers and the tag index together. The operation touches every cipher with the tag, so on a large vault it rewrites many cipher files in one change. Tags are only a label, so deletion never removes a cipher itself.

## References

- `tag.delete`
- `DeleteConfirmModal`
- `FocusTrap`
