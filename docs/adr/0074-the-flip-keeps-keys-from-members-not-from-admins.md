# ADR 0074. The Flip Keeps Keys from Members, Not from Admins

> Status: Accepted (2026-09-30)

## Context

After a vault is flipped to team shape, members must not hold the Root Key, while admins still need keys to administer the Space. The invite and unlock paths initially ignored role, preventing elevated joiners from acting as admins. A reset admin's old device also retained a keywrap and could otherwise pass an admin-role check.

## Decision

Make flipped key handling role-scoped. On invite, write a keywrap for elevated joiners when `!flipped || elevated`. Unlock through the admin path only when the device maps to a live admin and its own keywrap file exists. The keywrap-existence check fails closed and prevents a legacy no-binding fallback from entering the admin path; copied keywraps remain HPKE-bound to the target device key. Elevated members use their own password and the member canary. Before the approval commit is pulled, the member tail refuses with sync-and-retry. The keywrap and member row are written in one approval commit.

Define `device_maps_to_admin` as a live-role predicate: `reset.is_none() && removed.is_none()`. All consumers, including unlock dispatch, rotation staging, rekey adoption, and keywrap stripping, use it. The flip's key-strip loop and rotation staging were already role-aware; invite and unlock were updated to match. No role-edit route exists; reset and remove tombstone and rotate.

## Consequences

Members hold no Space keys after the flip, while elevated members can administer it with their own keywrap. An elevated member device runs the admin convergence pass, which is role-legal and inert on a clean clone. Reset or removed admins cannot use retained keywraps to bypass the member-tail lockout. Admin demotion is not independently supported.

## References

- `device_maps_to_admin`
- `reset_locks_out_elevated_member_on_flipped_vault`
