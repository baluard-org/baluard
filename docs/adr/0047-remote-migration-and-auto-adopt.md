# ADR 0047. Remote Migration and Auto-Adopt (S3-8)

> Status: Accepted (2026-09-26)

## Context

A Space's git remote is transport and may need to move. Followers must not adopt a remote until it contains the history they need. Pointer data must also be authenticated as committed state before it changes a device's remote.

An automatic move to a hostile host could expose provider credentials during an authentication challenge. Failed migration attempts must preserve local user work.

## Decision

The administrator migrates a remote in this order: push the full history to the new remote, publish a plaintext pointer commit to the old remote for peers still following it, repoint the administrator's origin, and publish the pointer at the new address. Followers read the pointer from verified committed HEAD on their next pull and follow automatically only within the same forge host.

Cross-host moves require the explicit `vaults repoint` command. Provider credentials are host-gated at the credential callback and refused for hosts outside the provider's enrolled instances. Environment-variable and file tokens have no enrolled-host list; they rely only on the same-host follow gate and remain an explicit-choice residual.

Migration rollback does not use `reset --hard` on a commit that `commit_all` may have included user work in. A failed migration leaves its commit local and unpushed; a retry converges on top of it.

## Consequences

Followers only adopt a remote after its referenced history is present. A cross-provider migration requires the new provider to be connected before followers can fetch. A pointer to a repository the administrator cannot push to can strand followers until a newer pointer or manual repoint is available; commit signature verification remains in force.

Environment-variable and file tokens remain outside enrolled-host credential checks. Organization settings and readiness remain deferred.

## References

- Original record D44.
