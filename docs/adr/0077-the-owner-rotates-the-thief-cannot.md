# ADR 0077. The Owner Rotates, the Thief Cannot

> Status: Accepted (2026-10-01)

## Context

The 24-word recovery phrase is an alternate master credential. If it leaks, the owner must be able to replace it even without the phrase. Requiring the old phrase would lock out the owner and let a phrase-only holder interfere with remediation.

## Decision

Gate recovery-phrase rotation on the current master password, never the old phrase. Verify the KEK canary, rewrap the live Root Key under a fresh phrase, and replace the escrow. Show the new phrase once and provide copy, TXT, and PDF export. Treat rotation as optional, not forced during an unrelated password change. A future password-change UI must recommend rotation without running it. A flipped team Space refuses personal phrase rotation because its recovery contract is the Space Recovery Kit and personal recovery resets the device roster.

Sync the escrow replacement through cover-commit mutations. Until it reaches the remote, the old phrase can still open the remote copy. Fail closed if the password canary file is missing. Hold the autosync cycle lock while writing the swap. Do not add rate limiting for this in-session operation or encrypt the phrase escrow separately; an encrypted escrow would move the single point of failure and likely receive less protection from users.

## Consequences

The destructive personal recovery path that resets the registry remains API-only. If exposed as a flow, it must end with Root Key rotation and a fresh phrase; rotation alone would re-arm a leaked phrase through the rewrap. Until then, rotate as soon as exposure is suspected. The exposure window lasts until rotation has synced.

## References

- ADR 0080
- Space Recovery Kit
- `change_master_password`
