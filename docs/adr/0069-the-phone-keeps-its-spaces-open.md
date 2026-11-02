# ADR 0069. The Phone Keeps Its Spaces Open

> Status: Accepted (2026-09-29)

## Context

Mobile needs to keep multiple Spaces unlocked. A `MobileVaultHost` UniFFI object modeled on desktop `VaultHost` would include daemon-specific active-pointer and 30-second walker behavior that mobile does not have. The required per-vault exports already exist: `unlock`, `unlockWithKek`, `lock`, `isUnlocked`, and `shouldAutoLock`.

## Decision

Coordinate sessions in the app layer behind `AuthViewModel`, with no Rust changes. `MultiVaultSession` is a bounded access-order map from path to handle and retained KEK, with a maximum of three sessions. The vault switcher can adopt a cached, still-unlocked target without another unlock ceremony. `openAndUnlock` always verifies the password.

Only the on-screen vault remains unlocked across backgrounding. `ON_STOP` locks inactive sessions, and the auto-lock poll enforces each session's `shouldAutoLock` through `enforceAutoLock`. Eviction and adopt-replace lock the superseded handle. The `sessionKek` getter returns a copy; the session wipes its own buffer on lock or eviction. The switcher's slow path clears the conflict queue as `doAutoLock` does.

## Consequences

The three-session limit is constant. A fourth Space requires another unlock ceremony. Session entries do not survive process exit. Resident keys are held for at most three vaults, Argon2id remains transient and user-serialized, and the `:autofill` process retains its KEK-only path. Per-vault biometric quick unlock is unchanged and remains available across process exit.

## References

- Desktop `VaultHost`
- `AuthViewModel`
- `doAutoLock`
