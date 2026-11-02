# ADR 0022. Phase 6 Multi-Vault Switching

> Status: Accepted (2026-06-17)

## Context

Before Phase 6 the daemon held a single `Arc<VaultState>`, so only one vault could be open at a time. Phase 6 of the git providers and multi-vault plan replaces that with a keep-unlocked, switch-pointer model. The change was implemented as record D19-bis.

## Decision

`VaultHost` wraps a single `RwLock<VaultHostInner>` over `vaults: HashMap<String, Arc<VaultState>>` and `active: Option<String>`. One lock guards both, so there is no two-lock race and the invariant that `active` is always present in the map is provable.

- `vaults.switch` is a pointer flip. It validates the slug and sets `active` under one write lock, and touches the registry `last_opened` outside the lock. It performs no zeroization and no token change.
- Session tokens are per vault. `vault.unlock` returns `{slug, token}` and the desktop keeps a `Map<slug, token>`. The token check is per vault, so a vault A token is rejected for a vault B operation.
- The handler snapshots the target `Arc<VaultState>` once per request, so a mid-request `switch` cannot cause a TOCTOU error.
- `vaults.close` drains the `Arc`. It removes the entry, clears `active` if needed, and returns immediately. In-flight handlers finish and zeroize on the last drop.
- The auto-lock walker iterates the map every 30 seconds and applies each vault's own `auto_lock_minutes` and `last_activity`. When the active vault auto-locks, `active` is left pointing at it, so the user sees the re-unlock screen and not the vault picker.
- Cover-commit timers are per vault and keyed to the locked or unlocked state, never to `active`. A switch touches no cover timer.
- The desktop locks all vaults on Tauri `WindowEvent::Focused(false)`. It clears its token cache and refreshes on focus regain.
- `log_mlock_budget` logs the aggregate resident key bytes (96 B per vault for RootKey and SGK) and `RLIMIT_MEMLOCK` after every unlock.

## Consequences

OS suspend, screen-lock, and lid-close hooks are not implemented. They are documented as follow-up work: macOS `NSWorkspace`, Linux login1 D-Bus `PrepareForSleep`, and Windows `WM_POWERBROADCAST` and `SessionSwitch`.

## References

- `docs/adr/0088-git-providers-multi-vault.md`, Phase 6, for the full design and acceptance criteria
- `crates/baluard-runtime/src/host.rs`
- `crates/baluard-daemon/tests/phase6_switching.rs`
