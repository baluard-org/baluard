# ADR 0023. Quick Unlock: Per-Vault Biometric Scoping + Session PIN

> Status: Accepted (2026-06)

## Context

The earlier design used a single global keychain entry named `quick-unlock`. In multi-vault setups this was a privacy bug: enabling biometric unlock on vault A also unlocked vault B through the same OS keychain entry. It was also wrong for the common case where one vault supports Touch ID and another must require the master password only. This was recorded as D20.

## Decision

Quick unlock is split into two mechanisms, and both are per vault.

**A) Per-vault biometric (master-password escrow in the OS keychain)**

- The keychain account is `quick-unlock:<vault_id>` instead of `quick-unlock`. The `vault_id` is a deterministic UUID derived from the KDF salt (`VaultHandle::derive_vault_id` and `vault_id_for_path`). It is stable across vault renames and git sync.
- macOS uses `security-framework` v3. The secret is stored with `SecAccessControl(BIOMETRY_ANY)`, so Touch ID or the passcode is required on every read.
- Linux uses the `keyring` crate with the `linux-native-sync-persistent` backend and `crypto-rust`, a pure-Rust Secret Service client. No libsecret build dependency exists; a Secret Service provider must be available at runtime.
- Windows uses the `keyring` crate with the `windows-native` backend (Credential Manager and DPAPI). Credential Manager is not biometric-gated per read, which is why the session PIN fallback exists.
- The legacy global `quick-unlock` entry predates per-vault scoping; no supported build writes it and no startup wipe exists. Per-vault entries are deleted when the vault's data directory is removed (`vaults.detach --delete-from-disk`, CLI `vaults prune`), unless another registration shares the `vault_id`.
- Routes: `vault.biometric_status` (not token-gated), `vault.biometric_enable` and `vault.biometric_disable` (token-gated), and `vault.biometric_unlock` (host-level, not token-gated).

**B) Session PIN (fallback for Linux and for Windows without Hello)**

- The PIN state is in memory only. `PinEscrow` on `VaultState::pin` holds the Argon2id-derived KEK and an Argon2id verifier over the PIN. Both are zeroized on drop and never written to disk.
- PIN unlock skips the Argon2id master KDF. It calls `VaultHandle::unlock_with_kek`, which still verifies the keywrap and canaries, so a stale KEK (for example after a master password change on another device) fails closed.
- The PIN is session-bound. It dies on daemon restart or vault close. It survives soft-lock because the escrow is a separate `VaultState` field from the handle.
- After `pin::MAX_PIN_FAILURES` (5) wrong PINs the escrow is destroyed and the master password becomes mandatory. The 10^6 keyspace cannot be brute-forced through this in-process cap.
- Routes: `vault.pin_status` (not token-gated), `vault.pin_enable` and `vault.pin_disable` (token-gated), and `vault.pin_unlock` (host-level, not token-gated, mirrors `vault.biometric_unlock`).

**Desktop frontend.** The login screen queries `vault.biometric_status` and `vault.pin_status` (slug-routed, safe before unlock) and shows whichever buttons are enabled for the selected vault.

**Vault detach.** Detaching a vault (dropping its registry entry) is exposed in the `VaultSwitcher` dropdown through `DetachVaultModal`. The destructive arm (`delete_from_disk`) is deliberately not exposed in the UI. Only the safe, reversible detach is. The power-user escape hatch is the CLI: `baluard vaults detach <slug> --delete-from-disk`, gated by slug retyping and the daemon-side `.baluard` marker check. The daemon route `vaults.detach` still supports both flags for the CLI caller.

## Consequences

Biometric is the primary experience on macOS. Linux has no biometric keychain, so the in-memory PIN fills the same role (cheap re-unlock while the daemon is alive) without weakening the master-password-derived KEK chain. Windows without Hello gets the same PIN fallback.

The PIN dies on daemon restart, so the user must enter the master password after a restart. After the 5-strike destruction there is no soft recovery path.

The UI is free of destructive actions until a future revision may add a destructive arm gated by a master-password reprompt.
