# ADR 0012. Store Split

> Status: Accepted (completed 2026-06-04)

## Context

The desktop frontend is a SolidJS and Tailwind v4 application inside Tauri v2. All IPC goes through `daemon(action, payload)`, which calls Tauri's `invoke("daemon_request")`. IPC is strictly request and response; there is no server-sent event channel and no streaming.

The monolithic `AppContext` held 30 signals, and the `useActions` hook contained 243 lines. This coupled unrelated state and required manual signal resets on lock: `lock()` performed seven separate resets, and forgetting one would leave decrypted vault data alive in the UI after a lock.

## Decision

The desktop frontend will use two providers and standalone signals, with no external state library:

- `context/AuthContext.jsx` owns `status`, `vaultInfo`, and `biometricAvailable` for the application lifecycle. It wraps the application and owns lock, unlock, and vault creation actions.
- `context/VaultContext.jsx` owns 12 cipher, navigation, device-fleet, and settings-modal signals. It mounts only while the application is unlocked.
- `context/errorSignal.js` provides a global error signal consumed by the auth and vault layers.
- `context/themeSignal.js` provides theme state that survives lock and unlock, and synchronizes the document body class and local storage.
- Component-local `createSignal` state holds values consumed by one component subtree, such as cipher views and delete confirmation in `VaultView`, and reprompt state in `RepromptModal`.

`I18nProvider` wraps `AuthProvider`. The app renders the locked, initialization, recovery, or unlocked screen according to auth state, and each pre-unlock screen consumed the auth context plus the global error signal. The unlocked screen mounts `VaultProvider` around `VaultView`, which uses the auth context, the vault context, and its own local signals. The auth provider owns three signals and co-locates lock, unlock, and vault creation. The vault provider owns twelve signals and co-locates cipher CRUD. At the time of the split, six further signals were component-local, in `VaultView` and `RepromptModal`.

The structural reset is the central mechanism. `VaultProvider` mounts inside a `<Show when={status() === "unlocked"}>` boundary. Locking sets `status` to `locked`, which unmounts `VaultProvider` and destroys all 12 vault signals and the six local signals automatically. The lock action therefore performs only two resets (`setStatus` and `setVaultInfo`) instead of seven, and it is impossible to forget a signal because new vault state lives under the unmounted subtree by construction.

Actions are co-located with their stores; `useActions.js` is removed. A signal consumed by exactly one component subtree remains local, while context is used only for cross-component communication.

## Consequences

Unmounting the vault provider resets vault state as part of the UI lifecycle and removes the need for manual resets of each signal. No cross-store compound actions remain after the split. The same boundary is the reason later providers that hold vault-scoped data (conflict queue, auto-sync, agent approvals) are mounted inside the unlocked subtree, and why a keep-unlocked vault switch needs explicit clearing where the provider survives the switch (see ADR 0093).

The record describes the structure as decided on 2026-06-04. The implementation has since grown and differs in detail, and the code is authoritative:

- `context/errorSignal.js` no longer exists. Errors and warnings are shown through the toast signal (ADR 0017).
- The auth state machine has eight states, because a `welcome` state was added in front of `init` (ADR 0020 records the seven-state wizard).
- `VaultProvider` now has many more signals than twelve, and other providers (`UpdateProvider`, `VaultSwitcherProvider`, `AutoSyncProvider`, `ConflictResolutionProvider`, `AgentApprovalProvider`) wrap or sit inside it. The two-provider rule (auth, vault) plus standalone signals still holds as the organizing principle.

## References

- ADR 0013 for the refactors and frontend constraints that followed.
- ADR 0101 for the original Domain 7 grouping.
