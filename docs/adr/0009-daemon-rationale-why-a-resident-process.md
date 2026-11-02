# ADR 0009. Rationale for a Resident Daemon

> Status: Accepted

## Context

Every mainstream competitor ships a daemonless desktop app: an Electron or standalone process holds the cryptography in-process, and the browser extension integrates through native messaging aimed at the app itself. That single-app model is viable and proven. Baluard keeps a daemon anyway. The split adds packaging complexity but establishes a process boundary around key material and a single synchronization writer, and the reasons below outrank the simplicity a single process would buy.

## Decision

The vault engine will run in a separate daemon process, owned as a sidecar by the desktop application. It is not folded into the UI process. The daemon is the only process that holds the KEK, Root Key, and Space Group Keys (SGKs). The reasons, in priority order:

1. **Key-process isolation (the load-bearing reason).** The desktop webview parses remote-influenced content, including favicons, imported files, and entry strings. A decoder or rendering flaw in the UI tier can reach displayed plaintext and the clipboard, but not key material. Keeping `baluard-runtime` inside the application process would convert a compromised UI into a compromised vault. Bitwarden accepts this exposure because its cryptography already runs in the renderer; Baluard does not require that design.
2. **Single synchronization writer per machine.** The daemon is the sole synchronization writer for the on-disk repository, and its `cycle_lock` prevents parallel synchronization cycles (ADR 0006). Without the daemon, the NMH and CLI would run commit, pull, and push cycles in separate processes. Git file locks serialize raw writes but not semantic intent, so concurrent cycles would churn merge conflicts and race on `sync-state.json`. Bitwarden's server arbitrates per-object revisions, while a Git remote arbitrates far less. With the weaker arbiter, a single writer is not optional.
3. **One unlocked session, three clients.** Desktop, CLI, and the browser extension's NMH relay share the daemon's unlocked vaults and bridge tokens, so the user unlocks once for all three. Per-client sessions would give each process its own key material and its own unlock flow, as the Bitwarden CLI and extension do today.
4. **Capability enforcement for the webview.** The action allowlist and forbidden-key filter in the desktop bridge (ADR 0008) are effective because the webview is a client of the daemon socket and authority and key material remain on the daemon side. Trust boundary and capability boundary coincide. In-process, the allowlist would become advisory.
5. **Deterministic teardown.** Quitting the app stops the daemon, and the daemon locks every vault and zeroizes keys on SIGTERM. No key material outlives the UI lifecycle, and no second process lingers with secrets in memory.

**Alternative rejected.** Hosting the daemon role inside the desktop application process, serving the socket in-process, was evaluated together with a daemonless native UI toolkit and rejected on points 1 through 3. Availability was not the differentiator, because the extension is gated on the running application either way: the sidecar dies with the app. The differentiators are key isolation, a single sync writer, and the shared unlocked session.

**Lifecycle.** The daemon is a Tauri sidecar. The app starts it on launch, or adopts a healthy same-version daemon that another client already started, and it replaces a stale or unresponsive one (ADR 0008). Quitting stops a daemon the app spawned and waits for it to exit, and an adopted daemon has its vaults locked over the socket. NMH and CLI do not start the daemon: NMH fails closed if the socket is unavailable, and the CLI directs users to `baluard-daemon` or `--direct`. Closing the window hides it to the system tray, with an optional macOS Dock presence, and leaves the daemon running so debounced pushes, periodic pulls, and conflict resolution continue while the UI is hidden. Quitting the application stops everything: there is no background Git synchronization and no headless operation after quit. Synchronization is tied to the application lifecycle by design.

A standalone headless daemon, started by system autostart with synchronization and no UI ever, is technically possible because the binary runs on its own. It is not built and not planned. It would give up the zeroize-on-quit guarantee in point 5 and needs its own threat model, since keys would stay resident while the user believes the application is closed.

## Consequences

The process boundary protects key material from UI-process compromises and gives synchronization one writer. Desktop, CLI, and NMH clients share one unlocked session. Synchronization stops when the application quits. A headless mode remains unbuilt because it would remove the current key-zeroization-on-quit lifecycle guarantee. The boundary is a boundary against the UI process, not against other processes of the same OS user: they share the UID and reach the same socket, and the per-vault session token is the remaining control.

## References

- `cycle_lock` in the auto-sync coordinator (ADR 0006)
- Webview action allowlist and forbidden-key filter (ADR 0008)
- `desktop/src-tauri/src/daemon_ctl.rs`
- `docs/security/threat-model.md`
