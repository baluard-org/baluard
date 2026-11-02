# ADR 0008. Desktop Tier: Client-Server IPC Socket

> Status: Accepted

## Context

The desktop application needs a secure local interface shared by its UI and CLI, with the vault engine running in a Rust daemon. The webview is the least-trusted component of the desktop tier, and the socket is the capability boundary between it and the key material (ADR 0009).

## Decision

The desktop tier will use a Rust daemon (`baluard-daemon`), a socket-based CLI client (`baluard-cli`), and a Tauri v2 UI built with SolidJS and Tailwind.

**Daemon and socket.** Tauri starts the daemon on application launch. The daemon unlocks vaults into `zeroize`-protected memory and listens on a platform-aware domain socket: Linux uses `$XDG_RUNTIME_DIR/baluard/baluard.sock` (falling back to the data directory), macOS uses `~/Library/Application Support/baluard/baluard.sock`, and Windows reserves the named pipe `\\.\pipe\baluard`. `BALUARD_SOCKET` and the CLI `--socket` flag override the path. Paths are centralized in `baluard_core::paths`. On Unix, the daemon sets umask `0177` before bind so the socket is born with `0600` permissions and restores the previous umask afterward. At startup it probes an existing socket path with a connect: a live listener makes startup fail rather than steal the socket, and only a dead stale file is removed. It uses Tokio for asynchronous I/O, handles SIGINT and SIGTERM, and on either signal locks every open vault, which zeroizes key material, before exit. A transient `accept` error backs off and continues instead of ending the daemon.

**Peer verification.** Every connection is checked against the daemon's effective UID: `SO_PEERCRED` on Linux and `getpeereid` on macOS. A different UID is rejected. A same-UID process still reaches the socket, so access to vault data additionally needs the per-vault session token. On targets without a verified transport, the check fails closed. The Windows named-pipe transport is not implemented: the pipe name and token path exist in `paths.rs`, but the daemon refuses connections there until a pipe DACL check lands, and the desktop IPC returns an error.

**CLI.** The CLI serializes commands into Protobuf and sends them to the daemon by default (ADR 0007). `--direct` runs `baluard-core` in-process, and `--socket <path>` selects a custom daemon socket. The CLI keeps its session token per socket and per vault slug in the OS keyring, with a token file next to the socket used only where no keyring is available, because the token is a capability that no same-UID process should read from a file.

**Tauri UI.** The UI calls the `daemon_request` Tauri command, which proxies Protobuf over the socket. The command is asynchronous and runs the blocking socket I/O in `spawn_blocking`: a synchronous command runs on the main UI thread and would freeze the webview while it waits on the daemon. The UI includes a system tray with Show and Quit actions; CRUD for Login, Card, Identity, SSH Key, Secure Note, Bank Account, Driver's License, and Passport/ID; a CSPRNG password generator and EFF 7776-word passphrase generator; a TOTP widget with boundary-aligned refresh; auto-lock settings; dark and light themes; eight import formats and two export formats; nested folders; a device fleet dashboard; and biometric unlock.

**Webview hardening.** `daemon_request` is a gate, not a pass-through. It checks two things before any state access. First, the action must appear in `DESKTOP_ALLOWED_ACTIONS`, a list built from the `daemon(...)` call sites in the frontend; any other action is denied, including host-level routes that need no token and the deliberately CLI-only destructive routes. A new UI action must be added to the list, and a debug build logs the denied action name so a miss is loud in development. Second, the payload must not carry a forbidden top-level key: `delete_from_disk`, `force`, `in_path`, or `out_path`. The check inspects parsed JSON object keys only, never substrings, so entry text containing the word "force" cannot trip it. The path keys are forbidden so a compromised webview gains neither a file-read nor a file-write primitive through import and export; desktop backup flows use dedicated Rust-side dialog commands instead. Destructive vault detach with deletion from disk is therefore reachable only from the CLI.

**Daemon lifecycle.** Startup adopts a healthy daemon that reports the version this app shipped with, even if the CLI or another client started it. It replaces an unresponsive daemon or one with a different version, so a stale sidecar left over from an update is never trusted. On exit the app stops a daemon it spawned and waits for it to exit. It only locks the vaults of an adopted daemon over the socket and leaves the process to its owner. The rationale for a separate daemon process and its lifecycle limits are in ADR 0009.

## Consequences

The daemon and socket architecture centralizes vault state for the desktop and CLI, and the allowlist keeps the webview to the capabilities the UI actually uses. The cost is that every new UI action needs an allowlist entry. The desktop features listed above are implemented on Linux and macOS. Windows is not yet served by the socket transport. The socket is not a boundary between users who share one OS account, because they share a UID.

## References

- `crates/baluard-daemon/src/main.rs`, `crates/baluard-daemon/src/handler.rs`
- `crates/baluard-core/src/paths.rs`
- `desktop/src-tauri/src/lib.rs` (`DESKTOP_ALLOWED_ACTIONS`, `daemon_request`)
- `desktop/src-tauri/src/daemon_ctl.rs`
- `docs/security/threat-model.md`
- ADR 0007, ADR 0009
