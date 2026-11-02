# ADR 0082. The Store Never Signs

> Status: Accepted (2026-10-30)

## Context

Desktop updates must work across supported platforms without exposing update capabilities to web content or using a custom update server. Linux packages differ in their update ownership and sandbox capabilities. The bundled daemon is not managed by Tauri's updater and must not be killed during sync or key rotation.

## Decision

Use Tauri v2 updater plugin stable 2.12.x, not 3.0 alpha, with static `latest.json` manifests on GitHub Releases. Expose only Rust commands for check, prepare, install, and status; do not expose updater JavaScript APIs or add GitHub to CSP `connect-src`. Require `requireSignedVersion: true` and `allowDowngrades: false`. Release CI must ensure each `.sig` contains a `version:` matching the manifest, because artifacts signed by older CLIs lack a version and fail closed.

Use AppImage as the primary Linux format and the only self-updating Linux format. Publish only `linux-x86_64-appimage`, not the bare `linux-x86_64` key, to prevent deb or rpm clients resolving the AppImage. Deb and rpm check and notify but do not install; their HTTPS metadata read is size-capped and unsigned. Support Flatpak and Snap with caveats while stores own updates. Snap requires manual `snap connect` for `u2f-devices` and `password-manager-service`; Flatpak hidraw access is coarse. Native messaging and vault-location differences require a test matrix before store builds claim support. AppImage updates require bundled libgit2, OpenSSL, and libssh2, Secret Service and hidraw access in the sandbox, and FUSE or a documented `--appimage-extract-and-run` fallback.

Use fixed `updates-beta` and `updates-stable` tags whose manifests move. Keep version artifacts on immutable per-version releases and upload manifests last. Do not depend on GitHub `/releases/latest`, which excludes prereleases. Add AppImage and macOS app targets to the release pipeline alongside deb, rpm, and dmg. macOS installs from DMG and updates through signed `.app.tar.gz`; Developer ID signing and notarization remain separate, and beta-to-beta keychain and Touch ID continuity requires testing. Windows support waits for named-pipe IPC, then uses per-user NSIS updates with a bundled-daemon replacement test. Treat upstream tauri#15134 as a risk to verify.

Before installation, prepare the daemon: finish or refuse in-flight sync, conflict resolution, and key rotation; call `vaults.lock_all`; stop the daemon cleanly and wait for exit; prevent respawn; and respawn it if installation fails. Replace the Drop-only SIGTERM restart behavior and the startup `pgrep -x` sweep, which also kills CLI- or NMH-started daemons. Include the daemon build version in `ping` and refuse desktop-to-daemon IPC when versions differ. Preserve browser-extension NMH reconnection. Because checks disclose IP and version to GitHub, use a jittered six-hour cadence and an opt-out. Require user action to install; provide notes, progress, restart, dismiss, and release-page fallback. Signature failures are fatal and non-retryable.

## Consequences

The updater signing key is a dedicated minisign pair with offline backup; losing it strands installed clients and does not replace OS signing. The plugin's reported Rust version is 1.77.2, so no desktop MSRV split is required. QuotaGauge's `updates.rs` and manifest generator are references, but the generator must be rewritten for Baluard's platform matrix, optional Windows, macOS architecture decision, and prerelease filenames. Flatpak and Snap remain caveat-tier until their sandbox integration matrix passes. AppImage remains the only self-updating Linux format.

## References

- Tauri v2 updater plugin 2.12.x
- QuotaGauge `updates.rs` and manifest generator
- tauri#15134
