# Changelog

Notable user-facing changes per release.

## [UNRELEASED]

- The desktop app now brings the daemon back automatically after a crash, instead of showing "Daemon is not running" until a manual restart.
- A security-key enumeration crash or hang can no longer take the daemon down: the HID probe runs in a short-lived child process, and a hung probe is killed after five seconds instead of stalling shutdown.
- The in-app "What is git?" explainer pages are gone on desktop and mobile. The link now opens <https://baluard.app/what-the-git/> in the system browser, so the explainer can be corrected without shipping an app release.

## 0.1.1 - 2026-11-04

- Fixed sync setup on macOS: the desktop sent an empty payload when polling the daemon about an OAuth sign-in, so the first GitHub connection always died with a generic error. The browser round-trip itself was fine.
- Sync setup converged on one shared implementation for desktop and mobile: an existing empty provider repo is adopted instead of refused, and pushes stay on the transport the vault itself stored, even when a personal git config rewrites GitHub URLs to SSH.
- Sync setup failures now say what actually went wrong instead of collapsing into "An unexpected error occurred".
- The Windows build carries the named-pipe IPC work end to end, hardened after real-VM smoke testing: per-user pipe names, server identity checks on both sides, and an explicit DACL.
- The daemon shuts down within two seconds even when a stuck hardware-key probe used to hold it alive past SIGTERM.
- Deleting a vault with delete-from-disk no longer leaves its Quick Unlock entry behind in the OS keychain.
- The CLI finished the Cipher-to-Entry wording rename.
- New app icon on desktop and mobile: a larger lock with a light rim, plus a clearer tray glyph.
- Known gaps: the Windows installer is unsigned (SmartScreen warns) and does not yet bundle the VC++ redistributable; the macOS app stays a dev-smoke handoff build while a signed pipeline is pending.

## 0.1.0 - 2026-11-04

- First tagged release.
- Desktop for Linux: deb, rpm, and AppImage. The deb and rpm register the browser bridge system-wide for Chrome, Chromium, Edge, and Firefox.
- Desktop for Windows: NSIS installer bundling the CLI, daemon, and browser bridge.
- CLI and daemon in `Baluard-cli-amd64.tar.gz`.
- Browser extension zips for manual install; both stores carried the same version under review.
- Android APK, also live in the F-Droid repo at <https://baluard.app/fdroid/repo/>.
- Debian and Fedora installs straight from the package repos at <https://baluard.app/repo/>.
- Every artifact listed in the signed SHA256SUMS; update signatures use the minisign public key pinned at <https://baluard.app/security/>.
- Known gap: no macOS builds yet.

## 2026-05-04 - Project begins

- Work on Baluard starts. The repository's visible history begins with the migration from a dual Rust+Go codebase to a pure-Rust core with UniFFI bindings for mobile.
