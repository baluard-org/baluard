# Changelog

Notable user-facing changes per release.

## UNRELEASED

- The desktop app now has a native macOS menu (About, Settings, Check for updates, Sync now) and the web-style right-click menu no longer appears outside text fields.
- Buttons across the desktop app give a brief press ripple for tactile feedback.
- The People tab is now called Sharing on desktop and mobile, with clearer wording about what it does.

## 0.1.4 - 2026-11-05

- The desktop sidebar has a TOTP filter showing every entry that carries a one-time code seed, with a count, like on mobile.
- Long unbroken strings in secure notes now scroll horizontally inside the notes card instead of running past its edge.
- One-time codes now work when an entry carries just the secret instead of a full otpauth:// URI, so imports from other password managers show codes without editing every entry.
- Desktop folders are listed alphabetically at every level instead of in creation order.
- Password history dates now read YYYY-MM-DD instead of an ambiguous locale date.
- Entries with several websites now list them all in the entry view, each with open and copy buttons, and the order can be changed by dragging (first one is the primary).
- The browser extension gains a view button on every match: it opens that entry in the desktop app, asking to unlock first when the vault is locked.
- The sync dot in the desktop title bar is clickable: clicking it syncs immediately, with a short cooldown.
- The CLI can update itself, notices when a newer release is available, and installs through a mise path too.
- CLI fixes: vaults list honors --direct on machines with a running daemon, removing an entry's last passkey now sticks, and --output json in direct mode matches the daemon format (it also no longer exposes passkey private keys).

## [UNRELEASED]

No user-facing changes yet.

- The browser extension now pairs through the canonical host name (app.baluard.browser). Older 0.1.0 extensions keep working: every installer and app registration also carries the previous name.
- The macOS and Windows desktop apps now register the browser-extension bridge themselves: the app writes and refreshes the native-messaging manifests on startup (macOS) or the installer registers them with the app manifest beside it (Windows), so the extension works right after installing the app, with no extra setup.

- Fixed a cross-device sync failure: joining a vault from a second device could push an incomplete enrollment that every other device then refused, breaking sync for all of them. Enrollments now land as one complete signed commit, and a sync that would overwrite your unsaved local edits stops with a clear message instead of silently discarding them.
- Desktop apps can now update themselves: the app checks for new signed releases, asks before downloading anything, and restarts into the new version. The check runs in the background on a slow jittered schedule and can be turned off in Settings; a manual "Check for updates" button lives there too. Linux updates work from the AppImage; deb and rpm users keep updating through the package repositories.
- The Windows installer now installs to %LOCALAPPDATA%\\Programs\\Baluard instead of %LOCALAPPDATA%\\Baluard, keeping the app out of the folder that holds your vault data, and no longer shows the uninstall-previous-version page on reinstalls. Existing installs move to the new folder on their next update or reinstall; your vaults and settings stay where they are.

## 0.1.2 - 2026-11-05

- The desktop app now brings the daemon back automatically after a crash, instead of showing "Daemon is not running" until a manual restart.
- A security-key enumeration crash or hang can no longer take the daemon down: the HID probe runs in a short-lived child process, and a hung probe is killed after five seconds instead of stalling shutdown.
- macOS builds are now published on the releases page as a zip named non-notarized: the app inside is ad-hoc signed, so Gatekeeper's quarantine marker must be removed once before first launch (development builds on Apple Silicon; an x86_64 build exists for local VM debugging only and is not published).
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
