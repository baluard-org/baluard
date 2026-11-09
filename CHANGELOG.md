# Changelog

Notable user-facing changes per release.

## [UNRELEASED]

- The Android autofill picker header now carries the Baluard logo and wordmark on the left and the Choose a login prompt on the right, with more room below the status bar.
- The git backup setup is now a full settings page on mobile, with proper room for the own-server flow.
- Desktop: the site-icon backfill now respects the Show website icons setting; the fetch button was unreachable.

## 0.2.4 - 2026-11-09

- The autofill login picker now looks like the app's entry cards, with a search bar on top. It only lists entries that match the site you are filling; search finds anything else, ignoring accents, and never floods the sheet with more than twenty suggestions.

- Settings > Sync gains a site-icon backfill: after importing a vault, one click fetches the missing website icons entry by entry (2-second budget per site, slow sites skipped), with progress and cancel.

- Showing a recovery phrase now ends with a second confirmation that asks whether you really stored the words, and the words screen states clearly that they are the only way to recover the vault.

- Settings screens have more breathing room: clearer spacing between entries and their dividers, and the cards on the Sharing screen now carry their own action buttons.

- The Passkeys setting in Autofill now actually opens Android's passkey-provider picker; before, the button did nothing.

- Buttons and fields with long labels no longer clip their text in Spanish, Portuguese, or French.

## 0.2.3 - 2026-11-08
- Filled fields now breathe a soft neon halo three times after the fill ring, about one second per breath, and then return to their normal look.

## 0.2.2 - 2026-11-08
- Deleting a vault can now also delete its repository on the provider. Deleting the remote repository always requires your 24-word recovery phrase; removing the vault from this device alone asks for the master password. Disconnecting sync with repository deletion asks for the phrase too.
- The autofill picker that lists all your logins now renders as a normal opaque screen instead of a see-through overlay over the browser page.

## 0.2.1 - 2026-11-08

- The Android launcher icon now matches the new grey app icon.
- Opening Baluard from the autofill dropdown or a keyboard suggestion no longer renders the app see-through over the page you were on.

## 0.2.0 - 2026-11-08

- Baluard now ships on Google Play. Subscriptions there are verified through Google's servers, so trial starts and lapses hold correctly.

## 0.1.12 - 2026-11-07

- Android autofill no longer puts logins into verification-code boxes, and the one-time code lands on your clipboard with a confirmation whenever a fill has one.
- App-to-web suggestions are now on by default: logins saved for a website can fill inside an app after you confirm that app once. Turn it off in Settings > Security.
- Importing a backup is much faster: large imports no longer decrypt the whole vault again after every entry.
- Backing out of the supporter upgrade sheet on mobile now returns you to where you were instead of dead-ending.
- On the Play build, subscription status is now verified through Google's servers, so trial starts and lapses hold correctly.
- The Android download is now a single arm64 build, so it is about 70 MB smaller to install.

## 0.1.10 - 2026-11-07

- The Google Play build now gates sync, authenticator codes, and shared-vault member management behind the Baluard Supporter subscription, with an in-app upgrade sheet and a 14-day trial handled by Google Play. Subscribing or lapsing applies without restarting the app. Your vault stays on the device either way. The F-Droid build stays fully free and carries no billing code.

## 0.1.8 - 2026-11-06

- The delete confirmation and the import dialog on mobile now show real text instead of raw keys like detail.deleteBody.

## 0.1.7 - 2026-11-06

- The app icon is a grey tile with the lock casting a soft shadow onto it, so it stays visible on dark taskbars and docks.

- The desktop app now locks itself whenever the daemon reports the session as dead, including expiry and re-unlock from another client, instead of showing a stale vault.

- Two-factor fields with names like user[totp_code] are now detected and filled, on both the popup Fill and the inline menu, and picking an entry on a two-factor field inserts only the code. Detection distinguishes real code boxes from look-alike payment, setup, and search fields, and prefers explicitly marked ones.

- The extension view-in-app button now uses the accent color so it reads as opening the app, not copying to the clipboard.

- On the extension popup, the copy-code button's border is a live countdown for the current two-factor code: it starts fully red and drains clockwise into the regular border color, snapping back full when the code rotates. The ring reads the entry's window length, so no code is generated until you copy.

- The browser extension pulses a soft ring on the fields it just filled and fades it out after two seconds, so you can see what it touched.

- The macOS Check for Updates menu item now checks in the background without opening Settings.

- The vault list has a sync button next to New that runs the same pull and push as settings; the top-right dot is a passive indicator again since it cannot be clicked reliably.

## 0.1.6 - 2026-11-06

- Desktop one-time codes now show a live countdown with a depleting bar and a copy button, like on mobile, and a failed code fetch shows an error with a retry instead of hiding the code.
- When the daemon rejects the session token, the desktop now drops to the lock screen instead of leaving a stale but normal-looking vault where live features silently fail.
- Mobile settings are grouped into focused drill-down categories so each screen is easier to scan.
- Desktop settings and sharing screens get a polish pass: more consistent controls, easier-to-scan navigation, better contrast, and motion that respects reduced-motion preferences.

## 0.1.5 - 2026-11-06

- The Chrome extension store update pipeline is fully automated: uploads are CRX3-signed with the store-registered key and submitted through the API.
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

## 0.1.3 - 2026-11-05

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
