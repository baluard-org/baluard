Baluard portable (Windows x64)
==============================

Run: double-click baluard-portable.exe. No install, no admin rights.
Runs on Windows 11, x64.

Everything Baluard stores lives in the data\ folder next to the
executable: vaults, settings, logs, and provider tokens. The vault is
encrypted. Provider tokens are stored as files, so the Windows Credential
Manager is never used; this also means PIN and biometric unlock are not
available in the portable build. The bundled WebView2 runtime lives in
WebView2\, so no system WebView is needed, even offline.

Updates: the app checks GitHub for new versions and offers them in-app.
Accept the prompt and Baluard downloads, verifies, and installs the
update itself, then restarts. Your vaults in data\ are kept. Updating
never touches anything outside the Baluard folder. During the final
install step the app closes for a moment and comes back on its own: do
not start it again while that is happening. Keep about 2 GB free on the
drive for the download and the swap. `baluard self-update` stays
disabled; the app handles updates.

Advanced: baluard-portable.exe also forwards commands to the CLI in a
terminal, using the same data folder. The SSH agent is not served by the
portable build.

Not included in the portable build:
- Browser extension integration (needs the installed version).

The zip is not code-signed. Windows may show a SmartScreen warning on
first run: choose More info, then Run anyway.

Before ejecting the drive, quit Baluard fully (close the window), so the
daemon can stop writing.

Keep the drive formatted NTFS or exFAT.
Only one Baluard window runs per Windows session: starting a second copy focuses the existing window instead.
