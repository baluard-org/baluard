# Release protocol

One runbook for shipping a Baluard release across every variant. All commands run from the repository root. The staging directory is `./dist` (gitignored). Store IDs and credentials live outside the repository; this page records the names, locations, and the order of operations so a release never requires archaeology.

## Variants and artifacts

| Variant | Artifacts | Distribution channel |
|---|---|---|
| Core, daemon, CLI (Rust workspace) | `baluard`, `baluard-daemon` binaries | Inside every desktop package; standalone `tar.gz` archives via `just release` |
| Desktop Linux | `.deb`, `.rpm`, `.AppImage` | apt and dnf repositories at `https://baluard.app/repo`, GitHub Releases |
| Desktop macOS | `.app`, `.dmg` | GitHub Releases; ad-hoc signed only (Developer ID and notarization are a known gap) |
| Desktop Windows | NSIS `setup.exe` | GitHub Releases; cross-built on Linux with cargo-xwin (`just desktop-windows`); MSI stays Windows-only (WiX) |
| Browser extension (Chrome) | `dist/baluard-extension-<version>-chrome.zip` | Chrome Web Store, extension ID `nmkmfkmdhbifkjdhioejeoegcjpaiijl` |
| Browser extension (Firefox) | `dist/baluard-extension-<version>-firefox.zip` | Firefox AMO, gecko ID `baluard@actitud.xyz` |
| Native messaging host | `baluard-nmh` + four host manifests | Shipped inside the deb and rpm with system-wide manifests (see below); dev installs use `just install-nmh-manifest` |
| Mobile Android | Release APK | GitHub Releases and the F-Droid repository at `https://baluard.app/fdroid/repo/` |
| Mobile iOS | none | No pipeline yet |

## Version bump

Run `just bump-version X.Y.Z` first. It moves every version source in one pass and refuses non-semver or non-increasing versions:

| Source | What it drives |
|---|---|
| `Cargo.toml` (`[workspace.package]`) | All workspace crates |
| `desktop/src-tauri/Cargo.toml` | Desktop package version; drives deb/rpm/dmg file names (its own workspace root, easy to miss) |
| `desktop/package.json` | Desktop UI package |
| `browser/shared/package.json` | Extension build package |
| `browser/shared/manifest.base.json` | Extension manifest version (single source for both stores) |
| `mobile/androidApp/build.gradle.kts` | `versionName` and `versionCode` (`major*1000000 + minor*1000 + patch`) |
| `mobile/.../i18n/Strings{En,Es}.kt` | Mobile about-screen string |

The recipe then rebuilds the committed extension dists so the bump commit carries fresh dists (the B11 rule: `browser/<store>/dist` artifacts are committed and must never go stale). `Cargo.lock` is refreshed by cargo, never sed-edited. Commit the version sources and the rebuilt dists together.

## Keys and credentials

Everything that signs lives outside the repository. Losing any of these orphans the matching channel.

| Secret | Location | Signs |
|---|---|---|
| Updater minisign key | `~/.tauri/baluard-updater.key` | Release artifacts (`.sig` sidecars, `SHA256SUMS`) and desktop updater bundles; public key pinned in `tauri.conf.json` |
| Release GPG key | `~/.baluard/release-gnupg` | apt and dnf repository metadata; fingerprint `223310EA BF1A B6FE E6BD DF3E 2A53 1D54 E6D7 4804` |
| F-Droid repo key + APK keystore | `~/.baluard/fdroid/` (`config.yml`, `keystore.p12`, `allowed-apk-signing-key`) | APK and F-Droid indexes; repo fingerprint `C5A690013893C46F208A506AEA9217D37FF007C0A2B0A2514039FE28DD58C7A8` |
| Chrome Web Store OAuth | Bitwarden (`CHROME_CLIENT_ID`, `CHROME_CLIENT_SECRET`, `CHROME_REFRESH_TOKEN`) | Store API uploads; export into the environment only when running `just ext-submit` |
| AMO JWT keys | Bitwarden (`AMO_JWT_KEY`, `AMO_JWT_SECRET`) | `web-ext sign` submissions |

Non-secret store identifiers live on the release box in `~/.config/environment.d/baluard.conf` (mode 600, read at login):

```sh
BALUARD_CHROME_EXTENSION_ID=nmkmfkmdhbifkjdhioejeoegcjpaiijl
CHROME_EXTENSION_ID=nmkmfkmdhbifkjdhioejeoegcjpaiijl
CHROME_PUBLISHER_ID=d6e3a68c-a6f3-4359-9769-9fd105198720
```

`BALUARD_CHROME_EXTENSION_ID` is consumed at desktop build time: `scripts/build-nmh-manifests.sh` bakes `chrome-extension://<id>/` into the chrome, chromium, and edge host manifests that the deb and rpm install system-wide (`/etc/opt/chrome`, `/etc/chromium`, `/etc/opt/edge`, and `/usr/lib` or `/usr/lib64/mozilla` for Firefox). Unset, it falls back to a `baluard-unconfigured` placeholder origin that can never match a real extension; never ship packages built without the real ID. A terminal opened before the environment changed needs a re-login, or prefix the variable for one-off runs.

## Build matrix

| Target | Command | Notes |
|---|---|---|
| Core + CLI + daemon | `just build-release` | daemon and CLI carry the `fido2` feature |
| Desktop Linux | `just desktop-build` | sidecars, deb/rpm/AppImage, and NMH manifest regeneration in one recipe |
| Desktop macOS | `just desktop-build` on a macOS host, then `just build-signed` | targets `dmg` and `app`; ad-hoc signing only |
| Desktop Windows | `just desktop-windows` | cargo-xwin cross-compile of the sidecars plus NSIS bundling |
| Extension zips | `just ext-package` | rebuilds both dists, enforces the drift gate, zips each store |
| Android APK | `just android-apk` | `mobile/scripts/build-android-apk.sh --release`; verify `versionCode` increased |
| CLI archives | `just release` | `tar.gz` + checksums into `./dist` |

## Release pipeline

Build the desktop packages and the APK first, then run one command:

```sh
just release-repositories
```

Stage order, fail-fast (any failure stops the pipeline):

1. `ext-package`: rebuilds both extension dists, refuses drift against the committed dists, writes the store zips.
2. `fdroid-stage`: verifies the APK (application ID, signing certificate, `versionName`), signs it into `repo-out/fdroid/repo`, regenerates the F-Droid indexes.
3. `release-sign`: minisign sidecars plus signed `SHA256SUMS` over `./dist` (covers `.AppImage`, `.deb`, `.rpm`, `.tar.gz`, `.zip`).
4. `repo-stage`: builds the apt and dnf trees into `repo-out` (GPG-signed metadata; already-signed RPMs are not signed twice; package history persists in `~/.baluard/linux-repo-history/`).
5. `repo-sync`: mirrors `repo-out` into `../baluard-org`, removing stale generated files and leaving unrelated website changes untouched.

Publishing is a manual review, commit, and push of the `baluard-org` diff. The pipeline never commits or pushes. The Linux trees map to `repo/`, the F-Droid tree to the site root `fdroid/`; a push of `baluard-org` main is what updates `baluard.app` and both Linux repositories.

## Store publishing

Explicit and manual only, never part of `release-repositories`:

```sh
just ext-submit
```

- Requires a version bump first; the Chrome upload API rejects a re-upload of an unchanged version.
- Firefox: the submission is built from `browser/firefox/dist` via `web-ext sign --channel listed`; the packaged zip is used only for the version cross-check.
- Chrome: pure curl flow against the v2 publisher API (token exchange, `-T` upload of the packaged zip, publish with an empty body).
- First listed AMO submission needs `AMO_METADATA` (summary, categories, license); minified-source review may need `AMO_UPLOAD_SOURCE`.
- Partial credentials are a hard error, not a skip. A configured store failing aborts the run after the other store submitted.
- The Chrome item exists since 2026-11-03 (first upload). The AMO listing is not yet submitted.

## Update channels

| Variant | How users get updates |
|---|---|
| Desktop Linux | apt/dnf repository metadata regenerated every pipeline run; in-app updater artifacts are built but no feed endpoint is configured yet |
| Desktop macOS / Windows | New download from GitHub Releases; updater artifacts are produced (signature required, no downgrades) but no feed endpoint is configured yet |
| Browser extension | Store-managed auto-update after `just ext-submit` (Chrome) / AMO approval (Firefox) |
| Mobile Android via F-Droid | Index regeneration in `fdroid-stage`; requires a higher `versionCode`; the repo keeps the latest three APKs |
| Direct downloads | New GitHub release with minisign sidecars and signed `SHA256SUMS` |

## Pre-release checklist

1. `just check` green (fmt, clippy, audit, tests, build).
2. `just test-release-scripts` green (seven hermetic suites: fdroid, sync-site-repos, build-extension-packages, submit-extension-stores, build-windows-installer, build-nmh-manifests, bump-version).
3. `just smoke-pkg` for the deb, and the relevant `e2e` recipes for changed surfaces (`e2e-desktop`, `e2e-android` with `just emulator`, `e2e-extension`, `e2e-extension-firefox`).
4. After `just desktop-build`, confirm the NMH manifests carry the real origin: `grep -r baluard-unconfigured desktop/src-tauri/nmh-manifests/` must find nothing.
5. Confirm the newest store zips carry the bumped version (`just ext-package` already refuses a mismatch).

## Known gaps

- macOS: ad-hoc signing only; no Developer ID certificate or notarization.
- iOS: no build or store pipeline.
- Windows: no MSI (WiX is Windows-only); no Authenticode signing.
- Desktop updater: artifacts and key pinning exist, feed endpoint not configured.
- Chrome Web Store listing: pending review at first upload; AMO listing not yet created.
