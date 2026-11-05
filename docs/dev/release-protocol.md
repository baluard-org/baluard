# Release protocol

One runbook for shipping a Baluard release across every variant. All commands run from the repository root. The staging directory is `./dist` (gitignored). Store IDs and credentials live outside the repository; this page records the names, locations, and the order of operations so a release never requires archaeology.

## Variants and artifacts

| Variant | Artifacts | Distribution channel |
|---|---|---|
| Core, daemon, CLI (Rust workspace) | `baluard`, `baluard-daemon` binaries | Inside every desktop package; standalone `tar.gz` archives via `just release` |
| Desktop Linux | `.deb`, `.rpm`, `.AppImage` | apt and dnf repositories at `https://baluard.app/repo`, GitHub Releases |
| Desktop macOS | `.app` in a zip (`Baluard-macos-aarch64-non-notarized.zip`) | GitHub Releases; ad-hoc signed, not notarized (Developer ID and notarization are a known gap) — Gatekeeper strips the quarantine xattr before first launch. Linux cross-builds it through the aarch64 pipeline. The daemon self-registers the browser-bridge manifests into every installed browser at startup (`BALUARD_CHROME_EXTENSION_ID` must be set at build time or the Chrome-family manifests are skipped) |
| Desktop Windows | NSIS `setup.exe` | GitHub Releases; cross-built on Linux with cargo-xwin (`just desktop-windows`); MSI stays Windows-only (WiX). Installs to `%LOCALAPPDATA%\\Programs\\Baluard` via the forked template (`desktop/src-tauri/installer.nsi`, re-sync against the bundler version with `just nsis-fork-diff`), keeping the app out of the `%LOCALAPPDATA%\\baluard` data dir. The installer writes the per-browser native-messaging registry keys (`installer-hooks.nsh`) pointing at the manifest the daemon writes beside itself on first startup |
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
| F-Droid repo key + APK keystore | `~/.baluard/fdroid/` (`config.yml`, `keystore.p12`, `allowed-apk-signing-key`) | APK and F-Droid indexes; repo fingerprint `1CE90DCFE0FB1003F2F66999257B5E6F074E46EE453FB0D44F8CF8E13E6EEAAB` |
| Android upload keystore | `~/.baluard/baluard-android-upload.keystore` (mode 600, RSA 4096, alias `baluard-upload`; keystore and passwords backed up in Bitwarden) | Release APKs and the Play AAB via the `baluardRelease` signing config |
| Chrome Web Store OAuth | Bitwarden (`BALUARD_CHROME_CLIENT_ID`, `BALUARD_CHROME_CLIENT_SECRET`, `BALUARD_CHROME_REFRESH_TOKEN`) | Store API uploads; export into the environment only when running `just ext-submit` |
| AMO JWT keys | Bitwarden (`BALUARD_AMO_JWT_KEY`, `BALUARD_AMO_JWT_SECRET`) | `web-ext sign` submissions |

Non-secret store identifiers live on the release box in `~/.config/environment.d/baluard.conf` (mode 600, read at login):

```sh
BALUARD_CHROME_EXTENSION_ID=nmkmfkmdhbifkjdhioejeoegcjpaiijl
BALUARD_CHROME_EXTENSION_ID=nmkmfkmdhbifkjdhioejeoegcjpaiijl
BALUARD_CHROME_PUBLISHER_ID=d6e3a68c-a6f3-4359-9769-9fd105198720
```

`BALUARD_CHROME_EXTENSION_ID` is consumed at desktop build time: `scripts/build-nmh-manifests.sh` bakes `chrome-extension://<id>/` into the chrome, chromium, and edge host manifests that the deb and rpm install system-wide (`/etc/opt/chrome`, `/etc/chromium`, `/etc/opt/edge`, and `/usr/lib` or `/usr/lib64/mozilla` for Firefox). Unset, it falls back to a `baluard-unconfigured` placeholder origin that can never match a real extension; never ship packages built without the real ID. A terminal opened before the environment changed needs a re-login, or prefix the variable for one-off runs.

## Build matrix

| Target | Command | Notes |
|---|---|---|
| Core + CLI + daemon | `just build-release` | daemon and CLI carry the `fido2` feature |
| Desktop Linux | `just desktop-build` | sidecars, deb/rpm/AppImage, and NMH manifest regeneration in one recipe |
| Desktop macOS | `just desktop-build` on a macOS host, then `just build-signed` | targets `dmg` and `app`; ad-hoc signing only. Dev-smoke only, no release: `scripts/build-macos-app.sh [--smoke]` cross-builds the app bundle from Linux (cargo-zigbuild + staged SDK + cross-built OpenSSL per the script header; SDK tbds need the arm64e shim step). Releases still come off a macOS host
| Desktop Windows | `just desktop-windows` | cargo-xwin cross-compile of the sidecars plus NSIS bundling |
| Extension zips | `just ext-package` | rebuilds both dists, enforces the drift gate, zips each store |
| Android APK | `just android-apk-release` | `mobile/scripts/build-android-apk.sh --release` with the upload keystore; verify `versionCode` increased; the build verifies the APK signature with `apksigner` before reporting success |
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

## GitHub release staging

The published release carries ONLY stable, unversioned asset names, so the site's `releases/latest/download/<name>` links always track the newest release and no file exists twice on the release. Stage the upload set after `release-repositories`:

```sh
just release-stage
# Android APK ride-along (not part of dist/):
scripts/stage-release-assets.sh --version <X.Y.Z> --apk ~/.baluard/fdroid/repo/<app.baluard.mobile_N>.apk dist
```

`scripts/stage-release-assets.sh` copies `./dist` artifacts into `release-upload/` under the stable mapping (Baluard-amd64.AppImage, Baluard-amd64.deb, Baluard-amd64.rpm, Baluard-amd64-setup.exe, Baluard-cli-amd64.tar.gz, Baluard-android.apk, Baluard-extension-chrome.zip, Baluard-extension-firefox.zip, Baluard-macos-aarch64-non-notarized.zip), signs `SHA256SUMS` with the updater minisign key, and fails loudly on target collisions, unmapped files, wrong-arch or stale-version strays, or a missing `--require` entry. Note there are two signed `SHA256SUMS` files by design: `dist/` carries the versioned-name set the apt/dnf repo build consumes, while `release-upload/` carries this stable-name set for the GitHub release; the site and the repo trees each publish their own. Only the updater payloads keep per-asset `.sig` files (AppImage, setup exe); everything else is covered by the signed `SHA256SUMS`. Upload with `gh release upload <tag> --clobber release-upload/*` and keep versioned names out of the release. The versioned names stay required locally: the apt/dnf pools, the extension submit flow, and the CI artifacts all consume them.

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
- The Chrome item exists since 2026-11-03 (first upload). Both store listings (Chrome, AMO) were submitted 2026-11-03 and are pending review at first upload.

## Update channels

| Variant | How users get updates |
|---|---|
| Desktop Linux (AppImage) | In-app updater: the app polls `updates-stable` / `updates-beta` channel manifests (`latest.json` assets on those fixed GitHub releases); deb/rpm stay repository-managed |
| Desktop macOS | In-app updater through the `darwin-aarch64` manifest key (the signed `.app.tar.gz`); the non-notarized zip is for first installs |
| Desktop Windows | In-app updater through the `windows-x86_64` manifest key (the signed setup exe) |
| Browser extension | Store-managed auto-update after `just ext-submit` (Chrome) / AMO approval (Firefox) |
| Mobile Android via F-Droid | Index regeneration in `fdroid-stage`; requires a higher `versionCode`; the repo keeps the latest three APKs |
| Direct downloads | New GitHub release with stable asset names, per-asset `.sig` only for the updater payloads (AppImage, setup exe, app tar.gz), and signed `SHA256SUMS` |

## Update channel publication (local-first pipeline)

Every published version ships its channel manifest the same day, from the local pipeline (CI's `publish-updates` dispatch is the mirror, not the primary):

1. Stage the stable set: `just release-stage dist` (the recipe carries the Android APK and the full `--require` list).
2. Generate the manifest: `node scripts/generate-updates-manifest.mjs --tag <X.Y.Z> --artifacts-dir release-upload --strict --require-stamped --notes-file <notes.md> --out /tmp/latest.json`. The matrix publishes `linux-x86_64-appimage`, `darwin-aarch64`, and `windows-x86_64`; `--strict` refuses a missing key and `--require-stamped` refuses a signature without a version comment. Every signature is verified against the pinned pubkey before anything is written.
3. Upload it onto the fixed channel release: `gh release upload updates-stable --clobber /tmp/latest.json` (create the release with `--prerelease` the first time so it can never hijack `releases/latest`; beta versions publish onto `updates-beta` the same way). The channel release is the only mutable piece — versioned releases and their artifacts are immutable once published.

`requireSignedVersion` stays `true` in `tauri.conf.json`: updater signatures are stamped with a `version:` trusted comment by `just release-stage` (via `scripts/sign-updater-sigs.sh`, rsign over the unwrapped Tauri key — the shipped Tauri CLI 2.12.4 writes no such comment itself). Without the stamp, the plugin refuses every install with `MissingSignedVersion`, which is exactly what any 0.1.x client got against the 0.1.2 channel manifest before it was re-signed. The CI mirror runs the same generator without `--strict`/`--require-stamped` because its windows job builds no installer; the local pipeline is the primary.

The desktop confirm-first flow: the Rust command surface (`desktop/src-tauri/src/updater.rs`) downloads only after the user accepts the UpdateBanner dialog, drains and locks vaults over IPC (`system.prepare_update`), stops the daemon, installs, and relaunches; on Windows the NSIS install step exits the app itself. The check cadence (jittered startup probe, 6h background interval, opt-out in Settings) and the pure scheduling pieces live in `desktop/src/lib/update.js`.

## Pre-release checklist

1. `just check` green (fmt, clippy, audit, tests, build).
2. `just test-release-scripts` green (eight hermetic suites: fdroid, sync-site-repos, build-extension-packages, submit-extension-stores, build-windows-installer, build-nmh-manifests, bump-version, generate-updates-manifest).
3. `just smoke-pkg` for the deb, and the relevant `e2e` recipes for changed surfaces (`e2e-desktop`, `e2e-android` with `just emulator`, `e2e-extension`, `e2e-extension-firefox`).
4. After `just desktop-build`, confirm the NMH manifests carry the real origin: `grep -r baluard-unconfigured desktop/src-tauri/nmh-manifests/` must find nothing.
5. Confirm the newest store zips carry the bumped version (`just ext-package` already refuses a mismatch).

## Known gaps

- macOS: ad-hoc signing only; no Developer ID certificate or notarization.
- iOS: no build or store pipeline.
- Windows: no MSI (WiX is Windows-only); no Authenticode signing, so SmartScreen warns. Clean Windows machines need the VC++ redistributable (`VC_redist.x64.exe`) before the bundled exes run; the release notes carry this prerequisite and bundling it into NSIS is still open.
- Windows installer: verified interactively on the Windows 11 smoke VM (uninstall old version, clean install, app launch over WebView2). A non-interactive start (ssh, scheduled task) exits with code 123 before any UI; that is a launch-context artifact, not an installer bug. The published 0.1.3 Windows installer was rebuilt in place from commit aa5b27d2 (carrying the post-0.1.3 desktop fixes) after the install-dir fix; the git tag intentionally stays at the 0.1.3 release commit because the other platforms' artifacts were built there.
- Desktop updater: the feed endpoint and publish job exist (release.yml `publish-updates`); the residual gap is publish-side signature re-verification and manifest expiry (deferred M5/M9).
- Chrome Web Store and AMO listings: both submitted 2026-11-03, pending review at first upload; automated ext-submit still needs the store API credentials in Bitwarden.
