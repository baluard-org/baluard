# Release protocol

One runbook for shipping a Baluard release across every variant. All commands run from the repository root. The staging directory is `./dist` (gitignored). Store IDs and credentials live outside the repository; this page records the names, locations, and the order of operations so a release never requires archaeology.

## Variants and artifacts

| Variant | Artifacts | Distribution channel |
|---|---|---|
| Core, daemon, CLI (Rust workspace) | `baluard`, `baluard-daemon` binaries | Inside every desktop package; standalone `tar.gz` archives via `just release` |
| Desktop Linux | `.deb`, `.rpm`, `.AppImage` | apt and dnf repositories at `https://packages.baluard.app`, GitHub Releases |
| Desktop macOS | `.app` in a zip (`Baluard-macos-aarch64-non-notarized.zip`) | GitHub Releases; ad-hoc signed, not notarized (Developer ID and notarization are a known gap). Gatekeeper strips the quarantine xattr before first launch. Linux cross-builds it via `scripts/build-macos-aarch64-deliverable.sh` (machine inputs are in the script header). The daemon self-registers the browser-bridge manifests into every installed browser at startup (`BALUARD_CHROME_EXTENSION_ID` must be set at build time or the Chrome-family manifests are skipped) |
| Desktop Windows | NSIS `setup.exe` + portable zip | GitHub Releases; cross-built on Linux with cargo-xwin (`just desktop-windows`, which also runs `scripts/build-windows-portable.sh` for the portable zip); MSI stays Windows-only (WiX). Installs to `%LOCALAPPDATA%\\Programs\\Baluard` via the forked template (`desktop/src-tauri/installer.nsi`, re-sync against the bundler version with `just nsis-fork-diff`), keeping the app out of the `%LOCALAPPDATA%\\baluard` data dir. The installer writes the per-browser native-messaging registry keys (`installer-hooks.nsh`) pointing at the manifest the daemon writes beside itself on first startup |
| Browser extension (Chrome) | `dist/baluard-extension-<version>-chrome.zip` | Chrome Web Store, extension ID `nmkmfkmdhbifkjdhioejeoegcjpaiijl` |
| Browser extension (Firefox) | `dist/baluard-extension-<version>-firefox.zip` | Firefox AMO, gecko ID `baluard@actitud.xyz` |
| Native messaging host | `baluard-nmh` + four host manifests | Shipped inside the deb and rpm with system-wide manifests (see below); dev installs use `just install-nmh-manifest` |
| Mobile Android | Release APK | GitHub Releases and the F-Droid repository at `https://packages.baluard.app/fdroid/repo/` |
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

## Multi-surface policy

One version for everything: `bump-version` moves all seven sources together, so no variant ever diverges. Every GitHub release ships the full stable-name asset set, including surfaces whose code did not change, because version strings are baked into the binaries; the desktop updates manifest is republished each release so users keep receiving updates, and F-Droid always receives the new versionCode APK. The per-surface gate applies only to the store submissions: submit to the Chrome Web Store or AMO only when the extension bundle actually changed, since an unchanged bundle just burns a review cycle. Never stack a new store version on a listing that is still in review; wait for the verdict first.

## Keys and credentials

Everything that signs lives outside the repository. Losing any of these orphans the matching channel.

| Secret | Location | Signs |
|---|---|---|
| Updater minisign key | `~/.tauri/baluard-updater.key` | Release artifacts (`.sig` sidecars, `SHA256SUMS`) and desktop updater bundles; public key pinned in `tauri.conf.json` |
| Release GPG key | `~/.baluard/release-gnupg` | apt and dnf repository metadata; fingerprint `223310EA BF1A B6FE E6BD DF3E 2A53 1D54 E6D7 4804` |
| F-Droid repo key + APK keystore | `~/.baluard/fdroid/` (`config.yml`, `keystore.p12`, `allowed-apk-signing-key`) | APK and F-Droid indexes; repo fingerprint `1CE90DCFE0FB1003F2F66999257B5E6F074E46EE453FB0D44F8CF8E13E6EEAAB` |
| Android upload keystore | `~/.baluard/baluard-android-upload.keystore` (mode 600, RSA 4096, alias `baluard-upload`; keystore and passwords backed up off this machine) | Release APKs and the Play AAB via the `baluardRelease` signing config; the same certificate is the Play app signing key (PEPK-transferred, matching the F-Droid `AllowedAPKSigningKeys` pin) |
| Play service account | `~/.baluard/play-service-account.json` (mode 600; JSON backed up off this machine; the SA is invited under Play Console Users and permissions with testing-track release rights, no production) | Google Play uploads via `just play-submit`; `BALUARD_PLAY_SERVICE_ACCOUNT_JSON` overrides the path |
| Chrome Web Store OAuth | `~/.secrets` plus an off-machine copy (`BALUARD_CHROME_CLIENT_ID`, `BALUARD_CHROME_CLIENT_SECRET`, `BALUARD_CHROME_REFRESH_TOKEN`) | Store API uploads; export into the environment only when running `just ext-submit` |
| Chrome CRX upload key | `~/.baluard/chrome-web-store/chrome-crx-upload.key` (mode 600, RSA 2048; public half registered on the item's Package tab, private backed up off this machine) | `BALUARD_CHROME_CRX_KEY` overrides the path; ext-submit signs uploads into CRX3 when the key exists (required after Verified CRX Uploads opt-in) |
| AMO JWT keys | `~/.secrets` plus an off-machine copy (`BALUARD_AMO_JWT_KEY`, `BALUARD_AMO_JWT_SECRET`) | `web-ext sign` submissions |

Non-secret store identifiers live on the release box in `~/.config/environment.d/baluard.conf` (mode 600, read at login):

```sh
BALUARD_CHROME_EXTENSION_ID=nmkmfkmdhbifkjdhioejeoegcjpaiijl
BALUARD_CHROME_PUBLISHER_ID=d6e3a68c-a6f3-4359-9769-9fd105198720
BALUARD_GITLAB_CLIENT_ID=<gitlab application id>
BALUARD_CODEBERG_CLIENT_ID=<codeberg client id>
```

`BALUARD_CHROME_EXTENSION_ID` is consumed at desktop build time: `scripts/build-nmh-manifests.sh` bakes `chrome-extension://<id>/` into the chrome, chromium, and edge host manifests that the deb and rpm install system-wide (`/etc/opt/chrome`, `/etc/chromium`, `/etc/opt/edge`, and `/usr/lib` or `/usr/lib64/mozilla` for Firefox). Unset, it falls back to a `baluard-unconfigured` placeholder origin that can never match a real extension; never ship packages built without the real ID. A terminal opened before the environment changed needs a re-login, or prefix the variable for one-off runs.

`BALUARD_GITLAB_CLIENT_ID` and `BALUARD_CODEBERG_CLIENT_ID` (public identifiers, not secrets) are consumed at build time via `option_env!`: they bake into the daemon, CLI, desktop bundle, and mobile native lib. Unset or empty, the build keeps `REPLACE_WITH_*` placeholders and the OAuth flows refuse to start with a plain-language error. A terminal opened before the environment changed needs a re-login, or prefix the variables for one-off runs.

## Build matrix

| Target | Command | Notes |
|---|---|---|
| Core + CLI + daemon | `just build-release` | daemon and CLI carry the `fido2` feature |
| Launching release legs | `just build-linux` / `build-windows` / `build-android` / `build-macos` | detached wrappers owning each leg's env bundle; logs and exit codes land in `/tmp/leg-<leg>.{log,rc}`, `just legs-status` polls. Each leg asserts the specific secret variables it needs before any long work and unsets the store-submission credentials; the desktop legs also fail when the built daemon lacks the real provider client ids. `just legs-status` polls the four legs. The recipes wrap the commands the build matrix names below; the env bundles live there, so a relaunch cannot silently drop half of one |
| Desktop Linux | `just desktop-build` | rebuilds sidecars unconditionally (a version bump that edits only manifests defeats mtime staleness checks; the 0.2.0 release shipped stale 0.1.12 sidecars this way), then deb/rpm/AppImage and NMH manifest regeneration in one recipe. Linux binaries statically embed libgit2 (`libgit2-sys` vendored, linux cfg in `crates/baluard-core/Cargo.toml`) so the deb does not pin a distro soname Ubuntu noble cannot satisfy; libgit2 security patches therefore arrive via `cargo update` on libgit2-sys, not distro updates — check libgit2-sys releases before each release |
| Desktop macOS | Dev-smoke on a macOS host (`just desktop-build`, `just build-signed`; dmg/app, ad-hoc). Releases and the smoke VM bundle come off Linux: `scripts/build-macos-aarch64-deliverable.sh` (aarch64 deliverable zip + updater payload) and `scripts/build-macos-app.sh [--smoke]` (x86_64 VM debug bundle), both cargo-zigbuild against the local SDK with the shim steps each script header documents |
| Desktop Windows | `just desktop-windows` | cargo-xwin cross-compile of the sidecars plus NSIS bundling, then the portable zip (`scripts/build-windows-portable.sh` writes `dist/Baluard_<version>_x64-portable.zip` directly) |
| Extension zips | `just ext-package` | rebuilds both dists, enforces the drift gate, zips each store |
| Android APK | `just android-apk-release` | `mobile/scripts/build-android-apk.sh --release` with the upload keystore; verify `versionCode` increased; the build verifies the APK signature with `apksigner` before reporting success |
| CLI archives | `just release` | `tar.gz` + checksums into `./dist` |

## Release pipeline

Start every release with `just release-preflight`: all four workspace repos (baluard, baluard-org, baluard-packages, baluard-docs) must read AHEAD=0, BEHIND=0, DIRTY=0 before anything runs. Then sweep `git log <last-tag>..HEAD` against the changelog, and cut only when `just changelog-check <tag>` passes after the cut. If a repair lands after the cut, force-move the tag to the commit the platform artifacts actually build from; 0.7.3 moved twice as lint repairs and an e2e harness fix landed after the first cut.

Build the desktop packages and the APK first, then run one command:

```sh
just release-repositories
```

Stage order, fail-fast (any failure stops the pipeline):

1. `dist-collect`: copies the four desktop bundles into `./dist` and removes the previous release's loose files, refusing to delete anything when a bundle is missing (the build legs never write `dist/` themselves).
2. `ext-package`: rebuilds both extension dists, refuses drift against the committed dists, writes the store zips.
3. `fdroid-stage`: verifies the APK (application ID, signing certificate, `versionName`), signs it into `repo-out/fdroid/repo`, regenerates the F-Droid indexes.
4. `release-sign`: minisign sidecars plus signed `SHA256SUMS` over `./dist` (covers `.AppImage`, `.deb`, `.rpm`, `.tar.gz`, `.zip`), refusing any file whose version differs from the workspace version.
5. `repo-stage`: builds the apt, dnf, and Arch (pacman) trees into `repo-out` (GPG-signed metadata; already-signed RPMs are not signed twice; package history persists in `~/.baluard/linux-repo-history/`). The Arch leg rebuilds the pacman database from scratch each run and refreshes `aur/` (PKGBUILD version, checksum, .SRCINFO) for the AUR submission.
6. `repo-sync`: publishes `repo-out` to the package site checkout `../baluard-packages` (the `baluard-org/baluard-packages` repository; `packages.baluard.app` serves it as a custom domain), removing stale generated files and leaving author-owned files untouched. Publication commits and pushes the site repo and the package repo.

Publishing is a manual review, commit, and push of the `baluard-org` diff. The pipeline never commits or pushes. The Linux trees map to `repo/`, the F-Droid tree to the site root `fdroid/`; a push of `baluard-org` main is what updates `baluard.app` and both Linux repositories.

The F-Droid index is only as fresh as the last `baluard-org` push: `fdroid-stage` regenerates the files locally, but the served copy at `baluard.app/fdroid/repo/index.xml` moves only when the diff is published. A release is not done until the served index carries the new `versionCode` (read the `versioncode` child elements; attribute greps read nothing) and lists exactly the retention limit of APKs. The repository keeps only the newest three APKs by default (`BALUARD_FDROID_APK_RETENTION`, see [fdroid-repository.md](fdroid-repository.md)); older versions leave the main index, and there is no archive. The signed index jars (`entry.jar`, `index-v1.jar`) must ride every publish: a global `*.jar` git ignore once served them 404, so the package repo's `.gitignore` carries the `!fdroid/repo/*.jar` negation. Never drop that negation, and never publish the `fdroid/` tree without the jars.

The Play upload is its own step after the bump and the Android build: `just play-submit` releases the play-flavor AAB to internal testing (`BALUARD_PLAY_TRACK=alpha` for the closed track, production refused without `BALUARD_PLAY_ALLOW_PRODUCTION=1`). While Baluard is in pre-release, internal and closed testing must always carry the same version: upload both tracks every release, and the script's sha256 check lets the second run assign the already-committed bundle without re-uploading. The script checks the bundle pool before uploading so a burned versionCode fails the run instead of burning another, verifies the uploaded code matches the workspace, and gates on the service account at `~/.baluard/play-service-account.json`; the full rules live in [google-play.md](google-play.md).

## GitHub release staging

The published release carries ONLY stable, unversioned asset names, so the site's `releases/latest/download/<name>` links always track the newest release and no file exists twice on the release. Stage the upload set after `release-repositories`:

```sh
just release-stage
```

`scripts/stage-release-assets.sh` copies `./dist` artifacts into `release-upload/` under the stable mapping (Baluard-amd64.AppImage, Baluard-amd64.deb, Baluard-amd64.rpm, Baluard-amd64-setup.exe, Baluard-amd64-portable.zip, Baluard-cli-amd64.tar.gz, Baluard-android.apk, Baluard-extension-chrome.zip, Baluard-extension-firefox.zip, Baluard-macos-aarch64-non-notarized.zip), signs `SHA256SUMS` with the updater minisign key, and fails loudly on target collisions, unmapped files, wrong-arch or stale-version strays, or a missing `--require` entry. Note there are two signed `SHA256SUMS` files by design: `dist/` carries the versioned-name set the apt/dnf repo build consumes, while `release-upload/` carries this stable-name set for the GitHub release; the site and the repo trees each publish their own. Only the updater payloads keep per-asset `.sig` files (AppImage, setup exe, app.tar.gz); everything else is covered by the signed `SHA256SUMS`. The staging also carries the committed `updater.pub` so the README's manual checksum-verification flow works against the release page. Upload with `gh release upload <tag> --clobber release-upload/*` and keep versioned names out of the release. The versioned names stay required locally: the apt/dnf pools, the extension submit flow, and the CI artifacts all consume them.

Release notes are approved verbatim before `gh release create`, and the live-verify gate checks the published body against the closer. Every release body ends with one blank line and then exactly `As always, thanks for trying Baluard :)` on its own line. No leading word, no variants; the phrase lives in release bodies only.

## Store publishing

Explicit and manual only, never part of `release-repositories`:

```sh
just ext-submit
```

- Requires a version bump first; the Chrome upload API rejects a re-upload of an unchanged version. Reruns are otherwise safe: AMO answers 409 `Version already exists` for a resubmitted version and the submit script treats that answer as the completed state, so a run that got one store submitted and the other rejected can be finished by fixing the cause and rerunning `just ext-submit`.
- Firefox: the submission is built from `browser/firefox/dist` via `web-ext sign --channel listed`; the packaged zip is used only for the version cross-check. Every AMO submission carries the source package: build it with `scripts/build-amo-source-zip.sh <repo-root> <out-dir>` (git archive of the release commit plus a README and a reviewer-facing `build.sh`) and pass it via `AMO_UPLOAD_SOURCE`. Before submitting, run that `build.sh` in a clean temp dir and diff the rebuild against `dist/baluard-extension-<version>-firefox.zip`: byte-identical contents is the claim the reviewer holds us to.
- Chrome: curl flow against the v2 publisher API (token exchange, `-T` upload, publish with an empty body). With the CRX key present the zip is signed into a CRX3 first; the CRX media must carry the `X-Goog-Upload-Protocol: raw` and `X-Goog-Upload-File-Name: <name>.crx` headers or the store rejects even a valid signed CRX with `PKG_MUST_UPDATE_AS_CRX` (zip uploads need no such headers). The token exchange feeds each secret to curl from its own 0600 temp file: curl reads stdin once, so two `name@` stdin fields in one call silently starve the second.
- A release that adds a new manifest permission must have that permission's justification saved on the dashboard's Privacy practices tab before ext-submit runs: the Chrome upload API rejects with `INVALID_ITEM_METADATA` (`does not meet the requirements to be published`) until the tab is complete, and the fill is a manual owner step the API cannot do. 0.7.4 hit this with the new `privacy` permission; AMO's machine questionnaire never asked an equivalent question.
- First listed AMO submission needs `AMO_METADATA` (summary, categories, license). The machine-processing questionnaire was answered Yes, so treat `AMO_UPLOAD_SOURCE` as unconditional on every update, not optional.
- Partial credentials are a hard error, not a skip. A configured store failing aborts the run after the other store submitted.
- First-time setup for the Chrome API: enable the Chrome Web Store API on the OAuth client's project (`https://console.developers.google.com/apis/api/chromewebstore.googleapis.com/overview?project=<project-id>`); uploads return 403 `SERVICE_DISABLED` naming the project until then, and enabling takes a few minutes to propagate without a token re-mint. Keep the consent screen in Production (testing-mode refresh tokens expire weekly), and back up the CRX private key off this machine before opting in: losing it permanently freezes the item's update ability. The API error body carries the real reason; when a submit step fails with static text, replay the exchange-plus-upload manually and print the response body.
- Both stores are approved and automated: Chrome since 2026-11-03, the AMO 0.1.0 listing cleared 2026-11-06, and the 0.1.7 Firefox update cleared review in under ten minutes the same day. `just ext-submit` covers both stores end to end. Check AMO verdicts without the dashboard with an HMAC-JWT from `BALUARD_AMO_JWT_KEY`/`BALUARD_AMO_JWT_SECRET` against `https://addons.mozilla.org/api/v5/addons/addon/baluard@actitud.xyz/versions/?filter=all_with_unlisted`; `file_status: public` means approved and live.
- Google Play is API-driven through `just play-submit` (service-account JWT to the androidpublisher API); the signing identity, version-code rules, testing tracks, subscription model, and per-release flow live in [google-play.md](google-play.md).

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
2. Publish it with `just updates-publish <X.Y.Z>` (scripts/publish-updates-manifest.sh): generate against `release-upload` with `--strict --require-stamped`, refuse any manifest whose version does not read back as the tag, back up the live channel manifest, upload to the fixed channel (`updates-stable`, or `updates-beta` for dashed prerelease tags), verify the channel asset by API, poll the served bytes, and roll the backup back in if any check fails. `--dry-run` stops after generation. Create the channel release with `--prerelease` the first time so it can never hijack `releases/latest`; the channel release is the only mutable piece, since versioned releases and their artifacts are immutable once published.

Those mechanics are enforced by scripts/publish-updates-manifest.sh and its hermetic suite now; the incidents behind them (wrong target, stale `/tmp` file republished, silent `--clobber` no-op, CDN staleness, 0.4.6 serving 0.4.5 for a minute) are why the script backs up the channel, verifies through the API, hash-polls the served bytes, and refuses version mismatches instead of trusting quiet success.

`requireSignedVersion` stays `true` in `tauri.conf.json`: updater signatures are stamped with a `version:` trusted comment by `just release-stage` (via `scripts/sign-updater-sigs.sh`, rsign over the unwrapped Tauri key; the shipped Tauri CLI 2.12.4 writes no such comment itself). Without the stamp, the plugin refuses every install with `MissingSignedVersion`, which is exactly what any 0.1.x client got against the 0.1.2 channel manifest before it was re-signed. The CI mirror runs the same generator without `--strict`/`--require-stamped` because its windows job builds no installer; the local pipeline is the primary.

The desktop confirm-first flow: the Rust command surface (`desktop/src-tauri/src/updater.rs`) downloads only after the user accepts the UpdateBanner dialog, drains and locks vaults over IPC (`system.prepare_update`), stops the daemon, installs, and relaunches; on Windows the NSIS install step exits the app itself. The check cadence (jittered startup probe, 6h background interval, opt-out in Settings) and the pure scheduling pieces live in `desktop/src/lib/update.js`.

## Pre-release checklist

1. `just check` green (fmt, clippy, audit, tests, build).
2. `just test-release-scripts` green (the registered suites: fdroid, sync-site-repos, build-extension-packages, submit-extension-stores, build-windows-installer, build-nmh-manifests, bump-version, generate-updates-manifest, publish-updates-manifest, sign-updater-sigs, stage-release-assets, upload-play-release, build-arch-repo, build-apt-repo, verify-release-live, check-changelog, android-launcher-icons).
3. `just smoke-pkg` for the deb, and the relevant `e2e` recipes for changed surfaces (`e2e-desktop`, `e2e-android` with `just emulator`, `e2e-extension`, `e2e-extension-firefox`).
4. After the build legs, `just release-post-checks <version>` green: it fails on missing sidecars, greps the actual GitLab and Codeberg client IDs in the four consumed release sidecars, and checks the NMH manifests and the store APK version. The `strings <binary> | grep REPLACE_WITH_` probe finds exactly one match on every binary, including healthy ones: `option_env!`'s fallback literal compiles in unconditionally, so that count is inert and greping for it proves nothing.
5. Confirm the newest store zips carry the bumped version (`just ext-package` already refuses a mismatch).
6. `just dist-collect` stages `dist/` fresh: it copies the four desktop bundles in, deletes the previous release's loose files, and refuses to delete anything when a source bundle is missing, so a partial build cannot destroy the staged set of the last run. `release-repositories` runs it as its first step; the manual call is for inspecting the set before signing.

## Release-day gotchas

- The build-leg wrappers (`just build-linux|windows|android|macos`) own `/tmp/leg-<leg>.log` and refuse to launch when it exists without its `.rc`: a shell redirect like `just build-linux >log 2>&1 &` pre-creates the log and trips the guard. Launch bare, one subshell per leg; `just legs-status` reads the state.
- `dist/archive-*/` subtrees are pruned by `release-stage`'s stale-version guard, so superseded artifacts can stay under `dist/archive-<version>/`. Loose old-version files anywhere else under `dist/` still refuse the stage (`dist-collect` deletes them first, so this guard is the backstop).
- `repo-out/` is wholesale-mirrored into the packages repo by `repo-sync`; a scratch directory staged there ships silently. `sync-site-repos.sh` now refuses unexpected top-level entries, so add genuinely new outputs to its known set instead of working around the guard.
- The desktop bundles never reach `dist/` on their own: deb/rpm/AppImage land in `desktop/src-tauri/target/release/bundle/` and the NSIS setup exe in `desktop/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/`, which is why `release-repositories` starts with `just dist-collect` (0.7.3's first run staged a packages diff with zero new blobs for exactly this reason). The portable zip is the exception: its build script writes `dist/Baluard_<version>_x64-portable.zip` directly, and `dist-collect` refuses to run when that file is absent so the site's `releases/latest/download/Baluard-amd64-portable.zip` card can never point at a release without it. Two nets back a skipped or partial collect: the recipe refuses to run when a bundle is missing, and `release-sign` refuses files whose version differs from the workspace. The audit that catches anything at the end: `git -C ../baluard-packages status -uall | grep <version>` must list new blobs under `pool/`, `rpms/`, `arch/`, and `fdroid/` — a diff carrying only metadata and retention churn means the artifacts never arrived.
- When an e2e leg fails against an external site, read the FAIL dump's `url:` field before bisecting product code: the 0.7.3 chrome leg was red all cycle on a harness assertion (`document.body.innerText` excludes content hidden under the site's overlays) while the browser already sat on the success URL. Wait on `location.pathname` from inside the page instead of page text, and bound the driver's `ctx.close()` teardown so a FAIL exits promptly instead of wedging the `just` recipe for an hour.
- The deb container smoke needs `universe` enabled first: bare `ubuntu:24.04` cannot resolve libwebkit2gtk and friends, and the install dies with rc=100 on unsatisfiable Depends before any Baluard defect is tested. Enable universe, `apt-get update`, then install the deb and check `ldd` reports zero `not found`.
- `cargo audit` reports RUSTSEC-2023-0071 (rsa crate, Marvin timing side channel) permanently: the agent serves imported RSA as an explicitly accepted risk (ADR 0111), the advisory has no upstream fix, and the report is expected, not a gate failure.
- The GitHub release carries exactly the 18 stable-name assets `release-upload/` stages. The deb/rpm updater `.sig` files are deliberately absent: the mapping table marks them repo-internal (consumed by the apt/dnf trees), so their absence upstream is correct, not an upload miss.
- The Windows NSIS leg needs `TAURI_SIGNING_PRIVATE_KEY` in the environment: without it the bundle builds fine and the run then dies at updater signing (`A public key has been found, but no private key`, rc 1). Rerun with the key; the warm rebuild takes a couple of minutes.
- Probe release assets by their stable names. The `dist/` versioned names match no release asset under the stable-name scheme and 404 by design.
- Download probes must follow redirects (`curl -L`): release download URLs 302 to signed CDN URLs, and a bare curl returns an empty body that reads like a failure.
- After `just ext-submit`, delete the `.amo-upload-uuid` file web-ext leaves inside `browser/firefox/dist`: the B11 drift gate reads that directory and an untracked stray fails the next `just ext-package`.
- The F-Droid `index.xml` carries `versioncode` as child elements, not XML attributes, so attribute-shaped greps read nothing.
- The updates-stable manifest embeds each platform's signature over the exact artifact bytes: replacing an updater payload at the same version means re-stamping its `.sig`, re-uploading asset plus sig plus `SHA256SUMS`, and regenerating the manifest before the update path works again.
- When a release gate fails and you rerun it, copy the failing log aside first: every rerun writes the same `/tmp` path, and 0.7.4 lost the evidence for a once-only `test-release-scripts` failure (never reproduced across seven later runs) to exactly this.
- Changelog sections take the UTC date: run `date -u` at cut time instead of trusting the wall clock. 0.7.4 was cut at 21:41 local (UTC-3) and correctly dated 2026-11-18; both 0.7.3 and 0.7.4 landed near local midnight and hit this rule.
- Launch long recipes as real background tasks, never as a detached subshell inside a foreground tool call: when the tool call times out the whole process group dies with it. 0.7.5's `release-repositories` was killed this way mid `repo-stage` and the wait sat on a status file that was never written. The build-leg wrappers survive this because they set their own `.rc`.
- When polling a build leg that was relaunched, compare the `.rc` file's mtime against the log's mtime, not just its existence: a stale `.rc` from the failed prior run makes an existence-only wait loop exit immediately (0.7.5's macOS leg, relaunched twice after the netwatch fix, read an old rc=1 while the new build was still compiling).
- iroh 0.35 pins `netwatch 0.5`, whose published macOS route monitor calls socket2 0.6-only APIs (`Type::RAW` behind the `all` feature, `From<Socket>` for the std UnixStream added in 0.6) against socket2 0.5.x, so the macOS sidecar build fails and no newer netwatch satisfies iroh 0.35 (API break since 0.6). The vendored patch under `vendor/netwatch` (raw-libc `create_socket`, wired via `[patch.crates-io]` in BOTH the root and desktop/src-tauri Cargo.toml) is the fix; a `netwatch`-touching dependency change requires rerunning the macOS leg, because a host-target `cargo check` never compiles the macOS-only `bsd.rs` and proves nothing. macOS libc has no `SOCK_CLOEXEC` (only `O_CLOEXEC`), so the vendored socket opens bare `SOCK_RAW`.
- Wiring a new stable release asset is four edits in one pass: the stage mapping table, the `STABLE_ASSETS` require list in `release-common.sh`, the `collect-dist` required-bundles gate, and the affected script-test fixtures. 0.8.0 shipped the portable zip as site-first-class and collect-gated, yet `release-stage` still refused the stage because the mapping and require entries were missing; the audit's unmapped-artifact refusal is what caught both the gap and the residue.
- A build leg that assembles inside `dist/` must clean its staging directory after the final artifact lands, or the directory joins the stage audit's prune list: 0.8.0's `dist/portable-staging/` residue tripped the unmapped-artifact audit on the very first post-wiring release. The audit refusing unknown files is the feature; producers and the prune list stay in sync deliberately.
- Mobile-target cfg gaps surface only at the android leg: an ungated caller of a cfg-split function compiles clean on every desktop host and dies E0425 rc=101 on `aarch64-linux-android` (0.8.0's `register_dispatch` calling the desktop-only `register_for_current_exec_impl`). A host `cargo check --target aarch64-linux-android` proves nothing — ring's build script needs the NDK env the leg wrapper exports — so the only verification is rerunning the leg; `rm -f` the stale log and `.rc` sentinels first, and write cfg-exclusive bindings (a cfg'd `return` trips clippy `needless_return` under `-D warnings`).
- Release builds regenerate committed generated files, and the post-leg dirty sweep must review those diffs as content: 0.8.0's android leg regenerated the mobile UniFFI binding carrying a real catch-up (the recovery feature's updated `kitPhrase` doc that the committed copy predated). The preflight `DIRTY=0` gate forces the resolution; committing the regenerated file is the answer, not reverting it.
- The release gate's `-D warnings` turns every warning deferred as pre-existing during feature work into a hard denial, and cross-target gating needs `--all-targets`: a plain `cargo clippy --target x86_64-pc-windows-msvc` compiles lib and bins but not tests, so a cfg(unix)-only test passed the xwin check and failed only under the denied `--all-targets` run (0.8.0's launcher chmod-injection rollback test). Fix root causes at fold time and rerun `just check` after any post-gate edit instead of trusting a targeted run that looks clean.
- `just smoke-pkg` takes a PATH to a built package, not a type keyword (`just smoke-pkg deb` fails with `Unknown package type`), and the smoke scripts install via the package's own distro tooling, so on a foreign host replicate the CI matrix in containers: `podman run --network host` with the repo at `/work:Z`, ubuntu:24.04 (universe enabled, per the deb gotcha above) for the deb and fedora:43 for the rpm, `SMOKE_ARTIFACTS` pointed at a mounted dir; both containers print `SMOKE PASS` with a screenshot artifact.

## Known gaps

- macOS: ad-hoc signing only; no Developer ID certificate or notarization. The aarch64 release bundle comes off `scripts/build-macos-aarch64-deliverable.sh`, which encodes the SDK tbd shims, per-entry zip compression, and the updater-key requirement; keep its checked-in pipeline current instead of reviving /tmp copies.
- iOS: no build or store pipeline.
- Windows: no MSI (WiX is Windows-only); no Authenticode signing, so SmartScreen warns. Clean Windows machines need the VC++ redistributable (`VC_redist.x64.exe`) before the bundled exes run; the release notes carry this prerequisite and bundling it into NSIS is still open.
- Windows installer: verified interactively on the Windows 11 smoke VM (uninstall old version, clean install, app launch over WebView2). A non-interactive start (ssh, scheduled task) exits with code 123 before any UI; that is a launch-context artifact, not an installer bug. The published 0.1.3 Windows installer was rebuilt in place from commit aa5b27d2 (carrying the post-0.1.3 desktop fixes) after the install-dir fix; the git tag intentionally stays at the 0.1.3 release commit because the other platforms' artifacts were built there.
- Desktop updater: the feed endpoint and publish job exist (release.yml `publish-updates`); the residual gap is publish-side signature re-verification and manifest expiry (deferred M5/M9).
- Chrome Web Store and AMO listings: AMO 0.8.0 approved and public within minutes of submission (2026-11-21); Chrome 0.8.0 uploaded and in Google's review queue as of the same date. Store status is a per-release fact, not a standing clearance — check the AMO versions endpoint and the Chrome dashboard after each `ext-submit`.
