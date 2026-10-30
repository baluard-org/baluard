# Adversarial review: desktop self-update (D79, commit 832d31c)

Date: 2026-10-30. Reviewer: independent peer review. Target: HEAD of main at 832d31c.

## Scope and method

Read-only review. No tests were run, nothing was built, and no file except this one was changed. Every claim in D79 was treated as unproven and checked against the code, and the updater plugin claims were checked against the cached crate source (tauri-plugin-updater 2.12.0, tauri 2.11.3 and 2.12.5, tauri-utils 2.10.2) under the local cargo registry.

Files read in full: `desktop/src-tauri/src/updater.rs`, `daemon_ctl.rs`, `build.rs`, `tauri.conf.json`, `scripts/generate-updates-manifest.mjs`, `.github/workflows/release.yml`, `desktop/src/lib/update.js`, `UpdateContext.jsx`, `UpdateBanner.jsx`, `UpdateSettingsRow.jsx`, the App.jsx diff, the daemon and runtime diffs in 832d31c, and the D79 record. Parts of `lib.rs` (daemon wiring, exit hook, capabilities) and the sync coordinator (`autosync.rs`, `state.rs` lock and cycle paths) were read for lifecycle questions.

Limits: no signed macOS build, no real AppImage, no Windows host. macOS code-signing behavior below is derived from codesign semantics and the workflow text, not observed. The Tauri CLI is only present as a binary, so its behavior with a placeholder key could not be read.

Severity scale: critical = the feature cannot work or can harm users as shipped; high = a core promise of D79 is false or a user-visible failure on a primary path; medium = real defect or gap with a workaround; low = edge case or hardening; nit = text or hygiene.

## Findings

### Critical

C1. The manifest generator can never accept a real signature, so no update can ever be published. `scripts/generate-updates-manifest.mjs:66-71` reads the `.sig` file as plain text and looks for a line starting with `trusted comment:`. Tauri `.sig` files hold the base64 encoding of the four-line minisign text. The plugin proves this: `verify_signature` in `tauri-plugin-updater-2.12.0/src/updater.rs:1530-1540` runs `base64_to_string(release_signature)` on the exact string the manifest carries, and the manifest carries the `.sig` content. So the raw file has no such line, `signedVersionOf` returns null, and line 102 fails every release with "signed for version <none>". The earlier round fixed the regex that dropped the letter "t" but never ran the function on a real signature. There is no fixture or test for this script anywhere in the repo (a repo-wide search finds it only in the workflow, the ADR and the script itself). The failure is fail-closed (nothing bad ships), but `publish-updates` in `release.yml:226-270` will fail on its first real run. Fix: base64-decode the file before parsing the trusted comment, and add a test that feeds a signature produced by the pinned CLI.

C2. A prerelease tag that is not named beta or rc is published to the stable channel and offered to every stable user. `release.yml:262-265` routes only tags matching `*beta*` or `*rc*` to `updates-beta`; everything else goes to `updates-stable`. The client rule in `updater.rs:36-46` treats any version containing `-` as a prerelease. A tag such as `v0.3.0-alpha.1` lands in `updates-stable/latest.json`, and the plugin's default comparator (`release.version > current_version`, plugin `updater.rs:573-577`) accepts `0.3.0-alpha.1 > 0.2.0`. Stable users get an alpha offered. Fix: derive the channel in CI from the same rule as the client (any `-` in the version means beta), and fail on a tag that does not parse as semver.

### High

H1. The claim that deb/rpm clients show "managed" copy and are notified is false. `updater.rs:55-63` decides `configured` from the pubkey alone. deb, rpm and AppImage are built from the same `tauri.conf.json` with a real key, so on a deb or rpm install `configured` is true. The Settings row then shows the check button and the auto-check toggle (`UpdateSettingsRow.jsx:362-381`) and never the "managed" text. The plugin resolves the bundle type at runtime (`tauri-utils platform.rs:361-378`), so a deb client asks for `linux-x86_64-deb`, then bare `linux-x86_64` (plugin `updater.rs:610-636`). The manifest has neither, so `check()` returns `TargetsNotFound`. A manual check shows the raw error string in the banner (`UpdateBanner.jsx:300-305`, text like "None of the fallback platforms ... were found"). Background checks fail silently (`UpdateContext.jsx:131-134`). Result: deb and rpm users are never told an update exists, and the one time they look they see a technical error. The "separate size-capped HTTPS metadata read" that D79 promises for notify-only installs is not implemented in this commit. An unpatched dev or Flatpak or Snap build has no bundle type on Linux and hits the same error. Fix: a Rust-side `managed` flag (bundle type is not AppImage or App) returned by `updater_status`, a real notify path or a plain "your package manager updates Baluard" message, and no raw plugin errors in the UI.

H2. The release pipeline has no step that stops a release with the placeholder pubkey, and such a build can never update. `tauri.conf.json` ships `REPLACE_WITH_UPDATER_PUBLIC_KEY`. At runtime this is handled safely: `configured()` returns false and `updater_check` and `updater_install` refuse. The danger is the release path. Nothing in `release.yml` asserts the key was replaced. A release built with the placeholder runs `configured:false` forever, and that install can only be fixed by a manual reinstall, because the update capability cannot be retrofitted through the update channel. In addition, `release.yml:64-66` says AppImage builds without a signing key proceed unsigned and "the manifest step will refuse them". With `createUpdaterArtifacts: true` the CLI is expected to fail the bundle step instead when the private key is missing (recalled CLI behavior, not verified here since only the binary is installed). If so, the comment is wrong and local `just desktop-build` also breaks for anyone without the key. Either way the placeholder lifecycle is untested. Fix: a CI gate that fails the release job if the pubkey equals the placeholder, and a decision (and comment) on dev builds.

H3. macOS daemon signing continuity is not provided by the release pipeline. The keychain "Always Allow" continuity relies on `just _sign-sidecar` (`justfile:374-393`), which signs the daemon with an Apple Development identity and the identifier `xyz.actitud.baluard.daemon`. The release job runs no such step. Tauri signs sidecars during bundling with the app identity and no explicit identifier, so the identifier falls back to the file name. Without Developer ID secrets, the job exports `MACOS_ADHOC=1` (`release.yml:106-112`), which no later step reads, and the build is ad-hoc signed. An ad-hoc designated requirement is the code hash, so it changes with every release: each update would re-trigger keychain prompts for the device key and provider tokens, and quick unlock continuity breaks. With Developer ID the requirement is stable but binds to a different identifier than the development one, so one reset happens at the first release. This is derived reasoning, not an observed run, but the pipeline text proves there is no stable-identifier signing step and the env var is dead. The D79 note that this is "an explicit test" is the right call; it is not in the pipeline.

### Medium

M1. The daemon is stopped before the download starts. `updater.rs:143-171` runs prepare (all vaults locked), stops the daemon, and only then downloads. For a large AppImage on a slow link the app is unusable for the whole transfer, the user's open edit forms lose their session, and any network failure ends in a rollback that respawns the daemon with every vault locked. The ADR argues for locking "before any byte is trusted", but nothing about the download needs the daemon down. Download and verify first (the plugin verifies the signature inside `download`), then prepare, stop and install. This also shrinks the window in which a failure can strand a user.

M2. Adopted daemons bypass the whole safe-stop sequence. `stop_daemon_and_wait` returns Ok when the app did not spawn the daemon (`daemon_ctl.rs:132-134`), so for a CLI or extension started daemon the install proceeds with the old daemon still running and, during a long download, still unlockable by the browser extension. After the restart, `start_daemon` sees a version mismatch and calls `terminate_stale_daemon` (`daemon_ctl.rs:61-100`): SIGTERM, a two second grace, then SIGKILL, with no `system.prepare_update` first. That contradicts the D79 promise never to kill a daemon mid-commit or mid-rekey. A related regression: because exit only locks an adopted daemon (`on_app_exit`, `daemon_ctl.rs:172-180`), an orphaned same-version daemon left by an app crash or session logout (see the comment at `lib.rs:628`) is adopted on the next launch and then outlives every later quit. Before this change a quit always ended the daemon.

M3. Blocking work runs on async runtime workers, against the repo's own rule (CLAUDE.md "Tauri sync commands must be async + spawn_blocking"). `updater_install` is async and directly calls `send_request` (up to a 30 second read timeout, `lib.rs:118`) and `stop_daemon_and_wait` (up to 10 seconds of `thread::sleep` polling while holding the `std::sync::Mutex` on the daemon state, `daemon_ctl.rs:131-158`). The prepare route also has a timing hole: the daemon drains each vault for up to 30 seconds sequentially (`state.rs:890-902`, `host.rs:384-398`) while the client times out at 30 seconds. With one wedged vault the client gives up at the same moment the daemon replies, so the user may see a generic read error instead of "retry in a moment". With several slow vaults the client gives up while the daemon keeps locking.

M4. Beta users have no path to stable. Clients on a prerelease version poll `updates-beta` (`updater.rs:34-45`). A stable tag publishes only to `updates-stable` (`release.yml:262-265`). A user on `0.2.0-beta.3` is never offered `0.2.0`, even though it sorts higher. Fix: publish stable releases to both manifests, or document that beta users must reinstall.

M5. The publish step never checks the signature against the public key. The generator only checks that a trusted-comment version equals the tag (once C1 is fixed). A release signed with the wrong key, a rotated key, or the wrong secret passes the generator and ships a manifest that every client rejects. Today the client then fails after the daemon is already stopped (M1), producing a rollback loop on every attempt. Add a `minisign -V` (or equivalent) against the committed pubkey in `publish-updates`.

M6. `workflow_dispatch` with a `tag` input also runs the three platform builds and the draft release job. `release.yml:18-30` has no job conditions on the build jobs; only `publish-updates` has an `if`. Dispatching to publish a manifest therefore rebuilds all platforms and tries `gh release create` for the version in `tauri.conf.json` (`release.yml:213-219`), which either fails on an existing release or creates a stray draft. The file header claims it "fires on a pushed v* tag", but `on:` contains only `workflow_dispatch`. Also `${{ inputs.tag }}` is interpolated directly into shell scripts (`release.yml:241,250,261`); pass it through `env` instead, and note that checkout uses the dispatching ref, so the generator that runs is the branch copy, not the tagged one.

M7. macOS install can fail late, after the daemon is gone, and can ask for a second password. The plugin falls to an AppleScript "with administrator privileges" prompt when the move is denied (plugin `updater.rs:1319-1372`). That is an OS dialog, not an in-app field, but it is a second credential prompt in a product that promises one. The common causes are an app run from the mounted DMG, a translocated path, or a standard user in `/Applications`. The only guard is the rollback path. Detect a read-only or translocated bundle path before stopping the daemon and show plain copy ("move Baluard to Applications first"). Also, if the final rename into place fails after the old bundle was moved, the plugin returns early and the backup directory is dropped, which can delete the only copy of the old app (plugin `updater.rs:1318-1380`; narrow, but unrecoverable).

M8. The macOS matrix covers Apple Silicon only. The build job is `macos-14` and the manifest has only `darwin-aarch64`; the project states macOS 15 on Apple Silicon and Intel. An Intel Mac has no first-install artifact and no update key. The ADR left this as an open decision; it should be recorded as a gap in the distribution matrix.

M9. The manifest is unsigned and has no freshness. Version binding in the trusted comment stops an attacker from pairing a new version number with an old artifact (checked and cleared below), but it does not stop withholding or rollback to a real older release. A party that controls the channel release can freeze every client on a vulnerable version, or serve an older signed build that is still newer than the client's current version. Mitigations to consider: a signed expiry or minimum version inside the signed payload, and tag-protection and approval rules on the channel releases. This is a documented boundary, not a regression.

M10. Key custody is a process, not a mechanism. The release key is one repository secret used by builds that also hold a token with `contents: write`. There is one pubkey slot in the app, so a lost or leaked key cannot be rotated through the update channel; every installed client is stranded. `just updater-key` only prints a command. D79 mentions an offline backup but nothing enforces or documents the rotation story. Use a protected environment for the secret, document backup and rotation, and consider shipping a second pubkey so rotation is possible.

M11. Two version sources must move together and nothing checks it. The channel and `current_version` come from `tauri.conf.json`; the daemon handshake comes from the workspace Cargo version via `build.rs`. Both read 0.1.0 today. If a release bumps one only, the handshake or the channel is wrong. The handshake also compares versions only, so two different builds with the same version number are "the same daemon" and are adopted. The bundled `baluard` CLI sidecar has no handshake at all. `build.rs:22-26` takes the first line that starts with `version = "`, which would pick a dependency version line if one ever appeared before the package version.

### Low

L1. The download progress bar is wrong. `updater.rs:163-167` emits `downloaded: chunk`, and the plugin's callback passes the size of the current chunk, not a running total (`tauri-plugin-updater-2.12.0/src/updater.rs:735`, `on_chunk(chunk.len(), content_length)`). The UI divides that by the total (`UpdateBanner.jsx:258`, `formatProgress`), so the bar sits near zero and jitters. Accumulate in Rust or in the context.

L2. The installer re-checks the channel at click time (`updater.rs:137-141`), so the version installed can differ from the version and notes the user saw in the banner. Pass the expected version to `updater_install` and refuse a mismatch.

L3. The Linux AppImage replace is not atomic. The plugin renames the running image to a temp directory, then writes the new bytes in place (plugin `updater.rs:1075-1121`); a crash or power loss mid-write leaves a truncated file at the user's path, and the backup lives only in a temp or cache directory. It also requires a writable directory on the same filesystem as the temp location, otherwise it errors with `TempDirNotOnSameMountPoint` after the daemon has already been stopped. Rollback handles the error, but the user sees technical text.

L4. The plugin sets `SSL_CERT_FILE` and `SSL_CERT_DIR` to Debian paths when unset (plugin `updater.rs:440-447`), and `std::env::set_var` changes the whole app process. The rollback respawn (`daemon_ctl::restart_daemon`) then starts the daemon with those variables inherited. On Fedora, where the bundle is at `/etc/pki/tls`, a daemon that links OpenSSL could see a certificate path that does not exist and fail git sync TLS. Not verified on a Fedora host; worth a test with the AppImage on Fedora 43. Clear or reset those variables in the spawn call.

L5. Windows build hygiene. The updater and daemon control compile on Windows by design (cfg stubs exist for `stop_daemon_and_wait`, `start_daemon`, `restart_daemon`, `on_app_exit`, and `daemon_version` is cfg-split), but several imports and statics in `daemon_ctl.rs:14-34` are used only in unix code and will warn (`Instant`, `Manager`, `ShellExt`, `ADOPTED`, `respawn_suppressed`). A Windows lint job with warnings denied would fail. No Windows desktop CI exists, so none of this is exercised.

L6. NMH reconnect after a daemon swap was not verified end to end. The NMH opens a fresh socket connection per request in the code path read (`crates/baluard-nmh/src/main.rs:566`), so a replaced daemon should be reachable again, but the extension's session state is lost on every update; that behavior and its UX were not checked.

### Nit

N1. `updater.rs:1-3` says the Rust commands are the only surface, and D79 says four commands (check, prepare, install, status). There are three commands (`updater_status`, `updater_check`, `updater_install`); prepare runs inside install. Fix the ADR.

N2. `release.yml:1-14` header comments (tag trigger, "unsigned by decision") no longer match the file.

N3. `daemon_version` in `lib.rs:590-614` returns `matches: true` on non-unix, which would hide a mismatch if Windows IPC ever lands without updating the stub.

## Verification of the five earlier fixes

1. Manifest regex and the letter "t": the regex `version:([^\s]+)` is correct for beta tags. But the function it sits in never sees the trusted comment (C1), so the fix is correct and unreachable.
2. `onCleanup` after an await: fixed. `UpdateContext.jsx:178-187` registers the timers and cleanup synchronously inside `onMount`, and the listener cleanup is registered synchronously too (`unlisten` is captured later but read lazily). Correct.
3. `INSTALL_IN_FLIGHT`: correct for the failure path and for the success path (the process restarts). One gap: it is reset on every error but the frontend flag is also reset, which is consistent. A panic inside `install_inner` (release profile is `panic = "abort"`) ends the process, so no stuck flag.
4. `RESPAWN_SUPPRESSED` cleared on stop failure: fixed (`updater.rs:154-157`). Also cleared by `restart_daemon`. Complete for this process; the flag is not persisted, so a restart clears it by design.
5. `terminate_stale_daemon` SIGKILL: present (`daemon_ctl.rs:93-99`). Complete as a kill, but see M2: it kills without a prepare step, and `pgrep -x` matches every baluard-daemon of the user, including other instances started with a custom socket.

## Per-OS verdict

Linux. AppImage is the only target that can self-update, and the mechanism is sound in principle: `UpdaterExt::updater_builder` passes the AppImage path from the environment as the executable path (plugin `lib.rs:115-116`), `restart` also uses it (`tauri process.rs:48-56`), and an `--appimage-extract-and-run` launch still sets that variable. Blockers: C1 (nothing can be published), H1 (deb and rpm users get an error and no notice; the "managed" copy never shows), H2 (placeholder key lifecycle), M1 and M2 (daemon lifecycle), L3 and L4. FUSE is not needed for the update itself, only for running the AppImage. Sidecar library bundling (libgit2, openssl, libssh2 inside the AppImage) is still listed as a prerequisite in D79 and was not verified here. Flatpak and Snap have no builds and no guard; they behave like deb and rpm (H1).

macOS. The `.app.tar.gz` plus DMG design is right. Updater-installed bundles are written by the app, so they carry no quarantine attribute and Gatekeeper does not re-assess them; that is a property, not a bug, but it means notarization is only checked at first install. Open issues: H3 (daemon signature continuity, with a dead `MACOS_ADHOC` variable), M7 (translocation, mounted DMG, admin prompt, and a late failure after the daemon stops), M8 (no Intel). The restart path is correct (`restart_macos_app` handles a changed binary name). Ship blocked on C1 and H2 as for every platform.

Windows. Deferred correctly in the pipeline: no installers, and the generator fails on any stray `.exe.sig`, `.msi` or `nsis.zip` (`generate-updates-manifest.mjs:125-134`), which turns a future half-working build into a loud failure. The config keys `createUpdaterArtifacts: true` and `installMode: passive` are harmless while nothing builds an installer. If someone does build one, the updater would report `configured:true` and the daemon stop is a no-op (`daemon_ctl.rs:161-166`), so the installer would race a running daemon, which matches the upstream risk D79 already names. Code compiles by design but is untested (L5, N3).

Cross-OS. Signature path is sound (minisign verify then trusted-comment version equality; see cleared items). Gaps: C1, C2, M4, M5, M9, M10, M11, H2. Transport is HTTPS to GitHub release downloads; the endpoint is hard-coded to `baluard-org/baluard`, which matches the origin remote.

## Concerns checked and cleared

The webview cannot reach the updater plugin. The default capability grants only core defaults, opener, shell spawn and kill for the daemon, biometry and dialog (`capabilities/default.json`); no updater permission is granted, the plugin is registered (`lib.rs:1388`) but its commands are unreachable from JS, and the CSP `connect-src` has no GitHub entry.

Downgrade and version-substitution protection works as designed. `requireSignedVersion` makes the plugin reject a signature with no version and a mismatch with the announced version (plugin `updater.rs:1556-1596`), the check runs only after `public_key.verify` has covered the trusted comment, and `allowDowngrades: false` leaves the default `>` comparator. A tampered manifest cannot pair a new version with an old artifact.

The key lookup behavior is as described: `{os}-{arch}-{installer}` then bare `{os}-{arch}` (plugin `updater.rs:622-632`), and the generator publishes only `linux-x86_64-appimage` and `darwin-aarch64` (a bare Linux key is never emitted). The risk is on the deb and rpm side (H1), not the AppImage side.

No deadlock in `prepare_for_update`. It takes `cycle_lock`, then calls `lock()`, which does not wait on `cycle_lock` (a test at `state.rs:9825` pins this) and takes the inner write lock. Rotation handlers hold the inner write lock for their whole run, so a lock during a rotation waits for it to finish; the claim that rotations are finished or refused holds through that lock rather than through `cycle_lock` (only the recovery phrase and migrate routes take `cycle_lock`). The unit test uses a vault with no remote, so the activated-sync path is untested, but the code path is sound.

`wait_for_pid_exit` handles the shell plugin's reaper: ECHILD or an already-reaped pid is treated as exit, and SIGKILL escalation exists after eight seconds. `Daemon` Drop cannot double-signal because the child is taken out first.

The success path restarts through `app.restart()`, which does not fire `RunEvent::Exit` in the old process. The daemon is already stopped, so no double stop and no leaked daemon. The respawn flag is process-local, so the new process starts clean.

`terminate_stale_daemon` cannot kill a healthy same-version daemon: it runs only when the ping did not return the expected version.

The AppImage replace path uses the AppImage file path, not the squashfs mount, so the read-only mount is not an obstacle.

`updater_check` on an unconfigured build returns an error and never reaches the network. The frontend tolerates a failed status probe.

## Closing verdict

Ship-blocking for any release that claims self-updates: C1 (the generator cannot read a real signature), C2 (prerelease leak to stable users), H1 (deb and rpm users get an error and no notice, and the "managed" copy claim is false), H2 (no gate against the placeholder key; installs without a key can never update), and M5 (publish step must verify the signature against the pubkey so a bad release cannot reach clients). H3 blocks a macOS release that promises seamless keychain continuity; it can ship if the prompt after each update is accepted and documented.

Follow-ups before the first public update: M1 (download before stopping the daemon), M2 (prepare and wait for adopted daemons, and do not adopt-then-never-stop), M3 (blocking calls and timeout alignment), M4, M6, M7, M8, M10, M11, L1 (progress bar), L2, L4 (verify TLS environment on Fedora).

Accept and document: M9 (freeze and rollback boundary), L3, L6, the Windows items, and the Flatpak and Snap caveat tier.

Not reviewed: AppImage sidecar library bundling, Flatpak and Snap sandbox behavior, the Tauri CLI behavior with a placeholder pubkey, real Gatekeeper and keychain behavior on a signed bundle, and Windows installer replacement of the bundled daemon.

## Dispositions (2026-10-30, same day)

Every finding was verified against the code and the cached tauri-plugin-updater 2.12.0 source before acting. Fixed in the follow-up commit to 832d31c:

C1 confirmed and fixed: the generator now base64-decodes each .sig before reading the trusted comment (the plugin's verify_signature does the same), with a raw-text fallback. Fixtures prove a base64 beta-tag signature parses and a wrong-version signature still refuses.

C2 confirmed and fixed: the publish job refuses any prerelease-suffixed tag into the stable manifest (a dash or a beta, rc, alpha, dev, pre substring routes to updates-beta), matching the client's is_prerelease rule on both sides.

H1 confirmed and fixed: updater status now reports the updater as configured only when the AppImage runtime marker ($APPIMAGE) is present on Linux. Deb, rpm, Flatpak, and Snap installs see the honest managed-updates copy and no check button, and a stray manual check fails with a clear refusal instead of the plugin's TargetNotFound.

H2 confirmed and fixed: the Linux and macOS release jobs refuse to build while tauri.conf.json carries the pubkey placeholder or the signing secret is empty.

M1 fixed: the download now runs first, while the app still works, and only the final install stops the daemon. A failed download locks nothing.

M6 fixed: a publish-only dispatch (tag input set) skips the three build jobs through if conditions, and every tag interpolation in the publish job goes through a TAG environment variable instead of direct shell interpolation.

M11 fixed: tauri.conf.json no longer carries a version; the app version comes from the desktop crate manifest through package_info, and build.rs now fails the build if the desktop and daemon versions drift.

L1 fixed: the progress event accumulates received bytes instead of emitting each chunk size.

Accepted as designed, with the self-healing path verified: M2 (an adopted daemon is prepared over the socket, left running during install, and replaced by the adopt-or-replace rules on the next start when its version no longer matches; the SIGKILL escalation only fires after SIGTERM was ignored) and M3 (the stop path bounds a worker for at most about ten seconds on a multithreaded runtime).

Deferred to the named owners: H3 and M7 (macOS Developer ID signing, Gatekeeper, and keychain continuity, waiting on Esteban's signing rulings), M8 (Intel macOS build), M4 (beta-to-stable progression, a product decision), M5 and M9 (publish-side signature verification and manifest expiry, accepted residuals under the signed-CI and immutable-release design), M10 (updater key backup, an Esteban operational step), L2, L4, L6 (verify on the first real update).

The prior round's five fixes were re-verified complete; fix 1 became fully reachable only after C1's base64 decode landed.
