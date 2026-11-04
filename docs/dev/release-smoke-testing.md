# Release smoke testing from the dev box

Purpose: prove each platform build actually runs before a release, driven by an agent from the dev box (Linux). The minimum smoke per platform: launch the app, unlock the seeded vault, verify the secrets list renders, edit one entry and save it, keep proof screenshots. Every platform in this doc does those five steps; only the transport differs.

## What exists today

| Surface | Entry point | Engine | Verifies |
|---|---|---|---|
| CLI e2e | `just test-e2e` | release binary against a temp vault + socket | full CLI round trips (`crates/baluard-cli/tests/e2e`) |
| Desktop (Linux) | `just e2e-desktop [flow.mjs]` | `tauri-driver` + WebKitWebDriver under Xvfb, webdriverio client | real WebKitGTK webview DOM via `data-testid` selectors |
| Linux package | `just smoke-pkg <pkg>` | `scripts/linux-smoke.sh`: apt/dnf install of the `.deb`/`.rpm`, launch under Xvfb | dependency resolution (soname drift), process stays alive, daemon socket appears, screenshot artifact |
| Android | `just emulator` then `just e2e-emu`, or `just e2e-android` on a device | Maestro flows in `e2e/mobile/*.yaml` via `mobile/scripts/run-maestro.sh` | Compose UI markers and text asserts on a real APK |
| Browser extension | `just e2e-extension` / `just e2e-extension-firefox` | Playwright over Chromium CDP / geckodriver + real NMH + real daemon | popup DOM and the desktop bridge pairing ceremony |
| Desktop (Windows) | `just e2e-windows` | Playwright over the WebView2 CDP port baked into the SMOKE installer build, SSH-tunneled from the guest VM | same `data-testid` selectors as the Linux desktop flows |
| Desktop (macOS) | `just e2e-macos` | webdriverio over the embedded WebDriver server inside the SMOKE app bundle (WKWebView native driving), SSH-tunneled from the quickemu Sequoia guest | same `data-testid` selectors as the Linux desktop flows |

All desktop flows share one selector vocabulary (`desktop/src` `data-testid` attributes), so a flow written for Linux webview drives the Windows webview unchanged. That is the whole reason the Windows harness is thin.

## One-time setup

### Desktop Linux (tauri-driver)

- Rust toolchain + `cargo install tauri-driver --locked`.
- Xvfb and WebKitWebDriver (package `webkit2gtk4.1` on Fedora).
- Desktop npm deps: `just desktop-deps`.
- The runner builds the CLI + daemon + debug app itself (`just build` equivalents), stages the sidecar copy the app actually spawns, seeds a disposable vault through the CLI, and runs everything inside a `mktemp` sandbox: own `HOME`, own `BALUARD_DATA_DIR`, `BALUARD_DISABLE_KEYRING=1`. No manual seeding, nothing touches your real vaults.

### Android (Maestro + emulator)

- Maestro CLI: `curl -Ls "https://get.maestro.mobile.dev" | bash`.
- `adb` (Fedora: `android-platform-tools`) and the Android SDK. Emulator details: `docs/dev/dev-setup-mobile.md`.
- The emulator recipe (`just emulator`) expects an AVD named `baluard-e2e`, launches it headless (`-no-window`, software GPU, no snapshots), and is idempotent.
- Install the E2E APK on the target: `cd mobile && ./scripts/build-android-apk.sh --e2e --install`. The `--e2e` build drops FLAG_SECURE so Maestro can screenshot. The default alpha APK is arm64-only; an emulator needs an x86_64 build.
- Maestro transport rules (adb-server conflicts, `inputText` chunking, IME focus) are documented in `mobile/AGENTS.md`. Read it before writing a flow.

### Windows guest (the quickemu VM)

The Windows smoke drives the SMOKE installer build inside the Windows 11 VM from the Linux host. Nothing is installed in the guest except Baluard and your SSH key; the host drives the webview over CDP.

1. VM runs quickemu with sshd reachable on host port 22220 (setup done during the 0.1.0 smoke round; user `Quickemu`).
2. Install your SSH public key into the guest, so the harness runs `ssh -p 22220 Quickemu@127.0.0.1` with no password prompts. For an admin user the key goes into `%ProgramData%\ssh\administrators_authorized_keys` with `icacls /inheritance:r /grant SYSTEM:F /grant Administrators:F`; the user-level `authorized_keys` file is ignored for admins. A dedicated key outside `~/.ssh` works fine (`ssh -i` + `BALUARD_SMOKE_WIN_SSH` override).
3. Build and install the SMOKE build: `scripts/build-windows-installer.sh --smoke`, copy `*-smoke-setup.exe` into the guest, run it. The shipped artifact carries no debug port; the smoke build adds exactly one webview flag (see below). NSIS cannot install over SSH: Session 0 has no interactive desktop and the installer fails or hangs. Launch it through a scheduled task targeting the logged-on session, or install by hand in the VM console.
4. Seed the smoke vault once: launch the app in the guest, create a vault, master password in `BALUARD_SMOKE_PW`, and add one login entry. The smoke flow edits this entry and restores it, so the same seed serves every run.
5. `npm install` inside `e2e/windows` (set `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`; the harness only attaches over CDP, it never launches a local browser).

Why the SMOKE build exists (2026 reality, verified against wry 0.57 / tauri-runtime-wry 2.12): the WebView2 loader ignores `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` whenever the host app sets `AdditionalBrowserArguments`, and wry always sets it. wry's automation hook for `TAURI_WEBVIEW_AUTOMATION` is implemented for webkitgtk only and is a no-op on webview2, so `tauri-driver` + msedgedriver cannot drive a stock Windows build either (chromedriver fails with `DevToolsActivePort file doesn't exist`). The only working injection point is the app's own `additionalBrowserArgs`, which is baked in at build time by `desktop/src-tauri/tauri.smoke.conf.json` and applied with `--config` by the `--smoke` build.

**Never ship the debug port or the `devtools` feature in release artifacts.** Both hand a local attacker JS execution inside a password manager's webview. The flag lives only in the smoke config, applied only to smoke builds; keep it that way in review.

### macOS guest (the quickemu VM)

The macOS smoke drives the SMOKE app bundle inside the Sequoia 15 VM from the Linux host. macOS has no WKWebView driver tool, so the bundle embeds the WebDriver server (`tauri-plugin-wdio-webdriver`, the `smoke` cargo feature); `tauri-driver` and msedgedriver are Windows/Linux-only.

1. VM runs quickemu with Remote Login enabled and the smoke key authorized in the guest's `~/.ssh/authorized_keys` (host port 22221, user `smoketests`; key at `~/.local/share/baluard-smoke/mac-guest-key`). No administrators_authorized_keys split exists on macOS. The console session must be logged in (auto-login on): GUI windows only render in the Aqua session, and `open -a` from SSH still needs a live console session to attach to.
2. Build the SMOKE bundle: `scripts/build-macos-app.sh --smoke`. This is the Linux-to-macOS cross-build recipe made reproducible: cargo-zigbuild + the staged SDK at `~/.local/opt/macos-sdk/MacOSX.sdk` + a cross-built OpenSSL 3.6.3 staged at `/tmp/ossl-x86` (the repo's `OPENSSL_DIR=/usr` pins Linux headers into the C graph, so darwin targets need their own OpenSSL). Two SDK quirks are handled by the script: the SDK's tbds list `arm64e` targets that zig rejects (the `shim-tbd.py` step strips them into `framework-shims/`, and the SDK's `usr/lib` tbds are stripped in place, originals kept in `/tmp/sdk-tbd-backup`), and zig prefixes every `-L`/`-F` with the sysroot (root-relative `home/` and `tmp/` symlinks inside the SDK make the prefixed paths resolve). The tauri-cli bundler cannot emit macOS bundles on Linux, so the script assembles `Baluard-smoke.app` by hand (Info.plist, sidecars, icons).
3. Install it in the guest: `tar cf - -C desktop/src-tauri/target/x86_64-apple-darwin/release/bundle/macos Baluard-smoke.app | ssh -p 22221 smoketests@127.0.0.1 'tar xf - -C /tmp'`, then `sudo mv /tmp/Baluard-smoke.app /Applications/`. The bundle is not codesigned; tar over SSH carries no quarantine attribute, so Gatekeeper never blocks it.
4. Seed the smoke vault once: launch the app in the guest, create the vault with the master password in `BALUARD_SMOKE_PW`, add one login entry. The CLI built alongside works too: `BALUARD_PASSWORD=<pw> ./baluard init --slug baluard-smoke --name smoke --json` then `baluard --direct add login ...` in the guest.
5. `npm install` inside `e2e/macos` (webdriverio only, no browser download).

**Never ship the `smoke` feature or `tauri-plugin-wdio-webdriver` in release artifacts.** The embedded WebDriver server accepts JS execution and command mocking from any process that can reach its port. It is an optional dependency behind the opt-in `smoke` feature; shipped builds never enable it.

## How to run

```bash
# Desktop Linux (default flow: unlock; more flows: crud, generator, health, organize, settings, sharing, trash)
BALUARD_E2E_PW=e2e-desktop-pw1 just e2e-desktop

# Linux package smoke (installs the package; needs root: run in a container or CI)
just smoke-pkg repo-out/baluard_0.1.0-1_amd64.deb

# Android emulator
BALUARD_E2E_MASTER_PW=e2e-mobile-pw1 just emulator
BALUARD_E2E_MASTER_PW=e2e-mobile-pw1 just e2e-emu

# Android device (dedicated device only: flow 01 wipes app data)
BALUARD_E2E_MASTER_PW=e2e-mobile-pw1 just e2e-android

# Windows app in the guest VM
BALUARD_SMOKE_PW=smoke-vault-pw1 just e2e-windows

# macOS app in the guest VM
BALUARD_SMOKE_PW=smoke-vault-pw1 just e2e-macos
```

Windows env knobs (all optional): `BALUARD_SMOKE_WIN_SSH` (default `ssh -o BatchMode=yes -p 22220 Quickemu@127.0.0.1`), `BALUARD_SMOKE_WIN_PORT` (default 22220), `BALUARD_SMOKE_CDP` (default 9222), `BALUARD_SMOKE_ARTIFACTS` (default a temp dir), `BALUARD_SMOKE_WIN_RESET=1` wipes `%LOCALAPPDATA%\baluard` first (destructive: that directory holds the install AND the app data; reinstall the smoke build and re-seed afterwards).

macOS env knobs (all optional): `BALUARD_SMOKE_MAC_PORT` (default 22221), `BALUARD_SMOKE_MAC_USER` (default `smoketests`), `BALUARD_SMOKE_MAC_APP` (default `/Applications/Baluard-smoke.app`), `BALUARD_SMOKE_WEBDRIVER_PORT` (default 4445), `BALUARD_SMOKE_ARTIFACTS`, `BALUARD_SMOKE_MAC_RESET=1` wipes `~/Library/Application Support/baluard` in the guest (destructive: removes the seeded vault; the install survives; re-seed afterwards).

## macOS harness internals (`e2e/macos/`)

Sequence, all from the host:

1. Probe SSH reachability (`sw_vers -productVersion`).
2. On `BALUARD_SMOKE_MAC_RESET=1`, wipe the app-data directory and exit.
3. Locate the app bundle, kill leftovers (`pkill -f Baluard-smoke`, `pkill -x baluard-daemon`).
4. Launch with `open -a`, which lands the app in the console (Aqua) session. Plain SSH-spawned GUI apps are the macOS Session 0: they do not attach to the window server. No scheduled-task equivalent is needed; `open` routes through launchd.
5. Forward the embedded WebDriver port: `ssh -N -L 4445:127.0.0.1:4445`. The server is a W3C WebDriver endpoint inside the app (`tauri-plugin-wdio-webdriver`, port from `TAURI_WEBDRIVER_PORT`, default 4445).
6. Wait for `GET /status` through the tunnel (40 x 1 s).
7. webdriverio `remote()` attaches to the forwarded port with empty capabilities; the embedded server binds the session to the app's own window. Drive the five smoke steps with the shared `data-testid` selectors, exactly like the Windows flow: `login-password` -> `login-unlock` -> wait `vault-view` (30 s) -> `cipher-row` -> `detail-edit` -> edit `form-username` -> `form-save` -> reopen and assert persisted -> restore. Two idempotent rounds, so reruns need no reset.
8. Screenshots land in the artifacts dir at each stage plus `99-failed.png` on failure; pass/fail comes from DOM asserts.
9. Cleanup kills the app, the daemon, and the tunnel, success or failure.

Diagnostics learned in the 0.1.0 VM round: qemu's e1000 corrupts every slirp-to-guest frame on this qemu build (pcap-proven growing-garbage frames, silent drops, `!` rejected routes), so the guest stays on virtio-net; the OpenCore picker is patched (`DefaultVolume=macOS`, `Timeout=5`) and the recovery image detached, so every boot lands straight in macOS; the VNC password is runtime-only and must be re-applied after each relaunch (`set_password vnc` over the monitor socket, display started with `password=on`).

## Windows harness internals (`e2e/windows/`)

Sequence, all from the host:

1. Probe SSH reachability.
2. Open a persistent port forward: `ssh -N -L 9222:127.0.0.1:9222`.
3. Kill leftovers (app, daemon, orphaned `msedgewebview2.exe`: a surviving browser process silently owns the user-data folder and a new launch would join it without the debug port), then launch daemon first and app second through scheduled tasks so both land in the logged-on desktop session. Session 0 (plain SSH) refuses WebView2 and the host exits silently. Two task-specific gotchas, both hit in the 0.1.0 VM round: the app's own sidecar spawn silently fails under a scheduled task, but a daemon started the same way runs fine and the app adopts it (the Unix-only daemon kill sweep is `#[cfg(unix)]`, so Windows never kills the adopted daemon; adoption is the D79 handshake), and daemons die on keyring init under task tokens (`ERROR_NO_SUCH_LOGON_SESSION`), which is why the launch bats export `BALUARD_DISABLE_KEYRING=1`.
4. Wait for `http://127.0.0.1:9222/json/version` through the tunnel.
5. Playwright `chromium.connectOverCDP` finds the Baluard page among the CDP targets.
6. Drive the five smoke steps with the shared `data-testid` selectors: `login-password` -> `login-unlock` -> wait `vault-view` (30 s: the Argon2id KDF is slow) -> `cipher-row` -> `detail-edit` -> edit `form-username` -> `form-save` -> reopen and assert the value persisted -> edit back to the original.
7. The edit-restore pattern makes reruns work with no reset between runs.
8. Screenshots land in the artifacts dir at each stage; pass/fail comes from DOM asserts, screenshots are for human eyes (a blank webview fails the `vault-view` wait).
9. Cleanup deletes the scheduled task, kills the app, and closes the tunnel, success or failure.

**Windows installer**: NSIS fails or hangs in `/S` and scheduled-task modes under the OpenSSH session (Session 0 has no interactive desktop). Until an MSI ships, install or upgrade through a scheduled task targeting the logged-on session, or in the VM console. An `msiexec /qn`-friendly MSI is the long-term fix; MSI packaging is tracked as a separate packaging task.

**OS-level reset** (optional, between releases): boot the VM from a throwaway qcow2 overlay so the base disk never changes:

```bash
qemu-img create -f qcow2 -b ~/.local/share/quickemu/win11/disk.qcow2 -F qcow2 /tmp/smoke-overlay.qcow2
# point the .conf at the overlay, run the round, delete the overlay afterwards
```

TPM/NVRAM state lives outside the qcow2 and is shared; that is fine because the base image is already provisioned.

## Guard rails (apply to every platform)

- Fixed timeouts after unlock: KDF and daemon sidecar startup are slow by design. Wait on the unlocked-state marker with a 30 s budget; never poll with tight sleeps.
- Assert DOM/semantics, never pixels or coordinates. Pixels only as screenshot artifacts.
- Isolate entries by opening the target row, not by assuming list order beyond `.first()`.
- Idempotent flows: mutate, assert, mutate back. A failed run must not poison the next one.
- Secrets stay synthetic. `BALUARD_E2E_PW`, `BALUARD_E2E_MASTER_PW`, `BALUARD_SMOKE_PW` are throwaway values. Never a real master password, never a real vault. The mobile flows wipe app data (`clearState`); never aim them at a device holding real vaults.
- Fail closed: a missing selector, a missed wait, or a dead tunnel exits nonzero. No soft passes.

## Where the deeper rules live

- Desktop runner behavior, sidecar staging, daemon-kill warning: header of `e2e/desktop/run-e2e-desktop.sh`.
- Maestro transport rules and flow-authoring checklist: `mobile/AGENTS.md`.
- Release flow and packaging: `docs/dev/release-protocol.md`.
