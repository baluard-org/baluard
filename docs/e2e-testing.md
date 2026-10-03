# E2E Testing Plan

Snapshot: main @ `2cbdb0f`, 2026-10-03. Companion to `docs/feature-parity.md`: the parity matrix is the feature inventory; this doc defines how every feature gets an end-to-end test path.

## Goal

Unit tests prove parts work alone. E2E proves the product works as a whole: real processes, real sockets, real storage, real devices. The bar: no feature ships without at least one automated E2E path that exercises it through a public surface (CLI, daemon socket, desktop UI, mobile UI, or browser extension).

Principles:

- Synthetic data only. Test vaults, fake credentials, throwaway git remotes. No real secret ever enters a test, and no test artifact is ever sent to an external API.
- Hermetic. Runs on a clean machine with `BALUARD_DISABLE_KEYRING=1` (existing keyring bypass), tempdir vaults, and local bare git repos as remotes. No network services beyond localhost.
- Deterministic first. Waits on assertions, never on sleeps. Zero-retry locally; a flaky test is a bug to fix, not a flag to set.
- Fast enough to run on every push. Layer budgets: CLI/daemon under 5 min, desktop under 10, mobile under 15, extension under 10.

## Layers (chosen stack)

Four layers, one per surface. Each was chosen against alternatives; rejected options are listed at the end.

### Phase 1: CLI + daemon (Rust)

The highest-value layer and the cheapest. The CLI is the executable spec (see the CLI-first-class principle in `docs/feature-parity.md`), so this layer IS the product E2E.

- Tools: `assert_cmd` + `predicates` + `tempfile`, all pre-1.0-stable crates, driven from `cargo test` integration tests.
- Shape: each test builds a tempdir vault, spawns the real daemon binary on a scratch socket, runs the real `baluard` binary against it, and asserts on stdout, exit codes, and on-disk vault state (decrypted where the test owns the password).
- Coverage targets: vault lifecycle (create/unlock/lock/autolock), cipher CRUD, folders, tags, trash (list/restore/purge), archive, attachments, import/export (all 8+2 formats), generator, SSH keygen, TOTP display, settings (client + space knobs), passkey routes, device enrollment/revocation, root-key rotation, recovery phrase + rotation, provider connect (against a local fake-forge server), sync cycles, and multi-device conflict flows (two clones of one bare remote, commit on both, resolve).
- Daemon-only surface (sharing, spaces, groups, policies, approvals, reveals, escrow) is exercised through the same harness by speaking the protobuf socket protocol directly from a Rust test client, no UI required.
- Unlock in tests via the existing `BALUARD_PASSWORD` env path and `--direct` mode for both-mode coverage of every command.
- Home: `crates/baluard-cli/tests/e2e/` plus a `fake-forge` test server under `crates/` (tiny axum or hyper stub implementing the GitHub/GitLab/Codeberg endpoints the providers actually call).

### Phase 2: Android (Maestro)

- Tools: Maestro, YAML flows, driving the real device over adb (the wireless debugging device) in development, and an emulator in CI.
- Shape: build-install-launch via the existing `just android-install`; flows cover creation wizard (including the recovery-phrase save sheet), unlock (password and biometric-gated KEK), list/search/detail, add/edit/delete, folders, tags, generator (with history), settings sub-pages (with back gesture), vault switcher, and equivalent-domains dialog.
- Out of first scope: system autofill and accessibility-tile cross-app flows (need separate instrumentation with UI Automator; tracked as a follow-up, not a Maestro job).
- Home: `e2e/mobile/` with one YAML file per journey, shared seed commands in `e2e/mobile/helpers.yaml`.

### Phase 3: Desktop (WebdriverIO + tauri-plugin-wdio)

- Tools: the official Tauri path. `tauri-plugin-wdio` (Rust + JS) registered behind a cargo feature `e2e`, with the embedded WebDriver server plugin so no external `tauri-driver` process is needed, and the WebdriverIO Tauri service on the test side.
- Shape: real WebKitGTK webview, real daemon, real socket. The plugin adds `browser.tauri.execute()` and IPC mocking; the E2E suites use execute for session setup (seed vault path) but never mock the daemon in E2E specs - mocking is reserved for a thin component-level layer if needed.
- Prerequisite: the desktop crate must build on the dev machine. This box currently fails at `gdk-3.0` headers; `just sysdeps` prints the fix. CI (Linux + xvfb) carries the suite until then.
- Coverage targets: setup wizard, login screen (locale from settings-pub), unlock flows (password, PIN status surface, biometric button states), vault view (list, search, detail, edit, delete, archive), folders/tags UI, generator modal (with history drawer), import/export, settings modal, vault switcher (switch/close/detach), sync tab (connect, status dot, conflict banner + resolution panel), sharing suite (people, groups, collections, outboxes, contacts, bridge), device fleet panel, passkey rename, password history.
- Home: `e2e/desktop/` with `wdio.conf.ts` and one spec per modal/flow. The plugin stays out of release builds via the feature flag.
- Fallback if wdio fights the WebKitGTK setup: `@srsholmes/tauri-playwright` (socket-bridge plugin + Playwright-compatible API, native screenshots/video). Same feature-flag pattern.

### Phase 4: Browser extension (Playwright + real NMH)

- Tools: Playwright with its bundled Chromium (branded Chrome 137+ removed the extension side-load flag), persistent-context launch with `--load-extension` pointing at the built MV3 output.
- Shape, two rings:
  - Ring 1 (extension + daemon, no native messaging): load the extension, drive the popup/settings UI, mock nothing else.
  - Ring 2 (full chain): register the native messaging host manifest pointing at the real `baluard-nmh` binary, run the real daemon, and exercise the actual unlock-and-fill loop on a local test page.
- Firefox: Playwright cannot install extensions in Firefox; use Selenium + geckodriver with a temporary addon install, or defer Firefox ring 2 until Chromium coverage is green.
- Home: `e2e/extension/`.

## Feature-to-layer map

Every parity-matrix feature lands in at least one layer:

| Feature area | E2E layer |
|---|---|
| Vault create/unlock/lock/rotate/recover | Phase 1 (CLI+daemon) |
| Cipher CRUD, folders, tags, trash, archive | Phase 1 + Phase 2 journey |
| Attachments, import/export | Phase 1 |
| Generator, SSH keygen, TOTP display | Phase 1 + Phase 2/3 journeys |
| Settings (client + space knobs) | Phase 1 + Phase 3 UI |
| Passkeys (list/delete/rename) | Phase 1 + Phase 3 UI |
| Git sync, providers, conflicts, multi-device | Phase 1 (two clones, bare remote, fake forge) |
| Sharing: spaces, members, groups, policies, approvals, reveals, escrow | Phase 1 daemon socket client |
| Device fleet, enrollment, revocation, rotation | Phase 1 |
| Quick unlock (PIN routes, biometric status) | Phase 1 routes + Phase 3 UI states |
| Desktop UI journeys (all modals above) | Phase 3 |
| Android UI journeys | Phase 2 |
| Browser extension fill loop | Phase 4 ring 2 |
| System autofill / accessibility tile (cross-app) | Follow-up instrumentation, not Maestro |

## CI

- One GitHub Actions workflow, four jobs, all triggered on push/PR to main.
- CLI/daemon: ubuntu runner, `just build` + `cargo test -p baluard-cli --test e2e`. Needs no display.
- Desktop: ubuntu + xvfb + webkit2gtk runtime deps (same set as the deb bundle list). Uploads videos/traces on failure.
- Android: emulator job (KVM runner), Maestro cloud runner optional later; artifacts: flow videos on failure.
- Extension: ubuntu + Playwright bundled Chromium; ring 2 needs the NMH manifest registered in the runner's profile dir.
- Failure artifacts (logs, screenshots, flow videos) upload on any failure; retention 14 days.

## Rejected options, with reasons

- tester.army/e2e: hybrid agent+deterministic runner; no desktop-app engine, emulator-focused mobile, model-in-the-loop sends UI screenshots to an external API. Revisit only for Android if Maestro's YAML proves limiting, with a local model and synthetic data.
- Plain-browser Playwright against the vite dev server with a `__TAURI__` IPC shim: the shim would fake the daemon; not E2E.
- Raw `tauri-driver`: superseded by the wdio plugin path (embedded driver, execute API, log forwarding).
- Appium, Detox: heavier than Maestro for this need; Detox leans React Native.
- Espresso/Compose instrumented tests: still the right tool for the cross-app autofill follow-up, not for whole-journey coverage.

## Status

| Phase | State |
|---|---|
| 1 CLI + daemon | Not started |
| 2 Android Maestro | Not started |
| 3 Desktop wdio | Blocked on this box's GTK headers (`just sysdeps`); CI carries it |
| 4 Extension | Not started |

Rollout order is the phase order. Phase 1 first: it needs no new runtime infrastructure and covers the largest feature surface.

## Keeping this document current

When a feature lands, its PR names the E2E layer and spec file that covers it (or a deliberate skip with a reason, recorded here). When the parity matrix grows a row, this doc's map grows with it. When a tool choice changes, the rejected list gets the old choice and the reason.
