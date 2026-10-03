# E2E Testing Plan

Snapshot: main @ `e3a01ce`, 2026-10-03, third revision. Companion to `docs/feature-parity.md`: the parity matrix is the feature inventory; this doc defines how every feature gets an end-to-end test path. Two independent adversarial reviews against source are folded in; the enabling-work table below is the result.

## Goal

Unit tests prove parts work alone. E2E proves the product works as a whole: real processes, real sockets, real storage, real devices. The bar: no feature ships without at least one automated E2E path that exercises it through a public surface (CLI, daemon socket, desktop UI, mobile UI, or browser extension).

Principles:

- Synthetic data only. Test vaults, fake credentials, throwaway git remotes. No real secret ever enters a test, and no test artifact is ever sent to an external API.
- Hermetic. `BALUARD_DISABLE_KEYRING=1`, tempdir vaults, local bare git repos as remotes, no network beyond localhost. See harness conventions for the `.env` and egress rules.
- Deterministic first. Waits on assertions, never on sleeps. Zero-retry locally; a flaky test is a bug to fix, not a flag to set.
- Fast enough to run on every push. Layer budgets (warm build cache): CLI/daemon under 5 min, desktop under 10, mobile under 15, extension under 10.
- Platform scope: all four phases run on Linux (macOS largely untested). The CLI and desktop clients speak Unix sockets only; Windows named-pipe coverage is future work despite being a product floor.

## Harness conventions

- Spawn every child process with `current_dir(tempdir)` and a scrubbed environment (allowlist, not inherit). Both binaries call `dotenvy::dotenv()` at startup and would otherwise ingest the developer's repo-root `.env` (which lists real tokens) into test processes.
- One daemon instance per test, fresh `BALUARD_DATA_DIR` per instance. This resets the in-memory unlock rate limiter and prevents cross-test state.
- Socket paths stay short (Unix sockets cap at 104-108 bytes; long tempdir names overflow).
- Wrong-password specs: at most one failed unlock per vault, wait out the 2s handler backoff before the retry, never loop toward lockout (10 failures = 1h lockout; failed attempts also persist in `meta/kdf-attempts.json`). Lockout itself is a unit-level test, not E2E.
- `BALUARD_NO_PROMPT=1` currently answers an empty password, which burns a rate-limit failure. E3 changes it to fail loudly.
- TOTP display specs assert format, or compare against an independent implementation inside one window; never race the 30s boundary.
- Auto-lock E2E costs at least 60-90s (smallest policy is minutes, walker ticks every 30s); test the mechanism at the runtime level with paused time instead, and cover only the UI indicator in E2E.
- `git` must be on PATH (vault creation shells out to it); CI installs it.
- A settings spec that turns on `fetch_favicons` hits arbitrary external domains; assert persistence only, or run with egress blocked.

## Enabling work (prerequisites)

Small, test-enabling changes, verified against current source. E1-E6 serve Phase 1; E7 Phase 3; E8/E12 Phase 4/2; E9-E11 cross-cutting.

| # | Change | Where | Why |
|---|---|---|---|
| E1 | Gate `file://` local remotes behind a cargo feature (`e2e-hooks`), not an env var: an env var relaxes transport policy in shipped binaries. Drop `http://` from the plan entirely: the fake forge hands out `file://` clone URLs, its API surface is already reachable (`instance_url` accepts `http://127.0.0.1`, and libgit2 only demands credentials after a 401, so unauthenticated local remotes work) | `crates/baluard-core/src/sync/engine.rs` `validate_git_url` (local schemes are `cfg(test)`-only today) | The harness points vaults at local bare repos |
| E2 | One shared password helper: `ensure_unlocked_daemon` (24 call sites), `unlock_daemon`, and `vaults switch` all read `BALUARD_PASSWORD` first; `BALUARD_NO_PROMPT` fails loudly instead of answering an empty password | `crates/baluard-cli/src/commands/mod.rs` | Unattended daemon-mode operation; today only direct mode reads the env, everything else prompts and hangs |
| E3 | Non-interactive confirmations, right-sized: stdin piping is the primary mechanism (prompts read piped stdin fine under `assert_cmd`). Add `--yes`/`--force` only for destructive commands (`device enroll-with-phrase`, `export` overwrite); `vaults detach --delete-from-disk` keeps the slug retype even with `--yes` | `crates/baluard-cli/src/commands/mod.rs` (`device enroll-with-phrase`, `export`, `vaults detach`, `vaults recover-kit`, `vaults switch`) | Deterministic flows; destructive actions keep their human-proof |
| E4 | None needed. Reuse `baluard-daemon`'s exported proto types and the existing hand-rolled socket client in its test suite (`daemon_spawn.rs`, `socket_routes.rs`, ~250 KB of fixtures covering daemon spawn, routing, PIN, switching) | - | `baluard-cli` is binary-only, but the daemon crate is lib+bin and already publishes what a test client needs |
| E5 | Parameterize the GitHub provider (defer until a GitHub-specific flow is scheduled): device-flow URLs are hardcoded constants and the octocrab client (used for PAT validation too) ignores `instance_url`; raw-reqwest calls already honor an `/api/v3` override, so a stub must serve both path shapes. GitLab and Codeberg already route via their base URL and need nothing | `crates/baluard-core/src/providers/github.rs` | A fake forge must serve the GitHub flow when tested |
| E6 | `BALUARD_SOCKET` env override in `paths::socket_path()` | `crates/baluard-core/src/paths.rs` (`BALUARD_DATA_DIR` exists; the socket path has no override) | Desktop and NMH must reach a test daemon; NMH already calls `socket_path()`, so E6 alone covers it |
| E7 | Desktop escape hatch: when `BALUARD_SOCKET` is set, skip the startup `pgrep` kill (which SIGTERMs every `baluard-daemon` on the system, including the developer's real daemon and any parallel test daemon), skip the sidecar spawn, and connect to the given socket | `desktop/src-tauri/src/lib.rs` (kill + unlink + sidecar today, no override) | Point the desktop app at the Phase 3 test daemon instead of fighting it |
| E8 | Phase 4 setup mechanics: inject a fixed extension `key` into a copied `dist` at test setup (never into `manifest.base.json`, which Firefox and the store builds share); run the bridge pairing ceremony for real over the daemon socket (`pair_start`/`pair_approve`/`pair_complete`) instead of hand-seeding `bridge-pairings.json`; launch the NMH through a wrapper script exporting `BALUARD_DATA_DIR`/`BALUARD_SOCKET`/`BALUARD_DISABLE_KEYRING`; do not reuse `just install-nmh-manifest` (hardcodes `$HOME` and release paths) | `browser/`, `crates/baluard-nmh/`, new e2e fixtures | Chrome derives the extension ID from the key; the pairing state is daemon-owned |
| E9 | Machine-readable `init` output (`--json`) including the recovery phrase, or a stable phrase-output convention | `crates/baluard-cli` | Phase 1 multi-device flows must feed clone B's `device enroll-with-phrase` from A's init; parsing the decorated stdout box is fragile |
| E10 | Autosync off-switch (`BALUARD_AUTOSYNC=0`) or a rule to run sync scenarios `--direct`: autosync activates on unlock when a remote is configured and pushes with a 5s debounce, racing explicit `sync` commands in tests | `crates/baluard-runtime/src/autosync.rs`, `state.rs` | Deterministic sync/conflict scenarios |
| E11 | Hermetic spawn discipline in the harness: cwd=tempdir + env allowlist for every spawned binary (both load `dotenvy` from cwd upward); optionally a `BALUARD_NO_DOTENV` hook | harness + both `main.rs` | The repo-root `.env` holds real tokens; the plan's own no-real-secrets rule demands this |
| E12 | Skip `FLAG_SECURE` in debug/E2E builds | `mobile/.../platform/SecureFlag.android.kt` (set app-wide today) | Maestro screenshots and screenrecord return black frames otherwise; failure artifacts would be useless |
| E13 | `just test-e2e` recipe: builds `baluard-cli`, `baluard-daemon`, `baluard-nmh`, then runs the e2e target; the e2e target is excluded from `just test`. `cargo test -p baluard-cli --test e2e` alone does NOT build the daemon binary (not a dependency) and would spawn a stale one | `justfile` | Correct test-target wiring |

## Phase 1: CLI + daemon (Rust)

The highest-value layer and the cheapest. The CLI is the executable spec, so this layer IS the product E2E. It extends existing fixtures, it does not start from nothing: the daemon test suite already covers spawn/routing/PIN/switching, and its sync tests are explicitly waiting for the fake-remote fixture this plan delivers. Reuse the die-with-parent guard so orphan daemons never accumulate.

- Tools: `assert_cmd` + `predicates` + `tempfile`, driven from `cargo test` integration tests at `crates/baluard-cli/tests/e2e/main.rs`.
- Shape: tempdir vault, real daemon on a scratch socket, real `baluard` binary; assert on stdout, exit codes, and on-disk vault state (decrypted where the test owns the password). Daemon-only surface (sharing, spaces, groups, policies, approvals, reveals, escrow, activity, templates, packages, join, access, notices, contacts, bridge pairing) is exercised by speaking the protobuf protocol directly with the reused test client. Note: provider connect has no CLI command; those flows go through the socket client too.
- Multi-device conflict flows: A `init`s and pushes; B clones, runs `device enroll-with-phrase` with the phrase from A's init output (E9), then unlocks. A fresh clone carries no device key and cannot open until enrolled. Run a spike first to confirm A verifies B's roster entries and signed commits over a `file://` remote before scoping the full matrix.
- Performance: debug-mode Argon2id dominates (3.6s per unlock-class command vs 0.07s release). Add `[profile.dev.package."*"] opt-level` overrides for argon2/AEAD/hash crates, use the `mobile-low` KDF profile for harness vaults, and treat the 5-minute budget as warm-cache. CI needs rust-cache, `protoc`, and `libssl-dev`.
- Fake forge: a small local HTTP stub for the provider API surface (reuse the shape of the scripted `cfg(test)` mock in `providers/types.rs`), handing out `file://` clone URLs (E1). GitHub flows wait for E5; GitLab/Codeberg work immediately.

## Phase 2: Android (Maestro)

- Tools: Maestro, YAML flows, real device over adb in development, emulator in CI.
- Build reality: the committed-`.so` premise is false (`*.so` is gitignored; `--skip-native` only works on a machine with prior builds). CI must run `cargo ndk -t x86_64` for the emulator ABI (the existing mobile-alpha workflow already does this for arm64 with a 20-minute budget). Wait for `sys.boot_completed` before install; verify nested virtualization on the chosen runner class before designing around KVM.
- Selectors: the app has zero Compose test tags today. Add `testTag` + `testTagsAsResourceId` for Maestro `id:` selectors; pin the emulator to en-US since text selectors track the device locale.
- Biometric: drive the system prompt with injected fingerprint events (`adb emu finger touch` after enrollment) or defer to the instrumentation follow-up; Maestro cannot press BiometricPrompt itself.
- Coverage: creation wizard (recovery save sheet), unlock, list/search/detail, add/edit/delete, folders, tags, generator (with history), settings sub-pages (back gesture), vault switcher, equivalent-domains dialog. Cross-app autofill stays a UI-Automator follow-up.
- Home: `e2e/mobile/`, one YAML per journey, shared helpers file.

## Phase 3: Desktop (WebdriverIO + tauri-plugin-wdio)

- Tools: real WebKitGTK webview, real daemon, real socket via the E6/E7 escape hatch. The plugin adds `browser.tauri.execute()` and IPC mocking; E2E specs never mock the daemon.
- Prerequisites to schedule with this phase: only 11 `data-testid` attributes exist in `desktop/src` - add them along with specs; pin `LANG=en_US.UTF-8` because the UI language follows `navigator.language`.
- Native GTK file dialogs (recovery-sheet save, import/export) cannot be driven by WebDriver; add a test hook that routes those to a fixed tempdir path in E2E builds.
- Build wiring: stage the sidecar binaries (`binaries/baluard-daemon-<target-triple>`, as `linux-smoke.yml` does), build the frontend `dist` first, and carry the plugin capability via a separate E2E Tauri config (`tauri build --debug --no-bundle --config tauri.e2e.conf.json -- --features e2e`) since capabilities cannot be feature-conditional; verify the CSP `connect-src` does not block the plugin bridge.
- Per-launch state: `render-watchdog.flag` and `desktop-prefs.json` persist in `BALUARD_DATA_DIR`; every launch gets a fresh data dir.
- Coverage: setup wizard, login, unlock flows, vault view, folders/tags, generator, import/export, settings, vault switcher, sync tab (conflict banner + resolution), sharing suite, device fleet, passkey rename, password history.
- Home: `e2e/desktop/`. Fallback if wdio fights WebKitGTK: `@srsholmes/tauri-playwright`.

## Phase 4: Browser extension (Playwright + real NMH)

- Tools: Playwright bundled Chromium (branded Chrome 137+ removed the side-load flag), persistent-context launch.
- Ring 1 (real NMH, real daemon, popup surface): register the NMH manifest pointing at the real binary, run the real daemon, exercise unlock/search/fill-in-popup. Requires E6 and E8.
- Ring 2 (full chain): add a live local test page for the content-script inline autofill loop.
- Bridge read rate limits apply per pairing: one daemon plus one pairing per spec file, paced calls; pairing tokens live for hours, so ceremony setup is per-suite, not per-test.
- Firefox: Selenium + geckodriver temporary addon install, or deferred until Chromium coverage is green.
- Home: `e2e/extension/`.

## Feature-to-layer map

| Feature area | E2E layer |
|---|---|
| Vault create/unlock/lock/rotate/recover | Phase 1 (CLI+daemon) |
| Cipher CRUD, folders, tags, trash, archive | Phase 1 + Phase 2 journey |
| Attachments, import/export | Phase 1 |
| Generator, SSH keygen, TOTP display | Phase 1 + Phase 2/3 journeys |
| Settings (client + space knobs) | Phase 1 + Phase 3 UI |
| Passkeys (list/delete/rename) | Phase 1 + Phase 3 UI |
| Git sync, providers, conflicts, multi-device enrollment | Phase 1 (two clones, bare remote, fake forge) |
| Sharing: spaces, members, groups, policies, approvals, reveals, escrow | Phase 1 daemon socket client |
| Activity, notices, templates, packages, join, access review, contacts | Phase 1 daemon socket client |
| Device fleet, enrollment, revocation, rotation | Phase 1 |
| Quick unlock (PIN routes, biometric status) | Phase 1 routes + Phase 3 UI states |
| Bridge pairing ceremony | Phase 1 socket client + Phase 4 rings |
| Desktop UI journeys (all modals above) | Phase 3 |
| Android UI journeys | Phase 2 |
| Browser extension fill loop | Phase 4 ring 2 |
| System autofill / accessibility tile (cross-app) | Follow-up instrumentation, not Maestro |

## CI

- One workflow, four jobs, on push/PR to main; the existing extension workflow merges into it rather than duplicating.
- CLI/daemon: ubuntu, rust-cache, `protoc`, `libssl-dev`, `just build` + the e2e target. No display needed.
- Desktop: ubuntu + xvfb + the build dependency set from `just sysdeps` (dev headers; the deb runtime library list alone does not compile). Videos/traces on failure.
- Android: KVM-capable runner (verify nested virtualization on the chosen runner class before committing), `sys.boot_completed` wait, `cargo ndk -t x86_64` native build (`.so` files are not committed), Maestro run. Flow videos on failure (meaningful only with E12).
- Extension: ubuntu + Playwright Chromium; NMH manifest registered and pairing ceremony run in the runner profile.
- Failure artifacts upload on any failure; retention 14 days.

## Rejected options, with reasons

- tester.army/e2e: hybrid agent+deterministic runner; no desktop-app engine, emulator-focused mobile, model-in-the-loop sends UI screenshots to an external API. Revisit only for Android if Maestro's YAML proves limiting, with a local model and synthetic data.
- Plain-browser Playwright against the vite dev server with a `__TAURI__` IPC shim: the shim would fake the daemon; not E2E.
- Raw `tauri-driver`: superseded by the wdio plugin path (embedded driver, execute API, log forwarding).
- Appium, Detox: heavier than Maestro for this need; Detox leans React Native.
- Espresso/Compose instrumented tests: still the right tool for the cross-app autofill follow-up, not for whole-journey coverage.

## Status

| Item | State |
|---|---|
| Enabling work E1-E13 | Not started; E1-E6 ride with Phase 1, E10-E13 too |
| Phase 1 CLI + daemon | Not started; multi-device flow gated on a spike |
| Phase 2 Android Maestro | Not started; needs E12 + native-build CI |
| Phase 3 Desktop wdio | Blocked on this box's GTK headers (`just sysdeps`); CI carries it; needs E6/E7 |
| Phase 4 Extension | Not started; needs E6/E8 |

Rollout order: enabling work rides with its phase. Phase 1 first: no new runtime infrastructure, largest feature surface.

## Keeping this document current

When a feature lands, its PR names the E2E layer and spec file that covers it (or a deliberate skip with a reason, recorded here). When the parity matrix grows a row, this doc's map grows with it. When a tool choice changes, the rejected list gets the old choice and the reason.
