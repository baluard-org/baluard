# ADR 0108: Desktop UI Stack, Webview (Tauri v2) vs Native Rust (Rune)

Date: 2026-11-14 (recorded since 2026-10; full lineage below)
Status: accepted (Tauri v2 + SolidJS retained for desktop production; the Rune spike decides the native path)
Review: peer-reviewed 2026-11-07, two independent reviews folded in; the monitoring log at the bottom carries every update since

## Decision

Retain Tauri v2 + SolidJS for desktop production. Shipping continues unaffected. The accessibility gate is closed for the framework primitive layer: screen-reader parity was measured and passed on Linux (Orca/AT-SPI, instrumented), and observed once on Windows (narrated, keyboard-driven, my own run, uninstrumented). It stays open for Baluard's own screens and custom widgets; the spike's screen-reader pass is the product-level gate. The remaining open question is rewrite cost, measured by a one-week spike. The spike is no longer gated and its go/no-go runs on pre-registered thresholds. GPUI-Kit is the named fallback if the spike fails on velocity or breadth (Decision item 5). Updates recorded 2026-11-14: reference table rebuilt with verified repository links for every candidate ever assessed, FastFrame reclassified to the egui family, GPUI-Kit v0.9.1 a11y claim recorded (unmeasured), Whisker added to monitoring, head-to-head of the two contenders added.

Lineage: first recorded as `docs/desktop-webview-vs-rust-gpui.md` in the baluard repo (commit 8a27a960), extended through GPUI-Kit v0.7.3 (5adbb416) and rust-i18n (bc3c8e4b) checkpoints, pruned for the public release in 744cdfcd (2026-11-05), re-homed 2026-11-07 to the workspace-level `docs/` folder, outside the three repos, and updated with the Rune evaluation. 2026-11-14: voice-passed and moved into the repo as this ADR, public from here on; the workspace copy is gone.

## Context

Baluard currently uses Tauri v2 with SolidJS for its desktop frontend.
This document analyzes replacing Tauri and webviews on desktop with a pure Rust GPU UI stack, and is now the canonical record for that decision.

Evaluated alternatives (every candidate ever assessed for Rust-on-desktop; repository links verified 2026-11-14):

| Candidate | Site | Repository | Family | Status in this record |
|---|---|---|---|---|
| Tauri v2 + SolidJS | https://tauri.app | https://github.com/tauri-apps/tauri | Webview | Status quo, retained for production |
| GPUI upstream (Zed) | https://gpui.rs | https://github.com/zed-industries/zed (`crates/gpui`) | GPUI | Rejected: incomplete AccessKit bindings for forms, roadmap tied to Zed |
| GPUI-CE | https://gpui-ce.github.io | https://github.com/gpui-ce/gpui-ce | GPUI | Rejected at evaluation: screen-reader parity unproven; 1.6k stars, ex-Zed maintainer core |
| GPUI-Kit (ex gpui-component, Longbridge) | https://gpui-kit.com | https://github.com/longbridge/gpui-kit | GPUI | Rejected at v0.7.3: a11y hygiene only; v0.9.1 (20.6k stars) now claims built-in AccessKit plus headless UI tests, claim unmeasured (log 2026-11-14) |
| FastFrame | https://fastframe.dev | https://github.com/crmne/fastframe | egui support crates | Reclassified 2026-11-14: egui family, not GPUI; retires several hand-rolled risk rows for an egui path only |
| Rune (Anomaly) | none | https://github.com/anomalyco/rune | Self-rendered Rust | Leading native candidate; a11y gate closed at primitive layer 2026-11-07; spike pending |
| Whisker | https://whisker.rs | https://github.com/whiskerrs/whisker | Retained Rust core + per-platform hosts | Added 2026-11-14; fails the a11y gate by absence; mobile watch item (log 2026-11-14) |

## Summary Evaluation Matrix

| Category | Tauri v2 + SolidJS (status quo) | GPUI / GPUI-CE + FastFrame / GPUI-Kit | Rune | Assessment |
|---|---|---|---|---|
| Memory zeroization | Weak (V8/JavaScript GC retains strings) | Complete (zeroize-on-drop in Rust buffers; app layer still wraps secrets) | Complete (same pattern; app layer wraps secrets) | Native wins |
| Binary size and packaging | WebKitGTK/WebView2 runtime dependencies | Single static native binary | Single static binary, embedded fonts, own renderer | Native wins |
| Security boundary | IPC boundary + webview sandbox | In-process Rust calls or 0600 socket | In-process Rust calls or 0600 socket | Native wins |
| Renderer variance | Three OS webview drivers (WebKitGTK, WKWebView, WebView2), per-driver bugs we cannot patch | One codepath, variable on Linux Vulkan and Windows DX12 | One renderer everywhere (WGSL instanced, wgpu/Metal), Linux path unproven at scale | Rune structurally best; unproven on Linux desktop breadth |
| Screen reader a11y | Native OS tree via HTML/ARIA | Incomplete AccessKit bindings | AT-SPI/Orca instrumented pass 2026-11-07 (framework primitives); Windows narrated pass same week (observed once, uninstrumented) | Rune wins at the primitive layer; product-level gate runs in the spike |
| IME | Complete system IME integration | Prone to focus bugs outside macOS | Preedit via winit; fractional-scaling IME untested | Tauri wins (untested ≠ lost) |
| i18n | JSON bundles + reactive signals | rust-i18n solves lookup; plurals/BiDi/fonts in-house | Same answer, rust-i18n is framework-agnostic | Tauri wins (narrowing) |
| Widget maturity | Production-ready forms, tables, modals | Early primitives; heavy custom dev | Core covers secure fields, virtualized lists, modals, tooltips, focus rings (verified); password-strength visualizer in-house | Rune wins within GPUI family comparison |
| Agent testability | Browser devtools + e2e harness | Weak | Headless-first: Runtime API, --snap PNG, --tree JSON, input scripts, deterministic virtual clock | Rune wins strongly |
| Maturity and backing | Mature ecosystem | Early | Pre-1.0 (repo public 2026-10-22), Anomaly dogfoods it via opencode desktop (all OSes) and mobile | Tauri wins; Rune's backing is serious |

## Why the Webview Model Itself Is Now the Weaker Bet (2026-11-07)

Dependency risk is symmetric on churn: Tauri v3 will change APIs the way v1 to v2 did, and Rune changes APIs pre-1.0. Pinning workflows absorb both.
The asymmetry is where variance lives. Tauri delegates rendering to three different webview drivers, so breakage arrives per-OS and per-driver: WebKitGTK pain on Linux is documented in this file's history and independently confirmed by the Epic Games launcher's Linux preview problems (NVIDIA blank screens, DMABUF-disabling workarounds); WKWebView carries Safari-only quirks on macOS. None of that is patchable from our side.
Rune keeps one self-contained renderer for every platform, so churn is the only remaining variance. For a password manager, deterministic cross-platform rendering of secrets UI is a product requirement, not a nice-to-have.
Counterweight, stated honestly: the flip cost is the frontend rewrite. SolidJS/TypeScript muscle becomes Rust UI code, and that productivity cost is exactly what the spike must measure.

## Security and Runtime Advantages of a Native Rust UI

### 1. Memory Hygiene and Secret Zeroization
JavaScript garbage collection does not guarantee prompt memory deallocation. Plaintext passwords, tokens, and keys can persist in engine heaps indefinitely.
In a native Rust UI the entire tree is Rust. UI state can wrap secret types in `zeroize::ZeroizeOnDrop`, clearing memory immediately on view dismiss or lock.

### 2. Attack Surface and Packaging
Tauri on Linux requires WebKitGTK shared libraries, creating distribution dependencies across distro versions.
A native Rust UI produces a standalone binary linking system graphics libraries directly and removes the webview attack surface (DOM injection, CSS exfiltration, webview IPC vulnerabilities).

## Rune Profile (added 2026-11-06, verified 2026-11-07)

- Maker: Anomaly, the opencode team (Kit Langton ex-Zed, James Long ex-Mozilla/Prettier). Anomaly is not a small unknown: opencode is a widely used coding agent whose desktop app ships native installers for macOS (Apple Silicon, Intel), Windows (x64, ARM64), and Linux (deb, rpm, AppImage, each x64 and ARM64), with an iPhone companion app for starting, steering, and approving sessions (opencode.ai downloads page, captured 2026-11-07). The desktop app is built on Rune; the mobile app is built on the same Rune Rust backend (developer-attested 2026-11-07; consistent with Rune's demo/opencode fixtures and its showreel). Rune is load-bearing for their own shipping products.
- License MIT. Repo public 2026-10-22, default branch `dev`, installed by pinning a dev rev that is never rewritten. No external PRs accepted (agents open issues). This means the roadmap stays Anomaly's alone; it is the one structural trade-off of the Rune path.
- Stack: Taffy layout, Parley text with embedded Inter, one instanced uber-quad draw call per frame in WGSL, Metal backend plus wgpu fallback, web target. Linux builds need libxkbcommon and libwayland.

### Accessibility design (the gate-closer)
- AccessKit integration is a DEFAULT feature exposing every window and overlay to UI Automation on Windows (Narrator, NVDA, JAWS), NSAccessibility on macOS, and AT-SPI on Linux (Orca).
- Lazy tree building: nothing built until an assistive client asks; incremental per-commit updates.
- Defaults derived from elements: roles, labels from text, keys as automation ids, focus, text-field value/caret/selection, inline links, scroll offsets; modal dialogs remove the background from the tree.
- Builders for description/value/checked/disabled/read_only/invalid/sorted/live_region/position_in_set/active_descendant; assistive actions (click, focus, step, set value, expand/collapse, context menu, scroll) route to the same handlers pointer and keyboard users hit.
- Secure text fields never expose content to the accessibility tree; structural, in `crates/rune/src/a11y/node.rs` and `a11y/roles.rs` (maps to AccessKit Role::PasswordInput).

### Secure input (password-manager-critical, verified in source)
- `TextEdit::secure`, single- and multi-line, with a revealed state; Debug formatting redacts as `[redacted]`; multi-line mask is a fixed 12 bullets so byte length stays hidden; hidden secure fields hash their content.
- `ElementInfo.text` is documented `none` for secure fields, giving test-level assertions that the secret never renders.

### Agent-native testing
- Every app runs headless on a fixed virtual clock: `rune::Runtime` with `frame(dt)`, `find(key)`, pointer/key/paste APIs, `accessibility_json` / `accessibility_tree` / `accessibility_action`, `elements()`.
- CLI tooling: `--snap out.png`, `--tree`, `--script FILE.json` (tap/type/key/drag/shortcut/menu-pick), `--video`, scene lists.
- UI tests live inside example binaries as ordinary `#[test]` functions; Rune's own a11y suite (22 tests) and secure suite (20 tests) pass on Linux.

### Widget gaps from the old GPUI list, now core-owned
- Virtualized lists: `.virtual_rows(count, height, key, build)` with `virtual_rows_version(Hash)`; own tests prove 10,000 rows expose setSize and per-row position with only a small mounted window.
- Focus-trapped modals: `.modal(true, close)` removes background nodes from the a11y tree; own test `modal_hides_the_background_and_live_regions_announce`.
- Tooltips: first-class `El::help`, supplying hover tooltip plus accessible description.
- Inert subtrees, roving focus groups, keyboard rings, sticky headers, rich text, canvas input handlers: all core.
- Still in-house for Baluard: password-strength visualizer; styling layer (raw `text_input` lays out but draws no chrome; rune-kit's TextInput is the styled widget).

## Measured Evidence

### Host probe (2026-11-06, Linux workstation, headless)
- Clean build at rev 4ca683561a10 (rustc 1.99.1 pin): 282 crates, 2m6s, zero errors.
- Baluard-shaped probe crate: three tests passing in 0.11s.
  1. Master password pasted into a secure field never appears in the a11y JSON; node has role `password-input` with no value.
  2. 10,000-row vault list reports `setSize=10000`, rows carry `position`, fewer than 100 nodes mounted.
  3. `El::help` reaches both `ElementInfo.help` and the a11y description.
- kit-gallery a11y census: 25 distinct roles including real tables (cells, column headers), combo boxes, progress indicators, status regions.
- Rune's own suites on Linux: `--lib a11y` 22 passed, `--lib secure` 20 passed.

### Linux desktop pass (2026-11-07, Ubuntu 24.04 GNOME Wayland VM)
- Guest build of the same rev with guest rustc 1.99.1: 1m59s, zero errors.
- Headless `--snap` inside the guest renders pixel-identical to the host run, on software Vulkan (lavapipe; gpu init 50-140ms, frames 1.6ms).
- Windowed run under the live GNOME Wayland session: window maps, focuses, no crash.
- AT-SPI: complete, correctly-typed tree in GNOME's accessibility registry (radio buttons for theme and every accent swatch, toggle buttons, labeled slider, panels, frame). Orca attaches and reads it.
- Orca announces every control with name, role, and state, as captured in its debug log during my keyboard pass: `Settings frame.`, `Auto. / Light. / Dark.` with selected/not selected, `blue. / purple. / pink. / orange. / green. / graphite.`, `Launch at login toggle button pressed.`, `Show in menu bar toggle button pressed.`, `Play sounds toggle button not pressed.`, `Reduce motion toggle button pressed.`, `Animation speed panel.`, `Animation speed slider 0.5.`, `Theme panel.`, `Accent colour panel.`
- I drove the whole window by keyboard only. No problems.
- Evidence pack: `~/Dev/Baluard/logs/rune-vm-2026-11-07/` (atspi-tree.txt, guest-dark.png, orca-speech-rune-window.log, orca-session1-debug.out).

### Windows pass (2026-11-07)
- I ran the smoke test on Windows on another machine: keyboard navigable, narrated, all OK. Reader name and machine not recorded; the functional gate stands on my direct run.
- Peer-review classification: observed once, uninstrumented. NVDA remains untested, and NVDA, not Narrator, is what most blind Windows users run.

### Showreels (2026-11-07, informational)
- Two Rune-made videos show per-element GPU effects (fire, frosted glass, chrome, riso-print theming), a 102,000-object scene, a code-review diff surface, and a working Spotify downloader, all without jank.
- No screen-reader, Wayland, or IME evidence either way. What they do prove: real apps ship on Rune within weeks of the repo going public, and heavy theming/branding is data-level (`Theme::from_json`), relevant to Baluard's brand requirements.

## Technical Blockers as Previously Written (October 2026, GPUI family)

Kept for history and because they still describe the GPUI/CE/FastFrame/GPUI-Kit path.

### 1. Screen Reader Accessibility (was the critical blocker)
Baluard non-technical users require reliable assistive technology support. HTML form controls automatically populate OS accessibility backends; GPUI relies on AccessKit; upstream Zed prioritizes code editor requirements over form widgets; AccessKit support in GPUI and third-party widget toolkits was incomplete or experimental on Linux (AT-SPI) and Windows (UIA). Custom widgets inherited the cost per widget.
Status 2026-11-07: the generalized trigger, "proven screen-reader parity in any Rust-native candidate", is met by Rune. It stays unmet by the GPUI family.

### 2. Platform Display and IME Stability
macOS Metal is reliable. Linux winit/Vulkan suffered Wayland fractional-scaling, decoration, and NVIDIA swapchain regressions. IME composition boundary failures appear in custom GPU render loops. Windows DX12 lacks WebView2's mixed-DPI testing maturity.
Status: untested for Rune. Known inputs: Rune rides wgpu on Linux, preedit via winit. This stays on the spike's measurement list, and fractional-scaling plus IME checks are cheap additions to it.

### 3. Localization and i18n
rust-i18n (v4.0.0, MIT, active) closes the string-lookup half for any Rust UI path: compile-time YAML/JSON/TOML locale maps, global `t!` macro, fallback chains, extraction tooling. Already the GPUI-ecosystem standard via gpui-component.
Still in-house on any native path: ICU/CLDR plurals, RTL/BiDi layout mirroring, font fallback chains and shaping, locale-switch reactivity, compile-time key validation (extractor plus parity test).
The existing per-locale `en.json`/`es.json`/`pt.json` port with a flattening step, and a small Rust test over `available_locales!()`, replace the vitest key-parity tests.
Decision unchanged by this row: it was never the blocker.

### 4. Ecosystem and Widget Completeness
As written for the GPUI family (virtualized tables, tooltips, focus-trapped modals, secure masked inputs and strength visualizers).
Status for Rune: the first four are core-owned and upstream-tested (see Rune profile). The strength visualizer is in-house. Secure masked input is core and better than anything the webview offers: Rust-side zeroizable buffer, length-hiding mask, content hashing, a11y exclusion, Role::PasswordInput.

## Risks

| Risk | Status 2026-11-07 |
|---|---|
| Bus factor / abandonment | Reduced, not retired. Anomaly dogfoods Rune: the opencode desktop app ships on macOS, Windows, and Linux (opencode.ai, captured 2026-11-07) and is built on Rune, and its mobile app uses the same Rust backend (developer-attested). The framework is load-bearing for shipping products. Mitigation if Anomaly pivots: pinned rev plus MIT fork. |
| Roadmap control | Asymmetric, against Rune. No external PRs accepted; the roadmap is Anomaly's alone, and a Baluard fix to Parley, the focus tree, or event propagation cannot be upstreamed. Tauri is Commons Conservancy-governed with hundreds of contributors and open RFCs; its next major version may change APIs on the project's schedule. Dogfooding lowers Rune's abandonment odds but does not open its governance. A fork of a pre-1.0 GUI engine exceeds a solo maintenance budget: pinned rev plus MIT fork is mitigation of last resort, not a plan. |
| Pre-1.0 API churn | Stands, absorbed by pinning a dev rev that is never rewritten. |
| Linux desktop breadth | Open. One renderer is structurally better than three webview drivers, but fractional scaling, IME composition, and NVIDIA on Rune's Linux path are untested. On the spike's measurement list. 2026-11-14: upstream fixed the compositor/GPU adapter mismatch (zwp linux-dmabuf feedback) that black-screened NVIDIA+integrated Wayland desktops; our own fractional-scaling, IME, and NVIDIA pass stays on the spike list. |
| Frontend rewrite cost | Open. SolidJS/TypeScript productivity becomes Rust UI code. This is now the spike's primary question. |
| rune-kit breadth | Open, small. Password-strength visualizer and any missing styling layers are in-house work. |
| Secure clipboard concealment | Open. Clear-after-timer plus history exclusion: Windows `ExcludeClipboardContentFromMonitorProcessing` family, macOS `org.nspasteboard.ConcealedType`, Wayland clipboard ownership dies with the owner window. Tauri's clipboard plugin covers part today; the native path hand-rolls it. |
| Tray and background operation | Open. Tray-only running with a live unlocked session; GPU surface behavior on hide/show cycles; GNOME ships no tray by default (StatusNotifierItem path needed). Tauri has a tray plugin today. 2026-11-14: Rune gained a first-party `Tray` (StatusNotifierItem on Linux, behind the new optional `dbus` feature); hide/show GPU surface behavior stays on the spike list. |
| Screen-capture exclusion | Open. Windows `SetWindowDisplayAffinity`, macOS `NSWindow.sharingType`; raw-handle wiring is ours. Tauri exposes `set_content_protected` today. |
| Global shortcuts and autotype | Open. Wayland has no general global-hotkey API (xdg-desktop-portal GlobalShortcuts, compositor-dependent); autotype needs XTest or the libei/RemoteDesktop portal on Linux, `SendInput`/CGEvent elsewhere. 2026-11-14: Rune added Wayland global shortcuts (behind the optional `dbus` feature; X11 shortcuts already worked); autotype remains ours. |
| Keychain and biometric glue | Open. Windows Hello, Touch ID, Secret Service. Tauri plugin ecosystem provides helpers; the native path reimplements the glue. |
| Updater, signing, notarization | Open. `tauri-plugin-updater` plus signed installers exist today; the native path owns delta updates, MSI/MSIX signing, notarization, alongside the existing apt/rpm flow. |
| Crash reporting | Open, shared. A UI panic kills the window on either stack; the daemon already isolates the core. Panic and dump scrubbing is a security requirement: plan a panic hook that never prints secret memory. |
| Security-patch intake | Open, Rune-specific. A pinned dev rev with no release tags means wgpu/winit/AccessKit/Parley fixes arrive only via Anomaly bumps or rebase onto `dev`. |
| A11y beyond screen readers | Open. High contrast, forced colors, OS font scaling, reduced transparency: webviews inherit these from the OS; a custom renderer hand-builds them. 2026-11-14: Rune follows the desktop light/dark preference on Linux via the XDG portal; high contrast, forced colors, and font scaling remain hand-built. |
| Multi-window | Open, post-spike checklist. Quick-unlock popups and floating palettes; winit multi-window across Wayland/X11/Win32 is brittle territory. |

## Decision and Action Plan

1. Retain Tauri v2 + SolidJS for desktop production today. Shipping continues unaffected.
2. The accessibility gate is closed for the framework primitive layer: trigger 1 of the original plan is met by Rune at that layer (Linux instrumented, Windows observed once). Baluard's own screens and any custom widgets still inherit per-widget a11y cost, so the spike's screen-reader pass is the product-level gate. No framework-level re-evaluation trigger remains unmet for Rune as a candidate.
3. Run the one-week spike, target `crates/baluard-desktop-rune` (throwaway, no merge):
   - Open a real vault read-only via the existing daemon socket.
   - Vault list with search; decrypted titles asserted via Rune's Runtime test API.
   - Secure master-password unlock screen with a wrong-password error.
   - Screen-reader pass on both OSes (Orca on the Ubuntu VM, NVDA and Narrator on the Windows smoke VM), every control announced and keyboard-reachable.
   - Recorded numbers: build pain, binary size, RAM, rune-kit gaps, daemon glue, and the primary new metric: rewrite velocity, a real feature implemented in Rune versus its SolidJS counterpart, to price the frontend-rewrite cost.
   - Add cheap platform checks: fractional scaling, ibus IME composition.
   - GPU lifecycle: lock the OS, suspend and resume, re-focus; the wgpu surface must recover, not panic (device-lost path).
   - Memory canary: place a unique canary secret in a real entry, unlock, reveal it, lock, then dump process memory (`gcore`) and search for the canary; run the identical dump against the Tauri build as the control.
   - Output is a go/no-go on leaving Tauri, not shipping code, decided against thresholds pre-registered before day one: zero blocking a11y defects, canary absent from memory after lock, rewrite velocity within a fixed multiple of SolidJS. A failed screen-reader pass on either OS ends the Rune path for the cycle.
4. Keep the Tauri watch running regardless: WebKitGTK regressions on Linux and WKWebView quirks on macOS are the standing evidence for this evaluation, and Tauri v3's migration cost lands on the same calendar as the Rune decision.
5. Named fallback: GPUI-Kit (v0.9.1, https://github.com/longbridge/gpui-kit). If the Rune spike fails on rewrite velocity or widget breadth, not on a11y, the question re-opens with GPUI-Kit as the candidate. Its own gate runs before any breadth work: instrumented Orca pass on Linux, NVDA on Windows, and an audit that masked fields expose no a11y value and no writable `SetValue` path, plus a decision on length-hiding display.

## Remaining Untested (Rune)

- Wayland fractional scaling and mixed-DPI.
- IME composition through ibus/fcitx5 in the Rune event loop.
- NVIDIA proprietary driver path on Linux (wgpu fallback).
- macOS VoiceOver (NSAccessibility bridge unexercised by us).
- Rune's web target.
- Long-run memory behavior with large vaults (the 102k-object showreel scene suggests headroom, unmeasured).
- GPU surface lifecycle: device-lost recovery, suspend/resume, dock/undock, monitor reconfiguration.
- Clipboard concealment flags per platform (Windows history exclusion, macOS ConcealedType), if the native path proceeds.

## Head-to-Head: Rune vs GPUI-Kit, Against Baluard's Needs (2026-11-14)

Fresh evidence pulled today: Rune's `dev` changelog (no releases yet, still pin-a-rev) and GPUI-Kit v0.9.1 documentation (accessibility guide, Input reference, both verified in their repo). The Tauri column is what we ship today, not a hypothetical. This section supersedes the matrix's GPUI-family column judgment for the two survivors; the family's other members stay rejected.

| Need | Tauri v2 (shipping today) | Rune (dev, 2026-11-14) | GPUI-Kit (v0.9.1) | Edge |
|---|---|---|---|---|
| Secure field handling | HTML password input; value excluded from the a11y tree; JS heap retains strings, weak zeroization; copy allowed once revealed | `TextEdit::secure` core-owned: fixed 12-bullet multi-line mask hides byte length, Debug redacts, hidden fields hash content, `ElementInfo.text` is `none`, `Role::PasswordInput`, excluded from the a11y tree | `Input.masked(true)` + `InputContentType::Password`: clipboard and selection excluded while masked, `mask_toggle` reveals; a11y value withheld; per-char mask leaks byte length; no hashing or redaction documented; docs warn the a11y `SetValue` action stays registered unless disabled, so assistive tech can write into a read-only field | Rune, clearly; app-side zeroization wrapper needed on both |
| Screen-reader a11y (the gate) | OS webview tree, mature, free | AccessKit default-on; measured AT-SPI/Orca instrumented pass 2026-11-07; Windows narrated once, uninstrumented; NVDA untested | Strongest README-level story in the family: per-component contracts, headless a11y snapshot tests, unusually honest docs; but its own guide says headless snapshots do not prove the platform adapter or announcements, Linux AT-SPI "depends on the deployed adapter", and no platform pass is measured | Rune, measured; GPUI-Kit documented only |
| Widgets our screens need | Everything via web | Virtualized lists, focus-trapped modals, tooltips, combobox and popup lists, tables in the kit gallery, markdown and mermaid; strength visualizer in-house | 75+ components: virtualized DataTable, validation and mask patterns, OTP input, inline tokens, dock, code editor with Tree-sitter and LSP | GPUI-Kit wider; Rune covers our actual list |
| Agent and e2e testability | Browser devtools plus our e2e harness | Headless-first on a virtual clock: Runtime API, `--snap`, `--tree`, `--script`, `--video`, `App::headless_runtime`, motion audit | Headless window tests with a11y snapshots (`test-support` feature); keyboard path verified manually in a real window; no CLI snapshot or script runner | Rune |
| OS integration (tray, shortcuts, theme, dialogs) | Plugin ecosystem ships it today | New since our evaluation: first-party tray, Wayland global shortcuts, portal light/dark, native file dialog, macOS notifications and app icon (optional `dbus` feature) | Nothing documented at this layer; component-library scope; FastFrame's shell crates are egui-only | Tauri today; Rune closed much of the gap this week |
| Renderer determinism on Linux | Three webview drivers; WebKitGTK plus NVIDIA blank screens are standing evidence | One renderer; new: compositor-matching GPU adapter via linux-dmabuf feedback, fixing the black-window class on NVIDIA+integrated Wayland desktops; our own fractional-scaling, IME, and NVIDIA pass still pending | One engine (upstream GPUI); production scale proven by Discord (~290MB) and Longbridge Pro | Rune structurally, with a fresh Linux fix; GPUI has production scale evidence |
| IME | Complete | Preedit via winit; ibus/fcitx5 untested (spike) | InputState rides GPUI's native text-input interface with IME composition; Zed's Linux IME history is rough; unmeasured | Tauri baseline; GPUI-Kit paper edge; both unmeasured |
| i18n | JSON bundles plus reactive signals | rust-i18n plus in-house plurals, BiDi, font fallback | Identical answer | Tie among natives; Tauri wins the baseline |
| Memory | WebView heap; no canary control run yet | Unmeasured by us; ships procwatch and rune-perf; recent fixes cut heap (static trees carry no motion tracks, stale layout cache bounded) | Unmeasured by us; Discord's ~290MB is third-party GPUI evidence | Even; the canary test decides |
| Governance and churn | Commons Conservancy, open roadmap; Tauri v3 migration lands on the same calendar | MIT; no external PRs; roadmap is Anomaly's alone; opencode dogfoods it | Open contribution at the component layer; engine layer pins Zed's upstream GPUI snapshots (editor-first roadmap, exact pre-release pins, one yanked release already); the GPUI-CE fork exists and GPUI-Kit does not use it | GPUI-Kit better at its layer, worse at its foundation; Rune has one churn layer, GPUI-Kit two |
| Packaging and releases | deb, rpm, msi, dmg today | Git dependency, no releases, pin a `dev` rev | crates.io semver releases (v0.9.1), ordinary Cargo dependency | GPUI-Kit |
| Rewrite cost | Zero: existing SolidJS app, team muscle, 100+ ADRs | Full frontend rewrite; AI-agent-first docs and headless checks shorten the loop | Full frontend rewrite; shadcn-like component model maps more directly from SolidJS thinking | Unmeasured either way; the spike prices Rune, a GPUI-Kit spike would price the fallback |

Verdict paragraphs:

Rune stays the primary candidate on our measured needs. It is the only contender with instrumented screen-reader parity we ran ourselves, and its secure field is core password-manager behavior: length-hiding mask, content hashing, a11y exclusion, redacted Debug. GPUI-Kit's masked input is solid (clipboard and selection exclusion while masked, reveal toggle, a11y value withheld) but its per-char mask leaks byte length, nothing documents hashing or redaction, and its own accessibility guide flags an assistive-tech `SetValue` write path that survives read-only mode. For a vault UI, that last one matters.

GPUI-Kit is promoted from rejected to named fallback. What changed: v0.9.1's a11y contracts and headless tests, crates.io release hygiene with no git-rev pinning, component breadth, and 20.6k stars with a shipping fintech app on it. What did not change: none of it is measured on our gate, and its own accessibility guide says headless snapshots prove neither the platform adapter nor announcements, with Linux AT-SPI "depending on the deployed adapter", the exact row that failed this family in October.

Rune deltas since 2026-11-07 are recorded in the risk table: tray, Wayland shortcuts, portal theme, file dialog (optional `dbus` feature), macOS notifications, the linux-dmabuf GPU-adapter fix, and heap reductions. Autotype, updater, keychain and biometrics, and clipboard concealment remain ours on either native path. The spike plan is unchanged and still aimed at Rune; per the decision section, a failure on velocity or breadth re-opens with GPUI-Kit, not a quiet default to stay on Tauri.

Open caveat carried into the spike: memory and rewrite velocity are unmeasured for both contenders. Those two cells are what the spike exists to fill; nothing in this section changes that.

## Monitoring Log

### GPUI-Kit v0.7.3 (2026-10-12)
Checkpoint against the three re-evaluation triggers. Decision unchanged at the time: retain Tauri v2 + SolidJS. None of the triggers was met. AccessKit parity: no AT-SPI or UIA backend work in the notes; accessibility hygiene only. Wayland IME and fractional scaling: no mention. Form-control parity: partially eroded (virtualized DataTable and Diff viewer, tooltip placement API, dialog contracts); secure masked inputs and strength visualizers absent. Strategic signals: opt-in `gpui-fast` retained-view backend; exact pre-release pins (`gpui-pre =0.3.9`, v0.7.2 yanked); Diff and git-history components relevant to git-backed storage.

### rust-i18n v4 assessment (2026-10-13)
Closes the string-lookup and interpolation half of the i18n gap for any Rust UI path; ecosystem standard via gpui-component. If a native path happens, adopt rust-i18n; do not author custom lookup tooling. Still in-house: ICU plurals, BiDi/RTL, font fallback chains, locale-switch reactivity, compile-time key validation.

### Discord goes native (2026-11-05)
Discord announced its desktop client rebuilt in Rust with a GPUI-based interface, dropping Electron and React Native; early Windows build around 290MB RAM versus roughly 4GB. Validated GPUI at scale; changed nothing measurable for the gate since the build is closed-source and AccessKit parity was untouched. Monitoring: Discord's Linux/Windows builds, any upstream contributions.

### Epic Games Launcher goes Tauri (2026-11-05)
Epic's new launcher preview is Tauri v2 + React with a Rust core, replacing an Unreal-based UI; about 5.5s cold start, 46% faster than Steam. Strongest third-party validation of Baluard's exact current stack. Its Linux caveat mirrors ours: WebKitGTK plus NVIDIA users hit blank screens and rendering artifacts, forcing DMABUF-disabling workarounds. Standing evidence for the renderer-variance column.

### Rune discovered (2026-11-06)
Two-week-old public repo from Anomaly became the first native-Rust candidate with accessibility designed in (AccessKit default-on) and agent-native headless testing. Trigger 1 generalized to "proven screen-reader parity in any Rust-native candidate"; README parity upgraded to measured parity within 24 hours (see next entries).

### Probe and suites green (2026-11-06)
Baluard-shaped probe: secure fields excluded from a11y tree, 10k-row virtualization with setSize/position, tooltips in element and a11y models. Rune's own a11y (22) and secure (20) suites pass on Linux. Core owns virtualized lists, focus-trapped modals, inert subtrees, roving focus, tooltips. Prototype target moved from GPUI to Rune.

### Screen-reader gate closed (2026-11-07)
Ubuntu 24.04 GNOME Wayland VM: windowed Rune under the live session, complete AT-SPI tree, Orca announcing names/roles/states/values, full keyboard drive by me. Windows: narrated and keyboard-navigable, confirmed by my direct run. Trigger 1 satisfied. Risk correction from me: Anomaly is not a small shop; opencode desktop and mobile are built on Rune. Dependency-variance argument recorded: Tauri carries churn plus three webview drivers; Rune carries churn only. Spike question reframed from "can Rune do it" to "what does the rewrite cost per feature".

### Record re-homed (2026-11-07)
This document moved from the baluard repo (pruned in 744cdfcd for the public release) to the workspace-level `docs/` folder as the private internal record, updated with the Rune evaluation.

### Peer review pass (2026-11-07)
Two independent senior-engineer reviews of this record. Both endorse retaining Tauri now; both require the gate wording scoped to the primitive layer, an OS-integration risk pass, and a respecified spike. Adopted unconditionally: gate rewording, governance-asymmetry correction (Tauri's Commons Conservancy governance versus Rune's no-external-PRs roadmap), the OS-integration risk table, the GPU device-lost and suspend/resume test, the memory-canary test, NVDA on the Windows leg, and pre-registered go/no-go thresholds. Held for the next revision: spike scope cuts, renderer-variance rewrite, mock-daemon fallback, and font-fallback coverage for non-Latin vault data.

### Reference audit: verified repo links for every candidate (2026-11-14)
All seven candidates ever assessed now carry verified repository links in the reference table. Two corrections surfaced. FastFrame reclassified: https://github.com/crmne/fastframe is "egui on rails", Carmine Paolino's support-crate suite (text, fonts, emoji, icons, themes, i18n, log, tray, dock, titlebar, shell, graphics, audio, scroll, autostart, instance, notifications, update with rollback) extracted from his shipping apps (ZapFast, Spotifast, Solco, TonePush); the record had grouped it with the GPUI family. It retires several hand-rolled rows of the risk table (tray-only running, updater, i18n lookup, autostart, notifications, single instance) for an egui path only; it says nothing about Rune's path, and egui itself was never evaluated here as a candidate. GPUI-Kit moved to https://github.com/longbridge/gpui-kit (repo formerly longbridge/gpui-component), now v0.9.1, 20.6k stars, umbrella crate over gpui-base plus gpui-component, with a Native Shell sibling rendering AI-generated UI natively on iOS, Android, GTK, and AppKit whose GPUI desktop backend is in development. Its homepage and README now claim AccessKit roles, names, states, relationships, and actions built into the interaction layer and covered by tests, plus headless UI integration testing and WebAssembly support. Claim recorded, unmeasured: the measured-parity rule applies, README parity is not trigger parity. GPUI-CE verified at https://github.com/gpui-ce/gpui-ce (1.6k stars, ex-Zed maintainer core, vouch-system contribution policy, no-genAI prose policy). Decision unchanged.

### Whisker discovered (2026-11-14)
https://github.com/whiskerrs/whisker and https://whisker.rs, pre-alpha, 63 stars, created 2026-05-13, solo maintainer (itome, 581 of roughly 600 contributions). Rust-first cross-platform UI: a retained Rust core (element tree, Taffy layout, scheduling, input routing) emits a platform-neutral frame protocol, and per-platform hosts project it: native view hierarchies on iOS and Android, DOM on web, wgpu painting on desktop. Leptos-style fine-grained signals, `render!` macro DSL, `css!` styling, no VDOM and no scripting runtime. Its differentiator is sub-second hot reload with state preserved (symbol-table and jump-table live patching over WebSocket). The repo description still says "built on the Lynx C++ engine" while the docs explicitly deny any Lynx dependency: an early architecture pivot, a churn signal consistent with pre-alpha. Desktop verdict: fails trigger 1 by absence, no accessibility story documented anywhere and no AccessKit work on the wgpu host; it does not enter the desktop race and does not displace Rune. Mobile flag, the reason it stays on watch: native-view host projection brings platform a11y, IME, and text input for free on iOS and Android, exactly where self-rendered Rust UI (Rune included) is weakest and unproven; Baluard mobile is KMP/Compose with iOS pending and baluard-core already ships UniFFI bindings, so a Rust-UI mobile path is a real future question where this architecture fits better than Rune's. Watch triggers: (a) any AccessKit or a11y work on the desktop wgpu host, (b) a second maintainer or merged external PRs, (c) text-input and IME documentation for the native-view hosts. Re-assess only if (a) or (b) happens.

### Head-to-head: Rune vs GPUI-Kit (2026-11-14)
Full section added above the log. Rune keeps the primary slot on measured a11y and the stronger secure-field model; GPUI-Kit moves from rejected to named fallback with its own pre-registered gate (instrumented Orca, NVDA, masked-field a11y write-path audit). Risk rows updated for Rune's dev deltas: first-party tray, Wayland shortcuts, portal theme, native file dialog, macOS notifications, compositor-matching GPU adapter, heap reductions. GPUI-Kit's a11y guide is the family's best README-level story and stays unmeasured; its docs admit headless snapshots prove neither the platform adapter nor announcements, and flag the `SetValue` a11y write path that survives read-only mode.
