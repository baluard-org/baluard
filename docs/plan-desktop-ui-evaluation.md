# ADR 0008: Desktop UI Stack Evaluation — Leaving WebViews

**Date:** 2026-10-03
**Status:** Deferred. Stay on Tauri v2 + SolidJS through 1.0. Re-evaluate the GPUI Kit path after 1.0 ships. This document records the analysis so the future decision starts from facts, not memory.

## Context

The desktop client is Tauri v2 + SolidJS + Tailwind. It works. The question recorded here is whether to drop the webview and ship a native-Rust UI instead. The trigger for this evaluation was curiosity about the Rust-native UI space, not a failure of the current stack.

This document holds three things: the verified state of the candidate frameworks as of 2026-10-03, an honest cost/benefit for Baluard specifically, and the conditions under which the decision reopens.

All version numbers and download counts below were verified on 2026-10-03. This ecosystem moves fast. Re-verify before acting on anything in here.

## Baseline: what the current stack gives and costs

Given:

- Web platform maturity for free: text selection, IME, clipboard, virtualized lists, forms, focus management. The FocusTrap + ARIA work already in the app rides on this.
- i18n via `en`/`es`/`pt` JSON with key-parity tests.
- The desktop app is already a thin renderer over the daemon. All privileged work happens behind the Unix-socket protobuf IPC, with a `DESKTOP_ALLOWED_ACTIONS` whitelist on the Tauri side. The UI holds no key material and makes no crypto decisions.
- Windows: WebView2, bundled. macOS: system WebKit (WKWebView). No runtime web dependency to ship on either.

Costed:

- Linux packaging is the one real pain. `bundle.linux` declares system deps (webkit2gtk, gtk3, ayatana-appindicator, libgit2, openssl, libssh2), and deb soname package names (`libgtk-3-0t64`, `libgit2-1.9`, `libssl3t64`) drift between distro releases. This is a documented recurring gotcha.
- Two languages for desktop: the UI surface is JS, the product logic is Rust.
- Webview process memory and startup are heavier than a native window. Not user-visible on any target hardware today.

The structural asset worth naming: because the webview is only a renderer over the daemon contract, a UI-framework swap is contained to `desktop/src` + `desktop/src-tauri`. Core, daemon, runtime, CLI, NMH, and mobile do not move. The IPC boundary is what makes the exit path survivable.

## Candidates evaluated

Three, in the order encountered. Two are ecosystem signals. One is a real option.

### GPUI-CE (community fork of Zed's GPUI)

Facts, verified 2026-10-03:

- crates.io `gpui-ce` 0.2.2, published 2026-08-28. ~10.5k recent downloads, 31 dependents. The 0.3.x line was published then yanked and rewound to 0.2.x, which signals versioning churn in the first year.
- GitHub org created 2025-12. 542 stars, 2 public repos. Governance: public RFCs, community maintainer team. Not affiliated with Zed Industries.
- Renderers: Metal (macOS), Wayland/X11 (Linux), Win32 + DirectWrite (Windows). AccessKit for a11y. Taffy layout, Lyon paths, resvg SVG.
- The fork's own README says the best way to learn the APIs is to read the Zed source, and that pre-1.0 breaking changes between versions are normal. The fork decoupled releases from Zed. It did not fix the documentation gap.

Verdict: real and alive, but young. A framework foundation, not a product stack. Not a dependency for Baluard. Watch.

### Ely GPUI Components

Facts, verified 2026-10-03:

- Repo created 2026-09-30. 369 stars. 392 of 393 contributions from one person. Repo self-describes as "early", tracking components in `TASKS.md`.
- Live gallery at elygpui.com runs real GPUI code compiled to WebAssembly. Genuinely nice demo mechanism.
- macOS only. The README says "Tested on macOS only" and the capture tool is macOS-specific. A Linux gap report was filed within a day of launch documenting that buttons, forms, and navigation set no AccessKit roles and no element ids.
- Not on crates.io. Git dependency pinning upstream `zed-industries/zed` gpui at a fixed rev. License field says Apache-2.0, README says MIT or Apache-2.0.

Verdict: a design showcase, not a library to depend on. The a11y gap alone disqualifies it for a password manager. Watch as an ecosystem signal only.

### GPUI Kit (longbridge)

Facts, verified 2026-10-03:

- The production option. GitHub ~15k stars, project live since 2024-06. Layers: `gpui-base` (unstyled behavior: focus, selection, overlays, virtualization, accessibility), `gpui-component` (75+ styled components, shadcn-inspired, Lucide icons, semantic-token themes), `gpui-shell` (optional JS extension runtime with per-capability grants), `gpui-kit` umbrella crate.
- Packaging solved their own way: `gpui-pre*` crates are snapshots of upstream Zed GPUI published to crates.io. Apps depend on one versioned crate, no git revs. The ecosystem is consolidating around these snapshots rather than the gpui-ce fork.
- crates.io: `gpui-component` since 2025-02, now 0.7.0, 171k total downloads, ~106k recent. `gpui-kit` umbrella since 2026-09, already 38k downloads and 37 dependents. Release cadence: four releases in September 2026 alone.
- Production-proven: Longbridge Pro, a shipped commercial trading desktop, runs on it across macOS, Windows, and Linux.
- CI runs the full test suite, including headless UI integration tests, on aarch64-macOS, x86_64-Linux, and x86_64-Windows on every push. Metal rendering tests run on macOS. Lint and doc tests are macOS-only today.
- Accessibility: AccessKit roles, names, states, relationships, and actions built into the interaction layer and covered by tests.
- Testing: `gpui_kit::test` renders real components in headless windows, drives pointer and keyboard input, and asserts state, focus, layout, and a11y properties. Maps directly onto an E2E-first protocol.
- i18n built in via `rust-i18n`. WASM target for component showcases.
- Churn is real: 0.5 to 0.7 inside a year, occasional yanked releases. Pre-1.0.
- Dead weight for Baluard: rope/tree-sitter/LSP code editor, dock layout, JS extension host. Relevant weight: forms, virtualized lists, tables, dialogs, theming, i18n, the test harness.

Verdict: the only credible exit path. Not yet the moment to walk it.

## Comparison

| | GPUI-CE | Ely | GPUI Kit |
|---|---|---|---|
| Role | Framework fork | Design system | Component framework |
| Age | ~10 months | 4 days | ~2 years (component crate) |
| Platforms verified | macOS/Linux/Windows (upstream GPUI) | macOS only | macOS/Linux/Windows, full CI matrix |
| A11y | AccessKit at framework level | None set | Built in and tested |
| i18n | None | None | `rust-i18n` built in |
| Testing | Framework-level only | None documented | Headless UI integration harness, cross-platform |
| Packaging | crates.io, churn history | Git pin to Zed rev | crates.io snapshots, pinned exactly, CI-enforced |
| Production use | None known | None | Longbridge Pro, commercial, all three OSes |
| Docs | Thin ("read Zed source") | Site only | Full docs site + agent skills |
| License | MIT OR Apache-2.0 | MIT OR Apache-2.0 (field mismatch) | Apache-2.0 |

## Platform reality on GPUI Kit

Works on all three, not evenly:

| Platform | Renderer | Windowing | State |
|---|---|---|---|
| macOS | Metal | native | First class. Zed's home turf, years of production. |
| Linux | wgpu (Vulkan) | Wayland primary, X11 secondary | Good on sane drivers. Mesa on the target distros (Ubuntu 26.04, Fedora 43) is standard. NVIDIA proprietary has a quirk history. |
| Windows | DirectX 11 | Win32 | Functional and shipping, youngest backend (2025-vintage). IME and accessibility fixes still land upstream. |

Upstream GPUI fixes reach GPUI Kit on longbridge's snapshot cadence, not Zed's. Factor that lag into any future security or platform-regression response.

## What leaving webviews buys

- One language for desktop. The JS surface disappears; the whole client is Rust.
- WebKitGTK leaves the Linux package. That deletes the soname-drift class of breakage at the root. The replacement is a Vulkan runtime dependency, which is standard on the target distros.
- Native window: faster startup, less memory, no webview process.
- Option to host `baluard-runtime` in-process, as mobile already does. The daemon stays for CLI, NMH, and multi-client use regardless.
- Rust UI tests run in CI headless on all three platforms.

## What it costs

- A full rewrite of `desktop/src`: login screen and vault unlock, setup wizard, VaultView (sidebar, list, detail), cipher editor, settings (including provider and sharing UI), conflict banner and resolution panel, vault switcher, auto-sync indicator, toasts, generator, every modal, FocusTrap equivalents, theme handling. Months of work for zero user-visible gain at the end.
- i18n rebuild on `rust-i18n` plus new parity tests. A11y parity work plus screen-reader verification on all three OSes.
- Exposure to pre-1.0 API churn in the framework, the component layer, and the upstream snapshot, three moving layers instead of one.
- A dependency-class swap, not a dependency deletion: WebKitGTK on Linux becomes Vulkan drivers; WebView2 on Windows becomes DX11. Both are more standard than webkit2gtk packaging, but neither is zero.
- A parallel port of a working app is the one move that reliably ships two half-apps. If this ever happens, it is a single replacement, not a migration.

## Decision triggers

Reopen this decision when any of these is true, not before:

1. Baluard 1.0 has shipped. Capacity is the binding constraint until then.
2. A concrete webview pain materializes: a WebKitGTK break on a target distro release, a webview security incident without vendor patch, or OS-level webview deprecation.
3. GPUI Kit reaches 1.0, or holds a stable line for 6+ months without a breaking release.
4. A new desktop-only project starts greenfield. There, GPUI Kit is the default stack, and this document is why.

Not triggers: curiosity, novelty, language purity. The current stack has no failing requirement.

## Recommendation

Stay on Tauri v2 + SolidJS through 1.0. No spike, no parallel port. Track GPUI Kit as the single exit path; ignore Ely until it ships on crates.io with cross-platform CI and a11y; treat GPUI-CE as upstream context. When a trigger above fires, redo the data pass in this document first: every number in it expires.
