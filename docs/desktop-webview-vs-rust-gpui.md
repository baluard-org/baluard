# Evaluation: Webview (Tauri v2) vs Native Rust UI (GPUI) for Baluard Desktop

Status: Evaluated (October 2026). Decision: Retain Tauri v2 + SolidJS for desktop production; monitor GPUI and AccessKit ecosystem evolution. Last checkpoint: GPUI-Kit v0.7.3 (2026-10-12), decision unchanged. Monitoring log at the end of this document.

## Context

Baluard currently uses Tauri v2 with SolidJS for its desktop frontend.
This document analyzes replacing Tauri and webviews on desktop with a pure Rust GPU UI stack (GPUI / GPUI-CE / FastFrame / GPUI-Kit).

Evaluated references:
- GPUI upstream: https://gpui.rs/
- GPUI Community Edition: https://gpui-ce.github.io/
- FastFrame: https://fastframe.dev/
- GPUI-Kit: https://gpui-kit.com/

## Summary Evaluation Matrix

| Category | Tauri v2 + SolidJS (Status Quo) | GPUI / GPUI-CE + FastFrame / GPUI-Kit | Assessment |
|---|---|---|---|
| Memory zeroization | Weak (V8/JavaScript GC retains strings) | Complete (zeroize-on-drop in Rust buffers) | GPUI wins |
| Binary size and runtime packaging | WebKitGTK/WebView2 runtime dependencies | Single static native binary, GPU drivers only | GPUI wins |
| Security boundary | IPC boundary + webview sandbox | In-process Rust calls or 0600 socket | GPUI wins |
| Display and driver stability | High (tested webview compositor backends) | Variable on Linux Vulkan and Windows DX12 | Tauri wins |
| Screen reader accessibility (a11y) | Native OS accessibility tree via HTML/ARIA | Incomplete AccessKit bindings (Linux/Win) | Tauri wins (Blocker) |
| Input Method Editors (IME) | Complete system IME integration | Prone to focus bugs outside macOS | Tauri wins |
| Internationalization (i18n) | Simple JSON bundles + reactive signals | Custom font fallback, layout, and lookup | Tauri wins |
| Widget maturity | Production-ready forms, tables, modals | Early-stage primitives; heavy custom dev | Tauri wins |

## Security and Runtime Advantages of GPUI

### 1. Memory Hygiene and Secret Zeroization
JavaScript garbage collection does not guarantee prompt memory deallocation. Plaintext passwords, tokens, and keys can persist in engine heaps indefinitely.
In GPUI, the entire UI tree is Rust. UI state can wrap secret types in `zeroize::ZeroizeOnDrop`, clearing memory immediately on view dismiss or lock.

### 2. Attack Surface and Packaging
Tauri on Linux requires WebKitGTK shared libraries (`libwebkit2gtk-4.1` / `libjavascriptcoregtk`), creating distribution dependencies across distro versions.
GPUI produces a standalone native binary linking system graphics libraries directly. It removes the webview attack surface (DOM injection, CSS exfiltration, webview IPC vulnerabilities).

## Technical Deficiencies and Blockers in GPUI (October 2026)

### 1. Screen Reader Accessibility (Critical Blocker)
Baluard non-technical users require reliable assistive technology support.
HTML form controls automatically populate OS accessibility backends (AT-SPI on Linux, UI Automation on Windows, NSAccessibility on macOS).
GPUI relies on AccessKit.
Upstream Zed prioritizes code editor requirements over form widgets.
On macOS, basic NSAccessibility works.
On Linux (AT-SPI) and Windows (UI Automation), AccessKit support in GPUI and third-party widget toolkits remains incomplete or experimental.
Custom widgets in FastFrame and GPUI-Kit do not reliably generate semantic accessibility nodes, live regions, or dialog focus traps.

### 2. Platform Display and IME Stability
macOS uses Metal and operates reliably.
Linux relies on `winit` / `blade` / Vulkan. Wayland fractional scaling, server-side vs client-side decorations, and NVIDIA proprietary driver swapchains suffer recurring regressions.
Complex IME input (ibus, fcitx5) for non-Latin and accented text frequently suffers focus and composition boundary failures in custom GPU render loops.
Windows DirectX 12 integration lacks the extensive mixed-DPI monitor testing present in Microsoft WebView2.

### 3. Localization and Internationalization (i18n)
Tauri leverages standard web font resolution, BiDi algorithms, and simple reactive i18n dictionaries (`en.json`, `es.json`, `pt.json`).
GPUI requires manual configuration for font fallback chains and shaping.
Neither FastFrame nor GPUI-Kit provides a localization subsystem, requiring Baluard to author custom string interpolation, pluralization, and layout mirroring logic.

### 4. Ecosystem and Widget Completeness (soft blocker, in-house work)
FastFrame and GPUI-Kit provide basic buttons and inputs modeled after Tailwind syntax.
They lack production implementations for:
- Virtualized multi-column lists and tables
- Clipped tooltip and overlay positioning
- Focus-trapped modal dialogs
- Password strength visualizers and secure masked text inputs with toggle controls

Reassessment (2026-10-12): this gap is engineering effort we control, not a permanent blocker. GPUI primitives support full custom components, and v0.7.3 already erodes the list (virtualized Diff viewer, maturing DataTable, tooltip and dialog contracts).
The secure masked input is also where GPUI beats the webview: a Rust-side input buffer can be zeroized on drop, which JavaScript GC never guarantees. The custom password field is the strongest argument for GPUI in a password manager.
The real cost sits one layer down: every custom widget must hand-wire its AccessKit roles, focus semantics, and screen-reader announcements against a bridge that is still incomplete on Linux and Windows. Custom components inherit blocker 1; they do not bypass it, and the a11y wiring cost repeats per widget.

## Decision and Action Plan

1. Retain Tauri v2 + SolidJS for desktop production. Accessibility and cross-platform UI stability are strict product requirements.
2. Re-evaluate GPUI when:
   - AccessKit reaches parity across Linux (AT-SPI) and Windows (UI Automation) inside GPUI or GPUI-CE.
   - Wayland IME handling and fractional scaling stabilize.
   - FastFrame or GPUI-Kit reaches feature parity for accessible form controls. Widget parity is partly buildable in-house, but that work only pays off after the first trigger (AccessKit parity) lands: every hand-built control depends on it.
3. If prototyping is desired, implement a non-production experimental crate under `crates/baluard-desktop-gpui` targeting read-only vault inspection over the existing daemon socket.

## Monitoring Log

### GPUI-Kit v0.7.3 (2026-10-12)

Checkpoint against the three re-evaluation triggers. Decision unchanged: retain Tauri v2 + SolidJS. None of the triggers is met.

**Trigger status**

1. **AccessKit parity on Linux (AT-SPI) and Windows (UI Automation): no movement.** The release ships accessibility hygiene only: the DataTable sort icon became a labelled button (#3396), `DropdownButton` gained `menu_accessibility_label` with a localized "More options" default (#3410), context menus now take focus before their first frame, fixing a debug-build abort with accessibility active (#3422), and focus rings stay inside list viewports (#3394). No AT-SPI or UIA backend work appears in the notes. The crash fix shows accessibility runs but remains fragile.
2. **Wayland IME and fractional scaling: no mention** in the release notes. The only platform-stability items are the optional `gpui-fast` backend and a single embedded Windows manifest (#3380).
3. **Accessible form-control parity: partially eroded, not reached.** The virtualized DataTable keeps maturing (separate header row height #3420, `visible_rows_changed` for one-row and empty tables #3397, right-click cell state #3413). A virtualized readonly Diff viewer shipped (#3378) plus a `tig` git-history example (#3388). Tooltips gained application-wide defaults and a placement API (#3376). Dialog entrances became configurable (#3405) and focus-recovery plus `open_dialog` contracts are now documented (#3386, #3406). Secure masked inputs and password strength visualizers are still absent; this remains the component Baluard needs most.

**New strategic signals**

- **GPUI Fast backend**: opt-in via the `gpui-fast` feature, paired with fixes that stop per-frame state writes in selectable text, inputs, `Root`, `TextViewState`, and resizable panels (#3407, #3418), so retained views stay on their scroll layer. This targets long-list scroll, the workload scale of a large vault.
- **Snapshot pinning**: exact pins `gpui-pre =0.3.9` (zed@93d7456) and `gpui-fast 0.1.7` (#3459) are reproducible but confirm the kit rides pre-release upstream snapshots that break freely. v0.7.2 was yanked and replaced by this release.
- **Diff + git-history components**: directly relevant to Baluard's git-backed storage if the prototype ever happens.

**Next checkpoint watches for**: AT-SPI/UIA entries in release notes (priority: the binding dependency), Wayland/IME fix entries, and `gpui-fast` promotion from optional feature to default backend. A password/masked input component is off the wait list: it is in-house work once the a11y foundation lands. A read-only prototype (`crates/baluard-desktop-gpui`, one custom component) can measure what AccessKit actually emits on Linux today and replace release-note watching with evidence.
