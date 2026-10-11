# Evaluation: Webview (Tauri v2) vs Native Rust UI (GPUI) for Baluard Desktop

Status: Evaluated (October 2026). Decision: Retain Tauri v2 + SolidJS for desktop production; monitor GPUI and AccessKit ecosystem evolution.

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

### 4. Ecosystem and Widget Completeness
FastFrame and GPUI-Kit provide basic buttons and inputs modeled after Tailwind syntax.
They lack production implementations for:
- Virtualized multi-column lists and tables
- Clipped tooltip and overlay positioning
- Focus-trapped modal dialogs
- Password strength visualizers and secure masked text inputs with toggle controls

## Decision and Action Plan

1. Retain Tauri v2 + SolidJS for desktop production. Accessibility and cross-platform UI stability are strict product requirements.
2. Re-evaluate GPUI when:
   - AccessKit reaches parity across Linux (AT-SPI) and Windows (UI Automation) inside GPUI or GPUI-CE.
   - Wayland IME handling and fractional scaling stabilize.
   - FastFrame or GPUI-Kit reaches feature parity for accessible form controls.
3. If prototyping is desired, implement a non-production experimental crate under `crates/baluard-desktop-gpui` targeting read-only vault inspection over the existing daemon socket.
