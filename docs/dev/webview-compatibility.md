# WebView Compatibility and the CSS Floor

> The engine support floor for Baluard's desktop frontend on all three webviews, why Tailwind CSS v4 is safe on every supported engine, and the guardrails that keep the floor honest. Companion to [WebKitGTK Frontend Constraints](webkitgtk-frontend.md), which owns the Linux layout rules and the probe rig.

---

## The stack and its floor

- The desktop frontend is SolidJS + Tailwind CSS v4 (`tailwindcss` 4.3.x via `@tailwindcss/vite`). Lightning CSS emits the final stylesheet and adds vendor prefixes.
- Tailwind v4's browser floor is **Safari 16.4+, Chrome 111+, Firefox 128+** (all released 2023). The framework's core depends on `@property` and `color-mix()`. Both are hard gates: no transpilation can lower them.
- Since Tailwind 4.1 the framework emits fallbacks, so pre-floor engines still render colors, shadows, and opacity modifiers sensibly. "Not working" describes 4.0, not what we ship.
- Firefox never applies: no supported Tauri webview uses it. The Safari and Chrome numbers are the ones that bind.

## Engine support floors (decided 2026-11-11)

| Engine | Platform | Support floor | Tailwind margin |
|---|---|---|---|
| WebView2 Runtime | Windows | **153.0.4234.48**, the WebView2 Runtime build Microsoft offers on its [download page](https://developer.microsoft.com/en-us/microsoft-edge/webview2). Older runtimes exist in the wild on machines that never updated, but no installer for them is offered anymore, so those machines are out of support. | Chromium 153-era, well above the Chromium 111 gate. |
| WKWebView | macOS | The app requires macOS 15, so the engine is Safari 18.x. | Safari 16.4 floor leaves two majors of headroom. |
| WebKitGTK | Linux | **2.44** (Ubuntu 24.04 as shipped; Debian 12 ships 2.42.x; Ubuntu 26.04 and Fedora 43 ship 2.48+). The CSS features Tailwind needs landed in WebKitGTK 2.40, so the engine floor covers the CSS floor with room to spare. | Verified by the probe rig in [WebKitGTK Frontend Constraints](webkitgtk-frontend.md). |

Notes on the Windows floor:

- The number is a support policy, not a technical gate. The WebView2 loader starts with much older builds; below our floor the app may still run but is untested and unsupported.
- The Evergreen runtime self-updates silently, so in practice Windows machines sit far above the floor. The floor exists so a bug report from a stale runtime can be classified as unsupported instead of investigated as a defect.

## Why this is not the cause of engine quirks

- Tailwind emits plain standard CSS. Engine-specific rendering bugs are not CSS-framework artifacts.
- The macOS theme-toggle clicks swallowed by launch toasts and the Arch search-bar misalignment are DOM hit-testing and compositor quirks. Hand-written CSS hits them equally.
- The Linux layout rules in [WebKitGTK Frontend Constraints](webkitgtk-frontend.md) stay authoritative: no absolute positioning for critical layout, physical longhands over logical inset shorthands where absolute positioning remains.

## Guardrails

- **No legacy mode exists in Tailwind v4 and none is planned.** If support ever needs to go below the floors above, Tailwind v3.4 is the escape hatch. Under the current platform minimums this reversal is not expected.
- **Do not reach for opt-in bleeding-edge utilities** with uneven engine support: `field-sizing`, `@starting-style`, `text-balance`. Audit before introducing: `grep -rE "field-sizing|starting-style|text-balance" desktop/src` (confirmed unused 2026-11-11).
- **Upgrading Tailwind or adding plugins re-raises the emitted-CSS floor.** Re-run the WebKitGTK probe rig before shipping.
- **Vendor prefixing is handled by Lightning CSS.** Verified in the built stylesheet: the `-webkit-backdrop-filter` form ships alongside the standard one, so `backdrop-blur` degrades gracefully on engines that only know the prefix.
