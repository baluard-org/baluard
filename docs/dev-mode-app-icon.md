# Dev-Mode App Icon in Third-Party App Switchers

**Status:** Known limitation (dev mode only)
**Affected:** Command-Tab Plus 2, AltTab, and similar third-party app switchers
**Not affected:** Native macOS Cmd+Tab, production builds

## Problem

When running the desktop app via `just desktop-dev` or `just desktop-debug`, third-party app switchers (Command-Tab Plus 2) display a generic terminal icon instead of the Baluard app icon.

## Root Cause

`cargo tauri dev` compiles and runs a bare executable at `target/debug/baluard-desktop` -- **not** inside a macOS `.app` bundle.

macOS resolves app icons from two different sources depending on who asks:

| Switcher | Icon source | Works in dev? |
|---|---|---|
| Native Cmd+Tab | `NSApplication.setApplicationIconImage` (runtime API) | Yes -- Tauri sets it programmatically at startup ([tauri-apps/tauri@307c2eb](https://github.com/tauri-apps/tauri/commit/307c2eb)) |
| Command-Tab Plus 2 | Reads `CFBundleIconFile` / `Assets.car` from the `.app` bundle on disk | No -- no `.app` bundle exists in dev mode |

Third-party switchers resolve the icon from the filesystem bundle via `NSRunningApplication.bundleURL`, then read `Info.plist` -> `CFBundleIconFile`. Without a bundle, they fall back to the generic executable icon.

## Production Builds

`just desktop-build` produces a proper `Baluard.app` bundle with the icon embedded. All switchers display it correctly.

## References

- Tauri dev-icon fix: <https://github.com/tauri-apps/tauri/commit/307c2eb>
- Tauri issue "Use Tauri app icon for development": <https://github.com/tauri-apps/tauri/issues/4637>
- AltTab similar fix: <https://github.com/lwouis/alt-tab-macos/commit/23fbc01>
