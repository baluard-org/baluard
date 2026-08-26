# Baluard Browser Extension

MV3 extension (Chrome + Firefox) that bridges the browser to the Baluard native host and daemon. Companion plan: `docs/plan-browser-extension.md`.

## Origin matching policy

- The extension compares page **origin** (scheme + host + port) against stored entry URIs. A credential saved for `https://example.com` does not autofill on `http://example.com` or on a different port. This blocks downgrade attacks where a network attacker serves a plain-HTTP page to capture the password typed into it.
- Broad `<all_urls>`-style host permissions remain because inline detection and badge counts require reading the tab URL on every page. This is standard for the password-manager category; the extension sends page URLs only to the local native host and daemon, never to a remote endpoint.

## Privacy note: tab URLs and the daemon

- On every tab activation/update, the tab URL is sent to the Baluard native messaging host and daemon to compute matching-entry badge counts. This data stays on the device (local IPC). The daemon-side match uses the same URI matcher as the desktop app, so fill decisions are consistent across clients.
- The native host debug log (developers only, `BALUARD_DEBUG=1`) records action names, not URL payloads. It is disabled in normal operation and is scheduled to be removed from release builds entirely.

## Security model

- All privileged operations go through the daemon's bridge routes, gated by a scoped bridge token and an action allowlist (`BRIDGE_ALLOWED_ACTIONS` in `crates/baluard-core/src/bridge/token.rs`). The extension never holds vault keys.
- Inline content-script messages are accepted only from frames the extension itself injected. Full routing (popup, autofill reads/writes) is available only to extension-owned pages.
