# Baluard Browser Extension

MV3 extension (Chrome + Firefox) that bridges the browser to the Baluard native host and daemon. Companion plan: `docs/adr/0092-browser-extension.md`.

## Origin matching policy

- The extension compares page **origin** (scheme + host + port) against stored entry URIs. A credential saved for `https://example.com` does not autofill on `http://example.com` or on a different port. This blocks downgrade attacks where a network attacker serves a plain-HTTP page to capture the password typed into it.
- Broad `<all_urls>`-style host permissions remain because inline detection and badge counts require reading the tab URL on every page. This is standard for the password-manager category; the extension sends page URLs only to the local native host and daemon, never to a remote endpoint.

## Privacy note: tab URLs and the daemon

- On every tab activation/update, the tab URL is sent to the Baluard native messaging host and daemon to compute matching-entry badge counts. This data stays on the device (local IPC). The daemon-side match uses the same URI matcher as the desktop app, so fill decisions are consistent across clients.
- The native host debug log (developers only, `BALUARD_DEBUG=1`) records action names, not URL payloads. It is disabled in normal operation and is scheduled to be removed from release builds entirely.

## Security model

- All privileged operations go through the daemon's bridge routes, gated by a scoped bridge token and an action allowlist (`BRIDGE_ALLOWED_ACTIONS` in `crates/baluard-core/src/bridge/token.rs`). The extension never holds vault keys.
- Inline content-script messages are accepted only from frames the extension itself injected. Full routing (popup, autofill reads/writes) is available only to extension-owned pages.

## Commands

- `just ext-build`: build both Chrome and Firefox extension bundles
- `just ext-build-chrome`: build Chrome extension bundle
- `just ext-build-firefox`: build Firefox extension bundle
- `just ext-package`: rebuild both dists, fail on drift from the committed dists, and zip each store dist into `./dist` as `baluard-extension-<version>-<store>.zip` for store upload
- `just ext-submit`: submit the newest packaged zips to Firefox AMO and the Chrome Web Store (credentials from the environment; see below)
- `just test-browser`: run extension test suite via Vitest
- `just install-nmh-manifest <browser> <ext_id>`: link native messaging host manifest for the specified browser

## Store submission

`just ext-submit` publishes. It never runs as part of `just release-repositories`: the store upload is the public boundary of the release flow, so it stays a deliberate step. The script refuses to submit when the newest packaged zip does not match the dist manifests; rerun `just ext-package` first.

Credentials live in the environment only (Bitwarden keeps them, never the repo):

- Firefox AMO: `AMO_JWT_KEY` and `AMO_JWT_SECRET` from the AMO API keys page. The submission uses the pinned `web-ext` release (`sign --channel listed --approval-timeout 0`); a system `web-ext` is used when installed, otherwise `npx` fetches the pinned one.
- Chrome Web Store: `CHROME_CLIENT_ID`, `CHROME_CLIENT_SECRET`, `CHROME_REFRESH_TOKEN`, `CHROME_EXTENSION_ID`, and `CHROME_PUBLISHER_ID`. The refresh token comes from the OAuth 2.0 Playground flow in the Chrome Web Store API guide (scope `https://www.googleapis.com/auth/chromewebstore`). The script exchanges it for an access token, uploads the zip, and publishes through the v2 API.

A store without credentials is skipped with a message; the run fails only when a configured store fails or no store is configured.

First submission notes:

- AMO requires listing metadata for the first `listed` submission (summary, categories, license). Point `AMO_METADATA` at a JSON file following the `web-ext sign --amo-metadata` format. The submission is built from `browser/firefox/dist`, not from the zip.
- The dist bundles are minified, so AMO review can request human-readable source. Point `AMO_UPLOAD_SOURCE` at a source archive when it does.
- Chrome requires 2-step verification on the publisher account, and each upload must carry a higher manifest version than the live item.
