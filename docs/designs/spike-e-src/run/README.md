# run/ — artifacts and logs from the empirical browser runs (2026-11-20)

- `logs/server-all-runs.log` — pass oracle: SPIKE-E CONNECTION-RECEIPT /
  HANDSHAKE-COMPLETE / FRAME-VERIFY-OK / TEST-OK / ACCEPT-ERROR lines for
  every browser run (wss + ws, Chrome + Firefox)
- `logs/chrome-wss-console.log` — Chromium 156 SW console (extension origin)
  for the wss run with --ignore-certificate-errors
- `logs/chrome-ws-console.log` — Chromium 156 SW console, ws://-only variant
- `logs/chrome-wss-nocert-console.log` — control: no cert flag → wss fails,
  ws fallback passes (server logged ACCEPT-ERROR fatal alert CertificateUnknown)
- `logs/firefox-bidi-install.log` — WebDriver BiDi webExtension.install result
  (Firefox 159 event page run; server logged ACCEPT-ERROR fatal alert
  BadCertificate for its wss attempt, then the ws fallback passed)
- `snow_spike.wasm.gz`, `glue.js.gz`, `background.js.gz` — gzip -9 size record
- `spike-e@baluard.invalid.xpi` — the exact artifact installed in Firefox
- `tether-server-cert.pem` — throwaway rcgen self-signed cert (CN=127.0.0.1);
  the server REGENERATES cert + key at every startup (the private key is
  deliberately not archived here)
- `bidi-install.mjs` — BiDi temporary-install driver (Node ≥ 22, global WebSocket)
- `wasm-smoke.mjs` — plain-Node FFI smoke test run in a node:22 container

Browser profile directories (chrome-profile, chrome-ws-profile,
chrome-nocert-profile, firefox-profile, firefox-bidi-profile) are not copied
into the repo — they are disposable and were never committed.
