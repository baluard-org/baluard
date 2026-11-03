# ADR 0092. Browser Extension

> Status: Accepted (2026-09-30). Phases 0 and 1 are implemented: native messaging host, bridge module, paired-companion pairing flow, allowlist, and the Chromium and Firefox MV3 clients. Since the original plan the extension also gained the in-field dropdown (amendment of 2026-07-19) and merged multi-vault matching with unlock requests (ADR 0098). Passkeys in the browser, capture of new or changed logins, the generator view, the sync badge, keyboard-shortcut fill, browser code-signature verification, and the Flatpak and Snap installer are not shipped and remain open (see "Open items").

This record is the full design. The short record is ADR 0024; this ADR carries the constraints that record condenses. Where the original plan text and the code disagree, the code wins and the difference is stated below.

## Context

Baluard has no application server. The Git remote is the vault's synchronization endpoint, so the Bitwarden and 1Password model (extension talks to a company API) does not apply. Browser access must use the unlocked desktop daemon. A 0600 Unix socket cannot be opened by a WebExtension, because MV3 has no raw-socket API. The reference architecture is KeePassXC-Browser: extension, native messaging host over stdio, local socket, desktop application, with the desktop holding the unlock and the extension riding it.

The extension, service worker, content script, page, and native messaging host are outside the desktop process trust boundary. They must not receive master passwords, vault session tokens, keys, KDF output, TOTP seeds, or passkey private keys.

The goal is a bridge client that lets the project be used daily against the open daemon: two extensions (Chromium family and Firefox) from one codebase that autofill credentials against the running desktop instance.

### Non-goals for v1

- No communication with any remote service from the extension.
- No standalone vault in the extension. The daemon stays the source of truth, as for the CLI and desktop.
- No passkey or WebAuthn ceremony in the browser. That is the untrusted-ceremony work tracked as SEC-1 in ADR 0095.
- No mobile client and no Safari (MV3 Safari is optional and immature).
- No browser code-signature verification (the 1Password-style hardening). This is a documented gap.
- No change to the crypto and security invariants: AES-256-GCM, Argon2id, the 0600 socket, token gating, zeroize on drop, peer credential verification.

### Reference research

| Source | Taken | Not taken |
|--------|-------|-----------|
| Bitwarden extension | MV3 structure: service worker with message passing, offscreen document for clipboard, `action` API, `chrome.storage.session` for state, `scripting` permission. | Its HTTPS transport and its in-extension crypto and vault (all crypto stays in the daemon). Its autofill-on-page-load default, which is an exfiltration risk. |
| KeePassXC-Browser and keepassxc-proxy-rust | The bridge topology: extension, native messaging host (stdio), local socket, app. The host as a thin Rust proxy. Per-OS host manifest locations. The model where the desktop holds the unlock. | KeePassXC's wire-crypto handshake, because the socket already has token gating and UID verification. |
| 1Password | North star only: verify the calling browser's code signature before trusting the bridge. | Not realistic in v1; recorded as a hardening gap. |
| MDN and Chrome native messaging documents | Exact stdio framing, manifest keys, per-OS manifest paths. | None. |

### Rejected transport: loopback HTTP

Loopback HTTP on the daemon was rejected. It widens the attack surface to any local process and the network stack, needs Origin and CORS pinning plus a second authentication path, and matches no major password manager. Native messaging keeps the existing UID-verified 0600 socket as the single trust boundary. `nativeMessaging` (`runtime.connectNative` and `sendNativeMessage`) is the only cross-browser escape hatch from a WebExtension to a local process.

## Decision

Build one shared Manifest V3 extension for Chromium-family browsers and Firefox. Use a service worker, popup, fill-executor content script, and a Rust `baluard-nmh` native messaging host. The NMH translates browser stdio JSON to the existing varint-prefixed protobuf daemon protocol and performs no vault or cryptographic operations. Trust boundary: the 0600 socket, the per-vault session token, the bridge token, and the server-enforced allowlist. Everything on the browser side of the NMH (popup, service worker, content script, page) is untrusted.

```
Browser (popup, service worker, content script)   untrusted, holds no secrets
        | nativeMessaging, stdio JSON, 32-bit native-endian length prefix
        v
baluard-nmh   stateless Rust proxy, re-mints a bridge token per spawn, enforces the allowlist
        | Unix domain socket 0600, varint-prefixed protobuf GatewayRequest and GatewayResponse
        v
baluard-daemon   TokenKind::Bridge check, allowlist, SO_PEERCRED
        v
baluard-core   crypto, vault, sync, bridge module
```

### Auth model: paired companion

The extension is not an unlock client. It is paired once with an already-unlocked daemon and then rides that unlock state, as KeePassXC-Browser does. The daemon's existing auto-lock walker covers the extension for free: there is no second Argon2id and no master password in browser memory. When the desktop locks, the extension is inert.

The vault session token is never held by the extension or by browser storage. The extension to NMH link is authenticated only by `allowed_origins` or `allowed_extensions` pinning. The NMH to daemon link carries a scoped bridge token. Extension JavaScript touches no secrets.

### NMH lifecycle: stateless with a durable pairing file

Standard native messaging spawns a fresh NMH per `connectNative` call and kills it on disconnect (SIGTERM or SIGKILL on Unix, job kill on Windows). A fresh NMH therefore has no token. The resolution is a durable pairing file with an ephemeral token:

- On pair completion the daemon writes `<data_dir>/bridge/pairings.json` (0600) containing a pairing secret (256-bit random, hex, zeroized on drop, compared in constant time) and a pairing ID. It contains no vault session token and no key material.
- On every spawn the NMH reads only its own entry, presents the secret to the daemon through `bridge.reauth`, and the daemon returns an ephemeral bridge token. The NMH stamps that token on every forwarded request.
- The token dies with the NMH process. SIGKILL gives no zeroize window, so the claim is "dies with the process", and the operating system reclaims the memory. The token never touches disk or browser storage.
- If the NMH has no pairing entry it reports `not-paired` and the extension starts the pairing flow.

"Pair" and "reauth" are distinct operations with distinct routes. Pair is the one-time human ceremony. Reauth is the silent, secret-gated machine re-mint on every spawn and after any daemon restart.

### Pairing ceremony: desktop-initiated, approve do not type

The first design used a typed 6-digit code with a 5-strike vault nuke. It was replaced. A code adds a read-then-type step under a timer and a lockout path, and the nuke was a denial-of-service hazard for a non-technical user, borrowed from the PIN policy for a lower-stakes ceremony where it did not fit. Approve-only has no code and therefore nothing to brute-force.

1. The user clicks "Add browser extension" in the desktop. `bridge.pair_start` is desktop-token-gated and sets a one-shot pending-approval flag with a short TTL (120 seconds, the daemon's pending TTL). No code is minted.
2. The extension calls `bridge.pair_complete`, which is not token-gated. The daemon holds the request pending. The NMH runs each request on its own thread so a blocked `pair_complete` does not freeze badge updates and other popup actions for the ceremony TTL.
3. The desktop shows "A Baluard extension wants to connect" with Approve and Deny, surfacing the browser identity so the user can sanity-check it. `bridge.pair_approve` and `bridge.pending` are the desktop-side routes.
4. On Approve the daemon consumes the one-shot flag, writes the pairing file entry, mints the first bridge token, and returns the pairing secret to the NMH.

Load-bearing requirement: the Approve click sets a one-time, desktop-session-token-gated flag that `bridge.pair_complete` consumes. The daemon must never auto-approve because the extension asked. Consent originates in the desktop, which is the trust anchor.

Security equivalence argument. The only threat a typed code defended against and approve-only does not is a same-UID attacker who can drive both the browser and the desktop UI. An attacker who can synthesize clicks in the desktop window already holds the desktop session token and can call `vault.export` directly, so pairing is not the boundary protecting the user there. Against the actual model (browser compromise, not desktop compromise) approve-only is equivalent. A surprise Approve is no weaker than a surprise code, since both depend on the user looking at the real desktop application. Approve is consent, not re-authentication, so no TOTP or step-up is required: pairing happens while the vault is already unlocked. A step-up belongs on a future confirm-destructive-bridge-operation surface, not on pairing.

Residual abuse protection: `bridge.pair_complete` goes through the per-vault `RateLimiter` as flood defense, with no vault nuke. The worst case is that the pending approval is dropped and the user clicks again.

### Capability model: scoped bridge token

The NMH must not hold the per-vault session token, which gates everything including `device.revoke` (full rekey). Pair completion mints a distinct bridge token.

- Registry. A host-level `HashMap<pairing_id, BridgeTokenEntry>` lives on `VaultHost`, not per vault, because bridge tokens are vault-agnostic. It is required for concurrent NMH instances (Chrome plus Firefox, or two profiles); a single optional token would have them clobber each other. NMH processes for the same pairing reuse that pairing's single live token. `bridge.reauth` is idempotent: it returns the live token if one exists and mints only when absent.
- Wire and handler. The bridge token rides the existing `session_token` field (no protobuf change), and the daemon disambiguates by lookup. Token verification branches on token kind. A live registry match marks the request `TokenKind::Bridge { pairing_id }`, enforces the allowlist instead of the normal token-required action set, and then snapshots the active vault. Otherwise the request falls to the per-vault path (`TokenKind::Vault`). A bridge-shaped 64-hex token that is not in the registry (daemon restarted, pairing revoked, token expired) on a `bridge.*` action returns the sentinel `stale bridge token` (`STALE_TOKEN_ERROR`, defined in core so emitter and matcher cannot drift). The NMH matches it, drops its cached token, runs `bridge.reauth` again from the still-valid pairing file, and retries once.
- Lock binding. Every bridge request re-checks that the vault is unlocked. The daemon does not proactively wipe tokens on lock. A locked vault yields the `locked` failure.
- TTL parity. Bridge tokens expire on the same cadence as the vault token (`BRIDGE_TOKEN_TTL_SECONDS`, 4 hours, mirroring `SESSION_TOKEN_TTL_SECONDS`) and are re-minted through `bridge.reauth`. This prevents the bridge token from becoming the least-scrutinized long-lived credential.
- Per-pairing read cap. Without a cap the allowlist redesign is theater: a compromised browser could loop `bridge.match` over a list of top domains and call `vault.get` for every hit at local-socket latency, which is a chunked `vault.list_full`. The daemon charges secret reads per `pairing_id`. Exceeding the cap auto-revokes the pairing. The cap bounds a browser compromise to a handful of credentials instead of the whole vault. Current code: 30 secret reads per 60 seconds (`READ_RATE_LIMIT_PER_MINUTE`, `READ_RATE_WINDOW_SECONDS`). Only `vault.get` is charged. `bridge.match` is deliberately not capped, because it returns metadata only and the toolbar badge calls it on every tab activation and update, so capping it would revoke the pairing under normal browsing. The original plan capped both at 10 to 20 per minute; the code supersedes it.
- Revocation. `bridge.revoke` removes the entry from the host registry and from the pairing file, so a live NMH's next request is denied immediately and does not depend on file deletion.

Code placement. The pairing logic, the pairing file format, token mint and verify, and the allowlist live in `crates/baluard-core/src/bridge/` (`pairing.rs`, `token.rs`, `mod.rs`), matching the established core module pattern. Daemon `bridge.*` routes are thin wrappers. The NMH reads its own pairing entry through core types, so there is no NMH to daemon dependency edge, and the file format is a first-class, testable artifact.

### Action allowlist

The allowlist is enforced server-side in the daemon after token verification, and again in the NMH as defense in depth. It is minimal and releases at most one credential at a time. `vault.list_full` is deliberately absent: it returns the entire decrypted vault in one call, a de facto export and the real blast radius.

| Action | Purpose and constraint |
|--------|------------------------|
| `bridge.match` | URL to matching `CipherMeta` (id, name, username, type). Metadata only, no passwords. Server-side URI match. |
| `vault.get` | One selected credential, on fill or copy only. One credential in browser memory at a time. |
| `vault.add` | Capture a new login. Admits the LoginData fields needed for capture, including `uris`. |
| `vault.update` | Field-gated, see below. |
| `cipher.totp_code` | Derived numeric code only. The seed does not cross on this route. |
| `generator.history_add`, `generator.history_clear` | Record or clear generated passwords. Listing history is excluded. |
| `bridge.config` | Returns only `default_uri_match`. |
| `sync.autosync_status` | Read-only sync state. |
| `bridge.request_unlock` | Added by ADR 0098. Asks the desktop to unlock a merge-eligible vault. It works before unlock by design; the desktop polls, shows the ask, and the user's approval is the unlock. No route accepts a master password from the extension. A newer request supersedes an older one. |

Pairing-ceremony routes sit outside the vault allowlist. `bridge.pair_complete` is a bootstrap action: the NMH forwards it with no bridge token because none exists yet, through a separate bootstrap list (`BOOTSTRAP_ACTIONS`) that is the NMH's defense-in-depth permit for the ceremony. `bridge.reauth` is secret-gated. `bridge.pair_start`, `bridge.pair_approve`, `bridge.pending`, `bridge.list`, `bridge.revoke`, `bridge.unlock_request` and `bridge.unlock_request_take` are the desktop-side management and polling routes, gated with the desktop's per-vault token.

Field gate on writes. Server-side, for `TokenKind::Bridge`:

- `vault.update` is rejected if it would change `fido2_credentials` (passkey tampering or data loss, which would defeat the passkey exclusion) or `uris` (autofill-redirect phishing: rewrite a bank login's URI to an attacker domain so the next fill delivers the credentials there). Password, username, notes, and TOTP updates are allowed, since "I changed my password on the site" capture is essential to usability. New URIs arrive only through `vault.add` (new entries) or the desktop.
- The update path replaces the whole `kind`, so an omitted `uris` or `fido2_credentials` would silently delete them. The daemon therefore fetches the stored cipher (a read exempt from the read cap, being an integrity check) and requires that a resent protected list is byte-equal to the stored list. Omission, shrinking, or any content change is refused. A payload whose declared type does not match the stored cipher type is also refused, so a payload claiming a login cannot overwrite a card.
- Writable keys are an allowlist, not a denylist, so a future cipher type's fields (for example a signing key private key) cannot cross by default.
- `vault.add` and `vault.update` also require the vault's write scope (`bridge_write_allowed`). A Viewer or a half-finished join on a shared vault cannot mint entries their own device could not push.

Excluded even with a valid bridge token: `settings.get` and `settings.set` (they leak the vault slug, enrollment policy and profile data), `generator.history_list` (returns prior generated secrets), `favicon.get` (not an SSRF, since it uses a fixed endpoint with a 16 KB cap and magic-byte check, but the extension fetches icons itself through its own host permissions), `vault.delete`, `vault.export`, `vault.import`, `vault.change_password`, `vault.list_full`, `device.revoke`, `vault.devices`, `vault.device_activity`, all `sync.*` mutations, all `provider.*`, `vault.attach_*`, `ssh.generate_key`, `passkey.*`, `vault.clone_*`, `folder.*`, `tag.*`, `vault.archive`, `vault.unarchive`, `vault.trash.*`, and `cipher.clone`.

Expanding the allowlist is a deliberate change with a same-change call-site update. The friction is intentional: it forces a conscious security decision per route.

Origin binding on reads. A `vault.get` or `cipher.totp_code` that carries a page URL (the inline-fill flow always does) is checked server-side with the same hostname matcher `bridge.match` uses, so a credential stored for one site cannot be fetched for a lookalike or downgraded page. Requests without a URL (popup and other extension-owned UI) are allowed, since the user picked the entry, and URI-less entries stay fillable from the popup and are logged.

### Management surface and revocable-grant model

Pairings are revocable grants, not devices. A paired browser has no device private key, is absent from the device private-key file, does not participate in the epoch hierarchy, and revoking it does not rotate the root key. The desktop provides a "Paired browser extensions" settings tab: add (starts the approve flow), list (name, browser, paired date), and revoke per row.

The daemon is the sole writer of `pairings.json`, using atomic temporary-file replacement. The desktop mutates it only through daemon routes. The NMH reads its own entry read-only. This avoids multi-process write races (pairing browser 2 while revoking browser 1 while N NMHs read).

Daemon log lines are tagged with the token kind (`Vault` or `Bridge { pairing_id }`), so bridge reads and writes can be told apart from desktop activity after an incident.

### Fill policy

Filling requires a user gesture. There is no autofill on page load and no armed-tab autofill. Autofill on load is a known exfiltration vector (a hostile page with a disguised form harvests credentials on visit) and the posture matches the industry default (1Password default, Bitwarden "auto-fill on page load" off).

Popup flow: the popup reads the current tab URL through `activeTab`, calls `bridge.match`, shows matching metadata, and on a click fetches one credential with `vault.get` and messages the content script in that tab. The content script is a pure fill executor:

- It is injected by `chrome.scripting.executeScript` into the top frame only (`frameIds: [0]`, never `all_frames`). A cross-origin login iframe, the classic credential-theft vector, is never filled. The trade-off is that legitimate embedded third-party logins do not autofill in v1; the user can copy from the popup. This designs out the page-influenced-target exfiltration class instead of mitigating it.
- It runs field detection once per user-initiated fill, with no continuous form scan.
- It rechecks the origin immediately before writing to the DOM and fails closed on mismatch. This closes the race where the popup matched tab A, the user clicked, and the tab navigated during the IPC round trip. Origin comparison is scheme plus host plus port, so a credential saved for `https://example.com` does not fill on `http://example.com` or another port (downgrade defense).
- There is no auto-submit.

Every fill originates from a trusted extension surface (the popup), which the page cannot reach.

Amendment (2026-07-19): in-field dropdown, opt-out setting. The original rule of no inline field icons is amended for usability parity with 1Password and Bitwarden. `inline.js` is a persistent top-frame content script registered with `chrome.scripting.registerContentScripts` (all frames false, `document_idle`) only while the `inlineAutofill` setting is on. The setting defaults to on and is toggled in the popup's settings view. Every load-bearing property is unchanged:

- Still no autofill on load. A fill needs two user gestures on Baluard's own UI (icon click, then entry click). The UI lives in a closed Shadow DOM that the page cannot traverse, restyle, or synthetically click.
- Matching stays server-side and origin-truthful. The service worker's `inline.matches` route matches against `sender.tab.url` (privileged tab metadata), never a URL the content script claims. The URL helper fails closed on non-HTTP(S) or missing URLs.
- Credential delivery is push-only. `inline.fill` fetches `vault.get` and pushes `baluard-inline-fill` to the requesting tab with `expectedOrigin` from `sender.tab.url`. The credential is never returned as a message response into the page context.
- The fill-time origin re-check remains.
- The icon appears on focus of username and password fields only, using username-field heuristics (autocomplete hints, word-boundary name, id, placeholder and aria-label hints, text-before-password structure). There is no continuous form scanning or page-load probing.
- Only extension-owned pages (popup, offscreen) get full message routing. A content script may send only the two inline routes (`inline.matches`, `inline.fill`); other actions from a content script are dropped. Inline results are projected to `{id, name, username, vault_slug}`, so vault names and the vault list stay in extension-owned UI.

### Multi-vault behavior

The bridge token is vault-agnostic, scoped to `TokenKind::Bridge { pairing_id }` plus the allowlist and not to a slug. The NMH forwards requests with no slug, and the daemon routes them to the active vault using its pointer-flip semantics (ADR 0022). The extension has no vault selector: the desktop is the switcher, and the extension inherits. The popup re-queries `bridge.match` on every open (cheap, single IPC, metadata only) and shows the active vault name in the header, so the user knows where a write will land. This addresses the silent cross-vault write hazard. A locked active vault fails closed with `locked`, and the extension asks the user to open the Baluard app.

Rejected: binding the extension to one vault at pairing (a re-pair tax on every switch), and an in-extension multi-vault selector (duplicates the desktop `VaultSwitcher` and invites sync drift).

Amendment by ADR 0098 (merged search). `bridge.match` fans out over every merge-eligible unlocked vault and succeeds when at least one is unlocked, so a sleeping personal vault does not blank autofill while a family vault is open. Each match carries `vault_slug` and `vault_name`, and the response lists eligible vaults and their lock state for the locked-vault chips. `vault.get`, `cipher.totp_code`, `vault.add` and `vault.update` may name a sibling vault through `vault_slug`: the slug must be merge-eligible and the target unlocked, otherwise the request is refused as for an unknown vault. A slug-scoped read of a non-active vault must carry the page URL so the origin binding applies. All other actions still require the active vault to be unlocked. The single-active-vault description above remains the default for single-vault users.

### Native messaging host

`crates/baluard-nmh/` translates stdio JSON to varint-prefixed protobuf and nothing else. It is stateless and holds no crypto or vault logic.

Daemon framing is the existing framing reused from the CLI client: `GatewayRequest` and `GatewayResponse` from `proto/auth.proto`, request as varint length plus encoded message, response read as varint length then decode, and the socket path from `baluard_core::paths`. The payload is JSON text, as in the Single-String Protobuf Gateway (ADR 0007).

Browser framing is the native messaging standard: a 32-bit native-endian length prefix followed by UTF-8 JSON, in both directions. Host to extension is capped at 1 MiB (the browser hard limit) and an oversize response is turned into a `proto` error. Extension to host is capped at 64 KiB (`MAX_REQUEST_BYTES`) even though browsers allow 64 MB. Diagnostics go to stderr only, since stdout must stay protocol-clean.

Wire JSON:

```json
{ "id": "<uuid>", "action": "bridge.match", "payload": "{\"url\":\"https://example.com\"}" }
{ "id": "<uuid>", "ok": true,  "payload": "<json string>" }
{ "id": "<uuid>", "ok": false, "error": "<message>", "code": "locked|no-daemon|denied|proto|not-paired" }
```

`payload` mirrors `GatewayRequest.payload`. The `id` lets the asynchronous service worker match responses on a long-lived `connectNative` port. The NMH does not interpret payload contents; it only checks that the payload is valid JSON.

Error classification (machine-readable `code`):

| Condition | Code | User-facing intent |
|-----------|------|--------------------|
| Socket connect refused or I/O failure reaching the daemon | `no-daemon` | Open the Baluard app |
| Pairing entry missing | `not-paired` | Run the pairing flow |
| Daemon failure mentioning lock | `locked` | Unlock the Baluard app |
| Other daemon refusal or non-allowlisted action | `denied` | Not permitted |
| Malformed stdio, invalid JSON payload, oversize frame | `proto` | Protocol error |
| Protocol version mismatch (extension side, see below) | `version-skew` | Update the Baluard desktop app |

Version handshake. The `ping` action is answered by the NMH itself, without the daemon, and returns `{ proto_version, nmh_version }` (the protocol version is `baluard_core::BALUARD_VERSION`). The extension fails closed with a `version-skew` message on mismatch. A password manager must never silently run a partially understood protocol. The original plan also listed `daemon_version` in the payload; the NMH ping does not carry it, so the daemon version is not currently compared.

The NMH is a confused deputy that parses untrusted JSON while holding an authenticated socket. Its defenses: the same allowlist as the daemon (so a daemon routing bug is not reachable through an action the NMH should never forward), the 64 KiB request cap, rejection of non-JSON payloads before forwarding (fail closed), and no logging of payloads, because `vault.get` responses carry plaintext. The debug log (`BALUARD_DEBUG=1`) records action names only.

### Host manifest and install locations

Host name `xyz.actitud.baluard`. Chromium manifest: `{ "name", "description": "Baluard bridge", "path": "<abs path to baluard-nmh>", "type": "stdio", "allowed_origins": ["chrome-extension://<EXT_ID>/"] }`. Firefox uses `allowed_extensions: ["baluard@actitud.xyz"]`, matching the gecko add-on ID in the Firefox manifest (`strict_min_version` 115.0). Pinning to the extension ID means a random extension cannot talk to the NMH. Store IDs are fixed on upload and the host manifest must use the final published ID; the development flow uses a key-pinned fixed development ID.

User-level locations:

| Platform | Browser | Location |
|----------|---------|----------|
| Linux | Chromium | `~/.config/chromium/NativeMessagingHosts/` |
| Linux | Chrome | `~/.config/google-chrome/NativeMessagingHosts/` |
| Linux | Firefox | `~/.mozilla/native-messaging-hosts/` |
| macOS | Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| macOS | Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/` |
| macOS | Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` |
| Windows | Chrome | Registry key under `HKCU\Software\Google\Chrome\NativeMessagingHosts\...`, default value is the path to the host manifest |
| Windows | Firefox | Registry key under `HKCU\Software\Mozilla\NativeMessagingHosts\...`, default value is the path to the host manifest |

The development recipe `just install-nmh-manifest <browser> <ext_id>` writes the manifest for Linux and macOS and also knows Brave and Edge (and Brave Origin on macOS). It does not handle Windows registry keys or sandboxed browsers; those remain design only (see "Open items").

The Linux deb/rpm packages register the native host system-wide. `scripts/build-nmh-manifests.sh` (run automatically by `just desktop-build`) generates the host manifests under `desktop/src-tauri/nmh-manifests/`, and the Tauri `deb.files`/`rpm.files` config installs them: Firefox at `/usr/lib/mozilla/native-messaging-hosts/` (deb) and `/usr/lib64/mozilla/native-messaging-hosts/` (64-bit rpm), Chrome at `/etc/opt/chrome/native-messaging-hosts/`, Chromium at `/etc/chromium/native-messaging-hosts/`, and Edge at `/etc/opt/edge/native-messaging-hosts/`. Each manifest points at the packaged `/usr/bin/baluard-nmh`. The Firefox manifest authorizes the AMO id (`baluard@actitud.xyz`); the chrome-family manifests authorize the Chrome Web Store id via `BALUARD_CHROME_EXTENSION_ID` at build time. That id does not exist until the first store upload, so without the env var the chrome manifests ship a placeholder origin (loud build warning) and the store bridge stays dev-only. Windows (registry keys) and macOS (user-level `~/Library`) registration remain manual.

### Extension component

One Vite build produces two bundles (`browser/chrome`, `browser/firefox`), distinguished only by manifest and extension ID, from the shared codebase in `browser/shared/`. JavaScript is browser-agnostic through the `chrome` and `browser` namespace shim. Firefox has no `chrome.offscreen`, so the clipboard copy runs in the popup there.

MV3 realities that shape the design:

- The service worker is not persistent. It can be terminated after roughly 30 seconds idle. It reconnects the NMH when needed. Session storage holds only preferences and transient request IDs and never secrets, in line with the rule that extension JavaScript holds no secrets.
- A service worker has no DOM, so clipboard copy uses an offscreen document. The offscreen document owns the auto-clear timer (configurable, validated in settings, default about 20 seconds). Direct fill is preferred over copy because fill never touches the clipboard.
- The content script is injected on demand (Fill policy), except the opt-out inline script.
- The popup contains no master-password or unlock flow.

Permissions: `nativeMessaging`, `storage`, `scripting`, `activeTab`, `offscreen`, and `clipboardWrite`, with `http://*/*` and `https://*/*` host permissions. There is no `<all_urls>` and no `webRequestBlocking`. The original plan listed `alarms` for periodic work (TOTP refresh, lock polling); no current feature needs it, so the shipped manifest omits it and `clipboardWrite` is present instead. Broad host permissions remain because inline detection and badge counts must read the tab URL on every page. This is standard for the category. Page URLs go only to the local native host and daemon.

The extension shows an action-badge count of matches for the current tab (`chrome.action.setBadgeText`): zero-DOM ambient discoverability with no attack surface. Every NMH error code maps to a friendly, actionable, localized message (`no-daemon` reads as "Open the Baluard app to fill passwords", never a socket error name) with no hard technical terms. This was a Phase 1 gate and not later polish.

### Sandboxed browsers on Linux: Flatpak and Snap

A sandboxed browser cannot reach the host NMH binary or the 0600 socket: manifest discovery happens inside the sandbox's filesystem view and the socket path is outside it (KeePassXC issue 12327). The design mimics KeePassXC-Browser, with Flatpak primary and Snap secondary.

Flatpak (primary and primary test target):

1. The installer writes the host manifest into the browser's data directory inside its sandbox view, for example `~/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/xyz.actitud.baluard.json` for Firefox, or `~/.var/app/<chromium-app-id>/config/<browser>/NativeMessagingHosts/` for Chromium-family browsers.
2. The manifest `path` points to a `flatpak-spawn` wrapper, not the NMH, because the sandboxed browser cannot execute a host binary by path: `exec flatpak-spawn --host --watch-bus /usr/local/bin/baluard-nmh "$@"`. `--host` runs the NMH outside the sandbox where it can reach the socket; `--watch-bus` ties its lifetime to the caller.
3. The browser needs permission to talk to the portal: `flatpak override --user --talk-name=org.freedesktop.Flatpak org.mozilla.firefox`.
4. No socket proxying is needed. The NMH runs on the host and connects to the real `$XDG_RUNTIME_DIR/baluard/baluard.sock`.

The desktop installer was to detect installed Flatpak browsers and perform steps 1 to 3 automatically. A systemd path unit that re-creates the manifest when the browser overwrites it on update (KeePassXC's "mangler") is the robustness fallback, deferred.

Snap (secondary, best effort): Ubuntu's Firefox snap uses the `webextensions` permission table, set with `flatpak permission-set webextensions xyz.actitud.baluard snap.firefox yes` and verified with `flatpak permissions webextensions`. The NMH binary must sit on a path the snap can execute, and the snap's host manifest lives in the snap's confined view.

Non-goals for sandbox support: custom or fork browsers' sandboxes (for example Librewolf Flatpak) beyond the documented paths (users can copy the manifest by hand), and shipping a Firejail profile (document the path, as KeePassXC does).

### Security model and threat surface

Preserved and load-bearing: all cryptography stays in `baluard-core`, and the extension and NMH never see keys, KDF output, TOTP seeds, passkey private keys, or the master password. The 0600 socket and SO_PEERCRED UID verification are unchanged; the NMH runs as the user because the browser spawns it under the user's account. The per-vault session token and its constant-time comparison are unchanged, and the bridge token is a separate, scoped token.

Threats introduced by the extension and their treatment:

1. Page malware reads autofilled fields. Inherent to every browser password manager. Mitigations: fill only on explicit user gesture, never on load, top-frame-only fill, and an inline UI the page cannot touch (closed Shadow DOM). Residual: field values are readable after fill, the same posture as Bitwarden and 1Password.
2. Malware controlling the browser drives the unlocked extension. 1Password mitigates by verifying the browser's code signature; Baluard cannot in v1, a documented hardening gap. What exists instead: pairing originates in the trusted desktop so a drive-by cannot pair; extension ID pinning; and the scoped token plus allowlist cap the damage. A compromised browser cannot rekey, delete, export, list the full vault, or change the master password through the bridge. Residual: a compromised browser that can synthesize gestures in the popup can autofill into attacker pages. This is what makes deferred signature verification survivable rather than reckless.
3. Pairing file compromise (`pairings.json`, 0600). This was originally under-rated and is classified honestly as a revocable read-capable grant at rest. A same-UID reader gains the pairing secret, can mint bridge tokens through `bridge.reauth`, and while the vault is unlocked can enumerate credentials one at a time with `vault.get`. That is more than the baseline, where the vault session token is never at rest. It is not a full-vault-in-one-call capability (no `list_full`), not destructive (allowlist), not persistent across lock (every request re-checks unlock state), and it is gated behind the same UID and 0600 socket the attacker already had. It does not contradict "keys never at rest unencrypted": the file holds no key material, only a revocable capability secret, and revocation is instant. On macOS the secret may later be stored in a `SecAccessControl` keychain entry scoped to the NMH code signature (Touch ID or passcode on read). Linux and Windows keyrings are same-UID readable through D-Bus or Credential Manager, so parity there is weaker. It is a platform-conditional improvement and must not be presented as universal. Deferred to a post-v1 hardening pass.
4. Bridge token in NMH memory only (see lifecycle).
5. NMH as confused deputy (see the NMH section).
6. Clipboard exfiltration. A copy leaks to any application, clipboard managers, and possibly cloud clipboard sync. The extension clears the clipboard after about 20 seconds, matching the desktop policy.

Several review findings were examined and overturned or downgraded; the record is kept for honesty. `favicon.get` is not an SSRF (fixed endpoint, size cap, magic-byte check, default off), though it stays off the bridge as an unneeded side effect. The `generator.history_list` leak is real but subordinate to the `vault.list_full` baseline; both are excluded.

### Dependency on the desktop

The extension needs the desktop running and unlocked. NMH auto-starting the daemon is deferred, and the Add browser extension button assumes the extension is already installed.

## Consequences

The desktop remains the only unlock authority, and the browser receives only the selected credential. Native messaging preserves the existing socket boundary without adding loopback HTTP or a second network-facing daemon surface.

The durable pairing secret is a meaningful, revocable capability and must be protected as such. A compromised browser can read or alter only the bridge's explicitly allowed data while a vault is unlocked, and read volume is bounded by the per-pairing cap with auto-revocation. Revocation is immediate for live tokens and does not require device rekeying.

Top-frame-only filling excludes legitimate embedded login forms. Browser signature verification remains a hardening gap, and the install story for sandboxed browsers and Windows is not yet automated. Allowlist growth requires a deliberate change for each route.

### Open items

- Capture on form submit (a "Save to <vault name>?" prompt with the vault name in the affirmative text, to prevent writing into the wrong vault after a switch), the popup generator, the sync badge, the keyboard-shortcut fill, and cross-device dogfooding are plan items not present in the extension source today. The bridge allowlist already admits the routes they need (`vault.add`, `vault.update`, `generator.history_*`, `sync.autosync_status`, `bridge.config`).
- Passkeys in the browser (ADR 0095, SEC-1) and inline badges for passkeys.
- NMH packaging: ship `baluard-nmh` inside the desktop installer, which registers host manifests on first run (the preferred direction), or as a standalone artifact.
- Dev versus store extension IDs: pinning needs the final published ID.
- Windows registry installation and the Flatpak and Snap installer steps are documented but not implemented in `just` recipes.
- Flatpak systemd path-unit "mangler" if browser updates overwrite the manifest.
- Extension discoverability: how a user learns the extension exists and where to get it (store listing, first-run desktop banner). Worth stating at release time.
- Last-seen tracking on paired extensions, NMH auto-starting the daemon, browser code-signature verification, macOS keychain storage of the pairing secret, Safari.

### Source versus plan differences

Source was preferred over the original plan text. Differences found: the read cap is 30 per minute on `vault.get` only (plan: 10 to 20 per minute on `bridge.match` and `vault.get`); the allowlist also contains `bridge.request_unlock` (ADR 0098); `vault.add` admits more LoginData fields than `vault.update` (including `uris`); the manifest has `clipboardWrite` and no `alarms`; the NMH ping carries `proto_version` and `nmh_version` but not `daemon_version`; the pairing TTL is 120 seconds.

## References

- ADR 0024, the condensed record of this design: `docs/adr/0024-browser-extension-paired-companion-bridge.md`.
- ADR 0098, merged multi-vault search and `bridge.request_unlock`: `docs/adr/0098-merged-search.md`.
- ADR 0095, passkey support and the browser ceremony trust model: `docs/adr/0095-passkey-support.md`.
- ADR 0022, multi-vault switching and the active pointer: `docs/adr/0022-phase-6-multi-vault-switching.md`.
- ADR 0007, Single-String Protobuf Gateway: `docs/adr/0007-single-string-protobuf-gateway.md`.
- `docs/security/threat-model.md`, scoped bridge token entry.
- `crates/baluard-core/src/bridge/`
- `crates/baluard-nmh/src/main.rs`
- `crates/baluard-runtime/src/bridge.rs`
- `crates/baluard-daemon/src/handler.rs`
- `browser/shared/src/`
- `browser/README.md`
