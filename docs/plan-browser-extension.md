# Plan: Browser Extension (Chromium + Firefox)

> Status: Phase 0 and Phase 1 implemented (NMH host binary, bridge module, paired-companion pairing flow, allowlist, MV3 extensions for Chrome and Firefox). Phase 2 (passkeys, inline badges) deferred.
> Scope: bridge-style MV3 extension that talks to a running `baluard-daemon`, NOT a server-backed client.
> Owner: Esteban. Dogfooding target.

## 1. Goal

Two browser extensions (Chromium-family + Firefox) that autofill and capture
credentials against the **open Baluard daemon instance** on the user's machine,
so the project can be dogfooded daily and polished before mobile.

This is a **bridge client**, not a server client. Bitwarden's and 1Password's
extensions talk to their company servers; ours cannot, because Baluard has no
server (the git remote *is* the server). The correct reference architecture is
**KeePassXC-Browser**: extension talks to a local desktop app over a native
bridge.

## 2. Non-goals (v1)

- No talking to any remote server from the extension. All vault access is local
  through the daemon.
- No standalone vault (the extension is a thin client; the daemon is the source
  of truth, same as CLI/desktop).
- No passkey/WebAuthn in the browser yet (Phase 2 untrusted-ceremony work,
  see `plan-passkey-support.md` SEC-1). Out of scope for v1.
- No mobile. No Safari (MV3 Safari is optional/immature; revisit later).
- No browser code-signature verification (1Password-style hardening). Documented
  gap, deferred. See section 7.
- No breaking of the crypto/security invariants in AGENTS.md (AES-256-GCM,
  Argon2id, 0600 socket, token-gating, zeroize-on-drop, SO_PEERCRED).

## 3. Reference research: what we copy, what we don't

| Source | Take | Don't take |
|--------|------|------------|
| **Bitwarden extension** | MV3 structure: service worker + message-passing (`BrowserApi`-style), offscreen docs for clipboard, `action` API, `chrome.storage.session` for state, `scripting` permission. | Its transport (HTTPS to Bitwarden API) and its in-extension crypto/vault. We keep all crypto in the daemon. Its auto-fill-on-page-load default (exfil risk). |
| **KeePassXC-Browser + keepassxc-proxy-rust** | The bridge topology itself: extension -> native messaging host (stdio) -> local socket -> app. The NMH-as-thin-Rust-proxy idea. Per-OS NMH manifest install locations. The "desktop holds the unlock, extension rides it" auth model. | KeePassXC's wire crypto handshake (we already have token-gating + UID verify on the socket). |
| **1Password** | Desktop-app/browser-extension connection hardening as a *north star*: verify the calling browser's code signature before trusting the bridge (macOS/Windows). | We cannot realistically match code-signature verification in v1; documented as a hardening gap (section 7). |
| **MDN + Chrome native-messaging docs** | Exact stdio framing (32-bit native-endian length prefix, JSON, 1MB host->ext cap, 64MB ext->host cap), manifest keys, per-OS manifest paths. | - |

### Why native messaging, not loopback HTTP

A 0600 Unix socket cannot be opened by a WebExtension (no raw-socket API in
MV3). The only cross-browser escape hatch to a local process is
`nativeMessaging` (Chrome `runtime.connectNative`/`sendNativeMessage`, Firefox
identical). Loopback HTTP on the daemon was rejected: it widens the attack
surface to any local process + network stack, requires Origin/CORS pinning and
a second auth path, and matches no major password manager. Native messaging
keeps the existing UID-verified 0600 socket as the single trust boundary.

## 4. Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │ Browser (Chromium or Firefox)                            │
 │                                                          │
 │  Popup (SolidJS)        Service Worker (MV3)             │
 │  ─ NO master password  ─ holds NO secrets at all         │
 │  ─ list/search by URL   ─ chrome.runtime.connectNative   │
 │  ─ click login to fill  ─ routes allowlisted actions     │
 │  ─ generator              ┌───────────────┐              │
 │       │                   │ nativeMessaging│              │
 │       ▼                   ▼  (stdio JSON,  │             │
 │  ┌──────────────┐    ┌──────────────┐  len-prefixed)     │
 │  │ content      │◄──►│ service      │                    │
 │  │ script       │ msg│ worker       │                    │
 │  │ (fill only,  │    └──────┬───────┘                    │
 │  │  on command) │           │ stdin/stdout               │
 │  └──────────────┘           │                            │
 └─────────────────────────────┼────────────────────────────┘
                               ▼
                      ┌─────────────────┐     NEW
                      │ baluard-nmh     │  (standalone Rust binary,
                      │ (proxy)         │   registered as NMH)
                      │  - read stdio   │
                      │  - open socket  │
                      │  - varint+proto │
                      │  - STATELESS:   │
                      │    re-mints     │
                      │    bridge token │
                      │    per spawn    │
                      │    via pairing  │
                      │    file         │
                      └────────┬────────┘
                               │ Unix domain socket 0600
                               │ (varint-length-prefixed protobuf:
                               │  GatewayRequest / GatewayResponse)
                               ▼
                      ┌─────────────────┐
                      │ baluard-daemon  │ (already running, started by
                      │                 │  desktop tray or `baluard daemon`)
                      │  TokenKind::    │
                      │   Bridge check  │
                      │  + allowlist    │
                      │  SO_PEERCRED    │
                      └────────┬────────┘
                               ▼
                      ┌─────────────────┐
                      │  baluard-core   │  crypto + vault + sync
                      │  + bridge/ mod  │  + pairing/token logic
                      └─────────────────┘
```

Trust boundary = the 0600 socket + per-vault session token + bridge token +
server-enforced allowlist. Everything left of the NMH (popup, service worker,
content script, the page) is **untrusted** and never receives raw key material
or the master password. The extension is a **paired companion**: it never
unlocks, never sees the master password, never holds the vault session token.
It rides the desktop's unlock state via the NMH.

## 5. Auth model: paired companion (DECISION 1-4)

The extension is NOT a first-class unlock client. It is paired once with an
already-unlocked daemon and then rides that unlock state. This matches
KeePassXC-Browser and is strictly safer than an own-unlock extension.

**Decision 1, Auth model: paired companion (not own-unlock).**
The extension never sees the master password. You pair it once; afterward it
works while the desktop daemon is unlocked and is dead when locked. Single
source of lock truth = the daemon's existing auto-lock walker covers the
extension for free. No second Argon2id, no master password in browser memory.

**Decision 2, Token placement: NMH/daemon memory (Option 3).**
The vault session token is NEVER held by the extension or browser storage. The
daemon/NMH is the anchor. The extension -> NMH link is authenticated only by
`allowed_origins`/`allowed_extensions` pinning; the NMH -> daemon link carries
the real token. Extension JS touches no secrets.

**Decision 3, NMH lifecycle: stateless + durable pairing file (Option β).**
Standard native messaging spawns the NMH fresh per `connectNative` and kills it
on disconnect. A fresh NMH has no token. Resolution: on pair-complete the
daemon writes a 0600 **pairing file** (containing a pairing secret + pairing
ID, NOT the vault session token) to `<data_dir>/bridge/pairings.json`. Every
fresh NMH spawn reads its entry, presents the secret to the daemon, and the
daemon **re-mints an ephemeral bridge session token** for that NMH instance.
Token dies with the NMH; pairing file is durable. Vault locks anywhere -> token
voids -> NMH re-pairs cheaply on next spawn, daemon says "locked, open the
desktop app" if still locked. One binary, standard lifecycle, ephemeral token,
durable revocable pairing.

**Decision 4, Pairing ceremony: desktop-initiated approve-don't-type (review; supersedes the typed 6-digit code).**
No digits to transcribe. The user opens the desktop app and clicks "Add
browser extension" (or the extension triggers a pairing request and the
desktop surfaces it). The daemon creates a **pending-approval flag**
(desktop-session-token-gated, one-shot, short TTL). The extension calls
`bridge.pair_complete`; the daemon holds it pending; the desktop UI shows
"A Baluard extension wants to connect, Approve / Deny"; the user clicks
**Approve** (desktop token-gated) -> the daemon unblocks, mints the first
bridge token, writes the pairing file, returns the pairing secret to the NMH.

**Why this beats the typed code on both axes:**
- **Usability:** one click instead of read-then-type-under-a-60s-timer. No
  fat-finger lockout path. No brute-force surface AT ALL (no code = nothing to
  guess), so the entire rate-limit/nuke machinery below is gone.
- **Security equivalence:** the only threat the typed code defended against that
  approve-only doesn't is "same-UID attacker who can drive BOTH the browser AND
  the desktop UI." But an attacker who can synthesize clicks in the Tauri
  desktop window already holds the desktop session token and can call
  `vault.export` directly -> the bridge pairing isn't the boundary protecting
  you there. Against the actual model (browser compromise, NOT desktop
  compromise), approve-only is equivalent.

**Load-bearing requirement:** the Approve click must set a **one-time,
desktop-session-token-gated pending-approval flag** that `bridge.pair_complete`
*consumes*. The daemon must NOT auto-approve merely because the extension
asked. Consent originates in the desktop (the trust anchor per Decisions 1-4);
the digit-carrying step is simply removed.

**Residual abuse protection:** `bridge.pair_complete` still routes through the
existing per-vault `RateLimiter` (defense against a flooding attacker), but
there is **no vault nuke** on abuse, the worst case is the pending-approval is
rejected/dropped, the user re-clicks "Add browser extension." (the prior 5-strike vault-nuke was a DoS landmine for a non-tech user and
borrowed the PIN nuke for a lower-stakes ceremony where it didn't fit. Removed.)

**Why a surprise-Approve is no weaker than a surprise-code:** a same-UID
attacker who could socially-engineer a user into typing a code they saw could
just as easily socially-engineer that user into clicking Approve. The defense
in both cases is "the user is looking at the real desktop app," which is
identical. The surprise-approve dialog surfaces the browser identity so the
user can sanity-check it.

**TOTP/step-up NOT required for approve:** pairing happens while the vault is
already unlocked (Decision 1-3 require an unlocked daemon). The desktop session
token already proves the user authenticated to the desktop; Approve is consent,
not re-authentication. (If a future "confirm destructive bridge op" surface is
added, that's where step-up belongs, not pairing.)

## 6. Capability model: scoped bridge token (DECISION 5-8)

**Decision 5, Token model: scoped bridge token, NOT the per-vault session token
(Model 2); host-level registry, concurrent-NMH-safe (review C1/C4 + I4).**
The NMH does NOT hold the real per-vault session token (which gates everything
including `device.revoke` -> full rekey). Pair-complete mints a distinct
**bridge token**. Implementation is concrete against the real token model (the
daemon today holds one `session_token: RwLock<Option<String>>` per `VaultState`;
`TokenKind` is NEW plumbing):

- A **host-level bridge-token registry** lives on `VaultHost` (not per-vault,
  since bridge tokens are vault-agnostic per Decision 10): `HashMap<pairing_id,
  BridgeTokenEntry>` where `BridgeTokenEntry { token, last_active }`. This is
  required for **concurrent NMH instances**: a user running Chrome + Firefox,
  or two profiles, has multiple live bridges; a single-`Option<String>` token
  model would have them clobber each other.
- **Handler auth flow:** `verify_session_token` is refactored to *branch on token
  kind*. If `req.session_token` matches a live entry in the host bridge registry
  -> mark the request `TokenKind::Bridge { pairing_id }`, enforce the **allowlist
  (Decision 7) instead of** `TOKEN_REQUIRED_ACTIONS`, then snapshot the active
  vault. Else fall through to the existing per-vault token path
  (`TokenKind::Vault`). The bridge token rides the existing `session_token` wire
  field (no proto change); the daemon disambiguates by lookup.
- **Same-pairing concurrency:** multiple NMH processes for the *same* pairing_id
  reuse that pairing's single live token (`bridge.reauth` is idempotent, returns
  the live token if one exists for the pairing_id, mints only if absent).
- **Lifetime binding to lock state:** a bridge request fails `locked` when the
  active vault is locked. The daemon need not proactively wipe tokens on lock;
  every bridge request re-checks active-vault unlocked state.
- **TTL parity with the vault token:** bridge tokens carry
  `bridge_token_created` and expire on the same cadence as the per-vault session
  token (`SESSION_TOKEN_TTL_SECONDS`, 4h). On expiry the NMH re-runs
  `bridge.reauth` (cheap, idempotent). Prevents a bridge token from quietly
  becoming the least-scrutinized long-lived credential.
- **Per-`pairing_id` rate cap on credential-read routes (review , 
  BLOCKER):** without this, the allowlist redesign is theater. The daemon caps
  `bridge.match` + `vault.get` per `pairing_id` via the existing `RateLimiter`
  (~10-20/min; a human fills a handful of logins a minute). Burst abuse escalates
  to `bridge.revoke` for that `pairing_id`. Why load-bearing: a compromised
  browser (§10.2, an accepted gap) can otherwise loop `bridge.match` over a
  hardcoded list of top-N domains (github, gmail, your-bank...), then `vault.get`
  every hit at sub-millisecond local-socket latency, a chunked `vault.list_full`
  with extra round-trips, undoing the entire point of dropping `list_full`. The
  cap bounds a browser compromise to a handful of credentials, not the whole
  vault.
- **Revoke** drops the `pairing_id` entry from the host registry (not just the
  pairing file) so a live NMH's next request is denied immediately.

Rationale: bounds the pairing-file compromise to the actual extension surface,
never full vault power. Direct application of "principle least privilege"
(AGENTS.md security protocol).

**Decision 6, Code placement: `crates/baluard-core/src/bridge/` (Placement 1).**
Pairing logic, pairing file format, bridge token mint/verify, and the action
allowlist live in core (new `bridge/` module: `pairing.rs`, `token.rs`,
`mod.rs`), matching the established pattern (`crypto/`, `keys/`, `vault/`,
`sync/`, `providers/`, `device_manager.rs`). The daemon's `bridge.*` routes are
thin wrappers. The NMH depends on core (which it already does for socket
framing) and reads its own pairing entry via core types, no NMH -> daemon
dependency edge. The pairing file format becomes a first-class, proptest-able,
auditable artifact.

**Decision 7, Allowlist: minimal, no bulk-plaintext, one credential at a time
(review-revised Stance A; resolves C2, C4, I1, I2, D3, #4).**
Bridge tokens permit ONLY these actions (enforced server-side in the daemon's
handler after token verification). **`vault.list_full` is NOT on the list**: it returns the entire decrypted vault in one call (a de-facto export, and the
real blast radius, per review). Instead the extension sees metadata + one
credential at a time:

```
bridge.match            # URL -> matching CipherMeta (id, name, username, type).
                        #   Metadata only, NO passwords. Server-side URI match.
vault.get               # single selected credential, on fill/copy only.
                        #   One credential in browser memory at a time.
vault.add               # capture new login.
vault.update            # capture password change. FIELD-GATED for Bridge tokens
                        #   (see below): password/username/notes/totp OK;
                        #   fido2_credentials + uris REJECTED.
cipher.totp_code        # TOTP copy (derived numeric code only; seed never crosses).
generator.history_add, generator.history_clear   # generator (record/clear).
                        #   NOTE: history_list is EXCLUDED, it returns prior
                        #   generated secrets (plaintext leak, review C2).
bridge.config           # returns ONLY default_uri_match. NOT settings.get
                        #   (which leaks slug/enrollment_policy/profile PII).
sync.autosync_status    # sync badge (read-only).
```

**`vault.update` field gate for Bridge tokens (review C4 + X3):** server-side,
when `TokenKind::Bridge`, `vault.update` is REJECTED if the payload modifies
`fido2_credentials` (passkey tamper / data loss, defeats the passkey exclusion)
OR `uris` (autofill-redirect phishing: rewrite a bank login's URI to an
attacker domain, then next fill delivers creds there). Password / username /
notes / totp updates are allowed, that's the common "I changed my password on
the site" capture flow, essential for good UX. New URIs only via `vault.add`
(new entries) or the desktop.

**Favicons:** NOT a daemon route for the bridge. The extension fetches site
icons itself via its own `host_permissions` (or `chrome://favicon`). Review
found `favicon.get` is NOT an SSRF (fixed Google endpoint, 16KB cap, magic-byte
check, default-off) but it's still a network side-effect the extension doesn't
need on the daemon path.

NOT permitted (rejected even with a valid bridge token): `vault.delete`,
`vault.export`, `vault.import`, `vault.change_password`, `vault.list_full`,
`device.revoke` (full rekey!), `vault.devices`, `vault.device_activity`, all
`sync.*` mutation (init/disconnect/pull/push), all `provider.*`,
`vault.attach_*` (2MB blobs + plaintext bytes), `ssh.generate_key` (key
material), `passkey.*` (Phase 2 deferred), `vault.clone_*`, `folder.*`,
`tag.*`, `vault.archive`, `vault.unarchive`, `cipher.clone`, `settings.get`,
`settings.set`, `vault.trash.*`, `generator.history_list`, `favicon.get`.

Expansion is a deliberate allowlist change + same-change call-site update
(pre-1.0 WIP per STATUS). The friction is intentional, it forces a conscious
security decision per route.

**Decision 8, Management surface: pair + list + revoke, revocable-grant model
(Level 2); `bridge.reauth` added; daemon is sole pairing-file writer (review X1, I10, M3).**
Paired browsers are NOT part of the device-fleet epoch model, they have no
device private key, are not in `meta/device-privkey.json`, do not participate
in the key hierarchy, and revoking them does NOT rotate the root key. A paired
browser is a revocable auth grant with its own table and cheap revoke. Desktop
ships a "Paired browser extensions" settings tab: list (name, browser,
paired-date), "Pair new" button (mints code), revoke per row.

**Pairing-file ownership (review M3):** the daemon is the SOLE writer of
`<data_dir>/bridge/pairings.json` (atomic tmp+rename, review N2). The desktop
mutates it only via daemon routes. The NMH reads its own entry **read-only**
(never writes). This avoids multi-process write races (pair browser 2 while
revoking browser 1 while N NMHs read).

Daemon routes (all token-gated with the per-vault token except the pairing
flow):
- `bridge.pair_start`: **desktop-initiates** (token-gated; the "Add browser
  extension" button). Sets a **one-shot pending-approval flag** (desktop-session
  -token-gated, short TTL) and returns a request handle. No code is minted
  (Decision 4 approve-don't-type).
- `bridge.pair_complete`: called by the extension/NMH (not token-gated).
  Held pending until the user clicks **Approve** in the desktop UI (which
  consumes the one-shot flag from `pair_start`). On Approve: writes pairing file,
  mints first bridge token, returns pairing secret to the NMH. Rate-limited via
  the existing `RateLimiter` (flood defense; **no vault nuke**: Decision 4).
- `bridge.reauth`: **NEW** (review X1; this is the spawn-time re-mint Decision
  3 describes, which the original route list omitted). Secret-gated (pairing
  secret, not code, not token); idempotent (returns the live token for the
  pairing_id if one exists, else mints). Called by the NMH on every spawn and
  after any daemon restart. Rate-limited via the existing `RateLimiter`.
- `bridge.list`: token-gated; lists paired extensions.
- `bridge.revoke`: token-gated; removes the pairing_id from the host bridge
  registry (Decision 5) + deletes the pairing file entry. A live NMH's next
  request is denied immediately (not just file deletion).

**Revoke vs lock vocabulary (review X1):** "pair" = the one-time human ceremony
(Decision 4, code-gated). "reauth" = the silent machine re-mint on every spawn
(secret-gated, no human). Decision 3's old wording conflated the two; they are
distinct operations and now have distinct routes.

## 7. Fill policy & multi-vault (DECISION 9-10)

**Decision 9, Fill policy: popup-driven, per-fill user gesture (Trigger 3+4 hybrid);
top-frame-only fill (review C3/D1).**
No auto-fill ever, no fill on page load, no armed-tab auto-fill. Fill flow:
open extension -> popup reads current tab URL via `activeTab` -> calls
`bridge.match` (URL -> matching `CipherMeta`, server-side, Decision 7) -> shows
matching logins -> user clicks one -> popup calls `vault.get` for that single
credential -> messages the content script in that tab -> content script fills
the focused/best-detected form. Keyboard shortcut (e.g. Ctrl-Shift-L) also
counts as a gesture, bound to "fill current tab."

Consequences that REDUCE the plan's complexity vs a naive Trigger 3:
1. The **content script is a pure fill-executor**, not a UI-injector. No inline
   field icons, no injected DOM the page can tamper with, no continuous
   form-detection-for-display. The content script receives a "fill this login"
   command and runs field detection ONCE per user-initiated fill. Less page
   surface = less exfil surface.
2. Every fill **originates from a trusted extension surface** (our popup), not
   a page-injected element. A compromised page cannot trick the fill because
   the trigger lives entirely in the popup, which the page can't reach.
3. **Top-frame-only injection (review C3/D1):** the content script is injected
   via `chrome.scripting.executeScript({ target: { tabId, frameIds: [0] } })` , 
   TOP FRAME ONLY, not `all_frames`. A cross-origin login iframe (the classic
   credential-theft vector) simply doesn't get filled. Trade-off: legit
   embedded third-party logins won't autofill in v1 (acceptable; user can
   copy-paste from the popup). This designs out the page-influenced-target
   exfil class rather than mitigating it. Pair with `documentUrlPatterns`
   matching the popup-confirmed origin.
4. **Fill-time origin re-check:** the content script
   re-verifies `location.origin` against the credential's stored URI
   immediately before writing to the DOM, and fails closed on mismatch. Closes
   the narrow race where the popup matched tab A's URL, the user clicked fill,
   and the tab navigated (redirect / slow load) during the ~100ms IPC round
   trip, so the fill never lands in a now-different page.

This is the modern industry-default posture (1Password default, Bitwarden
"auto-fill on page load = off"). Auto-fill-on-load is a known exfil vector
(malicious page with disguised form harvests creds on visit); we do not repeat
that mistake.

**Amendment (2026-07-19): in-field dropdown menu, opt-out setting.** Decision
9's consequence 1 ("no inline field icons") is amended for usability parity
with 1Password/Bitwarden: `inline.js` is a persistent top-frame content
script, registered ONLY while the `inlineAutofill` setting is on
(`chrome.scripting.registerContentScripts`, allFrames: false, document_idle;
setting default ON, toggle in the popup's Settings view). The security
posture is unchanged in every load-bearing respect:
- Still no auto-fill on load. Filling needs two user gestures on OUR UI
  (icon click -> entry click); the UI lives in a closed Shadow DOM the page
  cannot traverse, restyle, or synthetically click.
- Matching stays server-side and origin-truthful: the SW's `inline.matches`
  route matches against `sender.tab.url` (privileged tab metadata), never a
  URL the content script claims. `senderUrl()` fails closed on non-http(s)
  or missing URLs.
- Credential delivery is push-only: `inline.fill` fetches `vault.get` and
  pushes `baluard-inline-fill` to the requesting tab with `expectedOrigin`
  from `sender.tab.url`. The credential is never returned as a message
  response into the page context.
- Fill-time origin re-check stays (inline.js refuses if `location.hostname`
  drifted during the IPC round trip).
- The icon appears on focus of username/password fields only
  (`isUsernameField` heuristics: autocomplete hints, word-boundary
  name/id/placeholder/aria-label hints, text-before-password structure).
  No continuous form scanning, no page-load probing, nothing
  fingerprintable beyond what the badge already queries.

**Decision 10, Multi-vault: extension follows the daemon's active pointer (Model ii).**
The bridge token is vault-agnostic: scoped to `TokenKind::Bridge { pairing_id }`
+ the allowlist, NOT to a specific slug. The NMH forwards requests with no slug;
the daemon routes bridge requests to the active vault (its existing pointer-flip
semantics). The extension has NO vault selector, the desktop is the switcher,
the extension inherits. Re-query `bridge.match` on every popup open (cheap,
single IPC, metadata only) so the list is always fresh to the current active
vault. The popup header shows the active vault name (read-only, refreshed on
open) so the user knows where a capture will land (review I8: silent
cross-vault write hazard). If the active vault is locked, the request fails
closed with `locked`; the extension surfaces "open the Baluard app."

Rejected: binding the extension to one vault at pairing (re-pair tax on every
switch) and an in-extension multi-vault selector (duplicates desktop's
`VaultSwitcher`, sync drift).

## 8. Component: `baluard-nmh` (new Rust binary)

**Location:** `crates/baluard-nmh/`.

**Responsibility:** translate stdio-JSON (browser) <-> varint-prefixed protobuf
(daemon). Nothing else. Stateless (Decision 3). No crypto, no vault logic.

**Daemon framing (already exists, reuse verbatim from
`crates/baluard-cli/src/client.rs`):**
- `GatewayRequest`/`GatewayResponse` from `proto/auth.proto` (prost).
- Request: varint-length prefix + `req.encode_to_vec()`.
- Response: read varint length, then `GatewayResponse::decode`.
- Socket path: `baluard_core::paths` (same resolver CLI uses).

**NMH stdio framing (browser native-messaging standard):**
- Each message: 32-bit native-endian length prefix + UTF-8 JSON.
- Direction symmetric. Cap host->extension at 1MB (browser hard limit).
- NMH must write debug to **stderr only** (stdout must stay protocol-clean).

**NMH wire JSON (minimal):**
```json
// extension -> NMH
{ "id": "<uuid>", "action": "bridge.match", "payload": "{\"url\":\"https://example.com\"}" }

// NMH -> extension
{ "id": "<uuid>", "ok": true,  "payload": "<json string>" }
{ "id": "<uuid>", "ok": false, "error": "<message>", "code": "locked|no-daemon|denied|proto|not-paired" }
```
`payload` mirrors the daemon's `GatewayRequest.payload` (JSON strings, per
AGENTS.md "Daemon Wire Format"). The NMH does NOT parse payload contents, only
relays. `id` lets the async service worker match requests to responses over a
long-lived `connectNative` port.

**Lifecycle:**
- `connectNative` spawns a fresh NMH; browser sends SIGTERM/SIGKILL (Unix) or
  Job-kill (Windows) on disconnect.
- On spawn: NMH reads its pairing entry via core. If absent -> `not-paired`
  (extension initiates Ceremony 3). If present -> presents secret to daemon ->
  daemon re-mints ephemeral bridge token -> NMH stamps it on every forwarded
  request.
- Reconnect on disconnect; surface `no-daemon` / `locked` to the UI.

**Error codes the NMH must classify:**
- socket connect refused -> `no-daemon` (UI: "Open the Baluard app").
- pairing file missing -> `not-paired` (extension runs Ceremony 3 flow).
- daemon returns `success=false` with auth/lock error -> `locked` / `denied`.
- malformed stdio -> `proto`.

### NMH manifest + install (per OS, per browser)

Host manifest (Chromium):
```json
{ "name": "xyz.actitud.baluard", "description": "Baluard bridge",
  "path": "/abs/path/to/baluard-nmh", "type": "stdio",
  "allowed_origins": ["chrome-extension://<EXT_ID>/"] }
```
Firefox uses `allowed_extensions: ["baluard@actitud.xyz"]` and a gecko add-on
id in the extension manifest.

Locations (user-level):
- Linux Chromium: `~/.config/chromium/NativeMessagingHosts/`
- Linux Chrome:   `~/.config/google-chrome/NativeMessagingHosts/`
- Linux Firefox:  `~/.mozilla/native-messaging-hosts/`
- macOS Chrome:   `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
- macOS Chromium: `~/Library/Application Support/Chromium/NativeMessagingHosts/`
- macOS Firefox:  `~/Library/Application Support/Mozilla/NativeMessagingHosts/`
- Windows: registry key under
  `HKCU\Software\Google\Chrome\NativeMessagingHosts\...` (Chrome) and
  `HKCU\Software\Mozilla\NativeMessagingHosts\...` (Firefox), default value =
  path to the host manifest.

`allowed_origins`/`allowed_extensions` pins the bridge to our extension ID
only, so a random extension cannot talk to `baluard-nmh`. Dev (load-unpacked)
IDs are generated; store IDs are fixed on upload, the host manifest uses the
final published ID; dev flow uses a key-pinned fixed dev ID.

## 9. Component: the extensions (shared codebase, two targets)

**Repo layout** (matches existing `browser/chrome`, `browser/firefox`):
```
browser/
├── shared/                 # 95% of the code, identical for both targets
│   ├── manifest.base.json  # merged with target manifest at build
│   ├── src/
│   │   ├── background/     # MV3 service worker entry
│   │   ├── popup/          # SolidJS popup (NO unlock; URL-filtered list, generator)
│   │   ├── content/        # fill-executor only (no UI injection)
│   │   ├── lib/
│   │   │   ├── nmh.js      # connectNative wrapper, id-multiplex, reconnect
│   │   │   ├── daemon.js   # allowlisted action helpers
│   │   │   ├── autofill.js # field detection + fill heuristics (shared: content.js + inline.js)
│   │   │   ├── inline.js   # in-field dropdown (opt-out setting; registered dynamically by the SW)
│   │   │   └── pair.js     # Ceremony 3 code entry + completion
│   │   └── i18n/           # reuse desktop en.json / es.json
│   └── vite.config.js
├── chrome/
│   ├── manifest.json       # MV3, host_permissions, allowed_origins ext id
│   └── package.json        # (exists)
└── firefox/
    ├── manifest.json       # MV3 + browser_specific_settings.gecko.id
    └── package.json        # (exists)
```

**One Vite build, two output bundles** distinguished only by manifest +
extension ID. JS is browser-agnostic via the `chrome`/`browser` namespace shim
(`webextension-polyfill` or a thin `BrowserApi` like Bitwarden).

**MV3 realities (from Bitwarden's migration notes):**
- Service worker, **not** a persistent background page. Can be killed after
  ~30s idle. State in `chrome.storage.session` only, and per Decision 2, that
  state is NEVER secrets (no token, no password). Just UI prefs + transient
  request `id`s.
- No DOM in the service worker -> clipboard copy via an **offscreen document**
  (`offscreen` permission).
- Content script injected via `scripting` on the fill command (Decision 9), not
  continuously on every page load.
- `alarms` for any periodic work (TOTP refresh, lock-state polling).

### Permissions (minimal)

```
permissions:      ["nativeMessaging","storage","scripting","activeTab","alarms","offscreen"]
host_permissions: ["http://*/*","https://*/*"]
```
No `<all_urls>`; host_permissions cover http/https. No `webRequestBlocking`.

## 10. Security model & threat surface

**Preserved (load-bearing, must not regress):**
- All crypto stays in `baluard-core`. The extension and NMH never see keys,
  KDF output, TOTP seeds, passkey private keys, or the master password.
- 0600 socket + SO_PEERCRED UID verify unchanged. NMH runs as the user (the
  browser spawns it under the user's account), so UID matches.
- Per-vault session token, constant-time compared, unchanged. The bridge token
  is a SEPARATE, SCOPED token (Decision 5); extension/NMH never hold the vault
  token.

**New / increased risks introduced by the extension:**

1. **Malware in the page can read autofilled fields.** Inherent to all
   browser password managers. Mitigations: fill ONLY on explicit user gesture
   from the popup (Decision 9), never auto-fill on load, so a hostile page
   cannot harvest by merely being visited. No inline-field DOM injection the
   page can tamper with. Top-frame-only fill (Decision 9) closes cross-origin
   iframe theft. Residual (field values readable after fill) is the same
   posture as Bitwarden/1Password; documented.
2. **Malware controlling the browser can drive the unlocked extension.**
   1Password mitigates by verifying the browser's code signature. We CANNOT do
   this in v1, documented hardening gap. Mitigations we DO have: (a) Ceremony
   3 pairing originates in the trusted desktop, so a drive-by can't pair; (b)
   `allowed_origins`/`allowed_extensions` pins the bridge to our extension ID;
   (c) the scoped bridge token (Decision 5) + allowlist (Decision 7) cap the
   damage: `bridge.match` (metadata) + one-at-a-time `vault.get` + gated
   `vault.add`/`vault.update` + generate, a compromised browser CANNOT
   `device.revoke` (rekey), `vault.delete`, `vault.export`, `vault.list_full`,
   or change your master password through the bridge. Residual: a compromised
   browser that can synthesize gestures in our popup can autofill into attacker
   pages. This is what makes the deferred code-signature verification survivable
   rather than reckless.
3. **Pairing file compromise (`<data_dir>/bridge/pairings.json`, 0600), HONEST
   reclassification (review X2, was under-rated).** A reader gains the pairing
   secret and can mint bridge tokens via `bridge.reauth`. This is a **revocable
   read-capable grant at rest**: while the vault is unlocked, a same-UID
   attacker holding the secret can enumerate credentials one-at-a-time via
   `vault.get`. That is MORE than the status quo (the per-vault session token is
   NEVER at rest). It is NOT, however, full-vault-in-one-call (no `list_full` on
   the bridge), NOT destructive (allowlist), and NOT persistent across lock
   (each request re-checks active-vault unlocked state). It is gated behind the
   same UID + 0600 socket the attacker already had. We accept this as a
   revocable grant (revocation = desktop `bridge.revoke`, instant) rather than
   pretend it's negligible. It does NOT contradict "keys never at rest
   unencrypted", no key material is in `pairings.json`, only a revocable
   capability secret. Documented in the threat-model addendum.
4. **Bridge token in NMH memory only.** Ephemeral, dies with the process on
   browser close (SIGKILL gives no zeroize window, review N-b, but the OS
   reclaims the memory; reworded from "zeroized" to "dies with the process"),
   re-minted on next spawn via the durable pairing secret. Never touches disk,
   never touches browser storage.
5. **NMH is a confused deputy parsing untrusted JSON (review X6).** It holds an
   authenticated socket to the daemon and forwards attacker-influenced
   `action`+`payload`. Defenses: (a) NMH enforces the **same allowlist** as the
   daemon (defense in depth, so a daemon routing bug isn't reachable via an
   action the NMH should never forward); (b) hard-cap stdio request size at
   ~64KB (the 64MB ext→host limit is huge); (c) reject non-JSON `payload`
   before forwarding (fail-closed); (d) NMH never logs `payload` (responses
   contain plaintext on `vault.get`).
6. **Clipboard exfil (review M2).** Copy-to-clipboard leaks to any app,
   clipboard managers, and possibly cloud-clip sync. The extension MUST clear
   the clipboard after ~20s (matching the desktop's policy) and prefer direct
   fill over copy wherever possible (fill never touches the clipboard).

**Audit distinguishability (review M5):** every daemon log line is tagged with
`TokenKind` (`Vault` vs `Bridge{pairing_id}`), so post-incident you can tell
bridge reads/writes apart from desktop activity. Cheap, and makes Decision 8's
"last active" column nearly free.

## 11. Phased implementation (tracer bullets)

Each phase is independently verifiable end-to-end.

**Phase 0 - Bridge skeleton + core bridge module**
- `crates/baluard-core/src/bridge/` (Decision 6): `pairing.rs`, `token.rs`,
  `mod.rs`. Pairing file format, secret gen, bridge token mint/verify. Proptests
  for secret gen + token verify.
- `crates/baluard-nmh`: stdio loop, varint+proto relay to daemon, stderr
  logging. Reads pairing entry via core.
- Daemon: `bridge.pair_start` + `bridge.pair_complete` + `bridge.list` +
  `bridge.revoke` routes (Decision 8). `TokenKind::Bridge` on auth result +
  allowlist check in `handler.rs` (Decision 5+7).
- Extension: empty popup + service worker that `connectNative`s and sends a
  `ping` -> NMH -> daemon `vault.info` (NOT token-gated, side-effect-free , 
  review N-a; isolates the socket+framing path from the token path) ->
  round-trip displayed in popup. A second ping exercises `bridge.reauth` + one
  allowlisted read (`sync.autosync_status`) to prove the token path.
- **Version handshake (review X5/I6):** the `ping` response carries
  `{ proto_version, nmh_version, daemon_version }`; the extension hard-fails
  closed with a `version-skew` UI ("update the Baluard desktop app") on
  mismatch. A password manager must never silently run a partially-understood
  protocol.
- `just` targets: `build-nmh`, `install-nmh-manifest` (writes host manifests
  for current OS + browser, dev extension ID).
- Verify: popup shows daemon info JSON. Daemon log shows the bridge connection
  + `TokenKind::Bridge` auth tag.

**Phase 1 - Pairing + read + autofill (the dogfooding core)**
- Desktop "Paired browser extensions" settings tab (Decision 8): "Add browser
  extension" button (triggers the approve-don't-type flow), list, revoke.
- Extension pairing flow (Decision 4): extension calls `bridge.pair_complete` ->
  daemon holds pending -> desktop shows "A Baluard extension wants to connect , 
  Approve / Deny" -> user clicks Approve (desktop token-gated, one-shot flag) ->
  daemon unblocks, mints token, writes pairing file. NMH re-mints via
  `bridge.reauth` on spawn.
- `bridge.match` (current-tab URL -> matching `CipherMeta`) -> popup list.
  Popup header shows active vault name (review I8).
- **Toolbar badge:** `chrome.action.setBadgeText` shows the
  match count for the current tab on the toolbar icon, zero-DOM ambient
  discoverability with no attack surface. The "it just works" feedback the plan
  was missing.
- Click a login -> `vault.get` (single credential) -> message content script
  (top-frame-only, Decision 9 + fill-time origin re-check) -> fill focused/best
  form.
- Copy-to-clipboard via offscreen doc, auto-clear after ~20s (review M2).
  TOTP copy (`cipher.totp_code`).
- **Error-state UX: Phase-1 GATE, not Phase-3 polish:**
  every NMH error code (`locked|no-daemon|denied|proto|not-paired|version-skew`)
  maps to a friendly, actionable, i18n'd message (en/es, reuse desktop strings).
  Bar = PIN's "Incorrect PIN. N attempts left." e.g. `no-daemon` -> "Open the
  Baluard app to fill passwords" (not "ECONNREFUSED"). No hard tech terms
  (AGENTS.md UX principle). This ships before anyone else uses it.
- Verify: pair via desktop approve, search a login, autofill a real site, copy a
  password + TOTP. Confirm multi-vault active-pointer routing (Decision 10).

**Phase 2 - Capture + edit + generator**
- Capture: on form submit in content script, detect new/changed credentials,
  prompt **"Save to <em>Personal</em> vault?"** (vault name IN the affirmative
  prompt, not just an ambient header label). Protects against
  "I forgot I switched vaults this morning" writing a secret into the wrong
  (possibly shared/work) vault. -> `vault.add` / `vault.update`.
- Generator in popup (reuse `generator.*`).
- Lock reflection: show daemon lock state; "open the Baluard app" when locked.
- Verify: save a brand-new login from a signup page; it appears in desktop.

**Phase 3 - Polish**
- Sync badge (`sync.autosync_status`). Favicon icons fetched extension-side
  (NOT via daemon).
- Keyboard shortcut fill (Ctrl-Shift-L).
- i18n (reuse desktop en/es). Settings: URI match strategy via `bridge.config`.
- Cross-device dogfood: a capture on machine A syncs via git and appears in the
  extension on machine B after pull (dogfoods autosync end-to-end).
- Threat-model addendum (section 10).

**Deferred (explicitly not v1):**
- Passkeys in-browser (Phase 2 untrusted ceremony, `plan-passkey-support.md`).
- NMH auto-starting the daemon.
- Browser code-signature verification (1Password-style hardening).
- Safari.
- Last-seen tracking on paired extensions (Level 2.5).

## 12. Build / dev commands (proposed additions to justfile)

```
just ext-build           # build both chrome + firefox bundles via Vite
just ext-build-chrome
just ext-build-firefox
just build-nmh           # cargo build -p baluard-nmh (release)
just install-nmh-manifest BROWSER=chrome EXT_ID=...   # write host manifest for current OS
just install-flatpak-shim   # write flatpak-spawn wrapper + overrides for flatpak browsers
just ext-dev-chrome      # build + print load-unpacked path
just ext-dev-firefox     # build + print about:debugging load path
```

## 12a. Sandboxed browsers: Flatpak & Snap (review M1)

Ubuntu ships Firefox as a Snap by default; many Linux users run Firefox or
Chromium as Flatpaks. A sandboxed browser **cannot reach the host NMH binary or
the 0600 socket**: native-messaging manifest discovery happens inside the
sandbox's filesystem view, and the socket path is outside it. This is exactly
KeePassXC issue #12327. We **mimic KeePassXC-Browser's resolution**, prioritizing
**Flatpak** (per project decision), Snap secondary.

### Flatpak mechanism (primary)

Reference: Harald Sitter's KDE blog (the KeePassXC flatpak integration author).

1. **Manifest lives in the sandbox's view.** The desktop installer writes the
   NMH host manifest into the flatpak browser's data dir, e.g.
   `~/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/xyz.actitud.baluard.json`
   (Firefox) or `~/.var/app/<chromium-app-id>/config/<browser>/NativeMessagingHosts/`
   (Chromium-family).
2. **The manifest `path` points to a `flatpak-spawn` wrapper**, NOT the NMH
   directly, the sandboxed browser cannot exec a host binary by path. The
   wrapper:
   ```sh
   #!/bin/sh
   exec flatpak-spawn --host --watch-bus /usr/local/bin/baluard-nmh "$@"
   ```
   `flatpak-spawn --host` runs the NMH **outside** the sandbox (where it can
   reach the 0600 socket); `--watch-bus` ties its lifetime to the caller.
3. **The browser flatpak needs permission to talk to the portal.** Installer
   runs:
   `flatpak override --user --talk-name=org.freedesktop.Flatpak org.mozilla.firefox`
4. **Socket reachability:** because the NMH runs on the host (via
   `flatpak-spawn`), it connects to the real `$XDG_RUNTIME_DIR/baluard/baluard.sock`
   normally. No socket proxying needed, the NMH itself escapes the sandbox.

The desktop installer (Phase 1) detects installed flatpak browsers and performs
steps 1-3 automatically. A systemd path-unit "mangler" (KeePassXC's approach,
for when the browser overwrites the manifest on update) is the robustness
fallback; defer to Phase 3.

### Snap mechanism (secondary)

Ubuntu's Firefox-snap uses the `webextensions` permission table. The installer
runs:
```
flatpak permission-set webextensions xyz.actitud.baluard snap.firefox yes
```
(`flatpak permissions webextensions` to verify.) The NMH binary must be on a
path the snap can execute; the snap's native-messaging-host manifest lives in
the snap's confined view. Snap support is best-effort in v1; Flatpak is the
priority and primary test target.

### Non-goals for sandbox v1

- No support for custom/fork browsers' sandboxes (Librewolf-flatpak, etc.)
  beyond the documented paths; users can copy the manifest manually.
- No Firejail profile shipping in v1 (document the path, like KeePassXC's wiki).

## 13. Resolved decisions (grilling session log)

1. **Auth model:** paired companion (not own-unlock). Extension never sees
   master password; rides desktop unlock.
2. **Token placement:** NMH/daemon memory (Option 3). Extension JS holds no
   secrets.
3. **NMH lifecycle:** stateless + durable pairing file (Option β). Ephemeral
   bridge token re-minted per spawn via the pairing secret.
4. **Pairing ceremony:** desktop-initiated **approve-don't-type** (review; supersedes the typed 6-digit code). One-shot desktop-token-gated
   pending-approval flag; user clicks Approve. No code, no brute-force surface.
5. **Token model:** scoped bridge token, not the per-vault session token
   (Model 2). `TokenKind::Bridge { pairing_id }` + server-enforced allowlist.
6. **Code placement:** `crates/baluard-core/src/bridge/` (Placement 1).
7. **Allowlist:** metadata + one-credential-at-a-time (review-revised).
   `bridge.match` + `vault.get` (not `vault.list_full`); `favicon.get`/
   `settings.get`/`generator.history_list` excluded; `vault.update` field-gated
   (no `fido2_credentials`, no `uris`).
8. **Management surface:** pair + list + revoke, revocable-grant model
   (Level 2). Not device-fleet; revoke does not rekey. `bridge.reauth` added
   (silent spawn-time re-mint); daemon is sole pairing-file writer.
9. **Fill policy:** popup-driven, per-fill user gesture (Trigger 3+4 hybrid).
   Content script is fill-executor only; **top-frame-only injection** (no
   `all_frames`) closes cross-origin iframe theft.
10. **Multi-vault:** extension follows the daemon's active pointer (Model ii).
    No extension-side vault selector. Popup header shows active vault name.

### Resolved via peer review

11. **Pairing abuse defense (review A-4/B-2, revised):** the prior
    6-digit-code + 5-strike vault-nuke was a DoS landmine for a non-tech user.
    Replaced by approve-don't-type (no code = nothing to brute-force).
    `bridge.pair_complete` still rate-limited (flood defense), but **no vault
    nuke**: worst case the pending-approval is dropped and the user re-clicks
    "Add browser extension."
12. **Bridge-token storage:** host-level `HashMap<pairing_id, BridgeTokenEntry>`
    on `VaultHost` (not per-vault); concurrent-NMH-safe; same-pairing NMHs reuse
    one live token.
13. **`vault.update` field gate:** Bridge tokens may edit password/username/
    notes/totp but NOT `fido2_credentials` or `uris` (passkey tamper + autofill
    redirect). New URIs only via `vault.add` or desktop.
14. **No bulk plaintext to the browser:** drop `vault.list_full`; use
    `bridge.match` (metadata) + per-fill `vault.get`. Pairing file honestly
    reclassified as a revocable read-capable grant at rest (not "acceptable/
    negligible").
15. **`bridge.reauth` route:** secret-gated, idempotent; the spawn-time re-mint
    Decision 3 describes. Daemon-restart recovery path. Splits "pair" (human)
    from "reauth" (machine).
16. **Flatpak/Snap:** mimic KeePassXC-Browser. Flatpak primary (manifest in
    sandbox view + `flatpak-spawn --host --watch-bus` wrapper + portal talk
    permission); Snap secondary (`webextensions` permission table).
17. **Version handshake:** `ping` carries proto/nmh/daemon versions; extension
    hard-fails `version-skew` on mismatch (never degrade).
18. **Defense-in-depth + audit:** NMH enforces the same allowlist as the daemon;
    daemon log tags every request `Vault` vs `Bridge{pairing_id}`.
19. **Overturned review findings (kept for honesty):** `favicon.get` is NOT an
    SSRF (fixed Google endpoint, verified in source); `generator.history_list`
    leak is real but subordinate to the `vault.list_full` baseline it shares , 
    both removed.

### Resolved via review (security + usability lens)

20. **Per-`pairing_id` rate cap on credential reads (BLOCKER):**
    `bridge.match` + `vault.get` capped ~10-20/min via `RateLimiter`, burst ->
    `bridge.revoke`. Without it a compromised browser loops `bridge.match` over a
    bank/github/gmail domain list then `vault.get`s every hit, a chunked
    `vault.list_full`. This is what makes the allowlist redesign actually bound
    a browser compromise.
21. **Approve-don't-type pairing:** see Decision 4 + entry 11.
    Strictly friendlier AND removes the brute-force surface + the nuke DoS.
22. **Bridge-token TTL parity:** bridge tokens expire on
    `SESSION_TOKEN_TTL_SECONDS` (4h) like the vault token; NMH re-runs
    `bridge.reauth` on expiry.
23. **Fill-time origin re-check:** content script re-verifies
    `location.origin` vs the credential URI before writing; fails closed on
    tab-navigate-during-IPC race.
24. **Usability gates:** toolbar badge for ambient
    discoverability (no DOM, no attack surface); vault name IN the capture
    prompt ("Save to *Personal* vault?"), not just a header label; error-state
    UX is a Phase-1 gate, every code -> friendly actionable i18n string, no
    hard tech terms (AGENTS.md UX principle).
25. **macOS keychain for pairing secret:**
    on macOS, store the pairing secret in a `SecAccessControl` keychain entry
    scoped to the NMH code signature (Touch ID/passcode on read), raising the
    bar above a flat 0600 file. Linux/Windows keyring backends are same-UID-
    readable via D-Bus/Credential Manager, so parity there is weaker , 
    platform-conditional win, don't oversell as universal. Defer to a hardening
    pass post-v1.

## 14. Remaining open questions

1. **NMH packaging.** Ship `baluard-nmh` inside the desktop installer (so the
   user installs once), or as a standalone artifact? Lean: bundle with desktop
   installer, desktop registers the NMH manifests on first run. Confirm in
   Phase 1.
2. **Dev vs store extension IDs.** Dev (load-unpacked) IDs are generated; store
   IDs are fixed on upload. `allowed_origins`/`allowed_extensions` pinning
   needs the final ID. v1 dev flow: key-pinned fixed dev ID; store ID handled
   at publish. Confirm in Phase 0.
3. **Flatpak systemd mangler (robustness).** KeePassXC uses a systemd path-unit
   to re-mangle the manifest when the flatpak browser overwrites it on update.
   Defer to Phase 3; decide if needed once the installer's auto-setup is
   tested against browser updates.
4. **Extension discoverability.** Decision 8's "Add browser
   extension" button assumes the extension is already installed. How does a
   user learn the extension exists + where to get it (store listing, first-run
   desktop banner)? Likely out of scope for this doc but worth a line so it
   isn't forgotten at release time.
