# Browser extension tethered to the mobile app

Status: exploration rev 3, 2026-11-20. Not a decision. Revised after two Claude peer reviews and four spikes (A device keys, B MV3 CSP, C FGS/battery, D handshake). Driver: phone-first users. The common case is the browsing machine on a different network than the phone (office, company, second home), so the internet relay path is the primary v1 transport; direct LAN pairing is NOT in v1 (it is unproven on the browser side: Firefox upgrades ws://, a phone-served self-signed WSS cannot be pinned from the WebSocket API, and Android 17 makes ACCESS_LOCAL_NETWORK mandatory at targetSdk 37 — follow-up phase behind its own spike). Grounded in ADR 0092 (browser extension), ADR 0095 (passkeys), ADR 0113 (P2P sync transport), the bridge code (`crates/baluard-core/src/bridge/`, `crates/baluard-runtime/src/bridge.rs`, `crates/baluard-daemon/src/handler.rs`), and the extension client (`browser/shared/src/`). Drafted as ADR 0114; next free ADR number: 0115.

## Goal

The desktop browser extension rides the Baluard mobile app as its unlock authority instead of the desktop daemon. The phone is the thing that is always with-you; the browsing machine runs nothing Baluard-owned. The primary case is "both devices online, different networks" (office laptop and phone in a pocket); same-LAN pairing is a possible later phase, not in v1. Android users who enable browser tethering accept the foreground-service posture it requires.

## Honest cost baseline (corrected by review)

The doc previously claimed the bridge policy was transport-agnostic and already in core. That was wrong, and the extraction is the first work item:

- `baluard-core/src/bridge/` (606 lines) holds only the pairing file format, `PairingSecret` (a 256-bit random bearer value, explicitly "NOT a key", `pairing.rs:7-9`), and the `BRIDGE_ALLOWED_ACTIONS` const with `is_allowed` (`token.rs:48-73`).
- `baluard-runtime/src/bridge.rs` (656 lines) holds the registry: live tokens keyed by `PairingId`, TTL re-mint (`bridge.reauth`, 4 h TTL, `token.rs:18`), `charge_read` (30 per 60 s, `token.rs:157`), auto-revocation, constant-time compares via `subtle`. Runtime, not core.
- `baluard-daemon/src/handler.rs` (~9.6k lines; bridge routes around `:2159-3430`) holds the actual policy: `route_bridge_request` runs the allowlist check, charges the read cap, auto-revokes, applies the field gate and origin binding (`bridge_read_matches_page`, `:2857`), and carries `bridge_write_gated` (D21) and cross-vault scope. This is the crate mobile does not link.
- Mobile exposes nothing bridge-related through UniFFI today (`baluard-uniffi` depends on core + runtime only).

Work item 0 therefore: extract bridge policy from `handler.rs` into `baluard-runtime`, with the existing tests, before any tether code exists. This is a ~1k-line security-critical refactor and the honest precondition for the "same code, enforced phone-side" claim. Also verify mobile's session/write-scope model is equivalent to desktop's `bridge_write_gated` rules; confirmed existence, not equivalence.

The extension seam is genuinely one call site: `chrome.runtime.connectNative` at `browser/shared/src/background.js:42`.

## Platform constraints: the design space is small

A MV3 service worker has exactly one general network primitive: WebSocket (`wss://`). Fetch is request-shaped and useless for a long-lived bridge. WebTransport is Chrome-only (Firefox has none). No raw TCP, UDP, or QUIC. Web Bluetooth and Web NFC are document-context-only with no service-worker support.

Consequences:

- BLE, NFC, and USB are dead as transports. USB survives as a dev tool (`adb reverse`).
- "Both online, different networks" requires an outbound-only leg from the phone plus a rendezvous endpoint the browser can reach.
- Chrome (SW) and Firefox (event pages) have different worker lifetimes and WebSocket semantics; they must be handled and tested separately, not as one.

Resolved by Spike B (2026-11-19, empirical on Chromium 156 + Firefox 159): the MV3 default `extension_pages` CSP contains no `connect-src`, and WebSocket connections are not host-permission-gated in either browser, so the background context can open `wss://` to an arbitrary user-supplied relay host with no manifest change and no host permissions. Two design rules follow: never add `connect-src` or `default-src` to the manifest CSP (`default-src` silently swallows WebSocket as its fallback directive; a `connect-src` wildcard is an exfiltration-grade hole that buys nothing), and no `optional_host_permissions` is needed for the relay socket (only if the tether later uses fetch against it). Shipped precedent: the Alby extension connects to user-configured `wss://` relays on both stores. Enterprise self-host stands. Full report: `docs/designs/spike-b-mv3-csp-relay.md`.

## Topology

```text
Browser extension (MV3 SW)          untrusted; holds ONLY a non-extractable device key
        |  WSS + per-session AEAD channel (spec below)
        v
reachability layer (v1 ships both)
  internet: phone dials OUT to a relay; extension dials the same relay;   [primary]
            relay routes by rendezvous id, sees metadata + ciphertext only
  LAN:      phone serves WSS directly (mDNS discovery)        [NOT in v1; follow-up phase behind its own spike]
        v
Baluard mobile app (Android, foreground service while browser access is on)
        |  baluard-runtime bridge routes (extracted policy; see baseline)
        v
vault + git sync (unchanged)
```

The phone is a bridge server, not a vault server. Relay posture: the primary self-host method is the relay as a `baluard relay` CLI subcommand (the CLI already ships in the apt/rpm/dnf trees, so self-hosting is install + one command behind systemd on any always-on machine the user owns; the docker image stays as an optional extra for VPS-only users, same wire protocol); the Baluard-hosted relay is opt-in and replaceable, which is also the enterprise answer (a company hosts its own relay and the phone dials nothing else). The invariant to claim is "no server sees vault data", not "no server": a hosted relay sees rendezvous ids, timing, and ciphertext sizes, and hosting it makes Baluard a metadata processor (privacy policy, retention, GDPR statement, uptime/abuse commitment). That is a product decision to make before building, not an implementation detail.

Relay hostility must be survivable: it can deny service (drop, delay, DoS) but not read, alter (AEAD rejects), replay (freshness + counters reject), or substitute a peer (device-key authentication fails). A hostile or expired relay degrades to an explicit "phone unreachable", never to a wrong answer. Traffic analysis is real (fill timing reveals which sites a user logs into, when); state it as accepted residual risk or pad later, do not ignore it.

Relay realism: the router core is small, but squat protection (first-wins lets an attacker claim an id before the phone dials), per-IP rate limits, rendezvous id TTL, frame-size caps, backpressure, TLS termination, health checks, and abuse logging push the relay to ~500-1000 lines plus a deployment story ("stateless" becomes "small, bounded state"). TLS at the relay is required even though the envelope is E2E (Firefox upgrade-insecure-requests upgrades ws:// to wss://): tailscale serve in front (valid cert, zero config), Caddy/Traefik in front, or native ACME in the CLI later. First-party Tailscale Funnel support extends the CLI relay to boxes without a public IP: `baluard relay` + Funnel on the box gives a public ts.net URL with no port forwarding (a home server behind CGNAT qualifies); the extension needs no Tailscale, the QR carries the funnel URL as the relay endpoint, and Funnel terminates TLS at the user's device while the funnel relays act as a non-decrypting TCP proxy (metadata class unchanged; keeps "no Baluard-operated server sees vault data" true). Funnel does not run on the phone (CLI-only platform; Android and iOS apps lack it), so it is a reachability add-on for the relay box, never a phone endpoint. Review estimate, adopt it.

Wake-up push (FCM/APNs on demand) stays rejected: multi-second latency kills inline autofill.

## Channel spec (new; replaces "sequence counters" hand-wave)

The repo's HPKE usage today is one-shot `OpModeS::Base` key wrap (`crypto/hpke_wrap.rs:56`): anonymous sender, one-way, no ordering, no replay protection. "The pairing key authenticates both ends" would be false with it. Spec for the tether channel:

1. Enrollment (pairing time): the extension generates a non-extractable WebCrypto device credential pair and registers the public halves with the phone. Mutual pinning: the phone pins the extension's Ed25519 signing key and X25519 static key; the extension pins the phone's Ed25519 signing key and X25519 static key (fingerprints shown in the pairing ceremony). Viability confirmed by Spike A (2026-11-19, empirical on Chromium 156 + Firefox 159): Ed25519 `generateKey(..., false, ["sign","verify"])` works on Chrome ≥ 137 / Firefox ≥ 129, X25519 derive works non-extractable on both (pass the peer key as `{name:"X25519", public: pub}`, not `publicKey`), and the `CryptoKey` persists in IndexedDB on the extension origin and signs correctly after full worker/page restarts on both browsers. Two honest limits from the spike: a non-extractable IndexedDB key is NOT device-bound (copying the browser profile directory clones it; Bugzilla 1556794), so pairing still needs the QR secret + approve screen as the human check; and in-origin code can abuse the key as a signing oracle, which is CSP/dependency hygiene, not cryptography. Compatibility shim: fall back to non-extractable ECDSA P-256 if Ed25519 is rejected (Chrome < 137). Full report: `docs/designs/spike-a-webcrypto-device-key.md`.
2. Handshake (per session, i.e. per worker wake): RESOLVED by Spike D (2026-11-20, working prototype, 8/8 tests): the channel is the "webnative" construction (Noise-KX-flavored), NOT HPKE Auth. Both sides contribute fresh ephemeral X25519 keys; session key = HKDF over the triple DH blend DH(eI,eR) || DH(eI,sR) || DH(sI,eR) with the full transcript including a fresh server nonce; the phone signs msg2 with its pinned static Ed25519 key and the extension signs the transcript with the device key; the phone executes nothing before its nonce is in the transcript and echoed back. Sender-ephemeral HPKE Auth alone is dead: it gives no forward secrecy (phone-static leak decrypts recorded handshakes; KCI applies), and its first frame under static keys is replayable within the timestamp window; it would also force a new JS HPKE dependency (no WebCrypto HPKE API exists), which the webnative construction avoids entirely (X25519 deriveBits + HKDF + AES-GCM + Ed25519 are all WebCrypto-native). Rust side: the construction is custom, not a stock Noise pattern (transcript signing with Ed25519 has no Noise equivalent), so production handshake code requires a dedicated security review before ADR 0114 moves to Accepted; prefer a stock Noise pattern (XX/IK, nonce echo at the application layer) if the review shows equivalence. Prototype + tests: `docs/designs/spike-d-src/`; report: `docs/designs/spike-d-two-party-handshake.md`. Implementation trap recorded in the report: never reinterpret sk bytes as pk bytes in HPKE — silent `OpenError` instead of a validation failure.
3. Data frames: AES-256-GCM (repo invariant) with AAD binding {session transcript hash, direction, sequence counter, timestamp, pairing id, action}. Counters are per-direction per-session, in memory only; a worker restart means a new session and a new handshake, so a rolled-back storage cannot rewind a counter.
4. Freshness and reordering: phone rejects frames whose timestamp drifts beyond a tolerance (e.g. 30 s) and whose sequence is not the next expected (small reorder window acceptable for a request-response protocol); the relay cannot replay an old response into the current session because the transcript hash changes per session and cannot re-order across sessions.
5. No bearer secret on the wire or at rest: the current 256-bit `PairingSecret` is not used as a key and never crosses the channel; `bridge.reauth`'s token re-mint either rides the authenticated session or the session replaces tokens on the tether. Decide during implementation; both are safe if bound to the session.
6. Pre-protobuf gate: every `GatewayRequest` path is now internet-reachable. The envelope must verify, decrypt, and check {pairing, allowlist, frame size cap} BEFORE any protobuf parsing. Hard frame size limits from frame one.

## Trust model deltas (rev 2)

1. Extension holds a secret (revised honestly). This is NOT "same posture as threat 2". It is a new threat, 3b: "remote-capable credential at rest in the browser profile". Today (ADR 0092:57) the extension touches no secrets; threat 3 needs same-UID file access plus the 0600 socket; a tether credential is usable from anywhere at any time until revoked, and nothing on the wire proves the client is the extension unless we make it so. Readers of `chrome.storage.local`: same-UID disk malware (unencrypted LevelDB on Linux/Windows), devtools on the extension worker, malicious extensions with `debugger`, profile backups/copies. Preferred mitigation, replacing the bearer model: the non-extractable device key above (stolen profile bytes yield a useless handle bound to one browser profile). Fallback if browser support fails: documented bearer secret + 30-day pairing expiry with explicit re-approval + per-session biometric + last-seen display. Guardrail: a lint/test forbids `chrome.storage.sync` for any pairing material (it would cloud-sync the credential).
2. No `SO_PEERCRED`. Replaced by device-key authentication in the handshake plus the pinned phone key; extension-ID pinning (`0092:202`) does not carry over, and the device key is what restores a per-client identity.
3. Consent origin moves to the phone. The approve click happens in the app. The first-connect approve screen must show what is being approved (browser name/IP), not just a bare accept.
4. Policy enforcement moves to the phone only after work item 0 (the extraction). Until then, "same code" is false; after it, allowlist, field gates, origin binding, locked-vault fail-closed, and multi-vault semantics are enforced phone-side.
5. Biometric step-up per fill/passkey remains the genuine security upgrade over desktop.

Capped-vs-uncapped truth (corrected by review): the 30/60 s cap covers `vault.get` and `passkey.provider_assert` (`handler.rs:2701`); `bridge.match` is deliberately uncapped (`:2697-2700`). Over the tether that means an attacker with a valid session can enumerate every domain in the vault forever. Tether requirement: cap `bridge.match` per the ADR 0114 decision 5a caps (per-distinct-domain counters, throttling never revokes), close the slow-drip hole (29 reads/min never trips the burst auto-revoke; 43k/day is possible today) with the throttle notification, plus a daily cap on secret reads.

## Pairing spec (new)

Direction reversal with reasons: the phone has the camera, so the extension displays the QR and the phone scans it (the review's "extension scans" was unworkable without camera-permission plumbing in the extension). QR payload: relay endpoint(s) (or LAN host), rendezvous id, one-time pairing secret, extension device pubkey fingerprint. Existing ceremony parameters carry over: short TTL (120 s), single-use, 3 attempts (`bridge.rs:102,150-197`).

- Rendezvous id: 128-bit random, generated by the extension (or phone; pick one, document it), expires with the QR.
- First-connect proof of possession: the one-time secret authenticates the first handshake message. PAKE is rejected for v1 (ADR 0114 decision 4); TTL, single use, and phone-side confirmation are the mitigations.
- Race/squat: the phone rejects any first connect whose proof of possession fails, and the approve screen shows browser identity and IP; the relay's first-wins squat window is closed by the phone dialing out immediately after QR generation.
- Key pinning: mutual pinning at pairing — the extension pins the phone's Ed25519 and X25519 keys; the phone pins the extension's Ed25519 and X25519 keys (ADR 0114 decision 4). Rotation or phone reinstall means re-pair.
- Desktop "mirror" of the desktop-initiated approve flow: acknowledge in the ADR that this mirror does not exist yet and is scoped as part of pairing v2.

## The mobile OS reality (resolved by Spike C)

Android: enabling browser tethering requires a foreground service. Spike C (2026-11-19/20, sources + measurements on a Galaxy S25 Ultra / Android 17) resolves the type question: declare `connectedDevice` (`FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_CONNECTED_DEVICE`, platform prerequisite satisfied by declaring `CHANGE_WIFI_STATE` or `CHANGE_WIFI_MULTICAST_STATE`). The platform docs explicitly cover "interactions with external devices that require a … network connection"; the type has no runtime time limit (`dataSync` is disqualified as a 24/7 type: 6 h/24 h cap since Android 15, service must stop within seconds of `onTimeout` or the app crashes); the Play Console use case "Continuous Data Transfer to an External Device" fits, with a pairing-flow video as evidence; and KDE Connect ships exactly this type on both stores. Fallbacks if Play pushes back, in order: "active session" framing (FGS only while tethering is enabled/connected), then `specialUse` with a concrete subtype string (case-by-case review risk), then `dataSync` with stop-on-timeout + reconnect. F-Droid needs no Play declaration. Policy-shaped design rules: FGS starts from an explicit user action, honest persistent notification with one-tap stop, never from `BOOT_COMPLETED`.

The measured battery story: 25 s keepalive on WiFi is effectively free (~0.15 %/day net, radio asleep 99.6 % of wall time, RTT 16-25 ms fresh-TLS) and unlock latency is dominated by relay routing, not the phone. On cellular, 25 s sits inside the LTE RRC tail (inactivity ≈ 11.6 s) and costs ~5 %/h in the worst published case, so the keepalive must be adaptive: 25 s on WiFi/screen-on, 60-120 s background WiFi, 60-300 s cellular. Doze suspends network access for ALL apps including FGS (empirically confirmed on-device: no handshake completes in deep idle), so Doze is a disconnect event: show "authority offline", reconnect on wake; users who want overnight availability opt into the battery-optimization exemption, whose published acceptable-use table lists exactly this case ("peripheral device companion app — maintaining a persistent connection"). Cellular + Doze + 24 h OEM-killer dogfood numbers follow the measurement protocol in the spike report. OEM battery killers (Xiaomi, Samsung) still require whitelisting in practice; design for connection churn and cheap per-session re-handshakes (the channel spec already assumes this). Full report: `docs/designs/spike-c-fgs-latency-battery.md`.

iOS: no inbound sockets, outbound dies in minutes, Safari Web Extension is a separate project. Out of scope v1, unchanged.

## Locked-phone state machine (new; fail-closed over the network)

Explicit FSM, no boolean soup:

- `disconnected` → `handshaking` → `paired_locked` → `paired_unlocked` (+ transient `needs_biometric` when a step-up is required). Any state → `disconnected` on session loss.
- FGS keeps the socket alive; it does NOT keep the vault unlocked. Mobile auto-lock (timer + backgrounding) drives `paired_unlocked → paired_locked` exactly like today.
- Over-tether unlock: the desktop flow's `request_unlock` (`handler.rs:2736`) does not map to a phone in a pocket. Spec: a locked-phone tether request produces a notification with a biometric prompt; the extension shows "unlock your phone" and retries with backoff. Rate-limit the notification path (e.g. 3 per minute, backoff to 1/h) because it is a new phishing vector: any session-holder can ring the user's phone repeatedly. The phone only unlocks the vault on an explicit, biometric-gated, in-app action, never from the wire.

## Multi-phone / multi-browser rules (new)

`BridgeRegistry` is keyed by `PairingId` (`bridge.rs:47`) with single pending-pairing and pending-unlock slots (`bridge.rs:55-70`). Rules to state in the ADR: N browsers may pair to one phone (each = one `PairingId`, one rendezvous id); one browser profile pairs to one phone at a time (device key is single-purpose); per-pairing caps are independent; the relay must accept N concurrent rendezvous ids per phone and the pending slots must not let a second pairing DoS the first.

## What is new (build list, corrected order)

0. Extract bridge policy from `baluard-daemon/handler.rs` into `baluard-runtime`, with tests. Precondition for everything below.
1. Extension transport seam at `background.js:42`, plus the WSS transport implementing the channel spec (per-session webnative handshake per Spike D: both-ephemeral X25519 + HKDF transcript + Ed25519 signatures, AES-GCM frames, counters, freshness), Chrome-SW and Firefox-event-page variants tested separately.
2. Device-key enrollment: non-extractable WebCrypto key in the extension (Spike A confirmed on both browsers), registered at pairing, pinned phone key. Persist in IndexedDB (the only storage that holds a `CryptoKey`; `chrome.storage` is JSON-only and `storage.sync` must stay off-limits for pairing material by lint).
3. Mobile bridge server (Rust, behind `baluard-uniffi`): outbound relay client (no LAN listener in v1), speaking the existing gateway payloads into the extracted runtime routes, with the pre-protobuf gate from the channel spec.
4. Pairing ceremony v2 (extension-displayed QR, phone scans and approves; proof of possession; pinning; re-pair on rotation).
5. Relay: ~500-1000 lines, bounded state (rate limits, id TTL, frame caps, squat rules), implemented as a `baluard relay` CLI subcommand (PRIMARY self-host path; ships in the existing apt/rpm/dnf trees, systemd unit template included) with the optional docker image for VPS-only users; TLS story: tailscale serve or Caddy in front, native ACME later; optional hosted instance (with the GDPR/product decision made first).
6. App settings: "Browser access: off / anywhere" (LAN mode arrives with the later LAN phase, not a v1 toggle), battery notice, pairing list with revoke + last-seen, notification rate limiting. Adaptive keepalive from Spike C: 25 s WiFi/screen-on, 60-120 s background WiFi, 60-300 s cellular; Doze = offline state; battery-optimization exemption offered with plain-language framing.
7. Tether-specific caps: `bridge.match` capped per ADR 0114 decision 5a, daily read cap, fill visibility on the phone.

## Spikes

- Spike A (RESOLVED, favorable): non-extractable device key is viable on Chrome AND Firefox MV3 in 2026, empirically verified including cross-reload IndexedDB persistence. Report: `docs/designs/spike-a-webcrypto-device-key.md`. No degradation forced on either platform; threat 3b mitigations stand as documented.
- Spike B (RESOLVED, favorable): arbitrary user-supplied `wss://` relay host works on both browsers with no manifest CSP change and no host permissions; rule adopted: manifest CSP stays free of `connect-src`/`default-src`. Report: `docs/designs/spike-b-mv3-csp-relay.md`.
- Spike C (RESOLVED, favorable with one design change): FGS type is `connectedDevice` (KDE Connect precedent, no time limit, fits the Play "Continuous Data Transfer to an External Device" use case; fallbacks: active-session framing, then `specialUse`); keepalive must be adaptive (25 s WiFi free at ~0.15 %/day net, measured; 25 s cellular unacceptable at ~5 %/h worst case, use 60-300 s); Doze disconnects even an FGS (measured), so offline state + wake reconnect is the shipped behavior, with the battery-optimization exemption as the documented overnight-availability lever. Report: `docs/designs/spike-c-fgs-latency-battery.md`.
- Spike D (RESOLVED, favorable): two-party handshake working prototype, 8/8 tests in an isolated container. Channel = "webnative" construction (X25519 triple-DH blend + HKDF transcript + Ed25519 signatures, Noise-KX-flavored), zero new JS crypto dependencies; HPKE-Auth upgrade dropped (no FS, no WebCrypto HPKE API). Server-nonce-before-any-request is the replay invariant. Reports: `docs/designs/spike-d-two-party-handshake.md`, source `docs/designs/spike-d-src/`.

## Recommendation

Ship the internet-relay tether as v1, Android first, with the mandatory foreground service; LAN pairing is NOT in v1 (follow-up phase behind its own spike). Gated on work item 0 (extraction), the channel and pairing specs above, and the hosted-relay GDPR decision. All four spikes resolved favorably (2026-11-19/20): the device-key trust model needs no fallback, the relay path needs no CSP concession, the FGS posture is `connectedDevice` with an adaptive keepalive (cellular intervals of 60-300 s and Doze-as-disconnect are the design changes Spike C forces), and the handshake is the webnative construction per Spike D (both-ephemeral X25519 + HKDF transcript + Ed25519 signatures; zero new JS dependencies; the phone's nonce must be in the transcript and echoed before any request executes). Drafted as ADR 0114 (`docs/adr/0114-browser-tethered-to-mobile.md`, Proposed 2026-11-19): amends ADR 0092 (line 9 "no application server" becomes "no server sees vault data"; line 57 "extension touches no secrets" becomes "extension holds a non-extractable device credential") and reconciles with ADR 0113 (mobile runs foreground-only there by explicit decision; the tether reverses that for the bridge, and the browser leg is the only reason a second relay exists next to iroh).

Deliberately not pursued: BLE/NFC/USB transports (platform-impossible or dev-only), FCM wake-up (latency), WebTransport (Firefox parity), iOS tether (separate project), and letting the extension decrypt the synced vault directly (violates the no-keys-in-browser invariant).
