# Spike E — stock Noise IK via `snow`, compiled to WASM, in MV3 background contexts (Chrome + Firefox, 2026)

**Status:** answered · **Researched:** 2026-11-20 · **Owner:** spike-e-snow-wasm
**Question (ADR 0114 Appendix A item 1):** can the tether handshake be a **stock Noise IK pattern via the Rust `snow` crate** — native on the phone, compiled to wasm32-unknown-unknown with hand-written JS glue inside a Chrome MV3 service worker and a Firefox MV3 event page — replacing the custom "webnative" construction (spike D), with pinned statics, a responder nonce-echo replay defense, and verified encrypted transport frames in both directions over WebSocket?

**Verdict: PROVEN (both browsers).** Working prototype: **8/8 native tests green**, WASM module **103,108 B raw / 39,539 B gzip** (+2.2 KB JS glue), and **five empirical browser/server runs** in which a real IK handshake completed end-to-end over WebSocket — the *native Rust server* (simulating the phone) verified the nonce echo and decrypted+matched 4 transport frames per session. Chrome MV3 service worker: **wss:// to a self-signed cert** (with `--ignore-certificate-errors`) **and** ws:// both pass. Firefox MV3 event page: passes via ws:// fallback; its wss attempt is blocked **only by self-signed-cert trust** (server saw the fatal alert `BadCertificate`), not by capability — and `certutil` is not installed on this machine, so the Firefox wss-with-trusted-cert path is a documented gap, not a failure. Source preserved at `docs/designs/spike-e-src/` (standalone workspace, inert in-tree).

---

## Wire shape and defense (what was proven)

```
IK:   <- s                       initiator pins the responder (phone) static at build time
      ...
      -> e, es, s, ss   msg1     payload = PROTOCOL_LABEL ("baluard-spike-e-v1"); responder
                                 also verifies get_remote_static() == pinned device static
      <- e, es, ss      msg2     payload = fresh 32-byte CSPRNG responder nonce
      -> frame #1       echo     payload = echoed nonce (transport counter 0);
                                 responder rejects any mismatch and never enters transport
      ...               frames   2 encrypted frames each direction (up-1, up-2 r→i; dn-1,
                                 dn-2 i→r), all AEAD-verified server-side
```

- The nonce echo is an **application-layer first-frame step**, exactly the ADR 0114 Appendix A item 6 mechanic ("phone sends a fresh nonce per attempt; msg3 must echo it; nothing executes pre-verification"). A replayed msg1 authenticates (same pinned key) but gets a **fresh** nonce; the stale echo is rejected; a duplicate echo *ciphertext* fails AEAD decryption because counter 0 is single-use (both are dedicated tests).
- WebSocket is ordered and reliable, so **a strict per-session transport nonce counter suffices — no reorder window** (documented invariant; duplicates/reorder surface as `Decrypt` errors rather than accepted frames).
- IK gives mutual authentication against pinned statics (KCI-resistant per Noise Explorer's IK analysis) and the same forward secrecy properties spike D hand-built. What stock IK does **not** give (and spike D's construction added): an Ed25519 signature over the transcript with domain separation. If device-identity attestation needs a signature, it can ride as an application payload over the IK channel (verified channel) instead of living inside the handshake — a design simplification, not a loss.

## Verdict table

| # | Sub-question | Verdict | Evidence (accessed/tested 2026-11-20) |
|---|---|---|---|
| 1 | `snow` supports IK / 25519 / ChaChaPoly / BLAKE2s and builds for wasm32-unknown-unknown | **YES** — snow 0.10.0 (latest on crates.io, released 2025-07-19); pure-Rust default resolver; 103 KB module | crates.io API (`max_stable_version 0.10.0`, `updated_at 2025-07-19`); empirical build in `baluard-rust:1.89` container (Rust 1.89.0) |
| 2 | WASM instantiates from an MV3 background with `script-src 'self' 'wasm-unsafe-eval'` | **YES, both** — Chrome MV3 SW (Chromium 156.0.8078.47) and Firefox MV3 event page (159.0): `fetch` + `WebAssembly.instantiate` from the extension origin, no streaming, no MIME issues | Empirical (BG-WASM-INSTANTIATED in SW console both browsers); MDN WebExtensions CSP (wasm from Chrome 103 / Firefox 102) |
| 3 | Full IK handshake + nonce echo over WebSocket from the SW/event page | **YES, both** — server log: `HANDSHAKE-COMPLETE` per session | Empirical (server oracle, run log preserved at `spike-e-src/run/logs/server-all-runs.log`) |
| 4 | 2 verified encrypted transport frames **each direction** | **YES, both** — `FRAME-VERIFY-OK` ×4 per session (`up-1/up-2` r→i echoed by the initiator; `dn-1/dn-2` i→r) | Empirical (`TEST-OK` 6–38 ms/session) |
| 5 | wss:// with a **self-signed** server cert | **Chrome: YES** with `--ignore-certificate-errors`; **without it: cert rejected** (`CertificateUnknown` alert server-side). **Firefox: cert-blocked** (`BadCertificate` alert); no headless cert-override flag and `certutil`/libnss3-tools not installed on this host → ws:// fallback is the Firefox path today | Empirical controls (runs C1/C3/F2 below) |
| 6 | ws:// fallback from MV3 backgrounds | **YES, both** — plain `ws://127.0.0.1:17845` passes with the same CSP (which declares **no** `default-src`/`connect-src`/`upgrade-insecure-requests`); Firefox did **not** force-upgrade ws→wss despite its default CSP containing `upgrade-insecure-requests` (declaring a custom `extension_pages` CSP replaces the default) | Empirical (runs C2, C3, F2) |
| 7 | Prescribed Firefox install method (`.xpi` in `profile/extensions` + `extensions.autoDisableScopes=0`) | **NO on release Firefox** — the unsigned MV3 xpi is silently dropped (never appears in `extensions.json`; nothing runs). Signature enforcement is locked in release builds; the pref only matters for scoped-disable, not for signing. **Adapted:** WebDriver BiDi `webExtension.install` (temporary install, the spike-b precedent) works | Empirical (F1 vs F2); Firefox `remote/webdriver-bidi/modules/root/webExtension.sys.mjs` (params: `extensionData {type:"archivePath", path}`) |
| 8 | Replay defense works end-to-end | **YES** — 3 native tests (wrong echo, stale echo vs fresh responder session, duplicate echo ciphertext); server-side oracle verifies the echo before any frame is accepted | Native tests 5–7 of 8 |
| 9 | Third-party-audit standing of this stack | **STRONG** — snow audited by Trail of Bits (funded by 1Password, June 2026, 10 findings fixed); Noise IK formally verified (Noise Explorer, eprint 2018/766); WireGuard ships IKpsk2 at scale | 1password.com/blog/strengthening-snow-for-the-open-source-community; noiseexplorer.com/patterns/IK; WireGuard whitepaper |

## Method

Everything that executes Rust ran inside podman (`localhost/baluard-rust:1.89`, Rust 1.89.0; `--network host`; cargo home on the mounted scratch dir); browsers ran on the host. Exact commands are in `spike-e-src/README.md`; abbreviated:

1. **Native ground truth** — workspace `core` (lib `snow-spike`: handshake state machines + build-time pinned keys) and `tether-responder` (tokio + tokio-tungstenite 0.30 IK responder; `wss://127.0.0.1:17844` via tokio-rustls 0.26/rustls 0.23/ring with an rcgen 0.14 self-signed cert, plus `ws://127.0.0.1:17845`). `cargo test --workspace --release` → **8/8 ok**.
2. **WASM build** — `cargo build -p snow-spike --target wasm32-unknown-unknown --release` (target added inside the throwaway container). cdylib exports `spike_alloc/spike_dealloc/spike_start/spike_read/spike_write/spike_stage` over linear-memory buffers; hand-written `glue.js` (plain `fetch` + `WebAssembly.instantiate`, no wasm-bindgen-cli).
3. **FFI smoke** — `node run/wasm-smoke.mjs` in `node:22-bookworm-slim`: export surface, `spike_start` → 114 B msg1 + stage 1, garbage msg2 → error code `-3`, alloc/dealloc sane (`SMOKE-OK`).
4. **Browser runs** — server in podman, then:
   - C1: Chromium 156 `--headless=new --load-extension=extension/chrome --ignore-certificate-errors` (wss primary).
   - C2: same with `extension/chrome-ws` (ws-only variant).
   - C3: same with `extension/chrome-nocert` and **no** cert flag (negative control).
   - F1: Firefox 159 `--headless --profile …`, xpi placed in `profile/extensions`, `extensions.autoDisableScopes=0` (prescribed method).
   - F2: Firefox 159 `--remote-debugging-port 17898` + `run/bidi-install.mjs` → `webExtension.install {extensionData:{type:"archivePath", path}}` (temporary install), event page runs.
   Pass oracle is **server-side only**: `CONNECTION-RECEIPT` (SW reached us) → `HANDSHAKE-COMPLETE` (IK + nonce echo verified) → `FRAME-VERIFY-OK` ×4 → `TEST-OK`. SW console lines (`BG-*`) captured via `--enable-logging=stderr` for Chrome (diagnostics only); Firefox FF log + `ACCEPT-ERROR` lines distinguish "never ran" from "handshake failed".

## Results

### Native tests (release profile, container, 2026-11-20): 8/8 ok

| Test | Asserts |
|---|---|
| `pinned_statics_are_consistent_pairs` | pinned pk = real `x25519(sk)` (build-time derivation checked) |
| `happy_path_handshake_and_frames_both_directions` | full IK + echo + 2 frames each direction, payloads match |
| `responder_rejects_impostor_static` | wrong initiator static → auth failure at msg1 |
| `responder_rejects_unpinned_initiator` | honest key not on pin list → `PinnedKeyMismatch` |
| `wrong_echo_rejected` | corrupted echo nonce → rejected |
| `replayed_msg1_and_stale_echo_are_rejected` | fresh responder gives fresh nonce; stale echo rejected; **responder never enters transport** |
| `replayed_echo_ciphertext_rejected_in_transport` | duplicate echo ciphertext fails AEAD (counter 0 spent) |
| `stale_msg2_rejected_by_fresh_initiator` | old msg2 fails against a new ephemeral |

### Browser/server runs (2026-11-20; oracle = server log)

| Run | Context | Endpoint reached | WASM instantiated | Handshake | Frames 4/4 | Server evidence |
|---|---|---|---|---|---|---|
| C1 | Chromium 156 MV3 **service worker** | `wss://127.0.0.1:17844` (self-signed + `--ignore-certificate-errors`) | ✔ | ✔ | ✔ | `TEST-OK endpoint=wss elapsed_ms=6`; client: `BG-USING wss… failures []` |
| C2 | Chromium 156 MV3 SW (ws-only build) | `ws://127.0.0.1:17845` | ✔ | ✔ | ✔ | `TEST-OK endpoint=ws elapsed_ms=38` |
| C3 | Chromium 156 MV3 SW, **no cert flag** | wss **fails** → ws fallback | ✔ | ✔ | ✔ | `ACCEPT-ERROR endpoint=wss reason=received fatal alert: CertificateUnknown` + `TEST-OK endpoint=ws elapsed_ms=10` |
| F1 | Firefox 159 MV3 event page, **xpi-in-profile (prescribed)** | — | ✘ **extension never loaded** | — | — | absent from `extensions.json` (release signature enforcement); no receipt |
| F2 | Firefox 159 MV3 event page, **BiDi temporary install** | wss **fails** (cert) → ws fallback | ✔ | ✔ | ✔ | `ACCEPT-ERROR endpoint=wss reason=received fatal alert: BadCertificate` + `TEST-OK endpoint=ws elapsed_ms=5` |

Chrome never fell back in C1 (wss succeeded first). F2's wss attempt demonstrably **reached the server** (the alert is server-side evidence), so the Firefox wss gap is purely certificate trust.

### Bundle sizes (release profile: `opt-level="z"`, `lto`, `strip`, `panic="abort"`)

| Artifact | Raw | gzip -9 |
|---|---|---|
| `snow_spike.wasm` (IK initiator, pinned statics baked in) | **103,108 B** | **39,539 B** |
| `glue.js` (instantiate + FFI marshalling + RNG hook) | 2,777 B | 1,230 B |
| `background.js` (state machine, both browsers) | 4,554 B | 1,879 B |
| Firefox xpi (manifest + glue + background + wasm) | 43,447 B | — |
| (comparison: with getrandom's `wasm_js` backend the wasm was 120,301 B / 43,876 B — wasm-bindgen runtime residue) | | |
| `tether-responder` native binary (phone side, not browser-bound) | 1,807,152 B | — |

**Backends/features compiled into the wasm:** snow 0.10.0 `default-features = false` + `default-resolver`, `use-curve25519`, `use-chacha20poly1305`, `use-blake2`, `use-getrandom` → pure-Rust resolver (curve25519-dalek 4.1.3, chacha20poly1305 0.10.1, blake2 0.10.6) + getrandom 0.3.4 with the **custom** backend. `ring` is **not** in the wasm dependency graph (`cargo tree` verified).

## Findings worth keeping (implementation traps, found empirically)

1. **snow 0.10.0's default features drag `ring` into every build**: the `std` feature list contains `ring/std`, which activates the optional `ring` dependency — and ring's getrandom 0.2 (a) does not compile for wasm32-unknown-unknown without its own `js` feature and (b) itself needs the wasm-bindgen runtime. Use `default-features = false` + explicit `use-*` features for a clean pure-Rust wasm graph.
2. **getrandom 0.3's `wasm_js` backend requires the wasm-bindgen JS runtime** (its `catch`/`JsValue` crypto import emits `__wbindgen_placeholder__` / `__wbindgen_externref_xform__` imports and ~90 describe stubs — unusable with "plain extern C exports"). The **`custom` backend** is the clean route: `--cfg getrandom_backend="custom"`, then define `#[no_mangle] unsafe extern "Rust" fn __getrandom_v03_custom(dest, len)` (the `no_mangle` is mandatory — without it the symbol stays an unresolved import) forwarding to **one** plain `env` import that glue.js backs with chunked `crypto.getRandomValues`. CSP-safe (no eval), works in SW and event page.
3. **snow 0.10's audited API differs from 0.9-era muscle memory**: `Builder::local_private_key`/`remote_public_key` return `Result<Self, _>` (chain with `?`), `write_message`/`read_message` return `usize`, and handshake completion is `is_handshake_finished()` (no token tuples).
4. **x25519-dalek `StaticSecret::from(sk).to_bytes()` returns the secret bytes, not the public key** — build-time key derivation must use `PublicKey::from(&StaticSecret)`. This bit the spike exactly like spike D finding 3 predicted (reinterpret-sk-as-pk class), and the pinned-keys consistency test caught it only after the helper itself was fixed to not share the bug.
5. **Firefox release builds silently ignore unsigned xpis placed in `profile/extensions`** — they never appear in `extensions.json`, regardless of `extensions.autoDisableScopes=0`. WebDriver BiDi `webExtension.install` (temporary install) is the headless-compatible substitute; its params shape is `extensionData {type: "archivePath"|"path"|"base64", …}` (Firefox `WebExtension.sys.mjs`).
6. **MV3 CSP decision (documented)**: declare exactly `extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"`. **No `default-src`** (it is the fallback directive for connect-src; spike-b proved a bare `default-src 'self'` blocks background WebSockets), **no `connect-src`** (unnecessary — WebSocket is unrestricted without it — and it cannot express a per-user host cleanly), **no `upgrade-insecure-requests`** (it would force-upgrade the ws:// fallback to wss://; empirically, Firefox MV3 accepted plain `ws://127.0.0.1` under this custom CSP, i.e. declaring a CSP replaces Firefox's UIR-carrying default rather than adding to it).
7. **A naive TLS accept loop kills the whole fixture server on the first client cert-reject** (`acceptor.accept()` returns `Err` on the fatal alert; a `?`-propagating listener task then ends the runtime). Log-and-continue per accept is required — and the resulting `ACCEPT-ERROR reason=received fatal alert: …` lines turned out to be the best evidence that Firefox's wss attempt reached the server and died on trust alone.
8. **Server TLS stack pitfalls**: `tokio-rustls`'s default feature enables rustls's `aws-lc-rs` provider, which combined with a ring-enabled rustls leaves two providers and panics at runtime ("could not automatically determine the process-level CryptoProvider") — pin `default-features = false` and select exactly one provider (ring keeps the Debian container build cmake-free).

## Limits

- **Firefox wss was not proven** — only that its failure is certificate trust (`BadCertificate` alert at the server). Production needs a trusted cert (system/user CA or Let's Encrypt); `certutil`/libnss3-tools is not installed on this host so the profile-cert9.db route was not exercised. Chrome wss+`--ignore-certificate-errors` is a dev-only convenience.
- **Single session per wasm module** (thread-local initiator state, no SW restart/re-hydration test). Chrome SW idle-termination (~30 s) and Firefox event-page unload (~30 s) lifetime behaviors were not re-tested here (spike-b covered the WebSocket-keepalive mechanics); the tether client must re-run `spike_start` per wake, which is cheap (~1 ms of work, no device-state loss since statics are pinned constants).
- **No PSK variant** (WireGuard ships IKpsk2; snow supports `psk(n, …)` — a one-line addition, untested here).
- **Transcript binding is minimal**: msg1 carries a constant protocol label; ADR Appendix A items 2–3 (version/pairing-ID binding, domain-separated Ed25519 transcript signature) are application-layer work above this spike; a device-identity signature can be an authenticated IK payload instead of a handshake element.
- **ADR Appendix A item 6's full semantics** (10 s nonce expiry, single-use nonce state store, constant-time compare) are application state, not spike code — the spike proves the *mechanism* (fresh nonce per attempt, echo-or-reject, nothing executes pre-verification).
- **Zeroization and panic-path hygiene** of the WASM side were not audited (native snow uses vetted primitives; a production review should check linear-memory scratch handling).
- Latency measured here (6–38 ms/session on loopback) is not a meaningful network benchmark.

## Recommendation (ADR 0114 Appendix A item 1)

**Adopt stock Noise IK via snow: native snow on the phone, snow compiled to wasm32-unknown-unknown in the browser extension, WebSocket transport, responder nonce echo as an application-layer first frame.** This answers item 1's equivalence question in the affirmative and lets the custom webnative handshake code be deleted: IK gives the same mutual authentication against pinned statics and forward secrecy that spike D hand-rolled, with better audit standing than any custom construction — snow is Trail-of-Bits audited (June 2026, 10 findings fixed, 1Password-funded), Noise IK is formally verified (Noise Explorer, eprint 2018/766), and IKpsk2 ships at WireGuard scale. Practical shape proven by this spike: ~103 KB wasm + ~2 KB glue in the browser (39.5 KB + 1.2 KB gzipped over the wire), one `crypto.getRandomValues` hook, CSP satisfied by `script-src 'self' 'wasm-unsafe-eval'`, wss for Chrome dev/production-trusted certs and ws-loopback as the tested fallback. Design notes to carry forward: pin the PSK upgrade (IKpsk2) as a follow-up decision; keep the pinned-key derivation in one audited code path (`PublicKey::from(&StaticSecret)`, never sk-as-pk); keep the strict transport counter (ordered WebSocket ⇒ no reorder window) as a stated invariant; and specify the Firefox wss trust story (trusted CA) since headless Firefox cannot bypass cert errors. **Fallback if adoption breaks:** pure-JS `@chainsafe/libp2p-noise` (maintains Noise in JS, audited lineage via libp2p) as the browser-side implementation, or keep the spike-D webnative construction with the dedicated third-party handshake review — but nothing observed here suggests either will be needed.

## Source list (accessed 2026-11-20 unless noted)

- https://crates.io/api/v1/crates/snow — snow `max_stable_version 0.10.0`, `updated_at 2025-07-19` (crates.io API)
- https://crates.io/api/v1/crates/tokio-tungstenite (0.30.0), /tokio-rustls (0.26.6), /rcgen (0.14.10) — fixture versions
- https://www.1password.com/blog/strengthening-snow-for-the-open-source-community — Trail of Bits audit of snow, June 2026, 10 findings fixed (verified context, 2026-11-20)
- https://noiseexplorer.com/patterns/IK — Noise IK formally verified via Noise Explorer (eprint 2018/766) (verified context, 2026-11-20)
- WireGuard protocol whitepaper (IKpsk2 in production) — verified context
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_Security_Policy — MV3 CSP defaults; `wasm-unsafe-eval` (WebAssembly from Chrome 103 / Firefox 102) (verified context, checked 2026-11-20)
- https://github.com/mozilla-firefox/firefox/blob/main/remote/webdriver-bidi/modules/root/webExtension.sys.mjs — BiDi `webExtension.install` params (`extensionData`/`archivePath`), read 2026-11-20
- getrandom 0.3.4 README + source (vendored in the cargo cache during the spike) — `wasm_js` backend requires wasm-bindgen; custom backend (`#[no_mangle] unsafe extern "Rust" fn __getrandom_v03_custom`)
- Empirical artifacts: this spike's own runs, preserved at `docs/designs/spike-e-src/` (source, `run/logs/server-all-runs.log` oracle transcript, per-browser console extracts, xpi, cert PEM)
