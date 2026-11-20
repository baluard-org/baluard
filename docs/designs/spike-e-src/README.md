# Spike E — stock Noise IK (snow) as a WASM browser-tether initiator

Isolated empirical spike for ADR 0114 Appendix A item 1 ("adopt stock Noise IK via
snow?"). Full report: `docs/designs/spike-e-snow-wasm.md` (this directory is the
preserved scratch project, not a workspace member — inert in-tree).

**Verdict (short): PROVEN.** The same `Noise_IK_25519_ChaChaPoly_BLAKE2s`
handshake — native responder (tokio + tokio-tungstenite over TLS WebSocket) and
the `snow` crate compiled to WASM with hand-written JS glue — completed a full
IK handshake (pinned statics, responder nonce-echo replay defense) plus 2
verified encrypted transport frames in each direction from both a Chrome MV3
service worker (wss and ws) and a Firefox MV3 event page (ws; wss only blocked
by self-signed-cert trust, not by capability). 8/8 native tests green.

## Layout

```
Cargo.toml            workspace (core, tether-resolver)
.cargo/config.toml    wasm32 rustflags: --cfg getrandom_backend="custom"
core/                 "snow-spike" lib+cdylib: handshake logic, pinned keys
                      (build.rs, deterministic), wasm FFI exports, 8 tests
tether-responder/     "tether-responder" bin: tokio + tokio-tungstenite IK
                      responder; wss://127.0.0.1:17844 (rustls, self-signed
                      rcgen cert) + ws://127.0.0.1:17845 fallback listener
extension/            MV3 fixtures: chrome/ (service worker, canonical wasm
                      artifact), firefox/ (event page), chrome-ws/ (ws-only
                      variant), chrome-nocert/ (no --ignore-certificate-errors
                      control). Build step copies the .wasm into each dir:
                      cp target/wasm32-unknown-unknown/release/snow_spike.wasm \
                        extension/{chrome,chrome-ws,chrome-nocert,firefox}/
run/                  logs, sizes, generated cert, xpi, helper scripts
```

## Rebuild + run (all Rust execution inside podman, never on the host)

```bash
# native tests (8/8 green)
podman run --rm --network host -v /var/tmp/spike-e:/work:Z \
  -e CARGO_HOME=/work/.cargo-home-spike localhost/baluard-rust:1.89 \
  bash -c 'cd /work && cargo test --workspace --release'

# wasm build (target install happens in the throwaway container)
podman run --rm --network host -v /var/tmp/spike-e:/work:Z \
  -e CARGO_HOME=/work/.cargo-home-spike localhost/baluard-rust:1.89 \
  bash -c 'rustup target add wasm32-unknown-unknown && \
           cd /work && cargo build -p snow-spike --target wasm32-unknown-unknown --release'

# server (phone side)
podman run --rm --name spike-e-server --network host \
  -v /var/tmp/spike-e:/work:Z -w /work localhost/baluard-rust:1.89 \
  ./target/release/tether-responder

# wasm FFI smoke test (plain Node, no wasm-bindgen runtime)
podman run --rm --network host -v /var/tmp/spike-e:/work:Z \
  docker.io/library/node:22-bookworm-slim node /work/run/wasm-smoke.mjs
```

Browsers ran on the host (2026-11-20): Chromium 156.0.8078.47 via
`--headless=new --load-extension=extension/chrome [--ignore-certificate-errors]`;
Firefox 159.0 via WebDriver BiDi `webExtension.install` (temporary install,
`run/bidi-install.mjs`) — the prescribed xpi-in-profile install is blocked by
release-Firefox signature enforcement (empirically confirmed, see report).

## Key implementation notes

- snow 0.10.0 (latest on crates.io, 2025-07-19) with `default-features = false`:
  its `std` feature enables `ring/std`, which drags ring (+ getrandom 0.2,
  which does not compile for wasm32-unknown-unknown) into the wasm graph.
  Verified via `cargo tree`.
- WASM randomness: getrandom 0.3 `custom` backend (`--cfg
  getrandom_backend="custom"`) + one `#[no_mangle] unsafe extern "Rust" fn
  __getrandom_v03_custom` forwarding to a single plain `env` import
  (`spike_js_random_fill`) backed by `crypto.getRandomValues` in glue.js.
  This avoids the wasm-bindgen runtime that the `wasm_js` backend requires
  (its `catch`/JsValue ABI imports ~90 `__wbindgen_*` glue functions).
- snow 0.10 audited API: `Builder::local_private_key/remote_public_key` return
  `Result<Self, _>`; `write_message/read_message` return `usize`; handshake
  completion via `is_handshake_finished()`.
- Sizes (release: opt-level=z, lto, strip, panic=abort):
  `snow_spike.wasm` 103,108 B raw / 39,539 B gzip-9; glue.js 2,777 / 1,230;
  background.js 4,554 / 1,879; xpi (wasm+glue+bg+manifest) 43,447 B.
