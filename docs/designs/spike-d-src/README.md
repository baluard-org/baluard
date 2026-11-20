Spike D source: two-party handshake prototype for the browser-tether channel.

Standalone cargo crate. Not a workspace member (workspace members are listed
explicitly in the root Cargo.toml). Run in an isolated container:

podman run --rm -v "$PWD":/spike -w /spike --network host rust:1.89 cargo test

- src/lib.rs: scheme 2 "webnative" (X25519 ECDH + HKDF transcript + Ed25519) + shared tests
- src/hpke_auth.rs: scheme 1 "hpke-extra-ephemeral" (HPKE OpModeS::Auth upgrade)

Verdict lives in docs/designs/spike-d-two-party-handshake.md.
