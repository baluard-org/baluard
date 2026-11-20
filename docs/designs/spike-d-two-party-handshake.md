# Spike D — Two-party handshake for the tether channel

**Status:** resolved (2026-11-20). Working prototype, 8/8 tests green, run in the `baluard-rust:1.89` podman container (not on the host, per the dogfood rule). Source preserved at `docs/designs/spike-d-src/` (standalone crate, not a workspace member). Superseded note: the original recommendation to adopt an audited Noise implementation (`snow`) was withdrawn in the ADR 0114 second review — the construction is custom (Ed25519 transcript signing has no Noise equivalent) and instead requires the dedicated third-party handshake review scoped in ADR 0114 Appendix A.

**Question:** ADR 0114 decision 3 requires a channel establishment scheme with three properties the repo's one-shot HPKE (`OpModeS::Base`) does not give: (1) mutual authentication against pinned statics, (2) forward secrecy — a later leak of BOTH static keys must not decrypt recorded handshake traffic, (3) first-frame replay defense — a captured first message replayed by a hostile relay within the timestamp window must never cause the phone to execute a request. Two candidates:

- **S1 "hpke-extra-ephemeral":** upgrade the repo's `hpke` usage to `OpModeS::Auth` (sender static authenticates) and mix a phone-contributed ephemeral X25519 + server nonce into the key schedule.
- **S2 "webnative":** no HPKE at all — raw X25519 ECDH (ephemeral + static blends, both sides), HKDF-SHA256 transcript, Ed25519 signatures. Everything maps 1:1 to WebCrypto primitives.

## Wire shape (both schemes)

```
msg1 (extension → phone):  initiator ephemeral pubkey [+ HPKE encapsulation in S1]
msg2 (phone → extension):  responder ephemeral pubkey || server nonce (32B) [|| Ed25519 sig in S2]
msg3 (first data frame, NOT executed): device identity proof || echoed nonceR
session key = HKDF(ikm = [hpke-export ||] DH(eI,eR) || DH(eI,sR) || DH(sI,eR),
                   salt = "baluard-tether-handshake-v1", info = transcript incl. nonceR)
```

The phone executes NOTHING until msg3 verifies: pinned device key matches, nonceR echo matches the fresh nonce it just sent, signature over the full transcript verifies. A replayed msg1 gets a fresh msg2 (new ephemeral + new nonce); the old msg3 fails the nonce echo; the attacker cannot produce a new valid msg3 without the device key and the ephemeral secrets.

## Results

| Test | S2 webnative | S1 hpke-extra-ephemeral |
|---|---|---|
| Happy path: keys match | ok | ok |
| Forward secrecy (both statics leaked, transcript recorded, ephemerals wiped) | ok — attack derivation ≠ real key | ok |
| Replay msg1: old msg3 rejected (nonce echo mismatch) | ok | ok |
| Impostor static / unpinned device key rejected | ok (sig) | ok (Auth open fails) |

## Findings worth keeping

1. **S2 is the recommendation.** Zero new JS dependencies: X25519 `deriveBits`, HKDF, AES-GCM, and Ed25519 are all first-class WebCrypto (Spike A confirmed non-extractable on Chrome 133/137+, Firefox 129/130+). S1 would require shipping a JS HPKE implementation (no WebCrypto HPKE API exists) — a new, audit-required crypto dependency, for no security gain over S2 (S2's Ed25519 signature + triple-DH blend covers everything HPKE Auth covers, plus gives both parties FS contributions from both ephemerals).
2. **The ADR's "HPKE OpModeS::Auth" upgrade is therefore dead** — not because it is wrong in Rust, but because it buys the wrong dependency profile for the browser side. ADR 0114 decision 3 should name the S2 construction (Noise-KX-flavored: `e, es, ee` + signed transcript) instead of HPKE Auth.
3. **Implementation trap found empirically:** building an HPKE sender identity as `PublicKey::from_bytes(sk_bytes)` silently accepts the SCALAR bytes as an x-coordinate — the Auth key schedule then embeds a "public key" that is not the real public, and the receiver never matches (silent `OpenError`, no validation error). Any production HPKE code must derive the public from the static secret, never reinterpret sk bytes as pk bytes. (This cost the spike most of its debugging time.)
4. **x25519-dalek's `EphemeralSecret` is single-use by design** (consumed by `diffie_hellman`, no serialization). The prototype models ephemerals as fresh single-use `StaticSecret`s; production must preserve the single-use guarantee — the construction is custom, not a stock Noise pattern, so it carries the dedicated third-party review scoped in ADR 0114 Appendix A, with vetted primitives (x25519-dalek, ed25519-dalek, hkdf, aes-gcm) in Rust and WebCrypto primitives on the JS side.
5. **msg3 is a data frame, not a handshake frame:** it rides the encrypted channel and the phone rejects stale ones via nonceR echo. This is what makes "replay across restarts handled by the handshake" true: every handshake is bound to a fresh server nonce, and no request executes pre-nonce.

## Recommendation

Adopt S2 ("webnative": X25519 + HKDF transcript + Ed25519, Noise-KX-flavored) for the tether channel, implemented in Rust with vetted primitives (x25519-dalek, ed25519-dalek, hkdf, aes-gcm) and in JS via WebCrypto primitives. The construction is custom and needs the third-party review listed in ADR 0114 decision 3 / Appendix A; prefer a stock Noise pattern (XX/IK with the nonce echo as an application-layer step) if that review shows equivalence. Drop the HPKE-Auth upgrade from ADR 0114 decision 3. Keep the phone-nonce-before-any-request rule as a hard invariant with a dedicated test.

## Limits

- Desktop-to-desktop Rust round trip only; the JS implementation is untested (the primitive mapping is the deliverable, a JS test harness is implementation work).
- No wire-level AEAD frame tests (sequence counters, reorder windows) — that is the channel spec's follow-on work.
- No stock Noise library fits the signed-transcript construction; the dedicated third-party handshake review (ADR 0114 Appendix A) is the compensating control, and it first checks stock-pattern equivalence.
