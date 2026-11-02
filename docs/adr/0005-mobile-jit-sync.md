# ADR 0005. Mobile Just-in-Time Synchronization

> Status: Accepted as a design direction. The autofill-time hook is not implemented; mobile sync runs on the triggers in ADR 0089.

## Context

Mobile operating systems may terminate background synchronization loops, leaving local vault data stale when an autofill request arrives. A mobile client has no long-lived daemon that could keep polling (ADR 0010), so freshness must be tied to events the OS does deliver.

## Decision

Before presenting a biometric challenge for a mobile browser or credential-provider autofill request, the client will perform just-in-time synchronization. Through UniFFI, `baluard-core` fetches the remote branch and checks the SHA delta. If the remote has changes, it pulls them, decrypts entries, and updates the local cache before requesting biometrics.

The ordering matters. The fetch happens before the biometric prompt so the user sees the current entry on the first attempt and does not authenticate twice. The fetch step needs no key material: `SyncEngine::fetch_locked` is an objects-only fetch with no unlock, decrypt, checkout, or state transition, and it refuses to run while the sync state machine is busy. Only the pull and decrypt steps need an unlocked vault, so they follow the biometric ceremony. Any hook of this kind must respect the autofill process constraints in ADR 0090: it runs in a separate memory-constrained process with its own vault handle, and the Argon2id master-password derivation never runs there.

## Consequences

Autofill uses current remote data when a change is available. The fetch and any required pull occur in the foreground autofill flow because mobile background synchronization cannot be relied upon, which adds network latency to the fill path and requires a bounded timeout so an offline phone fills from the local copy instead of failing.

As built, the autofill service does not call a fetch or pull. Freshness comes from the mobile sync triggers in ADR 0089: pull on unlock, sync after each change, a foreground pull behind a 10-minute guard, a mandatory flush on backgrounding, and an opt-in periodic background fetch through `fetch_locked`. The gap this record targets, a stale local copy at the moment of autofill, remains open for entries edited on another device since the last foreground pull.

## References

- ADR 0010, ADR 0089, ADR 0090
- `SyncEngine::fetch_locked` and `background_fetch` in `crates/baluard-uniffi/src/lib.rs`
