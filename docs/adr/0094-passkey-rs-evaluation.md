# ADR 0094. Passkey Rust Library Evaluation

> Status: Accepted (2026-06-12). Decided by the Phase 0.3 spike. The adoption has since been carried through the ceremony module, the daemon routes, and the mobile provider path (see ADR 0095).

## Context

Baluard acts as a WebAuthn authenticator. It must generate passkeys (registration ceremony) and serve them for authentication (assertion ceremony). The library choice had to satisfy five requirements:

1. Implement the authenticator role (the client side of WebAuthn), not the relying-party role.
2. Support ES256 (P-256 with SHA-256) at minimum.
3. Allow access to the raw private key bytes so they can be encrypted under Baluard's item key, which is what makes a passkey usable across devices through git sync.
4. Support pluggable user verification (OS biometrics, master-password re-prompt).
5. Be maintained, widely used, and not abandonware.

`webauthn-rs` implements the relying-party role used to generate and verify challenges. It does not provide an authenticator implementation. A hand-built authenticator would require ceremony logic, COSE encoding, AuthenticatorData construction, signing, and credential storage, which was estimated at about 600 lines plus interop risk.

### Candidates

| Crate | Maintainer | Role | Notes |
|-------|-----------|------|-------|
| `passkey` 0.5.x | 1Password | Client, authenticator, and credential store | Pure Rust, asynchronous, pluggable user verification. Adopted. |
| `webauthn-rs` 0.5.x | Kanidm | Relying party only | Not an authenticator. Kept for challenge generation and verification in the spike and in tests. |
| `win_webauthn` | Bitwarden | Windows platform FIDO2 | Windows-only, thin CTAP2 wrapper over the OS API. Not cross-platform, so not viable as the core ceremony. |

A hand-rolled authenticator was the fallback: it would be adopted only if `passkey` could not fit the vault model, with the specific reason documented. The two-hour spike showed it fits.

## Decision

Adopt `passkey` 0.5.x, also referred to as passkey-rs, for the WebAuthn authenticator role. Use `webauthn-rs` 0.5.x for relying-party challenge generation and verification, as the in-process counterparty that proves the ceremony interoperates.

Bridge the libraries through their serde-compatible JSON representations. The registration flow is `webauthn_rs::start_passkey_registration`, `passkey::Client::register`, then `webauthn_rs::finish_passkey_registration`. Assertion is `start_passkey_authentication`, `passkey::Client::authenticate`, `finish_passkey_authentication`.

```
webauthn-rs (relying party)  <--- JSON, serde ---> passkey (authenticator)
  challenges, verification                           ceremony, credential store, user validation
                                                              |
                                                     Baluard store
                                                     (Login cipher envelope plus item-key wrap)
```

Implement Baluard's `CredentialStore` over decrypted Login ciphers and their embedded `fido2_credentials`. Passkeys are embedded inside `LoginData` (the Bitwarden-compatible model) and there is no standalone Passkey cipher variant. New passkeys are stored as encrypted cipher envelopes, and the private key bytes are wrapped under the item key, as for every other cipher type. The private key is never stored outside the encrypted vault representation.

Implement user validation through the library's asynchronous `UserValidationMethod` interface. It exposes `check_user`, `is_presence_enabled`, and `is_verification_enabled`, which allows platform biometric or password re-prompt flows. The trait needs `async-trait`; Baluard's validation already needs asynchronous prompts for OS biometrics, so the dispatch overhead is negligible.

Use ES256 as the supported credential algorithm. The spike confirmed that registration and assertion round trips work, that the credential's private key material is available through the `Passkey` structure (its `key` field holds the COSE key pair, and serialization preserves it), and that `Aaguid::new_empty()` with attestation preference `None` supports Baluard's software authenticator model (the `none` attestation format, no hardware attestation chain).

### Findings and gaps

| Finding | Impact | Mitigation |
|---------|--------|------------|
| ES256 only, no EdDSA | Medium | ES256 is the universal WebAuthn baseline and covers the large majority of deployments. EdDSA (Ed25519) is a nice-to-have, deferred. This is a `passkey` 0.5.x limitation, not a WebAuthn limit. |
| `coset` version mismatch between the two crates' type graphs (`passkey-types` uses coset 0.3 to 0.4) | Low | Bridge through JSON so neither crate's COSE types cross the boundary. |
| `async_trait` required on the validation implementation | Low | Add `async-trait`. |
| Private key access through the `Passkey` struct | Confirmed | Baluard wraps it under the item key. |
| `public_suffix::PublicSuffixList` required as a generic parameter | Low | Transitive dependency, used for RP ID verification. |
| `Client<S, U, P, F>` takes four generic parameters | Low | S is the credential store, U the user-validation method, P the public-suffix provider, F the fetcher. All are pluggable, so storage and verification are replaceable without changing the ceremony code. |

The selected `MemoryStore` in the evaluation (a map from credential ID bytes to `Passkey`) is only a library fixture. Production storage is the vault-backed store and must not retain unencrypted credentials in a process-wide map.

### Dependencies

Workspace level: `passkey` 0.5, `webauthn-rs` 0.5, `webauthn-rs-proto` 0.5, `webauthn-rs-core` 0.5. In `baluard-core`: `async-trait` 0.1, `public-suffix` 0.1, and `url` 2. The `danger-allow-state-serialisation` feature on `webauthn-rs` is gated to dev-dependencies only, never at workspace level. The ADR originally said Baluard adds no direct `coset` dependency; see "Source versus decision text" below.

## Consequences

The authenticator ceremony uses a maintained Rust implementation already used in a production password manager, in pure Rust with no C FFI for the core ceremony. Its pluggable store and validation interfaces fit the encrypted vault and platform verification boundaries. ES256 covers the great majority of WebAuthn deployments.

The adopted implementation supports ES256 but not EdDSA. ES256 is the required baseline and EdDSA remains deferred. The dependency adds roughly fifteen transitive crates, including COSE and public-suffix support. The JSON bridge avoids coupling Baluard directly to a particular `coset` version.

Risks and their handling. 1Password deprecating the crate is judged unlikely given their investment, and the crate is open source under permissive MIT and Apache-2.0 licensing, so it can be forked. Continued use depends on keeping the `passkey` and `webauthn-rs` interfaces compatible and tracking transitive type changes, in particular a `coset` version divergence: if `passkey-types` pins a specific `coset` version, Baluard may need to match it.

Registration and assertion round trips were verified against a local relying-party flow in `crates/baluard-core/tests/passkey_spike.rs`.

### Rollout status

Done: the vault-backed `BaluardCredentialStore` and the `BaluardUserValidation` implementation (initially always-allow, with OS biometrics deferred); the daemon routes for the passkey ceremony. Open at the time of the decision and tracked in ADR 0095: browser extension integration (page script, native messaging host, conditional mediation); the mobile provider integrations; cross-device assertion.

### Source versus decision text

The code differs from the evaluation text in these ways, and the code is authoritative:

- `baluard-core` now depends directly on `coset` (workspace version 0.4) and `passkey-types`, both behind the `passkey-ceremony` feature. The credential store decodes stored COSE keys with `coset` itself, so the "no direct `coset`" statement describes the spike, not the integrated module.
- `webauthn-rs`, `webauthn-rs-proto`, and `webauthn-rs-core` are dev-dependencies of `baluard-core`. Production code uses `passkey` as the authenticator and does not link the relying-party crates. They remain the in-process relying-party oracle for tests.
- The production AAGUID is the all-zero `Aaguid::new_empty()` (`BALUARD_AAGUID`), as in the spike.
- `BaluardUserValidation::check_user` currently grants presence and a configurable verification flag (default true) without prompting. Real user verification is supplied by the caller, for example the mobile provider's per-call grant, not by this type.

## References

- `docs/adr/0095-passkey-support.md`
- `crates/baluard-core/src/crypto/webauthn/`
- `crates/baluard-core/tests/passkey_spike.rs`
