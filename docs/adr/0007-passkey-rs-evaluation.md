# ADR 0007: passkey-rs Evaluation (Phase 0.3 Spike)

**Date:** 2026-06-12
**Status:** Accepted — adopt `passkey-rs` 0.5.x as Baluard's WebAuthn authenticator library

## Context

Baluard needs to act as a WebAuthn authenticator: generate passkeys (registration ceremony) and serve them for authentication (assertion ceremony). We need a Rust crate that:

1. Implements the CTAP2 authenticator role (client side of WebAuthn)
2. Supports ES256 (P-256 + SHA-256) at minimum
3. Allows access to raw private key bytes for encrypting under Baluard's item key (cross-device sync)
4. Supports pluggable user verification (OS biometrics, master password re-prompt)
5. Maintained, well-audited, not abandonware

### Candidates

| Crate | Maintainer | Role | Notes |
|-------|-----------|------|-------|
| `passkey` 0.5.x | 1Password | Full client+authenticator+store | Pure Rust, async, pluggable UV |
| `webauthn-rs` 0.5.x | Kanidm | RP-side only | We use this for challenge generation/verification |
| `win_webauthn` | Bitwarden | Windows platform FIDO2 | Windows-only, thin CTAP2 wrapper |

## Decision

Adopt `passkey` 0.5.x as the authenticator library. Use `webauthn-rs` 0.5.x as the relying-party side (challenge generation + verification).

## Spike Results

**Test file:** `crates/baluard-core/tests/passkey_spike.rs`
**Outcome:** 2/2 tests pass (registration + assertion round-trip through webauthn-rs)

### What Works

1. **Registration ceremony**: `webauthn_rs::start_passkey_registration()` → `passkey::Client::register()` → `webauthn_rs::finish_passkey_registration()` ✅
2. **Assertion ceremony**: `webauthn_rs::start_passkey_authentication()` → `passkey::Client::authenticate()` → `webauthn_rs::finish_passkey_authentication()` ✅
3. **JSON bridge**: Both crates use serde-compatible types. `serde_json::to_value()` / `from_value()` bridges between them cleanly.
4. **UserValidationMethod**: Async trait with `check_user()`, `is_presence_enabled()`, `is_verification_enabled()`. Baluard will implement this with OS biometric gates.
5. **MemoryStore**: `HashMap<Vec<u8>, Passkey>` implements `CredentialStore`. Baluard will implement our own store backed by encrypted cipher envelopes.
6. **Self-attestation**: `Aaguid::new_empty()` + `AttestationConveyancePreference::None` works for our "none" format (no hardware attestation chain).

### Findings & Gaps

| Finding | Impact | Mitigation |
|---------|--------|------------|
| ES256 only (no EdDSA) | Medium | ES256 is the universal baseline. EdDSA (Ed25519) is nice-to-have; all browsers/platforms support ES256. Defer to Phase 5+ |
| `coset` version mismatch | Low | passkey-types uses coset 0.3-0.4. We avoid direct coset usage; JSON bridge handles the alg field |
| `async_trait` required on UV impl | Low | Add `async-trait` dep. Baluard's UV impl already needs async (OS biometric prompts) |
| Private key access via `Passkey` struct | ✅ Confirmed | `Passkey.key` field contains the COSE key pair. Serialization preserves it. Baluard wraps this under the item key |
| `public_suffix::PublicSuffixList` needed as generic param | Low | Comes as transitive dep. Used for RP ID verification |
| `Client<S, U, P, F>` takes 4 generic params | Low | S=store, U=UV method, P=public suffix provider, F=fetcher. All pluggable |

### Integration Architecture

```
┌─────────────┐     JSON/serde      ┌──────────────┐
│  webauthn-rs │ ◄──────────────────► │   passkey-rs  │
│  (RP role)   │                      │  (Authenticator)│
│              │                      │               │
│ Challenges,  │                      │ Ceremony,     │
│ Verification │                      │ Credential    │
│              │                      │ Store, UV     │
└─────────────┘                      └───────┬───────┘
                                             │
                                     ┌───────▼───────┐
                                     │ Baluard Store  │
                                     │ (CipherItem +  │
                                     │  ItemKey wrap) │
                                     └───────────────┘
```

Baluard's `CredentialStore` impl will:
- Look up passkeys from decrypted `CipherKind::Passkey` entries
- Store new passkeys as encrypted cipher envelopes
- Private key bytes wrapped under the item key (same as all other cipher types)

## Dependencies Added

```toml
# Cargo.toml (workspace)
passkey = "0.5"
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"
webauthn-rs-core = "0.5"

# baluard-core/Cargo.toml (dev-deps for spike)
passkey = { workspace = true }
webauthn-rs = { workspace = true }
webauthn-rs-proto = { workspace = true }
url = "2"
public-suffix = "0.1"
async-trait = "0.1"
```

## Consequences

### Positive
- Battle-tested by 1Password's production deployment
- Pure Rust, no C FFI needed for the core ceremony
- Pluggable store and UV method fit Baluard's architecture
- ES256 covers >99% of WebAuthn deployments
- Active maintenance (1Password team, MIT/Apache-2.0 dual licensed)

### Negative
- No EdDSA support (passkey-rs limitation, not WebAuthn spec)
- Additional ~15 crate transitive deps (coset, public-suffix, etc.)
- `async_trait` overhead on UV method dispatch (negligible for our use case)

### Risks
- **1Password deprecation**: Unlikely given their investment, but crate is open source under permissive license
- **coset version divergence**: Monitor; if passkey-types pins to a specific coset version, we may need to match

## Next Steps

- [ ] Phase 0.4: Implement `BaluardCredentialStore` (bridges passkey store trait to cipher envelopes)
- [ ] Phase 0.4: Implement `BaluardUserValidation` (OS biometrics + master password re-prompt)
- [ ] Phase 1: Wire daemon IPC routes for passkey ceremony
- [ ] Phase 1: Desktop UI for passkey creation and autofill
