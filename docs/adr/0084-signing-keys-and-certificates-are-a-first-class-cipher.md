# ADR 0084. Signing Keys and Certificates Are a First-Class Cipher

> Status: Accepted (2026-11-01)

## Context

Notes do not provide expiry warnings, fingerprint and public-key copy controls, or appropriate field handling for private keys. Release signing material was stored as attachments inside a consumer password-manager login, demonstrating the need to model long-lived signing identities. A signing key and its certificate chain form one identity; SSH keys have distinct per-use authentication workflows and fingerprint conventions.

## Decision

Add one `SigningKey` cipher variant, displayed as "Signing keys & certificates," with optional key and certificate halves. Keep `SshKey` separate. Store `private_key` with password-equivalent handling: omit it from `vault.list` metadata, include it in full reads and `list_full`, encrypt it under the item key, zeroize it on drop, and refuse it through the bridge's Decision 7 fill allowlist. Treat the passphrase with the same protections. Store `public_key`, leaf-first `certificates`, `key_format` (`pem`, base64 for binary formats such as PKCS#12 or raw material, and `openpgp`), `expires_at`, issuer, subject, and fingerprint. Normalize DER to PEM on ingest. Use the existing serde enum with tag `signingKey`; the pre-1.0 wire format may change.

Parse certificate metadata in a dedicated daemon module. Reuse the total DER TLV primitive from `attest.rs`, with separate PEM decoding, name and time parsing, and SHA-256 fingerprinting. Apply a size cap and totality property test. Do not extend `parse_cert`, which remains the FIDO attestation verifier. Fill subject, issuer, dates, and fingerprint from the leaf certificate, using user-entered values as fallback. Support Ed25519 and Ed448 names and dates as well as RSA and EC. Store OpenPGP keys as armor with user-entered expiry; do not add an OpenPGP parser. Defer SAN parsing because subject CN provides domain association.

Show expiry badges on list rows and entry detail while the vault is open. Store `expires_at` as optional Unix seconds on the cipher and mirror it in the list index. Display the earliest expiry across the certificate chain. Do not add background checks or scheduling. Target long-lived purchased wildcard, corporate, mTLS client, customer CA, code-signing, and PGP material; do not use the type for frequently renewed ACME certificates. Store ACME account and DNS provider credentials as Logins. Sharing retains the password trust model: anyone who can open the entry can copy the private key. Per-field ACLs are out of scope for 1.0.

Do not serve signing operations through the daemon; that is a separate plan. Ship storage, display, copy, and expiry badges with the entry type. Land these 0.1.0 invariants now: rotation rewraps unparseable cipher bytes when they decrypt under the current key and all attachments decrypt; entries stranded by earlier rotations remain stranded because their old Root Key is gone, and phrase recovery restores them. Make bridge reads an allowlist of ID, name, type, username, password, and TOTP-presence flag, refusing non-Login kinds. Keep bridge writes within Decision 7: capture adds may use the full Login shape, while edits accept username, password, and TOTP seed, preserve URI and passkey lists by resend-equality, and update no root field beyond the note. Reject non-Login items when requesting agent access.

## Consequences

Structured fields enable expiry, fingerprint, and copy surfaces without stronger encryption than notes, which use the same envelope. The private key remains readable to anyone with entry access. Per-field access control and daemon signing operations are deferred. The 0.2 implementation must add certificate-aware conflict merging and private-key drop zeroization; include the passphrase in sensitive-key masking and mobile search exclusion; implement explicit `Drop` zeroization; add flat fields to `cipher_to_json`; choose a Bitwarden export type or lossy downgrade; bump backup-container version; and recompute parsed issuer, subject, fingerprint, and expiry on save, using user values only as fallback. Bitwarden-format import cannot carry these entries because attachments are dropped, so manual re-entry is required. Renewal history must be capped and zeroized. Client work includes desktop schema and detail gating, filters, en/es/pt locales, mobile strings, and CLI display.

## References

- Decision 7 bridge allowlist
- `attest.rs`
- `parse_cert`
- Backup container format
