# ADR 0014. SSH Key Generation

> Status: Accepted (completed 2026-06-09)

## Context

SSH key generation must keep raw private key material within the daemon. Supported key types must cover modern use and P-256 FIPS compliance without retaining a vulnerable RSA dependency.

## Decision

The daemon generates SSH keypairs with the `ssh-key` crate and the system CSPRNG (`OsRng`). The `ssh.generate_key` command accepts `{type: "ed25519"|"ecdsa256"}` and returns JSON containing `public_key`, `fingerprint` (SHA-256), and `private_key`, all as formatted OpenSSH strings. An unknown type is rejected.

The security boundary is precise. The seed and the raw key objects stay inside the daemon process and are never returned. What crosses IPC is only the formatted OpenSSH output, and the generation call does not persist it. The unencrypted OpenSSH private key text is returned once so that the user can save it, or so that it can be stored as an entry (the vault encrypts it at rest like any other entry field). The desktop therefore keeps the private key behind a disclosure and offers an explicit copy action.

Key types:

- Ed25519 is the default and recommended type. The keypair is built from a 256-bit seed drawn from `OsRng`, through `ed25519-dalek` (`Ed25519Keypair::from_seed`).
- ECDSA P-256 is offered for FIPS compliance and uses the `ssh-key` crate with the NIST P-256 curve.
- RSA 4096 was offered originally for legacy compatibility and was removed in the L7 fix. The `rsa` crate has RUSTSEC-2023-0071, a Marvin Attack timing side channel with no upstream fix, and it is pulled in transitively by the `ssh-key` crate's `rsa` feature. Ed25519 and ECDSA P-256 cover modern needs. Any future RSA support depends on an upstream fix.

The project uses `rand` 0.8 with `rand_core` 0.6, while `ssh-key` 0.7 requires `rand_core` 0.10. Ed25519 avoids the mismatch by constructing the keypair directly from seed bytes. ECDSA generation uses a small `Adapter` type that implements `ssh_key::rand_core::TryRng` and `TryCryptoRng` by delegating to `rand::rngs::OsRng`, with `Infallible` as the error type because `OsRng` is treated as non-failing.

The desktop uses `SshKeyGenerator.jsx` with a type selector, a generation button with a spinner, copy actions for the public key and fingerprint, and the private key behind a warning disclosure (a `<details>` element).

## Consequences

Raw key material is created and dropped inside the daemon. Ed25519 and ECDSA P-256 are supported; RSA 4096 is unavailable because of the unresolved vulnerability, and users who need RSA must generate it elsewhere. The RNG adapter bridges the project's `rand` version and the version required by `ssh-key`, and it must be revisited when either dependency moves. The formatted private key does reach the client, so the client treats it as sensitive and shows it only behind the disclosure.

The original record stated that private key material never crosses the IPC boundary. Per the source code, the unencrypted OpenSSH private key string is part of the response, so this ADR states the narrower guarantee above.

## References

- `ssh.generate_key`
- `SshKeyGenerator.jsx`
- RUSTSEC-2023-0071
