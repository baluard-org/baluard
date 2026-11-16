# ADR 0111. The Agent Serves Imported RSA Keys

> Status: Accepted (2026-11-16)

## Context

Users carry legacy RSA keys: servers with `authorized_keys` entries pinned to
`id_rsa`, devices that never moved off RSA, and private keys stored in the
pre-2018 PKCS#1 PEM container. The daemon's generators only produce Ed25519
and ECDSA P-256 (ADR 0014), and the agent matched that served set (ADR 0110)
after the L7 fix removed RSA 4096 over RUSTSEC-2023-0071, the Marvin Attack
timing side channel in the `rsa` crate.

That advisory remains open upstream: no released `rsa` version carries a fix,
including the 0.10 release candidates. The exclusion therefore cannot end with
a dependency update; supporting the keys is an explicit acceptance of the
residual risk, taken because the user-facing need is real and the served-path
gates keep the exposure bounded.

## Decision

The agent serves imported RSA keys for signing:

- `ssh_agent_keys::load_material` accepts `Algorithm::Rsa` alongside Ed25519
  and ECDSA P-256. Containers: OpenSSH format first, then legacy PKCS#1 PEM
  (`BEGIN RSA PRIVATE KEY`) and PKCS#8 PEM (`BEGIN PRIVATE KEY`) through the
  `rsa` crate's decoders.
- Signing honors the sign-request flags (RFC 8332): `ssh-agent` flag 2 signs
  with rsa-sha2-256, flag 4 with rsa-sha2-512, and neither with legacy
  `ssh-rsa` (SHA-1) so servers predating RFC 8332 keep authenticating.
- Generation is unchanged: the daemon still generates only Ed25519 and
  ECDSA P-256. RSA keys enter through import or paste, never through
  `ssh.generate_key`.
- Every existing gate applies unchanged: master switch, per-key
  `serve_via_agent` opt-in, per-sign approval unless auto-approve is on,
  audit records, uid-checked 0600 socket. Ed25519 remains the recommended
  default in the UI.

## Consequences

The `rsa` crate (0.10 rc line, pulled by `ssh-key`'s `rsa` feature) returns to
the daemon dependency tree with its documented, unpatched Marvin timing side
channel in PKCS#1 v1.5 signing. Exploitation requires observing the timing of
many signing operations through the agent socket; an attacker with that
access can already request arbitrary signatures, so the marginal escalation
is offline key recovery, and default per-sign approval keeps request volume
human-paced. `cargo audit` will keep reporting the open advisory: that report
is expected and accepted here, not silently suppressed.

Servers and clients negotiate: modern clients use the SHA-2 variants, and the
SHA-1 fallback exists solely for old servers. SHA-1 SSH signatures remain
weaker authentication material; the UI copy should keep recommending Ed25519
for new keys.

## References

- `crates/baluard-daemon/src/ssh_agent_keys.rs`
- ADR 0014 (generation; RSA generation stays out)
- ADR 0110 (agent serve gates)
- RUSTSEC-2023-0071
