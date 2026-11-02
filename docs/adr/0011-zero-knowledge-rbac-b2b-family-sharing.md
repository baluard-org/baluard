# ADR 0011. Zero-Knowledge RBAC for Business and Family Sharing

> Status: Accepted as the founding direction. The mechanism described below was superseded by ADR 0085, which is the authoritative design.

## Context

Business and family spaces need member invitations and revocation while keeping the space contents encrypted from the Git host. Baluard has no application server, so access control cannot rely on a central service: read scope must be enforced by keys, and write authorization must be verifiable by every client from the repository contents.

## Decision

Space access uses asymmetric envelope wrapping. A Space key is encrypted to each member's public key, a member opens it with a locally held private key, and the Git host stores only wrapped keys. Revocation rotates keys and re-encrypts, and an administrator drives both.

The founding design placed the wrapped Group Key for each member in `meta/access_list.json`, keyed by an invitee email whose public key `baluard-core` would fetch from the Git host. That file and that flow were never built in this form. The implementation instead uses these mechanics, specified in ADR 0085:

- **Identity-based membership.** Members are identified by an identity keypair, not an email address, and email addresses are never written to the repository. Contact cards are identity-signed, and trust is graded from a passphrase level through code-verified and administrator-approved. Roles above Editor require a code-verified identity, except organization onboarding, which uses administrator approval. A key server is rejected. Member records, role, display name, and trust level are plaintext in the repository, so the Git host learns who the members are by identifier and display name, not what they store.
- **Key layering.** A member never receives the Root Key or the Space Group Key. Admins open a random Space Meta Key from a Root-Key-sealed file, and members open it from a wrap sealed to their identity. Collection keys are random and wrapped per member through HPKE for each collection the member is granted, so access to one collection never exposes another. Item keys derive from the collection key with the same `baluard-item-v1` derivation used for personal entries.
- **Write authorization.** Every commit is signed, and each client verifies it against a first-match path policy resolved from the member roster, with no unsigned fallback on shared Spaces. Cryptographic read scope and signed write rights are separate controls, and provider repository permissions are a third, so none substitutes for another.
- **Revocation.** Removing a member rotates the Space Group Key and every collection key that member could open, re-wraps for the survivors, and prunes the member's grants. Rotating only the wrap would leave the old key live in the removed member's hands, so rotation is part of revocation. Revocation is eventual: a removed member can keep any bytes already pulled, and reads leave no trace in a Git repository. The earlier claim that a removed member's local entries become unreadable ciphertext does not hold, and no mechanism can recall data already copied.

Pair Spaces, family purposes and the recovery kit, collections, role templates, signed approvals, and groups are layered on this foundation in ADR 0032, ADR 0035, ADR 0043, ADR 0086, and ADR 0087.

## Consequences

The Git host stores wrapped keys and member identifiers but receives no plaintext Space contents. Revocation costs a re-encryption of the affected entries and replacement of the affected wraps. Because there is no server, enforcement depends on every client verifying signatures and policy, and a provider-level repository collaborator can still read the encrypted history. Revocation is eventual, not instantaneous, and it cannot revoke knowledge a member already had.

## References

- ADR 0085 (authoritative design), ADR 0086, ADR 0087
- `crates/baluard-core/src/vault/space_meta.rs`, `crates/baluard-core/src/vault/members.rs`
- `docs/security/threat-model.md`
