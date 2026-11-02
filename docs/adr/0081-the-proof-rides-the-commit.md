# ADR 0081. The Proof Rides the Commit

> Status: Accepted (2026-10-04)

## Context

Phrase enrollment on a locked clone could create a device and sign its first commit, but peers rejected the commit because signer verification reads `meta/devices.json` from the first-parent tree. The new device key existed only in its own commit tree. The deny-only gossip branch could not propagate enrollment. A clone of a vault that already contained a joined device failed for the same reason, before Root Key recovery.

## Decision

Phrase enrollment writes `meta/enrollments/<device_id>.proof`, an Ed25519 signature over canonical JSON for the device roster entry. Derive its key with HKDF(RootKey, `baluard-enroll-proof-v1`). Producing or verifying a proof requires the Root Key.

When first-parent roster signature verification fails, the pull-side verifier may validate an enrollment proof from the commit's own tree. Require that the entry is absent from the parent roster and present in the commit's `devices.json`, require the proof epoch to match the verifier's Root Key epoch, verify the Root-Key-derived proof, then verify the commit signature under the authorized device key. Use the extended roster for remaining path checks. Thread `EnrollVerifyKey` from `VaultHandle::enroll_verify_key()` into autosync activation, `sync.pull`, and direct-mode pulls. After phrase recovery, reverify fetched history with Root-Key checks.

Mirror the admission rule in staging policy for enrollment proofs, keywraps, member bindings, and `devices.json`; disarm the exception once the device is in the roster. Use three verification modes: `Root` for pulls, requiring the verifier and current epoch and disabled entirely for flipped vaults; `Structural` for clone walks without a Root Key; and `RootAllowHistorical` for post-enrollment history, falling back to structural checks for proofs from earlier epochs after rotation. Refresh autosync's cached verifier on rotation. Unthreaded pull paths such as join-poll fail closed and refuse enrollment commits.

## Consequences

An initial clone can structurally accept a forged parallel history because it has no Root Key. Phrase enrollment then performs `RootAllowHistorical` verification and rejects forged current-epoch proofs. Pulls admit only current-epoch, root-verified proofs in non-flipped vaults. A fake proof staged by a team member can reach the remote but is refused by peers. Rotation invalidates outstanding proofs, so a join racing rotation fails closed and must re-enroll. A proof authorizes only its own roster entry; replay still requires the device's private signing key for commits.

## References

- `meta/enrollments/<device_id>.proof`
- P5 staged-path policy
- `EnrollVerifyKey`
- `e2e_multi_device_join_and_sync`
- `e2e_multi_device_enrollment_proof_forgery_refused`
