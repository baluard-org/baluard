# Security policy

Baluard is a local-first password manager with no server. This file describes how to report a vulnerability and what happens after you do. The technical detail lives in the [security white paper](docs/security/security-white-paper.md) and the threat model it links to.

## Supported versions

Security fixes land on the latest release line only. Use the newest 0.1.x release before reporting; older builds will not receive patches.

## How to report

Please use GitHub's private security advisory on this repository. If you cannot use it, open a normal issue saying only that you have something to report privately and we will arrange a channel.

Include the Baluard version, your platform, and steps to reproduce. A proof of concept is welcome; secrets from a real vault are not, ever.

## What to expect

- Acknowledgement within five business days.
- A fix or a plain disposition, coordinated with you before public disclosure.
- Credit in the release notes if you want it, and silence if you do not.

## In scope

- The vault file format and its cryptography (envelopes, padding, key hierarchy, KDF).
- The daemon IPC surface: socket permissions, peer verification, session tokens, rate limiting.
- Hardware key sealing (FIDO2 hmac-secret seals, platform chip seals, attestation).
- Signed sync: commit signatures, roster verification, conflict handling.
- The browser bridge: pairing, the action allowlist, origin binding, read caps.
- Agent credential grants: approval, peer binding, TTL, output scrubbing, audit.
- The updater and release signing chain.
- The desktop, CLI, mobile, and extension clients where they enforce any of the above.

## Out of scope

- Attacks that require malware already running as your user on an unlocked session, unless they defeat a boundary the white paper claims. Same-user compromise sits below every client-side line, including ours.
- Social engineering of a person.
- TLS breakage or misconfiguration of a git host you chose.
- Vulnerabilities in third-party dependencies that are not reachable through Baluard. Report those upstream; a note to us is still appreciated.

## Limitations

One maintainer reviews reports, and there is no bug bounty. The white paper's assurance section states plainly what independent verification has and has not happened, and this file will be updated as that changes.
