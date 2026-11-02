# ADR 0100. Legacy Contact

> Status: Accepted (2026-10-26). Shipped for 1.0 on desktop (core module, deploy keys, owner operations, daemon routes and CLI, owner interface, contact read-only view, kit letter and manual, and an end-to-end "owner dies" test). Deferred past 1.0: mobile owner setup and contact flow, and the deploy-key last-used banner (GitLab reports the date; GitHub and Codeberg do not).

## Context

An owner may die or become incapacitated before sharing the secrets a partner or family member needs. The real-world nomination is "my sister should be able to get in if something happens to me", where the contact may live on another continent, may have no technical skill, and may not know she was nominated. Existing recovery paths (master password, recovery phrase) require the owner to arrange a secret hand-off in advance, and a recovery phrase alone grants nothing because the vault's git remote is private. The contact may have no Baluard account, no forge account, and no technical skill. The system has no server backend, so the git remote is the only communication channel.

No timestamp held by the contact can enforce a wait against a modified client, because a modified client rewinds anything it holds. The wait is therefore a social control enforced by the stock client and not cryptographic denial, and the feature must state that limitation plainly. A deploy key and repository access provide revocation and not an independent second factor, so the kit passphrase is the single secret protecting a leaked kit.

### Trust model

The contact can open the vault whenever the silence rule is met. The wait protects against mistakes and casual misuse and not against a determined contact with a modified client; documentation and interface say so. The repository holds only the Root Key encrypted under an escrow key `EK`, which lives only in the kit and on owner devices, so a repository leak alone is useless. Root Key rotation rewrites only the repository blob, so the kit never goes stale. Real denial is rotation: removing the deploy key or writing a Closed record stops only the stock client, because the contact may already hold everything. A denial that matters rotates the Root Key and makes the old epoch unreadable, while data already read cannot be revoked. Setup copy states that anyone who obtains the kit and guesses its passphrase can open the vault.

### Rejected designs

The earlier time-gated emergency design (the grantee requests, waits a delay, then recovers) was rejected and deleted: the grantee holds the file and can rewind any stored timestamp, and demoting it to owner-approved access fails the dead-owner case entirely. A forge issue as the request channel was cut because it requires the contact to hold a forge account or a write credential. Scoped tokens in the kit were cut because they expire (about a year for fine-grained tokens on one provider). A spare-key-sheet-only fallback was rejected as the sole path because a recovery phrase grants no repository access on a private remote and so covers none of the target use cases; the phrase remains the owner's own recovery. A command-line-only contact flow was rejected because a grieving non-technical contact cannot use a terminal.

## Decision

The feature is named Legacy Contact. It provides a desktop flow for the owner to arm a contact and a guided read-only desktop flow for the contact to open the vault after a period of owner silence. User-facing copy never uses the word "emergency" and never exposes git, deploy keys, epochs, or signatures: the kit is a spare key, the deploy key is nothing the contact ever sees, and the window is "days of no use". The contact surface collects exactly one secret, the kit passphrase, and never a second password.

### Artifacts

| Artifact | Location and content |
|---|---|
| Kit file | `<name>.bldlegacy`, one ASCII-armored text file with a plaintext letter above an encrypted body. Survives email, forwarding, and printing. Held by the contact and re-exportable from the owner store. |
| Owner store | `meta/legacy.enc`, encrypted under the Root Key and part of Root Key rotation coverage. Holds the `LK` private key, the contact data needed to reproduce the kit verbatim, and kit metadata. A missed re-seal after rotation is a shipped break and not an edge case. |
| Layer blob | `meta/legacy/<kit_id>.layer`: the Root Key under AES-256-GCM keyed by `EK`, with AAD `baluard/legacy-layer/v1 \|\| vault_id \|\| kit_id \|\| epoch`. Rotation rewrites it under the new Root Key and increments the sequence. |
| Owner record | `meta/legacy/<kit_id>.json`, the owner-signed state record. |
| Alive record | `meta/legacy/<kit_id>.alive`, the owner-signed heartbeat. |
| Deploy key | A read-only SSH deploy key created on the forge at arming. Its private half lives only inside the kit. Removed on deny, replace, and disarm. |
| `EK`, `LK` | A 32-byte escrow key and an Ed25519 signing keypair for legacy records, generated at arming. `EK` ships only in the kit. The `LK` public key ships in the kit and the private key lives in the owner store on every owner device. |

Layer, owner, and alive records sync under the existing `meta/**` Admin write policy. Arming requires a connected remote and is refused without one.

### Kit format

The kit is ASCII armor between `-----BEGIN BALUARD LEGACY KEY-----` and `-----END BALUARD LEGACY KEY-----` markers, preceded by the plaintext letter. The letter holds the owner's personal message and identity, an optional passphrase hint, the wait in days, and plain-language install instructions ("Install Baluard, choose Open with a kit letter, pick this file"); it is localized (en, es, pt at the interface layer), stored in the owner's language, and never contains secrets. The armored body is base64 of a sealed JSON record carrying the KDF parameters, nonce, ciphertext, and tag. The encrypted body contains the vault ID, kit ID, repository SSH URL, deploy private key, `EK`, `LK` public key, owner display name, creation timestamp, and wait window.

The body is encrypted with AES-256-GCM under a key derived by Argon2id from the NFKC-normalized, untrimmed passphrase, using the desktop standard profile (64 MiB, 3 iterations, parallelism 1, the same constants as the encrypted backup export in ADR 0099). The exact normalized letter bytes, newline-terminated, are the authenticated data, so the letter cannot be altered silently. Wrong passphrase and corruption are deliberately indistinguishable. Armor parsing tolerates CRLF, line wrapping, and quoted email paste; any other letter edit breaks the authenticated data and reads as a wrong passphrase.

Passphrase modes at arming are four generated EFF words delivered on a channel separate from the kit, or an owner-chosen, strength-metered phrase with a written hint. The generated mode is the default.

### Signed records

Owner records are signed under the domain tag `baluard/legacy/v1` with length-prefixed fields: vault ID, kit ID, state, reason, sequence, epoch, wait days, SHA-256 of the `LK` public key, `ek_check`, SHA-256 of the layer blob, deploy-key fingerprint, repository URL hash, and signer device ID. `ek_check` is `HMAC(EK, "legacy-check" || kit_id)`. Alive records use `baluard/legacy-alive/v1` and contain vault ID, kit ID, the shared sequence, and a day-rounded timestamp.

Verification takes the signer key from the `LK` public key sealed in the kit and never from the synced record. It checks that vault and kit IDs match, that the sequence strictly increases (rollback is refused and a lower sequence never reduces observed silence), that epoch and layer hash match the blob, and that `ek_check` matches the kit's `EK`. The contact client verifies record signatures before interpreting any state, including the Closed state, so a forged record cannot choose the refusal message.

### State machine

Stored states, signed by `LK`, are Armed and Closed. Closed carries the reason `denied`, `replaced`, or `disarmed`, and is terminal; re-arming creates a new kit ID. Any enrolled owner device may sign Closed, including a device enrolled through the recovery phrase. Derived states come from a pure function of record, alive record, and clock: Quiet (observed silence below the configured window) and Open (signed state Armed, window elapsed, layer blob intact). The contact client walks Sealed, Fetching, Waiting, Releasable, and Viewing.

The default wait is 30 days. The core accepts zero through 365 days; the interface presets a minimum of 14 days, and zero is explicit pure trust. Owner devices refresh the alive record on unlock only when the existing record is more than seven days old, with day-rounded timestamps to keep timing coarse and avoid a timing fingerprint. A phone-only owner stays alive because the shared runtime also signs on mobile unlock, and a fresh heartbeat nudges autosync after the unlock pull (a nudge sent before the pull would be undone by its force-checkout). Observed silence is the newest of the signed alive day and the forge deploy-key last-used value where the provider reports it. If local clock skew exceeds one day against the forge's HTTPS `Date` header, the forge value wins. A client that cannot check the remote fails closed and explains that it cannot check right now.

### Contact flow

The contact installs Baluard, chooses "Open with a kit letter", picks the file, and types the passphrase. The client clones the repository over SSH with the kit's deploy key and pinned host keys, verifies the record chain against `LK`, and shows a status such as "Ana last opened Baluard on 3 March; this opens on 2 April" while Quiet. When the wait is satisfied it releases a read-only vault view, enforced by the daemon and not by the interface. The silence countdown reads the verified heartbeat day and not the arming day. Writes are refused. The contact may export an encrypted backup or read attachments (`vault.export` and `vault.attach_download` are on the contact allowlist), or import entries into their own vault. The contact route refuses an export `out_path` so that a non-webview token holder gains no file-write primitive. The route flips the daemon active pointer to the view, consistent with every unlock path. The contact needs no forge account. Port 22 must be reachable; there is no HTTPS token fallback because a forge token in the kit would expire.

### Owner operations

Deny, replace, and disarm each sign Closed with the reason, remove the deploy key, and delete the layer blob. Deny and replace also rotate the Root Key in the same change, and disarm does not rotate. Replace opens the re-arm form, where arming auto-closes the current kit as one operation; a forge failure during arming rolls back by restoring the previous owner store bytes (never deleting a pre-existing store) and removing any created deploy key. When an owner returns after the window has elapsed, the application explains that the contact could have opened the vault and offers to close and rotate ("Lock it?"). Arm and close join the cover-mutation actions so kit artifacts commit and push immediately. A lost kit is resent byte-identically from the owner store without rotation. The passphrase is never stored, so a forgotten passphrase requires replacing the kit. Repository rename or provider change closes the kit and prompts a new one. A closed forge account ends access, and documentation recommends keeping an encrypted backup (ADR 0099) as well. Provider deploy-key last-used reporting is best effort and the banner degrades silently where unavailable. Self-hosted forges are matched by host with the port removed for the provider match, and a custom port builds an `ssh://` URL.

### Test requirements

Bypass tests: wrong passphrase and corrupt kit are indistinguishable and throttled; a tampered header fails the authenticated-data check; a cross-vault kit replay fails on vault ID; a forged heartbeat or Closed record by any other key fails; a lower-sequence replay does not shorten observed silence; a swapped, tampered, or cross-epoch layer blob fails; a forge host-key mismatch fails closed; the deploy key cannot push.

Race and lifecycle tests: heartbeat and contact fetch in the same second (heartbeat wins); deny after unwrap leaves the contact only the old epoch; rotation mid-life rewrites the blob and the old kit still opens; replace fails the old kit with the replaced message; resend is byte-identical and opens; a phone-only owner stays alive; arming without a remote is refused; the last-used poll appears or degrades quietly. Other tests: armor round trips through CRLF, line-wrapped, and quoted email paste; the header is readable as plain text; key material zeroizes on drop; i18n key parity; and an end-to-end "owner dies" test with two owner devices and a contact on a fresh data directory with no forge account that arms, stops heartbeats, advances a mocked clock, opens as contact, reads an item, and confirms writes are refused. The contact desktop flow and this end-to-end test were never droppable for 1.0.

### Review hardening

A full-feature adversarial review of the shipped build found, and the same day fixed, issues that remain design invariants: the contact path must verify record signatures and not trust the cloned chain; the resend path must export the letter and not the kit ID (pinned by a regression test); heartbeats must be pushed and not only written locally; the heartbeat nudge must follow the unlock pull; arm failure must restore and not delete a prior store; and signature verification must precede Closed-state interpretation. Reviewed as sound: HKDF view-key domain separation, canary verification when opening with the Root Key, rewrap-after-rotation ordering, and kit armor AAD binding.

### Provider requirements and verified boundaries

Deploy-key operations exist for GitHub, GitLab, and Codeberg behind the forge provider interface (ADR 0088). The owner token may need repository admin permission, and fine-grained tokens may lack the scope, in which case the arm flow tells the owner to reconnect the sync account. Last-used reporting is available on GitLab and absent on GitHub and Codeberg. Port 22 reachability is a documented limitation.

## Consequences

A non-technical contact can access a read-only vault without a forge account after the configured silence period. The owner can close access, but effective denial requires Root Key rotation, and data already read cannot be taken back. The configured wait protects against mistakes and casual misuse only; a determined contact with a modified client can bypass it. What stays cryptographic is that a kit never released opens nothing, a denied kit opens nothing, and a replaced kit opens nothing. A leaked kit is protected only by its passphrase.

The design depends on deploy-key APIs and SSH host-key pinning. Some providers do not report last-used time, so the interface cannot always provide that detail. Mobile owner setup and contact flows, the last-used banner, a forge-issue contact-request channel, collaborator invites, an early-approve state, and a contact write path are outside this release. The recovery phrase remains the owner's own recovery mechanism and is not a substitute for repository access. The user-facing description of the feature is in `docs/security/legacy-contact.md`.

Known gaps against the stated design: the kit's KDF parameters are read from the file on open without upper caps (the encrypted backup import enforces caps), and the contact route applies no dedicated attempt throttle beyond the Argon2id cost, although the design requires passphrase attempts to be rate-limited.

## References

- `docs/adr/0099-encrypted-backup.md`, encrypted backup format and shared KDF constants.
- `docs/adr/0085-sharing.md`, key rotation and device enrollment.
- `docs/adr/0088-git-providers-multi-vault.md`, forge provider interface.
- `docs/security/legacy-contact.md`, user-facing feature description.
- `crates/baluard-core/src/legacy.rs`, kit, records, and state derivation.
- `crates/baluard-runtime/src/legacy.rs`, arm, close, heartbeat, and contact view.
- `crates/baluard-core/src/providers/`, deploy-key provider operations.
