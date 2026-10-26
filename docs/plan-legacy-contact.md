# Plan: Legacy Contact (emergency access)

Status: SHIPPED for 1.0 (2026-10-26). This document is the settled design record; it supersedes the deleted `emergency.rs` time-gate design and the "spare key sheet only" fallback. Build lineage: (1) core module + emergency.rs deletion 4ef4011, (2) deploy keys e44e954, (3) owner ops 7da6e6ed, (4) daemon routes + CLI 3155f34, (5) owner UI 74d2979, (6) contact read-only view 88d3725, (7) letter template + manual 66328ac, plus the owner-dies E2E e9e29d2. Deferred to post-1.0 per the plan: mobile owner setup and contact flow, the last-used banner (GitLab reports the date; GitHub and Codeberg do not), and the forge-issue contact-request channel (cut: the contact needs no forge account). The two honest degradations above ship as documented.

## Peer review of the shipped build (2026-10-26)

A full-feature adversarial pass over 4ef4011..58eb5b4 returned ten findings, all confirmed against the code and all amended the same day:

- 1 (S1) The contact path trusted the cloned record chain without verifying signatures; `verify_record`/`verify_alive` existed but were test-only. `open_contact_view` now verifies both against the LK public key sealed in the kit, and the silence math reads the verified heartbeat day instead of the arm day (also fixing the countdown showing "0 more days" while Quiet).
- 2 (S1) `resend_json` swapped the resend tuple, exporting the kit id as the letter. Fixed; regression test pins the mapping.
- 3 (S1) Heartbeats were written locally but never pushed, so a read-only owner stayed "silent" on the remote forever. A fresh heartbeat now nudges autosync right after activation.
- 4 (S2) `legacy.arm`/`legacy.close` joined `COVER_MUTATION_ACTIONS` so kit artifacts commit and push immediately.
- 5 (S2) Self-hosted instances never matched the connected provider (bare base URLs cannot parse as remote URLs); a host-only extractor replaces the parser call.
- 6 (S2) The contact route now flips the daemon active pointer to the view, matching every unlock path (desktop requests already carried the slug, so this is consistency hardening).
- 7 (S2) `vault.export` and `vault.attach_download` joined the contact allowlist — the plan promises exports and attachment reading, both read-only.
- 8 covered in 1 (countdown math).
- 9 (S2) `arm`'s forge-failure rollback no longer deletes a pre-existing `meta/legacy.enc`; it restores the prior store bytes (the replace flow re-arms after a close).
- 10 (S4) The desktop armed card gained a Replace action that opens the re-arm form (arm auto-closes the current kit, one operation).

Clean: HKDF view-key domain separation, `open_with_root_key` canary verification, `rewrap_after_rotation` ordering, kit armor AAD binding.

## Problem

A vault owner dies or is incapacitated. Their partner, child, or sibling is locked out of everything: passwords, account seeds, notes, recovery codes for other services. The existing recovery paths (master password, recovery phrase) require the owner to pre-arrange a secret hand-off, and the phrase alone grants nothing because the vault's git remote is private. The real-world nominations are "my sister should be able to get in if something happens to me," where the sister may live on another continent, may have no technical skill, and may not even know she was nominated.

Design constraints that shaped every decision: no server backend (the git remote is the only channel), the contact may have zero accounts and zero technical skill, and no clock check on data the contact holds can be trusted (a modified client rewinds anything).

## Trust model

The feature gives a named contact a path to open the vault when the owner goes silent, after a waiting period. Five rules, with two honest degradations:

- Honest trust statement: the contact can open the vault whenever the silence rule is met. The wait protects against mistakes and casual misuse, not a determined contact with a modified client. Docs and UI say this plainly.
- Factors at rest (degraded): the kit file plus its passphrase is the single secret protecting a leaked kit. The deploy key and the repo add revocability, not a second independent factor. Passphrase strength is the whole defense of a leaked kit, and the setup copy states the risk.
- Layer blob: the repo holds only the Root Key encrypted under an escrow key `EK`. `EK` lives only in the kit and on owner devices. A repo leak alone is useless. Root Key rotation rewrites only the repo blob, so the kit never goes stale.
- Real denial is rotation: removing the deploy key or writing a "closed" record stops only the stock client, because the contact may already hold everything. A denial that matters rotates the Root Key, making the old epoch unreadable. Data already read is gone; nothing fixes that.
- Social wait: default 30 days of owner silence (owner picks 0 to 365; preset minimum 14). The stock client enforces it, owner devices keep signing coarse "alive" records while in use, and the wait is a social control. `N = 0` is honest pure trust.

## Rejected designs

- The original `emergency.rs` time gate (grantee requests, waits `delay_seconds`, recovers): the grantee holds the file and can rewind any stored timestamp, so the gate was bypassable; it was demoted to owner-approved-only, which fails the dead-owner case entirely. Deleted.
- Forge issue as the request channel: requires the contact to hold a forge account or a write credential. Breaks the non-technical-contact case. Cut.
- Scoped tokens in the kit: expire (about a year for GitHub fine-grained PATs). Cut.
- Spare-key-sheet-only fallback: a recovery phrase grants no repo access on a private remote, so it covers none of the target use cases. Rejected as the sole path; the phrase remains the owner's own recovery mechanism.
- Contact CLI-only flow: a grieving non-technical contact cannot use a terminal. Rejected; the contact gets a guided desktop flow in 1.0.

## Architecture

Actors: the owner (one or more enrolled devices, any of which can sign), and the contact (no Baluard account, no vault, holds the kit file).

Artifacts:

- Kit file `<name>.bldlegacy`: one ASCII-armored text file. Plaintext letter header above an encrypted body; survives email, forwarding, and printing. Created at arming, held by the contact, re-exportable from `meta/legacy.enc` if lost.
- Owner secret store `meta/legacy.enc`: encrypted under the Root Key (joins the rotation coverage list). Holds the `LK` Ed25519 private key, the contact plaintext needed to re-export the kit verbatim, and the kit metadata.
- Layer blob `meta/legacy/<kit_id>.layer`: AES-256-GCM(Root Key) under `EK`, AAD binds vault id, kit id, and epoch. Synced under the existing `meta/**` Admin write policy.
- Owner record `meta/legacy/<kit_id>.json`: the owner-signed state record (see payloads). Synced.
- Alive record `meta/legacy/<kit_id>.alive`: the owner-signed heartbeat. Synced.
- Deploy key: a read-only SSH deploy key created on the forge at arming; private half lives only inside the kit. The contact clones the repo with it. Removed on deny/replace/disarm.
- `EK` (32-byte escrow key) and `LK` (Ed25519 signing keypair for legacy records): generated at arming. `EK` ships only in the kit; `LK` public ships in the kit, `LK` private lives in `meta/legacy.enc` on every owner device.

## State machine

Stored states, signed by `LK`: **Armed** and **Closed**. Closed carries a reason: `denied`, `replaced`, or `disarmed`. Closed is terminal; re-arming mints a new kit id. Any owner-enrolled device can sign Closed, including a device freshly recovered from the recovery phrase.

Derived states, computed by a pure function from record + alive + clock: **Quiet** (observed silence under N days) and **Open** (record Armed, observed silence N days or more, layer blob intact). The contact client walks Sealed, Fetching, Waiting, Releasable, Viewing.

Observed silence: the newest of (alive record day-rounded timestamp, forge `last used` for the deploy key where the provider reports it). A device clock skewed more than a day against the forge's HTTPS `Date` header falls back to the forge value; fully offline clients fail closed on the fetch and show "cannot check right now."

Heartbeat discipline: owner devices refresh the alive record on unlock only when the existing one is more than 7 days old, day-rounded, to keep the timing coarse (T14 fingerprint discipline). A phone-only owner stays alive because `baluard-runtime` signs on mobile unlock too.

## Signed payloads

Owner record, signed under domain tag `baluard/legacy/v1` with length-prefixed fields: vault_id, kit_id, state, reason, seq, epoch, window_days, SHA-256 of `LK` public, `ek_check` (HMAC(`EK`, "legacy-check" || kit_id)), SHA-256 of the layer blob, deploy-key fingerprint, repo URL hash, signer device id. Verifier checks: signer key is the `LK` public from the kit (never a key from the synced record), vault and kit ids match, seq strictly increases (refuses rollback), epoch and layer hash match the blob, `ek_check` matches the kit's `EK`.

Alive record, tag `baluard/legacy-alive/v1`: vault_id, kit_id, seq (shared sequence), day-rounded timestamp.

Layer blob: AES-256-GCM(EK, root_key), AAD `baluard/legacy-layer/v1` || vault_id || kit_id || epoch. Rotation rewrites it under the new Root Key and bumps seq. This replaces the old `emergency.json` rewrap hook.

## Kit format

ASCII armor, modeled on `.bldbak`: a plaintext letter header, a blank line, then a base64 body. The body is AES-256-GCM keyed by Argon2id (import profile parameters, matching the encrypted backup container), with the exact header bytes as AAD so the letter cannot be altered silently. Wrong passphrase and corruption are deliberately indistinguishable; passphrase attempts are rate-limited.

Header (localized, plain language, en/es/pt at the UI layer, stored in the owner's language): the owner's personal message, who they are, a passphrase hint line if the owner chose one, the wait in days, and "Install Baluard, choose Open a vault I was left, pick this file." The header never contains secrets.

Body (encrypted): vault_id, kit_id, repo SSH URL, deploy private key, `EK`, `LK` public, owner display name, created timestamp, window days.

Passphrase modes at arming: default four generated EFF words (delivered on a channel separate from the kit), or an owner-chosen phrase with a written hint, strength-metered, with the copy "anyone who gets this file and guesses the passphrase can open this vault."

## Flows

Arm: owner connects a remote, opens setup, picks the contact name, window, and passphrase mode. The app mints kit_id, `EK`, `LK`, the deploy key, writes the record (Armed), the layer blob, `meta/legacy.enc`, and exports the kit file. Arming without a connected remote is refused.

Contact open: install, pick the kit, type the passphrase, the app clones over SSH with the deploy key into a local read-only view, verifies the record chain against `LK` public, shows "Ana last opened Baluard on 3 March; this opens on 2 April" while Quiet, then releases: a read-only vault view. Writes are refused; the contact can export an encrypted backup or import entries into their own vault.

Deny/replace/disarm: any owner device signs Closed(reason), removes the deploy key, deletes the layer blob, and (denied/replaced) rotates the Root Key in the same change. An owner returning after an Open period is shown "Ana's key could have opened on X. Lock it?" with Lock = Closed plus rotation.

Lost kit: "send again" re-exports the sealed file byte-identically from `meta/legacy.enc`; no rotation needed. Renaming the repo or changing providers closes the kit with a banner to make a new one; a closed forge account ends the kit (the docs say to keep a `.bldbak` backup as well).

## Scope

In, in build order: (1) core `legacy` module with tests, delete `emergency.rs`; (2) `ForgeProvider` deploy-key methods for GitHub, GitLab, Codeberg plus SSH clone transport with pinned host keys; (3) runtime arm/deny/disarm/replace/status, heartbeat on unlock, last-used poll; (4) daemon routes (`legacy.*`) and owner CLI (`baluard legacy ...`); (5) desktop owner UI (setup, status, banners, resend, replace); (6) desktop contact flow (the read-only view); (7) manual page, kit letter, i18n; (8) post-1.0: mobile owner setup and contact flow.

Cut for 1.0: forge issue channel, collaborator invites, early-approve state, contact write path, mobile flows. Droppable if time runs short: owner CLI parity first, the last-used banner second. Never droppable: the contact desktop flow and the E2E test.

## Tests required before ship

Bypass: wrong passphrase and corrupt kit are indistinguishable and throttled; tampered header fails the AEAD check; cross-vault kit replay fails on vault_id; forged heartbeat or Closed record by any other key fails; lower-seq replay does not shorten observed silence; swapped, tampered, or cross-epoch layer blob fails; forge host-key mismatch fails closed; the deploy key cannot push; lower seq never reduces silence.

Race and lifecycle: heartbeat and contact fetch in the same second, heartbeat wins; deny after unwrap leaves the contact only the old epoch; rotation mid-life rewrites the blob and the old kit still opens; Replace fails the old kit with the replaced message; resend is byte-identical and opens; a phone-only owner stays alive; arming without a remote is refused; the last-used poll appears or degrades quietly.

Other: armor round-trips through CRLF, line-wrapped, and quoted email paste; header readable as plain text; key material zeroizes on drop; i18n key parity; an E2E ("owner dies") with two owner devices and a contact on a fresh data dir with no forge account: arm, stop heartbeats, advance a mocked clock, open as contact, read an item, confirm writes are refused.

## Security invariants and UX rules

Crypto stays X25519/Ed25519/HPKE/AES-256-GCM/Argon2id. All legacy key material zeroizes on drop. `meta/legacy.enc` joins the rotation coverage list (a missed re-seal after rotation is a shipped break, not an edge case). The contact surface collects exactly one secret (the kit passphrase); no second password prompts. User-facing copy never names git, deploy keys, epochs, or signatures: the kit is a "spare key," the deploy key is nothing the contact ever sees, the window is "days of no use." The word "emergency" appears nowhere in user-facing strings; the feature is "Legacy contact."

## Open items to verify at build time

Per-provider deploy-key API permissions (owner token may need repo admin; fine-grained PATs may lack the scope; the arm flow surfaces "reconnect your sync account" if so). Per-provider deploy-key last-used reporting (GitHub and GitLab report it; Forgejo/Codeberg may not, in which case the banner degrades silently). Port 22 reachability for SSH clones (documented limitation; no HTTPS fallback because a token in the kit would expire).
