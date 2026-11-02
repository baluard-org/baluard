# Emergency, org, and identity: how recovery layers fit together

Status: design record + shipped-kit reference. Covers the trusted-contact
escrow (ADR 0021), the personal identity recovery phrase, and the Space
Recovery Kit (power-pack S4-7). Written 2026-09-29 (wave 42).

## 1. The three layers

| Layer | What it protects | Mechanism | Where |
|---|---|---|---|
| Personal identity recovery | One human's vault | 24-word BIP-39 phrase wraps the Root Key (`meta/recovery.json`); recovery resets the device registry and enrolls one fresh device | `recovery.rs` + `device_manager.rs::recover_from_phrase` |
| Trusted-contact emergency access (ADR 0021) | Delegated access while the owner lives | Contact's X25519 key wraps the Root Key in `meta/emergency.json`; the owner's Ed25519-signed approval gates the release; rotation rewraps | `emergency.rs` (core-wired; routes/CLI/UI deferred) |
| Space Recovery Kit | A Space whose every admin device is lost | 24-word BIP-39 phrase wraps the Space's Root Key in `meta/recovery-kit.json` (git-tracked, syncs with the repo) | `vault/recovery_kit.rs` (shipped 2026-09-29) |

The registry-reset rule matters: the personal flow resets the device
registry because one human's vault has no peers. A Space kit recovery
MUST NOT do that — the roster is what every peer verifies signatures
against, and wiping it would orphan the whole Space.

## 2. What recovery means in a Space

A kit-recovered device lands **on the existing Owner member row as a new
bound device**. Never a new member row; never the personal vault's
registry reset. Concretely, the recovery ceremony (follow-up slice; see
section 5):

1. Install Baluard fresh and clone the Space's git remote. The clone
   needs no keys — git transport is public to anyone with repo access.
2. Run recovery with the phrase: the kit wrap unwraps the Root Key and
   the result verifies against the root canary (`meta/rk-canary.enc`).
3. Enroll a new device whose keywrap carries that Root Key, and write
   its device binding inside the live Owner member row's own subtree
   (`meta/members/<owner>/devices/<new-device>.json`).
4. Unlock through the normal admin path, pull, and **rotate the Root
   Key** so every lost device's keywrap dies.

The identity rides the existing cross-device heal: the new device
adopts the owner row's identity on first unlock. Old admin devices,
if any survive, keep working untouched.

## 3. Who approves recovery in an org

Nobody — that is the point. Approval in band is impossible when every
admin device is gone, so **possession of the phrase is the approval**.
This is ADR 0061's code-is-approval doctrine one level deeper: the phrase is
the only credential left. Two consequences, both deliberate:

- The kit bypasses the quorum gate by design. Quorum exists so living
  admins constrain each other; the kit exists for when no quorum can
  convene. A Space that wants both sets quorum 2 for everyday sensitive
  ops and accepts that the safe overrides everything.
- The only off switch is an admin disabling the kit (removing the
  file). There is no expiry, no request flow, no status machine. A
  removed file and a phrase in a safe are the entire model.

The trusted-contact flow (ADR 0021) keeps its owner-signed approval because
it serves a different scenario: delegated access while the owner is
alive to approve.

## 4. Interaction with the Team-shape flip

The kit wraps the Root Key, and the flip never destroys the Root Key —
it only stops distributing it to members (S3-7b). So:

- Pre-flip and post-flip kits are the same artifact; the flip does not
  touch the kit file.
- A post-flip recovery works end to end: the recovered Root Key
  verifies against the canary, and the admin unlock tail opens
  `meta/space.enc` under the Root-Key HKDF to obtain the SMK, so every
  member-visible meta file reads normally.
- Root rotation rewraps the kit in both rotation paths (`rotate_root_key`
  and `revoke_device_and_rekey`), so the phrase in the safe keeps
  working after any rotation. Re-enabling rotates the phrase: the old
  phrase dies the moment the new kit is written.

## 5. Shipped today and the follow-up

Shipped (core, tested; ceremony + routes 2026-09-29):

- `space_recovery_kit_enable` / `_disable` / `_status` (Owner/Admin
  gated, founder equivalence) on `VaultHandle`.
- `rewrap_kit` wired into both rotation paths (P4 failure semantics).
- `recover_root_from_kit` (phrase + vault-id checked unwrap).
- The recovery ceremony itself: `recover_device_with_kit` (canary
  verified, fresh device enrolled into the existing registry, bound to
  the live Owner member row, brick guard refusing devices that already
  hold keys).
- Surfaces: daemon routes (`space.kit_enable/_disable/_status`
  token-gated admin; host-level `vault.recover_kit`), the desktop
  Space settings section (enable/disable/status, one-time phrase
  panel), and the CLI disaster path: `baluard vaults recover-kit
  <slug>`.

Deferred: a login-screen recovery UI on desktop and any mobile
recovery surface. The CLI is the natural fresh-machine tool; revisit
if demand says otherwise.

## 6. Boundaries and threat model

- Whoever holds the phrase holds the Space, whenever the kit file
  exists. Store the phrase accordingly (physical safe, not a note app).
- Losing both the phrase and every admin device loses the Space. The
  kit is the last key, not a backup service.
- The kit file is plaintext metadata: the only secret inside is a
  ciphertext wrapped to the phrase. Members can read the file locally
  (meta reads are ungoverned) and can decrypt nothing.
- A hostile admin can rewrite the kit, but gains nothing: admins
  already hold the Root Key. The kit only matters when no admin device
  survives.
- Domain separation: `space-recovery-kit` (this kit) vs
  `recovery-keywrap` (personal vault phrase) vs `emergency-escrow`
  (trusted contact). A phrase for one mechanism opens nothing in the
  others, and the kit's vault-id field stops a phrase from opening a
  different Space's clone.
