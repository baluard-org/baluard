# ADR 0016. User Profile

> Status: Accepted (completed 2026-06-09); avatar storage superseded, see Decision

## Context

Profile fields belong to the encrypted vault profile. Storing avatar data inline in a JSON file would enlarge Git diffs on every change, and profile input must be constrained before any file is written, because the avatar extension feeds a file name.

## Decision

The fields `display_name`, `subtitle`, and `avatar_ext` are stored in `meta/profile.enc`, encrypted with AES-256-GCM under the root key through `derive_profile_key`. They were migrated out of plaintext `settings.json`; the migration strips the identity fields from the plaintext file after `profile.enc` is written, and a crash window between the two writes is tolerated by a legacy read fallback and a cleanup on the next read.

The avatar is a separate file in the vault directory, synchronized through Git, so that image bytes do not bloat the settings diffs. The original decision stored it as unencrypted `meta/avatar.{ext}` on the rationale that the vault is encrypted at rest. That rationale was wrong for a Git-synchronized vault, because the file reached the remote in cleartext as personal data. The implementation was changed (the M1 audit fix) and the encrypted layout is now authoritative:

- The image is stored as `meta/avatar.enc` regardless of the source extension, as an AES-256-GCM envelope of the form 12-byte nonce, ciphertext, 16-byte tag, the same envelope as attachments. The plaintext extension is kept only inside the encrypted `profile.enc` as `avatar_ext`.
- The key is derived by a domain-separated derivation (`derive_avatar_key`), separate from item keys. It originally derived from the Space Group Key, and it now derives from the member-visible metadata key material so that member devices can read the avatar after a team-shape flip (ADR 0060). Reads try the metadata key first and fall back to the legacy SGK derivation. Any rewrite migrates the blob, and rotation re-encrypts it.
- Legacy plaintext `meta/avatar.{ext}` files are deleted when a new avatar is set. All whitelisted extensions are removed, not only the previous one, so that no stray plaintext copy remains.

Input constraints are enforced by the daemon before any write. The extension must be one of `png`, `jpg`, `jpeg`, `gif`, or `webp`; the whitelist is the path-traversal guard for the legacy file names. The base64 payload is capped at 350,000 characters, which is about 256 KB of decoded image data. The core encryption helper has its own plaintext limit of 350 KiB. Setting an empty payload removes the avatar and clears `avatar_ext`. The managing-device rule from ADR 0060 applies: avatar writes are refused on devices that are not allowed to write shared metadata.

The daemon exposes `vault.avatar.get` to return base64 data and `vault.avatar.set` to accept `{data, ext}`. `SettingsModal` keeps local state and synchronizes it to `VaultContext` on modal close through `createEffect`.

On 2026-06-26, display preferences and vault identity or policy settings were also split from `settings.json`; ADR 0021 is the authoritative record of that split.

## Consequences

Profile fields and the avatar image are encrypted. The avatar is a separate Git-tracked blob, so changing it produces one binary change and leaves the settings diffs small. Avatar size, extension, and path are constrained, and the avatar is covered by key rotation. The extension of the avatar is not visible in the remote, but the existence and approximate size (at most about 352 KB) of `meta/avatar.enc` are. A vault that was never rotated or re-saved may still hold a blob under the older key derivation, which a managing device migrates on the next read (ADR 0060).
## References

- `meta/profile.enc`
- `meta/avatar.enc` (replaces the original `meta/avatar.{ext}`)
- `derive_profile_key`, `derive_avatar_key`
- `vault.avatar.get`, `vault.avatar.set`
- ADR 0021 for `meta/settings-pub.json` and `meta/settings.enc`
- ADR 0060 for the member-visible avatar key and the write-gate rule
