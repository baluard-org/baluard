# ADR 0024. Browser Extension: Paired-Companion Bridge

> Status: Accepted (2026-06; phases 0 and 1 done)

## Context

Baluard has no server, so the Bitwarden and 1Password model where the extension talks to a company API does not apply. A 0600 Unix socket cannot be opened by a WebExtension, because MV3 has no raw-socket API. The only cross-browser escape hatch is `nativeMessaging` (Chrome `runtime.connectNative` and `sendNativeMessage`, Firefox identical). The reference architecture is KeePassXC-Browser: extension, native messaging host (stdio), local socket, app. This was recorded as D21.

## Decision

MV3 extensions talk to `baluard-daemon` through a new native messaging host, `baluard-nmh`. The extension is a paired companion. It never unlocks, never holds the master password, and never holds the vault session token. It rides the desktop's unlock state through a scoped bridge token.

**Components**

- `baluard-nmh` is a standalone, stateless Rust binary that relays stdio JSON to varint protobuf.
- The new `core/bridge/` module (`mod.rs`, `pairing.rs`, `token.rs`) holds the pairing file format with atomic writes, bridge token mint and verify, and the action allowlist.
- The scoped bridge token (`TokenKind::Bridge { pairing_id }`) lives in a host-level registry (`VaultHost::bridges`, `HashMap<pairing_id, BridgeTokenEntry>`). It is vault-agnostic, because the extension follows the desktop's active pointer. Its TTL equals the per-vault session token TTL (`SESSION_TOKEN_TTL_SECONDS`, 4 hours).

**Action allowlist.** The server enforces it in `verify_session_token` after token verification.

- Allowed: `bridge.match`, `vault.get` (single entry, on fill or copy only), `vault.add`, `vault.update`, `cipher.totp_code`, `generator.history_add`, `generator.history_clear`, `sync.autosync_status`, and `bridge.config`.
- `vault.update` is field-gated. Password, username, notes, and TOTP are accepted. `fido2_credentials` and `uris` are rejected for bridge tokens.
- Excluded, and rejected even with a valid bridge token: `vault.list_full`, `vault.delete`, `vault.export`, `vault.change_password`, `device.revoke`, all `sync.*` mutations, all `provider.*`, `vault.attach_*`, `ssh.generate_key`, `passkey.*`, `vault.clone_*`, `folder.*`, `tag.*`, `vault.archive` and `unarchive`, `cipher.clone`, `settings.*`, `vault.trash.*`, `generator.history_list`, and `favicon.get`.

**Pairing flow: approve, do not type.** The desktop user clicks "Add browser extension", which calls `bridge.pair_start` (gated by the desktop session token, sets a one-shot pending-approval flag with a short TTL). The extension calls `bridge.pair_complete`, which is held pending. The desktop UI shows "A Baluard extension wants to connect" with Approve and Deny. Approve consumes the flag, writes the pairing file, and returns the pairing secret to the NMH.

**Rate cap.** `bridge.match` and `vault.get` are capped per `pairing_id` through the existing `RateLimiter` (about 10 to 20 per minute). Burst abuse escalates to `bridge.revoke`.

**Fill policy**

- Fill is popup-driven with a per-fill user gesture. There is no auto-fill on load.
- The content script runs in the top frame only (`frameIds: [0]`).
- At fill time the content script re-checks `location.origin` against the credential's stored URI before writing to the DOM, and fails closed on mismatch.

**Pairing file ownership.** The daemon is the sole writer of `<data_dir>/bridge/pairings.json`, using atomic tmp and rename. The desktop mutates it only through daemon routes. The NMH reads its own entry read-only.

**Lifecycle.** `connectNative` spawns a fresh NMH, and the browser terminates it on disconnect. On spawn the NMH reads its pairing entry through core and presents the secret to the daemon, which re-mints an ephemeral bridge token. The token dies with the NMH. The pairing file is durable and revocable.

**Shared-vault write scope (2026-09-22, sharing plan S1b-5).** The allowlist is action-scoped, and sharing added a session-scope dimension. Over a bridge token, `vault.add` and `vault.update` additionally require the active vault's member row to carry cipher write scope (`VaultState::bridge_write_allowed`). Legacy vaults without `meta/members` stay owner-equivalent. Viewer rows and unbound or tombstoned devices are refused at a point where the extension can show the error. Reads are unchanged: `bridge.match`, `vault.get`, and `cipher.totp_code` stay open to viewers.

The same wave shipped `ensure_access_accepted` (sharing plan §4.5) through the notices transport check. Expired GitHub invitations (status `None`) are healed by a permission-matched re-invite and surfaced per member. For GitLab and Codeberg, `None` is reported only, because their grants are immediate and `None` may be a deliberate out-of-band removal that auto re-adding would resurrect.

## Consequences

The extension sees metadata and one credential at a time. A direct `vault.list_full` for the extension was rejected because it returns the entire decrypted vault in one call, which is a de facto export and the real blast radius. The rate cap bounds a browser compromise to a handful of credentials instead of the whole vault.

The pairing ceremony has no codes to transcribe, no brute-force surface, and no vault nuke on ceremony abuse. A 5-strike nuke was rejected earlier because it was a denial-of-service risk for non-technical users.

The fill-time origin check closes the classic credential-theft vector of cross-origin login iframes and the race between popup match and navigation during IPC.

An allowlist was chosen over a deny-list. Expanding it is a deliberate change with a same-change call-site update. The friction is intentional because it forces a conscious security decision per route.

A viewer-accepted capture would otherwise wedge at push time, because cipher paths are editor scope in the sharing policy table. This is why the write-scope check refuses viewers up front.

## References

- `docs/adr/0092-browser-extension.md` for the full design
- `crates/baluard-core/src/bridge/{mod,pairing,token}.rs`
- `crates/baluard-runtime/src/bridge.rs`
- `crates/baluard-nmh/`
- `browser/{shared,chrome,firefox}/`, with about 95% shared code and target wrappers
- `desktop/src/components/BridgeTab.jsx`
