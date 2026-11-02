//! Browser-extension bridge.
//!
//! Lets a paired browser extension (via the `baluard-nmh` native-messaging host
//! proxy) read/write a narrow allowlist of vault actions without ever seeing
//! the master password or the per-vault session token.
//!
//! See `docs/adr/0092-browser-extension.md` for the full design (Decisions 1-25).
//!
//! ## Trust model
//!
//! - The browser, the NMH, and the page are all UNTRUSTED.
//! - The 0600 socket + SO_PEERCRED UID verify is the real trust boundary
//!   (unchanged by this module).
//! - A bridge token is a distinct, scoped credential (`TokenKind::Bridge`),
//!   NOT the per-vault session token. It permits only [`BRIDGE_ALLOWED_ACTIONS`].
//! - The pairing file (`<data_dir>/bridge/pairings.json`, 0600) is a revocable
//!   read-capable grant at rest: whoever holds a pairing secret can mint bridge
//!   tokens and read credentials one-at-a-time via `vault.get` while the vault
//!   is unlocked. See threat-model item §10.3. The daemon is the SOLE writer;
//!   the NMH reads its own entry read-only.

pub mod pairing;
pub mod token;

pub use pairing::{PairingEntry, PairingFile, PairingId, PairingSecret};
pub use token::{
    BRIDGE_ALLOWED_ACTIONS, BRIDGE_TOKEN_TTL_SECONDS, BridgeToken, BridgeTokenEntry,
    STALE_TOKEN_ERROR, is_allowed,
};
