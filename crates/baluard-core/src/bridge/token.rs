//! Bridge token + the allowlist it enforces.
//!
//! A `BridgeToken` is a distinct, scoped credential — NOT the per-vault session
//! token. It lives in the daemon's host-level registry
//! (`HashMap<PairingId, BridgeTokenEntry>`), is re-minted per NMH spawn via
//! `bridge.reauth`, expires on the same TTL as the vault token, and permits
//! only [`BRIDGE_ALLOWED_ACTIONS`].
//!
//! The allowlist is the security property. It is enforced server-side in the
//! daemon (and defense-in-depth in the NMH). See Decision 7 + Decision 5.

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// 4 hours. Mirrors `SESSION_TOKEN_TTL_SECONDS` in the daemon's `state.rs`.
/// Kept here as a single source of truth the daemon imports.
pub const BRIDGE_TOKEN_TTL_SECONDS: u64 = 4 * 3600;

/// The allowlist of actions a bridge token may perform (Decision 7).
///
/// Deliberately does NOT include `vault.list_full` (bulk plaintext), nor
/// destructive ops (`vault.delete`, `device.revoke`, `vault.export`, ...),
/// nor `favicon.get`/`settings.get`/`generator.history_list`.
///
/// `vault.update` is allowed but FIELD-GATED in the daemon handler: bridge
/// tokens may NOT modify `fido2_credentials` or `uris` (Decision 7 / 13).
pub const BRIDGE_ALLOWED_ACTIONS: &[&str] = &[
    "bridge.match",          // URL -> matching CipherMeta (metadata only, no passwords)
    "vault.get",             // single selected credential, on fill/copy only
    "vault.add",             // capture new login
    "vault.update",          // capture password change (field-gated for bridge tokens)
    "cipher.totp_code",      // TOTP copy (derived code only; seed never crosses)
    "generator.history_add", // record a freshly-generated password
    "generator.history_clear",
    "bridge.config",        // returns ONLY default_uri_match
    "sync.autosync_status", // read-only sync badge
];

/// Membership test against the allowlist. Used by both the daemon (authoritative)
/// and the NMH (defense-in-depth).
pub fn is_allowed(action: &str) -> bool {
    BRIDGE_ALLOWED_ACTIONS.contains(&action)
}

/// A 256-bit bridge token. Zeroized on drop. Hex on the wire + in the registry.
#[derive(Clone, PartialEq, Eq)]
pub struct BridgeToken(Box<[u8; 32]>);

impl BridgeToken {
    pub fn generate() -> Self {
        let mut buf = Box::new([0u8; 32]);
        OsRng.fill_bytes(buf.as_mut_slice());
        Self(buf)
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for BridgeToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for BridgeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeToken(**redacted**)")
    }
}

/// A live entry in the daemon's host-level bridge-token registry.
///
/// One per `PairingId`. Multiple NMH processes for the same pairing reuse the
/// same live token (`bridge.reauth` is idempotent). The token is invalidated
/// when: (a) the active vault locks (every bridge request re-checks unlocked
/// state), (b) it expires (`created + BRIDGE_TOKEN_TTL_SECONDS`), or
/// (c) `bridge.revoke` drops the entry.
#[derive(Debug, Clone)]
pub struct BridgeTokenEntry {
    /// The token bytes the NMH stamps on forwarded requests. Hex-compared
    /// against the request's `session_token` field.
    pub token: BridgeToken,
    /// Unix epoch seconds when minted.
    pub created: u64,
    /// Per-pairing abuse limiter state (loose window over `bridge.match` +
    /// `vault.get`). See Decision 5.
    pub reads_in_window: u32,
    pub window_started_at: u64,
}

impl BridgeTokenEntry {
    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Fresh entry with a new token, clock-stamped now.
    pub fn fresh() -> Self {
        let now = Self::now();
        Self {
            token: BridgeToken::generate(),
            created: now,
            reads_in_window: 0,
            window_started_at: now,
        }
    }

    /// Has the token exceeded its TTL?
    pub fn is_expired(&self) -> bool {
        let now = Self::now();
        now.saturating_sub(self.created) > BRIDGE_TOKEN_TTL_SECONDS
    }
}

/// Reads-per-minute cap before a pairing is auto-revoked.
/// A human fills a handful of logins a minute; ~30/min is generous. Burst abuse
/// (a compromised browser looping `bridge.match` over a domain list then
/// `vault.get`-ing every hit) trips this and revokes the pairing.
pub const READ_RATE_LIMIT_PER_MINUTE: u32 = 30;

/// The sliding window length (seconds) for the read cap.
pub const READ_RATE_WINDOW_SECONDS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn allowlist_excludes_bulk_and_destructive() {
        for forbidden in [
            "vault.list_full",
            "vault.delete",
            "vault.export",
            "device.revoke",
            "vault.change_password",
            "settings.get",
            "settings.set",
            "favicon.get",
            "generator.history_list",
            "passkey.delete",
            "ssh.generate_key",
            "provider.disconnect",
            "sync.pull",
        ] {
            assert!(
                !is_allowed(forbidden),
                "{forbidden} must NOT be bridge-allowed"
            );
        }
    }

    #[test]
    fn allowlist_includes_capture_and_read() {
        for ok in [
            "bridge.match",
            "vault.get",
            "vault.add",
            "vault.update",
            "cipher.totp_code",
            "bridge.config",
        ] {
            assert!(is_allowed(ok), "{ok} must be bridge-allowed");
        }
    }

    #[test]
    fn tokens_are_unique() {
        let a = BridgeToken::generate();
        let b = BridgeToken::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.to_hex().len(), 64);
    }

    #[test]
    fn allowlist_has_no_duplicates() {
        let set: HashSet<&&str> = BRIDGE_ALLOWED_ACTIONS.iter().collect();
        assert_eq!(set.len(), BRIDGE_ALLOWED_ACTIONS.len());
    }

    #[test]
    fn fresh_entry_is_not_expired() {
        let e = BridgeTokenEntry::fresh();
        assert!(!e.is_expired());
    }
}
