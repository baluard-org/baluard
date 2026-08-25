//! Daemon-side bridge-token registry + pairing-route helpers.
//!
//! Host-level (vault-agnostic, per Decision 10): one registry per daemon,
//! keyed by `PairingId`. Holds live bridge tokens, enforces the per-pairing
//! read-rate cap, and owns the approve-don't-type pairing
//! ceremony state (Decision 4).
//!
//! This module is the bridge auth brain; `handler.rs` is the thin router.

use std::collections::HashMap;
use std::sync::Arc;

use baluard_core::bridge::pairing::{PairingEntry, PairingFile, PairingId, PairingSecret};
use baluard_core::bridge::token::{
    BridgeTokenEntry, READ_RATE_LIMIT_PER_MINUTE, READ_RATE_WINDOW_SECONDS, is_allowed,
};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

/// Outcome of a `bridge.reauth` call.
#[derive(Debug)]
pub enum ReauthOutcome {
    /// Returned a (possibly freshly-minted) bridge token hex.
    Ok {
        token_hex: String,
        pairing_id: PairingId,
    },
    /// No pairing entry matches the presented secret.
    NotPaired,
}

/// Outcome of a pending-approval pairing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairApproval {
    /// User clicked Approve in the desktop UI.
    Approved,
    /// User clicked Deny, or the pending request was dropped/expired.
    Denied,
}

/// Host-level bridge state. Held inside `VaultHost` as its own
/// `Arc<RwLock<BridgeRegistry>>` so bridge auth never contends on the vault
/// map lock.
#[derive(Default)]
pub struct BridgeRegistry {
    /// Live bridge tokens, keyed by pairing id.
    tokens: HashMap<PairingId, BridgeTokenEntry>,
    /// One-shot approve-don't-type pending request (Decision 4). Only one
    /// pairing may be pending at a time per daemon; a new `pair_start`
    /// supersedes any prior pending.
    pending: Option<PendingPair>,
    /// A waiter registered by an in-flight `bridge.pair_complete` (extension).
    /// When the desktop calls `pair_approve`, this sender is resolved so the
    /// held pair_complete unblocks and mints the token. Replaced on each
    /// new pair_start / pair_complete.
    waiter: Option<tokio::sync::oneshot::Sender<WaiterPayload>>,
}

/// What the held pair_complete receives when the desktop approves.
#[derive(Clone)]
pub struct WaiterPayload {
    pub name: String,
    pub browser: String,
}

/// A pending approve-don't-type pairing.
#[derive(Debug, Clone)]
pub struct PendingPair {
    /// Random handle the desktop polls / subscribes for. Echoed back on
    /// approval so the desktop knows which request it confirmed.
    pub request_id: String,
    /// Label the desktop UI shows ("A Baluard extension wants to connect").
    pub browser_hint: String,
    /// Unix epoch seconds; pending expires after [`PENDING_TTL_SECONDS`].
    pub created_at: u64,
    /// Whether the desktop user has Approve / Deny / neither-yet.
    pub approval: Option<PairApproval>,
    /// One-time pairing code (audit C13). Displayed by the desktop, typed
    /// into the extension popup, verified by `verify_pair_code` BEFORE a
    /// `pair_complete` may register a waiter or finalize. Keeps a
    /// same-UID process from superseding the real extension's waiter and
    /// harvesting the freshly minted pairing.
    pub pair_code: String,
    /// Wrong-code attempts against `pair_code`. The pending is cancelled
    /// after [`MAX_PAIR_CODE_ATTEMPTS`].
    pub code_attempts: u8,
}

/// How long an unconfirmed pairing request stays valid.
pub const PENDING_TTL_SECONDS: u64 = 120;

/// Wrong pair-code attempts before the ceremony is cancelled.
pub const MAX_PAIR_CODE_ATTEMPTS: u8 = 3;

/// No-homoglyph alphabet for pair codes (no I/L/O/0/1).
const PAIR_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const PAIR_CODE_LEN: usize = 8;

fn generate_pair_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..PAIR_CODE_LEN)
        .map(|_| PAIR_CODE_ALPHABET[rng.gen_range(0..PAIR_CODE_ALPHABET.len())] as char)
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl BridgeRegistry {
    /// Create a fresh pending pairing request. Supersedes any prior pending
    /// (and any prior waiter — a re-started ceremony cancels the old one by
    /// DROPPING the sender, which triggers `RecvError` on the held
    /// `pair_complete` so it lands in the timeout/superseded error path
    /// rather than being treated as a successful approval).
    pub fn start_pair(&mut self, browser_hint: impl Into<String>) -> (String, String) {
        // Cancel any in-flight extension waiter by dropping the sender.
        // (Do NOT send an empty payload — the receiver would treat it as success.)
        drop(self.waiter.take());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pair_code = generate_pair_code();
        self.pending = Some(PendingPair {
            request_id: request_id.clone(),
            browser_hint: browser_hint.into(),
            created_at: now_secs(),
            approval: None,
            pair_code: pair_code.clone(),
            code_attempts: 0,
        });
        (request_id, pair_code)
    }

    /// Verify the one-time pair code presented by a `bridge.pair_complete`
    /// caller against the pending ceremony (audit C13). MUST run before the
    /// caller registers a waiter — a wrong-code caller must never supersede
    /// the real extension's waiter. Cancels the ceremony (and any waiter)
    /// after [`MAX_PAIR_CODE_ATTEMPTS`] wrong attempts or on TTL expiry.
    pub fn verify_pair_code(&mut self, presented: &str) -> Result<(), &'static str> {
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|p| now_secs().saturating_sub(p.created_at) > PENDING_TTL_SECONDS);
        if expired {
            self.pending = None;
            self.waiter.take();
            return Err("pending pairing expired");
        }
        let p = self.pending.as_mut().ok_or("no pending pairing")?;
        let a = presented.as_bytes();
        let b = p.pair_code.as_bytes();
        let ok = a.len() == b.len() && bool::from(subtle::ConstantTimeEq::ct_eq(a, b));
        if !ok {
            p.code_attempts += 1;
            if p.code_attempts >= MAX_PAIR_CODE_ATTEMPTS {
                self.pending = None;
                self.waiter.take();
                return Err("too many invalid pair codes; start pairing again");
            }
            return Err("invalid pair code");
        }
        Ok(())
    }

    /// Read the current pending (for the desktop UI to surface Approve/Deny).
    pub fn pending(&self) -> Option<&PendingPair> {
        self.pending
            .as_ref()
            .filter(|p| now_secs().saturating_sub(p.created_at) <= PENDING_TTL_SECONDS)
    }

    /// True if an extension has called `bridge.pair_complete` and is currently
    /// blocked waiting for the desktop to approve. Lets the desktop UI
    /// transition from "Waiting for extension" to "Extension connected —
    /// approve now" so the user knows the ceremony is live.
    pub fn has_waiter(&self) -> bool {
        self.waiter.is_some()
    }

    /// Register an in-flight `bridge.pair_complete` waiter. Returns a receiver
    /// that resolves when the desktop approves (or the ceremony is
    /// superseded/expired). The handler awaits this with a TTL timeout.
    pub fn register_waiter(
        &mut self,
        _name: String,
        browser: String,
    ) -> tokio::sync::oneshot::Receiver<WaiterPayload> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiter = Some(tx);
        // Remember the extension's requested browser so approve can show it.
        if let Some(p) = self.pending.as_mut() {
            if p.browser_hint == "unknown" || p.browser_hint.is_empty() {
                p.browser_hint = browser;
            }
        }
        rx
    }

    /// Mark the pending request Approved. If an extension pair_complete is
    /// waiting, resolves it (the handler then mints the token). Returns the
    /// request_id so the desktop can confirm which request it approved.
    pub fn approve_pending(&mut self) -> Result<String, &'static str> {
        let p = self.pending.as_mut().ok_or("no pending pairing")?;
        if now_secs().saturating_sub(p.created_at) > PENDING_TTL_SECONDS {
            self.pending = None;
            // Also fail any waiter.
            self.waiter.take();
            return Err("pending pairing expired");
        }
        let request_id = p.request_id.clone();
        // Resolve the extension waiter if one is registered. The handler that
        // owns the receiver performs the actual complete_pair + token mint.
        if let Some(tx) = self.waiter.take() {
            let _ = tx.send(WaiterPayload {
                name: p.browser_hint.clone(),
                browser: p.browser_hint.clone(),
            });
        } else {
            // No extension waiting yet: mark approved so a later pair_complete
            // can proceed immediately.
            p.approval = Some(PairApproval::Approved);
        }
        Ok(request_id)
    }

    /// Complete pairing: writes the pairing file, mints the first bridge token,
    /// returns the token hex. Called by the pair_complete handler AFTER the
    /// waiter resolves (desktop approved). Requires the pending to still be
    /// present and within TTL.
    pub fn complete_pair(
        &mut self,
        name: impl Into<String>,
        browser: impl Into<String>,
    ) -> Result<(PairingId, String), &'static str> {
        // Confirm a pending exists and is within TTL.
        {
            let p = self.pending.as_ref().ok_or("no pending pairing")?;
            if now_secs().saturating_sub(p.created_at) > PENDING_TTL_SECONDS {
                self.pending = None;
                return Err("pending pairing expired");
            }
        }
        self.pending = None;

        let pairing_id = PairingId::new();
        let secret = PairingSecret::generate();
        let entry = PairingEntry {
            pairing_id: pairing_id.clone(),
            name: name.into(),
            browser: browser.into(),
            secret: secret.to_hex().to_string(),
            created_at: now_secs(),
        };

        // Append to the pairing file (daemon is the SOLE writer).
        let mut pf = PairingFile::load().unwrap_or_default();
        pf.pairings.push(entry);
        pf.save_atomic().map_err(|_| "pairing file write failed")?;

        // Mint first token.
        let mut entry_tok = BridgeTokenEntry::fresh();
        let hex = entry_tok.token.to_hex().to_string();
        // Reads-window bookkeeping starts clean.
        entry_tok.reads_in_window = 0;
        entry_tok.window_started_at = now_secs();
        self.tokens.insert(pairing_id.clone(), entry_tok);

        Ok((pairing_id, hex))
    }

    /// `bridge.reauth`: present a pairing secret, get back a bridge token.
    /// Idempotent — returns the live token for the pairing if one exists and
    /// isn't expired; mints fresh otherwise. Re-loads the pairing file so a
    /// token minted in a prior daemon process (before restart) is restorable.
    pub fn reauth(&mut self, presented_secret_hex: &str) -> ReauthOutcome {
        let presented = match PairingSecret::from_hex(presented_secret_hex) {
            Ok(s) => s,
            Err(_) => return ReauthOutcome::NotPaired,
        };

        // Look up the pairing by secret. The pairing file is authoritative.
        let pf = match PairingFile::load() {
            Ok(pf) => pf,
            Err(_) => return ReauthOutcome::NotPaired,
        };
        let entry = pf
            .pairings
            .iter()
            .find(|p| constant_time_secret_eq(&presented, &p.secret));

        let Some(entry) = entry else {
            return ReauthOutcome::NotPaired;
        };
        let pairing_id = entry.pairing_id.clone();

        // Reuse a live, unexpired token if present.
        if let Some(existing) = self.tokens.get(&pairing_id) {
            if !existing.is_expired() {
                return ReauthOutcome::Ok {
                    token_hex: existing.token.to_hex().to_string(),
                    pairing_id,
                };
            }
        }

        // Mint fresh.
        let fresh = BridgeTokenEntry::fresh();
        let hex = fresh.token.to_hex().to_string();
        self.tokens.insert(pairing_id.clone(), fresh);
        ReauthOutcome::Ok {
            token_hex: hex,
            pairing_id,
        }
    }

    /// Verify a presented token (from the request's `session_token` field)
    /// against the live registry. Returns the `PairingId` on match.
    ///
    /// Constant-time posture: bridge tokens are 256-bit
    /// random, so timing enumeration is infeasible regardless, but we harden
    /// the cheap wins: (a) length-check BEFORE hex::decode so decode failures
    /// don't act as a format oracle, (b) fixed-size byte compare via ct_eq,
    /// (c) iterate ALL entries accumulating the match (no short-circuit) so
    /// loop timing doesn't leak which slot matched. The number of registered
    /// pairings IS observable (loop length) — acceptable; it's bounded by the
    /// user's own pairing count.
    pub fn verify_token(&self, presented_hex: &str) -> Option<PairingId> {
        // Fixed hex length for a 256-bit token = 64 chars. Check BEFORE decode.
        if presented_hex.len() != 64 {
            return None;
        }
        let presented = match hex::decode(presented_hex) {
            Ok(b) => b,
            Err(_) => return None, // non-hex char; format already gated by len
        };
        let mut matched: Option<PairingId> = None;
        for (id, entry) in &self.tokens {
            if entry.is_expired() {
                continue;
            }
            let tok = entry.token.as_bytes();
            // ct_eq returns Choice; convert to bool (constant-time) and
            // accumulate without short-circuit.
            let eq: bool = presented.as_slice().ct_eq(tok).into();
            if eq && matched.is_none() {
                matched = Some(id.clone());
            }
        }
        matched
    }

    /// Drop a pairing entirely: in-memory token + pairing-file entry.
    pub fn revoke(&mut self, pairing_id: &PairingId) -> Result<(), &'static str> {
        self.tokens.remove(pairing_id);
        let mut pf = PairingFile::load().unwrap_or_default();
        pf.remove(pairing_id);
        pf.save_atomic().map_err(|_| "pairing file write failed")
    }

    /// Charge a read (bridge.match / vault.get) against this pairing's
    /// rate window. Returns `false` if the pairing must be auto-revoked for
    /// abuse. Caller is responsible for the actual revoke.
    ///
    /// Atomicity: takes `&mut self`; the caller in `route_bridge_request`
    /// holds `host.bridge().write().await` across the check-and-increment, so
    /// two concurrent `vault.get` calls for the same pairing serialize through
    /// this exclusive lock. No separate atomic needed.
    pub fn charge_read(&mut self, pairing_id: &PairingId) -> bool {
        let Some(entry) = self.tokens.get_mut(pairing_id) else {
            return false; // unknown pairing -> reject downstream
        };
        let now = now_secs();
        if now.saturating_sub(entry.window_started_at) > READ_RATE_WINDOW_SECONDS {
            entry.window_started_at = now;
            entry.reads_in_window = 0;
        }
        entry.reads_in_window = entry.reads_in_window.saturating_add(1);
        entry.reads_in_window <= READ_RATE_LIMIT_PER_MINUTE
    }

    /// Is the action allowed for a bridge token? Delegates to the core
    /// allowlist (single source of truth).
    pub fn action_allowed(action: &str) -> bool {
        is_allowed(action)
    }
}

/// Constant-time comparison of a `PairingSecret` against a stored hex string.
fn constant_time_secret_eq(presented: &PairingSecret, stored_hex: &str) -> bool {
    let Ok(stored) = PairingSecret::from_hex(stored_hex) else {
        return false;
    };
    presented.as_bytes().ct_eq(stored.as_bytes()).into()
}

/// Convenience type alias used by the host + handler.
pub type SharedBridgeRegistry = Arc<RwLock<BridgeRegistry>>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Sandbox the pairing file into a temp dir for each test. Sets
    /// `BALUARD_DATA_DIR` (read by `baluard_core::paths::data_dir`) and holds
    /// a guard for the test's lifetime. Serialised by a mutex because env
    /// vars are process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Sandbox {
        _dir: tempfile::TempDir,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    fn sandbox() -> Sandbox {
        let guard = ENV_LOCK.lock().unwrap();
        // Leak the tempdir so it outlives the function; the path is what
        // matters and we clean up via env var reset.
        let dir = tempfile::tempdir().expect("tmpdir");
        // SAFETY: serialised by ENV_LOCK, same pattern as paths.rs tests.
        unsafe {
            std::env::set_var("BALUARD_DATA_DIR", dir.path().to_string_lossy().to_string());
        }
        Sandbox {
            _dir: dir,
            _guard: guard,
        }
    }

    #[tokio::test]
    async fn reauth_is_idempotent_within_ttl() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        reg.start_pair("chrome-test");
        reg.approve_pending().unwrap();
        let (id, token) = reg.complete_pair("test", "chrome").unwrap();

        // Reauth with the secret from the file should return the SAME token.
        let pf = PairingFile::load().unwrap_or_default();
        let entry = pf.get(&id).unwrap();
        match reg.reauth(&entry.secret) {
            ReauthOutcome::Ok {
                token_hex,
                pairing_id,
            } => {
                assert_eq!(token_hex, token);
                assert_eq!(pairing_id, id);
            }
            _ => panic!("reauth must succeed"),
        }
    }

    #[tokio::test]
    async fn reauth_rejects_unknown_secret() {
        let mut reg = BridgeRegistry::default();
        let bogus = PairingSecret::generate().to_hex().to_string();
        assert!(matches!(reg.reauth(&bogus), ReauthOutcome::NotPaired));
    }

    #[tokio::test]
    async fn verify_token_round_trips() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        reg.start_pair("chrome-verify");
        reg.approve_pending().unwrap();
        let (id, token) = reg.complete_pair("test", "chrome").unwrap();
        let verified = reg.verify_token(&token);
        assert_eq!(verified, Some(id));
        assert!(reg.verify_token("deadbeef").is_none());
    }

    #[tokio::test]
    async fn charge_read_caps_then_revokes() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        reg.start_pair("chrome-cap");
        reg.approve_pending().unwrap();
        let (id, _token) = reg.complete_pair("test", "chrome").unwrap();
        // Cap is 30/min; the 31st trips revoke.
        for _ in 0..READ_RATE_LIMIT_PER_MINUTE {
            assert!(reg.charge_read(&id));
        }
        assert!(!reg.charge_read(&id));
    }

    #[tokio::test]
    async fn complete_pair_requires_a_pending() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        // No start_pair: no pending exists -> complete_pair must fail.
        assert!(reg.complete_pair("test", "chrome").is_err());
    }

    /// New ceremony invariant (Phase 1 fix): approve_pending WITHOUT a waiter
    /// marks the pending Approved, so a subsequent pair_complete fast-path
    /// proceeds immediately. This is the desktop-approves-first ordering.
    #[tokio::test]
    async fn approve_before_complete_fast_path() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        reg.start_pair("chrome-fast");
        // Desktop approves first (no extension waiting yet).
        let req_id = reg.approve_pending().unwrap();
        assert!(!req_id.is_empty());
        // Pending is now marked Approved.
        assert!(matches!(
            reg.pending().map(|p| p.approval),
            Some(Some(PairApproval::Approved))
        ));
        // Extension's pair_complete then completes immediately.
        let (id, _token) = reg.complete_pair("test", "chrome").unwrap();
        let pf = PairingFile::load().unwrap_or_default();
        assert!(pf.get(&id).is_some());
    }

    #[tokio::test]
    async fn revoke_drops_token_and_file_entry() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        reg.start_pair("chrome-rev");
        reg.approve_pending().unwrap();
        let (id, token) = reg.complete_pair("test", "chrome").unwrap();
        reg.revoke(&id).unwrap();
        assert!(reg.verify_token(&token).is_none());
        let pf = PairingFile::load().unwrap_or_default();
        assert!(pf.get(&id).is_none());
    }

    /// C2 regression: a re-`start_pair` must CANCEL an in-flight
    /// waiter by dropping the sender (RecvError), NOT by sending an empty
    /// payload (which the receiver would mistake for approval). The old
    /// extension's held pair_complete must fail, not hijack the new slot.
    #[tokio::test]
    async fn start_pair_cancels_waiter_via_drop_not_send() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        reg.start_pair("chrome-old");
        // Extension A registers a waiter (held pair_complete).
        let rx_old = reg.register_waiter("old".into(), "chrome".into());
        // Desktop user re-starts the ceremony (e.g. clicked Add again).
        reg.start_pair("chrome-new");
        // The old waiter receiver must now be RESOLVED WITH ERROR, not yield
        // a (possibly empty) success payload.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), rx_old).await;
        assert!(
            matches!(outcome, Ok(Err(_))),
            "dropped sender must produce RecvError, not a hijack-success"
        );
        // And the new pending is intact (not consumed).
        assert!(reg.pending().is_some());
    }

    /// C13: two concurrent pair_complete callers; only the code-holder
    /// succeeds. A wrong-code caller (same-UID process racing the real
    /// extension) must be rejected BEFORE registering a waiter, so it can
    /// never supersede the legitimate waiter and harvest the minted
    /// pairing. A missing code is just a wrong code.
    #[tokio::test]
    async fn wrong_pair_code_does_not_supersede_waiter() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        let (_rid, code) = reg.start_pair("chrome-c13");

        // Legit extension verifies its code and registers the waiter.
        assert!(reg.verify_pair_code(&code).is_ok());
        let rx_legit = reg.register_waiter("legit".into(), "chrome".into());

        // Attacker calls pair_complete with a wrong code (and, separately,
        // with no code at all): both are rejected.
        assert_eq!(reg.verify_pair_code("XXXXXXXX"), Err("invalid pair code"));
        assert_eq!(reg.verify_pair_code(""), Err("invalid pair code"));

        // The legit waiter survived the attack: approving resolves it and
        // completes the pairing.
        reg.approve_pending().unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), rx_legit).await;
        assert!(matches!(outcome, Ok(Ok(_))), "legit waiter must resolve");
        let (id, _token) = reg.complete_pair("legit", "chrome").unwrap();
        let pf = PairingFile::load().unwrap_or_default();
        assert!(pf.get(&id).is_some());

        // A late second caller now finds no ceremony to hijack.
        assert_eq!(reg.verify_pair_code(&code), Err("no pending pairing"));
    }

    /// C13: three wrong attempts cancel the ceremony entirely (pending +
    /// any registered waiter), killing offline brute force of the code.
    #[tokio::test]
    async fn three_wrong_pair_codes_cancel_ceremony() {
        let _sb = sandbox();
        let mut reg = BridgeRegistry::default();
        let (_rid, code) = reg.start_pair("chrome-c13b");
        let _rx = reg.register_waiter("legit".into(), "chrome".into());

        assert_eq!(reg.verify_pair_code("AAAAAAAA"), Err("invalid pair code"));
        assert_eq!(reg.verify_pair_code("BBBBBBBB"), Err("invalid pair code"));
        assert_eq!(
            reg.verify_pair_code("CCCCCCCC"),
            Err("too many invalid pair codes; start pairing again")
        );

        // Ceremony is dead: pending gone, even the CORRECT code now fails.
        assert!(reg.pending().is_none());
        assert_eq!(reg.verify_pair_code(&code), Err("no pending pairing"));
    }
}
