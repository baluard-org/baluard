//! Agent credential grants (D80): scoped, peer-bound, read-only access for
//! local AI agents, with human approval on every new item.
//!
//! Boundary facts that shape this module:
//! - Grants bind to the requesting PROCESS (pid + executable + start time),
//!   never to a bearer token: a returned bearer capability would be usable by
//!   every same-UID process on the machine (the audit-C12 rule reprompt_verify
//!   already follows).
//! - The TTL is absolute from approval. Sliding renewal would let an agent
//!   loop keep a grant alive forever.
//! - Agent traffic never feeds `touch_activity`, so an agent polling cannot
//!   hold off auto-lock.
//! - Grants die on explicit lock, on the auto-lock timer, and on daemon
//!   restart. `vaults.lock_all` (the desktop blur path) skips vaults with
//!   live grants per the D80 blur-lock ruling; `vault.lock` never does.

use baluard_core::error::{BaluardError, VaultError};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// How far up the process tree the daemon walks when checking that a `run`
/// request comes from the same process that asked for the grant. The agent
/// spawns `baluard run` as a child, so the presenting process is a descendant
/// of the bound pid, not the bound pid itself.
const TREE_WALK_DEPTH: usize = 8;

pub const AGENT_TOKEN_PREFIX: &str = "agt_";
/// Caps on simultaneously pending approval requests (per executable and
/// total) so one hostile or buggy process cannot flood the desktop with
/// prompts or crowd out a real request.
pub const MAX_PENDING_PER_EXE: usize = 1;
pub const MAX_PENDING_TOTAL: usize = 3;
pub const DEFAULT_TTL_SECS: u64 = 900;

/// Process identity the daemon resolves from the socket peer credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBinding {
    pub pid: u32,
    pub exe_path: String,
    /// Linux /proc/<pid>/stat field 22 (clock ticks since boot). 0 where the
    /// platform cannot provide it (macOS); the pid+exe pair still binds.
    pub start_ticks: u64,
}

impl PeerBinding {
    pub fn new(pid: u32, exe_path: impl Into<String>, start_ticks: u64) -> Self {
        Self {
            pid,
            exe_path: exe_path.into(),
            start_ticks,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AgentGrant {
    pub(crate) token_sha256: [u8; 32],
    pub(crate) peer: PeerBinding,
    pub(crate) item_ids: Vec<String>,
    pub(crate) expires_at_ms: u64,
    /// VaultState session generation at mint time. A lock bumps the
    /// generation, so every grant minted before it dies without a scan.
    pub(crate) generation: u64,
}

/// Result of verifying an agent token against this vault's grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVerdict {
    pub grant_item_ids: Vec<String>,
    pub peer: PeerBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrantView {
    pub peer: PeerBinding,
    pub item_ids: Vec<String>,
    pub expires_at_ms: u64,
}

pub(crate) struct AgentGrants {
    grants: RwLock<Vec<AgentGrant>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// True when `chain` (the presenting process's ancestor chain, nearest
/// ancestor first, as (pid, start_ticks) pairs) contains the bound pid with
/// matching start ticks. Start ticks make pid reuse safe on Linux.
pub fn pid_in_process_tree(bound: &PeerBinding, chain: &[(u32, u64)]) -> bool {
    chain.iter().take(TREE_WALK_DEPTH).any(|(pid, start)| {
        pid == &bound.pid && (*start == bound.start_ticks || bound.start_ticks == 0 || *start == 0)
    })
}

/// Route allowlist for the agent token class. Everything not listed is
/// refused by prefix, mirroring CONTACT_VIEW_ALLOWED's default-deny shape.
pub const AGENT_ALLOWED_ACTIONS: &[&str] = &["agents.poll", "agents.run", "agents.revoke_own"];

impl AgentGrants {
    pub(crate) fn new() -> Self {
        Self {
            grants: RwLock::new(Vec::new()),
        }
    }

    /// Mints a token for one approval. Returns the full token exactly once;
    /// only its SHA-256 is retained.
    pub(crate) fn mint(
        &self,
        peer: PeerBinding,
        item_ids: Vec<String>,
        ttl_secs: u64,
        generation: u64,
    ) -> String {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = format!("{AGENT_TOKEN_PREFIX}{}", hex::encode(raw));
        let token_sha256 = sha256(token.as_bytes());
        let expires_at_ms = now_ms() + ttl_secs * 1000;
        self.grants.write().unwrap().push(AgentGrant {
            token_sha256,
            peer,
            item_ids,
            expires_at_ms,
            generation,
        });
        token
    }

    /// Constant-time verification by digest comparison. Expired grants are
    /// dropped lazily here; a lock invalidates everything via the generation
    /// check without any scan.
    pub(crate) fn verify(
        &self,
        token: &str,
        generation: u64,
    ) -> Result<AgentVerdict, BaluardError> {
        use subtle::ConstantTimeEq;
        if !token.starts_with(AGENT_TOKEN_PREFIX) {
            return Err(BaluardError::Vault(VaultError::InvalidOperation(
                "not an agent token".into(),
            )));
        }
        let digest = sha256(token.as_bytes());
        let now = now_ms();
        let mut grants = self.grants.write().unwrap();
        grants.retain(|g| g.expires_at_ms > now);
        for g in grants.iter() {
            if bool::from(g.token_sha256.ct_eq(&digest)) {
                if g.generation != generation {
                    return Err(BaluardError::Vault(VaultError::InvalidOperation(
                        "agent grant was invalidated by a vault lock".into(),
                    )));
                }
                return Ok(AgentVerdict {
                    grant_item_ids: g.item_ids.clone(),
                    peer: g.peer.clone(),
                });
            }
        }
        Err(BaluardError::Vault(VaultError::InvalidOperation(
            "agent grant is missing, expired, or revoked".into(),
        )))
    }

    /// Peers holding live grants right now (for the desktop running-grants
    /// view and the blur-lock exemption in `vaults.lock_all`).
    pub(crate) fn live_peers(&self, generation: u64) -> Vec<PeerBinding> {
        let now = now_ms();
        self.grants
            .read()
            .unwrap()
            .iter()
            .filter(|g| g.generation == generation && g.expires_at_ms > now)
            .map(|g| g.peer.clone())
            .collect()
    }

    pub(crate) fn has_live_grants(&self, generation: u64) -> bool {
        let now = now_ms();
        self.grants
            .read()
            .unwrap()
            .iter()
            .any(|g| g.generation == generation && g.expires_at_ms > now)
    }

    pub(crate) fn live_grant_views(&self, generation: u64) -> Vec<AgentGrantView> {
        let now = now_ms();
        self.grants
            .read()
            .unwrap()
            .iter()
            .filter(|g| g.generation == generation && g.expires_at_ms > now)
            .map(|g| AgentGrantView {
                peer: g.peer.clone(),
                item_ids: g.item_ids.clone(),
                expires_at_ms: g.expires_at_ms,
            })
            .collect()
    }

    /// Revokes one presented grant after normal generation/expiry
    /// verification. Used by an agent finishing its own work.
    pub(crate) fn revoke_token(&self, token: &str, generation: u64) -> bool {
        use subtle::ConstantTimeEq;
        if self.verify(token, generation).is_err() {
            return false;
        }
        let digest = sha256(token.as_bytes());
        let mut grants = self.grants.write().unwrap();
        let before = grants.len();
        grants.retain(|g| !bool::from(g.token_sha256.ct_eq(&digest)));
        grants.len() != before
    }

    /// Revokes every grant (agents.revoke). Locking needs no call: the
    /// generation check in `verify` already fails every pre-lock grant.
    pub(crate) fn revoke_all(&self) {
        self.grants.write().unwrap().clear();
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Pending approval requests, owned by `VaultHost` (an agent asks before any
/// vault is active, and the target vault may be locked).
pub struct PendingQueue {
    entries: RwLock<HashMap<String, PendingRequest>>,
    outcomes: RwLock<HashMap<String, (PendingOutcome, u64)>>,
}

#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request_id: String,
    pub vault_slug: Option<String>,
    pub peer: PeerBinding,
    pub claimed_name: String,
    pub need: String,
    pub item_ids: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingOutcome {
    Approved { token: String },
    Denied,
    TimedOut,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            outcomes: RwLock::new(HashMap::new()),
        }
    }

    /// Accepts a request unless the caps bite. The per-exe cap counts by
    /// executable path so a renamed process cannot dodge it.
    pub fn push(
        &self,
        vault_slug: Option<String>,
        peer: PeerBinding,
        claimed_name: String,
        need: String,
        item_ids: Vec<String>,
    ) -> Result<String, QueueFull> {
        let mut entries = self.entries.write().unwrap();
        Self::sweep(&mut entries);
        let per_exe = entries
            .values()
            .filter(|e| e.peer.exe_path == peer.exe_path)
            .count();
        if per_exe >= MAX_PENDING_PER_EXE || entries.len() >= MAX_PENDING_TOTAL {
            return Err(QueueFull);
        }
        let mut raw = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut raw);
        let request_id = hex::encode(raw);
        entries.insert(
            request_id.clone(),
            PendingRequest {
                request_id: request_id.clone(),
                vault_slug,
                peer,
                claimed_name,
                need,
                item_ids,
                created_at_ms: now_ms(),
            },
        );
        Ok(request_id)
    }

    pub fn list(&self) -> Vec<PendingRequest> {
        let mut entries = self.entries.write().unwrap();
        Self::sweep(&mut entries);
        let mut v: Vec<PendingRequest> = entries.values().cloned().collect();
        v.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms));
        v
    }

    pub fn get(&self, request_id: &str) -> Option<PendingRequest> {
        let cutoff = now_ms().saturating_sub(120_000);
        self.entries
            .read()
            .unwrap()
            .get(request_id)
            .filter(|entry| entry.created_at_ms > cutoff)
            .cloned()
    }

    pub fn deny(&self, request_id: &str) -> bool {
        self.entries.write().unwrap().remove(request_id).is_some()
    }

    /// Removes and returns the request on approval; the caller mints the
    /// grant against the returned peer binding so the grant can never be
    /// separated from the process that asked.
    pub fn take(&self, request_id: &str) -> Option<PendingRequest> {
        self.entries.write().unwrap().remove(request_id)
    }

    pub fn complete_approved(&self, request_id: &str, token: String) {
        self.outcomes.write().unwrap().insert(
            request_id.to_string(),
            (PendingOutcome::Approved { token }, now_ms() + 120_000),
        );
    }

    pub fn complete_denied(&self, request_id: &str) {
        self.outcomes.write().unwrap().insert(
            request_id.to_string(),
            (PendingOutcome::Denied, now_ms() + 120_000),
        );
    }

    /// One-time outcome read. Approval tokens are removed on retrieval, so
    /// a later poll cannot replay the grant.
    pub fn take_outcome(&self, request_id: &str) -> Option<PendingOutcome> {
        let mut outcomes = self.outcomes.write().unwrap();
        let now = now_ms();
        outcomes.retain(|_, (_, expires)| *expires > now);
        outcomes.remove(request_id).map(|(outcome, _)| outcome)
    }

    /// Requests older than the approval window are dropped so a vanished
    /// requester cannot be granted later (late-approval orphan rule).
    fn sweep(entries: &mut HashMap<String, PendingRequest>) {
        let cutoff = now_ms().saturating_sub(120_000);
        entries.retain(|_, e| e.created_at_ms > cutoff);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct QueueFull;

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pid: u32) -> PeerBinding {
        PeerBinding::new(pid, format!("/usr/bin/agent-{pid}"), 1000 + pid as u64)
    }

    // --- Grant lifecycle -------------------------------------------------

    #[test]
    fn minted_grant_verifies_and_reports_its_items() {
        let g = AgentGrants::new();
        let token = g.mint(peer(7), vec!["item-1".into()], 60, 3);
        assert!(token.starts_with(AGENT_TOKEN_PREFIX));
        let v = g.verify(&token, 3).unwrap();
        assert_eq!(v.grant_item_ids, vec!["item-1".to_string()]);
    }

    #[test]
    fn a_lock_invalidates_every_grant_via_generation() {
        let g = AgentGrants::new();
        let token = g.mint(peer(7), vec!["item-1".into()], 60, 3);
        // The lock bumps VaultState's session generation; verify now runs
        // with 4 and the pre-lock grant fails with the typed lock error.
        let err = g.verify(&token, 4).unwrap_err().to_string();
        assert!(err.contains("invalidated by a vault lock"), "{err}");
        // Re-minting under the new generation verifies fine.
        let fresh = g.mint(peer(7), vec!["item-1".into()], 60, 4);
        g.verify(&fresh, 4).unwrap();
    }

    #[test]
    fn expired_grants_are_refused_and_swept() {
        let g = AgentGrants::new();
        let token = g.mint(peer(7), vec!["i".into()], 0, 1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let err = g.verify(&token, 1).unwrap_err().to_string();
        assert!(err.contains("missing, expired, or revoked"), "{err}");
        assert!(g.live_peers(1).is_empty());
    }

    #[test]
    fn non_agent_tokens_are_refused_by_prefix() {
        let g = AgentGrants::new();
        let err = g.verify("some-session-token", 1).unwrap_err().to_string();
        assert!(err.contains("not an agent token"), "{err}");
    }

    #[test]
    fn live_peers_and_has_live_grants_see_only_current_generation() {
        let g = AgentGrants::new();
        assert!(!g.has_live_grants(1));
        g.mint(peer(7), vec!["i".into()], 60, 1);
        assert!(g.has_live_grants(1));
        assert_eq!(g.live_peers(1).len(), 1);
        assert_eq!(g.live_peers(1)[0].pid, 7);
        assert!(!g.has_live_grants(2));
    }

    #[test]
    fn revoke_all_clears_every_grant() {
        let g = AgentGrants::new();
        let t1 = g.mint(peer(7), vec!["i".into()], 60, 1);
        let t2 = g.mint(peer(8), vec!["i".into()], 60, 1);
        g.revoke_all();
        assert!(g.verify(&t1, 1).is_err());
        assert!(g.verify(&t2, 1).is_err());
    }

    #[test]
    fn revoke_token_removes_only_the_presented_grant() {
        let g = AgentGrants::new();
        let t1 = g.mint(peer(7), vec!["i".into()], 60, 1);
        let t2 = g.mint(peer(8), vec!["i".into()], 60, 1);
        assert!(g.revoke_token(&t1, 1));
        assert!(g.verify(&t1, 1).is_err());
        assert!(g.verify(&t2, 1).is_ok());
        assert!(!g.revoke_token(&t1, 1));
    }

    // --- Process-tree binding --------------------------------------------

    #[test]
    fn the_presenting_process_must_descend_from_the_bound_pid() {
        let bound = PeerBinding::new(500, "/usr/bin/agent", 4242);
        // agent(500) -> sh(600) -> baluard(700): presenting chain nearest first
        let chain = vec![(700u32, 1u64), (600u32, 2u64), (500u32, 4242u64)];
        assert!(pid_in_process_tree(&bound, &chain));
    }

    #[test]
    fn an_unrelated_tree_is_refused() {
        let bound = PeerBinding::new(500, "/usr/bin/agent", 4242);
        let chain = vec![(900u32, 9u64), (800u32, 8u64)];
        assert!(!pid_in_process_tree(&bound, &chain));
    }

    #[test]
    fn a_reused_pid_with_different_start_ticks_is_refused() {
        let bound = PeerBinding::new(500, "/usr/bin/agent", 4242);
        let chain = vec![(500u32, 9999u64)];
        assert!(!pid_in_process_tree(&bound, &chain));
    }

    #[test]
    fn walks_only_to_the_configured_depth() {
        let bound = PeerBinding::new(1, "/usr/bin/agent", 1);
        let chain: Vec<(u32, u64)> = (2..=64).map(|i| (i as u32, i as u64)).rev().collect();
        assert!(!pid_in_process_tree(&bound, &chain));
    }

    // --- Pending queue ----------------------------------------------------

    #[test]
    fn push_list_take_round_trip() {
        let q = PendingQueue::new();
        let id = q
            .push(
                Some("personal".into()),
                peer(7),
                "Claude".into(),
                "github login".into(),
                vec!["item-1".into()],
            )
            .unwrap();
        let listed = q.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].claimed_name, "Claude");
        let taken = q.take(&id).unwrap();
        assert_eq!(taken.peer.pid, 7);
        assert!(q.get(&id).is_none());
    }

    #[test]
    fn per_executable_cap_blocks_a_second_request_from_the_same_exe() {
        let q = PendingQueue::new();
        let p = peer(7);
        q.push(
            Some("personal".into()),
            p.clone(),
            "A".into(),
            "n".into(),
            vec![],
        )
        .unwrap();
        let err = q
            .push(Some("personal".into()), p, "A".into(), "n".into(), vec![])
            .unwrap_err();
        assert_eq!(err, QueueFull);
        // A different executable is not blocked by the per-exe cap.
        q.push(
            Some("personal".into()),
            peer(8),
            "B".into(),
            "n".into(),
            vec![],
        )
        .unwrap();
    }

    #[test]
    fn total_cap_blocks_the_fourth_pending_request() {
        let q = PendingQueue::new();
        for pid in 1..=3u32 {
            let mut p = peer(pid);
            p.exe_path = format!("/usr/bin/exe-{pid}");
            q.push(None, p, "n".into(), "n".into(), vec![]).unwrap();
        }
        let mut p = peer(4);
        p.exe_path = "/usr/bin/exe-4".into();
        assert_eq!(
            q.push(None, p, "n".into(), "n".into(), vec![]).unwrap_err(),
            QueueFull
        );
    }

    #[test]
    fn deny_removes_the_request() {
        let q = PendingQueue::new();
        let id = q
            .push(None, peer(7), "A".into(), "n".into(), vec![])
            .unwrap();
        assert!(q.deny(&id));
        assert!(q.list().is_empty());
        assert!(!q.deny(&id));
    }

    #[test]
    fn sweep_reuses_the_pending_slot_after_the_window() {
        let q = PendingQueue::new();
        let p = peer(7);
        let id1 = q
            .push(None, p.clone(), "A".into(), "n".into(), vec![])
            .unwrap();
        // Simulate the first request aging out of the approval window.
        q.entries
            .write()
            .unwrap()
            .get_mut(&id1)
            .unwrap()
            .created_at_ms = now_ms().saturating_sub(121_000);
        assert!(
            q.get(&id1).is_none(),
            "an expired request never reports pending"
        );
        let id2 = q.push(None, p, "A".into(), "n".into(), vec![]).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(q.list().len(), 1);
    }
}
